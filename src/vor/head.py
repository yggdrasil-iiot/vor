"""Verifies a Bifrost stream head the way TUF verifies metadata: two signatures from distinct trusted keys over a
statement that names the head file and its release.json by raw-byte SHA-256, a version that never goes below the
highest one this reader has seen, and an expiry.

Bifrost's layout (mappings/): heads/<stream>.json is {id, version, sha256}; head-attestations/<stream>.dsse.json is a
DSSE v1 envelope around an in-toto Statement v1 whose predicate carries headVersion, signedAt, expires, publishedBy and
approvedBy. The trusted keys come from a file the operator gives Vor, outside the registry: a registry cannot vouch
for itself. The rollback floor lives in Vor's own state directory, so a restored copy of mappings/ is caught.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .refusal import Refusal, sha256

IN_TOTO = "application/vnd.in-toto+json"
STATEMENT = "https://in-toto.io/Statement/v1"
PREDICATE = "https://github.com/yggdrasil-iiot/bifrost/attestation/mapping-head/v1"
INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
STREAM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

TrustedKeys = dict[str, list[Ed25519PublicKey]]


def load_trusted_keys(path: Path) -> TrustedKeys:
    """principal -> Ed25519 keys, from JSON lines {"principal": ..., "publicKey": <X.509 SubjectPublicKeyInfo, base64>}."""
    keys: TrustedKeys = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        key = load_der_public_key(base64.b64decode(entry["publicKey"]))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"{entry['principal']}: not an Ed25519 key")
        keys.setdefault(entry["principal"], []).append(key)
    return keys


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE pre-authentication encoding: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def instant(text) -> datetime:
    if not isinstance(text, str) or not INSTANT.fullmatch(text):
        raise ValueError(text)
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class FloorStore:
    """The highest head version accepted per stream and the digest of its statement, kept as one small JSON file per
    stream under Vor's state directory and replaced atomically."""

    def __init__(self, directory: Path):
        self.directory = directory

    def _file(self, stream: str) -> Path:
        return self.directory / "floors" / f"{stream}.json"

    def get(self, stream: str) -> tuple[int, str] | None:
        f = self._file(stream)
        if not f.exists():
            return None
        d = json.loads(f.read_text(encoding="utf-8"))
        return int(d["headVersion"]), d["statementSha256"]

    def raise_to(self, stream: str, version: int, statement_sha: str) -> None:
        f = self._file(stream)
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps({"headVersion": version, "statementSha256": statement_sha}), encoding="utf-8")
        os.replace(tmp, f)


@dataclass(frozen=True)
class Head:
    stream: str
    release_id: str
    version: str
    release_sha256: str
    head_file: str
    head_sha256: str
    attestation_file: str
    attestation_sha256: str
    statement_sha256: str
    head_version: int
    signed_at: str
    expires: str
    published_by: str
    approved_by: str

    @property
    def release_path(self) -> str:
        return f"releases/{self.release_id}/{self.version}/release.json"

    def summary(self) -> dict:
        return {"headVersion": self.head_version, "signedAt": self.signed_at, "expires": self.expires,
                "publishedBy": self.published_by, "approvedBy": self.approved_by,
                "source": {"file": self.attestation_file, "sha256": self.attestation_sha256}}


def _unverified(stream: str, rule: str, **more) -> Refusal:
    return Refusal("head-unverified", stream=stream, rule=rule, **more)


def _signer(envelope: dict, message: bytes, keys: list[Ed25519PublicKey]) -> Ed25519PublicKey | None:
    for s in envelope.get("signatures") or []:
        sig = s.get("sig") if isinstance(s, dict) else None
        if not isinstance(sig, str):
            continue
        try:
            raw = base64.b64decode(sig, validate=True)
        except (binascii.Error, ValueError):
            try:
                raw = base64.urlsafe_b64decode(sig)
            except (binascii.Error, ValueError):
                continue
        for key in keys:
            try:
                key.verify(raw, message)
                return key
            except InvalidSignature:
                continue
    return None


def verify_head(mappings: Path, stream: str, trusted: TrustedKeys, floors: FloorStore, now_ms: int) -> Head:
    """The head of one stream, or a Refusal: head-unverified, head-rollback or head-expired, in that order."""
    if not STREAM.fullmatch(stream):
        raise _unverified(stream, "stream-id")
    head_file, att_file = f"heads/{stream}.json", f"head-attestations/{stream}.dsse.json"
    try:
        head_bytes = (mappings / head_file).read_bytes()
        att_bytes = (mappings / att_file).read_bytes()
    except FileNotFoundError as e:
        raise _unverified(stream, "missing", file=Path(e.filename).name)
    head_sha = sha256(head_bytes)
    try:
        head = json.loads(head_bytes)
        envelope = json.loads(att_bytes)
        if envelope.get("payloadType") != IN_TOTO or not isinstance(envelope.get("payload"), str):
            raise ValueError("envelope")
        body = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(body)
        p = statement["predicate"]
        published, approved = p["publishedBy"], p["approvedBy"]
    except (ValueError, KeyError, TypeError, binascii.Error):
        raise _unverified(stream, "envelope")

    # Two principals, two trusted keys, two different keys: the four-eyes rule Bifrost signs under.
    if not isinstance(published, str) or not isinstance(approved, str) or published == approved:
        raise _unverified(stream, "principals", publishedBy=published, approvedBy=approved)
    message = pae(IN_TOTO, body)
    used = []
    for principal in (published, approved):
        key = _signer(envelope, message, trusted.get(principal, []))
        if key is None:
            raise _unverified(stream, "signature", principal=principal)
        if any(k.public_bytes_raw() == key.public_bytes_raw() for k in used):
            raise _unverified(stream, "same-key", principal=principal)
        used.append(key)

    try:
        release_id, version, release_sha = head["id"], head["version"], head["sha256"]
        release_path = f"releases/{release_id}/{version}/release.json"
        subject = statement["subject"]
        ok = (statement.get("_type") == STATEMENT and statement.get("predicateType") == PREDICATE
              and p.get("streamId") == stream and p.get("release") == head
              and isinstance(p.get("headVersion"), int) and not isinstance(p.get("headVersion"), bool)
              and p["headVersion"] >= 1 and len(subject) == 2
              and subject[0] == {"name": head_file, "digest": {"sha256": head_sha}}
              and subject[1] == {"name": release_path, "digest": {"sha256": release_sha}})
        signed_at, expires = instant(p["signedAt"]), instant(p["expires"])
    except (KeyError, TypeError, ValueError):
        ok = False
    if not ok:
        raise _unverified(stream, "subject", expected=head_sha,
                          computed=next((s.get("digest", {}).get("sha256") for s in statement.get("subject", [])
                                         if isinstance(s, dict) and s.get("name") == head_file), None))
    now = datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc)
    if signed_at > now:
        raise _unverified(stream, "signed-in-future", signedAt=p["signedAt"], now=iso(now_ms))

    statement_sha = sha256(body)
    version_number = p["headVersion"]
    floor = floors.get(stream)
    if floor is not None and (version_number < floor[0] or version_number == floor[0] and statement_sha != floor[1]):
        raise Refusal("head-rollback", stream=stream, floor=floor[0], candidate=version_number,
                      recordedStatementSha256=floor[1], candidateStatementSha256=statement_sha)
    if now >= expires:
        raise Refusal("head-expired", stream=stream, expires=p["expires"], now=iso(now_ms))
    if floor is None or version_number > floor[0]:
        floors.raise_to(stream, version_number, statement_sha)

    return Head(stream=stream, release_id=release_id, version=version, release_sha256=release_sha,
                head_file=f"mappings/{head_file}", head_sha256=head_sha, attestation_file=f"mappings/{att_file}",
                attestation_sha256=sha256(att_bytes), statement_sha256=statement_sha, head_version=version_number,
                signed_at=p["signedAt"], expires=p["expires"], published_by=published, approved_by=approved)
