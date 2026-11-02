"""Test-only tools: re-sign a head and re-publish a changed release over the Bifrost-published fixtures, and encode
Sparkplug B payloads. Fresh Ed25519 keys are made per test; no private key is committed."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_private_key

from vor.head import IN_TOTO, PREDICATE, STATEMENT, instant, pae

FIXTURES = Path(__file__).parent / "fixtures"
BINDING = "vor-binding-mixer1-temp"
DEVICE = "synthetic-site:line1:mixer1"
TOPIC = f"spBv1.0/Bifrost:Line1/DDATA/recipe-edge/{DEVICE}"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(doc) -> bytes:
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def ms(text: str) -> int:
    return int(instant(text).timestamp() * 1000)


def copy_registry(name: str, dest: Path) -> Path:
    shutil.copytree(FIXTURES / "registries" / name, dest / name)
    return dest / name / "mappings"


def statement_of(mappings: Path, stream: str) -> dict:
    env = json.loads((mappings / "head-attestations" / f"{stream}.dsse.json").read_bytes())
    return json.loads(base64.b64decode(env["payload"]))


def fixture_now(mappings: Path, stream: str = "line1") -> int:
    """One minute after the fixture head was signed: inside its validity window."""
    return ms(statement_of(mappings, stream)["predicate"]["signedAt"]) + 60_000


class Keys:
    def __init__(self, *principals: str):
        self.private = {p: Ed25519PrivateKey.generate() for p in principals}

    @classmethod
    def from_bifrost(cls, directory: Path, *principals: str) -> "Keys":
        """The keys `gates identity keygen` wrote: <principal>.key holds a base64 PKCS#8 DER Ed25519 private key."""
        keys = cls()
        keys.private = {p: load_der_private_key(base64.b64decode((directory / f"{p}.key").read_text().strip()), None)
                        for p in principals}
        return keys

    def trusted(self, path: Path, alias: dict[str, str] | None = None) -> Path:
        """Write a trusted-keys file; `alias` registers a principal under another principal's key."""
        lines = []
        for p, k in self.private.items():
            lines.append({"principal": p, "publicKey": spki(k)})
        for p, other in (alias or {}).items():
            lines.append({"principal": p, "publicKey": spki(self.private[other])})
        path.write_text("".join(json.dumps(x) + "\n" for x in lines), encoding="utf-8")
        return path


def spki(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()


def sign_head(mappings: Path, stream: str, keys: Keys, *, version: int = 1, signed_at: str | None = None,
              lifetime: timedelta = timedelta(days=90), published_by: str = "proposer",
              approved_by: str = "approver", signer_of: dict[str, str] | None = None) -> bytes:
    """Write head-attestations/<stream>.dsse.json for the current heads/<stream>.json; returns the statement bytes."""
    head_bytes = (mappings / "heads" / f"{stream}.json").read_bytes()
    head = json.loads(head_bytes)
    release = json.loads((mappings / "releases" / head["id"] / head["version"] / "release.json").read_bytes())
    old = statement_of(mappings, stream)["predicate"]
    signed = instant(signed_at or old["signedAt"])
    previous = None if version == 1 else {"headVersion": version - 1, "release": old["release"]}
    statement = {
        "_type": STATEMENT,
        "subject": [{"name": f"heads/{stream}.json", "digest": {"sha256": sha(head_bytes)}},
                    {"name": f"releases/{head['id']}/{head['version']}/release.json",
                     "digest": {"sha256": head["sha256"]}}],
        "predicateType": PREDICATE,
        "predicate": {"streamId": stream, "headVersion": version,
                      "expires": (signed + lifetime).strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "signedAt": signed.strftime("%Y-%m-%dT%H:%M:%SZ"), "cause": "publish",
                      "approvalId": release["approval"]["payload"]["approvalId"], "publishedBy": published_by,
                      "approvedBy": approved_by, "release": head, "previous": previous},
    }
    body = compact(statement)
    message = pae(IN_TOTO, body)
    signer_of = signer_of or {}
    sigs = [{"keyid": p, "sig": base64.b64encode(keys.private[signer_of.get(p, p)].sign(message)).decode()}
            for p in (published_by, approved_by)]
    envelope = {"payload": base64.b64encode(body).decode(), "payloadType": IN_TOTO, "signatures": sigs}
    (mappings / "head-attestations" / f"{stream}.dsse.json").write_bytes(compact(envelope))
    return body


def edit_json(path: Path, change) -> None:
    doc = json.loads(path.read_bytes())
    change(doc)
    path.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def republish(mappings: Path, stream: str, keys: Keys, **sign) -> None:
    """After payload files changed: re-hash evidence data files, proposal entries, release.json, the head file, and
    re-sign the head. What Bifrost would have produced had it published the changed bundle."""
    head = json.loads((mappings / "heads" / f"{stream}.json").read_bytes())
    root = mappings / "releases" / head["id"] / head["version"]
    payload = root / "payload"
    proposal = json.loads((payload / "proposal.json").read_bytes())
    for entry in proposal["files"]:
        if entry["kind"] == "evidence-artifact":
            edit_json(payload / entry["path"],
                      lambda d: d["file"].__setitem__("sha256", sha((payload / d["file"]["path"]).read_bytes())))
        entry["sha256"] = sha((payload / entry["path"]).read_bytes())
    (payload / "proposal.json").write_bytes((json.dumps(proposal, indent=2) + "\n").encode("utf-8"))
    edit_json(root / "release.json",
              lambda r: [f.__setitem__("sha256", sha((root / f["path"]).read_bytes())) for f in r["files"]])
    head["sha256"] = sha((root / "release.json").read_bytes())
    (mappings / "heads" / f"{stream}.json").write_bytes(compact(head))
    sign_head(mappings, stream, keys, **sign)


# --- Sparkplug B encoding (tests only) -----------------------------------------------------------------------------

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(number: int, wire: int, value) -> bytes:
    key = _varint(number << 3 | wire)
    if wire == 0:
        return key + _varint(value)
    if wire == 1:
        return key + value
    return key + _varint(len(value)) + value


def prop(datatype: int, value, slot: str | None = None) -> bytes:
    body = _field(1, 0, datatype)
    slot = slot or ("int" if datatype in (3, 7) else "long")
    body += _field(3, 0, value & 0xFFFFFFFF) if slot == "int" else _field(4, 0, value)
    return body


def metric(name: str, value: float | None = 217.25, *, timestamp: int | None = None, status: int | None = 0,
           server: int | None = None, quality: int | None = 192, datatype: int = 10,
           status_slot: str = "long") -> bytes:
    body = _field(1, 2, name.encode())
    if timestamp is not None:
        body += _field(3, 0, timestamp)
    body += _field(4, 0, datatype)
    keys, values = [], []
    if quality is not None:
        keys.append("Quality"), values.append(prop(3, quality))
    if status is not None:
        keys.append("ua_statuscode"), values.append(prop(7, status, status_slot))
    if server is not None:
        keys.append("ua_server_timestamp"), values.append(prop(8, server))
    if keys:
        ps = b"".join(_field(1, 2, k.encode()) for k in keys) + b"".join(_field(2, 2, v) for v in values)
        body += _field(9, 2, ps)
    if value is not None:
        if datatype == 10:
            body += _field(13, 1, struct.pack("<d", value))
        elif datatype == 12:
            body += _field(15, 2, str(value).encode())
        elif datatype == 11:
            body += _field(14, 0, int(bool(value)))
    return body


def payload(seq: int | None, *metrics: bytes, timestamp: int = 1) -> bytes:
    body = _field(1, 0, timestamp) + b"".join(_field(2, 2, m) for m in metrics)
    if seq is not None:
        body += _field(3, 0, seq)
    return body


def utc(ms_: int) -> str:
    return datetime.fromtimestamp(ms_ / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
