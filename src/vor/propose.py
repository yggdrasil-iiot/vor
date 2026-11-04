"""vor-propose: the agent's half of a governed write. It turns one usable ``read_governed`` answer into a command
proposal that names one OPC UA Method call, and signs it with the agent's own key; nothing reaches the plant until a
named approver co-signs the same bytes with ``gates command approve`` and Heimdall re-checks everything at the edge.

The proposal is a DSSE v1 envelope around an in-toto Statement v1 whose predicate is Bifrost's
``command-proposal/v2``. Its three subjects pin, by raw-byte SHA-256, the stream head file, the release.json it names
and the evidence: the answer exactly as Vor returned it, carried base64 so no re-serialization can change a byte.
This is a separate process from the MCP server on purpose: the server holds no key, so a prompt that steers a tool
call cannot obtain a signature.

``target.group`` and ``target.edge`` name the command node; ``target.device`` names the governed equipment by the
Sparkplug device id its data edge publishes (the ISA-95 path, for example ``synthetic-site:line1:mixer1``). The call
must be the one the pinned release's command binding links to the evidence's read binding (``vor.link``).

    vor-propose <evidence.json> --registry <dir> --by <principal> --by-key <file> --approved-by <principal>
                --group <g> --edge <e> --device <d> --object <nodeId> --method <nodeId>
                --input <name> --value <v> [--not-before <instant>] [--valid-for <s>] [--out-dir proposals]

Refuses (exit 1, a JSON ``proposal-refusal`` with ``error``) rather than sign a proposal Bifrost would refuse or that
the evidence does not support. Exit 2 is usage.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import math
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key

from .head import IN_TOTO, STATEMENT, STREAM, instant, pae
from .link import LinkRefused, match, resolve
from .refusal import sha256

PREDICATE = "https://github.com/yggdrasil-iiot/bifrost/attestation/command-proposal/v2"
MAX_WINDOW = timedelta(minutes=15)
NODE_ID = re.compile(r"nsu=[^;]+;s=.+")


class ProposalRefused(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail


def load_key(path: Path) -> Ed25519PrivateKey:
    """A key file as Bifrost writes one: base64 PKCS#8 DER on one line."""
    try:
        key = load_der_private_key(base64.b64decode(path.read_text(encoding="utf-8").strip(), validate=True), None)
    except (OSError, ValueError, binascii.Error) as e:
        raise ProposalRefused("key", str(e)) from e
    if not isinstance(key, Ed25519PrivateKey):
        raise ProposalRefused("key", "not an Ed25519 key")
    return key


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def propose(evidence: bytes, registry: Path, *, proposed_by: str, key: Ed25519PrivateKey, approved_by: str,
            group: str, edge: str, device: str, object_node_id: str, method_node_id: str, input_name: str,
            value: float, not_before: str, not_after: str, cmd_id: str | None = None) -> tuple[str, bytes]:
    """The signed proposal envelope for one call, or ProposalRefused. ``evidence`` is the raw answer bytes."""
    try:
        doc = json.loads(evidence)
    except (UnicodeDecodeError, ValueError) as e:
        raise ProposalRefused("evidence-malformed", str(e)) from e
    if not isinstance(doc, dict) or not isinstance(doc.get("verdict"), dict):
        raise ProposalRefused("evidence-malformed", "not a read_governed answer")
    if doc["verdict"].get("usable") is not True:
        raise ProposalRefused("evidence-unusable", str(doc["verdict"].get("status")))
    if not isinstance(doc.get("answer"), dict):
        raise ProposalRefused("evidence-malformed", "a usable verdict without an answer")
    answer = doc["answer"]
    pin = answer.get("pin") if isinstance(answer.get("pin"), dict) else {}
    stream = pin.get("stream_id")
    if not isinstance(stream, str) or not STREAM.fullmatch(stream):
        raise ProposalRefused("evidence-malformed", "pin.stream_id")

    # The head this registry serves now must be the one the evidence was read under; a proposal bound to anything
    # else is refused by approval and by the edge, so it is not signed here either.
    head_bytes = _read(registry / "mappings" / "heads" / f"{stream}.json")
    try:
        head = json.loads(head_bytes)
    except ValueError as e:
        raise ProposalRefused("head-mismatch", f"heads/{stream}.json: {e}") from e
    if not isinstance(head, dict):
        raise ProposalRefused("head-mismatch", f"heads/{stream}.json is not a head")
    if (head.get("id"), head.get("version"), head.get("sha256")) != (
            pin.get("release_id"), pin.get("version"), pin.get("release_sha256")):
        raise ProposalRefused("head-mismatch", f"head {head.get('id')} {head.get('version')} is not the pinned release")
    release_name = f"releases/{head['id']}/{head['version']}/release.json"
    if sha256(_read(registry / "mappings" / release_name)) != head["sha256"]:
        raise ProposalRefused("head-mismatch", f"{release_name} does not match the head")

    if proposed_by == approved_by or not proposed_by or not approved_by:
        raise ProposalRefused("same-principal", "proposer and approver must be two named principals")
    for node in (object_node_id, method_node_id):
        if not NODE_ID.fullmatch(node):
            raise ProposalRefused("node-id", f"{node}: expected nsu=<namespaceUri>;s=<identifier>")
    if not input_name or not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise ProposalRefused("input", "one named input with a finite numeric value")
    try:
        nb, na = instant(not_before), instant(not_after)
    except ValueError as e:
        raise ProposalRefused("window", f"not an instant: {e}") from e
    if not nb < na or na - nb > MAX_WINDOW:
        raise ProposalRefused("window", "notBefore must precede notAfter by at most 15 minutes")
    for part in (group, edge, device):
        if not part:
            raise ProposalRefused("target", "group, edge and device are required")

    # Evidence read from one equipment authorizes a Method of that equipment only: the published link says which.
    root = f"releases/{head['id']}/{head['version']}"
    try:
        link = resolve(registry / "mappings", root, device, method_node_id)
        match(root, link, answer, group=group, edge=edge, device=device, object_node_id=object_node_id,
              method_node_id=method_node_id, input_name=input_name)
    except LinkRefused as r:
        raise ProposalRefused(r.code, r.detail) from r

    cmd_id = cmd_id or str(uuid.uuid4())
    statement = {
        "_type": STATEMENT,
        "subject": [
            {"name": f"heads/{stream}.json", "digest": {"sha256": sha256(head_bytes)}},
            {"name": release_name, "digest": {"sha256": head["sha256"]}},
            {"name": "evidence", "digest": {"sha256": sha256(evidence)}},
        ],
        "predicateType": PREDICATE,
        "predicate": {
            "cmdId": cmd_id,
            "streamId": stream,
            "target": {"group": group, "edge": edge, "device": device},
            "method": {"objectNodeId": object_node_id, "methodNodeId": method_node_id,
                       "inputs": [{"name": input_name, "type": "Double", "value": float(value)}]},
            "validity": {"notBefore": not_before, "notAfter": not_after},
            "proposedBy": proposed_by,
            "approvedBy": approved_by,
            "evidence": {"mediaType": "application/json", "base64": base64.b64encode(evidence).decode("ascii")},
        },
    }
    payload = json.dumps(statement, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sig = key.sign(pae(IN_TOTO, payload))
    envelope = {"payload": base64.b64encode(payload).decode("ascii"), "payloadType": IN_TOTO,
                "signatures": [{"keyid": proposed_by, "sig": base64.b64encode(sig).decode("ascii")}]}
    return cmd_id, json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as e:
        raise ProposalRefused("head-mismatch", f"{path.name}: {e.strerror}") from e


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vor-propose", description="Sign a governed write proposal for co-signing.")
    ap.add_argument("evidence", type=Path, help="the read_governed answer, as Vor returned it")
    ap.add_argument("--registry", type=Path, required=True, help="the Bifrost registry Vor reads (holds mappings/)")
    ap.add_argument("--by", required=True, help="the proposing agent's principal")
    ap.add_argument("--by-key", type=Path, required=True, help="the agent's key file (base64 PKCS#8)")
    ap.add_argument("--approved-by", required=True, help="the principal who must co-sign")
    ap.add_argument("--group", required=True, help="the command node's Sparkplug group")
    ap.add_argument("--edge", required=True, help="the command node's Sparkplug edge id")
    ap.add_argument("--device", required=True, help="the equipment's Sparkplug device id (its ISA-95 path)")
    ap.add_argument("--object", required=True, help="objectNodeId, nsu=<uri>;s=<id>")
    ap.add_argument("--method", required=True, help="methodNodeId, nsu=<uri>;s=<id>")
    ap.add_argument("--input", required=True, help="the input argument's name")
    ap.add_argument("--value", type=float, required=True)
    ap.add_argument("--not-before", help="UTC instant, default now")
    ap.add_argument("--valid-for", type=int, default=900, help="seconds, at most 900 (default 900)")
    ap.add_argument("--out-dir", type=Path, default=Path("proposals"))
    args = ap.parse_args(argv)

    try:
        not_before = args.not_before or iso(datetime.now(timezone.utc))
        try:
            not_after = iso(instant(not_before) + timedelta(seconds=args.valid_for))
        except ValueError as e:
            raise ProposalRefused("window", f"not an instant: {e}") from e
        try:
            evidence = args.evidence.read_bytes()
        except OSError as e:
            raise ProposalRefused("evidence-malformed", f"{args.evidence}: {e.strerror}") from e
        cmd_id, envelope = propose(
            evidence, args.registry, proposed_by=args.by, key=load_key(args.by_key), approved_by=args.approved_by,
            group=args.group, edge=args.edge, device=args.device, object_node_id=args.object,
            method_node_id=args.method, input_name=args.input, value=args.value, not_before=not_before,
            not_after=not_after)
        args.out_dir.mkdir(parents=True, exist_ok=True)
        out = args.out_dir / f"{cmd_id}.dsse.json"
        try:
            with out.open("xb") as f:
                f.write(envelope)
        except FileExistsError as e:
            raise ProposalRefused("out-exists", str(out)) from e
    except ProposalRefused as r:
        print(json.dumps({"kind": "proposal-refusal", "accepted": False, "error": r.code, "detail": r.detail}))
        return 1
    print(json.dumps({"kind": "proposal", "accepted": True, "cmdId": cmd_id, "out": str(out),
                      "notBefore": not_before, "notAfter": not_after}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
