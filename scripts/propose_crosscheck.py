"""Cross-language check of the proposal contract: an envelope written by vor-propose (Python) is read by Bifrost's
``gates command`` (Java), which shares no code with it, only the bytes.

Over a copy of the fixture registry with two fresh keys (the agent and the operator) and their command grants:
vor-propose signs a proposal from a real Vor answer; ``gates command verify`` accepts it; ``gates command approve``
co-signs it under a command policy; the approved envelope carries the agent's payload string and signature unchanged;
``gates command verify --approved`` accepts it; a copy whose input value was changed after signing is refused
``command.signature``; and Mixer1's evidence for Mixer2's Method is refused by vor-propose (``link-mismatch``) and,
signed by the agent's key outside vor-propose, by ``gates command verify`` (``command.link.mismatch``).

    python scripts/propose_crosscheck.py [--bifrost ../bifrost] [--negative-control]

Needs ``<bifrost>/gates/target/bifrost-gates.jar`` and Java 17+. Exit 0 only when every assertion ran and held.
``--negative-control`` expects the tampered copy to be accepted, so the run must fail (exit 1): that run proves the
assertions can fail.
"""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from helpers import BINDING, DEVICE, FIXTURES, TOPIC, fixture_now, metric, payload  # noqa: E402
from vor.head import IN_TOTO, pae  # noqa: E402
from vor.propose import load_key  # noqa: E402
from vor.server import Question, Vor  # noqa: E402
from vor.stream import SampleCache  # noqa: E402

OBJECT = "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1"
METHOD = OBJECT + ".SetTemperature"
OBJECT2 = "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer2"
METHOD2 = OBJECT2 + ".SetTemperature"
DEVICE2 = "synthetic-site:line1:mixer2"
CHECKS = 9


class Check:
    def __init__(self):
        self.ran = 0

    def that(self, ok: bool, what: str) -> None:
        self.ran += 1
        print(("[CHECK] OK   " if ok else "[CHECK] FAIL ") + what, flush=True)
        if not ok:
            raise SystemExit(1)


def gates(jar: Path, *args: str) -> tuple[int, dict]:
    r = subprocess.run(["java", "-jar", str(jar), "command", *args], capture_output=True, text=True)
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
    report = json.loads(lines[-1]) if lines else {"stdout": r.stdout, "stderr": r.stderr}
    return r.returncode, report


def keys(reg: Path, keydir: Path, *principals: str) -> None:
    lines = []
    for who in principals:
        k = Ed25519PrivateKey.generate()
        der = k.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        (keydir / f"{who}.key").write_text(base64.b64encode(der).decode("ascii") + "\n", encoding="utf-8")
        pub = k.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        lines.append(json.dumps({"principal": who, "publicKey": base64.b64encode(pub).decode("ascii")}))
    with (reg / "identity" / "authorized-keys.jsonl").open("a", encoding="utf-8", newline="\n") as f:
        f.write("".join(line + "\n" for line in lines))


def grants(reg: Path) -> None:
    path = reg / "identity" / "activation-policy.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["rules"] += [
        {"id": "agent-proposes", "principal": "agent", "action": "propose_command", "target": "command",
         "kind": "method", "ref": "line1"},
        {"id": "operator-co-signs", "principal": "operator", "action": "approve_command", "target": "command",
         "kind": "method", "ref": "line1"}]
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def command_policy(path: Path) -> None:
    path.write_text(json.dumps({"version": "1.0.0", "default": "deny", "rules": [
        {"id": "set-temperature", "principal": "agent",
         "target": {"group": "Bifrost:Line1", "edge": "recipe-edge-cmd", "device": DEVICE},
         "command": METHOD, "constraint": {"type": "Double", "min": 0.0, "max": 100.0}}]}), encoding="utf-8")


def evidence(reg: Path, state: Path) -> bytes:
    cache = SampleCache(clock_ms=lambda: 0)
    vor = Vor(reg, FIXTURES / "trusted-keys.jsonl", state, {"mixer1-temp": Question("mixer1-temp", "line1", BINDING, "")},
              cache)
    now = fixture_now(reg / "mappings")
    cache.on_message("spBv1.0/Bifrost:Line1/NBIRTH/recipe-edge", payload(0))
    cache.on_message(TOPIC, payload(1, metric("Temp", 21.5, timestamp=now - 100, server=now - 90)))
    return json.dumps(vor.read("mixer1-temp", now), indent=1).encode("utf-8") + b"\n"


def tamper(envelope: dict) -> dict:
    """The same envelope with the input value changed inside the signed payload and the signatures kept."""
    s = json.loads(base64.b64decode(envelope["payload"]))
    s["predicate"]["method"]["inputs"][0]["value"] = 43.0
    body = json.dumps(s, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return dict(envelope, payload=base64.b64encode(body).decode("ascii"))


def other_equipment(envelope: dict, key_file: Path) -> dict:
    """The agent's own statement re-aimed at Mixer2's Method with Mixer1's evidence, signed with the agent's key."""
    s = json.loads(base64.b64decode(envelope["payload"]))
    s["predicate"]["target"]["device"] = DEVICE2
    s["predicate"]["method"].update(objectNodeId=OBJECT2, methodNodeId=METHOD2)
    body = json.dumps(s, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sig = load_key(key_file).sign(pae(IN_TOTO, body))
    return dict(envelope, payload=base64.b64encode(body).decode("ascii"),
                signatures=[{"keyid": "agent", "sig": base64.b64encode(sig).decode("ascii")}])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bifrost", type=Path, default=ROOT.parent / "bifrost")
    ap.add_argument("--negative-control", action="store_true")
    args = ap.parse_args()
    jar = args.bifrost / "gates" / "target" / "bifrost-gates.jar"
    if not jar.is_file():
        print(f"[CHECK] FAIL missing {jar}: build it with mvn -pl gates -am package", flush=True)
        return 1

    check = Check()
    with tempfile.TemporaryDirectory(prefix="vor-propose-") as tmp:
        work = Path(tmp)
        reg = work / "registry"
        shutil.copytree(FIXTURES / "registries" / "active", reg)
        (work / "keys").mkdir()
        keys(reg, work / "keys", "agent", "operator")
        grants(reg)
        command_policy(work / "command-policy.json")
        answer = work / "answer.json"
        answer.write_bytes(evidence(reg, work / "state"))

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = subprocess.run([sys.executable, "-m", "vor.propose", str(answer), "--registry", str(reg),
                            "--by", "agent", "--by-key", str(work / "keys" / "agent.key"), "--approved-by", "operator",
                            "--group", "Bifrost:Line1", "--edge", "recipe-edge-cmd", "--device", DEVICE,
                            "--object", OBJECT, "--method", METHOD, "--input", "targetTemperature", "--value", "42",
                            "--not-before", now, "--valid-for", "600", "--out-dir", str(work / "proposals")],
                           capture_output=True, text=True)
        made = json.loads(r.stdout) if r.stdout.strip() else {}
        check.that(r.returncode == 0 and made.get("accepted") is True, f"vor-propose signed a proposal ({made})")
        proposal = Path(made["out"])

        code, rep = gates(jar, "verify", str(reg), str(proposal))
        check.that(code == 0 and rep.get("kind") == "command-proposal-verification" and rep.get("cmdId") == made["cmdId"]
                   and rep.get("value") == 42.0, f"gates command verify accepts it ({rep.get('kind')}, {rep.get('error')})")

        approved = work / "proposals" / f"{made['cmdId']}.approved.dsse.json"
        code, rep = gates(jar, "approve", str(reg), str(proposal), "--approved-by", "operator", "--approved-by-key",
                          str(work / "keys" / "operator.key"), "--policy", str(work / "command-policy.json"),
                          "--out", str(approved))
        check.that(code == 0 and approved.is_file(), f"gates command approve co-signs it ({rep.get('error')})")

        mine, theirs = json.loads(proposal.read_bytes()), json.loads(approved.read_bytes())
        check.that(theirs["payload"] == mine["payload"] and theirs["signatures"][0] == mine["signatures"][0]
                   and len(theirs["signatures"]) == 2, "approval kept the agent's payload string and signature")

        code, rep = gates(jar, "verify", str(reg), str(approved), "--approved")
        check.that(code == 0 and rep.get("kind") == "command-approved-verification",
                   f"gates command verify --approved accepts the approved envelope ({rep.get('error')})")

        forged = work / "proposals" / "forged.dsse.json"
        forged.write_text(json.dumps(tamper(mine)), encoding="utf-8")
        code, rep = gates(jar, "verify", str(reg), str(forged))
        if args.negative_control:
            check.that(code == 0, "negative control: the tampered copy is accepted")
        else:
            check.that(code == 1 and rep.get("error") == "command.signature",
                       f"a value changed after signing is refused command.signature ({rep.get('error')})")

        r = subprocess.run([sys.executable, "-m", "vor.propose", str(answer), "--registry", str(reg),
                            "--by", "agent", "--by-key", str(work / "keys" / "agent.key"), "--approved-by", "operator",
                            "--group", "Bifrost:Line1", "--edge", "recipe-edge-cmd", "--device", DEVICE2,
                            "--object", OBJECT2, "--method", METHOD2, "--input", "targetTemperature", "--value", "42",
                            "--not-before", now, "--valid-for", "600", "--out-dir", str(work / "proposals")],
                           capture_output=True, text=True)
        refused = json.loads(r.stdout) if r.stdout.strip() else {}
        check.that(r.returncode == 1 and refused.get("error") == "link-mismatch",
                   f"vor-propose refuses Mixer1 evidence for Mixer2's Method ({refused.get('error')})")

        aimed = work / "proposals" / "mixer2.dsse.json"
        aimed.write_text(json.dumps(other_equipment(mine, work / "keys" / "agent.key")), encoding="utf-8")
        code, rep = gates(jar, "verify", str(reg), str(aimed))
        check.that(code == 1 and rep.get("error") == "command.link.mismatch",
                   f"signed outside vor-propose, gates command verify refuses it command.link.mismatch ({rep.get('error')})")

        check.that(check.ran == CHECKS - 1, f"all {CHECKS - 1} assertions ran before this one")
    print(f"[CHECK] PASS propose_crosscheck ({check.ran} assertions)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
