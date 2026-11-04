"""Regenerate tests/fixtures/registries with Bifrost's own CLI.

Every byte Vor's tests verify is written by Bifrost: the vor-read bundle from Bifrost's test resources is approved
and published on stream ``line1`` with a signed head, and two more registries add a lifecycle-only release on stream
``semantics`` (deprecated, then deprecated + retired). The private keys live in a temporary directory and are
deleted; only the public keys are kept, in ``tests/fixtures/trusted-keys.jsonl``, outside the registries.

    python scripts/make_fixtures.py [--bifrost ../bifrost]

Needs ``<bifrost>/gates/target/bifrost-gates.jar`` (``mvn -pl gates -am package -DskipTests``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures"
SEMANTIC_ID = "urn:bifrost:sem:Mixer/Temp"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(doc) -> bytes:
    """The bytes Bifrost hashes a parsed document as (MappingJson.bytes: keys sorted, compact)."""
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def dump(path: Path, doc) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


class Gates:
    def __init__(self, jar: Path):
        self.jar = jar

    def __call__(self, *args: str) -> dict:
        r = subprocess.run(["java", "-jar", str(self.jar), *args], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"gates {' '.join(args[:2])} failed ({r.returncode}): {r.stdout}{r.stderr}")
        last = [line for line in r.stdout.splitlines() if line.strip()][-1]
        return json.loads(last) if last.startswith("{") else {}


def policy(streams: list[str]) -> dict:
    rules = []
    for s in streams:
        rules.append({"id": f"publish-{s}", "principal": "proposer", "action": "publish",
                      "target": "mapping-publication", "kind": "mapping-release", "ref": s})
        rules.append({"id": f"approve-{s}", "principal": "approver", "action": "approve",
                      "target": "mapping-publication", "kind": "mapping-release", "ref": s})
    return {"version": "1.0.0", "default": "deny", "rules": rules}


def lifecycle_bundle(dest: Path, semantics: Path, signature_sha: str, actions: list[str]) -> None:
    """A lifecycle-only proposal: the semantic definition the events are about (the same bytes as vor-read's, which a
    bundle is validated against on its own) and one semantic-lifecycle event per action, chained by previousEvent."""
    (dest / "semantics").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(semantics, dest / "semantics" / "0.json")
    defn = json.loads(semantics.read_bytes())
    files = [{"path": "semantics/0.json", "kind": "semantic-definition", "id": defn["id"], "version": defn["version"],
              "sha256": sha(semantics.read_bytes())}]
    previous = None
    for n, action in enumerate(actions, start=1):
        event = {"kind": "semantic-lifecycle", "schemaVersion": "2.18.0", "id": f"mixer-temp-{action}",
                 "version": "1.0.0", "semanticId": SEMANTIC_ID, "revision": n, "previousEvent": previous,
                 "signatureSha256": signature_sha, "action": action, "replacementSemanticId": None,
                 "label": "Mixer process temperature", "description": "Synthetic lifecycle event",
                 "reason": "Synthetic fixture; not field evidence", "authoredBy": "fixture-author",
                 "authoredAt": f"2026-11-01T00:00:0{n}Z"}
        rel = f"lifecycle/{n - 1}.json"
        dump(dest / rel, event)
        files.append({"path": rel, "kind": "semantic-lifecycle", "id": event["id"], "version": "1.0.0",
                      "sha256": sha((dest / rel).read_bytes())})
        previous = {"id": event["id"], "version": "1.0.0", "sha256": sha(compact(event))}
    dump(dest / "proposal.json", {"kind": "mapping-proposal", "schemaVersion": "2.23.0", "id": "semantics-workspace",
                                  "version": "1.0.0", "baseRelease": None, "files": files})
    p = sha((dest / "proposal.json").read_bytes())
    dump(dest / "submission.json", {"kind": "mapping-submission", "schemaVersion": "2.9.0", "id": "semantics",
                                    "streamId": "semantics", "version": "1.0.0", "workspaceSha256": p,
                                    "proposalSha256": p, "baseRelease": None, "proposedBy": "proposer",
                                    "execution": "excluded",
                                    "context": {"equipment": [{"id": "mixer1", "label": "Mixer 1"}],
                                                "connections": []}})


class Publisher:
    """Fresh proposer/approver keys and Bifrost's CLI: publishes the vor-read release on stream ``line1`` and
    lifecycle-only releases on stream ``semantics`` into a registry. The private keys stay in ``keys``."""

    def __init__(self, gates: Gates, source: Path, work: Path):
        self.gates, self.source, self.work = gates, source, work
        self.keys = work / "keys"
        lines = []
        for principal in ("proposer", "approver"):
            gates("identity", "keygen", principal, "--out", str(self.keys))
            pub = (self.keys / f"{principal}.pub").read_text().strip()
            lines.append(json.dumps({"principal": principal, "publicKey": pub}))
        self.authorized = "\n".join(lines) + "\n"
        self.signers = ["--by", "proposer", "--by-key", str(self.keys / "proposer.key"),
                        "--approved-by", "approver", "--approved-by-key", str(self.keys / "approver.key")]

    def registry(self, r: Path) -> Path:
        (r / "identity").mkdir(parents=True)
        (r / "identity" / "authorized-keys.jsonl").write_text(self.authorized, newline="
")
        dump(r / "identity" / "activation-policy.json", policy(["line1", "semantics"]))
        bundle = self.work / f"{r.name}-vor-read"
        shutil.copytree(self.source, bundle)
        self.gates("mapping", "approve", str(r), str(bundle), "approval-vor-read", *self.signers)
        self.gates("mapping", "publish", str(r), str(bundle), "vor-read", "1.0.0", "--approval", "approval-vor-read",
                   *self.signers)
        return r

    def add_lifecycle(self, r: Path, actions: list[str]) -> None:
        catalog = self.gates("mapping", "lifecycle", str(r))
        entry = next(e for e in catalog["entries"] if e["semanticId"] == SEMANTIC_ID)
        bundle = self.work / f"{r.name}-semantics"
        lifecycle_bundle(bundle, self.source / "semantics" / "0.json", sha(compact(entry["signature"])), actions)
        self.gates("mapping", "approve", str(r), str(bundle), "approval-semantics", *self.signers)
        self.gates("mapping", "publish", str(r), str(bundle), "semantics", "1.0.0", "--approval",
                   "approval-semantics", *self.signers)


def vor_read_source(bifrost: Path) -> Path:
    return bifrost / "core" / "src" / "test" / "resources" / "mapping-fixtures" / "vor-read"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bifrost", type=Path, default=ROOT.parent / "bifrost")
    a = ap.parse_args()
    gates = Gates(a.bifrost / "gates" / "target" / "bifrost-gates.jar")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        pub = Publisher(gates, vor_read_source(a.bifrost), tmp)
        built = {name: pub.registry(tmp / name) for name in ("active", "deprecated", "retired")}
        pub.add_lifecycle(built["deprecated"], ["deprecate"])
        pub.add_lifecycle(built["retired"], ["deprecate", "retire"])

        target = OUT / "registries"
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        for name, r in built.items():
            shutil.copytree(r, target / name, ignore=shutil.ignore_patterns(".lock"))
        (OUT / "trusted-keys.jsonl").write_text(pub.authorized, newline="
")
    print(f"wrote {target} and {OUT / 'trusted-keys.jsonl'}")


if __name__ == "__main__":
    main()
