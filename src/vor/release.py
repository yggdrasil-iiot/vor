"""Reads a Bifrost mapping registry from raw bytes: head -> release.json -> payload files, each by SHA-256, then
resolves Vor's read binding against the released documents.

The read binding is an evidence-artifact in the release whose data file names the governed field (mapping set,
mapping, semanticId) and where Muninn publishes it (Sparkplug group, edge, device, metric). Every reference must
resolve to a document in the same release and agree with it. Meaning lifecycle is registry-wide: Bifrost refuses to
publish a binding to a retired meaning, so a retirement arrives as a lifecycle-only release, usually on another stream.
Vor replays the semantic-lifecycle events of every stream whose head verifies; a head that does not verify makes the
answer refuse, since Vor could then not tell whether the meaning was retired.
"""

from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass, field
from pathlib import Path

from .head import FloorStore, Head, TrustedKeys, verify_head
from .refusal import Refusal, sha256

UNIT_CODES = {"rpm", "Cel", "N.m", "1", "1/s", "mN.m", "K", "Pa", "kPa", "bar"}
POLICY_ENUMS = {"timestampBasis": {"source", "server"}, "uncertainInput": {"propagate", "reject"},
                "missingInput": {"reject"}, "badInput": {"propagate"}, "assembly": {"latest", "trigger-sequence"}}
BINDING_FIELDS = {"profileVersion", "streamId", "mappingSetRef", "mappingId", "equipmentInstanceId", "semanticId",
                  "group", "edge", "device", "metric", "governedDefinitionRef", "projection"}


@dataclass(frozen=True)
class Release:
    head: Head
    root: str
    doc: dict
    files: dict[str, str]
    documents: dict[tuple[str, str], tuple[str, dict]] = field(default_factory=dict)

    def document(self, kind: str, ref: dict) -> tuple[str, dict]:
        found = self.documents.get((kind, ref.get("id") if isinstance(ref, dict) else None))
        if found is None or found[1].get("version") != ref.get("version"):
            raise Refusal("binding-invalid", rule=f"{kind}-missing", ref=ref)
        return found

    def of_kind(self, kind: str) -> list[tuple[str, dict]]:
        return [v for (k, _), v in self.documents.items() if k == kind]


def _mismatch(rule: str, file: str, expected, computed) -> Refusal:
    return Refusal("provenance-mismatch", rule=rule, file=file, expected=expected, computed=computed)


def verify_release(mappings: Path, head: Head) -> Release:
    root = f"releases/{head.release_id}/{head.version}"
    release_file = f"{root}/release.json"
    try:
        raw = (mappings / release_file).read_bytes()
    except FileNotFoundError:
        raise _mismatch("release-missing", f"mappings/{release_file}", head.release_sha256, None)
    if sha256(raw) != head.release_sha256:
        raise _mismatch("release-digest", f"mappings/{release_file}", head.release_sha256, sha256(raw))
    doc = json.loads(raw)
    if doc.get("id") != head.release_id or doc.get("version") != head.version or doc.get("streamId") != head.stream:
        raise _mismatch("release-identity", f"mappings/{release_file}", [head.stream, head.release_id, head.version],
                        [doc.get("streamId"), doc.get("id"), doc.get("version")])

    files: dict[str, str] = {}
    for entry in doc.get("files", []):
        path = entry.get("path", "")
        norm = posixpath.normpath(path)
        if norm != path or not path.startswith("payload/") or path in files:
            raise _mismatch("release-path", path, None, None)
        try:
            data = (mappings / root / path).read_bytes()
        except FileNotFoundError:
            raise _mismatch("release-file", f"mappings/{root}/{path}", entry.get("sha256"), None)
        if sha256(data) != entry.get("sha256"):
            raise _mismatch("release-file", f"mappings/{root}/{path}", entry.get("sha256"), sha256(data))
        files[path] = entry["sha256"]

    release = Release(head=head, root=root, doc=doc, files=files)
    proposal = release_json(mappings, release, "payload/proposal.json")
    for entry in proposal.get("files", []):
        path = "payload/" + entry.get("path", "")
        if files.get(path) != entry.get("sha256"):
            raise _mismatch("proposal-file", f"mappings/{root}/{path}", entry.get("sha256"), files.get(path))
        release.documents[(entry.get("kind"), entry.get("id"))] = (path, release_json(mappings, release, path))
    return release


def release_json(mappings: Path, release: Release, path: str) -> dict:
    """A payload file already checked against release.json, parsed."""
    if path not in release.files:
        raise _mismatch("unlisted", f"mappings/{release.root}/{path}", None, None)
    return json.loads((mappings / release.root / path).read_bytes())


@dataclass(frozen=True)
class Meaning:
    semantic_id: str
    state: str
    replacement: str | None
    revision: int
    sources: list[dict]


def lifecycle(mappings: Path, trusted: TrustedKeys, floors: FloorStore, now_ms: int, semantic_id: str) -> Meaning:
    """The meaning's state replayed from the semantic-lifecycle events of every verified stream head.

    A stream whose head was accepted before stays in the set even if its head files disappear: the missing head then
    fails verification, so deleting a head cannot hide a lifecycle event (a retirement) it carried."""
    events: dict[str, tuple[dict, dict]] = {}
    streams = {f.stem for f in (mappings / "heads").glob("*.json")} | floors.streams()
    for stream in sorted(streams):
        head = verify_head(mappings, stream, trusted, floors, now_ms)
        release = verify_release(mappings, head)
        for path, doc in release.of_kind("semantic-lifecycle"):
            if doc.get("semanticId") != semantic_id:
                continue
            key = f"{doc.get('id')}@{doc.get('version')}"
            if key in events and events[key][0] != doc:
                raise _mismatch("lifecycle-event-conflict", path, None, None)
            events[key] = (doc, {"file": f"mappings/{release.root}/{path}", "sha256": release.files[path]})
    history = sorted(events.values(), key=lambda e: e[0].get("revision", 0))
    state, replacement = "active", None
    for n, (doc, _) in enumerate(history, start=1):
        if doc.get("revision") != n:
            raise _mismatch("lifecycle-revision", doc.get("id"), n, doc.get("revision"))
        action = doc.get("action")
        if action == "deprecate" and state == "active":
            state = "deprecated"
        elif action == "retire" and state == "deprecated":
            state = "retired"
        elif action != "revise":
            raise _mismatch("lifecycle-transition", doc.get("id"), state, action)
        if action != "revise" or doc.get("replacementSemanticId") is not None:
            replacement = doc.get("replacementSemanticId")
    return Meaning(semantic_id, state, replacement, len(history), [s for _, s in history])


@dataclass(frozen=True)
class Governed:
    """Everything the release says about the bound field, verified, before any sample is looked at."""
    question_id: str
    release: Release
    binding: dict
    binding_source: dict
    mapping_file: str
    mapping_id: str
    member: dict
    unit: dict
    policy: dict | None
    isa95_path: str
    isa95_levels: list[dict]
    hierarchy_source: dict
    meaning: Meaning

    def release_source(self, path: str) -> dict:
        return _source(self.release, path)


def _invalid(rule: str, **more) -> Refusal:
    return Refusal("binding-invalid", rule=rule, **more)


def _source(release: Release, path: str) -> dict:
    return {"file": f"mappings/{release.root}/{path}", "sha256": release.files[path]}


def resolve(mappings: Path, release: Release, question_id: str, binding_id: str, meaning_of) -> Governed:
    """The read binding `binding_id` checked against every document it names. `meaning_of(semanticId)` returns the
    lifecycle state; it runs only after the binding resolves, so a bad binding is reported as such first."""
    ev = release.documents.get(("evidence-artifact", binding_id))
    if ev is None:
        raise _invalid("binding-missing", bindingId=binding_id)
    ev_path, ev_doc = ev
    data_path = "payload/" + str((ev_doc.get("file") or {}).get("path", ""))
    if data_path not in release.files or release.files[data_path] != (ev_doc.get("file") or {}).get("sha256"):
        raise _mismatch("binding-file", f"mappings/{release.root}/{data_path}",
                        (ev_doc.get("file") or {}).get("sha256"), release.files.get(data_path))
    try:
        b = release_json(mappings, release, data_path)
    except ValueError:
        raise _invalid("binding-json")
    if set(b) != BINDING_FIELDS or b.get("profileVersion") != "0.1.0":
        raise _invalid("binding-fields", missing=sorted(BINDING_FIELDS - set(b)), extra=sorted(set(b) - BINDING_FIELDS))
    if b["projection"] != "identity":
        raise _invalid("projection", projection=b["projection"])
    if b["streamId"] != release.head.stream:
        raise _invalid("stream", binding=b["streamId"], head=release.head.stream)

    set_path, mset = release.document("mapping-set", b["mappingSetRef"])
    if mset.get("equipmentInstanceId") != b["equipmentInstanceId"]:
        raise _invalid("equipment", binding=b["equipmentInstanceId"], mappingSet=mset.get("equipmentInstanceId"))
    mapping = next((m for m in mset.get("mappings", []) if m.get("mappingId") == b["mappingId"]), None)
    if mapping is None:
        raise _invalid("mapping-missing", mappingId=b["mappingId"])
    steps = mapping.get("memberPath") or []
    if len(steps) != 1 or steps[0].get("kind") != "member":
        raise _invalid("member-path", memberPath=steps)
    _, target = release.document("target-instance", mset.get("targetInstanceRef") or {})
    if target.get("equipmentInstanceId") != b["equipmentInstanceId"]:
        raise _invalid("target-equipment", target=target.get("equipmentInstanceId"))
    _, model = release.document("semantic-definition", target.get("semanticDefinitionRef") or {})
    member = next((m for m in model.get("members", []) if m.get("memberId") == steps[0].get("memberId")), None)
    if member is None:
        raise _invalid("member-missing", memberId=steps[0].get("memberId"))
    if member.get("semanticId") != b["semanticId"]:
        raise _invalid("semantic-id", binding=b["semanticId"], member=member.get("semanticId"))
    if member.get("name") != b["metric"]:
        raise _invalid("metric", binding=b["metric"], member=member.get("name"))
    value_ref = mapping.get("valueRef") or {}
    if value_ref.get("kind") != "source":
        raise _invalid("value-ref", kind=value_ref.get("kind"))
    _, source = release.document("source-definition", value_ref.get("sourceRef") or {})
    access = source.get("access") or {}
    # Muninn names a metric by the member's browse name, the last segment of the OPC UA node identifier.
    if access.get("kind") != "opcua-node" or not str(access.get("identifier", "")).endswith("." + b["metric"]):
        raise _invalid("source-node", access=access)
    if mapping.get("outputUnit") != member.get("unit"):
        raise _invalid("output-unit", mapping=mapping.get("outputUnit"), member=member.get("unit"))

    hierarchies = release.of_kind("equipment-hierarchy")
    if len(hierarchies) != 1:
        raise _invalid("hierarchy-count", count=len(hierarchies))
    h_path, h = hierarchies[0]
    nodes = {n.get("equipmentInstanceId"): n for n in h.get("nodes", [])}
    chain, cursor = [], b["equipmentInstanceId"]
    while cursor is not None:
        if cursor not in nodes or len(chain) > 64:
            raise _invalid("hierarchy-path", at=cursor)
        chain.insert(0, nodes[cursor])
        cursor = nodes[cursor].get("parentEquipmentInstanceId")
    path = ":".join(n["equipmentInstanceId"] for n in chain)
    if b["device"] != path:
        raise _invalid("device", binding=b["device"], hierarchy=path)

    return Governed(question_id=question_id, release=release, binding=b, binding_source=_source(release, data_path),
                    mapping_file=set_path, mapping_id=b["mappingId"], member=member, unit=member.get("unit") or {},
                    policy=mapping.get("temporalPolicy"), isa95_path=path,
                    isa95_levels=[{"equipmentInstanceId": n["equipmentInstanceId"],
                                   "equipmentLevel": n.get("equipmentLevel")} for n in chain],
                    hierarchy_source=_source(release, h_path), meaning=meaning_of(b["semanticId"]))


def policy_valid(policy) -> bool:
    if not isinstance(policy, dict):
        return False
    for name in ("maxAgeMs", "maxSkewMs"):
        v = policy.get(name)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return False
    return all(policy.get(k) in allowed for k, allowed in POLICY_ENUMS.items())


def load(mappings: Path, trusted: TrustedKeys, floors: FloorStore, now_ms: int,
         question_id: str, stream: str, binding_id: str) -> Governed:
    """Head, release and binding of one question, verified in the order of the refusal table."""
    head = verify_head(mappings, stream, trusted, floors, now_ms)
    release = verify_release(mappings, head)
    return resolve(mappings, release, question_id, binding_id,
                   lambda semantic_id: lifecycle(mappings, trusted, floors, now_ms, semantic_id))
