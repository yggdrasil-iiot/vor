"""The published command binding a proposal must name (mapping contract 2.25.0): the release's one link whose read
binding's device is the proposal's ``target.device`` and whose Method is the proposal's ``methodNodeId``.

Vor resolves the link from the pinned release on its own, as Bifrost's approval and Heimdall each do in theirs: no
code is shared, only the published bytes. Every file it reads is checked against the digest release.json records for
it. No link for the key is ``link-missing``, more than one ``link-ambiguous``, and a link the proposal or its evidence
does not agree with ``link-mismatch``, with the differing field as the detail.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path

from .refusal import sha256

KIND = "command-binding"
PROFILE_FIELDS = {"profileVersion", "streamId", "mappingSetRef", "mappingId", "equipmentInstanceId", "semanticId",
                  "group", "edge", "device", "metric", "governedDefinitionRef", "projection"}
SHA = re.compile(r"[0-9a-f]{64}")


class LinkRefused(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(code)
        self.code, self.detail = code, detail


@dataclass(frozen=True)
class Link:
    id: str
    version: str
    group: str
    edge: str
    object_node_id: str
    method_node_id: str
    input_name: str
    input_type: str
    profile: dict
    binding_path: str
    binding_sha256: str
    mapping_set_path: str


class _Release:
    """A published release as read here: its directory, its root under mappings/, and release.json's files."""

    def __init__(self, mappings: Path, root: str):
        self.dir, self.root = mappings / root, root
        doc = json.loads((self.dir / "release.json").read_bytes())
        self.files = {f.get("path"): f.get("sha256") for f in doc.get("files", []) if isinstance(f, dict)}

    def bytes(self, path: str, code: str, detail: str) -> bytes:
        if path not in self.files or posixpath.normpath(path) != path or path.startswith(("/", "../")):
            raise LinkRefused(code, detail)
        try:
            data = (self.dir / path).read_bytes()
        except OSError:
            raise LinkRefused(code, detail)
        if sha256(data) != self.files[path]:
            raise LinkRefused(code, detail)
        return data

    def json(self, path: str, code: str, detail: str):
        try:
            return json.loads(self.bytes(path, code, detail))
        except ValueError:
            raise LinkRefused(code, detail)


def _text(doc, *keys: str) -> str:
    for k in keys:
        doc = doc.get(k) if isinstance(doc, dict) else None
    return doc if isinstance(doc, str) else ""


def profile(data: bytes) -> dict:
    """A Vor read binding, profile 0.1.0, or ValueError: exactly its twelve fields, each of its type."""
    b = json.loads(data)
    if not isinstance(b, dict) or set(b) != PROFILE_FIELDS:
        raise ValueError("fields")
    if b["profileVersion"] != "0.1.0" or b["projection"] != "identity":
        raise ValueError("version")
    for k in ("streamId", "mappingId", "equipmentInstanceId", "semanticId", "group", "edge", "device", "metric"):
        if not isinstance(b[k], str) or not b[k]:
            raise ValueError(k)
    s, d = b["mappingSetRef"], b["governedDefinitionRef"]
    if not (isinstance(s, dict) and set(s) == {"id", "version"} and _text(s, "id") and _text(s, "version")):
        raise ValueError("mappingSetRef")
    if not (isinstance(d, dict) and set(d) == {"templateRef", "version", "sha256"} and _text(d, "templateRef")
            and _text(d, "version") and SHA.fullmatch(_text(d, "sha256"))):
        raise ValueError("governedDefinitionRef")
    return b


def resolve(mappings: Path, root: str, device: str, method_node_id: str) -> Link:
    """The one link for (device, methodNodeId) in the release at ``mappings/<root>``."""
    r = _Release(mappings, root)
    listing = r.json("payload/proposal.json", "link-missing", "release")
    evidence, sets, links = {}, {}, []
    for e in listing.get("files", []) if isinstance(listing, dict) else []:
        key, path = f"{_text(e, 'id')}@{_text(e, 'version')}", "payload/" + _text(e, "path")
        kind = _text(e, "kind")
        if kind == "evidence-artifact":
            evidence[key] = r.json(path, "link-mismatch", "release-file")
        elif kind == "mapping-set":
            sets[key] = path
        elif kind == KIND:
            links.append(r.json(path, "link-mismatch", "release-file"))
    hits = []
    for link in links:
        ev = evidence.get(f"{_text(link, 'readBindingRef', 'id')}@{_text(link, 'readBindingRef', 'version')}")
        if ev is None:
            raise LinkRefused("link-mismatch", "readBindingRef")
        data = "payload/" + _text(ev, "file", "path")
        if _text(ev, "file", "sha256") != r.files.get(data):
            raise LinkRefused("link-mismatch", "binding.file")
        try:
            b = profile(r.bytes(data, "link-mismatch", "binding.file"))
        except ValueError:
            raise LinkRefused("link-mismatch", "binding.profile")
        m = link.get("method") if isinstance(link.get("method"), dict) else {}
        if b["device"] != device or _text(m, "methodNodeId") != method_node_id:
            continue
        inputs = m.get("inputs") if isinstance(m.get("inputs"), list) else []
        mapping_set = sets.get(f"{b['mappingSetRef']['id']}@{b['mappingSetRef']['version']}")
        if mapping_set is None:
            raise LinkRefused("link-mismatch", "binding.mappingSetRef")
        if len(inputs) != 1:
            raise LinkRefused("link-mismatch", "method.inputs")
        hits.append(Link(_text(link, "id"), _text(link, "version"), _text(link, "command", "group"),
                         _text(link, "command", "edge"), _text(m, "objectNodeId"), _text(m, "methodNodeId"),
                         _text(inputs[0], "name"), _text(inputs[0], "type"), b, data, r.files[data], mapping_set))
    if not hits:
        raise LinkRefused("link-missing", "device+methodNodeId")
    if len(hits) > 1:
        raise LinkRefused("link-ambiguous", "device+methodNodeId")
    return hits[0]


def match(root: str, link: Link, answer: dict, *, group: str, edge: str, device: str, object_node_id: str,
          method_node_id: str, input_name: str) -> None:
    """The proposal and its evidence say what the link says: the device, the evidence bound to the released
    read-binding bytes and fields, the command node, and the Method's signature. The value is the policy's to bound."""
    b = link.profile
    _that(b["device"] == device, "device")
    eb = answer.get("binding") if isinstance(answer.get("binding"), dict) else {}
    pin = answer.get("pin") if isinstance(answer.get("pin"), dict) else {}
    _that(_text(eb, "source", "sha256") == link.binding_sha256
          and _text(eb, "source", "file") == f"mappings/{root}/{link.binding_path}", "binding.source")
    for field in ("group", "edge", "device", "metric"):
        _that(_text(eb, field) == b[field], f"binding.{field}")
    d = b["governedDefinitionRef"]
    _that(all(_text(eb, "governedDefinitionRef", k) == d[k] for k in ("templateRef", "version", "sha256")),
          "binding.governedDefinitionRef")
    _that(_text(pin, "field_id") == b["mappingId"], "pin.field_id")
    _that(_text(pin, "file") == link.mapping_set_path, "pin.file")
    _that(group == link.group and edge == link.edge, "command")
    _that(object_node_id == link.object_node_id, "method.objectNodeId")
    _that(method_node_id == link.method_node_id, "method.methodNodeId")
    _that(input_name == link.input_name and link.input_type == "Double", "method.inputs")


def _that(ok: bool, detail: str) -> None:
    if not ok:
        raise LinkRefused("link-mismatch", detail)
