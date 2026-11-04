"""vor-propose: the envelope Bifrost's parser expects, signed over exact PAE bytes, pinned to the head the evidence was
read under; and every refusal it makes instead of signing. The evidence is a real Vor answer over the fixture
registry, so the bytes the proposal carries are the bytes an agent would have."""

import base64
import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from helpers import (BINDING, DEVICE, FIXTURES, TOPIC, Keys, edit_json, fixture_now, metric, payload, republish, sha,
                     sign_head)
from vor.head import IN_TOTO, pae
from vor.propose import PREDICATE, ProposalRefused, main, propose
from vor.server import Question, Vor
from vor.stream import SampleCache

REGISTRY = FIXTURES / "registries" / "active"
OBJECT = "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1"
METHOD = OBJECT + ".SetTemperature"
OBJECT2 = "nsu=urn:bifrost:opcua:sim;s=Line1/Mixer2"
METHOD2 = OBJECT2 + ".SetTemperature"
DEVICE2 = "synthetic-site:line1:mixer2"
# Bifrost CommandProposal.parse: exactly these predicate fields.
FIELDS = {"cmdId", "streamId", "target", "method", "validity", "proposedBy", "approvedBy", "evidence"}


def evidence(tmp_path, quality_bad=False, registry=REGISTRY, trusted=FIXTURES / "trusted-keys.jsonl") -> bytes:
    cache = SampleCache(clock_ms=lambda: 0)
    vor = Vor(registry, trusted, tmp_path / "state",
              {"mixer1-temp": Question("mixer1-temp", "line1", BINDING, "")}, cache)
    now = fixture_now(registry / "mappings")
    cache.on_message("spBv1.0/Bifrost:Line1/NBIRTH/recipe-edge", payload(0))
    bad = {"status": 0x808B0000, "quality": 0} if quality_bad else {}
    cache.on_message(TOPIC, payload(1, metric("Temp", 21.5, timestamp=now - 100, server=now - 90, **bad)))
    # Indented and newline-terminated, as a host might save it: any re-serialization would change these bytes.
    return json.dumps(vor.read("mixer1-temp", now), indent=1).encode("utf-8") + b"\n"


def args(**over):
    a = dict(proposed_by="agent", key=Ed25519PrivateKey.generate(), approved_by="operator", group="Bifrost:Line1",
             edge="recipe-edge", device=DEVICE, object_node_id=OBJECT, method_node_id=METHOD,
             input_name="targetTemperature", value=42.0, not_before="2026-11-02T10:00:00Z",
             not_after="2026-11-02T10:15:00Z")
    a.update(over)
    return a


def decode(envelope: bytes):
    env = json.loads(envelope)
    body = base64.b64decode(env["payload"])
    return env, body, json.loads(body)


def test_the_envelope_has_the_shape_bifrost_parses_and_pins_head_release_and_evidence(tmp_path):
    ev = evidence(tmp_path)
    a = args()
    cmd_id, envelope = propose(ev, REGISTRY, **a)
    env, body, s = decode(envelope)

    assert env["payloadType"] == IN_TOTO and len(env["signatures"]) == 1
    assert env["signatures"][0]["keyid"] == "agent"
    a["key"].public_key().verify(base64.b64decode(env["signatures"][0]["sig"]), pae(IN_TOTO, body))

    assert list(s) == ["_type", "subject", "predicateType", "predicate"] and s["predicateType"] == PREDICATE
    p = s["predicate"]
    assert set(p) == FIELDS and p["cmdId"] == cmd_id and p["streamId"] == "line1"
    assert p["method"] == {"objectNodeId": OBJECT, "methodNodeId": METHOD,
                           "inputs": [{"name": "targetTemperature", "type": "Double", "value": 42.0}]}
    assert p["validity"] == {"notBefore": "2026-11-02T10:00:00Z", "notAfter": "2026-11-02T10:15:00Z"}

    head_bytes = (REGISTRY / "mappings" / "heads" / "line1.json").read_bytes()
    head = json.loads(head_bytes)
    release = f"releases/{head['id']}/{head['version']}/release.json"
    assert s["subject"] == [
        {"name": "heads/line1.json", "digest": {"sha256": sha(head_bytes)}},
        {"name": release, "digest": {"sha256": sha((REGISTRY / "mappings" / release).read_bytes())}},
        {"name": "evidence", "digest": {"sha256": sha(ev)}},
    ]
    carried = base64.b64decode(p["evidence"]["base64"])
    assert p["evidence"]["mediaType"] == "application/json" and carried == ev, "the answer travels byte for byte"


def test_the_same_inputs_sign_the_same_bytes(tmp_path):
    ev = evidence(tmp_path)
    a = args(cmd_id="0b6f6c1e-4f0a-4c51-9a53-7a2c3c1d2e10")
    assert propose(ev, REGISTRY, **a) == propose(ev, REGISTRY, **a)


@pytest.mark.parametrize("over, code", [
    ({"approved_by": "agent"}, "same-principal"),
    ({"not_after": "2026-11-02T10:15:01Z"}, "window"),
    ({"not_after": "2026-11-02T10:00:00Z"}, "window"),
    ({"not_before": "2026-11-02 10:00:00"}, "window"),
    ({"value": float("nan")}, "input"),
    ({"value": float("inf")}, "input"),
    ({"method_node_id": "ns=2;s=Line1/Mixer1.SetTemperature"}, "node-id"),
    ({"device": ""}, "target"),
])
def test_refuses_what_bifrost_would_refuse(tmp_path, over, code):
    with pytest.raises(ProposalRefused) as r:
        propose(evidence(tmp_path), REGISTRY, **args(**over))
    assert r.value.code == code


def test_refuses_unusable_evidence(tmp_path):
    ev = evidence(tmp_path, quality_bad=True)
    assert json.loads(ev)["verdict"]["usable"] is False, "precondition: the fixture answer is a refusal"
    with pytest.raises(ProposalRefused) as r:
        propose(ev, REGISTRY, **args())
    assert r.value.code == "evidence-unusable"


def test_refuses_evidence_that_is_not_an_answer(tmp_path):
    for ev in (b"not json", b"[]", b'{"verdict": {"usable": true}}'):
        with pytest.raises(ProposalRefused) as r:
            propose(ev, REGISTRY, **args())
        assert r.value.code == "evidence-malformed"


def test_refuses_when_the_registry_head_moved_after_the_read(tmp_path):
    ev = evidence(tmp_path)
    reg = tmp_path / "reg"
    shutil.copytree(REGISTRY, reg)
    head = reg / "mappings" / "heads" / "line1.json"
    doc = json.loads(head.read_bytes())
    # A release 1.0.1 published after the read: its release.json exists and matches the new head.
    releases = reg / "mappings" / "releases" / doc["id"]
    shutil.copytree(releases / doc["version"], releases / "1.0.1")
    head.write_bytes(json.dumps(dict(doc, version="1.0.1")).encode("utf-8"))
    with pytest.raises(ProposalRefused) as r:
        propose(ev, reg, **args())
    assert r.value.code == "head-mismatch"


def test_refuses_when_the_release_file_does_not_match_its_head(tmp_path):
    ev = evidence(tmp_path)
    reg = tmp_path / "reg"
    shutil.copytree(REGISTRY, reg)
    head = json.loads((reg / "mappings" / "heads" / "line1.json").read_bytes())
    release = reg / "mappings" / "releases" / head["id"] / head["version"] / "release.json"
    release.write_bytes(release.read_bytes() + b" ")
    with pytest.raises(ProposalRefused) as r:
        propose(ev, reg, **args())
    assert r.value.code == "head-mismatch"


def key_file(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "agent.key"
    der = key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    path.write_text(base64.b64encode(der).decode("ascii") + "\n", encoding="utf-8")
    return key, path


def cli(tmp_path, ev_path, key_path, *extra):
    return ["--registry", str(REGISTRY), "--by", "agent", "--by-key", str(key_path), "--approved-by", "operator",
            "--group", "Bifrost:Line1", "--edge", "recipe-edge", "--device", DEVICE, "--object", OBJECT,
            "--method", METHOD, "--input", "targetTemperature", "--value", "42", "--out-dir",
            str(tmp_path / "proposals"), str(ev_path), *extra]


def test_cli_writes_one_proposal_named_by_its_cmd_id(tmp_path, capsys):
    ev_path = tmp_path / "answer.json"
    ev_path.write_bytes(evidence(tmp_path))
    key, key_path = key_file(tmp_path)
    assert main(cli(tmp_path, ev_path, key_path, "--not-before", "2026-11-02T10:00:00Z", "--valid-for", "600")) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["kind"] == "proposal" and report["notAfter"] == "2026-11-02T10:10:00Z"
    out = tmp_path / "proposals" / f"{report['cmdId']}.dsse.json"
    env, body, s = decode(out.read_bytes())
    key.public_key().verify(base64.b64decode(env["signatures"][0]["sig"]), pae(IN_TOTO, body))
    assert base64.b64decode(s["predicate"]["evidence"]["base64"]) == ev_path.read_bytes()


def test_cli_refuses_with_a_json_report_and_exit_1(tmp_path, capsys):
    ev_path = tmp_path / "answer.json"
    ev_path.write_bytes(evidence(tmp_path))
    _, key_path = key_file(tmp_path)
    assert main(cli(tmp_path, ev_path, key_path, "--valid-for", "901")) == 1
    report = json.loads(capsys.readouterr().out)
    assert report == {"kind": "proposal-refusal", "accepted": False, "error": "window",
                      "detail": "notBefore must precede notAfter by at most 15 minutes"}
    assert not (tmp_path / "proposals").exists() or not any((tmp_path / "proposals").iterdir())


def test_cli_refuses_a_key_that_is_not_ed25519_pkcs8(tmp_path, capsys):
    ev_path = tmp_path / "answer.json"
    ev_path.write_bytes(evidence(tmp_path))
    bad = tmp_path / "bad.key"
    bad.write_text("bm90IGEga2V5\n", encoding="utf-8")
    assert main(cli(tmp_path, ev_path, bad)) == 1
    assert json.loads(capsys.readouterr().out)["error"] == "key"


# --- the published command link (contract 2.25.0, proposal v2) -----------------------------------------------------

def test_the_predicate_is_v2_and_target_device_is_the_equipment_device_id(tmp_path):
    _, envelope = propose(evidence(tmp_path), REGISTRY, **args())
    p = decode(envelope)[2]
    assert decode(envelope)[2]["predicateType"].endswith("/command-proposal/v2")
    assert p["predicate"]["target"] == {"group": "Bifrost:Line1", "edge": "recipe-edge", "device": DEVICE}


def test_mixer2_proposal_signs_against_mixer2_link_with_mixer2_evidence_only(tmp_path):
    """Mixer1's evidence for Mixer2's Method: the key finds Mixer2's link, whose read binding is not the evidence's."""
    with pytest.raises(ProposalRefused) as r:
        propose(evidence(tmp_path), REGISTRY, **args(device=DEVICE2, object_node_id=OBJECT2, method_node_id=METHOD2))
    assert (r.value.code, r.value.detail) == ("link-mismatch", "binding.source")


@pytest.mark.parametrize("over, code, detail", [
    ({"device": "Line1/Mixer1"}, "link-missing", "device+methodNodeId"),
    ({"method_node_id": METHOD2}, "link-missing", "device+methodNodeId"),
    ({"device": DEVICE2}, "link-missing", "device+methodNodeId"),
    ({"edge": "other-edge"}, "link-mismatch", "command"),
    ({"group": "Bifrost:Line2"}, "link-mismatch", "command"),
    ({"object_node_id": OBJECT2}, "link-mismatch", "method.objectNodeId"),
    ({"input_name": "setpoint"}, "link-mismatch", "method.inputs"),
])
def test_refuses_a_call_the_link_does_not_name(tmp_path, over, code, detail):
    with pytest.raises(ProposalRefused) as r:
        propose(evidence(tmp_path), REGISTRY, **args(**over))
    assert (r.value.code, r.value.detail) == (code, detail)


def _answer_edit(ev: bytes, change) -> bytes:
    doc = json.loads(ev)
    change(doc["answer"])
    return json.dumps(doc, indent=1).encode("utf-8") + b"\n"


@pytest.mark.parametrize("change, detail", [
    (lambda a: a["binding"]["source"].__setitem__("sha256", "0" * 64), "binding.source"),
    (lambda a: a["binding"]["source"].__setitem__("file", "mappings/elsewhere.json"), "binding.source"),
    (lambda a: a["binding"].__setitem__("metric", "Speed"), "binding.metric"),
    (lambda a: a["binding"].__setitem__("device", DEVICE2), "binding.device"),
    (lambda a: a["binding"]["governedDefinitionRef"].__setitem__("version", "9.9.9"), "binding.governedDefinitionRef"),
    (lambda a: a["pin"].__setitem__("field_id", "temp-mixer2"), "pin.field_id"),
    (lambda a: a["pin"].__setitem__("file", "payload/mappings/1.json"), "pin.file"),
])
def test_refuses_evidence_not_bound_to_the_released_read_binding(tmp_path, change, detail):
    with pytest.raises(ProposalRefused) as r:
        propose(_answer_edit(evidence(tmp_path), change), REGISTRY, **args())
    assert (r.value.code, r.value.detail) == ("link-mismatch", detail)


def _registry(tmp_path):
    reg = tmp_path / "reg"
    shutil.copytree(REGISTRY, reg)
    return reg, reg / "mappings" / "releases" / "vor-read" / "1.0.0"


def test_refuses_a_link_file_whose_bytes_differ_from_release_json(tmp_path):
    ev = evidence(tmp_path)
    reg, root = _registry(tmp_path)
    link = root / "payload" / "command-bindings" / "mixer2-set-temperature.json"
    link.write_bytes(link.read_bytes() + b" ")
    with pytest.raises(ProposalRefused) as r:
        propose(ev, reg, **args())
    assert (r.value.code, r.value.detail) == ("link-mismatch", "release-file")


def _republished(tmp_path, change):
    """A release changed and published again under this test's keys, and an answer read under its new head."""
    reg, root = _registry(tmp_path)
    keys = Keys("proposer", "approver")
    trusted = keys.trusted(tmp_path / "trusted.jsonl")
    for head in (reg / "mappings" / "heads").glob("*.json"):
        sign_head(reg / "mappings", head.stem, keys)
    change(root)
    republish(reg / "mappings", "line1", keys)
    return reg, evidence(tmp_path, registry=reg, trusted=trusted)


def _add_link(root, name: str, doc: dict) -> None:
    rel = f"command-bindings/{name}.json"
    (root / "payload" / rel).write_bytes((json.dumps(doc, indent=2) + "\n").encode("utf-8"))
    edit_json(root / "payload" / "proposal.json", lambda p: p["files"].append(
        {"path": rel, "kind": "command-binding", "id": doc["id"], "version": doc["version"], "sha256": ""}))
    edit_json(root / "release.json", lambda r: r["files"].append({"path": "payload/" + rel, "sha256": ""}))


def test_refuses_two_links_for_one_device_and_method(tmp_path):
    """Bifrost refuses this at publish (command-binding.duplicate); a release that carries it anyway is not signed."""
    def twin(root):
        doc = json.loads((root / "payload" / "command-bindings" / "mixer1-set-temperature.json").read_bytes())
        _add_link(root, "mixer1-twin", dict(doc, id="mixer1-twin"))
    reg, ev = _republished(tmp_path, twin)
    with pytest.raises(ProposalRefused) as r:
        propose(ev, reg, **args())
    assert (r.value.code, r.value.detail) == ("link-ambiguous", "device+methodNodeId")


def test_refuses_a_link_whose_read_binding_is_not_in_the_release(tmp_path):
    def dangling(root):
        doc = json.loads((root / "payload" / "command-bindings" / "mixer2-set-temperature.json").read_bytes())
        doc["readBindingRef"] = {"id": "vor-binding-mixer3-temp", "version": "1.0.0"}
        _add_link(root, "mixer3", dict(doc, id="mixer3-set-temperature"))
    reg, ev = _republished(tmp_path, dangling)
    with pytest.raises(ProposalRefused) as r:
        propose(ev, reg, **args())
    assert (r.value.code, r.value.detail) == ("link-mismatch", "readBindingRef")


def test_a_republished_release_still_signs_the_honest_call(tmp_path):
    """Control for the two tests above: the republishing alone does not make the honest proposal fail."""
    reg, ev = _republished(tmp_path, lambda root: None)
    _, envelope = propose(ev, reg, **args())
    assert decode(envelope)[2]["predicate"]["target"]["device"] == DEVICE
