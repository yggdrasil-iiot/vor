"""One case per row of the refusal table, over the registries Bifrost published, plus the answer itself.

Release-side cases change a copy of the registry; when the change is one Bifrost could have published, the chain is
re-hashed and the head re-signed with keys made for the test, so the case isolates the rule it names.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from helpers import (BINDING, DEVICE, FIXTURES, TOPIC, Keys, copy_registry, edit_json, fixture_now, metric, ms,
                     payload, republish, sign_head)
from vor.head import FloorStore, load_trusted_keys
from vor.refusal import REASONS, Refusal
from vor.server import Question, Vor
from vor.stream import SampleCache
from vor.verdict import check_skew

VALUE = 217.25  # distinctive, so a refusal that leaked it would be caught
GROUP, EDGE = "Bifrost:Line1", "recipe-edge"


def feed(cache: SampleCache, now: int, *, device: str = DEVICE, **sample) -> None:
    topic = TOPIC.replace(DEVICE, device) if device else f"spBv1.0/{GROUP}/NDATA/{EDGE}"
    cache.on_message(f"spBv1.0/{GROUP}/NBIRTH/{EDGE}", payload(0))
    sample.setdefault("timestamp", now - 500)
    sample.setdefault("server", now - 400)
    cache.on_message(topic, payload(1, metric("Temp", VALUE, **sample)))


class World:
    def __init__(self, tmp: Path, registry: str = "active"):
        self.tmp = tmp
        self.mappings = copy_registry(registry, tmp)
        self.payload = self.mappings / "releases" / "vor-read" / "1.0.0" / "payload"
        self.trusted = FIXTURES / "trusted-keys.jsonl"
        self.state = tmp / "state"
        self.now = fixture_now(self.mappings)
        self.cache = SampleCache(clock_ms=lambda: self.now)
        self.keys = Keys("proposer", "approver")

    def own_keys(self) -> None:
        """Trust only this test's keys, and sign every head in the registry with them."""
        self.trusted = self.keys.trusted(self.tmp / "trusted.jsonl")
        for head in (self.mappings / "heads").glob("*.json"):
            sign_head(self.mappings, head.stem, self.keys)

    def republish(self, **sign) -> None:
        if self.trusted == FIXTURES / "trusted-keys.jsonl":
            self.own_keys()
        republish(self.mappings, "line1", self.keys, **sign)

    def read(self, question: str = "temp", now: int | None = None) -> dict:
        vor = Vor(self.mappings.parent, self.trusted, self.state,
                  {"temp": Question("temp", "line1", BINDING, "Mixer1 temperature")}, self.cache)
        return vor.read(question, self.now if now is None else now)


def reason(out: dict) -> str | None:
    assert ("answer" in out) and ("verdict" in out)
    if out["verdict"]["usable"]:
        return None
    assert out["answer"] is None
    text = json.dumps(out)
    assert str(VALUE) not in text and '"value"' not in text, "a refusal carries no sample value"
    return out["verdict"]["reason"]


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    feed(w.cache, w.now)
    return w


def test_answer_from_bifrost_bytes(world):
    out = world.read()
    assert out["verdict"] == {**out["verdict"], "usable": True, "status": "usable"}
    a = out["answer"]
    assert a["sample"]["value"] == VALUE and a["sample"]["quality"] == "good"
    assert a["pin"]["stream_id"] == "line1" and a["pin"]["release_id"] == "vor-read"
    assert a["pin"]["file"] == "payload/mappings/0.json" and a["pin"]["field_id"] == "temp"
    assert a["pin"]["digest_rule"] == "raw-bytes-sha256"
    head = json.loads((world.mappings / "heads" / "line1.json").read_bytes())
    assert a["pin"]["release_sha256"] == head["sha256"]
    assert a["unit"]["code"] == "Cel" and a["meaning"]["semanticId"] == "urn:bifrost:sem:Mixer/Temp"
    assert a["meaning"]["state"] == "active" and a["isa95Path"]["path"] == DEVICE
    assert a["head"]["publishedBy"] == "proposer" and a["head"]["approvedBy"] == "approver"
    assert a["policy"]["maxAgeMs"] == 5000 and a["sample"]["ageMs"] == 500
    assert a["sample"]["source"] == {"topic": TOPIC}
    assert "owner" not in json.dumps(a) and "sla" not in json.dumps(a)


def test_every_reason_has_a_case():
    names = {n[len("test_"):].replace("_", "-") for n in globals() if n.startswith("test_")}
    assert set(REASONS) <= names | {"provenance-mismatch"}  # parametrised below as test_provenance_mismatch


# --- head ----------------------------------------------------------------------------------------------------------

def test_head_unverified(world):
    (world.mappings / "head-attestations" / "line1.dsse.json").unlink()
    assert reason(world.read()) == "head-unverified"


@pytest.mark.parametrize("case,rule", [("untrusted-key", "signature"), ("same-principal", "principals"),
                                       ("same-key", "same-key"), ("head-file-changed", "subject"),
                                       ("bad-sig", "signature")])
def test_head_unverified_cases(tmp_path, case, rule):
    w = World(tmp_path)
    feed(w.cache, w.now)
    if case == "untrusted-key":
        w.trusted = Keys("proposer", "approver").trusted(tmp_path / "other.jsonl")
    elif case == "same-principal":
        w.own_keys()
        sign_head(w.mappings, "line1", w.keys, approved_by="proposer")
    elif case == "same-key":
        w.trusted = w.keys.trusted(tmp_path / "alias.jsonl", alias={"approver2": "proposer"})
        for head in (w.mappings / "heads").glob("*.json"):
            sign_head(w.mappings, head.stem, w.keys, approved_by="approver2", signer_of={"approver2": "proposer"})
    elif case == "head-file-changed":
        edit_json(w.mappings / "heads" / "line1.json", lambda h: h.__setitem__("version", "9.9.9"))
    elif case == "bad-sig":
        f = w.mappings / "head-attestations" / "line1.dsse.json"
        env = json.loads(f.read_bytes())
        env["signatures"][1]["sig"] = env["signatures"][0]["sig"]
        f.write_text(json.dumps(env))
    out = w.read()
    assert reason(out) == "head-unverified", out
    assert out["verdict"]["evidence"]["rule"] == rule


def test_head_rollback(world):
    world.own_keys()
    sign_head(world.mappings, "line1", world.keys, version=2)
    assert world.read()["verdict"]["usable"]
    sign_head(world.mappings, "line1", world.keys, version=1)
    out = world.read()
    assert reason(out) == "head-rollback"
    assert out["verdict"]["evidence"]["floor"] == 2 and out["verdict"]["evidence"]["candidate"] == 1


def test_head_rollback_same_version_other_statement(world):
    world.own_keys()
    assert world.read()["verdict"]["usable"]
    sign_head(world.mappings, "line1", world.keys, lifetime=timedelta(days=30))
    assert reason(world.read()) == "head-rollback"


def test_head_rollback_floor_survives_a_restart(world):
    world.own_keys()
    sign_head(world.mappings, "line1", world.keys, version=2)
    assert world.read()["verdict"]["usable"]
    assert FloorStore(world.state).get("line1")[0] == 2  # on disk, not held in memory
    sign_head(world.mappings, "line1", world.keys, version=1)
    # World.read builds a new Vor each call, so this read is a fresh process's view of the same state directory.
    assert reason(world.read()) == "head-rollback"


def test_head_expired(world):
    expires = world.read()["answer"]["head"]["expires"]
    out = world.read(now=ms(expires))
    assert reason(out) == "head-expired" and out["verdict"]["evidence"]["expires"] == expires


# --- release -------------------------------------------------------------------------------------------------------

RELEASE_FILES = [f["path"] for f in json.loads(
    (FIXTURES / "registries/active/mappings/releases/vor-read/1.0.0/release.json").read_bytes())["files"]]


@pytest.mark.parametrize("path", ["release.json"] + RELEASE_FILES)
def test_provenance_mismatch(world, path):
    f = world.mappings / "releases" / "vor-read" / "1.0.0" / path
    f.write_bytes(f.read_bytes() + b" ")
    out = world.read()
    assert reason(out) == "provenance-mismatch", out
    assert out["verdict"]["evidence"]["expected"] != out["verdict"]["evidence"]["computed"]


@pytest.mark.parametrize("field,value,rule", [
    ("projection", "linear", "projection"), ("device", "synthetic-site:line1", "device"), ("metric", "Rpm", "metric"),
    ("mappingId", "rpm", "mapping-missing"), ("equipmentInstanceId", "line1", "equipment"),
    ("streamId", "line2", "stream"), ("semanticId", "urn:bifrost:sem:Mixer/Rpm", "semantic-id")])
def test_binding_invalid(world, field, value, rule):
    edit_json(world.payload / "data" / "vor-read-binding.json", lambda b: b.__setitem__(field, value))
    world.republish()
    out = world.read()
    assert reason(out) == "binding-invalid", out
    assert out["verdict"]["evidence"]["rule"] == rule


def test_binding_invalid_unknown_question(world):
    assert reason(world.read("rpm")) == "binding-invalid"


def test_meaning_retired(tmp_path):
    w = World(tmp_path, "retired")
    feed(w.cache, w.now)
    out = w.read()
    assert reason(out) == "meaning-retired"
    assert [s["file"].rsplit("/", 1)[-1] for s in out["verdict"]["evidence"]["sources"]] == ["0.json", "1.json"]


def test_meaning_deprecated_is_usable_with_a_warning(tmp_path):
    w = World(tmp_path, "deprecated")
    feed(w.cache, w.now)
    out = w.read()
    assert out["verdict"]["usable"] and out["verdict"]["warning"]["code"] == "meaning-deprecated"
    assert out["answer"]["meaning"]["state"] == "deprecated"


def test_lifecycle_head_that_fails_refuses(tmp_path):
    w = World(tmp_path, "retired")
    feed(w.cache, w.now)
    (w.mappings / "head-attestations" / "semantics.dsse.json").unlink()
    out = w.read()
    assert reason(out) == "head-unverified" and out["verdict"]["evidence"]["stream"] == "semantics"


def test_deleting_a_lifecycle_head_after_it_was_seen_cannot_hide_the_retirement(tmp_path):
    w = World(tmp_path, "retired")
    feed(w.cache, w.now)
    assert reason(w.read()) == "meaning-retired"
    (w.mappings / "heads" / "semantics.json").unlink()
    (w.mappings / "head-attestations" / "semantics.dsse.json").unlink()
    out = w.read()
    assert reason(out) == "head-unverified" and out["verdict"]["evidence"]["stream"] == "semantics"


def test_unit_unknown(world):
    unknown = {"status": "unknown"}
    edit_json(world.payload / "semantics" / "0.json", lambda d: d["members"][0].__setitem__("unit", unknown))
    edit_json(world.payload / "mappings" / "0.json", lambda d: d["mappings"][0].__setitem__("outputUnit", unknown))
    world.republish()
    assert reason(world.read()) == "unit-unknown"


def test_policy_missing(world):
    edit_json(world.payload / "mappings" / "0.json", lambda d: d["mappings"][0].pop("temporalPolicy"))
    world.republish()
    assert reason(world.read()) == "policy-missing"


# --- sample --------------------------------------------------------------------------------------------------------

def test_no_sample(tmp_path):
    w = World(tmp_path)
    assert reason(w.read()) == "no-sample"


def test_no_sample_after_death(world):
    world.cache.on_message(f"spBv1.0/{GROUP}/NDEATH/{EDGE}", payload(None))
    assert reason(world.read()) == "no-sample"


@pytest.mark.parametrize("missing", [{"status": None}, {"timestamp": None}])
def test_sample_unknown(tmp_path, missing):
    w = World(tmp_path)
    feed(w.cache, w.now, **missing)
    assert reason(w.read()) == "sample-unknown"


def test_bad_quality(tmp_path):
    w = World(tmp_path)
    feed(w.cache, w.now, status=0x808B0000, quality=0)
    out = w.read()
    assert reason(out) == "bad-quality"
    assert out["verdict"]["evidence"]["ua_statuscode"] == "0x808B0000"
    assert out["verdict"]["evidence"]["severityBits"] == "10" and out["verdict"]["evidence"]["Quality"] == 0


def test_uncertain_rejected(tmp_path):
    w = World(tmp_path)
    feed(w.cache, w.now, status=0x40900000, quality=500)
    assert reason(w.read()) == "uncertain-rejected"


def test_uncertain_propagated_when_the_policy_says_so(tmp_path):
    w = World(tmp_path)
    edit_json(w.payload / "mappings" / "0.json",
              lambda d: d["mappings"][0]["temporalPolicy"].__setitem__("uncertainInput", "propagate"))
    w.republish()
    feed(w.cache, w.now, status=0x40900000, quality=500)
    out = w.read()
    assert out["verdict"]["usable"] and out["verdict"]["status"] == "usable-uncertain"


def test_stale(tmp_path):
    w = World(tmp_path)
    feed(w.cache, w.now, timestamp=w.now - 5001)
    out = w.read()
    assert reason(out) == "stale" and out["verdict"]["evidence"]["ageMs"] == 5001


def test_received_time_does_not_refresh_age(tmp_path):
    w = World(tmp_path)
    feed(w.cache, w.now, timestamp=w.now - 9000)  # received just now, sampled nine seconds ago
    assert reason(w.read()) == "stale"


def test_future_sample(tmp_path):
    w = World(tmp_path)
    feed(w.cache, w.now, timestamp=w.now + 1)
    assert reason(w.read()) == "future-sample"


def test_skew_exceeded():
    assert check_skew([1000], 0) == 0
    with pytest.raises(Refusal) as r:
        check_skew([1000, 1250], 200)
    assert r.value.reason == "skew-exceeded" and r.value.evidence["skewMs"] == 250


def test_location_mismatch(tmp_path):
    w = World(tmp_path)
    feed(w.cache, w.now, device="synthetic-site:line2:mixer1")
    out = w.read()
    assert reason(out) == "location-mismatch" and out["verdict"]["evidence"]["expected"] == DEVICE


def test_location_mismatch_on_node_data(tmp_path):
    w = World(tmp_path)
    feed(w.cache, w.now, device=None)
    assert reason(w.read()) == "location-mismatch"


def test_trusted_keys_file_is_outside_the_registry():
    keys = load_trusted_keys(FIXTURES / "trusted-keys.jsonl")
    assert set(keys) == {"proposer", "approver"}
