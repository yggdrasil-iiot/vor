"""The verdict on one sample under what the release says about its field: a pure function of (governed, sample, now).

Checks run in the order of the refusal table, after the head, release and binding checks that produced `governed`.
The answer carries every input it was decided from, each with its source: a release file and its raw-byte SHA-256,
or the MQTT topic the sample came on. A refusal carries evidence and never the sample value.
"""

from __future__ import annotations

from .head import iso
from .refusal import DIGEST_RULE, Refusal
from .release import UNIT_CODES, Governed, policy_valid
from .sparkplug import NUMERIC
from .stream import Sample

SEVERITY = {0: "good", 1: "uncertain", 2: "bad", 3: "bad"}
NUMERIC_TYPES = {"Double", "Float", "Int16", "Int32", "Int64", "UInt16", "UInt32", "UInt64", "Byte", "SByte"}


def quality(status_code: int) -> str:
    """Good, uncertain or bad from the two severity bits of a 32-bit OPC UA StatusCode (11 is reserved: bad)."""
    return SEVERITY[(status_code >> 30) & 3]


def _quality_evidence(s: Sample) -> dict:
    return {"ua_statuscode": f"0x{s.status_code:08X}", "severityBits": format((s.status_code >> 30) & 3, "02b"),
            "Quality": s.quality, "source": {"topic": s.topic}}


def check_skew(source_timestamps: list[int], max_skew_ms: int) -> int:
    """The spread of source timestamps over the inputs assembled into one value; zero for one scalar input."""
    skew = max(source_timestamps) - min(source_timestamps)
    if skew > max_skew_ms:
        raise Refusal("skew-exceeded", skewMs=skew, maxSkewMs=max_skew_ms, sourceTimestamps=source_timestamps)
    return skew


def evaluate(g: Governed, sample: Sample | None, now_ms: int) -> dict:
    if g.meaning.state == "retired":
        raise Refusal("meaning-retired", semanticId=g.meaning.semantic_id, revision=g.meaning.revision,
                      replacementSemanticId=g.meaning.replacement, sources=g.meaning.sources)
    if g.unit.get("status") != "known" or g.unit.get("code") not in UNIT_CODES:
        raise Refusal("unit-unknown", unit=g.unit, source=g.release_source(g.mapping_file))
    policy = g.policy
    if not policy_valid(policy):
        raise Refusal("policy-missing", mappingId=g.mapping_id, source=g.release_source(g.mapping_file))
    if sample is None:
        raise Refusal("no-sample", group=g.binding["group"], edge=g.binding["edge"], metric=g.binding["metric"])

    basis = sample.source_timestamp if policy["timestampBasis"] == "source" else sample.server_timestamp
    numeric_field = g.member.get("valueType") in NUMERIC_TYPES
    if (sample.status_code is None or sample.source_timestamp is None or basis is None
            or numeric_field and (sample.datatype not in NUMERIC or isinstance(sample.value, bool)
                                  or not isinstance(sample.value, (int, float)))):
        raise Refusal("sample-unknown", hasStatusCode=sample.status_code is not None,
                      hasSourceTimestamp=sample.source_timestamp is not None,
                      hasServerTimestamp=sample.server_timestamp is not None, datatype=sample.datatype,
                      valueType=g.member.get("valueType"), source={"topic": sample.topic})
    q = quality(sample.status_code)
    if q == "bad":
        raise Refusal("bad-quality", **_quality_evidence(sample))
    if q == "uncertain" and policy["uncertainInput"] != "propagate":
        raise Refusal("uncertain-rejected", uncertainInput=policy["uncertainInput"], **_quality_evidence(sample))

    age = now_ms - basis
    timing = {"ageMs": age, "maxAgeMs": policy["maxAgeMs"], "timestampBasis": policy["timestampBasis"],
              "evaluatedTimestamp": basis, "sourceTimestamp": sample.source_timestamp,
              "serverTimestamp": sample.server_timestamp, "now": now_ms}
    if age < 0:
        raise Refusal("future-sample", **timing)
    if age > policy["maxAgeMs"]:
        raise Refusal("stale", **timing)
    skew = check_skew([sample.source_timestamp], policy["maxSkewMs"])
    if sample.device != g.isa95_path:
        raise Refusal("location-mismatch", device=sample.device, expected=g.isa95_path, source={"topic": sample.topic})

    head, release = g.release.head, g.release
    verdict = {"usable": True, "status": "usable" if q == "good" else "usable-uncertain",
               "evidence": {"timing": timing, "skewMs": skew, "quality": _quality_evidence(sample)}}
    if g.meaning.state == "deprecated":
        verdict["warning"] = {"code": "meaning-deprecated", "replacementSemanticId": g.meaning.replacement,
                              "sources": g.meaning.sources}
    answer = {
        "questionId": g.question_id,
        "pin": {"stream_id": head.stream, "release_id": head.release_id, "version": head.version,
                "release_sha256": head.release_sha256, "file": g.mapping_file,
                "file_sha256": release.files[g.mapping_file], "field_id": g.mapping_id, "digest_rule": DIGEST_RULE,
                "source": {"file": f"mappings/{head.release_path}", "sha256": head.release_sha256}},
        "head": head.summary(),
        "meaning": {"semanticId": g.meaning.semantic_id, "name": g.member.get("name"),
                    "description": g.member.get("description"), "state": g.meaning.state,
                    "revision": g.meaning.revision, "source": g.release_source(g.mapping_file),
                    "lifecycleSources": g.meaning.sources},
        "unit": {"code": g.unit["code"], "system": "UCUM", "source": g.release_source(g.mapping_file)},
        "isa95Path": {"path": g.isa95_path, "levels": g.isa95_levels, "source": g.hierarchy_source},
        "binding": {"group": g.binding["group"], "edge": g.binding["edge"], "device": g.binding["device"],
                    "metric": g.binding["metric"], "governedDefinitionRef": g.binding["governedDefinitionRef"],
                    "source": g.binding_source},
        "policy": dict(policy, source=g.release_source(g.mapping_file)),
        "sample": {"value": sample.value, "quality": q, "ua_statuscode": sample.status_code,
                   "sourceTimestamp": sample.source_timestamp, "serverTimestamp": sample.server_timestamp,
                   "sourceTime": iso(sample.source_timestamp), "receivedAt": sample.received_at, "ageMs": age,
                   "source": {"topic": sample.topic}},
    }
    return {"answer": answer, "verdict": verdict}
