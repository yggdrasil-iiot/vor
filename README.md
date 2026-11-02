# vor

Vor is the governed reader of the Yggdrasil IIoT project. It is an MCP server (stdio) exposing exactly one tool, read_governed(question_id). It embeds no LLM; the MCP host does the reasoning. It answers with a value bound to a published Bifrost mapping release and a live Sparkplug B sample from Muninn, or with a deterministic refusal. Question ids are fixed in the configuration; a question id that is not configured is refused (binding-invalid, rule question-unknown). The host cannot ask for an arbitrary node or metric. Vor shares no code with Bifrost or Muninn: it reads only their published bytes (the Bifrost registry directory on disk, and Sparkplug B messages on an MQTT broker).

## What an answer contains

An answer contains the following items, each with its source (a release file path plus its raw-byte SHA-256, or the MQTT topic the sample came on):
- Semantic pin (stream_id, release_id, version, release_sha256, file, file_sha256, field_id, digest_rule "raw-bytes-sha256")
- Verified head (headVersion, signedAt, expires, publishedBy, approvedBy)
- Meaning (semanticId, name, description, lifecycle state, revision)
- UCUM unit code
- ISA-95 equipment path and its levels
- Sparkplug binding (group, edge, device, metric, governed definition reference)
- Temporal policy
- Sample (value, quality good/uncertain, OPC UA status code, source and server timestamps, age)
- Verdict (usable or usable-uncertain; carries a meaning-deprecated warning with the replacement semanticId when the meaning is deprecated)

A refusal has answer null and a verdict with usable false, a reason code, and evidence. A refusal never carries the sample value.

## Refusals

Checks run in this fixed order; the first failing check decides the reason. Vor verifies the DSSE (in-toto Statement v1) head attestation of a stream with Ed25519 public keys from the trusted keys file outside the registry; publisher and approver must be different principals with different keys. Vor replays semantic lifecycle events from releases at every stream head in the registry; every head must verify.

| Reason code | When it fires |
| --- | --- |
| head-unverified | Head file or DSSE envelope missing, publisher and approver are the same principal, a signature does not verify against a trusted key, both signatures from the same key, statement subjects do not match the head and release.json, or the head is signed in the future. |
| head-rollback | Head version below the stored floor, or the same version with a different statement. |
| head-expired | The current time is at or past the head's expires. |
| provenance-mismatch | release.json, the proposal, or a payload file does not match its recorded SHA-256 or identity. |
| binding-invalid | The read binding is missing or does not resolve (fields, projection other than identity, stream, mapping set, target, semantic definition, equipment, mapping, member path, semantic id, metric, source node, unit, hierarchy path, device not equal to the ISA-95 path), or the question is not configured. |
| meaning-retired | The meaning is retired in the semantic lifecycle. |
| unit-unknown | The output unit is not a known UCUM code. |
| policy-missing | The mapping has no valid temporalPolicy. |
| no-sample | No sample for the bound metric in the current Sparkplug session. |
| sample-unknown | The sample lacks a status code or source timestamp (or the timestamp the policy uses), or its type does not match the field's numeric type. |
| bad-quality | OPC UA status severity is bad. |
| uncertain-rejected | Severity is uncertain and the policy does not propagate uncertain input. |
| future-sample | The evaluated timestamp is after now. |
| stale | Sample age exceeds maxAgeMs. |
| skew-exceeded | The spread of source timestamps exceeds maxSkewMs (zero for a single scalar input). |
| location-mismatch | The Sparkplug device id is not the ISA-95 path from the release. |

(future-sample and stale cannot both apply to one sample.)

## Configuration

The configuration file is JSON, named by the environment variable VOR_CONFIG. Relative paths resolve against the config file's directory.

```json
{
  "registry": "registry",
  "trustedKeys": "trusted-keys.jsonl",
  "stateDir": "state",
  "mqtt": "tcp://localhost:1883",
  "questions": {
    "mixer1-temp": {"stream": "line1", "binding": "vor-binding-mixer1-temp",
                    "description": "Mixer1 process temperature in Cel"}
  }
}
```

- registry: The Bifrost registry directory (it contains mappings/).
- trustedKeys: JSON-lines file of trusted Ed25519 public keys.
- stateDir: Where rollback floors (head version and statement digest) are written per stream.
- mqtt: Broker URL.
- questions: Question id to stream, read-binding id, and a description shown to the host in the tool description.

## Run

Requirements: Python 3.11+. Dependencies: mcp (>=1.2,<2, FastMCP), paho-mqtt (>=2.0), cryptography (>=42).

Install:
```sh
pip install -e .
# for tests:
uv pip install -e ".[dev]"
```

Run:
```sh
VOR_CONFIG=path/to/vor.json vor
# or:
VOR_CONFIG=path/to/vor.json python -m vor.server
```

An MCP host launches it as a stdio server with command vor (or python -m vor.server) and the VOR_CONFIG environment variable set.

## Joining a running edge node

Vor subscribes to spBv1.0/# with QoS 1 and publishes nothing. A session starts with an NBIRTH at seq 0; sequence numbers must continue modulo 256. A sequence gap, an NDEATH, a DDEATH, or an undecodable payload drops the cached samples until the next birth. Each data message replaces a sample whole; metadata is never carried over from an earlier message. Muninn puts the OPC UA source time in the metric timestamp and adds the properties Quality, ua_statuscode, and ua_server_timestamp to each metric.

Vor caches nothing until it sees a birth. If Vor starts after the edge node's NBIRTH, read_governed answers no-sample until the edge node births again. Vor does not request a rebirth itself, because it publishes nothing. A Sparkplug primary host application or an operator sends the rebirth request (an NCMD with Node Control/Rebirth = true); Muninn's own CLI has:

```sh
java -jar muninn.jar host <mqttUrl> rebirth <group> <edge>
```

Verified live: started after the birth, Vor answered no-sample; after one rebirth request it answered usable with a sample about 1.3 s old.

## Tests and fixtures

Run tests:
```sh
pytest
```

Tests include a refusal case for every reason, provenance tampering of release.json and each payload file, real MCP stdio round trips, and NBIRTH/DBIRTH/DDATA bytes captured from a real Muninn session (tests/fixtures/muninn-wire).

Every registry byte the tests verify was written by Bifrost's own CLI. Regenerate with:
```sh
(cd ../bifrost && mvn -pl gates -am package -DskipTests)
python scripts/make_fixtures.py [--bifrost ../bifrost]
```

This requires <bifrost>/gates/target/bifrost-gates.jar. It writes tests/fixtures/registries/{active,deprecated,retired} and tests/fixtures/trusted-keys.jsonl; private keys are created in a temporary directory and deleted. tests/fixtures is marked -text in .gitattributes so line endings never change hash-pinned bytes.

## Design

The design specification is located at docs/superpowers/specs/2026-11-01-vor-m1-governed-read-design.md.
