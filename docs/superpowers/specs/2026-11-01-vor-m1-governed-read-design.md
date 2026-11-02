# Vor M1 — governed read path for AI agents

## Purpose

Vor (Vör) answers one concrete question for a Model Context Protocol (MCP) host: "What is Mixer1's current temperature in Cel (degrees Celsius), and may it be used?" It returns either one value bound to one governed data product accompanied by a deterministic trust verdict, or a structured refusal.

The existing industrial spine proves the pattern of model, govern, and feed:
1. Mimir derives definitions from the OPC UA type space.
2. Bifrost governs and publishes versioned, approved releases.
3. Muninn streams live OPC UA data as Sparkplug B messages.

Nothing in the current architecture allows a reasoning consumer to evaluate and consume a live value under the published release's own governing rules. Two concrete implementation gaps exist today:
- Muninn discards data quality and temporal metadata during read operations. Specifically, `muninn/src/main/java/dev/krillin/muninn/OpcUaInstanceBrowser.java` executes `getValue().getValue()`. This extracts only the raw value and drops the OPC UA `StatusCode`, `sourceTimestamp`, and `serverTimestamp`.
- `SparkplugCodec.java` stamps every egress payload with the transmission time using `new Date()`. It does not propagate the original sample time.

Consequently, no downstream consumer checks release head freshness, semantic lifecycle state, engineering units, or temporal policy before a number reaches a Large Language Model (LLM).

The M1 design enforces one core rule: a value without quality, source time, release pin, and policy verdict is never returned as usable.

The system adheres to an invariant of zero shared code. Vor reads the raw bytes published by Bifrost and the wire stream emitted by Muninn. It imports no code, libraries, or internal modules from either system. Vor is implemented in Python; Bifrost and Muninn are implemented in Java.

Vor embeds no LLM. The MCP host performs all reasoning tasks. Vor supplies only deterministic evidence and explicit refusals. The server pattern employs FastMCP over standard input/output (`stdio`), uses injectable clients, and exposes read-only tools. This follows the architecture of an existing advisory MCP server (`agent/server.py` in `LivingLikeKrillin/resequence-twin-lab`) as an independent implementation.

## Scope and non-goals

The scope of M1 comprises:
- Propagating OPC UA `StatusCode` and timestamps through Muninn.
- Updating the Bifrost simulation server to serve Bad and Uncertain samples on demand.
- Defining and publishing the read binding as an evidence artifact inside Bifrost releases.
- Implementing the Vor MCP server runtime.
- Executing two automated deterministic validation gates.

The following areas are excluded by design decision:
- Out of scope: Read authorization and Open Policy Agent (OPA) integration, because no contract field states which principal may read which release, and the existing OPA evaluator runs only inside the JVM for commands (`bifrost/core/src/main/java/dev/krillin/bifrost/core/acl/opa/`). Read authorization is deferred to M2.
- Out of scope: OT-side lineage and a specialized data-product catalog, because Eidos already emits OpenLineage and Open Data Contract Standard (ODCS) data contracts on the IT side, and a Bifrost record-mapping release already serves as the named, versioned, approved artifact. The release pin that Vor returns serves as the join key across systems.
- Out of scope: Calibration state tracking, because an OPC UA StatusCode of Good does not mean calibrated, and no contract field currently carries calibration metadata.
- Out of scope: Running an LLM in continuous integration (CI), because gates are deterministic. One recorded real MCP-host session containing prompt, tool calls, and answer may be kept as a fixture; it is never executed in CI.
- Out of scope: Unit or alias collision scenarios, because the unit contract is a closed set (`unit.status` is `known` with a 10-code Unified Code for Units of Measure (UCUM) list — `rpm`, `Cel`, `N.m`, `1`, `1/s`, `mN.m`, `K`, `Pa`, `kPa`, `bar` — or `not-applicable` or `unknown`), and Tyr has no alias field. The only erroneous unit condition authorable today is `unit.status = unknown`, which Vor refuses.
- Out of scope: Production keys, plant credentials, and live plant data in test fixtures, because fixtures are synthetic only: no keys, credentials or plant data are committed.

## Components and boundaries

The implementation boundaries span two existing repositories, one new repository, and five unchanged systems:

| Repository | Change in M1 |
|---|---|
| Muninn | `SampledMember` gains `statusCode`, `sourceTimestamp`, and `serverTimestamp`. `OpcUaInstanceBrowser` keeps the full `DataValue` (it already requests both timestamps). `SparkplugCodec` writes the per-metric timestamp and properties using Eclipse Tahu 1.0.14 `MetricBuilder.timestamp` and `properties`. Egress validation logic remains unchanged. |
| Bifrost sim | Adds one writable status-control node per governed member (for example, `Sim/Line1/Mixer1.Temp.StatusCode`, UInt32) that re-sets the member with a `DataValue` carrying that `StatusCode` and fresh timestamps using the Eclipse Milo 1.1.8 four-argument `DataValue` constructor. The default value remains Good so that existing test gates are unaffected. Today every simulation node is created Good. |
| Bifrost publication | Generates a synthetic release containing the mapping set, equipment hierarchy, semantic definition, temporal policy, and the read binding packaged as an `evidence-artifact`. Semantic lifecycle events come from separate lifecycle-only releases. No Bifrost core contract changed. |
| Vor (new) | New Python repository consisting of five core modules: `release.py`, `head.py`, `stream.py`, `verdict.py`, and `server.py`. |
| Mimir | No change. |
| Tyr | No change. |
| Huginn | No change. |
| Heimdall | No change. |
| Eidos | No change. |

The Vor repository decomposes into distinct functional modules:
- `release.py`: Verifies the provenance chain by computing SHA-256 digests over raw bytes in sequence: heads → `release.json` → proposal → payload. It resolves the read binding, semantic definitions, units, lifecycle states, and hierarchy paths from the payload files.
- `head.py`: Executes Dead Simple Signing Envelope (DSSE) Ed25519 cryptographic verification of the signed mapping head. It checks signatures, distinct signers, subject digests, validity windows, and validates the monotonic head version against an external rollback floor persisted outside the release tree.
- `stream.py`: Implements the MQTT client and Sparkplug B decoding engine. It maintains an in-memory cache of exactly one latest sample per bound metric, handles Sparkplug birth messages, death messages, and sequence counter gaps, and maps incoming properties.
- `verdict.py`: Implements a pure function: `(pin, policy, sample) -> verdict`. It performs deterministic quality mapping, freshness verification, skew calculation, and lifecycle checks, producing an answer structure or an explicit refusal code.
- `server.py`: Wraps the evaluation engine in a FastMCP stdio server exposing the single `read_governed` tool.

```
+-----------------------------------------------------------------------------------+
|                                 Bifrost Release                                   |
|  +--------------------+   +-----------------------+   +------------------------+  |
|  | Signed Head (DSSE) |-->| release.json (Digest) |-->| Payload (Artifacts)    |  |
|  +--------------------+   +-----------------------+   | - Read Binding JSON    |  |
|                                                       | - Record Mapping       |  |
|                                                       | - Temporal Policy      |  |
|                                                       +------------------------+  |
+-------------------------------------------------------------------|---------------+
                                                                    | raw bytes
                                                                    v
+-----------------------+  Sparkplug B (MQTT)   +-----------------------------------+
| Muninn                |---------------------->| Vor                               |
| - OpcUaInstanceBrowser|  Quality, ua_*, time  | - release.py (Byte provenance)    |
| - SparkplugCodec      |                       | - head.py    (DSSE / floor)       |
+-----------------------+                       | - stream.py  (MQTT decode/cache)  |
                                                | - verdict.py (Pure evaluation)    |
                                                | - server.py  (FastMCP stdio)      |
                                                +-----------------|-----------------+
                                                                  |
                                                                  | read_governed()
                                                                  v
                                                        +-------------------+
                                                        | MCP Host          |
                                                        | (LLM Reasoning)   |
                                                        +-------------------+
```

## Contracts

### Sparkplug sample encoding (Muninn → Vor)

The Sparkplug B 3.0 specification defines a well-known metric property named `Quality` (Int32) with three standardized states:
- `0`: BAD
- `192`: GOOD
- `500`: STALE

Sparkplug B 3.0 defines no Uncertain value for this property. The top-level payload `timestamp` represents the publication time. Muninn encodes metadata per metric in both birth (`NBIRTH`/`DBIRTH`) and data (`NDATA`/`DDATA`) messages:

| Field | Type | Rule |
|---|---|---|
| property `Quality` | Int32 | Evaluates to `0` if the OPC UA StatusCode severity is Bad or reserved; evaluates to `500` for `Uncertain_LastUsableValue`; evaluates to `192` for Good and for all other Uncertain status codes. This field is a lossy projection; the precise truth resides in `ua_statuscode`. Always emitted. |
| property `ua_statuscode` | UInt32 | Raw 32-bit OPC UA StatusCode value. Preserves all severity, sub-code, and flag bits without loss. Always emitted. |
| property `ua_server_timestamp` | UInt64 | Server timestamp represented in epoch milliseconds. Omitted when the OPC UA server returns no server timestamp. |
| metric `timestamp` | UInt64 | OPC UA source timestamp represented in epoch milliseconds. Omitted when the OPC UA server returns no source timestamp. Never populated with the send time or message publication time. |

This projection rule duplicates the encoding logic established in the predecessor lab (`sparkplug-governance-lab/src/main/java/dev/krillin/sparkplug/opcua/UaSideChannel.java`).

Vor derives a three-state internal quality representation (`good`, `uncertain`, or `bad`) directly from the two severity bits of `ua_statuscode`:
- Bit pattern `00`: Good
- Bit pattern `01`: Uncertain
- Bit pattern `10`: Bad (or `11` reserved)

Vor uses the standard `Quality` property solely as a sanity cross-check against stream corruption. A missing `ua_statuscode` property or a missing metric `timestamp` forces the derived quality to `unknown`, never `good`. Metadata is never inherited from a previous sample; every cache update must contain complete metadata.

This vocabulary (`good`, `uncertain`, `bad`, `sourceTimestamp`, `serverTimestamp`) matches Bifrost's 2.23.0 `virtualDataValue` definition. The `virtualDataValue` structure is a design-time preview sample format, not a runtime wire contract.

### Published read binding (Bifrost release → Vor)

Field names alone cannot bind a governed field to a Sparkplug metric. Muninn identifies metrics by their OPC UA browse names, whereas Bifrost mapping releases identify governed fields by OPC UA node address: `opcua-node {namespaceUri, identifier}`.

To bridge this namespace difference without runtime lookup services, Bifrost publishes a versioned JSON read binding document inside the release payload as an `evidence-artifact`. The Bifrost contract schema for an `evidence-artifact` natively supports a file path, a raw SHA-256 digest, and a media type string.

The read binding JSON document is published in the release payload as a data file referenced by an evidence-artifact (`payload/data/vor-read-binding.json` in the fixture release). Its field names use camelCase, matching Bifrost's contract naming:
- `profileVersion`: Schema version of the read binding format.
- `streamId`: Unique identifier of the release stream.
- `mappingSetRef`: Reference object `{id, version}` identifying the mapping set in the release.
- `mappingId`: Mapping identifier within the mapping set, corresponding to the field identifier used in the semantic pin.
- `equipmentInstanceId`: Canonical equipment instance identifier.
- `semanticId`: Governed semantic term identifier.
- `group`: Sparkplug group identifier.
- `edge`: Sparkplug edge node identifier.
- `device`: Sparkplug device identifier.
- `metric`: Sparkplug metric name matching the Muninn browse name.
- `governedDefinitionRef`: Reference object `{templateRef, version, sha256}` identifying the governed definition published by Muninn.
- `projection`: String constant `identity`.

Vor verifies that all fields are present and that `projection` is `identity`. It confirms that `streamId` equals the head's stream; that `mappingSetRef` resolves to a mapping-set document in the release, and that the set's target and semantic definition resolve; that `equipmentInstanceId` matches the mapping set; and that `mappingId` exists in the set. It verifies that the mapping's member path resolves to a member whose `semanticId` equals the binding's, that the member name equals `metric`, that the mapping's source node identifier ends with `"." + metric`, and that the output unit is present. Finally, Vor confirms that the equipment hierarchy contains exactly one path to `equipmentInstanceId` and that `device` equals that ISA-95 path. A failure of any of these checks results in a `binding-invalid` outcome with the failing rule named in the evidence.

### Policy source (release → Vor)

Vor enforces policy; it never defines policy. Policy is authored and published exclusively inside Bifrost releases.

Vor reads one policy format: the read binding names a mapping in a mapping set, and the policy is that mapping's `temporalPolicy`. Required fields include:
- `timestampBasis`: Choice of `source` or `server`.
- `maxAgeMs`: Maximum permitted sample age in milliseconds.
- `maxSkewMs`: Maximum permitted timestamp skew across inputs in milliseconds.
- `uncertainInput`: Handling rule, set to `propagate` or `reject`.
- `missingInput`: Handling rule, set to `reject`.
- `badInput`: Handling rule, set to `propagate`.
- `assembly`: Input assembly mode, set to `latest` or `trigger-sequence`.

The 2.22 record mapping `commonPolicy` (mode `single-virtual-frame`, `maxAgeMs`, `maxSkewMs`, `uncertainInput`) is not a policy source in M1. A 2.22 record mapping is a finite broadcast recipe — a declared result set from a provider query with common scalar sources broadcast to every row — and `commonPolicy` governs that whole virtual frame. Bifrost validates the recipe but executes no provider, and Muninn publishes OPC UA instance members only, so no runtime puts record rows on the Sparkplug wire for Vor to judge (see the Open questions section).

A read binding lacking a valid policy specification is refused with reason code `policy-missing`.

Temporal calculations operate deterministically:
- `ageMs` = evaluation wall-clock time − timestamp selected by `timestampBasis`.
- A negative age indicates clock skew or a future timestamp and is refused with reason code `future-sample`.
- An age exceeding `maxAgeMs` is refused with reason code `stale`.
- Skew is interpreted as the spread of source timestamps across all inputs assembled into one value: $\max(T_{\text{source}}) - \min(T_{\text{source}})$. For a single scalar input, the skew is identically zero. The Bifrost contract contains no prose definition of `maxSkewMs`; this specification records that interpretation explicitly.
- Samples with derived quality `uncertain` pass evaluation only when `uncertainInput` equals `propagate`. In that event, the sample is marked with verdict `usable-uncertain`.
- Samples with derived quality `bad` are refused regardless of policy configuration.

### Answer and refusal (Vor → MCP host)

Vor exposes exactly one tool via FastMCP: `read_governed(question_id)`.

Only pre-configured, bound question identifiers are accepted. The tool permits no free-form OPC UA queries, no topic paths, and no dynamic policy overrides.

An answer response consists of distinct sections, where each section includes an explicit `source` attribute containing a file path plus raw-byte SHA-256 digest, or the live MQTT topic:
- `pin`: Identifies the exact governance lineage. Fields:
  - `stream_id`: Identifier of the stream binding.
  - `release_id`: Identifier of the governing release.
  - `version`: Version string of the release.
  - `release_sha256`: SHA-256 digest of the release descriptor.
  - `file`: Path to the source mapping file within the release.
  - `file_sha256`: SHA-256 digest of the mapping file.
  - `field_id`: Bound field identifier.
  - `digest_rule`: Canonical rule string used to compute digests.
  This structure matches the semantic pin schema used by Eidos, implemented independently.
- `head`: Cryptographic head metadata. Fields: `headVersion`, `signedAt`, `expires`, `publishedBy`, and `approvedBy`.
- `meaning`: Semantic definition containing `semanticId` and current semantic lifecycle state.
- `unit`: Verified UCUM unit string.
- `isa95Path`: Hierarchical location path of the equipment.
- `policy`: Resolved temporal policy criteria applied during evaluation.
- `sample`: Telemetry payload. Fields:
  - `value`: Raw numeric or primitive value.
  - `quality`: Derived quality string (`good` or `uncertain`).
  - `ua_statuscode`: Raw OPC UA StatusCode.
  - `sourceTimestamp`: OPC UA source timestamp in epoch milliseconds.
  - `serverTimestamp`: OPC UA server timestamp in epoch milliseconds.
  - `receivedAt`: Epoch milliseconds recorded when Vor's stream engine received the message.
  - `ageMs`: Computed age in milliseconds relative to the evaluation time.
- `verdict`: Final evaluation outcome. Fields: `usable` (boolean `true`), `status` (`usable` or `usable-uncertain`), and `evidence`.

The `receivedAt` field records Vor's local clock upon message ingestion. It is tracked separately from both OPC UA timestamps. Local ingestion time never refreshes the age of an underlying OPC UA sample.

Accountability fields are restricted strictly to `publishedBy` and `approvedBy` extracted from the DSSE signed head. There is no `owner` or `sla` field in the Bifrost contracts, and Vor does not fabricate synthetic accountability attributes.

When a validation rule fails, Vor returns a refusal response:
- The top-level `answer` field is `null`.
- `verdict.usable` is set to `false`.
- `verdict.reason` contains exactly one error code from a closed enumeration.
- `verdict.evidence` contains a structured explanatory dictionary.

Evaluation checks run in a strictly defined, invariant order. The first rule failure terminates evaluation and determines the reason code. No numeric sample value is ever emitted within a refusal response.

Handling of semantic lifecycle deprecation follows Bifrost core semantics:
- A deprecated semantic meaning remains usable. Vor sets `verdict.usable = true` and includes a warning attribute populated with `replacementSemanticId`.
- A retired semantic meaning causes evaluation to fail immediately with reason code `meaning-retired`.

## Data flow

The operational data flow executes in four distinct phases:

```
[Phase 1: Publication]
  Operator publishes release -> Generates DSSE Head signed by Publisher + Approver

[Phase 2: Bootstrap & Verification]
  Vor reads release bytes -> Verifies DSSE signatures -> Checks rollback floor
  -> Verifies SHA-256 of release.json -> Verifies payload files
  -> Resolves read binding, unit, policy, lifecycle, ISA-95 path

[Phase 3: Telemetry Ingestion]
  Muninn streams Sparkplug B -> Vor stream.py ingests MQTT
  -> Validates device id == hierarchy path -> Decodes Quality, ua_*, timestamps
  -> Caches latest sample per metric

[Phase 4: Tool Execution]
  MCP Host calls read_governed(question_id)
  -> Vor re-verifies head expiration & lifecycle state
  -> Evaluates cached sample against policy (Age, Skew, Quality)
  -> Returns complete Answer OR Refusal
```

1. **Publication**: An operator publishes a release containing a signed DSSE head. Bifrost enforces that the publisher and approver identities are distinct cryptographic key pairs.
2. **Bootstrap and Verification**: Vor performs bootstrap and verification on every `read_governed` call rather than once at startup, re-reading the registry per call. It verifies the DSSE head using Ed25519 public keys from a separately configured trusted keys file that lives outside the registry, ensuring that a registry cannot supply its own keys. Vor confirms that the publisher and approver keys differ and asserts that the current wall-clock time is before the head expiration timestamp. It validates the head against the rollback floor, which is stored per stream in a state directory (recording the head version and statement digest) and survives restarts; the head version must meet or exceed the floor, and a same-version head with a different statement digest results in a `head-rollback` failure. Vor calculates the SHA-256 digest of `release.json` over raw bytes, confirms the digest against the head subject, and verifies the proposal and payload files. To establish lifecycle state, Vor replays semantic lifecycle events found in the releases at every stream head in the registry (such as a lifecycle-only release on a separate semantics stream). Every one of those stream heads must pass the same verification; if any fails, the read is refused with that head's reason. Vor then parses the read binding JSON, locating the referenced semantic member, engineering unit, ISA-95 equipment hierarchy path, and temporal policy.
3. **Telemetry Ingestion**: Vor connects to the MQTT broker, subscribes to `spBv1.0/#` with QoS 1, and publishes nothing. A session starts at an NBIRTH message with sequence counter 0, and sequence counters must continue modulo 256. A sequence counter gap, an NDEATH, a DDEATH, or an undecodable payload drops the edge node's samples until the next birth; data received outside an active session is ignored. Vor caches nothing until it sees a birth. If Vor starts after the edge node's NBIRTH, it answers `no-sample` until the next birth. Because Vor publishes nothing, it does not send rebirth requests; a Sparkplug primary host application or an operator sends the rebirth request (an NCMD with `Node Control/Rebirth = true`). In verification against a real Muninn session, starting after the birth caused Vor to answer `no-sample`, and issuing one rebirth request transitioned it to answering `usable`. When a birth or data message arrives within a session, Vor decodes `Quality`, `ua_statuscode`, `ua_server_timestamp`, and the metric-level source `timestamp`. Vor stores the single latest sample in an in-memory cache keyed by metric path. Each message replaces a sample whole; no metadata is carried over from an earlier message. The Sparkplug device identifier is verified against the ISA-95 equipment hierarchy path during evaluation (yielding reason `location-mismatch`), not at ingestion.
4. **Tool Execution**: On every invocation of `read_governed(question_id)`, Vor executes the evaluation pipeline. It re-verifies the release head expiration against current wall-clock time and checks that the semantic lifecycle state has not transitioned to retired. It extracts the cached sample for the bound metric. Vor computes sample age using the configured `timestampBasis`, calculates timestamp skew, maps the OPC UA status code, and applies the temporal policy. If all checks pass, Vor returns a complete answer payload. If any check fails, Vor halts immediately and returns a refusal payload containing the corresponding reason code and diagnostic evidence.

## Failure handling

Evaluation occurs in a fixed, deterministic sequence. The first check that fails terminates processing and sets the corresponding reason code:

| Condition | Reason code |
|---|---|
| Missing envelope, bad signature, wrong or identical principals | `head-unverified` |
| Head version below floor, or same version with a different statement | `head-rollback` |
| `now >= expires` | `head-expired` |
| Release or payload hash mismatch, invalid read binding | `provenance-mismatch` / `binding-invalid` |
| Meaning retired | `meaning-retired` |
| `unit.status` not `known` | `unit-unknown` |
| No temporal policy | `policy-missing` |
| No sample yet, death message, or sequence gap | `no-sample` |
| Missing `ua_statuscode` or source timestamp | `sample-unknown` |
| StatusCode severity Bad | `bad-quality` |
| Uncertain and `uncertainInput = reject` | `uncertain-rejected` |
| Age above `maxAgeMs`, or negative age | `stale` / `future-sample` |
| Skew above `maxSkewMs` | `skew-exceeded` |
| Device id differs from hierarchy path | `location-mismatch` |

Every refusal payload populates the `verdict.evidence` object with structured diagnostic context:
- For `head-unverified` or `provenance-mismatch`: The rule name, the expected SHA-256 digest, and the computed SHA-256 digest.
- For `head-rollback`: The current rollback floor version, the candidate head version, and the recorded statement hash.
- For `head-expired`: The ISO 8601 expiration timestamp and the evaluation wall-clock timestamp.
- For `bad-quality` or `uncertain-rejected`: The raw 32-bit `ua_statuscode` rendered in hexadecimal, the decoded severity bit pattern, and the standard Sparkplug `Quality` integer.
- For `stale` or `future-sample`: The computed `ageMs`, the configured `maxAgeMs` limit, and the timestamp values evaluated.
- For `skew-exceeded`: The computed skew spread in milliseconds and the configured `maxSkewMs` ceiling.
- For `location-mismatch`: The incoming Sparkplug device identifier string and the expected ISA-95 equipment hierarchy path string.

No numeric sample value is included in any field of a refused response.

## Testing and gates

### Unit testing

Unit tests validate isolated component mechanics:
- **Muninn**: Verifies StatusCode severity bit parsing; verifies handling of absent source and server timestamps; validates Sparkplug B encode/decode round trips preserving `Quality`, `ua_statuscode`, and metric `timestamp`; confirms that existing metric egress filtering is unchanged.
- **Bifrost simulation**: Confirms that writing to the status-control node (`Sim/Line1/Mixer1.Temp.StatusCode`) alters the actual `DataValue` returned to an OPC UA client; confirms that resetting the node restores a Good status code.
- **Vor**: Contains a table-driven unit test verifying every row in the failure handling table; tests file tampering detection across all release artifacts; validates persistent rollback prevention across process restarts; verifies refusal on expired heads; asserts that refusal responses never contain numeric values.

### Gate (i): Refusal gate

Gate (i) validates end-to-end failure handling using live components. The harness launches a real MQTT broker, the Bifrost OPC UA simulation server, Muninn configured with `--session --hierarchy`, the Vor service, and an automated MCP protocol client. No mocks are permitted.

The test executes a mandatory sequential lifecycle:
1. **Initial Baseline**: Asserts that `read_governed` returns an answer with `verdict.usable = true`.
2. **Bad Quality**: An external OPC UA test client writes a Bad StatusCode to `Sim/Line1/Mixer1.Temp.StatusCode`. The gate asserts that `read_governed` transitions to a refusal with reason code `bad-quality`.
3. **Recovery**: The test client restores the StatusCode to Good. The gate asserts that `read_governed` returns to `verdict.usable = true`.
4. **Head Expiration**: The harness presents an expired release head signed with synthetic test keys. The gate asserts that `read_governed` returns a refusal with reason code `head-expired`.
5. **Meaning Retirement**: The harness publishes a release update marking the semantic meaning as retired. The gate asserts that `read_governed` returns a refusal with reason code `meaning-retired`.

Each transition asserts that the verdict changed from the immediately preceding state. The expired head fixture is signed during test execution using synthetic Ed25519 keys; Vor contains no testing backdoor, debug switch, or clock-manipulation hook to bypass cryptographic or temporal checks.

### Gate (ii): Side-by-side gate

Gate (ii) compares both read paths on the same sample. A frozen simulation sample is read concurrently through two parallel paths: directly from the OPC UA server via a standard client, and through Vor via `read_governed`.

1. **Under Good Conditions**:
   - Direct OPC UA read returns raw temperature value $V_1$.
   - Vor returns answer with value $V_2$.
   - Assert $V_1 = V_2$.
   - The direct OPC UA read contains no governance release pin, no verified UCUM unit, and no temporal policy enforcement. Vor's answer includes complete provenance and policy verification.
2. **Under Bad Quality Conditions**:
   - The simulation server status-control node is written with a Bad StatusCode.
   - The direct OPC UA read continues to return the raw numeric value $V_1$.
   - Vor returns a structured refusal with reason code `bad-quality` and zero numeric values.

### Harness invariants

All gates adhere to the same failure criteria:
- Any missing service, network timeout, zero executed test cases, or skipped required assertions results in an immediate non-zero exit code.
- Every test gate incorporates a negative control: an intentional mismatch between computed and expected outputs must cause the gate script to fail with a non-zero exit code.

## Delivery plan

Delivery proceeds across five ordered phases:

| Order | Repository | Work | Estimated lines |
|---|---|---|---|
| 0 | Bifrost | Spike: confirm that a read-binding evidence artifact survives the approval and publication workflow with its exact byte digest intact. | Small |
| 1 | Bifrost | Implement simulation status control node and unit tests; author synthetic release containing read binding and temporal policy. | 150–250 |
| 2 | Muninn | Implement sample metadata propagation (`statusCode`, `sourceTimestamp`, `serverTimestamp`), update codec, and author unit tests. | 220–350 |
| 3 | Vor | Implement bootstrap, release verifier, stream consumer, verdict pure function, FastMCP server, and table-driven unit tests. | 1,000–1,300 |
| 4 | Vor | Implement Gate (i) refusal test harness, Gate (ii) side-by-side test harness, and CI workflows. | 300–450 |

Total estimated effort: approximately 1,600–2,350 lines of code, excluding generated protobuf code and test fixtures.

## M2 and M3 outlook

The M2 milestone introduces the governed write path:
- The AI agent authors an operational command proposal formatted as a DSSE-signed envelope.
- A human operator co-signs the identical proposal payload using the Bifrost command line interface: `gates command approve`. The approved envelope enforces a fixed validity window signed by both entities.
- Heimdall is enhanced with an explicit `method` operation using the Eclipse Milo `CallMethodRequest` API.
- Executing an OPC UA Method call through Heimdall requires:
  1. Two valid cryptographic signatures from distinct principals.
  2. Principal grant validation confirming `propose` and `approve` authorizations.
  3. Strict model-head binding verification.
  4. Durable command-id reservation, so a replayed command is refused, including across restarts.
- OPA policy evaluation is integrated directly into the JVM method execution path.
- The proposal's evidence snapshot reuses the exact answer schema and semantic pin structure defined in M1.

Today, Heimdall's `call` operation is implemented as a Boolean trigger handshake rather than an OPC UA Method invocation.

The M3 milestone expands automated modeling: Mimir derives callable Method definitions directly from the OPC UA type space.

## Open questions

Two implementation questions remain open for resolution; two are resolved:
1. **Read-binding survival** (resolved): The step 0 spike confirmed that Bifrost's approval and publication preserve the evidence-artifact file bytes exactly, with no Bifrost code change; a Bifrost regression test now holds this (Bifrost PR #38). Vor's fixture registries are written by Bifrost's own CLI.
2. **Retirement visibility** (resolved): Lifecycle events are carried in published releases (lifecycle-only releases), and Vor replays them from the releases at every verified stream head in the registry, so retirement is confirmed from release bytes alone, without an external registry service. A head that fails verification refuses the read.
3. **Skew definition**: M1 binds a single scalar, so skew is zero; the multi-input spread definition ($\max(T_{\text{source}}) - \min(T_{\text{source}})$) still needs to be confirmed against Bifrost before multi-input values are supported.
4. **Record-mapping reads**: Reading a field of a 2.22 record mapping under its `commonPolicy` needs a runtime that executes the recipe and publishes its rows (each value with its source timestamp and status) on the wire; no Yggdrasil component does this today. When one exists, the read binding gains a record-mapping form (record mapping reference plus field id) and Vor applies `commonPolicy`, including the multi-input skew of item 3 over the frame's inputs.
