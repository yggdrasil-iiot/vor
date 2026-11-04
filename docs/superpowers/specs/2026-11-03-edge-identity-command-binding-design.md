# Edge identity and governed command binding

## Purpose
The M2 governed write path leaves eight gaps open in the implementation:
- The link between data and command is undeclared: `vor-propose` refuses `binding-mismatch` only when the evidence binding's group/edge differ from the command target's (`vor/src/vor/propose.py` ~line 85); Heimdall never checks the link; the only barrier between evidence from equipment X and a Method on equipment Y is `CommandProposal.java:161`, `node.startsWith(p.objectNodeId() + ".")`, a naming convention of the sim's address space.
- `target.device` has two meanings: the proposal carries the OPC UA object path `Line1/Mixer1`; the read binding (`bifrost/core/src/test/resources/mapping-fixtures/vor-read/data/vor-read-binding.json`) carries the ISA-95 path `synthetic-site:line1:mixer1` and `equipmentInstanceId: mixer1`; Muninn publishes DDATA with the ISA-95 path as the Sparkplug device id when started with `--hierarchy` (`MuninnMain`, `HierarchyLocator.locate`); `Line1/Mixer1` cannot be a Sparkplug device id because it contains `/`; `COMMAND-PROPOSAL.md` calls `target` "the Sparkplug coordinates the command policy matches", which is false for `device` today.
- Bounds are copied: the command policy carries a `constraint` min/max; `bifrost/core/src/main/resources/opa/command_method.rego` line 11 hard-codes a `methods` table with the same Method, input name, type and `min: 0, max: 100`.
- Heimdall does not authenticate the OPC UA server: `OpcUaApplier.createGoverned()` sets the edge's application URI, certificate, chain, key pair and X509 identity provider and no certificate validator; Milo 1.1.8's `OpcUaClientConfigBuilder` constructor installs `CertificateValidator.InsecureCertificateValidator` by default (verified in the jar's bytecode; `bifrost/pom.xml` `milo.version` 1.1.8); Heimdall therefore accepts any server certificate, and another server at the same URL receives the Method call.
- Heimdall is not a Sparkplug node: a host cannot learn the write boundary's liveness or writable surface from `spBv1.0/`; it must watch the non-Sparkplug STATUS topic.
- Vor's `SampleCache` (`vor/src/vor/stream.py`) keys samples by `(group, edge, metric)` without the device, so two devices on one edge with the same metric name collide.
- Heimdall's MQTT reconnect (`NcmdOpcUaBridge.connectComplete`) resubscribes and republishes STATUS on Paho's automatic reconnect; Paho reuses the original connect options, including the original Will.
- `NcmdOpcUaBridge`'s class comment (line ~53) still says it "publishes a correlated Sparkplug NDATA response"; stage B moved responses to RESULT.

No Method runs unless a published, approved command binding ties the evidence's equipment to that Method, and Heimdall is a Sparkplug node whose liveness a host can see. Each verifier resolves the binding in its own code. The design is the result of two independent reviewers over six rounds, plus an independent review of the drafted spec against the code; where the reviewers first disagreed, the decisions below record where they converged.

## Hypotheses
- **H-trust**: "Heimdall does not call a Method on a server whose certificate it does not trust." Falsified if a server at the same URL with a different certificate receives a Method call.
- **H-device**: "The device string in the proposal names the equipment on the wire, in the evidence and in the policy." Verified only together with H-link.
- **H-link**: "Evidence read from equipment X cannot authorize a Method on equipment Y; that X's data node and Y's Method are one equipment is a published, approved artifact, not an address-space coincidence." Falsified if a proposal with Mixer1 evidence for Mixer2's Method passes `vor-propose`, approve or Heimdall.
- **H-node**: "A Sparkplug-only host learns the write boundary's liveness and Method command writable surface from `spBv1.0/` alone (setpoint nodes are not declared at birth), and the data node's session is untouched by the command node's life." Falsified if kill -9 of Heimdall yields no NDEATH carrying the NBIRTH's bdSeq, or if Vor drops Muninn's samples during Heimdall's birth, death or restart.
- **H-endpoint** (after H-trust): "The authenticated server receiving the command is the server the pinned link authorizes."

## Decisions

### 1. Target redefinition
- Decision: Redefine `target`. `target.group` and `target.edge` name the command node (where the NCMD is delivered; Heimdall must be that node). `target.device` names the governed equipment by its Sparkplug device id as the data edge publishes it: the ISA-95-derived path Muninn publishes as the device id (`synthetic-site:line1:mixer1`), resolved through the read binding, never through a DBIRTH under the command edge. The three are Sparkplug identifiers, not the coordinates of one topic; `COMMAND-PROPOSAL.md` line 25 ("the Sparkplug coordinates the command policy matches") is rewritten to say this, and the command policy still matches all three. The device id is an application serialization of the ISA-95 hierarchy (contract 2.23.0), not a string format ISA-95 itself mandates. The OPC UA object path stays only in `method.objectNodeId`.
- Reason: It is the one equipment id already crossing three applications on the wire (Muninn's DDATA topic, Vor's location check, `binding.device`).
- Consequence: Governed writes require Muninn to run with `--hierarchy`.

### 2. Proposal version
- Decision: Set the proposal version to `command-proposal/v2` with the same eight fields as v1 (`cmdId`, `streamId`, `target`, `method`, `validity`, `proposedBy`, `approvedBy`, `evidence`) and `target.device` redefined. Today `CommandProposal.parse` requires the exact predicateType and field set, so after the cut every v1 statement is refused `command.malformed` and no verifier reinterprets a v1 signature under the new meaning. Omit the `commandBindingRef` field: with key uniqueness enforced at publish, a signed reference could only agree with the key lookup or be refused, so it verifies nothing new. The trigger to add `commandBindingRef` is two command bindings sharing `(device, methodNodeId)`, for example a redundant command edge for one equipment.

### 3. Command binding link document
- Decision: Define the link as a new document kind, `command-binding`, in the published mapping release under mapping contract 2.25.0 (2.24.0 is the latest today), at path `payload/command-bindings/<id>.json`. It is covered by `release.json`'s file digests, so the proposal's second subject already commits it and the head attestation covers it: no new signature, no fourth subject. Authored in Tyr; approved and published by `gates mapping approve` / `publish` (four-eyes already exists). It is not the ISA-95 hierarchy (metadata only, names equipment not transport); not the command policy (per edge, unpublished, unattested, says who may act, not what is one equipment); not the governed definition (a type, not an instance); not a source-definition (`accessMode` is `const "read"` in every contract version).
  - Fields:
    - `kind`
    - `schemaVersion`
    - `id`
    - `version`
    - `equipmentRef` {hierarchy document id and version, `equipmentInstanceId`}
    - `readBindingRef` {id, version}
    - `command` {group, edge}
    - `method` {`objectNodeId`, `methodNodeId`, `inputs` [{`name`, `type`, `unit`}]}
    - `evidenceRefs`
  References follow the mapping contract's existing {id, version} convention. The read binding is not a mapping-contract document: it is an `evidence-artifact` (`evidence/vor-read-binding.json`, schemaVersion 1.1.0) whose `file.path` is the data file `data/vor-read-binding.json`, a Vor profile (`profileVersion 0.1.0`) carrying `streamId`, `mappingSetRef`, `mappingId`, `equipmentInstanceId`, `semanticId`, `group`, `edge`, `device`, `metric`, `governedDefinitionRef`, `projection`. `readBindingRef` names that evidence-artifact. Today only Vor parses the profile (`vor/src/vor/release.py`); Bifrost and Heimdall gain their own parser of profile 0.1.0 — a published data contract read independently, so zero shared code holds, as with `HierarchyLocator`. An unsupported `profileVersion` or `projection` is refused.
  Resolution: iterate the release's command bindings, resolve each `readBindingRef`, and match the key `(read binding device, link.method.methodNodeId)` against `(target.device, method.methodNodeId)`.
  - Publish-time validation (new codes):
    - `command-binding.duplicate` (one binding per device and methodNodeId within one release)
    - `command-binding.device-path` (the read binding's device equals the hierarchy path of `equipmentRef`)
    - `command-binding.inputs` (exactly one input, non-empty name, type `Double`, and a UCUM unit code)
    - `command-binding.unresolved` (a reference that does not resolve within the release)
  The unit is the declared interpretation of the input value; it is not compared with the precondition mapping's unit (a Method input need not share the measured member's unit, and the precondition member need not be the member the Method drives). No `connectionProfileRef` is placed in the link: the read binding already pins the source, which carries its own `connectionProfileRef` (a bare id string, `"sim-opcua"` in the fixture, nullable in some contract versions, naming no server); a copy could only be compared with its own original. Server identity arrives with `endpointRef` in 2.26.0 (D8).

### 4. Authorization bounds in command policy
- Decision: Bounds live in the command policy only. The link carries the Method signature (name, type, unit), which Mimir can evidence by browsing the server; the policy carries the authorization bounds. The OPA `methods` table stops being a constant in `command_method.rego`; Heimdall puts it in the evaluation input as `input.methods`, built per call from the resolved link (name, type) and the matching command-policy rule's constraint (min, max), and the policy reads `input.methods`. This is not a wasm data document: `OpaPolicy` evaluates with `data_addr` none today, so input needs no new wasm ABI calls, and a per-call table cannot go stale. The table is never copied from the proposal; a missing or malformed entry denies.

### 5. Verification at three independent points
- Decision: Verify at three independent points — `vor-propose`, `gates command approve`, and Heimdall — each resolving the link from the pinned release in its own code (zero shared code): the link exists for the key (`command.link.missing`), exactly one (`command.link.ambiguous`), and matches (`command.link.mismatch`, detail names the differing field). Matching means:
  1. `target.device` equals the read binding's `device` (detail `device`);
  2. the evidence is bound to the released read-binding bytes, in this order: the evidence-artifact's `file.sha256` equals `release.json`'s digest for that path and the bytes hash to it; the evidence's `binding.source.sha256` equals that digest and `binding.source.file` equals `mappings/<release-root>/<path>` exactly; field equality between the evidence binding and the parsed profile for `group`, `edge`, `device`, `metric` and `governedDefinitionRef` {`templateRef`, `version`, `sha256`}; the evidence's `pin.field_id` equals the profile's `mappingId` and `pin.file` equals the mapping-set path the profile's `mappingSetRef` resolves to;
  3. `target.group`/`target.edge` equal `link.command`;
  4. `method.objectNodeId` and `methodNodeId` equal `link.method`, and the proposal's input count, name and type equal the link's (the value stays bounded by the command policy).
  In `vor-propose` the hyphenated codes are `link-missing`, `link-ambiguous`, `link-mismatch`, replacing `binding-mismatch`. In `gates command approve` (which has no precondition step) the check runs after `bind` and before the policy check; in Heimdall it runs after the head match and before the precondition. Heimdall additionally requires `link.command` to equal its own group and edge. The precondition node comes from the read binding's `mappingId` and its source, replacing the `startsWith` heuristic.

### 6. Heimdall as Sparkplug edge node
- Decision: Stage A: Heimdall becomes its own Sparkplug edge node with its own configured edge id (for example `recipe-edge-cmd`) in the same group. It publishes NBIRTH (with `bdSeq`, `Node Control/Rebirth`, and one declared String metric `bifrost/command/v1`), keeps an NDEATH Will with the same `bdSeq`, numbers `seq` per message, and rebirths on `Node Control/Rebirth`. No DBIRTH or DCMD (devices are not modelled by Heimdall; UMH reads a device id as a location, so a Heimdall device would be a phantom asset); no outcome metrics; diagnostic counters deferred until a host that needs them is named. Correlated answers stay off Sparkplug: RESULT and QUERY move to `bifrost/<group>/RESULT|QUERY/<command-edge>`; the requester correlates by payload uuid = cmdId; the command ledger stays the durable record. Sparkplug defines no reply to NCMD; a second receipt channel as process metrics would be historized by hosts such as Ignition's MQTT Engine. STATUS is removed and its retained message cleared at migration. Heimdall publishes nothing on the data edge's topics.
  NCMD dispatch on the command edge, before `handle()`: a payload with no metrics is refused `command.malformed` on RESULT; if every metric is `Node Control/*` or `Properties/*`, exactly one Boolean `Node Control/Rebirth` goes to the session (true: NBIRTH with seq 0 and the same bdSeq; false: no-op); any other payload of this class is ignored and logged, not answered on RESULT (an answer there would reply to the node owner's protocol on the requester's channel; today's `isNodeControl` already chose silence for that reason); otherwise more than one metric is refused `command.malformed` on RESULT (covers a Rebirth mixed with a command, and two setpoints; this is Bifrost's restriction, not Sparkplug's, closing the gap where a second unsigned metric was accepted and silently dropped because the signature covers only the first metric); otherwise one metric goes to `handle()`, unchanged (setpoint, Method or read). Node Control on the QUERY topic is `command.malformed`, not a rebirth or a read. Preserving setpoints does not extend the Method-only command-binding guarantee (H-link) to setpoints.

### 7. bdSeq advancement and persistence
- Decision: `bdSeq` advances on every MQTT CONNECT, including after a process restart, wraps 255 to 0, and is kept on a rebirth without CONNECT (Sparkplug 3.0; the specification prescribes no storage). Heimdall persists it as a small file in its durable directory `COMMAND_LEDGER_PATH`. Under stage A that path is required for the node to start (today it is optional, "unset = no record", `NcmdOpcUaBridgeMain`; the Method path already refuses without it); Heimdall refuses to CONNECT if the storage is unavailable or the file is corrupt. Order per connect: read the last value, compute the next, write the file and fsync it and its directory entry, then CONNECT with the Will carrying that value; NBIRTH repeats it. A crash between the two steps can only skip a number, never reuse one. Heimdall manages reconnect itself — a new Will with the next bdSeq, a fresh NBIRTH, and resubscription — instead of Paho's automatic reconnect, which reuses the old Will. Muninn's `EdgeSession` keeps bdSeq in memory and is not the template for this.
- Reason: After kill -9 the broker holds the Will (bdSeq n) until keepalive lapses; a restarted process that births with bdSeq n again would be marked dead by the late Will.

### 8. Server authentication before endpoint identity
- Decision: Server authentication comes before endpoint identity. First Heimdall sets a server trust store and Milo's `DefaultClientCertificateValidator` (milo-stack-core 1.1.x) and refuses an untrusted server before any read or call. The validator applies to the identity path (`createGoverned`); the anonymous path (`createAnonymous`, `SecurityPolicy.None`, `OpcUaApplier.java` ~line 206) has no server certificate to check. Today the Method path runs on either path: the bridge builds `MethodPath` unconditionally (`NcmdOpcUaBridgeMain.java` ~line 504) and the OPC UA client is anonymous whenever `HEIMDALL_IDENTITY_DIR` is unset (`OpcUaApplier.java` ~line 190); only the sim's `SIM_REQUIRE_IDENTITY` refuses it. Step 1 therefore also makes Heimdall refuse every `op=method` command when no identity is configured, before the reservation (`command.identity.required`). Then, in the following contract (2.26.0), the link gains `endpointRef` (server ApplicationUri and certificate thumbprint) and Heimdall compares the authenticated peer with it before the reservation (`command.link.endpoint`). An execution-time endpoint guarantee requires both to exist; a general trust store may accept several servers, so trust alone does not prove the link authorizes this one.

## Scope and non-goals

### In scope
1. Step 1 (bifrost): Heimdall server trust store and validator, `command.identity.required` for `op=method` without an identity, G1, ENTERPRISE row 12 note.
2. Step 2 (vor): `SampleCache` keyed with the device, G2.
3. Step 3 (bifrost, tyr, vor): Contract 2.25.0 and proposal v2 in bifrost first (schema and validation, `command-binding` publish checks, Vor profile 0.1.0 parser, approve and Heimdall link checks, precondition from the read binding, OPA `input.methods`, fixtures with mixer2, G3, `COMMAND-PROPOSAL.md`, `INTEGRATION.md`, `ENTERPRISE.md`), then tyr (authoring `command-binding`, contract copy), then vor (`vor-propose` v2 and link resolution, fixtures, injection gate, crosscheck), landing under stage B with `link.command` equal to the data edge.
4. Step 4 (bifrost, vor): Stage A in bifrost (session, required `COMMAND_LEDGER_PATH`, persisted bdSeq, own reconnect, `SPB_EDGE` default changed to a command-edge name, four-rule NCMD dispatch preserving setpoints, effective-URI resolution and SAN validation prior to connect, RESULT/QUERY under the command edge, STATUS removed and its users migrated, class comment, G4, docs), `run-yggdrasil-full-loop-gate.sh` moving Heimdall and its command publisher to the command edge, vor injection gate watching for zero Heimdall traffic on `spBv1.0/<group>/+/<data-edge>`, and the link's `command.edge` changing to the command edge.
5. Step 5 (bifrost, tyr): Contract 2.26.0 `endpointRef`, `command.link.endpoint`, G5.

### Non-goals
- DBIRTH and DCMD payloads (devices are not modelled by Heimdall; UMH reads a device id as a location, so a Heimdall device would be a phantom asset).
- Outcome metrics and diagnostic counters (deferred until a host that needs them is named).
- `commandBindingRef` field in the proposal (deferred until redundant command edges share `(device, methodNodeId)`).
- Execution-time endpoint guarantees before step 5 (arrives with contract 2.26.0 `endpointRef`).
- Unknown-outcome reconciliation and trusted edge clock (remain open from M2).
- Multi-input Methods (publish-time validation restricts links to exactly one input).

## Contracts

### Command binding (mapping contract 2.25.0)
The link is a new document kind, `command-binding`, in the published mapping release under mapping contract 2.25.0. It is stored at path `payload/command-bindings/<id>.json`. The file is covered by `release.json` digests, so the proposal's second subject commits it and the head attestation covers it; no new signature or fourth subject is added. Documents are authored in Tyr, then approved and published via `gates mapping approve` and `gates mapping publish`.

The command binding is distinct from other mapping concepts:
- It is not the ISA-95 hierarchy, which contains metadata only and names equipment rather than transport.
- It is not the command policy, which is edge-scoped, unpublished, and unattested, specifying authorized callers rather than equipment identity.
- It is not the governed definition, which defines a type rather than an instance.
- It is not a source-definition, where `accessMode` is `const "read"` across all contract versions.

| Field | Meaning |
| :--- | :--- |
| `kind` | Document kind (`command-binding`). |
| `schemaVersion` | Schema version identifier. |
| `id` | Unique document identifier. |
| `version` | Document version string. |
| `equipmentRef` | Object containing hierarchy document id, version, and `equipmentInstanceId`. |
| `readBindingRef` | Object reference `{id, version}` targeting the read-binding evidence-artifact. |
| `command` | Object `{group, edge}` defining the command node coordinates. |
| `method` | Object containing `objectNodeId`, `methodNodeId`, and `inputs` list of `{name, type, unit}`. |
| `evidenceRefs` | List of references following the mapping contract `{id, version}` convention. |

Verifiers resolve the binding by iterating the release's command bindings, resolving each `readBindingRef`, and matching the key `(read binding device, link.method.methodNodeId)` against `(target.device, method.methodNodeId)`.

Publish-time validation enforces the following codes:
- `command-binding.duplicate`: Exactly one binding per device and `methodNodeId` within a release.
- `command-binding.device-path`: The read binding's device equals the hierarchy path of `equipmentRef`.
- `command-binding.inputs`: Exactly one input with a non-empty name, type `Double`, and a valid UCUM unit code.
- `command-binding.unresolved`: A reference that does not resolve within the release.

The input unit is the declared interpretation of the input value. It is not compared with the precondition mapping's unit, as a Method input need not share the measured member's unit, and the precondition member need not be the member driven by the Method.

The link omits `connectionProfileRef`. The read binding already pins the source, which specifies its own `connectionProfileRef` (a bare id string, `"sim-opcua"` in test fixtures, nullable in some contract versions, naming no server). A duplicate field in the link could only be compared against its source original. Execution-time server identity arrives with `endpointRef` in contract 2.26.0.

### Read binding (Vor profile 0.1.0)
The read binding is an `evidence-artifact` document at `evidence/vor-read-binding.json` (schemaVersion 1.1.0) rather than a mapping-contract document. Its `file.path` points to the data file `data/vor-read-binding.json`, which contains a Vor profile (`profileVersion 0.1.0`) with fields: `streamId`, `mappingSetRef`, `mappingId`, `equipmentInstanceId`, `semanticId`, `group`, `edge`, `device`, `metric`, `governedDefinitionRef`, and `projection`. The link's `readBindingRef` names this evidence-artifact.

Vor parses the profile in `vor/src/vor/release.py`. Bifrost and Heimdall implement independent parsers for profile 0.1.0 based on the published data contract, sharing zero code, consistent with `HierarchyLocator`. An unsupported `profileVersion` or `projection` is refused.

### Command proposal v2
The proposal version is `command-proposal/v2`. It retains the eight fields from v1: `cmdId`, `streamId`, `target`, `method`, `validity`, `proposedBy`, `approvedBy`, and `evidence`.

The `target.device` field is redefined:
- `target.group` and `target.edge` name the command node receiving the NCMD payload; Heimdall must be that node.
- `target.device` names the governed equipment using the Sparkplug device id published by the data edge (`synthetic-site:line1:mixer1`). This is resolved through the read binding and never through a DBIRTH under the command edge.
- The identifiers represent Sparkplug identifiers rather than coordinates of a single topic; line 25 of `COMMAND-PROPOSAL.md` reflects this redefinition, and command policy rules continue to match all three.
- The device id is an application serialization of the ISA-95 hierarchy (contract 2.23.0), not a format mandated by the ISA-95 standard.
- The OPC UA object path is restricted to `method.objectNodeId`.

`CommandProposal.parse` enforces exact predicate types and field sets. Statements signed under v1 are refused with `command.malformed`, preventing reinterpretation of v1 signatures under v2 semantics.

The proposal omits a `commandBindingRef` field. Because uniqueness of `(device, methodNodeId)` is enforced at publication, a signed link reference could only agree with the key lookup or be refused, providing no additional verification. The trigger to add `commandBindingRef` is the introduction of multiple command bindings sharing `(device, methodNodeId)`, such as redundant command edges for one piece of equipment.

### Topics under stage A

| Topic | Publisher | Purpose |
| :--- | :--- | :--- |
| `spBv1.0/<group>/NBIRTH/<command-edge>` | Heimdall | Announces command node birth, carrying `bdSeq`, `Node Control/Rebirth`, and the declared String metric `bifrost/command/v1`. |
| `spBv1.0/<group>/NDEATH/<command-edge>` | Broker (Heimdall's Will) | Signals command node failure, carrying the NBIRTH's `bdSeq`. |
| `spBv1.0/<group>/NCMD/<command-edge>` | Requester / `gates command publish` | Transports command execution payloads (`bifrost/command/v1` or setpoint) or node control requests (`Node Control/Rebirth`). |
| `bifrost/<group>/RESULT/<command-edge>` | Heimdall | Every correlated answer (command outcome, refusal, read-back); requesters correlate via payload uuid matching `cmdId`. Not Sparkplug. |
| `bifrost/<group>/QUERY/<command-edge>` | Any consumer | A read-back request; Heimdall subscribes and answers on RESULT. Not Sparkplug. |
| `spBv1.0/<group>/+/<data-edge>` | Muninn (the data node's session) | The data edge's Sparkplug messages. Heimdall publishes nothing to these topics. |
| `bifrost/<group>/STATUS/<edge>` | None | Topic is removed; retained messages are cleared during migration. |

Heimdall models no devices and issues no DBIRTH or DCMD messages, avoiding phantom assets in hosts such as UMH that interpret device ids as physical locations. Outcome metrics are omitted, and diagnostic counters are deferred until required by an identified host. Correlated responses remain outside Sparkplug topics because Sparkplug defines no NCMD reply mechanism, and emitting process metrics would result in unintended historization by hosts such as Ignition MQTT Engine. The command ledger serves as the durable record.

### NCMD dispatch on the command edge
Dispatch runs on the command edge's NCMD prior to `handle()`:
1. No metric: Refused with `command.malformed` on RESULT.
2. Every metric is `Node Control/*` or `Properties/*`: Exactly one Boolean `Node Control/Rebirth` goes to session management (true: NBIRTH with `seq` 0 and the same `bdSeq`; false: no-op). Any other payload of this class is ignored and logged without answering on RESULT, preventing replies to the node owner's protocol on the requester's channel.
3. Otherwise more than one metric: Refused with `command.malformed` on RESULT (covers a Rebirth mixed with a command, and two setpoints). This is Bifrost's restriction rather than a Sparkplug 3.0 rule; it closes the gap where a second unsigned metric was accepted and silently dropped because the command signature covers only the first metric.
4. Otherwise one metric: Routed to `handle()` unchanged (setpoint, Method, or read).

Node Control on the QUERY topic is refused as `command.malformed`, not processed as a rebirth or a read. Preserving setpoints does not extend the Method-only command-binding guarantee (H-link) to setpoints.

### Session numbers
`bdSeq` advances on every MQTT CONNECT, including process restarts, wraps from 255 to 0, and remains unchanged during a rebirth without CONNECT per Sparkplug 3.0.

Heimdall stores `bdSeq` as a file in the directory specified by `COMMAND_LEDGER_PATH`. Under stage A, `COMMAND_LEDGER_PATH` is mandatory for node startup; Heimdall refuses to CONNECT if storage is inaccessible or the file is corrupt.

The persistence sequence per connect is:
1. Read the previous sequence value from disk.
2. Calculate the next value.
3. Write the value to disk and execute an fsync on both the file and its parent directory entry.
4. Establish the MQTT CONNECT packet using an NDEATH Will carrying this new value.
5. Publish NBIRTH carrying the same value.

A crash between disk sync and connection can skip a sequence number but cannot reuse one. This prevents an invalid death sequence where a broker holds a Will with sequence `n` following an ungraceful termination (`kill -9`) and marks a restarted node dead upon processing the delayed Will against an identical sequence `n`.

Heimdall manages reconnections directly, issuing a new Will with an incremented `bdSeq`, a fresh NBIRTH, and restored subscriptions. It disables Paho's automatic reconnect, which reuses the prior Will payload. Muninn's `EdgeSession` maintains `bdSeq` solely in memory and is not used as a pattern for Heimdall.

NBIRTH carries `seq` 0; each later message Heimdall publishes increments it.

## Verification at three points
Verification occurs independently within `vor-propose`, `gates command approve`, and Heimdall. Each verifier resolves the link directly from the pinned release using dedicated logic without shared code dependencies.

| Check | vor-propose | gates command approve | Heimdall |
| :--- | :--- | :--- | :--- |
| Existence | `link-missing` | `command.link.missing` | `command.link.missing` |
| Uniqueness | `link-ambiguous` | `command.link.ambiguous` | `command.link.ambiguous` |
| Matching | `link-mismatch` | `command.link.mismatch` | `command.link.mismatch` |

In `vor-propose`, hyphenated error codes replace `binding-mismatch`. Error details identify the specific mismatched field.

Matching validates the following conditions:
1. `target.device` matches the read binding's `device` (detail code `device`).
2. Evidence binds to the released read-binding bytes according to this evaluation order:
   - The evidence-artifact's `file.sha256` matches `release.json`'s digest for that path, and the payload bytes hash to that digest.
   - The evidence's `binding.source.sha256` matches that digest, and `binding.source.file` equals `mappings/<release-root>/<path>` exactly.
   - Field values match between the evidence binding and the parsed profile for `group`, `edge`, `device`, `metric`, and `governedDefinitionRef` (`templateRef`, `version`, `sha256`).
   - The evidence's `pin.field_id` equals the profile's `mappingId`, and `pin.file` matches the mapping-set path resolved via the profile's `mappingSetRef`.
3. `target.group` and `target.edge` match `link.command`.
4. `method.objectNodeId` and `methodNodeId` match `link.method`, and the proposal input count, names, and types match `link.method.inputs` (input values remain governed by policy constraints).

Pipeline insertion points:
- In `gates command approve`, link verification executes after `bind` and before policy evaluation (this gate has no precondition step).
- In Heimdall, verification executes after the head match and before the precondition check.
- Heimdall performs an additional check: `link.command` must match its own configured group and edge.
- Precondition evaluation replaces the `startsWith` heuristic by deriving the precondition node directly from the read binding's `mappingId` and its source definition.

The OPA `methods` table is removed as a constant from `command_method.rego`. Heimdall supplies authorization parameters dynamically via `input.methods`. This table is constructed per invocation by merging the resolved link's Method signature (`name`, `type`) with the matching command policy rule's parameter constraints (`min`, `max`). The policy reads from `input.methods`. This avoids changes to the Wasm ABI (since `OpaPolicy` evaluates with `data_addr` unset) and prevents stale authorization state. The evaluation table is never populated from proposal parameters; missing or malformed entries result in an evaluation denial.

## Server authentication
Server identity verification is implemented in two stages:
1. Server trust store: Heimdall configures a server trust store and enforces Milo's `DefaultClientCertificateValidator` (`milo-stack-core` 1.1.x), rejecting untrusted servers prior to executing reads or Method calls. This validation applies to the secure connection path (`createGoverned`). The anonymous path (`createAnonymous`, `SecurityPolicy.None` in `OpcUaApplier.java`) performs no certificate validation, so Heimdall refuses every `op=method` command when no identity is configured (`command.identity.required`); today nothing in Heimdall enforces this.
2. Endpoint binding (contract 2.26.0): The command binding adds `endpointRef`, containing the server `ApplicationUri` and certificate thumbprint. Heimdall compares the authenticated server certificate against `endpointRef` before reserving the command ledger entry, rejecting mismatches with `command.link.endpoint`.

Execution-time endpoint integrity is established only when both checks are active. A general trust store may accept several servers, so trust alone does not prove that the link authorizes this one.

## Consequences and risks
- Governed write execution requires running Muninn with the `--hierarchy` flag enabled.
- The command ledger segments log files per UTC day per edge (`CommandLedger`). Introducing a new command edge id creates new segments; `cmdId` records reserved prior to the transition cannot be resolved afterward. The risk is bounded by the 15-minute proposal validity window; cutover must occur with no inflight proposals.
- Heimdall's OPC UA application URI resolves to `HEIMDALL_APPLICATION_URI` when set, otherwise deriving as `urn:bifrost:heimdall:<foldSegment(group)>:<foldSegment(edge)>`. Two refusals run prior to any MQTT CONNECT and OPC UA connect: an existing certificate whose subjectAltName URI differs from the effective URI (or has no URI, or more than one) is refused `identity.uri.mismatch`; an override set while the identity directory holds no certificate is refused `identity.uri.override-without-certificate`. A new identity is created only under the derived URI, ensuring two edges remain two principals. The override only carries an existing certificate (self-signed or CA-issued) across a Sparkplug rename, keeping its thumbprint and server trust without certificate re-provisioning. If a site requires a CA-mandated URI scheme for new identities, client identity becomes a published, versioned field next to `endpointRef`, not a wider environment override.
- `CommandAuthorizer.fieldMatches` supports the `*` wildcard across device, group, and edge fields. Because link validation enforces exact identity checks independently of policy evaluation, a wildcard device rule cannot bypass link verification.
- Components consuming the legacy STATUS topic require migration under stage A: `run-edge-resilience-gate.sh` (assertion E2 checking the STATUS Will upon forced termination) and `TopicWatcher` (clearing retained STATUS messages). The Method gate's M1 check, which verifies that no messages appear on the node's NDATA topic, widens its filter to `spBv1.0/<group>/+/<data-edge>`. In `run-yggdrasil-full-loop-gate.sh` (which ran Muninn and Heimdall under the shared edge id `recipe-edge` as two sessions for one node), Heimdall and its command publisher move to the command edge under stage A. The Vor injection gate's check that Heimdall logged the Rebirth as ignored no longer applies because Heimdall no longer subscribes to the data edge's NCMD; it becomes a watcher on `spBv1.0/<group>/+/<data-edge>` confirming no traffic from Heimdall. Published command bindings set `command.edge` to the command edge.
- Muninn requires no code modifications; its published device id serves as the identity anchor. Mimir requires no modifications, though it may supply server-side evidence for Method signatures and certificates. The Spine gate runs Muninn without `--hierarchy` and executes no governed writes, remaining unaffected.
- Industrial plant infrastructure considerations: Ignition Edge and Cirrus Link instantiate one MQTT client per edge node. HiveMQ's Sparkplug-aware broker retains NBIRTH messages, making the command edge node discoverable. Kepware is not a Sparkplug publisher and stays the OPC UA connectivity layer. Sites enabling remote writes in gateway software (such as Ignition MQTT Transmission) must restrict write permissions on those channels to preserve Heimdall's boundary guarantees.

## Testing and gates

### G1: Server trust
- Passes: Method gate M1 succeeds when connecting to a simulator presenting a trusted certificate.
- Refused: A server hosting the identical URL with an untrusted certificate is rejected before any read or Method invocation occurs, resulting in zero Method calls.
- Refused: With no identity configured, an `op=method` command is refused `command.identity.required`, with zero Method calls.
- Negative control: Restoring the insecure validator allows the untrusted server to connect, causing the gate script to exit with a non-zero code.
- Negative control: Skipping the identity refusal lets an anonymous `op=method` command reach the Method call, causing the gate script to exit with a non-zero code.

### G2: Vor cache
- Passes: Unit tests verify cache resolution with two separate devices sharing an identical metric name under the same edge without key collisions.
- Negative control: Executing the test against the legacy cache key structure produces a collision failure.

### G3: Link
The test fixture incorporates `mixer2` (hierarchy definition, source, mapping set, read binding, command binding, and simulator Method). Existing Method gates M1–M7 and the injection gate are migrated to proposal v2.
- Passes: A v2 proposal specifying device `synthetic-site:line1:mixer1` and Mixer1's command link applies successfully.
- Refused (with zero Method calls):
  - Mixer1 evidence paired with Mixer2's Method fails at `vor-propose` (`link-mismatch`), approve, and Heimdall (`command.link.mismatch`).
  - A proposal formatted under schema v1 fails (`command.malformed`).
  - A proposal referencing device `Line1/Mixer1` fails (`command.link.missing`).
  - Evidence containing a `binding.source.sha256` that does not match the release digest fails (`command.link.mismatch`).
  - An NCMD payload combining `Node Control/Rebirth` and `bifrost/command/v1` fails (`command.malformed`).
- Refused at publish: a second binding for the same device and `methodNodeId` (`command-binding.duplicate`); a read binding whose device differs from the hierarchy path (`command-binding.device-path`); a binding with two inputs or a non-UCUM unit (`command-binding.inputs`); a `readBindingRef` that does not resolve (`command-binding.unresolved`).
- Negative control: Disabling Heimdall's link check permits execution of a cross-equipment command, causing the gate script to exit with a non-zero code.

### G4: Node
- Passes: A network watcher confirms Heimdall emits NBIRTH containing `bdSeq`, `Node Control/Rebirth`, and `bifrost/command/v1`. Emitting `Node Control/Rebirth` triggers an NBIRTH with `seq` 0 and the identical `bdSeq`. A `kill -9` process termination triggers NDEATH with the active `bdSeq` after the broker Will timer elapses (~1.5× keepalive). Rapid restart publishes an NBIRTH with `bdSeq + 1`, preventing invalidation by the earlier delayed Will. `read_governed` operations execute without interruption. A watcher monitoring `spBv1.0/<group>/+/<data-edge>` captures no traffic from Heimdall. No retained STATUS message remains on the broker. RESULT correlates on the command edge. A signed setpoint on the command edge applies. A two-metric payload and a Rebirth mixed with a command are refused `command.malformed` with zero writes. A renamed edge with the override set to the certificate's URI keeps the thumbprint and its Method applies with the unchanged server trust. An existing certificate whose URI differs from the effective URI is refused at start with zero connects. The override over an empty identity directory is refused and writes no certificate.
- Negative control: Emitting any Heimdall message onto the data edge breaks Muninn's message sequence, causing Vor to drop samples per `vor/src/vor/stream.py` rules (sequence gap, node birth, or death) and terminating the gate with a non-zero code.

### G5: Endpoint
- Passes: A command link whose `endpointRef` matches the authenticated server's ApplicationUri and certificate thumbprint applies.
- Refused: A command link specifying an `endpointRef` that differs from the connected server's ApplicationUri or certificate thumbprint is rejected with `command.link.endpoint`, resulting in zero Method calls.
- Negative control: Disabling endpoint comparison allows the Method call to apply, causing the gate script to exit with a non-zero code.

## Delivery plan
Each step is delivered as a single pull request per repository and merged in numerical order:

1. Repository `bifrost`: Add Heimdall server trust store configuration and certificate validator; refuse `op=method` without an identity (`command.identity.required`); implement gate G1; add note to ENTERPRISE table row 12.
2. Repository `vor`: Update `SampleCache` key construction to include device id; implement gate G2.
3. Contract 2.25.0 and proposal v2 implementation:
   - First, repository `bifrost`: Define schemas and validation rules; add `command-binding` publication checks; implement Vor profile 0.1.0 parser; add link verification checks to approve and Heimdall; derive preconditions from read bindings; construct dynamic OPA `input.methods`; add `mixer2` test fixtures; implement gate G3; update `COMMAND-PROPOSAL.md`, `INTEGRATION.md`, and `ENTERPRISE.md`.
   - Second, repository `tyr`: Add authoring support for `command-binding` and import updated contract schemas.
   - Third, repository `vor`: Update `vor-propose` for proposal v2 and link resolution; update fixtures; update injection gate and crosscheck tests. Merged under stage B routing with `link.command` pointing to the data edge.
4. Repository `bifrost`: Deploy stage A edge separation (implement command node session, enforce mandatory `COMMAND_LEDGER_PATH`, persist `bdSeq`, implement custom reconnection logic, add NCMD dispatch router, route RESULT and QUERY to the command edge, remove STATUS topic and migrate consumers, update class comments, implement gate G4, update documentation). Update `vor` injection gate to match new topics. Update mapping releases to set `command.edge` to the dedicated command edge id.
5. Repositories `bifrost` and `tyr`: Implement contract 2.26.0 adding `endpointRef`; implement `command.link.endpoint` validation in Heimdall; implement gate G5.

## Open questions
1. Heimdall OPC UA application URI management under stage A is resolved by using `HEIMDALL_APPLICATION_URI` when set, falling back to derivation as `urn:bifrost:heimdall:<foldSegment(group)>:<foldSegment(edge)>`. Pre-connect validation refuses subjectAltName mismatches and forbids overrides without an existing certificate, carrying existing server trust across Sparkplug renames without certificate re-provisioning while new identities derive strictly from edge identity.
2. Redundant command edges for one equipment: the trigger for introducing `commandBindingRef` (Decision 2).
3. Unknown-outcome reconciliation and the trusted edge clock remain open from M2.
