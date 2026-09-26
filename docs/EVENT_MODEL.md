# Normalized event model

Adapters translate implementation-specific observations into events. Artifact
extraction and optional compatibility oracles consume only this model and the
scenario; they must not parse vendor logs or inspect vendor-private objects.

## Event envelope

```json
{
  "sequence": 2,
  "kind": "crypto_token.observed",
  "actor": "mallory",
  "implementation": "fastdds",
  "outcome": "observed",
  "monotonic_ns": 1234567890,
  "source": "mallory.log",
  "attributes": {
    "token_class": "datawriter",
    "local_participant_guid": "...",
    "destination_participant_guid": "..."
  }
}
```

`kind`, `actor`, `implementation`, and `outcome` are required. `attributes` carries event-specific facts. `source` identifies the concrete log, packet capture, callback, or probe that produced the observation.

Native probes add `monotonic_ns` from the host steady clock. The runner tails all role
logs while they execute and sorts a fully timestamped native event set before assigning
canonical `sequence` values. Legacy logs without timestamps retain source order and
must not be used for cross-process lifecycle ordering claims.

Differential discovery does not compare the merged event list directly. It builds a
partial-order projection from semantic state multiplicity and edges backed by shared
`action_id`/`source_action_id`, application message, or run-local key fingerprint.
Unrelated actor and callback order is therefore observational noise rather than a new
artifact. Actor-local adjacency remains available as diagnostic coverage only and is
not rewarded by the artifact-guided scheduler.

## Evidence discipline

- Events record observations, not severity conclusions.
- Key bytes, private keys, passwords, and certificate private material are not stored.
- Key equality tests use `hmac-sha256-run-local-v1`. The runner generates one
  random 256-bit HMAC secret for the process group, passes it only to that run, and
  does not persist it. Native and Python probes therefore produce comparable
  `key_fingerprint` values inside one run without exposing raw keys or creating a
  stable cross-run key identifier.
- An adapter must distinguish an observed value from an inferred value.
- Missing evidence is not a passing result when an execution process failed.
- A runtime acceptance event and an application-delivery event are distinct.

## Initial event kinds

| Kind | Meaning |
|---|---|
| `probe.ready` | A process reached a named coordination point |
| `probe.observer_error` | White-box instrumentation failed without changing the protocol result |
| `access_control.decision` | An endpoint or operation was allowed or denied |
| `crypto_token.generated` | A local endpoint token was generated for a concrete remote route |
| `crypto_token.observed` | A participant obtained token plaintext or a normalized token view |
| `key_material.observed` | A token contained one or more key classes |
| `authorization.revoked` | A previously issued authority was revoked |
| `key.rotated` | An endpoint or participant moved to a new key/session generation |
| `endpoint_pair.observed` | A real writer/reader cryptographic association was established |
| `capability.decrypt` | Observed key material decrypted protected traffic |
| `capability.forge` | Observed key material produced protected bytes |
| `network.packet_sent` | A constructed packet entered the selected transport |
| `crypto.protected_message_accepted` | The intended implementation accepted protected bytes |
| `endpoint.matched` | A local endpoint matched its remote peer |
| `endpoint.created` | A local endpoint was created for a lifecycle epoch |
| `endpoint.destroyed` | Endpoint deletion completed and defines a key-lifecycle boundary |
| `endpoint.recreated` | A replacement endpoint was created for the next lifecycle epoch |
| `participant.disconnected` | A real participant and all contained entities were deleted |
| `participant.reconnected` | A replacement secure participant completed creation |
| `credential.authenticated` | The implementation authenticated a participant identity |
| `credential.revoked` | The implementation invalidated a local or remote identity |
| `transport.fault_armed` | A loopback UDP fault became active |
| `transport.datagram_dropped` | The shim suppressed an outbound loopback datagram |
| `transport.datagram_delayed` | The shim delayed an outbound loopback datagram |
| `transport.datagram_duplicated` | The shim duplicated an outbound loopback datagram |
| `transport.datagram_captured` | The shim retained a bounded wire image without mutating delivery |
| `transport.datagram_replayed` | The shim resent an exact captured wire datagram |
| `application.write_attempt` | A sample was fully populated and is about to enter the DDS write call |
| `application.sample_written` | The DDS write call returned success |
| `application.sample_received` | A real application endpoint returned the sample |
| `application.observation_window` | A bounded post-action window reached its target or expired |
| `memory_safety.violation` | A native sanitizer detected a normalized memory-safety failure |
| `action.started` | A runner-planned adapter action began |
| `action.delegated` | A transport action was synchronously handed to its shim |
| `action.completed` | A runner-planned adapter action completed |
| `execution.divergence` | The scheduler preserved a partial trace after timeout, barrier failure, or role failure |
| `process.exit` | A scenario role completed or failed |

The schemas under `schemas/` define the machine-readable envelope. Event-specific attribute schemas will be versioned separately as native adapters are added.

`policy_authorization_consistency` evaluates concrete access decisions against the
scenario's publish/subscribe expressions. An observed allow outside the declared
permission lattice is a violation; an unobserved decision is `not_applicable`, never a
pass. This permits identity/grant-selection experiments without putting a
vendor-specific exploit in the invariant engine.

`crypto_token_transport_consistency` joins an outbound and inbound
`key_material.observed` event by its run-local fingerprint, token class, destination
participant, destination endpoint, and source endpoint. A fingerprint received on a
different route is a violation. Missing either side is `not_applicable`, making the run
inconclusive instead of silently treating incomplete instrumentation as a pass.
Exact-route retransmissions are idempotent: receiving the same fingerprint more than
once on the route where it was generated is allowed. Only a fingerprint observed on a
different participant/endpoint route is a rebinding violation.

`observer_health` requires at least one selected white-box event and rejects any run
containing `probe.observer_error` as `not_applicable`, which makes the overall run
inconclusive. `endpoint_key_lifecycle` divides generated user-endpoint KeyMaterial at
an `endpoint.destroyed` boundary and requires disjoint run-local fingerprints before
and after recreation. Missing observations on either side are inconclusive, not pass.

`session_rotation_delivery` consumes `key.rotated` events from the crypto transform,
requires each 32-bit session identifier to advance by exactly one at the observed
rotation, and correlates the surrounding `application.write_attempt.sample_index` with
an application receive at the intended reader. The configured
`max_blocks_per_session` is checked against the scenario so an accidentally unmutated
run cannot pass as a rekey experiment.

Fast DDS white-box events label each route `endpoint_class=user` only when both
source and destination entity IDs are non-builtin. `unauthorized_key_disclosure`
uses that label plus `observation_phase=received` so discovery/liveliness key
traffic cannot be mistaken for disclosure of a denied application endpoint key.
Key-scope assertions should likewise select `observation_phase=received` and
`endpoint_class=user` when the invariant is recipient separation for application
endpoints; builtin crypto endpoints intentionally follow different key-sharing rules.
The observer also emits one fingerprint per semantic key component:
`material_semantics=common_sender` for authority intentionally shared by all intended
receivers and `material_semantics=recipient_specific` for pair-specific origin
authentication material. Recipient-scope comparison ignores the common component.
For received user-endpoint material, token direction determines the required local
authority: a `datawriter` token is consumed by a subscriber, while a `datareader`
token is consumed by a publisher. Optional invariant evaluation applies `subscribe`
and `publish` policy checks respectively; receiving a remote reader token is not, by
itself, evidence that a writer gained read access.

`application.write_attempt` and `application.sample_written` are deliberately distinct.
A reader callback may run on another thread before `DataWriter::write()` returns, so a
receive event may legitimately precede `application.sample_written`. Cross-process
causality should use the attempt event and correlate `sample_index` plus `message` (or
an adapter-specific opaque sample identifier), not assume that log line order grouped
by process is causal order.

`action.started` and `action.completed` bracket one local adapter action from the
runner-generated plan. They contain the action id, adapter-owned operation name, and
declared relative timestamp. These events are execution context rather than security
conclusions; endpoint, authorization, key, and application events produced between
them remain the evidence consumed by security invariants. A transport action emits
`action.delegated` instead of claiming local completion; the runner separately requires
the matching applied-fault event.

`credential.revoked` distinguishes `local_identity=true` from a remote invalidation.
Fast DDS may emit the same semantic transition at both the white-box boundary and the
public participant listener; artifact logic treats the event as a boundary, not a
counter. `key.rotated` with `rotation_kind=participant_master_key` is emitted only
after the crypto plugin successfully regenerates the remaining participant's key in
response to remote revocation.

Transport events are evidence from the syscall-boundary shim. They include the fault,
action id, packet length, and loopback flag, never raw packet contents. Explicit
capture records an action id, and replay adds `source_action_id` so evidence binds the
resent bytes to that stored wire image rather than an unrelated later control packet.
The runner requires every requested mutation to produce its correlated applied event;
absence or a failed outcome makes the trial inconclusive.

## Artifact projection

Artifact identity uses only semantic event fields. GUIDs, timestamps, packet lengths,
payloads, and key fingerprints remain available in evidence for correlation but are
excluded from cross-run fingerprints. Actor-local three-event motifs preserve temporal
shape without treating cross-process log adjacency as causality. See
`ARTIFACT_MODEL.md` for slicing and differential rules.
