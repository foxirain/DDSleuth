# Normalized event model

Adapters translate implementation-specific observations into events. Oracles consume only this model and the scenario; they must not parse vendor logs or inspect vendor-private objects.

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
| `application.write_attempt` | A sample was fully populated and is about to enter the DDS write call |
| `application.sample_written` | The DDS write call returned success |
| `application.sample_received` | A real application endpoint returned the sample |
| `action.started` | A runner-planned adapter action began |
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
token is consumed by a publisher. Candidate extraction applies `subscribe` and
`publish` policy checks respectively; receiving a remote reader token is not, by
itself, evidence that a writer gained read access.

`application.write_attempt` and `application.sample_written` are deliberately distinct.
A reader callback may run on another thread before `DataWriter::write()` returns, so a
receive event may legitimately precede `application.sample_written`. Cross-process
causality should use the attempt event and correlate `sample_index` plus `message` (or
an adapter-specific opaque sample identifier), not assume that log line order grouped
by process is causal order.

`action.started` and `action.completed` bracket one adapter action from the
runner-generated plan. They contain the action id, adapter-owned operation name, and
declared relative timestamp. These events are execution context rather than security
conclusions; endpoint, authorization, key, and application events produced between
them remain the evidence consumed by security invariants.
