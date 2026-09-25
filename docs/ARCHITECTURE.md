# Architecture

## Design goal

DDSleuth searches runtime states that are poorly represented by a static control-flow
view. Its product is a ranked, replayable candidate trace—not an exploit proof.

```text
Semantic scenario
       |
       v
Trajectory pool ----------> Coverage-guided scheduler <---+
                                  |                       |
                                  v                       |
Implementation adapter ----> Normalized runtime events ---+
                                  |
                                  v
                  Temporal/security invariant engine
                                  |
                                  v
                 Candidate extraction and clustering
                                  |
                                  v
                    Ranked replayable runtime leads
```

Source scanning, exploit generation, exploitability proof, and disclosure writing are
non-goals. They can consume DDSleuth output, but they are not stages of DDSleuth.

## Scenario layer

A scenario declares actors, policy intent, protected resources, implementation
configuration, process roles, and assertions. It does not contain an oracle
implementation or vendor-private object layout.

`policy.grant_order` is explicit because grant selection order can be security-relevant
when certificate subjects collide or overlap. Object insertion order and JSON
serialization order are never used as hidden policy inputs.

## Trajectory layer

A trajectory is a concrete distributed schedule: role start order, monotonic launch
offsets, event barriers, and semantic scenario assignments. `preserve` schedules keep
the baseline causal barriers. `relaxed` schedules deliberately remove them and explore
join/order races. The generator always retains a baseline and uses a deterministic seed
to select the remaining schedules under a fixed execution budget.

The coverage-guided scheduler executes the causal baseline first and extracts
semantic states plus actor-local and global transitions from each trace. Run-specific
GUIDs, timestamps, fingerprints, and measurements are intentionally excluded. Runtime
novelty rewards the schedule features that produced it; the next case balances those
learned rewards with unseen static features. The report retains the exact selection
order, per-trial novelty, and cumulative coverage. This is runtime protocol coverage,
not compiler source-line coverage. Action plans may also receive stable,
order-preserving timing jitter.

Matrix dimensions remain useful for semantic controls, but they are inputs to the
trajectory generator rather than the primary abstraction. Dotted paths can address
array elements, allowing environment and command parameters of individual roles to be
varied alongside their schedule. Roles can also carry a timed, ordered action plan.
The core validates and materializes the plan but treats action names as adapter-owned
semantics; this keeps endpoint lifecycle execution vendor-neutral while allowing
matrix paths to mutate individual action times and arguments.

## Scheduler and adapter layer

An adapter launches or attaches to one DDS implementation and translates its
observations into normalized events. White-box adapters may instrument a security
plugin or implementation boundary. Black-box adapters may use RTPS capture, controlled
participants, and application callbacks.

Native scenarios coordinate roles with structured event barriers. Launch offsets are
exploration mutations, not causal evidence. A source process that exits early or a
barrier timeout is not a passing security result. The adapter nevertheless preserves
events produced before the divergence, adds `execution.divergence`, and records
unlaunched roles. Candidate extraction can retain an earlier overgrant or key-route
anomaly without pretending the complete experiment succeeded.

Every role records the basename, size, and SHA-256 of its resolved executable. Policy,
identity-certificate, scenario, and executable digests form the configuration
provenance needed to compare or replay a trial. Absolute host paths are omitted.
Action plans are derived deterministically from the digested scenario, stored beside
the run logs, and exposed through a runner-reserved environment variable that scenario
roles cannot replace.

Participant reconnect is implemented by deleting the real secure participant and all
contained entities, creating a new participant from the bound credentials, registering
the type/topic again, and rematching endpoints. Credential revocation uses exact
short-lived X.509 certificates and waits for the implementation authentication
callback. In the Fast DDS observer build, remote revocation and the subsequent
participant-key regeneration are separate events.

Transport mutation is a distinct, opt-in boundary. The Fast DDS adapter can preload a
small UDP shim only for roles with `transport.*` actions in a loopback scenario. It
captures at most one bounded datagram and implements exact replay plus drop, delay, and
duplication. Non-loopback addresses are passed through untouched. The library hash is
part of evidence provenance.

## Evidence layer

Events record observations, not conclusions. Examples include:

- endpoint creation allowed or denied by access control;
- a CryptoToken generated or received on a concrete route;
- common sender or receiver-specific key material observed through a run-local HMAC;
- endpoint destruction and recreation boundaries;
- session rotation;
- participant disconnect/reconnect and credential invalidation;
- applied UDP drop, delay, duplication, or exact replay;
- protected data returned by a real application reader;
- scheduler or process divergence after a partial security trace.

Secret key bytes are never required in the normalized evidence format. Native events
carry monotonic timestamps so cross-process temporal checks do not depend on filename
or buffered log order.

## Semantic invariant layer

Oracles evaluate declared properties and return `pass`, `violation`, or
`not_applicable` with exact event indexes. They are fail-closed: incomplete observation
does not become a pass. Capability assessment remains separate from root-cause
classification.

Instrumentation health is itself an invariant. An enabled observer must emit required
evidence and no observer error. Lifecycle oracles consume explicit destruction,
revocation, and rotation boundaries.

Fast DDS KeyMaterial is split into `common_sender` and `recipient_specific` components
before fingerprinting. Common sender material is intentionally shared by authorized
receivers; destination-scope separation applies only to recipient-specific material.
Direction is evaluated independently: received `datawriter` material requires local
subscribe authority and received `datareader` material requires local publish
authority. This prevents normal protected writer/reader pairing from being promoted
as unauthorized key delivery.

## Candidate layer

Candidates are discovery leads, not vulnerability verdicts. A candidate has a stable
semantic fingerprint, risk tier, priority score, confidence, actors, resources, exact
event indexes, and the schedule that exposed it. Policy overgrant, unauthorized
application delivery, unauthorized user-key delivery, temporal invariant violations,
and partial stateful divergences are extracted independently of process success.

The exploration aggregator clusters the same candidate across trajectories and
repetitions. It reports occurrence rate, complete-run occurrences, schedule
sensitivity, and whether the signal appeared only after schedule mutation. Candidate
ranking never upgrades a lead into a CVSS or exploitability claim.

Post-revocation writes are correlated with later application delivery by message. An
actual delivery from a locally revoked participant is emitted as a `critical_lead`,
while the mere ability to call a write API is not treated as compromise.

## Campaign layer

The campaign runner verifies scenario digests, materializes per-case identities and
policies when requested, executes cases sequentially, and preserves evidence per
trial. Repetitions retain every outcome and report violation rate, Wilson interval, and
mixed-outcome status. Sequential execution remains the safe default until isolation of
DDS domains and transport resources can be proven.

Policy mutations are fail-closed. A campaign must materialize and sign policy artifacts
per case, or explicitly mark an external configuration as unverified for diagnostics.

## Fast DDS first and portability boundary

Fast DDS is the reference target because the current vertical slice covers signed
policies, multiple identities, endpoint matching, volatile-secure token delivery,
AES-GCM-GMAC material, lifecycle transitions, session rotation, and application
delivery. The core does not import Fast DDS headers or depend on its GUID layout.

Future Cyclone DDS, OpenDDS, and Connext adapters must emit the same normalized event
types. Portable scenarios should require only adapter configuration changes.
