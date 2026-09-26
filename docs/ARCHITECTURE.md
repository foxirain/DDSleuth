# Architecture

## Design goal

DDSleuth searches runtime states that are poorly represented by a static control-flow
view. Its product is a neutral, replayable behavioral artifact—not a vulnerability
verdict or exploit proof.

```text
Semantic scenario
       |
       v
Trajectory pool ----------> Artifact-guided scheduler <---+
                                  |                       |
                                  v                       |
Implementation adapter ----> Normalized runtime events ---+
                                  |
                                  v
                 Semantic state and partial-order engine
                                  |
                                  v
                  Artifact slicing and clustering
                                  |
                                  v
                 Ranked replayable observations
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

The artifact-guided scheduler executes a replicated causal baseline first and then
immediately uses feedback. It extracts semantic states, shared-identifier partial-order
edges, boundary milestones, semantic artifact fingerprints, and runtime diagnostics
from each trace. Global log
adjacency is excluded because poll/buffer order is not protocol causality. Run-specific
GUIDs, timestamps, fingerprints, and measurements are also excluded. New semantic
artifacts, diagnostics, milestones, causal edges, and states receive descending
weights; raw actor-local motif novelty is not rewarded. Boundary
composition is rewarded by depth—the number of distinct identity, authorization, key,
lifecycle, transport, and application phases actually crossed—without predicting
severity. The next case balances learned artifact yield with unseen static features
and an exploration term. The report retains selection order, novelty reward,
artifact-potential reward, zero-progress streak, and cumulative coverage. A
configurable plateau terminates unproductive campaigns. A persistent, secret-free
cross-run corpus carries semantic feature coverage and scheduler rewards into later
campaigns. Corpus keys are domain-separated SHA-256 identifiers; assignment values,
payloads, key fingerprints, and raw feature strings are not persisted. This is runtime protocol
coverage, not compiler source-line coverage.

Matrix dimensions remain useful for semantic controls, but they are inputs to the
trajectory generator rather than the primary abstraction. Dotted paths can address
array elements, allowing environment and command parameters of individual roles to be
varied alongside their schedule. Roles can also carry a timed, ordered action plan.
Boundary-focused offsets mutate only revoke, rekey, reconnect, lifecycle, and transport
actions; broad stable jitter remains available as a separate dimension.
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
unlaunched roles. Artifact extraction can retain observations before the divergence
without pretending the complete experiment succeeded.

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
duplication. The runner forces every Fast DDS role onto explicit loopback UDP with
DataSharing disabled. Native actions call the shim synchronously; generic programs may
use its action-plan clock. Non-loopback addresses are passed through untouched. The
library hash is part of evidence provenance, and a missing/failed applied-fault event
makes the trial incomplete rather than passing.

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
- normalized sanitizer-confirmed native memory-safety failures;
- scheduler or process divergence after a partial security trace.

Secret key bytes are never required in the normalized evidence format. Native events
carry monotonic timestamps so cross-process temporal checks do not depend on filename
or buffered log order.

## Optional invariant layer

Compatibility oracles evaluate declared properties and return `pass`, `violation`, or
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

## Artifact layer

Artifacts are observed runtime behavior, including behavior that demonstrates a
defense working correctly. Each artifact has a stable semantic fingerprint, actors,
resources, exact evidence indexes, a normalized causal signature, crossed boundary
phases, evidence quality, and an outcome. It has no risk tier, CVSS, or exploitability
claim.

Extraction has two complementary paths. Pattern-independent boundary episodes retain
a short actor-local window around authorization, credential, key, lifecycle,
transport, and diagnostic boundaries. Interpretable extractors additionally record
local/remote revocation enforcement splits, replay suppression or redelivery,
participant key-epoch transitions, key-recipient topology, identity/GUID epoch
binding, post-revocation capabilities, delivery cardinality, and runtime diagnostics. Explicit action IDs,
messages, and run-local key identifiers close the causal slice; cross-process log
adjacency never does.

Each semantic configuration retains replicated baselines. Mutated executions are
projected into count-bucketed states and edges over explicit action, message, key, and
lifecycle correlations. Features that vary among matched controls are suppressed as
normal nondeterminism. A remaining change is exported as a baseline differential
artifact, without deciding which side is correct.

The exploration aggregator clusters artifacts across schedules and repetitions. It
reports novelty, exact-trajectory reproducibility, semantic prevalence, baseline
divergence, population support, control noise, boundary depth, evidence quality,
schedule sensitivity, and mutation-only status separately. Context-only boundary
episodes do not inflate semantic cluster counts. A derived `research_priority` orders manual or model-assisted
review; it is explicitly not vulnerability severity.

When a new semantic fingerprint appears, only that exact trajectory receives bounded
confirmation executions. A causal prefilter can remove actions absent from the evidence
slice; the dynamic reducer then accepts each further removal only if an execution
reproduces the exact fingerprint.

## Campaign layer

The campaign runner verifies scenario digests, materializes per-case identities and
policies when requested, executes cases sequentially, and preserves evidence per
trial. Repetitions retain every outcome and report violation rate, Wilson interval, and
mixed-outcome status. Baseline and confirmation repetition counts are independent of
the main exploration budget. Sequential execution remains the safe default until isolation of
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
