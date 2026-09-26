# Research plan

## Thesis

Security-relevant runtime artifacts that static analysis cannot directly observe can
be found systematically by exploring multi-principal trajectories, modeling causal
state transitions, and preserving compact evidence at protocol boundaries. Separate
downstream analysis determines whether an artifact is a vulnerability.

## Research questions

1. Which state-, timing-, and order-dependent behaviors are observable only in live DDS executions?
2. Which event, causal, and artifact abstractions transfer across DDS Security implementations?
3. Which topology, lifecycle, transport, and interoperability mutations maximize novel artifact yield?
4. How well do novelty, boundary depth, differential behavior, and reproducibility prioritize later research?
5. What nondeterminism and instrumentation-divergence rates result from each observation mode?

## Milestones

### M1 — Fast DDS golden vertical slice

- Normalize the existing three-party harness output.
- Reproduce policy denial, cross-recipient token delivery, key disclosure, decryption, forgery, and application delivery.
- Remove finding-specific assumptions from the core.

### M2 — Native Fast DDS adapter

- [x] Replace text markers with structured event emission.
- [x] Generate identities, Governance, and Permissions from scenarios.
- [x] Replace runner sleeps and file polling with explicit event barriers.
- Parameterize topics, partitions, protection kinds, transports, and endpoint directions.
- [x] Build a public benign native probe for endpoint authorization and delivery.
- [x] Build an opt-in Fast DDS SecurityManager observer with route-bound,
  run-local key fingerprints and fail-closed transport consistency checks.

### M3 — Fast DDS invariant matrix

- [x] Deterministic Cartesian scenario expansion and resumable campaign execution.
- [x] Deterministic pairwise covering arrays for high-dimensional interaction search.
- [x] Repeated trials, flake detection, and confidence intervals.
- Participant, DataWriter, and DataReader CryptoTokens.
- [x] Multiple authorized and unauthorized recipients.
- Synchronous and asynchronous delivery.
- [x] Endpoint recreation with pre/post key-freshness and delivery checks.
- [x] Denied late join after an established protected association.
- [x] Protocol-driven session rekey with triggering-sample delivery correlation.
- [x] Secure participant reconnect with pre/post application delivery.
- [x] Exact X.509 expiry, remote credential revocation, and participant master-key rekey.
- [x] Exact loopback UDP replay plus drop/delay/duplication fault actions.
- Authorized late join and broader credential replacement/CRL experiments.
- Unicast and multicast recipient sets.

### M3.5 — Stateful discovery engine

- [x] Deterministic role-order, barrier-mode, and launch-spacing trajectories.
- [x] Preserve partial security traces after process and barrier divergence.
- [x] Preserve legacy security leads as an optional compatibility analysis layer.
- [x] Extract neutral boundary behavior independently of trial verdict.
- [x] Cluster artifacts across schedules and rank research value without severity.
- [x] Split common sender and recipient-specific Fast DDS key semantics.
- [x] Vendor-neutral timed role actions with a Fast DDS executor for endpoint create,
  match, write/wait, destroy, and recreation inside one long-lived participant.
- [x] Extend the action protocol to participant reconnect, real credential revocation,
  explicit revocation-driven rekey evidence, replay, and controlled transport faults.
- [x] Runtime coverage feedback over semantic states and transitions rather than source
  lines, with bounded pool selection and an auditable selection trace.
- [x] Replace cross-process adjacency with shared-identifier partial-order coverage,
  boundary-depth scoring, and semantic artifact guidance.
- [x] Fail closed when a requested transport mutation was not applied, force Fast DDS
  transport experiments onto UDP, and bind replay to an explicit captured wire image.
- [x] Add post-attack observation windows, coverage-plateau termination, and bounded
  lossless archival of repetitive runtime logs.
- [x] Normalize sanitizer-confirmed native memory-safety failures into neutral runtime
  diagnostic artifacts instead of generic process divergence.
- [x] Add bounded causal slices and count-bucketed baseline behavior differentials.
- [x] Separate novelty, reproducibility, semantic prevalence, baseline divergence,
  boundary depth, and evidence quality in the exploration report.
- [x] Add replicated matched controls, control-noise suppression, selective semantic
  artifact confirmation, and separate context/semantic cluster accounting.
- [x] Add key-recipient topology, identity epoch, delivery-cardinality, and
  post-revocation capability artifacts.

### M3.6 — Artifact minimization and adaptive mutation

- [x] Add execution-verified action-plan delta debugging and a causal prefilter.
- Feed minimized scenarios automatically back into the active campaign queue.
- Learn action-window mutations from observed boundary intervals rather than fixed jitter alone.
- [x] Add fixed boundary-focused offsets as the precursor to learned action windows.
- [x] Add partial-order reduction for independent actor and callback ordering.
- Add sequence-aware transport targeting for RTPS submessage classes.
- [x] Add cross-run semantic-feature persistence and corpus deduplication.
- Add deterministic campaign checkpoint/resume for scheduler state.

### M4 — Second implementation

- Add a Cyclone DDS adapter.
- Run the same invariant suite without changing oracle code.
- Record implementation-specific observability limitations.

### M5 — Differential and mixed-vendor execution

- Add OpenDDS.
- Execute homogeneous and mixed-vendor matrices.
- Normalize security events and minimize divergent scenarios.

### M6 — Evaluation and research artifact

- Known-vulnerability and seeded-bug benchmark corpus.
- Detection, false-positive, repeatability, and minimization measurements.
- Comparison with static analysis and protocol fuzzing baselines.
- Artifact precision after manual semantic classification, schedule sensitivity,
  causal-slice reduction, cluster stability, and downstream validated-finding yield.
- Reproducible containers and paper artifact.

## Publication gates

No unpatched vendor-specific trigger or exploit-capability module is published before coordinated disclosure. Public benchmarks must be fixed, already public, synthetic, or explicitly approved for release.
