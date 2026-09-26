# Research plan

## Thesis

Security faults that static analysis misses can be found systematically by exploring
multi-principal runtime trajectories and checking temporal, authorization, key-routing,
lifecycle, and application-delivery invariants across distributed state transitions.

## Research questions

1. Which state-, timing-, and order-dependent security faults are missed by conventional static analysis and packet fuzzing?
2. How much of one invariant suite can be reused across independent DDS Security implementations?
3. Which topology, lifecycle, and interoperability mutations expose the most security boundary violations?
4. Which runtime signals most reliably predict a later validated High/Critical finding?
5. What false-positive and nondeterminism rates result from each observation mode?

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
- [x] Extract policy overgrant, unauthorized delivery, user-key route, temporal,
  and execution-divergence candidates independently of trial verdict.
- [x] Cluster candidates across schedules and rank schedule-sensitive leads.
- [x] Split common sender and recipient-specific Fast DDS key semantics.
- [x] Vendor-neutral timed role actions with a Fast DDS executor for endpoint create,
  match, write/wait, destroy, and recreation inside one long-lived participant.
- [x] Extend the action protocol to participant reconnect, real credential revocation,
  explicit revocation-driven rekey evidence, replay, and controlled transport faults.
- [x] Runtime coverage feedback over semantic states and transitions rather than source
  lines, with bounded pool selection and an auditable selection trace.
- [x] Replace cross-process adjacency with actor-local and shared-identifier causal
  coverage, weighted security milestones, and High/Critical frontier scoring.
- [x] Fail closed when a requested transport mutation was not applied, force Fast DDS
  transport experiments onto UDP, and bind replay to an explicit captured wire image.
- [x] Add post-attack observation windows, coverage-plateau termination, and bounded
  lossless archival of repetitive runtime logs.
- [x] Normalize sanitizer-confirmed native memory-safety failures into ranked High
  discovery leads instead of generic process divergence.

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
- Candidate precision, schedule sensitivity, and validated High/Critical yield.
- Reproducible containers and paper artifact.

## Publication gates

No unpatched vendor-specific trigger or exploit-capability module is published before coordinated disclosure. Public benchmarks must be fixed, already public, synthetic, or explicitly approved for release.
