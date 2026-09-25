# Research plan

## Thesis

Security faults in DDS implementations can be found systematically by generating multi-principal policy topologies and checking cross-layer invariants between authorization policy, logical token destination, cryptographic recipient, key lifecycle, wire identity, and application-visible effects.

## Research questions

1. Which policy and recipient-binding flaws are missed by conventional static analysis and packet fuzzing?
2. How much of one invariant suite can be reused across independent DDS Security implementations?
3. Which topology, lifecycle, and interoperability mutations expose the most security boundary violations?
4. How reliably can an unexpected token or key be escalated into demonstrated confidentiality, integrity, or availability impact?
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
- Authorized late join, reconnect, credential expiration, and revocation.
- Unicast and multicast recipient sets.

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
- Reproducible containers and paper artifact.

## Publication gates

No unpatched vendor-specific trigger or exploit-capability module is published before coordinated disclosure. Public benchmarks must be fixed, already public, synthetic, or explicitly approved for release.
