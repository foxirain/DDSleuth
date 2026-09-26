# Changelog

All notable changes are recorded here. Versions follow Semantic Versioning, with
Python pre-release spelling used for packages (`0.1.0a1`) and a human-readable Git tag
(`v0.1.0-alpha.1`).

## 0.4.0-alpha.1 — Unreleased

### Changed

- make adjacent action-order crossings around credential, key, participant,
  endpoint, and transport boundaries part of the default trajectory pool;
- prioritize causal state-transition mutations over broad clock jitter and feed
  matched-control semantic deltas directly into scheduler reward;
- represent removal or replacement of a stable control outcome as a first-class
  `semantic_outcome_transition` artifact;
- require complete executions for strict mutation-only semantic qualification while
  retaining incomplete observations as diagnostics;
- classify semantic, context, and diagnostic clusters independently in exploration
  report schema v4;
- use one execution-completeness contract across scheduling, confirmation, and
  reporting;
- fail native probe lifecycle preconditions explicitly instead of dereferencing a
  null publisher or subscriber after a causally invalid reconnect ordering;
- install the declared setuptools backend and wheel command with release extras so
  the no-isolation package gate works in a clean Python 3.12 environment.

### Added

- `confirmed_mutation_only_semantic_clusters` as the strict discovery target;
- de-duplicated target groups that link direct and matched-control views of the same
  dynamic effect;
- exact mutation-operator provenance, baseline support, complete-occurrence counts,
  and diagnostic-only aggregate metrics;
- `--no-causal-order-mutations` for controlled ablation experiments.

## 0.3.0-alpha.1 — 2026-09-26

### Changed

- canonicalize differential traces as partial orders over explicit action, message,
  key, and lifecycle correlations instead of actor callback adjacency;
- repeat matched baselines separately from the exploration budget, suppress features
  that vary within controls, and distinguish population support from exact-trajectory
  reproducibility;
- automatically confirm newly observed semantic artifacts without repeating the full
  trajectory matrix;
- focus timing mutations on revoke, rekey, reconnect, endpoint-lifecycle, and transport
  boundaries;
- guide future selections with semantic artifact fingerprints and a persistent cross-run
  corpus rather than raw actor-local motif novelty;
- classify generic boundary episodes as context-only clusters so they do not inflate
  novel or mutation-only semantic artifact counts.

### Added

- key-recipient topology, identity/GUID epoch, post-revocation capability, and delivery
  cardinality artifact families;
- dynamically verified action-plan delta debugging plus a causal reduction prefilter;
- control-noise, replicated-control, confirmed-cluster, context-cluster, and semantic
  cluster metrics in exploration report schema v3.

## 0.2.0-alpha.1

- reposition the core as stateful runtime security discovery rather than a PoC prover;
- make neutral runtime artifacts, rather than vulnerability candidates, the default
  output of run, campaign, and exploration workflows;
- add stable artifact fingerprints, bounded causal evidence slices, boundary-phase
  depth, and count-bucketed baseline behavior differentials;
- rank research value using separate novelty, reproducibility, semantic prevalence,
  baseline divergence, boundary depth, and evidence-quality dimensions;
- support deterministic offline reanalysis of persisted campaign evidence without
  rerunning the DDS implementation;
- add deterministic role-order, launch-spacing, and barrier-mode trajectory search;
- preserve normalized evidence when a later process or event barrier diverges;
- extract and rank stable runtime artifacts independently of pass/inconclusive status;
- cluster artifacts across schedules and mark mutation-only observations;
- support numeric array components in matrix mutation paths;
- infer unauthorized application delivery directly from declared policy;
- split Fast DDS common sender and recipient-specific key fingerprints to prevent
  legitimate multi-recipient sharing from becoming a scope-collision false positive;
- map received DataWriter/DataReader key material to subscribe/publish authority in
  the correct direction, eliminating normal protected-writer pairing false positives;
- always retain a zero-offset causal baseline and compare schedule sensitivity within
  each semantic matrix configuration;
- collapse identical token-route retransmissions during schedule differencing so
  reliable-transport retries do not become false differential artifacts;
- add validated, runner-materialized timed role action plans and Fast DDS scripted
  endpoint lifecycle execution inside long-lived secure participants;
- add real secure-participant disconnect/reconnect and pre/post delivery scenarios;
- generate second-granularity expiring test certificates and observe public Fast DDS
  credential invalidation callbacks;
- extend the revision-pinned observer with remote-revocation and successful
  participant master-key rekey evidence;
- add a loopback-only UDP fault shim for drop, delay, duplication, and exact wire replay,
  with library provenance bound into evidence;
- add runtime semantic state/transition coverage and feedback-guided selection from a
  trajectory pool, including stable order-preserving action timing jitter;
- distinguish correlated post-revocation delivery from the benign but useful
  local-write/remote-suppression enforcement artifact;
- fail closed unless every requested transport mutation emits an action-correlated
  applied event, and force Fast DDS transport experiments away from SHM/DataSharing;
- synchronize native transport actions with the probe and add explicit wire-image
  capture so replay cannot silently select a later control datagram;
- add post-attack observation windows for negative delivery evidence;
- replace global log adjacency with actor-local and shared-identifier causal coverage,
  weighted security milestones, frontier scoring, and plateau termination;
- pair semantic controls with dynamic mutations so a large matrix cannot consume the
  entire trajectory pool with baselines;
- normalize ASan/UBSan/TSan/MSan memory failures into neutral runtime diagnostics;
- preserve exact large logs as gzip while keeping compact event-complete text logs.

## 0.1.0-alpha.1 — 2026-09-26

Initial research preview:

- policy-aware multi-participant scenario and evidence schemas;
- ephemeral identity and signed Governance/Permissions generation;
- event-driven Fast DDS process orchestration;
- Cartesian and pairwise campaigns with resumable repeated trials;
- run-local HMAC key-material fingerprints;
- revision-pinned Fast DDS CryptoToken and session-rotation observer overlay;
- recipient, authorization, exact-route, key-scope, endpoint-lifecycle,
  session-rotation, revocation, and application-capability oracles;
- public secure-delivery, multi-recipient, denied late-join, endpoint-recreation,
  and session-rotation scenarios.

This release is an alpha research artifact. It is not a production security control.
