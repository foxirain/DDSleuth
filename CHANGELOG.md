# Changelog

All notable changes are recorded here. Versions follow Semantic Versioning, with
Python pre-release spelling used for packages (`0.1.0a1`) and a human-readable Git tag
(`v0.1.0-alpha.1`).

## 0.2.0-alpha.1 — Unreleased

- reposition the core as stateful runtime security discovery rather than a PoC prover;
- add deterministic role-order, launch-spacing, and barrier-mode trajectory search;
- preserve normalized evidence when a later process or event barrier diverges;
- extract and rank stable runtime candidates independently of pass/inconclusive status;
- cluster candidates across schedules and mark mutation-only signals;
- support numeric array components in matrix mutation paths;
- infer unauthorized application delivery directly from declared policy;
- split Fast DDS common sender and recipient-specific key fingerprints to prevent
  legitimate multi-recipient sharing from becoming a scope-collision false positive;
- map received DataWriter/DataReader key material to subscribe/publish authority in
  the correct direction, eliminating normal protected-writer pairing false positives;
- always retain a zero-offset causal baseline and compare schedule sensitivity within
  each semantic matrix configuration;
- collapse identical token-route retransmissions during schedule differencing so
  reliable-transport retries do not become security candidates;
- add validated, runner-materialized timed role action plans and Fast DDS scripted
  endpoint lifecycle execution inside long-lived secure participants.

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
