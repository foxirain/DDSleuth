# DDSleuth

**Stateful runtime security discovery for DDS.**

[![CI](https://github.com/foxirain/DDSleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/foxirain/DDSleuth/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

DDSleuth is an experimental, runtime-first framework for discovering behavioral
artifacts that emerge across DDS protocol state, participant order, endpoint
lifecycle, authorization, key distribution, transport mutation, and
application-visible delivery. It explores distributed execution trajectories and
exports compact causal observations for later human or model-assisted investigation.

> **Alpha status:** DDSleuth is a research instrument, not a production security
> control. Its checked-in scenarios are designed for authorized, isolated test
> environments.

The project starts with Fast DDS because its reference experiments cross the entire
runtime path from signed Governance and Permissions documents through CryptoToken
delivery, protected RTPS traffic, and a real application `DataReader`. The trajectory,
event, semantic, and artifact models are vendor-neutral; implementation-specific
observation belongs behind adapters.

## What this project discovers

Static analysis and LLM code review already inspect individual source paths well.
DDSleuth targets the complementary state space: it executes multiple principals with
different permissions, perturbs their order and timing, and checks relationships that
exist only across processes and protocol phases:

- the logical destination inside a security message must match its cryptographic and network recipient;
- a participant denied access to a topic must not receive key material that grants access to that topic;
- keys for one participant, endpoint, topic, or domain must not authorize another;
- revocation, rematching, rekeying, and endpoint recreation must not preserve stale authority;
- the same semantic experiment must not change security behavior solely because join
  order, delay, reconnect, revocation, or lifecycle interleaving changed.

DDSleuth stops at a ranked, replayable runtime artifact. It does not label an artifact
as a vulnerability or assign severity. Source tracing, exploitability analysis, PoC
development, and advisory writing are deliberately downstream research tasks.

## Current milestone

The Fast DDS vertical slice now includes scenario and evidence schemas, ephemeral X.509
identity generation, signed Governance and Permissions generation, structured native
events, event-driven process barriers, run-local key fingerprints, fail-closed
invariant evaluation, Cartesian and pairwise matrices, resumable repeated campaigns,
configuration and executable provenance, reliability summaries, stateful trajectory
generation, partial-trace preservation, causal artifact extraction, baseline
differentials, and schedule-sensitive artifact clustering. A vendor-neutral timed action-plan model
now drives endpoint and participant lifecycles, real certificate-expiry revocation,
and loopback transport faults. The Fast DDS probe can disconnect and recreate a
secure participant in-process; the revision-pinned observer records the resulting
remote revoke and participant master-key regeneration. A separate loopback-only
shim can drop, delay, duplicate, or replay the exact UDP wire datagram. Exploration
selects from a larger trajectory pool using semantic states, actor-local causal
motifs, boundary depth, and runtime novelty rather than truncating a precomputed
matrix. The legacy
three-party Fast DDS harness remains a private golden regression case; no
finding-specific trigger or unpatched exploit module is embedded in the public core.

The compatibility invariant evaluator covers token-recipient binding, exact outbound/inbound
token-route consistency, authorization isolation, policy overgrant, key-scope
separation, endpoint key freshness after destruction/recreation, post-revocation
authority reuse, session-key rotation delivery, observer health, and
application-visible writer impersonation.
It is not used to assign severity to discovery artifacts. Common sender key
material and recipient-specific key material are fingerprinted independently so
legitimate multi-recipient key sharing is not promoted into a false finding.

## Quick start

The Python runtime has no third-party package dependency. Identity and signed-policy
materialization additionally require the `openssl` command. Native Fast DDS probes
require their normal C++ build dependencies.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --editable .
ddsleuth --version
ddsleuth validate examples/fastdds/three_party_recipient_binding.json
./scripts/test.sh
```

Artifact extraction is independent of vulnerability evaluation:

```sh
ddsleuth extract-artifacts scenario.json run/evidence.json \
  --output run/artifacts.json
```

The optional `evaluate` command remains for invariant-regression experiments and
backward compatibility. It is not part of artifact severity or exploitability
analysis.

Existing campaigns can be reanalyzed without rerunning Fast DDS:

```sh
ddsleuth analyze-exploration trajectories/manifest.json \
  --run-root runs \
  --campaign-report runs/campaign-report.json \
  --output artifact-exploration-report.json
```

Generate unsigned Governance and Permissions documents from a scenario:

```sh
ddsleuth materialize-policies \
  examples/fastdds/three_party_recipient_binding.json \
  --output-dir .runs/policies \
  --subject 'mallory=CN=mallory, O=DDSleuth' \
  --subject 'bob=CN=bob, O=DDSleuth' \
  --subject 'alice=CN=alice, O=DDSleuth'
```

Supplying both `--signer-cert` and `--signer-key` additionally creates and verifies the S/MIME policy documents used by DDS Security.

Generate short-lived participant identities directly from the subjects declared in a
scenario:

```sh
ddsleuth materialize-identities \
  examples/fastdds/three_party_recipient_binding.json \
  --output-dir .runs/identities
```

Identity subjects use OpenSSL slash form (for example
`/CN=mallory/O=DDSleuth`). They are read back from the issued certificate in
RFC2253 form before Permissions XML is generated, so the policy is bound to the
certificate's actual canonical subject rather than the input spelling.

Private keys remain inside the ignored run directory, are mode `0600`, and are never
hashed into evidence. The manifest contains only certificate hashes and canonical
certificate subjects.

Expand selected security controls into a deterministic scenario matrix:

```sh
ddsleuth expand-matrix \
  examples/fastdds/three_party_recipient_binding.json \
  --output-dir .runs/protection-matrix \
  --strategy pairwise \
  --dimension 'governance.rtps_protection=["sign","encrypt"]' \
  --dimension 'topics.SecretTopic.metadata_protection=["sign","encrypt_with_origin_authentication"]'
```

`cartesian` is exhaustive. `pairwise` constructs a deterministic strength-2 covering
array: every value pair across every two dimensions is exercised without enumerating
the full product. The manifest records the strategy and interaction strength.

Run every generated case sequentially and produce a fail-closed campaign report:

```sh
ddsleuth run-matrix \
  .runs/protection-matrix/manifest.json \
  --run-root .runs/protection-campaign \
  --materialize-identities \
  --repetitions 10
```

Each case receives its own evidence and report directory. Interrupted campaigns can be
continued with `--resume`; existing evidence is digest-checked and re-evaluated instead
of being silently trusted. Matrix execution is sequential by default because cases may
share DDS domain and transport resources. A matrix that changes Governance or topic
policy is rejected unless each case materializes its own policy artifacts. The
`--allow-unbound-configuration` escape hatch is for harness diagnostics only; its
evidence is marked `external_unverified` and is not suitable for security conclusions.
Repeated campaigns retain every trial and report per-scenario violation rates, Wilson
95% intervals, and mixed-outcome (`flaky`) status instead of collapsing an intermittent
result into one pass/fail bit.

Explore stateful role schedules directly:

```sh
export DDSLEUTH_FASTDDS_NATIVE_PROBE=/path/to/ddsleuth_fastdds_observed_probe

ddsleuth explore \
  examples/fastdds/native_late_denied_join.json \
  --output-root .runs/late-join-exploration \
  --materialize-identities \
  --budget 24 \
  --pool-size 96 \
  --strategy artifact-guided \
  --spacing-ms 0 \
  --spacing-ms 25 \
  --spacing-ms 250 \
  --barrier-mode preserve \
  --barrier-mode relaxed
```

`preserve` trajectories retain causal event barriers while varying launch offsets.
`relaxed` trajectories remove those baseline constraints and explore participant start
orders and spacings. One zero-offset, barrier-preserving baseline is always retained,
even when only relaxed mutations or nonzero spacings are requested; the remaining
pool is selected deterministically from the configured seed. In the default
`artifact-guided` strategy, the baseline executes first. Each completed trace is
normalized into protocol states, actor-local transitions and three-event motifs,
explicit causal edges, boundary milestones, and diagnostics; GUIDs, timestamps, raw
key fingerprints, and application payloads are excluded from identity. Cross-process
log adjacency is never treated as protocol causality. Static schedule features that
produce new motifs, deeper boundary composition, or new differential behavior receive
energy when the next trajectory is selected. `--plateau-window` stops a campaign after
repeated zero-novelty trajectories (20 by default; 0 disables it). The `--budget`
limits executions while `--pool-size` controls the trajectory pool (default four times
the budget). `--action-jitter-ms` adds stable per-action timing mutations without
reordering a plan. Every trial writes `evidence.json`, `report.json`, and
`artifacts.json`; mutated trials also receive `differential-artifacts.json` when their
stable behavior projection differs from the baseline. The top-level
`exploration-report.json` keeps novelty, reproducibility, semantic prevalence,
baseline divergence, boundary depth, and evidence quality as separate dimensions.
`research_priority` orders review work only; it is not severity.

ASan, UBSan, TSan, and MSan output is normalized into `memory_safety.violation`
events and retained as a runtime diagnostic artifact even when the process cannot
complete normally. DDSleuth records the diagnostic and its preceding causal slice;
downstream analysis decides what it means.

The formal artifact fields, causal-slicing rules, ranking dimensions, and research
evaluation metrics are specified in [`docs/ARTIFACT_MODEL.md`](docs/ARTIFACT_MODEL.md).

Large structured-mode logs are compacted after event ingestion: the readable `.log`
keeps every `DDSLEUTH_EVENT` and bounded diagnostic head/tail sections, while the
byte-exact original is retained as `.log.gz`. Repetitive vendor errors therefore do
not dominate long campaign storage or discard forensic data.

Roles may also declare an ordered `actions` array. The runner validates it, writes a
versioned tab-separated plan inside the isolated run directory, and injects only that
runner-generated path into the process. For example:

```json
"actions": [
  {"id": "create-1", "at_ms": 0, "operation": "endpoint.create"},
  {"id": "match-1", "at_ms": 0, "operation": "endpoint.wait_match"},
  {"id": "write-1", "at_ms": 0, "operation": "sample.write"},
  {"id": "destroy-1", "at_ms": 25, "operation": "endpoint.destroy"},
  {"id": "disconnect", "at_ms": 50, "operation": "participant.disconnect"},
  {"id": "reconnect", "at_ms": 100, "operation": "participant.reconnect"},
  {"id": "create-2", "at_ms": 100, "operation": "endpoint.create"}
]
```

Action timestamps and arguments are ordinary scenario fields, so matrix dimensions
such as `execution.roles.1.actions.3.at_ms=[5,25,45]` can explore lifecycle timing
without adding a new probe mode for every sequence. Actions with equal timestamps keep
their declared order. `credential.wait_revoked` blocks on the implementation's real
authentication callback; a participant identity with `expires_after_seconds` is signed
with an exact second-granularity `notAfter` for this experiment. This is not a synthetic
"revoke" marker. `sample.observe TARGET WINDOW_MS` records either `target_reached` or
`expired` without turning the absence of a post-attack delivery into a process error.
See `native_participant_reconnect.json` and
`native_credential_revocation_rekey.json` for complete live cases.

Wire replay and transport faults are implemented outside the DDS API:

```sh
cmake -S probes/transport_fault -B build/transport-fault
cmake --build build/transport-fault
export DDSLEUTH_TRANSPORT_FAULT_LIBRARY="$PWD/build/transport-fault/libddsleuth_transport_fault.so"
```

Roles may then use `transport.drop_next`, `transport.delay_next`,
`transport.duplicate_next`, `transport.capture_next`, and `transport.replay_last`.
`capture_next` stores a bounded wire image without altering delivery, and replay
prefers that image over unrelated later control traffic. The shim interposes the UDP
send boundary, refuses to mutate non-loopback destinations, emits normalized events,
and has its SHA-256 recorded in evidence. `transport.replay_last` resends captured
bytes; it is not an application-level second write. For Fast DDS native scenarios the
runner disables builtin transports and DataSharing for every participant, and the
probe invokes the shim synchronously so declared action order is real wire order. A
trial is inconclusive unless every requested fault emits an action-id-correlated
applied event. See `native_transport_replay.json`.

To run a local Fast DDS golden harness, provide the executable, certificate directory, and signed policy directory through environment variables:

```sh
export DDSLEUTH_FASTDDS_PROBE=/path/to/fastdds_probe
export DDSLEUTH_FASTDDS_CERTS=/path/to/Fast-DDS/test/certs
export DDSLEUTH_FASTDDS_POLICIES=/path/to/signed/policies

ddsleuth run \
  examples/fastdds/three_party_recipient_binding.json \
  --run-dir .runs/fastdds-recipient-binding
```

The run directory contains per-role logs, `evidence.json`, `report.json`, and
`artifacts.json`.

The public native probe under `probes/fastdds_native/` provides a non-exploit secure
reader/writer driver. It consumes generated identities and policies, emits structured
authorization, lifecycle, and delivery events, and coordinates roles with
`start_after` barriers. The opt-in, revision-pinned Fast DDS source observer under
`probes/fastdds_instrumentation/` adds outbound/inbound CryptoToken route evidence and
ephemeral key-material fingerprints without changing the crypto protocol result.

The observer supports Fast DDS commit
[`f6376882050013616d1b0aeacaca2ccc9ee06874`](https://github.com/eProsima/Fast-DDS/commit/f6376882050013616d1b0aeacaca2ccc9ee06874).
It deliberately refuses other revisions;
source-context drift must be reviewed rather than fuzzily patched. Run
`./scripts/bootstrap-fastdds.sh` to prepare that exact revision, or
`./scripts/prepare-fastdds-observer.sh /path/to/Fast-DDS` for an existing clean
checkout.

Public Fast DDS scenarios now include benign delivery, exact key distribution, a live
denied participant, two authorized recipients, writer endpoint recreation, a denied
participant that joins after protected traffic has already flowed, forced session-key
rotation under continuous protected delivery, and an action-plan-driven writer
lifecycle, participant reconnect, certificate-expiry revocation with participant
rekey, and exact UDP replay. The
recreation scenario deletes and recreates a real writer inside one participant,
requires two application deliveries, and checks that user-endpoint key fingerprints
are disjoint across the destruction boundary. The late-join scenario keeps the real
writer alive after delivery and checks both authorization denial and absence of user
endpoint key disclosure during subsequent secure discovery. See both probe READMEs
for their build contracts. The rotation scenario lowers Fast DDS
`maxblockspersession`, publishes a numbered sequence, observes the actual crypto
transform session transition, and correlates every rotation-triggering sample with a
real application receive.

## Safety and disclosure

The checked-in scenarios are restricted to loopback execution by default. Private keys, signed policy artifacts, raw vendor-specific exploit modules, and embargoed vulnerability cases are excluded from version control. New implementation flaws should be reported to the affected vendor before a trigger or capability module is published.

See [Architecture](docs/ARCHITECTURE.md), [event model](docs/EVENT_MODEL.md),
[evaluation protocol](docs/EVALUATION_PROTOCOL.md),
[research plan](docs/RESEARCH_PLAN.md), and [security policy](SECURITY.md).

## Releasing

Install the release extras and run the complete gate before tagging:

```sh
python -m pip install --editable '.[release]'
./scripts/release-check.sh
```

The gate runs unit and native-header tests, materializes and verifies identities and
signed policies, builds an sdist and then builds the wheel from that sdist, checks both
artifacts' metadata and contents, and installs the wheel into a clean virtual
environment.
