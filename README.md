# DDSleuth

**Cross-layer security invariant testing for DDS.**

[![CI](https://github.com/foxirain/DDSleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/foxirain/DDSleuth/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

DDSleuth is an experimental, policy-aware framework for testing security invariants
across DDS participants, security plugins, RTPS traffic, and application-visible
effects.

> **Alpha status:** DDSleuth is a research instrument, not a production security
> control. Its checked-in scenarios are designed for authorized, isolated test
> environments.

The project starts with Fast DDS because we have a complete three-participant reference experiment that crosses the entire path from signed Governance and Permissions documents through CryptoToken delivery, protected RTPS traffic, and a real application `DataReader`. The core event model and invariant engine are vendor-neutral; implementation-specific behavior belongs behind adapters.

## What this project tests

Traditional static analysis inspects one codebase. DDSleuth instead executes multiple principals with deliberately different permissions and checks relationships that span processes and protocol layers:

- the logical destination inside a security message must match its cryptographic and network recipient;
- a participant denied access to a topic must not receive key material that grants access to that topic;
- keys for one participant, endpoint, topic, or domain must not authorize another;
- revocation, rematching, rekeying, and endpoint recreation must not preserve stale authority;
- an unexpected token or key is escalated only when its real decrypt, forge, or application-delivery capability is demonstrated.

## Current milestone

The Fast DDS vertical slice now includes scenario and evidence schemas, ephemeral X.509
identity generation, signed Governance and Permissions generation, structured native
events, event-driven process barriers, run-local key fingerprints, fail-closed
invariant evaluation, Cartesian and pairwise matrices, resumable repeated campaigns,
configuration and executable provenance, and reliability summaries. The legacy
three-party Fast DDS harness remains a private golden regression case; no
finding-specific trigger or unpatched exploit module is embedded in the public core.

Implemented invariant families cover token-recipient binding, exact outbound/inbound
token-route consistency, authorization isolation, policy overgrant, key-scope
separation, endpoint key freshness after destruction/recreation, post-revocation
authority reuse, session-key rotation delivery, observer health, and
application-visible writer impersonation.
Capability scoring is kept separate from root-cause classification.

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

To run a local Fast DDS golden harness, provide the executable, certificate directory, and signed policy directory through environment variables:

```sh
export DDSLEUTH_FASTDDS_PROBE=/path/to/fastdds_probe
export DDSLEUTH_FASTDDS_CERTS=/path/to/Fast-DDS/test/certs
export DDSLEUTH_FASTDDS_POLICIES=/path/to/signed/policies

ddsleuth run \
  examples/fastdds/three_party_recipient_binding.json \
  --run-dir .runs/fastdds-recipient-binding
```

The run directory contains per-role logs, `evidence.json`, and `report.json`.

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
denied participant, two authorized recipients, writer endpoint recreation, and a
denied participant that joins after protected traffic has already flowed, and forced
session-key rotation under continuous protected delivery. The
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
