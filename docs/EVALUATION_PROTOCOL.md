# Evaluation protocol

This document defines how DDSleuth results should be collected and reported.
It exists to keep a successful demonstration, a harness failure, and a security
violation from being collapsed into the same outcome.

## Experimental unit

One trial is the tuple of:

- scenario digest;
- implementation name, version, and executable digest;
- generated identity and policy artifact digests;
- matrix assignments;
- repetition index;
- normalized evidence bundle and oracle report.

Changing any element creates a different trial. Results from different scenario or
binary digests must not be pooled as repetitions of the same experiment.

## Outcomes

Each assertion returns one of three states:

- `pass`: all evidence required by the invariant was present and no violation was
  observed;
- `violation`: the evidence directly contradicts the invariant;
- `not_applicable`: instrumentation, configuration, or causal evidence was
  insufficient.

A process failure, missing process exit, observer error, or `not_applicable` assertion
makes the trial inconclusive. Infrastructure errors remain separate from semantic
outcomes. Capability claims require their own events; possession of a token is not by
itself proof of decryption, forgery, application delivery, or availability impact.

## Repetition and nondeterminism

Exploratory campaigns may use one trial per case. A result intended for disclosure or
publication should use at least ten independent trials after the scenario is frozen.
The campaign report retains each trial and reports:

- pass, violation, inconclusive, and infrastructure-error counts;
- mixed-outcome (`flaky`) status;
- violation rate;
- Wilson 95% interval.

Do not discard warm-up failures or rerun only failed cases. If a harness defect is
fixed, change the scenario or implementation artifact digest and begin a new campaign.

## Fast DDS controlled variables

The initial evaluation varies the following axes explicitly rather than relying on
object insertion order or ambient defaults:

- identity subject and grant order;
- authorized, denied, and late-joining principals;
- one and multiple recipients;
- endpoint creation, destruction, and recreation epoch;
- CryptoToken class and exact participant/endpoint route;
- metadata, data, RTPS, discovery, and liveliness protection kinds;
- session-key block threshold and sample count;
- transport and delivery mode once their adapters are available.

All checked-in scenarios use loopback. Matrix cases that mutate security policy must
materialize and sign policy artifacts per case.

## Observation modes

Results should identify their observation mode:

1. Application-only: authorization callbacks and real sample delivery.
2. Black-box protocol: packet capture and normalized RTPS/security metadata.
3. White-box boundary: token routes, run-local key fingerprints, and crypto lifecycle
   events from an observation-only source overlay.
4. Capability: controlled decryption, protected-byte construction, implementation
   acceptance, and application delivery.

White-box runs must include `observer_health`. Raw keys and stable cross-run key
identifiers are prohibited; equality is tested with an ephemeral per-run HMAC secret.

## Benchmark design

The benchmark corpus should contain four classes:

- fixed, publicly disclosed implementation vulnerabilities;
- synthetic seeded violations with one known invariant break each;
- benign edge cases that previously caused false positives;
- current implementation baselines with no presumed vulnerability.

Embargoed findings remain outside the public tree. They may be used in a private
evaluation only if their result is reported in aggregate until coordinated disclosure
permits release.

## Baselines and metrics

The research evaluation compares the framework with a static-analysis baseline and a
packet-fuzzing baseline under equal wall-clock and compute budgets. Report at least:

- validated invariant violations found;
- false positives on benign cases;
- inconclusive rate;
- time to first validated violation;
- scenario executions per hour;
- reproduction rate across clean runs;
- minimization ratio from discovering matrix case to final reproducer;
- implementation-specific code required outside the shared event/oracle core.

The primary claim is cross-layer detection, not raw crash count. A crash is counted as
a security result only after its trust boundary and attacker-controlled input are
established.

## Reproducibility record

An artifact release should include source and dependency revisions, build flags,
sanitizer configuration, host and container metadata, scenario manifests, aggregate
reports, and scripts that regenerate public identities and policies. Private keys,
raw undisclosed exploit traffic, and persistent fingerprint secrets must not be
included.

## Threats to validity

At minimum, discuss implementation instrumentation effects, loopback-only timing,
shared operating-system identity between roles, incomplete transport coverage,
vendor-specific observability, nondeterministic discovery, and the difference between
master-key distribution and derived session-key rotation. These limitations should be
measured or labeled, not hidden by a passing aggregate verdict.
