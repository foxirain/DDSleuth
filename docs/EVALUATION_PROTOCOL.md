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
- trajectory selection rank and cumulative runtime artifact coverage when guidance is enabled;
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

A process failure, missing process exit, execution divergence, observer error, missing
transport-fault acknowledgement, or `not_applicable` assertion makes the trial
inconclusive. Infrastructure errors remain separate from semantic outcomes. Capability
claims require their own events; possession of a token is not by itself proof of
decryption, forgery, application delivery, or availability impact. Sanitizer-confirmed
native failures are retained as runtime diagnostic artifacts even though the trial
verdict is necessarily inconclusive.

An inconclusive trial may still contain a runtime artifact. Artifact extraction
operates on the preserved prefix, records `execution_complete`, and exports the exact
causal slice. This does not convert an incomplete trial into a vulnerability verdict;
it prevents an earlier observation from being discarded by a later barrier or process
failure.

## Repetition and nondeterminism

Exploratory campaigns use at least three matched control trials and may begin with one
trial per mutation. A newly observed semantic artifact receives bounded confirmation
trials of the exact trajectory. A result intended for disclosure or publication should
use at least ten independent trials after the scenario is frozen.
The campaign report retains each trial and reports:

- pass, violation, inconclusive, and infrastructure-error counts;
- mixed-outcome (`flaky`) status;
- violation rate;
- Wilson 95% interval.

Do not discard warm-up failures or rerun only failed cases. If a harness defect is
fixed, change the scenario or implementation artifact digest and begin a new campaign.
Features that vary among matched controls are reported as control noise and excluded
from baseline differentials; they are not silently deleted from the original evidence.

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
- participant disconnect/reconnect and exact credential-expiry time;
- UDP drop, delay, duplication, explicit capture, and exact replay action;
- transport and delivery mode.

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
5. Transport fault: an opt-in loopback syscall boundary that records the exact fault
   applied without storing packet contents.

White-box runs must include `observer_health`. Raw keys and stable cross-run key
identifiers are prohibited; equality is tested with an ephemeral per-run HMAC secret.

## Benchmark design

The benchmark corpus should contain five classes:

- fixed, publicly disclosed implementation vulnerabilities;
- synthetic seeded violations with one known invariant break each;
- benign edge cases that previously caused false positives;
- current implementation baselines with no presumed vulnerability.
- unlabeled trajectory campaigns used to measure genuinely new artifact discovery.

Embargoed findings remain outside the public tree. They may be used in a private
evaluation only if their result is reported in aggregate until coordinated disclosure
permits release.

## Baselines and metrics

The research evaluation compares the framework with seeded-random scheduling, a
static-analysis baseline, and a packet-fuzzing baseline under equal wall-clock and
compute budgets. Report at least:

- unique artifact clusters per execution-hour;
- semantic artifact clusters and context-only boundary clusters separately;
- time to first mutation-only artifact;
- novelty and exact-trajectory reproducibility as separate distributions;
- population support, confirmed-cluster count, and control-noise features suppressed;
- semantic prevalence and schedule sensitivity;
- baseline differential precision after manual classification;
- median causal-slice reduction relative to the complete trace;
- instrumentation-divergence and inconclusive rates;
- runtime states, partial-order causal edges, semantic artifacts, and boundary phases
  covered per execution;
- artifact-guided versus seeded-random yield under the same budget;
- cluster stability across independent scheduler seeds;
- original/minimized action counts and executions required by artifact-preserving
  delta debugging;
- implementation-specific code required outside the shared event/artifact core.

Validated vulnerabilities may be reported as a downstream outcome, but vulnerability
yield is not an artifact-engine label and must not train the scheduler into asserting
severity.

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
