# Runtime artifact model

## Scope

DDSleuth observes behaviors that require a live distributed execution. It does not
decide whether those behaviors are exploitable or assign vulnerability severity. A
runtime artifact is a stable statement of the form:

> Under trajectory T and configuration C, boundary B produced observable behavior O,
> supported by causal evidence slice E.

This definition includes positive enforcement behavior. Suppression of an exact replay
and fresh key creation after reconnect are useful artifacts because later experiments
can detect when a mutation changes either behavior.

## Unit of observation

An artifact contains:

- a stable fingerprint over semantic behavior, never raw GUIDs, timestamps, payloads,
  or key fingerprints;
- the artifact family, observation class, and observed outcome;
- participating actors and protected resources;
- exact indexes into `evidence.json`;
- a normalized causal signature;
- the identity, authorization, key, lifecycle, transport, application, diagnostic, or
  instrumentation phases crossed by the evidence slice;
- evidence completeness and quality metadata;
- descriptive measurements that do not contain secret key values.

Observation classes include `boundary_trace`, `boundary_behavior`,
`boundary_topology`, `boundary_binding`, `boundary_capability`,
`boundary_cardinality`, `matched_semantic_differential`, `baseline_differential`,
`runtime_diagnostic`, and `instrumentation_diagnostic`.

Every cluster has one explicit class:

- `semantic`: a protocol, security-state, topology, lifecycle, or application outcome;
- `context`: a generic boundary episode or partial-order differential used to explain
  a semantic result;
- `diagnostic`: instrumentation divergence or sanitizer-confirmed memory failure.

The classes are disjoint. A process failure can therefore remain reviewable without
inflating semantic discovery counts.

## Causality

DDSleuth accepts the following relations as causal evidence:

1. bounded program-order context within one actor for evidence slicing;
2. a shared runner-generated action identifier;
3. a replay event's explicit source capture identifier;
4. a shared application message identifier inside an isolated experiment;
5. a run-local keyed fingerprint linking generated and received key material.

Cross-process line adjacency is excluded. Logs may be buffered or polled in a different
order from the protocol execution, so global adjacency would create false causal
edges.

The exported slice begins with events that establish an observation. It is closed over
explicit correlations and adds at most one preceding actor-local event per selected
event. Actor context is not recursively expanded, preventing a small observation from
degenerating into the complete trace.

## Stable behavior projection

Baseline differentials compare a partial-order projection rather than raw event JSON.
The projection contains:

- normalized semantic states with occurrence counts bucketed as `one` or `many`;
- directed edges only between events joined by an explicit action, source action,
  message, or run-local key correlation;
- boundary milestones;
- runtime and instrumentation diagnostics.

Run-local identifiers and measurements are excluded. Unrelated callback and polling
orders collapse to the same projection. At least three matched baseline repetitions
are used when available; any feature that varies within those controls is classified
as control noise and removed from mutation deltas.

Replicated controls also define a stable semantic projection. If a causal mutation
removes a stable artifact or replaces it with another outcome, DDSleuth emits a
`semantic_outcome_transition`. Added outcomes retain their native artifact family.
This makes both sides of a state transition observable instead of treating absence as
an unstructured trace difference.

## Ranking dimensions

Cluster ranking keeps independent dimensions visible:

- **novelty:** how rare the fingerprint is within the campaign;
- **reproducibility:** the Wilson 95% lower bound for the best exact-trajectory
  repeat rate, reported beside its raw rate and trial count so a single observation
  cannot masquerade as proven stability;
- **population support:** a separate Wilson lower bound over the complete campaign;
  it is breadth of observation, not exact-condition reproducibility;
- **semantic prevalence:** the best occurrence rate across schedules within one
  semantic configuration;
- **baseline divergence:** whether the artifact is a differential or occurs only under
  mutation;
- **boundary depth:** how many distinct runtime phases the slice crosses;
- **evidence quality:** structured-source coverage and execution completeness.

An artifact is `confirmed` only after at least three executions of one exact
trajectory with at least two reproductions. `confirmed_complete` additionally
requires the reproductions to come from complete executions. A strict discovery
target satisfies all of `artifact_class == semantic`, `only_under_mutation`, and
`confirmed_complete`; it is exported as `target_qualified`. Generic context clusters
are capped in review priority and excluded from semantic novelty and mutation-only
counts. Diagnostics retain separate confirmation and mutation-only accounting.

A single effect can have both a direct artifact (for example,
`delivery_cardinality=exact`) and a matched-control transition (for example,
`delivery_cardinality: missing -> exact`). Qualified clusters therefore carry a
`target_group_id` and a `target_role`. The transition is the primary view and the
direct artifact is supporting evidence. `confirmed_mutation_only_semantic_groups`
is the de-duplicated research-queue size; the cluster count remains available for
auditing every representation.

`research_priority` is a bounded weighted summary used only to order review. It must
not be converted into CVSS, exploitability, or a vulnerability label. Downstream human
or model-assisted analysis consumes the artifact and performs source tracing,
security-property definition, validation, and disclosure work.

## Minimization

A causal prefilter retains actions whose identifiers occur in the evidence slice, but
it is not proof that the artifact survives. Artifact-preserving minimization uses
delta debugging with execution in the loop: an action removal is accepted only when
the exact target fingerprint reappears. Role offsets and action delays are then reduced
under the same preservation rule. Reports retain original/minimized action counts,
timing sums, and execution-trial count.

## Research evaluation

A controlled evaluation should report:

- unique artifact clusters per execution-hour;
- time to first mutation-only artifact;
- guided versus seeded-random artifact yield under equal budgets;
- cluster stability across independent seeds;
- exact-trajectory reproduction rate;
- baseline differential precision after manual classification;
- median causal-slice reduction relative to the full trace;
- instrumentation-divergence rate;
- adapter portability using equivalent scenarios across DDS implementations.

Known seeded behaviors are useful for sensitivity measurement, but evaluation must also
include unlabeled campaigns. Otherwise the experiment measures only whether an
extractor recognizes artifacts it was explicitly designed to recognize.
