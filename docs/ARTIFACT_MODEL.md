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

The five observation classes are `boundary_trace`, `boundary_behavior`,
`baseline_differential`, `runtime_diagnostic`, and `instrumentation_diagnostic`.

## Causality

DDSleuth accepts the following relations as causal evidence:

1. program order within one actor;
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

Baseline differentials compare a projection rather than raw event JSON. The projection
contains:

- normalized semantic states with occurrence counts bucketed as `one` or `many`;
- actor-local state transitions;
- actor-local three-event motifs;
- explicit cross-actor causal transitions;
- boundary milestones;
- runtime and instrumentation diagnostics.

Run-local identifiers and measurements are excluded. A difference therefore represents
a semantic outcome, ordering, or coarse multiplicity change instead of normal GUID or
key randomness.

## Ranking dimensions

Cluster ranking keeps independent dimensions visible:

- **novelty:** how rare the fingerprint is within the campaign;
- **reproducibility:** the Wilson 95% lower bound for the best exact-trajectory
  repeat rate, reported beside its raw rate and trial count so a single observation
  cannot masquerade as proven stability;
- **semantic prevalence:** the best occurrence rate across schedules within one
  semantic configuration;
- **baseline divergence:** whether the artifact is a differential or occurs only under
  mutation;
- **boundary depth:** how many distinct runtime phases the slice crosses;
- **evidence quality:** structured-source coverage and execution completeness.

`research_priority` is a bounded weighted summary used only to order review. It must
not be converted into CVSS, exploitability, or a vulnerability label. Downstream human
or model-assisted analysis consumes the artifact and performs source tracing,
security-property definition, validation, and disclosure work.

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
