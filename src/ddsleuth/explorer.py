from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

from .artifacts import (
    ArtifactBundle,
    RuntimeArtifact,
    artifact_class,
    discover_artifacts,
    discover_matched_differential_artifacts,
    discover_matched_semantic_differential_artifacts,
    execution_is_complete,
    write_artifacts,
)
from .campaign import CampaignReport, load_manifest
from .evidence import load_evidence
from .models import JsonValue
from .scenario import load_scenario


def _semantic_key(assignments: Mapping[str, JsonValue]) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (name, json.dumps(value, sort_keys=True, separators=(",", ":")))
            for name, value in assignments.items()
            if not name.startswith("trajectory.")
        )
    )


def _trajectory_key(assignments: Mapping[str, JsonValue]) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (name, json.dumps(value, sort_keys=True, separators=(",", ":")))
            for name, value in assignments.items()
            if name != "trajectory.scheduler_seed"
        )
    )


def _is_baseline(assignments: Mapping[str, JsonValue]) -> bool:
    marker = assignments.get("trajectory.scheduler_seed")
    if marker is True:
        return True
    return (
        assignments.get("trajectory.barrier_mode") == "preserve"
        and assignments.get("trajectory.spacing_ms") == 0
        and assignments.get("trajectory.action_jitter_ms", 0) == 0
        and assignments.get("trajectory.boundary_offset_ms", 0) == 0
        and "trajectory.causal_mutation" not in assignments
    )


def _mutation_operators(assignments: Mapping[str, JsonValue]) -> tuple[str, ...]:
    operators: list[str] = []
    causal = assignments.get("trajectory.causal_mutation")
    if isinstance(causal, Mapping):
        actor = causal.get("actor", "unknown")
        action = causal.get("action_id", "unknown")
        relation = causal.get("relation", "unknown")
        anchor = causal.get("anchor_action_id", "unknown")
        operators.append(f"causal:{actor}:{action}:{relation}:{anchor}")
    if assignments.get("trajectory.barrier_mode") == "relaxed":
        operators.append("barrier:relaxed")
    boundary_offset = assignments.get("trajectory.boundary_offset_ms", 0)
    if isinstance(boundary_offset, (int, float)) and boundary_offset != 0:
        operators.append(f"boundary-offset:{boundary_offset:g}ms")
    jitter = assignments.get("trajectory.action_jitter_ms", 0)
    if isinstance(jitter, (int, float)) and jitter != 0:
        operators.append(f"action-jitter:{jitter:g}ms")
    spacing = assignments.get("trajectory.spacing_ms", 0)
    if isinstance(spacing, (int, float)) and spacing != 0:
        operators.append(f"role-spacing:{spacing:g}ms")
    return tuple(operators)


def _research_priority(
    *,
    novelty: float,
    boundary_depth: int,
    baseline_divergence: float,
    reproducibility: float,
    evidence_quality: float,
) -> int:
    depth = min(1.0, boundary_depth / 6.0)
    score = 100.0 * (
        0.25 * novelty
        + 0.20 * depth
        + 0.20 * baseline_divergence
        + 0.25 * reproducibility
        + 0.10 * evidence_quality
    )
    return max(0, min(100, round(score)))


def _wilson_lower(successes: int, trials: int, z: float = 1.959963984540054) -> float:
    if trials <= 0:
        return 0.0
    proportion = successes / trials
    denominator = 1.0 + z * z / trials
    center = proportion + z * z / (2.0 * trials)
    margin = z * math.sqrt(
        proportion * (1.0 - proportion) / trials + z * z / (4.0 * trials * trials)
    )
    return max(0.0, (center - margin) / denominator)


def _target_group_id(fingerprint: str) -> str:
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:12]
    return f"DDSLEUTH-TARGET-{digest}"


def _assign_target_groups(clusters: list[dict[str, JsonValue]]) -> None:
    """Collapse direct and differential views of one effect into one target group."""

    transitions: list[dict[str, JsonValue]] = []
    for cluster in clusters:
        cluster["target_group_id"] = None
        cluster["target_role"] = "not_qualified"
        if (
            cluster.get("target_qualified") is True
            and cluster.get("observation_class") == "matched_semantic_differential"
        ):
            fingerprint = str(cluster["fingerprint"])
            cluster["target_group_id"] = _target_group_id(fingerprint)
            cluster["target_role"] = "primary"
            transitions.append(cluster)

    for cluster in clusters:
        if cluster.get("target_qualified") is not True:
            continue
        if cluster.get("target_group_id") is not None:
            continue
        family = cluster.get("family")
        outcome = cluster.get("outcome")
        operators = set(cluster.get("mutation_operators", []))
        matches: list[dict[str, JsonValue]] = []
        for transition in transitions:
            observations = transition.get("observations")
            if not isinstance(observations, Mapping):
                continue
            mutation_outcomes = {
                value.strip()
                for value in str(observations.get("mutation_outcome", "")).split(",")
                if value.strip()
            }
            transition_operators = set(transition.get("mutation_operators", []))
            if (
                observations.get("baseline_family") == family
                and outcome in mutation_outcomes
                and bool(operators & transition_operators)
            ):
                matches.append(transition)
        if matches:
            matched = min(matches, key=lambda item: str(item["artifact_id"]))
            cluster["target_group_id"] = matched["target_group_id"]
            cluster["target_role"] = "supporting"
        else:
            fingerprint = str(cluster["fingerprint"])
            cluster["target_group_id"] = _target_group_id(fingerprint)
            cluster["target_role"] = "primary"


def analyze_exploration(
    manifest_path: Path,
    run_root: Path,
    campaign: CampaignReport,
    output_path: Path,
) -> Mapping[str, JsonValue]:
    """Aggregate neutral runtime artifacts across trajectories.

    Ranking estimates research value, not vulnerability severity. The report
    keeps novelty and reproducibility separate so a one-off rare behavior is
    not confused with a stable boundary phenomenon.
    """

    _, manifest_cases = load_manifest(manifest_path)
    by_index = {case.index: case for case in manifest_cases}
    resolved_run_root = run_root.resolve()
    occurrences: dict[str, list[dict[str, JsonValue]]] = defaultdict(list)
    exemplars: dict[str, RuntimeArtifact] = {}
    completed_trials = 0
    analyzed_trials = 0
    contexts: list[dict[str, Any]] = []

    def record(artifact: RuntimeArtifact, context: Mapping[str, Any]) -> None:
        result = context["result"]
        exemplars.setdefault(artifact.fingerprint, artifact)
        occurrences[artifact.fingerprint].append(
            {
                "scenario_id": result.scenario_id,
                "run_dir": result.run_dir,
                "repetition": result.repetition,
                "assignments": dict(result.assignments),
                "evidence_events": list(artifact.evidence_events),
                "execution_complete": artifact.execution_complete,
                "boundary_depth": artifact.boundary_depth,
                "evidence_quality": artifact.evidence_quality,
            }
        )

    for result in campaign.cases:
        if result.status != "completed":
            continue
        case = by_index.get(result.index)
        if case is None:
            raise ValueError(f"campaign references unknown manifest case {result.index}")
        scenario = load_scenario(case.scenario_path)
        run_dir = (resolved_run_root / result.run_dir).resolve()
        if not run_dir.is_relative_to(resolved_run_root):
            raise ValueError(f"campaign run directory escapes run root: {result.run_dir!r}")
        evidence = load_evidence(run_dir / "evidence.json")
        bundle = discover_artifacts(scenario, evidence)
        write_artifacts(bundle, run_dir / "artifacts.json")
        execution_complete = execution_is_complete(scenario, evidence)
        context = {
            "result": result,
            "scenario": scenario,
            "evidence": evidence,
            "run_dir": run_dir,
            "execution_complete": execution_complete,
        }
        contexts.append(context)
        analyzed_trials += 1
        if execution_complete:
            completed_trials += 1
        for artifact in bundle.artifacts:
            record(artifact, context)

    baselines: dict[tuple[tuple[str, str], ...], list[Mapping[str, Any]]] = defaultdict(list)
    for context in contexts:
        result = context["result"]
        if _is_baseline(result.assignments) and context["execution_complete"]:
            baselines[_semantic_key(result.assignments)].append(context)

    for context in contexts:
        result = context["result"]
        controls = baselines.get(_semantic_key(result.assignments), [])
        if (
            not controls
            or _is_baseline(result.assignments)
            or not context["execution_complete"]
        ):
            continue
        control_evidence = tuple(control["evidence"] for control in controls)
        differences = (
            *discover_matched_semantic_differential_artifacts(
                controls[0]["scenario"],
                control_evidence,
                context["scenario"],
                context["evidence"],
            ),
            *discover_matched_differential_artifacts(
                controls[0]["scenario"],
                control_evidence,
                context["scenario"],
                context["evidence"],
            ),
        )
        write_artifacts(
            ArtifactBundle(
                schema_version=1,
                scenario_id=context["scenario"].scenario_id,
                scenario_digest=context["scenario"].digest,
                run_id=context["evidence"].run_id,
                artifacts=differences,
            ),
            context["run_dir"] / "differential-artifacts.json",
        )
        for artifact in differences:
            record(artifact, context)

    trials_by_semantics = Counter(
        _semantic_key(context["result"].assignments) for context in contexts
    )
    trials_by_trajectory = Counter(
        _trajectory_key(context["result"].assignments) for context in contexts
    )

    clusters: list[dict[str, JsonValue]] = []
    for fingerprint, items in occurrences.items():
        exemplar = exemplars[fingerprint]
        complete_occurrences = sum(item["execution_complete"] is True for item in items)
        occurrences_by_semantics = Counter(
            _semantic_key(item["assignments"])
            for item in items
            if isinstance(item.get("assignments"), Mapping)
        )
        occurrences_by_trajectory = Counter(
            _trajectory_key(item["assignments"])
            for item in items
            if isinstance(item.get("assignments"), Mapping)
        )
        complete_occurrences_by_trajectory = Counter(
            _trajectory_key(item["assignments"])
            for item in items
            if item["execution_complete"] is True
            and isinstance(item.get("assignments"), Mapping)
        )
        semantic_prevalence = max(
            (
                count / trials_by_semantics[key]
                for key, count in occurrences_by_semantics.items()
                if trials_by_semantics[key]
            ),
            default=0.0,
        )
        reproduction_measurements = [
            (
                _wilson_lower(count, trials_by_trajectory[key]),
                count / trials_by_trajectory[key],
                count,
                trials_by_trajectory[key],
            )
            for key, count in occurrences_by_trajectory.items()
            if trials_by_trajectory[key]
        ]
        (
            reproducibility,
            reproducibility_observed,
            reproduction_occurrences,
            reproduction_trials,
        ) = max(reproduction_measurements, default=(0.0, 0.0, 0, 0))
        population_support = _wilson_lower(len(items), analyzed_trials)
        confirmed = reproduction_trials >= 3 and reproduction_occurrences >= 2
        confirmed_complete = any(
            trials_by_trajectory[key] >= 3 and count >= 2
            for key, count in complete_occurrences_by_trajectory.items()
        )
        schedule_sensitive_semantics = sum(
            0 < count < trials_by_semantics[key]
            for key, count in occurrences_by_semantics.items()
        )
        schedule_sensitive = schedule_sensitive_semantics > 0
        baseline_occurrences = sum(
            isinstance(item.get("assignments"), Mapping)
            and _is_baseline(item["assignments"])
            for item in items
        )
        baseline_complete_occurrences = sum(
            item["execution_complete"] is True
            and isinstance(item.get("assignments"), Mapping)
            and _is_baseline(item["assignments"])
            for item in items
        )
        mutation_complete_occurrences = sum(
            item["execution_complete"] is True
            and isinstance(item.get("assignments"), Mapping)
            and not _is_baseline(item["assignments"])
            for item in items
        )
        observed_only_under_mutation = baseline_occurrences == 0
        only_under_mutation = (
            baseline_complete_occurrences == 0 and mutation_complete_occurrences > 0
        )
        novelty = (
            1.0
            if analyzed_trials <= 1
            else 1.0 - min(1.0, (len(items) - 1) / (analyzed_trials - 1))
        )
        divergence = 1.0 if (
            exemplar.observation_class == "baseline_differential" or only_under_mutation
        ) else 0.0
        evidence_quality = max(float(item["evidence_quality"]) for item in items)
        boundary_depth = max(int(item["boundary_depth"]) for item in items)
        priority = _research_priority(
            novelty=novelty,
            boundary_depth=boundary_depth,
            baseline_divergence=divergence,
            reproducibility=reproducibility,
            evidence_quality=evidence_quality,
        )
        classification = artifact_class(exemplar)
        context_only = classification == "context"
        target_qualified = (
            classification == "semantic"
            and only_under_mutation
            and confirmed_complete
        )
        mutation_operators = sorted(
            {
                operator
                for item in items
                if isinstance(item.get("assignments"), Mapping)
                and not _is_baseline(item["assignments"])
                for operator in _mutation_operators(item["assignments"])
            }
        )
        if context_only:
            priority = min(priority, 25)
        clusters.append(
            {
                "artifact_id": exemplar.artifact_id,
                "fingerprint": fingerprint,
                "family": exemplar.family,
                "title": exemplar.title,
                "observation_class": exemplar.observation_class,
                "outcome": exemplar.outcome,
                "research_priority": priority,
                "novelty": round(novelty, 6),
                "reproducibility": round(reproducibility, 6),
                "reproducibility_observed": round(reproducibility_observed, 6),
                "reproduction_occurrences": reproduction_occurrences,
                "reproduction_trials": reproduction_trials,
                "population_support": round(population_support, 6),
                "confirmed": confirmed,
                "confirmed_complete": confirmed_complete,
                "artifact_class": classification,
                "context_only": context_only,
                "target_qualified": target_qualified,
                "semantic_prevalence": round(semantic_prevalence, 6),
                "baseline_divergence": round(divergence, 6),
                "boundary_depth": boundary_depth,
                "evidence_quality": round(evidence_quality, 6),
                "occurrences": len(items),
                "analyzed_trials": analyzed_trials,
                "occurrence_rate": len(items) / analyzed_trials if analyzed_trials else 0.0,
                "complete_occurrences": complete_occurrences,
                "baseline_occurrences": baseline_occurrences,
                "baseline_complete_occurrences": baseline_complete_occurrences,
                "mutation_complete_occurrences": mutation_complete_occurrences,
                "schedule_sensitive": schedule_sensitive,
                "semantic_configuration_count": len(occurrences_by_semantics),
                "schedule_sensitive_configuration_count": schedule_sensitive_semantics,
                "only_under_mutation": only_under_mutation,
                "observed_only_under_mutation": observed_only_under_mutation,
                "mutation_operators": mutation_operators,
                "actors": list(exemplar.actors),
                "resources": list(exemplar.resources),
                "boundary_phases": list(exemplar.boundary_phases),
                "causal_signature": list(exemplar.causal_signature),
                "observations": dict(exemplar.observations),
                "examples": items[:10],
            }
        )
    _assign_target_groups(clusters)
    clusters.sort(
        key=lambda item: (
            -int(item["research_priority"]),
            -float(item["novelty"]),
            str(item["artifact_id"]),
        )
    )

    manifest_raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    report: dict[str, JsonValue] = {
        "schema_version": 4,
        "exploration_kind": "stateful_runtime_artifact_discovery",
        "manifest": manifest_path.name,
        "base_scenario": manifest_raw.get("base_scenario"),
        "seed": manifest_raw.get("seed"),
        "budget": manifest_raw.get("budget"),
        "execution_budget": manifest_raw.get("execution_budget"),
        "artifact_guidance": (
            dict(campaign.selection) if campaign.selection is not None else None
        ),
        "generated_trajectories": len(manifest_cases),
        "expected_trials": campaign.trial_count,
        "analyzed_trials": analyzed_trials,
        "complete_trials": completed_trials,
        "infrastructure_errors": campaign.counts.get("error", 0),
        "artifact_cluster_count": len(clusters),
        "context_cluster_count": sum(item["context_only"] is True for item in clusters),
        "semantic_artifact_cluster_count": sum(
            item["artifact_class"] == "semantic" for item in clusters
        ),
        "diagnostic_cluster_count": sum(
            item["artifact_class"] == "diagnostic" for item in clusters
        ),
        "novel_artifact_clusters": sum(
            item["artifact_class"] == "semantic" and float(item["novelty"]) >= 0.75
            for item in clusters
        ),
        "mutation_only_artifact_clusters": sum(
            item["artifact_class"] == "semantic"
            and item["only_under_mutation"] is True
            for item in clusters
        ),
        "confirmed_artifact_clusters": sum(
            item["artifact_class"] == "semantic" and item["confirmed"] is True
            for item in clusters
        ),
        "confirmed_mutation_only_semantic_clusters": sum(
            item["target_qualified"] is True for item in clusters
        ),
        "confirmed_mutation_only_semantic_groups": len(
            {
                item["target_group_id"]
                for item in clusters
                if item["target_qualified"] is True
            }
        ),
        "mutation_only_diagnostic_clusters": sum(
            item["artifact_class"] == "diagnostic"
            and item["observed_only_under_mutation"] is True
            for item in clusters
        ),
        "confirmed_diagnostic_clusters": sum(
            item["artifact_class"] == "diagnostic" and item["confirmed"] is True
            for item in clusters
        ),
        "replicated_control_groups": sum(len(items) >= 3 for items in baselines.values()),
        "control_groups": len(baselines),
        "control_noise_features_suppressed": sum(
            int(exemplar.observations.get("baseline_noise_feature_count", 0))
            for exemplar in exemplars.values()
            if exemplar.family == "baseline_runtime_divergence"
        ),
        "artifact_clusters": clusters,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report
