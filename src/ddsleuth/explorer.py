from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

from .campaign import CampaignReport, load_manifest
from .candidates import (
    CandidateBundle,
    DiscoveryCandidate,
    discover_candidates,
    discover_schedule_differences,
    write_candidates,
)
from .evidence import load_evidence
from .models import JsonValue
from .oracles.evaluate import evaluate
from .scenario import load_scenario


def analyze_exploration(
    manifest_path: Path,
    run_root: Path,
    campaign: CampaignReport,
    output_path: Path,
) -> Mapping[str, JsonValue]:
    _, manifest_cases = load_manifest(manifest_path)
    by_index = {case.index: case for case in manifest_cases}
    occurrences: dict[str, list[dict[str, JsonValue]]] = defaultdict(list)
    exemplars: dict[str, DiscoveryCandidate] = {}
    completed_trials = 0
    analyzed_trials = 0
    contexts: list[dict[str, Any]] = []

    def semantic_key(assignments: Mapping[str, JsonValue]) -> tuple[tuple[str, str], ...]:
        return tuple(
            sorted(
                (name, json.dumps(value, sort_keys=True, separators=(",", ":")))
                for name, value in assignments.items()
                if not name.startswith("trajectory.")
            )
        )

    def record(candidate: DiscoveryCandidate, context: Mapping[str, Any]) -> None:
        result = context["result"]
        exemplars.setdefault(candidate.fingerprint, candidate)
        occurrences[candidate.fingerprint].append(
            {
                "scenario_id": result.scenario_id,
                "run_dir": result.run_dir,
                "repetition": result.repetition,
                "assignments": dict(result.assignments),
                "evidence_events": list(candidate.evidence_events),
                "execution_complete": candidate.execution_complete,
                "score": candidate.score,
                "confidence": candidate.confidence,
            }
        )

    for result in campaign.cases:
        if result.status != "completed":
            continue
        case = by_index[result.index]
        scenario = load_scenario(case.scenario_path)
        run_dir = run_root / result.run_dir
        evidence = load_evidence(run_dir / "evidence.json")
        report = evaluate(scenario, evidence)
        bundle = discover_candidates(scenario, evidence, report)
        write_candidates(bundle, run_dir / "candidates.json")
        context = {
            "result": result,
            "scenario": scenario,
            "evidence": evidence,
            "report": report,
            "run_dir": run_dir,
        }
        contexts.append(context)
        analyzed_trials += 1
        if not report.failed_processes and not report.incomplete_processes:
            completed_trials += 1
        for candidate in bundle.candidates:
            record(candidate, context)

    baselines: dict[tuple[tuple[tuple[str, str], ...], int], Mapping[str, Any]] = {}
    for context in contexts:
        result = context["result"]
        assignments = result.assignments
        if (
            assignments.get("trajectory.barrier_mode") == "preserve"
            and assignments.get("trajectory.spacing_ms") == 0
            and assignments.get("trajectory.action_jitter_ms", 0) == 0
        ):
            baselines[(semantic_key(assignments), result.repetition)] = context

    for context in contexts:
        result = context["result"]
        baseline = baselines.get((semantic_key(result.assignments), result.repetition))
        if baseline is None or baseline is context:
            continue
        differences = discover_schedule_differences(
            baseline["scenario"],
            baseline["evidence"],
            baseline["report"],
            context["scenario"],
            context["evidence"],
            context["report"],
        )
        write_candidates(
            CandidateBundle(
                schema_version=1,
                scenario_id=context["scenario"].scenario_id,
                scenario_digest=context["scenario"].digest,
                run_id=context["evidence"].run_id,
                candidates=differences,
            ),
            context["run_dir"] / "schedule-differences.json",
        )
        for candidate in differences:
            record(candidate, context)

    trials_by_semantics = Counter(
        semantic_key(context["result"].assignments)
        for context in contexts
    )
    clusters: list[dict[str, JsonValue]] = []
    for fingerprint, items in occurrences.items():
        exemplar = exemplars[fingerprint]
        complete_occurrences = sum(item["execution_complete"] is True for item in items)
        occurrences_by_semantics = Counter(
            semantic_key(item["assignments"])
            for item in items
            if isinstance(item.get("assignments"), Mapping)
        )
        schedule_sensitive_semantics = sum(
            0 < count < trials_by_semantics[key]
            for key, count in occurrences_by_semantics.items()
        )
        # Do not call a finding schedule-sensitive merely because it belongs to
        # one semantic matrix configuration and is absent from unrelated ones.
        schedule_sensitive = schedule_sensitive_semantics > 0
        baseline_occurrences = sum(
            isinstance(item.get("assignments"), Mapping)
            and item["assignments"].get("trajectory.barrier_mode") == "preserve"
            and item["assignments"].get("trajectory.spacing_ms") == 0
            and item["assignments"].get("trajectory.action_jitter_ms", 0) == 0
            for item in items
        )
        only_under_mutation = baseline_occurrences == 0
        priority_score = min(
            100,
            exemplar.score
            + min(6, max(0, len(items) - 1))
            + (4 if schedule_sensitive else 0)
            + (3 if only_under_mutation else 0)
            + (2 if complete_occurrences else 0),
        )
        clusters.append(
            {
                "candidate_id": exemplar.candidate_id,
                "fingerprint": fingerprint,
                "family": exemplar.family,
                "title": exemplar.title,
                "risk_tier": exemplar.risk_tier,
                "priority_score": priority_score,
                "base_score": exemplar.score,
                "max_confidence": max(float(item["confidence"]) for item in items),
                "occurrences": len(items),
                "analyzed_trials": analyzed_trials,
                "occurrence_rate": len(items) / analyzed_trials if analyzed_trials else 0.0,
                "complete_occurrences": complete_occurrences,
                "schedule_sensitive": schedule_sensitive,
                "semantic_configuration_count": len(occurrences_by_semantics),
                "schedule_sensitive_configuration_count": schedule_sensitive_semantics,
                "only_under_mutation": only_under_mutation,
                "actors": list(exemplar.actors),
                "resources": list(exemplar.resources),
                "signals": list(exemplar.signals),
                "examples": items[:10],
            }
        )
    clusters.sort(
        key=lambda item: (
            -int(item["priority_score"]),
            -float(item["max_confidence"]),
            str(item["candidate_id"]),
        )
    )

    manifest_raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    report: dict[str, JsonValue] = {
        "schema_version": 1,
        "exploration_kind": "stateful_runtime_security_discovery",
        "manifest": manifest_path.name,
        "base_scenario": manifest_raw.get("base_scenario"),
        "seed": manifest_raw.get("seed"),
        "budget": manifest_raw.get("budget"),
        "execution_budget": manifest_raw.get("execution_budget"),
        "coverage_guidance": (
            dict(campaign.selection) if campaign.selection is not None else None
        ),
        "generated_trajectories": len(manifest_cases),
        "expected_trials": campaign.trial_count,
        "analyzed_trials": analyzed_trials,
        "complete_trials": completed_trials,
        "infrastructure_errors": campaign.counts.get("error", 0),
        "candidate_cluster_count": len(clusters),
        "high_or_critical_leads": sum(
            item["risk_tier"] in ("high_lead", "critical_lead") for item in clusters
        ),
        "candidate_clusters": clusters,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report
