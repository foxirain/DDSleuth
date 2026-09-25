from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from .campaign_types import ManifestCase
from .evidence import EvidenceBundle
from .models import EvidenceEvent, JsonValue
from .scenario import load_scenario


# Deliberately exclude identifiers and measurements that create one feature per
# run. Coverage is intended to describe protocol state, not byte-level noise.
_SEMANTIC_ATTRIBUTES = (
    "operation",
    "endpoint",
    "topic",
    "token_class",
    "key_class",
    "material_semantics",
    "rotation_kind",
    "context",
    "phase",
    "reason",
    "fault",
    "transport",
    "local_identity",
)


@dataclass(frozen=True, slots=True)
class RuntimeCoverage:
    states: frozenset[str]
    transitions: frozenset[str]

    @property
    def features(self) -> frozenset[str]:
        return frozenset({*(f"state:{item}" for item in self.states), *(
            f"transition:{item}" for item in self.transitions
        )})


def _stable_value(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def semantic_state(event: EvidenceEvent) -> str:
    attributes = tuple(
        (name, _stable_value(event.attributes[name]))
        for name in _SEMANTIC_ATTRIBUTES
        if name in event.attributes
    )
    suffix = "|".join(f"{name}={value}" for name, value in attributes)
    core = f"{event.actor}|{event.kind}|{event.outcome}"
    return f"{core}|{suffix}" if suffix else core


def extract_runtime_coverage(evidence: EvidenceBundle) -> RuntimeCoverage:
    states: set[str] = set()
    transitions: set[str] = set()
    previous_global: str | None = None
    previous_by_actor: dict[str, str] = {}
    for event in evidence.events:
        state = semantic_state(event)
        states.add(state)
        if previous_global is not None:
            transitions.add(f"global:{previous_global}->{state}")
        previous_actor = previous_by_actor.get(event.actor)
        if previous_actor is not None:
            transitions.add(f"actor:{previous_actor}->{state}")
        previous_global = state
        previous_by_actor[event.actor] = state
    return RuntimeCoverage(frozenset(states), frozenset(transitions))


def _static_features(case: ManifestCase) -> frozenset[str]:
    features = {
        f"assignment:{name}={_stable_value(value)}"
        for name, value in case.assignments.items()
    }
    order = case.assignments.get("trajectory.order")
    if isinstance(order, list):
        for left, right in zip(order, order[1:]):
            if isinstance(left, str) and isinstance(right, str):
                features.add(f"order-edge:{left}->{right}")
    scenario = load_scenario(case.scenario_path)
    if scenario.execution is not None:
        for role in scenario.execution.roles:
            for action in role.actions:
                features.add(f"action:{role.actor}:{action.operation}")
    return frozenset(features)


def _tie_break(seed: int, case: ManifestCase) -> str:
    value = f"{seed}:{case.index}:{case.scenario_digest}".encode()
    return hashlib.sha256(value).hexdigest()


@dataclass(slots=True)
class CoverageGuidedScheduler:
    cases: tuple[ManifestCase, ...]
    seed: int = 0
    _static: dict[int, frozenset[str]] = field(init=False, default_factory=dict)
    _seen_static: set[str] = field(init=False, default_factory=set)
    _seen_runtime: set[str] = field(init=False, default_factory=set)
    _feature_reward: dict[str, float] = field(init=False, default_factory=dict)
    _feature_visits: dict[str, int] = field(init=False, default_factory=dict)
    _selected: set[int] = field(init=False, default_factory=set)
    _trace: list[dict[str, JsonValue]] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self._static = {case.index: _static_features(case) for case in self.cases}

    @staticmethod
    def _is_baseline(case: ManifestCase) -> bool:
        return (
            case.assignments.get("trajectory.barrier_mode") == "preserve"
            and case.assignments.get("trajectory.spacing_ms") == 0
            and case.assignments.get("trajectory.action_jitter_ms", 0) == 0
        )

    def choose(self, pending: Iterable[ManifestCase]) -> ManifestCase:
        choices = tuple(pending)
        if not choices:
            raise ValueError("coverage scheduler has no pending trajectory")
        baselines = tuple(case for case in choices if self._is_baseline(case))
        if baselines:
            return min(baselines, key=lambda case: _tie_break(self.seed, case))

        def score(case: ManifestCase) -> tuple[float, int, str]:
            features = self._static[case.index]
            unseen = len(features - self._seen_static)
            learned = sum(
                self._feature_reward.get(feature, 0.0)
                / max(1, self._feature_visits.get(feature, 0))
                for feature in features
            )
            # Static novelty keeps exploration broad. Runtime reward makes a
            # trajectory adjacent to a productive execution more likely next.
            return (unseen * 8.0 + learned, unseen, _tie_break(self.seed, case))

        return max(choices, key=score)

    def observe(self, case: ManifestCase, evidence: Iterable[EvidenceBundle]) -> None:
        combined: set[str] = set()
        state_count = 0
        transition_count = 0
        for bundle in evidence:
            coverage = extract_runtime_coverage(bundle)
            state_count += len(coverage.states)
            transition_count += len(coverage.transitions)
            combined.update(coverage.features)
        new_runtime = combined - self._seen_runtime
        features = self._static[case.index]
        reward = float(len(new_runtime))
        for feature in features:
            self._feature_visits[feature] = self._feature_visits.get(feature, 0) + 1
            self._feature_reward[feature] = self._feature_reward.get(feature, 0.0) + reward
        self._seen_static.update(features)
        self._seen_runtime.update(combined)
        self._selected.add(case.index)
        self._trace.append(
            {
                "selection_rank": len(self._trace),
                "case_index": case.index,
                "scenario_id": case.scenario_id,
                "baseline": self._is_baseline(case),
                "static_feature_count": len(features),
                "runtime_state_count": state_count,
                "runtime_transition_count": transition_count,
                "new_runtime_features": len(new_runtime),
                "cumulative_runtime_features": len(self._seen_runtime),
            }
        )

    def summary(self, pool_size: int, execution_budget: int) -> dict[str, JsonValue]:
        return {
            "strategy": "runtime-coverage-guided",
            "seed": self.seed,
            "pool_size": pool_size,
            "execution_budget": execution_budget,
            "selected_cases": len(self._trace),
            "covered_static_features": len(self._seen_static),
            "covered_runtime_features": len(self._seen_runtime),
            "selection_trace": list(self._trace),
        }
