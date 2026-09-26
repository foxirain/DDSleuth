from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Iterable

from .campaign_types import ManifestCase
from .evidence import EvidenceBundle
from .models import EvidenceEvent, EventKind, JsonValue
from .scenario import load_scenario


# Protocol/security state only. Run-local GUIDs, fingerprints, timestamps,
# byte counts, and application messages are deliberately absent.
_SEMANTIC_ATTRIBUTES = (
    "operation",
    "endpoint",
    "topic",
    "resource",
    "token_class",
    "endpoint_class",
    "observation_phase",
    "key_class",
    "material_semantics",
    "rotation_kind",
    "context",
    "phase",
    "reason",
    "fault",
    "transport",
    "transport_mode",
    "local_identity",
    "addressed_to_local",
    "lifecycle_epoch",
    "participant_epoch",
    "expected_samples",
    "observed_samples",
)

_COUNT_ATTRIBUTES = {"expected_samples", "observed_samples"}
_EPOCH_ATTRIBUTES = {"lifecycle_epoch", "participant_epoch"}
_FAULT_APPLIED_KINDS = {
    EventKind.TRANSPORT_DATAGRAM_DROPPED,
    EventKind.TRANSPORT_DATAGRAM_DELAYED,
    EventKind.TRANSPORT_DATAGRAM_DUPLICATED,
    EventKind.TRANSPORT_DATAGRAM_CAPTURED,
    EventKind.TRANSPORT_DATAGRAM_REPLAYED,
}


@dataclass(frozen=True, slots=True)
class RuntimeCoverage:
    states: frozenset[str]
    transitions: frozenset[str]
    milestones: frozenset[str] = frozenset()
    anomalies: frozenset[str] = frozenset()

    @property
    def features(self) -> frozenset[str]:
        return frozenset(
            {
                *(f"state:{item}" for item in self.states),
                *(f"transition:{item}" for item in self.transitions),
                *(f"milestone:{item}" for item in self.milestones),
                *(f"anomaly:{item}" for item in self.anomalies),
            }
        )


def _stable_value(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _bucket(name: str, value: JsonValue) -> JsonValue:
    if name in _COUNT_ATTRIBUTES and isinstance(value, int):
        return "zero" if value == 0 else "one" if value == 1 else "many"
    if name in _EPOCH_ATTRIBUTES and isinstance(value, int):
        return "first" if value <= 1 else "later"
    return value


def semantic_state(event: EvidenceEvent) -> str:
    attributes = tuple(
        (name, _stable_value(_bucket(name, event.attributes[name])))
        for name in _SEMANTIC_ATTRIBUTES
        if name in event.attributes
    )
    suffix = "|".join(f"{name}={value}" for name, value in attributes)
    core = f"{event.actor}|{event.kind}|{event.outcome}"
    return f"{core}|{suffix}" if suffix else core


def _event_milestones(event: EvidenceEvent) -> set[str]:
    kind = event.kind
    actor = event.actor
    attributes = event.attributes
    values: set[str] = set()
    if kind == EventKind.PROBE_READY:
        values.add(f"{actor}:participant_ready")
    elif kind == EventKind.CREDENTIAL_AUTHENTICATED:
        values.add(f"{actor}:peer_authenticated")
    elif kind == EventKind.ACCESS_CONTROL_DECISION:
        operation = attributes.get("operation", "unknown")
        values.add(f"{actor}:authorization:{operation}:{event.outcome}")
    elif kind in (EventKind.ENDPOINT_CREATED, EventKind.ENDPOINT_RECREATED):
        values.add(f"{actor}:endpoint_active")
        if kind == EventKind.ENDPOINT_RECREATED:
            values.add(f"{actor}:endpoint_recreated")
    elif kind == EventKind.ENDPOINT_MATCHED:
        values.add(f"{actor}:endpoint_matched")
    elif kind == EventKind.PARTICIPANT_DISCONNECTED:
        values.add(f"{actor}:participant_disconnected")
    elif kind == EventKind.PARTICIPANT_RECONNECTED:
        values.add(f"{actor}:participant_reconnected")
    elif kind == EventKind.CREDENTIAL_REVOKED:
        scope = "local" if attributes.get("local_identity") is True else "remote"
        values.add(f"{actor}:credential_revoked:{scope}")
    elif kind == EventKind.KEY_ROTATED:
        values.add(f"{actor}:key_rotated:{attributes.get('rotation_kind', 'unknown')}")
    elif kind == EventKind.KEY_MATERIAL_OBSERVED:
        values.add(
            f"{actor}:key_material:{attributes.get('observation_phase', 'unknown')}:"
            f"{attributes.get('endpoint_class', 'unknown')}:"
            f"{attributes.get('token_class', 'unknown')}"
        )
    elif kind == EventKind.APPLICATION_SAMPLE_WRITTEN:
        values.add(f"{actor}:sample_written")
    elif kind == EventKind.APPLICATION_SAMPLE_RECEIVED:
        values.add(f"{actor}:sample_received")
    elif kind == EventKind.TRANSPORT_FAULT_ARMED:
        values.add(f"{actor}:fault_armed:{attributes.get('fault', 'unknown')}")
    elif kind in _FAULT_APPLIED_KINDS:
        values.add(f"{actor}:fault_applied:{attributes.get('fault', 'unknown')}")
    elif kind == EventKind.APPLICATION_OBSERVATION_WINDOW:
        values.add(f"{actor}:observation_complete:{event.outcome}")
    return values


def extract_runtime_coverage(evidence: EvidenceBundle) -> RuntimeCoverage:
    """Extract deterministic security-state and causal coverage.

    Cross-process log adjacency is intentionally ignored: polling order is not
    protocol causality. Cross-actor transitions require a shared action id,
    key fingerprint, or application message.
    """

    states: set[str] = set()
    transitions: set[str] = set()
    milestones: set[str] = set()
    anomalies: set[str] = set()
    previous_by_actor: dict[str, str] = {}
    action_started: dict[tuple[str, str], str] = {}
    faults_armed: dict[tuple[str, str], str] = {}
    generated_keys: dict[str, str] = {}
    written_messages: dict[str, str] = {}
    locally_revoked: set[str] = set()
    post_revocation_messages: set[str] = set()
    received_samples: dict[tuple[str, str, int, str], int] = {}

    for event in evidence.events:
        state = semantic_state(event)
        states.add(state)
        previous_actor = previous_by_actor.get(event.actor)
        if previous_actor is not None:
            transitions.add(f"actor:{previous_actor}->{state}")
        previous_by_actor[event.actor] = state
        milestones.update(_event_milestones(event))

        action_id = event.attributes.get("action_id")
        if isinstance(action_id, str):
            action_key = (event.actor, action_id)
            if event.kind == EventKind.ACTION_STARTED:
                action_started[action_key] = str(event.attributes.get("operation", "unknown"))
            elif event.kind in (EventKind.ACTION_COMPLETED, EventKind.ACTION_DELEGATED):
                operation = action_started.get(action_key)
                if operation is not None:
                    transitions.add(
                        f"causal:action:{event.actor}:{operation}:started->{event.outcome}"
                    )
            if event.kind == EventKind.TRANSPORT_FAULT_ARMED:
                faults_armed[action_key] = str(event.attributes.get("fault", "unknown"))
            elif event.kind in _FAULT_APPLIED_KINDS and action_key in faults_armed:
                transitions.add(
                    f"causal:fault:{event.actor}:{faults_armed[action_key]}:armed->{event.outcome}"
                )

        fingerprint = event.attributes.get("key_fingerprint")
        if event.kind == EventKind.KEY_MATERIAL_OBSERVED and isinstance(fingerprint, str):
            phase = event.attributes.get("observation_phase")
            key_shape = (
                f"{event.attributes.get('endpoint_class', 'unknown')}:"
                f"{event.attributes.get('token_class', 'unknown')}:"
                f"{event.attributes.get('key_class', 'unknown')}"
            )
            if phase == "generated":
                generated_keys[fingerprint] = key_shape
            elif phase == "received" and fingerprint in generated_keys:
                transitions.add(f"causal:key:{generated_keys[fingerprint]}:generated->received")

        message = event.attributes.get("message")
        if event.kind == EventKind.APPLICATION_SAMPLE_WRITTEN and isinstance(message, str):
            topic = str(event.attributes.get("topic", "unknown"))
            written_messages[message] = topic
            if event.actor in locally_revoked:
                post_revocation_messages.add(message)
                milestones.add(f"{event.actor}:post_revocation_write")
        elif event.kind == EventKind.APPLICATION_SAMPLE_RECEIVED and isinstance(message, str):
            if message in written_messages:
                transitions.add(
                    f"causal:application:{written_messages[message]}:write->receive"
                )
            if message in post_revocation_messages:
                milestones.add(f"{event.actor}:post_revocation_delivery")
                anomalies.add("post_revocation_application_delivery")
            topic = event.attributes.get("topic")
            sample_index = event.attributes.get("sample_index")
            if isinstance(topic, str) and isinstance(sample_index, int):
                sample_key = (event.actor, topic, sample_index, message)
                count = received_samples.get(sample_key, 0) + 1
                received_samples[sample_key] = count
                if count == 2:
                    milestones.add(f"{event.actor}:duplicate_sample_delivery")
                    anomalies.add("duplicate_application_delivery")

        if (
            event.kind == EventKind.CREDENTIAL_REVOKED
            and event.outcome == "revoked"
            and event.attributes.get("local_identity") is True
        ):
            locally_revoked.add(event.actor)

        if event.kind == EventKind.EXECUTION_DIVERGENCE:
            anomalies.add("execution_divergence")
        elif event.kind == EventKind.OBSERVER_ERROR:
            anomalies.add("observer_error")
        elif event.kind == EventKind.PROCESS_EXIT and event.outcome == "failed":
            anomalies.add(f"process_failure:{event.actor}")
        elif event.kind == EventKind.MEMORY_SAFETY_VIOLATION:
            anomalies.add(
                f"memory_safety:{event.attributes.get('sanitizer', 'unknown')}:"
                f"{event.attributes.get('violation', 'unknown')}"
            )
        elif event.kind in _FAULT_APPLIED_KINDS and event.outcome == "failed":
            anomalies.add(f"fault_application_failed:{event.attributes.get('fault', 'unknown')}")

    return RuntimeCoverage(
        frozenset(states),
        frozenset(transitions),
        frozenset(milestones),
        frozenset(anomalies),
    )


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


def _feature_weight(feature: str) -> float:
    if feature.startswith("anomaly:"):
        return 32.0
    if feature.startswith("milestone:"):
        return 8.0
    if feature.startswith("transition:causal:"):
        return 4.0
    if feature.startswith("transition:"):
        return 1.0
    return 0.25


def _frontier_score(coverage: RuntimeCoverage) -> float:
    """Score proximity to a security boundary, not generic execution depth."""

    if coverage.anomalies & {
        "post_revocation_application_delivery",
        "duplicate_application_delivery",
    }:
        return 64.0
    if any(item.endswith(":post_revocation_write") for item in coverage.milestones):
        return 20.0
    replay_applied = any(
        item.endswith(":fault_applied:replay_last") for item in coverage.milestones
    )
    observation_complete = any(
        ":observation_complete:" in item for item in coverage.milestones
    )
    if replay_applied and observation_complete:
        return 12.0
    reconnected = any(
        item.endswith(":participant_reconnected") for item in coverage.milestones
    )
    recreated = any(item.endswith(":endpoint_recreated") for item in coverage.milestones)
    if reconnected and recreated:
        return 8.0
    return 0.0


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
    _no_progress_runs: int = field(init=False, default=0)
    _stop_reason: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._static = {case.index: _static_features(case) for case in self.cases}

    @staticmethod
    def _is_baseline(case: ManifestCase) -> bool:
        marker = case.assignments.get("trajectory.scheduler_seed")
        if isinstance(marker, bool):
            return marker
        return (
            case.assignments.get("trajectory.barrier_mode") == "preserve"
            and case.assignments.get("trajectory.spacing_ms") == 0
            and case.assignments.get("trajectory.action_jitter_ms", 0) == 0
        )

    def choose(self, pending: Iterable[ManifestCase]) -> ManifestCase:
        choices = tuple(pending)
        if not choices:
            raise ValueError("coverage scheduler has no pending trajectory")
        # Seed once with the least-perturbed trajectory. Running every baseline
        # before using feedback starves the feedback loop.
        if not self._trace:
            baselines = tuple(case for case in choices if self._is_baseline(case))
            if baselines:
                return min(baselines, key=lambda case: _tie_break(self.seed, case))

        total_visits = max(1, len(self._trace))

        def score(case: ManifestCase) -> tuple[float, int, str]:
            features = self._static[case.index]
            unseen = len(features - self._seen_static)
            learned = 0.0
            exploration = 0.0
            for feature in features:
                visits = self._feature_visits.get(feature, 0)
                if visits:
                    learned += self._feature_reward.get(feature, 0.0) / visits
                    exploration += math.sqrt(math.log(total_visits + 1) / visits)
                else:
                    exploration += 1.0
            scale = max(1, len(features))
            return (
                unseen * 2.0 + learned / scale + exploration / scale,
                unseen,
                _tie_break(self.seed, case),
            )

        return max(choices, key=score)

    def observe(self, case: ManifestCase, evidence: Iterable[EvidenceBundle]) -> float:
        combined: set[str] = set()
        state_count = 0
        transition_count = 0
        milestone_count = 0
        anomaly_count = 0
        valid_execution = True
        frontier_score = 0.0
        security_anomaly = False
        for bundle in evidence:
            coverage = extract_runtime_coverage(bundle)
            state_count += len(coverage.states)
            transition_count += len(coverage.transitions)
            milestone_count += len(coverage.milestones)
            anomaly_count += len(coverage.anomalies)
            if bundle.metadata.get("execution_error") is not None:
                valid_execution = False
                continue
            frontier_score = max(frontier_score, _frontier_score(coverage))
            security_anomaly = security_anomaly or bool(
                coverage.anomalies
                & {
                    "post_revocation_application_delivery",
                    "duplicate_application_delivery",
                }
            )
            combined.update(coverage.features)
        new_runtime = combined - self._seen_runtime
        novelty_reward = sum(_feature_weight(feature) for feature in new_runtime)
        reward = novelty_reward + frontier_score
        features = self._static[case.index]
        for feature in features:
            self._feature_visits[feature] = self._feature_visits.get(feature, 0) + 1
            self._feature_reward[feature] = self._feature_reward.get(feature, 0.0) + reward
        self._seen_static.update(features)
        self._seen_runtime.update(combined)
        self._selected.add(case.index)
        self._no_progress_runs = (
            0 if (new_runtime or security_anomaly) else self._no_progress_runs + 1
        )
        self._trace.append(
            {
                "selection_rank": len(self._trace),
                "case_index": case.index,
                "scenario_id": case.scenario_id,
                "baseline": self._is_baseline(case),
                "static_feature_count": len(features),
                "runtime_state_count": state_count,
                "runtime_transition_count": transition_count,
                "runtime_milestone_count": milestone_count,
                "runtime_anomaly_count": anomaly_count,
                "valid_execution": valid_execution,
                "new_runtime_features": len(new_runtime),
                "novelty_reward": round(novelty_reward, 3),
                "security_frontier_score": round(frontier_score, 3),
                "weighted_reward": round(reward, 3),
                "no_progress_runs": self._no_progress_runs,
                "cumulative_runtime_features": len(self._seen_runtime),
            }
        )
        return reward

    def plateau_reached(self, window: int) -> bool:
        if window <= 0 or self._no_progress_runs < window:
            return False
        self._stop_reason = f"runtime coverage plateau ({window} consecutive runs)"
        return True

    def summary(self, pool_size: int, execution_budget: int) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "strategy": "causal-security-coverage-guided",
            "seed": self.seed,
            "pool_size": pool_size,
            "execution_budget": execution_budget,
            "selected_cases": len(self._trace),
            "covered_static_features": len(self._seen_static),
            "covered_runtime_features": len(self._seen_runtime),
            "consecutive_no_progress_runs": self._no_progress_runs,
            "selection_trace": list(self._trace),
        }
        if self._stop_reason is not None:
            result["stop_reason"] = self._stop_reason
        return result
