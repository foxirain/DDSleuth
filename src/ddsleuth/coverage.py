from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
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
    motifs: frozenset[str] = frozenset()

    @property
    def features(self) -> frozenset[str]:
        return frozenset(
            {
                *(f"state:{item}" for item in self.states),
                *(f"transition:{item}" for item in self.transitions),
                *(f"motif:{item}" for item in self.motifs),
                *(f"milestone:{item}" for item in self.milestones),
                *(f"anomaly:{item}" for item in self.anomalies),
            }
        )


def _stable_value(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _feature_id(domain: str, feature: str) -> str:
    digest = hashlib.sha256(f"{domain}\0{feature}".encode()).hexdigest()
    return f"{domain}:sha256:{digest}"


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


def _correlation_keys(event: EvidenceEvent) -> tuple[tuple[str, str], ...]:
    """Return explicit run-local causality keys, never log adjacency."""

    keys: list[tuple[str, str]] = []
    action_id = event.attributes.get("action_id")
    if isinstance(action_id, str) and action_id:
        keys.append(("action", f"{event.actor}:{action_id}"))
    source_action_id = event.attributes.get("source_action_id")
    if isinstance(source_action_id, str) and source_action_id:
        keys.append(("action", f"{event.actor}:{source_action_id}"))
    for name in ("message", "key_fingerprint"):
        value = event.attributes.get(name)
        if isinstance(value, str) and value:
            keys.append((name, value))
    return tuple(keys)


def partial_order_projection(evidence: EvidenceBundle) -> dict[str, int]:
    """Canonicalize a trace modulo unrelated cross-process event ordering.

    The projection contains a count-bucketed multiset of semantic states and
    directed edges only when the events share an explicit action, message, or
    run-local key identifier.  It intentionally has no edge for mere log
    adjacency, so polling and callback interleavings do not manufacture a new
    differential artifact.
    """

    state_counts = Counter(semantic_state(event) for event in evidence.events)
    projection: dict[str, int] = {
        f"state:{state}": 1 if count == 1 else 2
        for state, count in state_counts.items()
    }
    correlated: dict[tuple[str, str], list[tuple[int, EvidenceEvent]]] = defaultdict(list)
    for position, event in enumerate(evidence.events):
        sequence = position if event.sequence is None else event.sequence
        for key in _correlation_keys(event):
            correlated[key].append((sequence, event))

    for (kind, _), members in correlated.items():
        # Sequence determines direction only among causally correlated events.
        ordered = sorted(members, key=lambda item: item[0])
        unique: list[str] = []
        for _, event in ordered:
            state = semantic_state(event)
            if not unique or unique[-1] != state:
                unique.append(state)
        for left, right in zip(unique, unique[1:]):
            projection[f"poedge:{kind}:{left}->{right}"] = 1

    coverage = extract_runtime_coverage(evidence)
    for milestone in coverage.milestones:
        projection[f"milestone:{milestone}"] = 1
    for anomaly in coverage.anomalies:
        projection[f"anomaly:{anomaly}"] = 1
    return projection


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
    motifs: set[str] = set()
    milestones: set[str] = set()
    anomalies: set[str] = set()
    previous_by_actor: dict[str, str] = {}
    history_by_actor: dict[str, list[str]] = defaultdict(list)
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
        actor_history = history_by_actor[event.actor]
        actor_history.append(state)
        if len(actor_history) >= 3:
            motifs.add(f"actor3:{'->'.join(actor_history[-3:])}")
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
        states=frozenset(states),
        transitions=frozenset(transitions),
        milestones=frozenset(milestones),
        anomalies=frozenset(anomalies),
        motifs=frozenset(motifs),
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
    return frozenset(_feature_id("static", feature) for feature in features)


def _tie_break(seed: int, case: ManifestCase) -> str:
    value = f"{seed}:{case.index}:{case.scenario_digest}".encode()
    return hashlib.sha256(value).hexdigest()


def _semantic_case_key(case: ManifestCase) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (name, _stable_value(value))
            for name, value in case.assignments.items()
            if not name.startswith("trajectory.")
        )
    )


def _feature_weight(feature: str) -> float:
    if feature.startswith("artifact:runtime_memory_diagnostic:"):
        return 48.0
    if feature.startswith("artifact:"):
        return 16.0
    if feature.startswith("partial:poedge:"):
        return 4.0
    if feature.startswith("anomaly:"):
        return 32.0
    if feature.startswith("milestone:"):
        return 8.0
    if feature.startswith("transition:causal:"):
        return 4.0
    if feature.startswith("motif:"):
        return 2.0
    if feature.startswith("transition:"):
        return 1.0
    return 0.25


def _artifact_potential(coverage: RuntimeCoverage) -> float:
    """Reward deep boundary composition without making a vulnerability claim."""

    phases: set[str] = set()
    for milestone in coverage.milestones:
        if "credential_" in milestone or "peer_authenticated" in milestone:
            phases.add("identity")
        if "authorization:" in milestone:
            phases.add("authorization")
        if "key_" in milestone:
            phases.add("key_lifecycle")
        if "endpoint_" in milestone or "participant_" in milestone:
            phases.add("lifecycle")
        if "fault_" in milestone:
            phases.add("transport")
        if "sample_" in milestone or "observation_complete:" in milestone:
            phases.add("application")
    depth_reward = float(len(phases) * len(phases))
    causal_reward = min(
        12.0,
        2.0
        * sum(transition.startswith("causal:") for transition in coverage.transitions),
    )
    anomaly_reward = min(24.0, 8.0 * len(coverage.anomalies))
    return depth_reward + causal_reward + anomaly_reward


def _frontier_score(coverage: RuntimeCoverage) -> float:
    """Compatibility alias for the pre-artifact scheduler API."""

    return _artifact_potential(coverage)


@dataclass(slots=True)
class ArtifactGuidedScheduler:
    cases: tuple[ManifestCase, ...]
    seed: int = 0
    corpus_path: Path | None = None
    _static: dict[int, frozenset[str]] = field(init=False, default_factory=dict)
    _seen_static: set[str] = field(init=False, default_factory=set)
    _seen_runtime: set[str] = field(init=False, default_factory=set)
    _feature_reward: dict[str, float] = field(init=False, default_factory=dict)
    _feature_visits: dict[str, int] = field(init=False, default_factory=dict)
    _selected: set[int] = field(init=False, default_factory=set)
    _trace: list[dict[str, JsonValue]] = field(init=False, default_factory=list)
    _no_progress_runs: int = field(init=False, default=0)
    _stop_reason: str | None = field(init=False, default=None)
    _initial_runtime_features: int = field(init=False, default=0)
    _baseline_semantics: set[tuple[tuple[str, str], ...]] = field(
        init=False,
        default_factory=set,
    )

    def __post_init__(self) -> None:
        self._static = {case.index: _static_features(case) for case in self.cases}
        if self.corpus_path is not None and self.corpus_path.is_file():
            raw = json.loads(self.corpus_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("schema_version") != 1:
                raise ValueError("artifact corpus schema_version must be 1")
            seen = raw.get("seen_runtime_features", [])
            visits = raw.get("feature_visits", {})
            rewards = raw.get("feature_rewards", {})
            if not isinstance(seen, list) or not isinstance(visits, dict) or not isinstance(rewards, dict):
                raise ValueError("artifact corpus fields are invalid")
            self._seen_runtime.update(
                str(item)
                for item in seen
                if isinstance(item, str) and item.startswith("runtime:sha256:")
            )
            self._feature_visits.update(
                {str(key): int(value) for key, value in visits.items() if int(value) >= 0}
            )
            self._feature_reward.update(
                {str(key): float(value) for key, value in rewards.items()}
            )
        self._initial_runtime_features = len(self._seen_runtime)

    def save_corpus(self) -> None:
        if self.corpus_path is None:
            return
        self.corpus_path.parent.mkdir(parents=True, exist_ok=True)
        value = {
            "schema_version": 1,
            "kind": "ddsleuth_runtime_artifact_corpus",
            "seen_runtime_features": sorted(self._seen_runtime),
            "feature_visits": dict(sorted(self._feature_visits.items())),
            "feature_rewards": {
                key: round(value, 6)
                for key, value in sorted(self._feature_reward.items())
            },
        }
        temporary = self.corpus_path.with_suffix(self.corpus_path.suffix + ".tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(self.corpus_path)

    @staticmethod
    def _is_baseline(case: ManifestCase) -> bool:
        marker = case.assignments.get("trajectory.scheduler_seed")
        if isinstance(marker, bool):
            return marker
        return (
            case.assignments.get("trajectory.barrier_mode") == "preserve"
            and case.assignments.get("trajectory.spacing_ms") == 0
            and case.assignments.get("trajectory.action_jitter_ms", 0) == 0
            and case.assignments.get("trajectory.boundary_offset_ms", 0) == 0
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

        # A mutation is useful for differential discovery only after its matched
        # semantic control has executed. Keep other baselines eligible so the
        # scheduler can move between semantic configurations without starving
        # the feedback loop.
        controlled_choices = tuple(
            case
            for case in choices
            if self._is_baseline(case)
            or _semantic_case_key(case) in self._baseline_semantics
        )
        if controlled_choices:
            choices = controlled_choices

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
        motif_count = 0
        milestone_count = 0
        anomaly_count = 0
        valid_execution = True
        artifact_potential = 0.0
        runtime_anomaly = False
        semantic_artifact_count = 0
        for bundle in evidence:
            coverage = extract_runtime_coverage(bundle)
            state_count += len(coverage.states)
            transition_count += len(coverage.transitions)
            motif_count += len(coverage.motifs)
            milestone_count += len(coverage.milestones)
            anomaly_count += len(coverage.anomalies)
            if bundle.metadata.get("execution_error") is not None:
                valid_execution = False
                continue
            artifact_potential = max(artifact_potential, _artifact_potential(coverage))
            runtime_anomaly = runtime_anomaly or bool(coverage.anomalies)
            combined.update(
                feature
                for feature in coverage.features
                if not feature.startswith("motif:")
            )
            combined.update(
                f"partial:{feature}"
                for feature in partial_order_projection(bundle)
            )
            # Local import avoids a module cycle: artifact extraction itself
            # consumes the coverage primitives above.
            from .artifacts import discover_artifacts

            scenario = load_scenario(case.scenario_path)
            artifacts = discover_artifacts(scenario, bundle).artifacts
            semantic = [item for item in artifacts if item.family != "boundary_episode"]
            semantic_artifact_count += len(semantic)
            combined.update(
                f"artifact:{item.family}:{item.fingerprint}" for item in semantic
            )
        new_runtime_features = {
            feature
            for feature in combined
            if _feature_id("runtime", feature) not in self._seen_runtime
        }
        new_runtime = {
            _feature_id("runtime", feature) for feature in new_runtime_features
        }
        novelty_reward = sum(
            _feature_weight(feature) for feature in new_runtime_features
        )
        reward = novelty_reward + artifact_potential
        features = self._static[case.index]
        for feature in features:
            self._feature_visits[feature] = self._feature_visits.get(feature, 0) + 1
            self._feature_reward[feature] = self._feature_reward.get(feature, 0.0) + reward
        self._seen_static.update(features)
        self._seen_runtime.update(
            _feature_id("runtime", feature) for feature in combined
        )
        self._selected.add(case.index)
        if self._is_baseline(case):
            self._baseline_semantics.add(_semantic_case_key(case))
        self._no_progress_runs = (
            0 if (new_runtime or runtime_anomaly) else self._no_progress_runs + 1
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
                "runtime_motif_count": motif_count,
                "runtime_milestone_count": milestone_count,
                "runtime_anomaly_count": anomaly_count,
                "semantic_artifact_count": semantic_artifact_count,
                "valid_execution": valid_execution,
                "new_runtime_features": len(new_runtime),
                "novelty_reward": round(novelty_reward, 3),
                "artifact_potential_score": round(artifact_potential, 3),
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
            "strategy": "runtime-artifact-guided",
            "seed": self.seed,
            "pool_size": pool_size,
            "execution_budget": execution_budget,
            "selected_cases": len(self._trace),
            "covered_static_features": len(self._seen_static),
            "covered_runtime_features": len(self._seen_runtime),
            "corpus_runtime_features": self._initial_runtime_features,
            "new_runtime_features": len(self._seen_runtime) - self._initial_runtime_features,
            "consecutive_no_progress_runs": self._no_progress_runs,
            "selection_trace": list(self._trace),
        }
        if self._stop_reason is not None:
            result["stop_reason"] = self._stop_reason
        return result


# Source compatibility for integrations that imported the alpha scheduler class.
CoverageGuidedScheduler = ArtifactGuidedScheduler
