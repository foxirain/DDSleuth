from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping

from .artifacts import ArtifactBundle, RuntimeArtifact
from .evidence import EvidenceBundle
from .models import JsonValue
from .scenario import parse_scenario


ArtifactExecutor = Callable[[Mapping[str, JsonValue]], ArtifactBundle | Iterable[RuntimeArtifact]]


@dataclass(frozen=True, slots=True)
class ReductionResult:
    scenario: Mapping[str, JsonValue]
    target_fingerprint: str
    original_action_count: int
    minimized_action_count: int
    original_timing_sum_ms: float
    minimized_timing_sum_ms: float
    execution_trials: int
    preserved: bool

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "target_fingerprint": self.target_fingerprint,
            "original_action_count": self.original_action_count,
            "minimized_action_count": self.minimized_action_count,
            "original_timing_sum_ms": self.original_timing_sum_ms,
            "minimized_timing_sum_ms": self.minimized_timing_sum_ms,
            "execution_trials": self.execution_trials,
            "preserved": self.preserved,
            "scenario": copy.deepcopy(dict(self.scenario)),
        }


def _roles(raw: Mapping[str, JsonValue]) -> list[dict[str, JsonValue]]:
    execution = raw.get("execution")
    if not isinstance(execution, Mapping):
        return []
    roles = execution.get("roles")
    if not isinstance(roles, list):
        return []
    return [role for role in roles if isinstance(role, dict)]


def _action_keys(raw: Mapping[str, JsonValue]) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []
    for role in _roles(raw):
        actor = role.get("actor")
        actions = role.get("actions")
        if not isinstance(actor, str) or not isinstance(actions, list):
            continue
        for index, action in enumerate(actions):
            if isinstance(action, Mapping):
                action_id = action.get("id")
                keys.append((actor, str(action_id) if isinstance(action_id, str) else f"#{index}"))
    return keys


def _remove_actions(
    raw: Mapping[str, JsonValue],
    removed: set[tuple[str, str]],
) -> dict[str, JsonValue]:
    candidate = copy.deepcopy(dict(raw))
    for role in _roles(candidate):
        actor = role.get("actor")
        actions = role.get("actions")
        if not isinstance(actor, str) or not isinstance(actions, list):
            continue
        kept: list[JsonValue] = []
        for index, action in enumerate(actions):
            if not isinstance(action, Mapping):
                kept.append(action)
                continue
            action_id = action.get("id")
            key = (actor, str(action_id) if isinstance(action_id, str) else f"#{index}")
            if key not in removed:
                kept.append(action)
        role["actions"] = kept
    parse_scenario(candidate)
    return candidate


def _fingerprints(result: ArtifactBundle | Iterable[RuntimeArtifact]) -> set[str]:
    artifacts = result.artifacts if isinstance(result, ArtifactBundle) else tuple(result)
    return {artifact.fingerprint for artifact in artifacts}


def _timing_sum(raw: Mapping[str, JsonValue]) -> float:
    total = 0.0
    for role in _roles(raw):
        offset = role.get("start_offset_ms", 0)
        if isinstance(offset, (int, float)) and not isinstance(offset, bool):
            total += float(offset)
        actions = role.get("actions")
        if isinstance(actions, list):
            for action in actions:
                if isinstance(action, Mapping):
                    at_ms = action.get("at_ms", 0)
                    if isinstance(at_ms, (int, float)) and not isinstance(at_ms, bool):
                        total += float(at_ms)
    return total


def minimize_action_plan(
    raw_scenario: Mapping[str, JsonValue],
    target_fingerprint: str,
    execute: ArtifactExecutor,
    *,
    max_trials: int = 64,
) -> ReductionResult:
    """Delta-debug an action plan while dynamically preserving one artifact.

    Every accepted reduction is executed and must reproduce the exact semantic
    artifact fingerprint.  This routine never infers preservation from source
    structure or timing alone.
    """

    if max_trials < 1:
        raise ValueError("max_trials must be positive")
    current = copy.deepcopy(dict(raw_scenario))
    parse_scenario(current)
    original = _action_keys(current)
    original_timing = _timing_sum(current)
    trials = 1
    if target_fingerprint not in _fingerprints(execute(current)):
        return ReductionResult(
            current,
            target_fingerprint,
            len(original),
            len(original),
            original_timing,
            original_timing,
            trials,
            False,
        )

    remaining = list(original)
    granularity = 2
    while remaining and trials < max_trials:
        chunk_size = max(1, (len(remaining) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(remaining), chunk_size):
            if trials >= max_trials:
                break
            chunk = set(remaining[start : start + chunk_size])
            candidate = _remove_actions(current, chunk)
            trials += 1
            if target_fingerprint in _fingerprints(execute(candidate)):
                current = candidate
                remaining = [key for key in remaining if key not in chunk]
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(remaining):
            break
        granularity = min(len(remaining), granularity * 2)

    # Normalize role offsets and action delays only when the artifact survives.
    # This turns a schedule-dependent reproduction into the smallest observed
    # timing constraint instead of leaving arbitrary waits in the result.
    for role_index, role in enumerate(_roles(current)):
        if trials >= max_trials:
            break
        offset = role.get("start_offset_ms", 0)
        if isinstance(offset, (int, float)) and not isinstance(offset, bool) and offset > 0:
            candidate = copy.deepcopy(current)
            _roles(candidate)[role_index]["start_offset_ms"] = 0
            parse_scenario(candidate)
            trials += 1
            if target_fingerprint in _fingerprints(execute(candidate)):
                current = candidate

        actions = role.get("actions")
        if not isinstance(actions, list):
            continue
        previous = 0.0
        for action_index, action in enumerate(actions):
            if trials >= max_trials:
                break
            if not isinstance(action, Mapping):
                continue
            at_ms = action.get("at_ms", 0)
            if not isinstance(at_ms, (int, float)) or isinstance(at_ms, bool):
                continue
            if float(at_ms) > previous:
                candidate = copy.deepcopy(current)
                candidate_action = _roles(candidate)[role_index]["actions"][action_index]
                candidate_action["at_ms"] = previous
                parse_scenario(candidate)
                trials += 1
                if target_fingerprint in _fingerprints(execute(candidate)):
                    current = candidate
                    at_ms = previous
            previous = float(at_ms)

    return ReductionResult(
        current,
        target_fingerprint,
        len(original),
        len(_action_keys(current)),
        original_timing,
        _timing_sum(current),
        trials,
        True,
    )


def causal_action_prefilter(
    raw_scenario: Mapping[str, JsonValue],
    evidence: EvidenceBundle,
    artifact: RuntimeArtifact,
) -> Mapping[str, JsonValue]:
    """Build an unverified action-slice candidate from explicit causal ids."""

    sequences = set(artifact.evidence_events)
    relevant_ids: set[str] = set()
    for position, event in enumerate(evidence.events):
        sequence = position if event.sequence is None else event.sequence
        if sequence not in sequences:
            continue
        for name in ("action_id", "source_action_id"):
            value = event.attributes.get(name)
            if isinstance(value, str):
                relevant_ids.add(value)
    removed = {
        key
        for key in _action_keys(raw_scenario)
        if not key[1].startswith("#") and key[1] not in relevant_ids
    }
    candidate = _remove_actions(raw_scenario, removed)
    return {
        "schema_version": 1,
        "kind": "causal_action_reduction_prefilter",
        "target_fingerprint": artifact.fingerprint,
        "causal_action_ids": sorted(relevant_ids),
        "original_action_count": len(_action_keys(raw_scenario)),
        "candidate_action_count": len(_action_keys(candidate)),
        "requires_dynamic_confirmation": True,
        "candidate_scenario": candidate,
    }
