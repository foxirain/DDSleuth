from __future__ import annotations

import copy
import hashlib
import itertools
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .matrix import MatrixDimension, expand_matrix
from .models import JsonValue
from .scenario import parse_scenario


class TrajectoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TrajectoryDescriptor:
    order: tuple[str, ...]
    spacing_ms: int
    barrier_mode: str
    action_jitter_ms: int = 0
    boundary_offset_ms: int = 0

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "order": list(self.order),
            "spacing_ms": self.spacing_ms,
            "barrier_mode": self.barrier_mode,
            "action_jitter_ms": self.action_jitter_ms,
            "boundary_offset_ms": self.boundary_offset_ms,
        }


def _descriptor_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _role_order(raw: Mapping[str, Any]) -> tuple[str, ...]:
    execution = raw.get("execution")
    if not isinstance(execution, Mapping):
        raise TrajectoryError("stateful exploration requires an execution object")
    roles = execution.get("roles")
    if not isinstance(roles, list) or not roles:
        raise TrajectoryError("stateful exploration requires execution roles")
    actors: list[str] = []
    for index, role in enumerate(roles):
        if not isinstance(role, Mapping) or not isinstance(role.get("actor"), str):
            raise TrajectoryError(f"execution.roles[{index}] has no actor")
        actors.append(role["actor"])
    if len(actors) > 8:
        raise TrajectoryError("automatic role-order exploration is limited to eight roles")
    return tuple(actors)


def _schedule_descriptors(
    actors: tuple[str, ...],
    spacings_ms: tuple[int, ...],
    barrier_modes: tuple[str, ...],
    action_jitters_ms: tuple[int, ...],
    boundary_offsets_ms: tuple[int, ...],
) -> list[TrajectoryDescriptor]:
    # Differential analysis needs one canonical control even when the caller
    # requests only relaxed schedules or omits zero from the spacing set.
    # Keeping it here (rather than bolting it onto the manifest later) also
    # subjects the baseline to the same scenario validation as every mutation.
    descriptors: list[TrajectoryDescriptor] = [
        TrajectoryDescriptor(actors, 0, "preserve", 0, 0)
    ]
    if "preserve" in barrier_modes:
        descriptors.extend(
            TrajectoryDescriptor(actors, spacing, "preserve", jitter, boundary_offset)
            for spacing in spacings_ms
            for jitter in action_jitters_ms
            for boundary_offset in boundary_offsets_ms
        )
    if "relaxed" in barrier_modes:
        descriptors.extend(
            TrajectoryDescriptor(tuple(order), spacing, "relaxed", jitter, boundary_offset)
            for order in itertools.permutations(actors)
            for spacing in spacings_ms
            for jitter in action_jitters_ms
            for boundary_offset in boundary_offsets_ms
        )
    unique: dict[tuple[tuple[str, ...], int, str, int, int], TrajectoryDescriptor] = {}
    for descriptor in descriptors:
        unique[(
            descriptor.order,
            descriptor.spacing_ms,
            descriptor.barrier_mode,
            descriptor.action_jitter_ms,
            descriptor.boundary_offset_ms,
        )] = descriptor
    return list(unique.values())


_BOUNDARY_OPERATION_MARKERS = (
    "credential.revoke",
    "authority.revoke",
    "authorization.revoke",
    "key.rotate",
    "participant.disconnect",
    "participant.reconnect",
    "endpoint.destroy",
    "endpoint.recreate",
    "transport.",
    "replay",
    "drop",
    "delay",
    "duplicate",
)


def _is_boundary_operation(operation: object) -> bool:
    return isinstance(operation, str) and any(
        marker in operation.lower() for marker in _BOUNDARY_OPERATION_MARKERS
    )


def _apply_schedule(
    raw: Mapping[str, Any],
    descriptor: TrajectoryDescriptor,
) -> dict[str, Any]:
    case = copy.deepcopy(dict(raw))
    execution = case.get("execution")
    if not isinstance(execution, dict) or not isinstance(execution.get("roles"), list):
        raise TrajectoryError("scenario execution is not mutable")
    roles = execution["roles"]
    by_actor = {
        role.get("actor"): role
        for role in roles
        if isinstance(role, dict) and isinstance(role.get("actor"), str)
    }
    if set(by_actor) != set(descriptor.order):
        raise TrajectoryError("trajectory role order does not match scenario actors")

    scheduled: list[dict[str, Any]] = []
    for rank, actor in enumerate(descriptor.order):
        role = copy.deepcopy(by_actor[actor])
        role["start_offset_ms"] = rank * descriptor.spacing_ms
        if descriptor.barrier_mode == "relaxed":
            role.pop("start_after", None)
        actions = role.get("actions")
        if isinstance(actions, list) and (
            descriptor.action_jitter_ms or descriptor.boundary_offset_ms
        ):
            previous = 0.0
            for action_index, action in enumerate(actions):
                if not isinstance(action, dict) or not isinstance(action.get("at_ms"), (int, float)):
                    continue
                identity = f"{actor}:{action.get('id', action_index)}".encode()
                direction = (hashlib.sha256(identity).digest()[0] % 3) - 1
                boundary_offset = (
                    descriptor.boundary_offset_ms
                    if _is_boundary_operation(action.get("operation"))
                    else 0
                )
                mutated = max(
                    0.0,
                    float(action["at_ms"])
                    + direction * descriptor.action_jitter_ms
                    + boundary_offset,
                )
                # Preserve plan order even when two mutation windows overlap.
                action["at_ms"] = max(previous, mutated)
                previous = float(action["at_ms"])
        scheduled.append(role)
    execution["roles"] = scheduled
    return case


def generate_trajectories(
    raw_scenario: Mapping[str, Any],
    *,
    dimensions: Iterable[MatrixDimension] = (),
    dimension_strategy: str = "pairwise",
    spacings_ms: Iterable[int] = (0, 25, 250),
    barrier_modes: Iterable[str] = ("preserve", "relaxed"),
    action_jitters_ms: Iterable[int] = (0,),
    boundary_offsets_ms: Iterable[int] = (0,),
    budget: int = 64,
    seed: int = 0,
) -> list[tuple[dict[str, Any], dict[str, JsonValue]]]:
    if budget < 1 or budget > 4096:
        raise TrajectoryError("exploration budget must be between 1 and 4096")
    spacings = tuple(dict.fromkeys(spacings_ms))
    if not spacings or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in spacings
    ):
        raise TrajectoryError("start spacings must be non-negative integers")
    modes = tuple(dict.fromkeys(barrier_modes))
    if not modes or any(mode not in ("preserve", "relaxed") for mode in modes):
        raise TrajectoryError("barrier modes must contain preserve and/or relaxed")
    jitters = tuple(dict.fromkeys(action_jitters_ms))
    if not jitters or any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in jitters
    ):
        raise TrajectoryError("action jitters must be non-negative integers")
    boundary_offsets = tuple(dict.fromkeys(boundary_offsets_ms))
    if not boundary_offsets or any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in boundary_offsets
    ):
        raise TrajectoryError("boundary offsets must be integers")

    dimensions = tuple(dimensions)
    if dimensions:
        semantic_cases = expand_matrix(
            raw_scenario,
            dimensions,
            max_cases=max(budget * 4, 256),
            strategy=dimension_strategy,
        )
    else:
        semantic_cases = [(copy.deepcopy(dict(raw_scenario)), {})]

    candidates: list[tuple[dict[str, Any], dict[str, JsonValue], bool, str]] = []
    for semantic_case, semantic_assignments in semantic_cases:
        actors = _role_order(semantic_case)
        original_roles = semantic_case["execution"]["roles"]
        has_barriers = any(
            isinstance(role, Mapping) and bool(role.get("start_after"))
            for role in original_roles
        )
        for descriptor in _schedule_descriptors(
            actors,
            spacings,
            modes,
            jitters,
            boundary_offsets,
        ):
            if (
                descriptor.barrier_mode == "relaxed"
                and not has_barriers
                and descriptor.order == actors
                and descriptor.spacing_ms == 0
                and descriptor.action_jitter_ms == 0
                and descriptor.boundary_offset_ms == 0
            ):
                continue
            case = _apply_schedule(semantic_case, descriptor)
            descriptor_raw = descriptor.to_dict()
            schedule_digest = _descriptor_digest(descriptor_raw)
            # A matrix-generated base id can exceed the readable prefix below.
            # Hash the semantic assignments into the trajectory identity so two
            # configurations with the same schedule cannot collapse after the
            # prefix is truncated.
            case_digest = (
                schedule_digest
                if not semantic_assignments
                else _descriptor_digest(
                    {
                        "semantic": semantic_assignments,
                        "trajectory": descriptor_raw,
                    }
                )
            )
            base_id = str(semantic_case.get("id", "trajectory"))
            base_title = str(semantic_case.get("title", "DDS trajectory"))
            case["id"] = f"{base_id[:96]}--trajectory-{case_digest[:16]}"
            case["title"] = (
                f"{base_title} [trajectory order={','.join(descriptor.order)}; "
                f"spacing={descriptor.spacing_ms}ms; barriers={descriptor.barrier_mode}; "
                f"action-jitter={descriptor.action_jitter_ms}ms; "
                f"boundary-offset={descriptor.boundary_offset_ms}ms]"
            )
            parse_scenario(case)
            assignments: dict[str, JsonValue] = dict(semantic_assignments)
            assignments["trajectory.order"] = list(descriptor.order)
            assignments["trajectory.spacing_ms"] = descriptor.spacing_ms
            assignments["trajectory.barrier_mode"] = descriptor.barrier_mode
            assignments["trajectory.action_jitter_ms"] = descriptor.action_jitter_ms
            assignments["trajectory.boundary_offset_ms"] = descriptor.boundary_offset_ms
            baseline = (
                descriptor.order == actors
                and descriptor.spacing_ms == 0
                and descriptor.barrier_mode == "preserve"
                and descriptor.action_jitter_ms == 0
                and descriptor.boundary_offset_ms == 0
            )
            selection_key = _descriptor_digest(
                {
                    "seed": seed,
                    "semantic": semantic_assignments,
                    "trajectory": descriptor_raw,
                }
            )
            candidates.append((case, assignments, baseline, selection_key))

    if not candidates:
        raise TrajectoryError("the exploration configuration generated no trajectories")

    # Allocate the bounded pool by semantic configuration, pairing a control
    # with at least one schedule mutation before adding more variants.  Keeping
    # every semantic baseline first can fill the entire pool with controls and
    # leave no dynamic experiment for the runtime scheduler.
    groups: dict[str, list[tuple[dict[str, Any], dict[str, JsonValue], bool, str]]] = {}
    for item in candidates:
        semantic = {
            name: value
            for name, value in item[1].items()
            if not name.startswith("trajectory.")
        }
        group_key = _descriptor_digest({"seed": seed, "semantic": semantic})
        groups.setdefault(group_key, []).append(item)
    ordered_groups = sorted(groups.items())
    for _, items in ordered_groups:
        items.sort(key=lambda item: (not item[2], item[3]))

    selected: list[tuple[dict[str, Any], dict[str, JsonValue], bool, str]] = []
    if len(candidates) <= budget:
        selected = sorted(candidates, key=lambda item: (not item[2], item[3]))
    else:
        # First pass: one baseline and one mutation per chosen semantic config.
        for _, items in ordered_groups:
            baseline = next((item for item in items if item[2]), items[0])
            selected.append(baseline)
            if len(selected) >= budget:
                break
            mutation = next((item for item in items if not item[2]), None)
            if mutation is not None:
                selected.append(mutation)
            if len(selected) >= budget:
                break
        # Second pass: deterministic round-robin over remaining mutations.
        depth = 1
        while len(selected) < budget:
            added = False
            for _, items in ordered_groups:
                mutations = [item for item in items if not item[2]]
                if depth < len(mutations):
                    selected.append(mutations[depth])
                    added = True
                    if len(selected) >= budget:
                        break
            if not added:
                break
            depth += 1

    # This marker is for scheduler seeding only. Every semantic configuration
    # may still have its own differential-analysis baseline.
    for index, item in enumerate(selected):
        item[1]["trajectory.scheduler_seed"] = index == 0
    return [(case, assignments) for case, assignments, _, _ in selected]


def write_trajectory_manifest(
    base_scenario_path: Path,
    output_dir: Path,
    *,
    dimensions: Iterable[MatrixDimension] = (),
    dimension_strategy: str = "pairwise",
    spacings_ms: Iterable[int] = (0, 25, 250),
    barrier_modes: Iterable[str] = ("preserve", "relaxed"),
    action_jitters_ms: Iterable[int] = (0,),
    boundary_offsets_ms: Iterable[int] = (0,),
    budget: int = 64,
    execution_budget: int | None = None,
    seed: int = 0,
    overwrite: bool = False,
) -> Path:
    raw = json.loads(base_scenario_path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise TrajectoryError("base scenario root must be an object")
    cases = generate_trajectories(
        raw,
        dimensions=dimensions,
        dimension_strategy=dimension_strategy,
        spacings_ms=spacings_ms,
        barrier_modes=barrier_modes,
        action_jitters_ms=action_jitters_ms,
        boundary_offsets_ms=boundary_offsets_ms,
        budget=budget,
        seed=seed,
    )
    if execution_budget is not None and execution_budget < 1:
        raise TrajectoryError("execution budget must be positive")
    effective_execution_budget = min(execution_budget or len(cases), len(cases))
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    if manifest_path.exists() and not overwrite:
        raise TrajectoryError(f"trajectory output already exists: {manifest_path}")

    manifest_cases: list[dict[str, JsonValue]] = []
    for index, (case, assignments) in enumerate(cases):
        scenario = parse_scenario(case)
        slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", scenario.scenario_id).strip("-")[:72]
        filename = f"{index:04d}-{slug or 'trajectory'}-{scenario.digest[:12]}.json"
        path = output_dir / filename
        if path.exists() and not overwrite:
            raise TrajectoryError(f"trajectory case already exists: {path}")
        path.write_text(json.dumps(case, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        manifest_cases.append(
            {
                "id": scenario.scenario_id,
                "file": filename,
                "digest": scenario.digest,
                "assignments": assignments,
            }
        )

    manifest: dict[str, JsonValue] = {
        "schema_version": 1,
        "kind": "stateful_trajectory_exploration",
        "base_scenario": base_scenario_path.name,
        "base_scenario_sha256": hashlib.sha256(base_scenario_path.read_bytes()).hexdigest(),
        "case_count": len(manifest_cases),
        "seed": seed,
        "budget": budget,
        "execution_budget": effective_execution_budget,
        "dimension_strategy": dimension_strategy,
        "spacings_ms": list(dict.fromkeys(spacings_ms)),
        "barrier_modes": list(dict.fromkeys(barrier_modes)),
        "action_jitters_ms": list(dict.fromkeys(action_jitters_ms)),
        "boundary_offsets_ms": list(dict.fromkeys(boundary_offsets_ms)),
        "baseline_always_included": True,
        "cases": manifest_cases,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path
