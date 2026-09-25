from __future__ import annotations

import copy
import hashlib
import itertools
import json
import random
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

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "order": list(self.order),
            "spacing_ms": self.spacing_ms,
            "barrier_mode": self.barrier_mode,
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
) -> list[TrajectoryDescriptor]:
    # Differential analysis needs one canonical control even when the caller
    # requests only relaxed schedules or omits zero from the spacing set.
    # Keeping it here (rather than bolting it onto the manifest later) also
    # subjects the baseline to the same scenario validation as every mutation.
    descriptors: list[TrajectoryDescriptor] = [
        TrajectoryDescriptor(actors, 0, "preserve")
    ]
    if "preserve" in barrier_modes:
        descriptors.extend(
            TrajectoryDescriptor(actors, spacing, "preserve")
            for spacing in spacings_ms
        )
    if "relaxed" in barrier_modes:
        descriptors.extend(
            TrajectoryDescriptor(tuple(order), spacing, "relaxed")
            for order in itertools.permutations(actors)
            for spacing in spacings_ms
        )
    unique: dict[tuple[tuple[str, ...], int, str], TrajectoryDescriptor] = {}
    for descriptor in descriptors:
        unique[(descriptor.order, descriptor.spacing_ms, descriptor.barrier_mode)] = descriptor
    return list(unique.values())


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
        for descriptor in _schedule_descriptors(actors, spacings, modes):
            if (
                descriptor.barrier_mode == "relaxed"
                and not has_barriers
                and descriptor.order == actors
                and descriptor.spacing_ms == 0
            ):
                continue
            case = _apply_schedule(semantic_case, descriptor)
            descriptor_raw = descriptor.to_dict()
            schedule_digest = _descriptor_digest(descriptor_raw)
            base_id = str(semantic_case.get("id", "trajectory"))
            base_title = str(semantic_case.get("title", "DDS trajectory"))
            case["id"] = f"{base_id[:96]}--trajectory-{schedule_digest[:12]}"
            case["title"] = (
                f"{base_title} [trajectory order={','.join(descriptor.order)}; "
                f"spacing={descriptor.spacing_ms}ms; barriers={descriptor.barrier_mode}]"
            )
            parse_scenario(case)
            assignments: dict[str, JsonValue] = dict(semantic_assignments)
            assignments["trajectory.order"] = list(descriptor.order)
            assignments["trajectory.spacing_ms"] = descriptor.spacing_ms
            assignments["trajectory.barrier_mode"] = descriptor.barrier_mode
            baseline = (
                descriptor.order == actors
                and descriptor.spacing_ms == 0
                and descriptor.barrier_mode == "preserve"
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

    # Keep all baselines first. The remaining budget is a deterministic seeded
    # sample over schedule and semantic mutations, not insertion-order truncation.
    candidates.sort(key=lambda item: (not item[2], item[3]))
    if len(candidates) > budget:
        baselines = [item for item in candidates if item[2]]
        non_baselines = [item for item in candidates if not item[2]]
        if len(baselines) >= budget:
            selected = baselines[:budget]
        else:
            random.Random(seed).shuffle(non_baselines)
            selected = baselines + non_baselines[: budget - len(baselines)]
            selected.sort(key=lambda item: (not item[2], item[3]))
    else:
        selected = candidates
    return [(case, assignments) for case, assignments, _, _ in selected]


def write_trajectory_manifest(
    base_scenario_path: Path,
    output_dir: Path,
    *,
    dimensions: Iterable[MatrixDimension] = (),
    dimension_strategy: str = "pairwise",
    spacings_ms: Iterable[int] = (0, 25, 250),
    barrier_modes: Iterable[str] = ("preserve", "relaxed"),
    budget: int = 64,
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
        budget=budget,
        seed=seed,
    )
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
        "dimension_strategy": dimension_strategy,
        "spacings_ms": list(dict.fromkeys(spacings_ms)),
        "barrier_modes": list(dict.fromkeys(barrier_modes)),
        "baseline_always_included": True,
        "cases": manifest_cases,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path
