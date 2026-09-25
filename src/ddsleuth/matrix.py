from __future__ import annotations

import copy
import hashlib
import itertools
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import JsonValue
from .scenario import parse_scenario


class MatrixError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MatrixDimension:
    path: tuple[str | int, ...]
    values: tuple[JsonValue, ...]

    @property
    def dotted_path(self) -> str:
        return ".".join(str(component) for component in self.path)


def parse_dimension(specification: str) -> MatrixDimension:
    if "=" not in specification:
        raise MatrixError("matrix dimension must use dotted.path=[values]")
    raw_path, raw_values = specification.split("=", 1)
    raw_components = tuple(part for part in raw_path.split(".") if part)
    path = tuple(
        int(component) if component.isdigit() else component
        for component in raw_components
    )
    if not path:
        raise MatrixError("matrix dimension path must not be empty")
    try:
        values = json.loads(raw_values)
    except json.JSONDecodeError as error:
        raise MatrixError(f"invalid JSON array for {raw_path}: {error}") from error
    if not isinstance(values, list) or not values:
        raise MatrixError(f"matrix dimension {raw_path} must contain a non-empty JSON array")
    return MatrixDimension(path=path, values=tuple(values))


def _render_path(path: tuple[str | int, ...]) -> str:
    return ".".join(str(component) for component in path)


def _set_path(
    document: dict[str, Any],
    path: tuple[str | int, ...],
    value: JsonValue,
) -> None:
    current: Any = document
    for component in path[:-1]:
        if isinstance(current, dict) and isinstance(component, str):
            child = current.get(component)
        elif isinstance(current, list) and isinstance(component, int):
            if component >= len(current):
                raise MatrixError(f"matrix list index is out of range: {_render_path(path)}")
            child = current[component]
        else:
            raise MatrixError(
                f"matrix path does not reference a compatible container: {_render_path(path)}"
            )
        if not isinstance(child, (dict, list)):
            raise MatrixError(
                f"matrix path does not reference a container: {_render_path(path)}"
            )
        current = child
    leaf = path[-1]
    if isinstance(current, dict) and isinstance(leaf, str):
        if leaf not in current:
            raise MatrixError(f"matrix path does not exist: {_render_path(path)}")
        current[leaf] = copy.deepcopy(value)
        return
    if isinstance(current, list) and isinstance(leaf, int):
        if leaf >= len(current):
            raise MatrixError(f"matrix list index is out of range: {_render_path(path)}")
        current[leaf] = copy.deepcopy(value)
        return
    raise MatrixError(
        f"matrix path does not reference a compatible value: {_render_path(path)}"
    )


def _slug(value: JsonValue) -> str:
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
    readable = re.sub(r"[^a-z0-9]+", "-", rendered.lower()).strip("-")[:24]
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:8]
    return f"{readable or 'value'}-{digest}"


def expand_matrix(
    raw_scenario: Mapping[str, Any],
    dimensions: Iterable[MatrixDimension],
    *,
    max_cases: int = 256,
    strategy: str = "cartesian",
) -> list[tuple[dict[str, Any], dict[str, JsonValue]]]:
    dimensions = tuple(dimensions)
    if not dimensions:
        raise MatrixError("at least one matrix dimension is required")
    if strategy not in ("cartesian", "pairwise"):
        raise MatrixError(f"unsupported matrix strategy: {strategy!r}")

    if strategy == "cartesian":
        case_count = 1
        for dimension in dimensions:
            case_count *= len(dimension.values)
        if case_count > max_cases:
            raise MatrixError(f"matrix expands to {case_count} cases, exceeding limit {max_cases}")
        rows: Iterable[tuple[int, ...]] = itertools.product(
            *(range(len(dimension.values)) for dimension in dimensions)
        )
    else:
        rows = _pairwise_rows(dimensions, max_cases=max_cases)

    base_id = raw_scenario.get("id")
    base_title = raw_scenario.get("title")
    if not isinstance(base_id, str) or not isinstance(base_title, str):
        raise MatrixError("base scenario must have string id and title")

    cases: list[tuple[dict[str, Any], dict[str, JsonValue]]] = []
    for row in rows:
        values = tuple(
            dimension.values[value_index]
            for dimension, value_index in zip(dimensions, row, strict=True)
        )
        case = copy.deepcopy(dict(raw_scenario))
        assignments: dict[str, JsonValue] = {}
        suffixes: list[str] = []
        labels: list[str] = []
        for dimension, value in zip(dimensions, values, strict=True):
            _set_path(case, dimension.path, value)
            assignments[dimension.dotted_path] = value
            suffixes.append(f"{dimension.path[-1]}-{_slug(value)}")
            labels.append(f"{dimension.dotted_path}={json.dumps(value, sort_keys=True)}")
        case["id"] = base_id + "--" + "--".join(suffixes)
        case["title"] = base_title + " [" + ", ".join(labels) + "]"
        parse_scenario(case)
        cases.append((case, assignments))
    return cases


def _pairwise_rows(
    dimensions: tuple[MatrixDimension, ...],
    *,
    max_cases: int,
) -> list[tuple[int, ...]]:
    if len(dimensions) == 1:
        rows = [(value,) for value in range(len(dimensions[0].values))]
        if len(rows) > max_cases:
            raise MatrixError(
                f"pairwise matrix requires {len(rows)} cases, exceeding limit {max_cases}"
            )
        return rows

    uncovered = {
        (left, left_value, right, right_value)
        for left in range(len(dimensions))
        for right in range(left + 1, len(dimensions))
        for left_value in range(len(dimensions[left].values))
        for right_value in range(len(dimensions[right].values))
    }
    rows: list[tuple[int, ...]] = []
    while uncovered:
        seed = min(uncovered)
        row: list[int | None] = [None] * len(dimensions)
        row[seed[0]] = seed[1]
        row[seed[2]] = seed[3]
        for dimension_index, dimension in enumerate(dimensions):
            if row[dimension_index] is not None:
                continue
            best_value = 0
            best_score = -1
            for candidate in range(len(dimension.values)):
                score = 0
                for other_index, other_value in enumerate(row):
                    if other_value is None or other_index == dimension_index:
                        continue
                    left, right = sorted((dimension_index, other_index))
                    left_value = candidate if left == dimension_index else other_value
                    right_value = other_value if right == other_index else candidate
                    if (left, left_value, right, right_value) in uncovered:
                        score += 1
                if score > best_score:
                    best_value = candidate
                    best_score = score
            row[dimension_index] = best_value

        completed = tuple(value for value in row if value is not None)
        if len(completed) != len(dimensions):
            raise MatrixError("internal pairwise construction failure")
        rows.append(completed)
        for left in range(len(dimensions)):
            for right in range(left + 1, len(dimensions)):
                uncovered.discard((left, completed[left], right, completed[right]))
        if len(rows) > max_cases:
            raise MatrixError(
                f"pairwise matrix requires more than {max_cases} cases"
            )
    return rows


def write_matrix(
    base_scenario_path: Path,
    output_dir: Path,
    dimensions: Iterable[MatrixDimension],
    *,
    max_cases: int = 256,
    overwrite: bool = False,
    strategy: str = "cartesian",
) -> Path:
    raw = json.loads(base_scenario_path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise MatrixError("base scenario root must be an object")
    cases = expand_matrix(raw, dimensions, max_cases=max_cases, strategy=strategy)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    if manifest_path.exists() and not overwrite:
        raise MatrixError(f"matrix output already exists: {manifest_path}")

    manifest_cases: list[dict[str, JsonValue]] = []
    for index, (case, assignments) in enumerate(cases):
        scenario = parse_scenario(case)
        base_slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(raw.get("id", "case"))).strip("-")
        filename = f"{index:04d}-{(base_slug or 'case')[:64]}-{scenario.digest[:12]}.json"
        path = output_dir / filename
        if path.exists() and not overwrite:
            raise MatrixError(f"matrix case already exists: {path}")
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
        "base_scenario": base_scenario_path.name,
        "case_count": len(manifest_cases),
        "strategy": strategy,
        "interaction_strength": 2 if strategy == "pairwise" else None,
        "cases": manifest_cases,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path
