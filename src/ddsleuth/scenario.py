from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .models import (
    AssertionSpec,
    EventBarrier,
    ExecutionSpec,
    IdentitySpec,
    ParticipantSpec,
    RoleCommand,
    Scenario,
)


class ScenarioError(ValueError):
    pass


def _require_string(raw: Mapping[str, Any], key: str, context: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(f"{context}.{key} must be a non-empty string")
    return value


def _string_list(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ScenarioError(f"{context} must be an array of strings")
    return tuple(value)


def _canonical_digest(raw: Mapping[str, Any]) -> str:
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_scenario(raw: Mapping[str, Any]) -> Scenario:
    if raw.get("schema_version") != 1:
        raise ScenarioError("schema_version must be 1")

    scenario_id = _require_string(raw, "id", "scenario")
    title = _require_string(raw, "title", "scenario")

    implementation_raw = raw.get("implementation")
    if not isinstance(implementation_raw, Mapping):
        raise ScenarioError("implementation must be an object")
    implementation = _require_string(implementation_raw, "name", "implementation")
    implementation_version = implementation_raw.get("version")
    if implementation_version is not None and not isinstance(implementation_version, str):
        raise ScenarioError("implementation.version must be a string")

    domain_id = raw.get("domain_id")
    if not isinstance(domain_id, int) or domain_id < 0 or domain_id > 232:
        raise ScenarioError("domain_id must be an integer between 0 and 232")

    participants_raw = raw.get("participants")
    if not isinstance(participants_raw, Mapping) or len(participants_raw) < 2:
        raise ScenarioError("participants must contain at least two actors")
    participants: dict[str, ParticipantSpec] = {}
    for name, participant_raw in participants_raw.items():
        if not isinstance(name, str) or not isinstance(participant_raw, Mapping):
            raise ScenarioError("each participant must be a named object")
        role = _require_string(participant_raw, "role", f"participants.{name}")
        permissions_raw = participant_raw.get("permissions", {})
        if not isinstance(permissions_raw, Mapping):
            raise ScenarioError(f"participants.{name}.permissions must be an object")
        permissions = {
            str(operation): _string_list(resources, f"participants.{name}.permissions.{operation}")
            for operation, resources in permissions_raw.items()
        }
        identity_raw = participant_raw.get("identity")
        identity = None
        if identity_raw is not None:
            if not isinstance(identity_raw, Mapping):
                raise ScenarioError(f"participants.{name}.identity must be an object")
            identity = IdentitySpec(
                subject=_require_string(identity_raw, "subject", f"participants.{name}.identity")
            )
        participants[name] = ParticipantSpec(
            name=name,
            role=role,
            permissions=permissions,
            identity=identity,
        )

    policy_raw = raw.get("policy", {})
    if not isinstance(policy_raw, Mapping):
        raise ScenarioError("policy must be an object")
    grant_order_raw = policy_raw.get("grant_order")
    if grant_order_raw is None:
        grant_order = tuple(participants)
    else:
        grant_order = _string_list(grant_order_raw, "policy.grant_order")
        if len(grant_order) != len(set(grant_order)):
            raise ScenarioError("policy.grant_order must not contain duplicates")
        if set(grant_order) != set(participants):
            raise ScenarioError("policy.grant_order must contain every participant exactly once")

    governance_raw = raw.get("governance", {})
    if not isinstance(governance_raw, Mapping):
        raise ScenarioError("governance must be an object")
    governance = dict(governance_raw)

    topics_raw = raw.get("topics", {})
    if not isinstance(topics_raw, Mapping):
        raise ScenarioError("topics must be an object")
    topics: dict[str, Mapping[str, Any]] = {}
    for name, topic_raw in topics_raw.items():
        if not isinstance(name, str) or not isinstance(topic_raw, Mapping):
            raise ScenarioError("each topic must be a named object")
        topics[name] = dict(topic_raw)

    assertions_raw = raw.get("assertions")
    if not isinstance(assertions_raw, list) or not assertions_raw:
        raise ScenarioError("assertions must be a non-empty array")
    assertions: list[AssertionSpec] = []
    assertion_ids: set[str] = set()
    for index, assertion_raw in enumerate(assertions_raw):
        if not isinstance(assertion_raw, Mapping):
            raise ScenarioError(f"assertions[{index}] must be an object")
        assertion_id = _require_string(assertion_raw, "id", f"assertions[{index}]")
        if assertion_id in assertion_ids:
            raise ScenarioError(f"duplicate assertion id: {assertion_id}")
        assertion_ids.add(assertion_id)
        oracle = _require_string(assertion_raw, "oracle", f"assertions[{index}]")
        parameters = assertion_raw.get("parameters", {})
        if not isinstance(parameters, Mapping):
            raise ScenarioError(f"assertions[{index}].parameters must be an object")
        assertions.append(AssertionSpec(assertion_id, oracle, dict(parameters)))

    execution_raw = raw.get("execution")
    execution: ExecutionSpec | None = None
    if execution_raw is not None:
        if not isinstance(execution_raw, Mapping):
            raise ScenarioError("execution must be an object")
        network = _require_string(execution_raw, "network", "execution")
        timeout_seconds = execution_raw.get("timeout_seconds", 60)
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ScenarioError("execution.timeout_seconds must be positive")
        log_format = _require_string(execution_raw, "log_format", "execution")
        roles_raw = execution_raw.get("roles")
        if not isinstance(roles_raw, list) or not roles_raw:
            raise ScenarioError("execution.roles must be a non-empty array")
        roles: list[RoleCommand] = []
        seen_actors: set[str] = set()
        for index, role_raw in enumerate(roles_raw):
            if not isinstance(role_raw, Mapping):
                raise ScenarioError(f"execution.roles[{index}] must be an object")
            actor = _require_string(role_raw, "actor", f"execution.roles[{index}]")
            if actor not in participants:
                raise ScenarioError(f"execution role references unknown actor: {actor}")
            if actor in seen_actors:
                raise ScenarioError(f"duplicate execution role for actor: {actor}")
            command = _string_list(role_raw.get("command"), f"execution.roles[{index}].command")
            if not command:
                raise ScenarioError(f"execution.roles[{index}].command must not be empty")
            environment_raw = role_raw.get("environment", {})
            if not isinstance(environment_raw, Mapping) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in environment_raw.items()
            ):
                raise ScenarioError(f"execution.roles[{index}].environment must contain strings")
            barriers_raw = role_raw.get("start_after", [])
            if not isinstance(barriers_raw, list):
                raise ScenarioError(f"execution.roles[{index}].start_after must be an array")
            barriers: list[EventBarrier] = []
            for barrier_index, barrier_raw in enumerate(barriers_raw):
                context = f"execution.roles[{index}].start_after[{barrier_index}]"
                if not isinstance(barrier_raw, Mapping):
                    raise ScenarioError(f"{context} must be an object")
                barrier_actor = _require_string(barrier_raw, "actor", context)
                if barrier_actor not in seen_actors:
                    raise ScenarioError(
                        f"{context}.actor must reference an earlier execution role"
                    )
                kind = _require_string(barrier_raw, "kind", context)
                outcome = barrier_raw.get("outcome")
                if outcome is not None and not isinstance(outcome, str):
                    raise ScenarioError(f"{context}.outcome must be a string")
                attributes = barrier_raw.get("attributes", {})
                if not isinstance(attributes, Mapping):
                    raise ScenarioError(f"{context}.attributes must be an object")
                barriers.append(
                    EventBarrier(
                        actor=barrier_actor,
                        kind=kind,
                        outcome=outcome,
                        attributes=dict(attributes),
                    )
                )
            roles.append(RoleCommand(actor, command, dict(environment_raw), tuple(barriers)))
            seen_actors.add(actor)
        execution = ExecutionSpec(network, float(timeout_seconds), log_format, tuple(roles))

    return Scenario(
        schema_version=1,
        scenario_id=scenario_id,
        title=title,
        implementation=implementation,
        implementation_version=implementation_version,
        domain_id=domain_id,
        participants=participants,
        grant_order=grant_order,
        governance=governance,
        topics=topics,
        assertions=tuple(assertions),
        execution=execution,
        raw=dict(raw),
        digest=_canonical_digest(raw),
    )


def load_scenario(path: str | Path) -> Scenario:
    scenario_path = Path(path)
    try:
        raw = json.loads(scenario_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ScenarioError(f"cannot read scenario {scenario_path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ScenarioError(f"invalid JSON in {scenario_path}: {error}") from error
    if not isinstance(raw, Mapping):
        raise ScenarioError("scenario root must be an object")
    return parse_scenario(raw)
