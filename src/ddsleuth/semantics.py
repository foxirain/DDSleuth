from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Iterable

from .models import EvidenceEvent, Scenario


_OPERATIONS = {
    "publish": "publish",
    "create_datawriter": "publish",
    "write": "publish",
    "subscribe": "subscribe",
    "create_datareader": "subscribe",
    "read": "subscribe",
}


def normalize_operation(operation: str) -> str | None:
    return _OPERATIONS.get(operation)


def is_permitted(
    scenario: Scenario,
    actor: str,
    operation: str,
    resource: str,
) -> bool:
    participant = scenario.participants.get(actor)
    permission = normalize_operation(operation)
    if participant is None or permission is None:
        return False
    expressions = participant.permissions.get(permission, ())
    return any(fnmatchcase(resource, expression) for expression in expressions)


def permitted_resources(
    scenario: Scenario,
    actor: str,
    operation: str,
) -> tuple[str, ...]:
    participant = scenario.participants.get(actor)
    permission = normalize_operation(operation)
    if participant is None or permission is None:
        return ()
    return tuple(participant.permissions.get(permission, ()))


def event_resource(
    scenario: Scenario,
    event: EvidenceEvent,
    *,
    operation: str,
) -> str | None:
    for attribute in ("resource", "topic", "topic_name"):
        value = event.attributes.get(attribute)
        if isinstance(value, str) and value:
            return value

    # A single-topic experiment has an unambiguous application resource even
    # when an older probe omitted the topic from its callback event.
    if len(scenario.topics) == 1:
        return next(iter(scenario.topics))

    allowed = permitted_resources(scenario, event.actor, operation)
    concrete = tuple(value for value in allowed if not any(char in value for char in "*?[") )
    if len(concrete) == 1:
        return concrete[0]
    return None


def actor_has_any_permission(
    scenario: Scenario,
    actor: str,
    operation: str,
    resources: Iterable[str] | None = None,
) -> bool:
    candidates = tuple(resources) if resources is not None else tuple(scenario.topics)
    return any(is_permitted(scenario, actor, operation, resource) for resource in candidates)
