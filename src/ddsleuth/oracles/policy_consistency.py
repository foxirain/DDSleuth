from __future__ import annotations

from ..evidence import EvidenceBundle
from ..models import AssertionSpec, EventKind, Scenario
from ..semantics import is_permitted, normalize_operation
from .base import OracleResult, OracleStatus, event_sequence


class PolicyAuthorizationConsistencyOracle:
    name = "policy_authorization_consistency"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        selected_actor = assertion.parameters.get("actor")
        selected_operation = assertion.parameters.get("operation")
        if selected_actor is not None and not isinstance(selected_actor, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="actor must be a string",
            )
        if selected_operation is not None and not isinstance(selected_operation, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="operation must be a string",
            )

        considered: list[int] = []
        overgrants: list[tuple[int, object]] = []
        for index, event in enumerate(evidence.events):
            if event.kind != EventKind.ACCESS_CONTROL_DECISION:
                continue
            if isinstance(selected_actor, str) and event.actor != selected_actor:
                continue
            operation = event.attributes.get("operation")
            resource = event.attributes.get("resource")
            if not isinstance(operation, str) or not isinstance(resource, str):
                continue
            normalized_operation = normalize_operation(operation)
            if normalized_operation is None:
                continue
            if isinstance(selected_operation, str) and normalized_operation != (
                normalize_operation(selected_operation) or selected_operation
            ):
                continue
            sequence = event_sequence(index, event.sequence)
            considered.append(sequence)
            if event.outcome == "allowed" and not is_permitted(
                scenario,
                event.actor,
                operation,
                resource,
            ):
                overgrants.append((sequence, event))

        if overgrants:
            first_sequence, first = overgrants[0]
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary=(
                    f"{first.actor} was allowed to {first.attributes.get('operation')} "
                    "a resource outside its declared policy"
                ),
                evidence_events=tuple(sequence for sequence, _ in overgrants),
                details={
                    "actor": first.actor,
                    "operation": first.attributes.get("operation"),
                    "resource": first.attributes.get("resource"),
                    "first_overgrant_event": first_sequence,
                },
            )

        if considered:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.PASS,
                summary="No observed access decision granted more authority than declared",
                evidence_events=tuple(considered),
            )

        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.NOT_APPLICABLE,
            summary="No matching access-control decision was observed",
        )
