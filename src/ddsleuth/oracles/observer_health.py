from __future__ import annotations

from ..evidence import EvidenceBundle
from ..models import AssertionSpec, EventKind, Scenario
from .base import OracleResult, OracleStatus, event_sequence


class ObserverHealthOracle:
    """Fail closed when white-box instrumentation is absent or reports an error."""

    name = "observer_health"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        required_kind = assertion.parameters.get(
            "required_event_kind", EventKind.KEY_MATERIAL_OBSERVED.value
        )
        if not isinstance(required_kind, str) or not required_kind:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="required_event_kind must be a non-empty string",
            )

        failures = [
            event_sequence(index, event.sequence)
            for index, event in enumerate(evidence.events)
            if event.kind == EventKind.OBSERVER_ERROR
        ]
        if failures:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="White-box observer reported an instrumentation error",
                evidence_events=tuple(failures),
                details={"observer_error_count": len(failures)},
            )

        observations = [
            event_sequence(index, event.sequence)
            for index, event in enumerate(evidence.events)
            if event.kind == required_kind
        ]
        if not observations:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="Required white-box observer evidence was not emitted",
                details={"required_event_kind": required_kind},
            )

        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.PASS,
            summary="White-box observer emitted evidence without reporting an error",
            evidence_events=tuple(observations),
            details={
                "required_event_kind": required_kind,
                "observation_count": len(observations),
            },
        )
