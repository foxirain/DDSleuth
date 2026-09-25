from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ..evidence import EvidenceBundle
from ..models import EventKind, JsonValue, Scenario
from .authorization import UnauthorizedKeyDisclosureOracle
from .base import Oracle, OracleResult, OracleStatus
from .impersonation import ApplicationImpersonationOracle
from .key_scope import KeyScopeSeparationOracle
from .lifecycle import RevokedAuthorityReuseOracle
from .endpoint_lifecycle import EndpointKeyLifecycleOracle
from .observer_health import ObserverHealthOracle
from .policy_consistency import PolicyAuthorizationConsistencyOracle
from .recipient_binding import RecipientBindingOracle
from .session_rotation import SessionRotationDeliveryOracle
from .token_transport import CryptoTokenTransportConsistencyOracle
from ..semantics import event_resource, is_permitted


_ORACLES: Mapping[str, Oracle] = {
    RecipientBindingOracle.name: RecipientBindingOracle(),
    UnauthorizedKeyDisclosureOracle.name: UnauthorizedKeyDisclosureOracle(),
    ApplicationImpersonationOracle.name: ApplicationImpersonationOracle(),
    KeyScopeSeparationOracle.name: KeyScopeSeparationOracle(),
    RevokedAuthorityReuseOracle.name: RevokedAuthorityReuseOracle(),
    PolicyAuthorizationConsistencyOracle.name: PolicyAuthorizationConsistencyOracle(),
    CryptoTokenTransportConsistencyOracle.name: CryptoTokenTransportConsistencyOracle(),
    ObserverHealthOracle.name: ObserverHealthOracle(),
    EndpointKeyLifecycleOracle.name: EndpointKeyLifecycleOracle(),
    SessionRotationDeliveryOracle.name: SessionRotationDeliveryOracle(),
}


@dataclass(frozen=True, slots=True)
class CapabilityAssessment:
    confidentiality: str
    integrity: str
    availability: str
    evidence_events: Mapping[str, tuple[int, ...]]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "confidentiality": self.confidentiality,
            "integrity": self.integrity,
            "availability": self.availability,
            "evidence_events": {
                name: list(events) for name, events in self.evidence_events.items()
            },
        }


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    schema_version: int
    scenario_id: str
    scenario_digest: str
    run_id: str
    verdict: str
    failed_processes: Mapping[str, int]
    incomplete_processes: tuple[str, ...]
    oracle_results: tuple[OracleResult, ...]
    capabilities: CapabilityAssessment

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "scenario_digest": self.scenario_digest,
            "run_id": self.run_id,
            "verdict": self.verdict,
            "failed_processes": dict(self.failed_processes),
            "incomplete_processes": list(self.incomplete_processes),
            "oracle_results": [result.to_dict() for result in self.oracle_results],
            "capabilities": self.capabilities.to_dict(),
        }


def _capabilities(scenario: Scenario, evidence: EvidenceBundle) -> CapabilityAssessment:
    confidentiality: list[int] = []
    integrity: list[int] = []
    availability: list[int] = []

    for index, event in enumerate(evidence.events):
        sequence = index if event.sequence is None else event.sequence
        if event.kind == EventKind.DECRYPT_CAPABILITY and event.outcome == "succeeded":
            confidentiality.append(sequence)
        if event.kind == EventKind.APPLICATION_SAMPLE_RECEIVED and event.outcome == "received":
            resource = event_resource(scenario, event, operation="subscribe")
            if resource is not None and not is_permitted(
                scenario,
                event.actor,
                "subscribe",
                resource,
            ):
                confidentiality.append(sequence)
        if event.kind in (
            EventKind.FORGE_CAPABILITY,
            EventKind.PROTECTED_MESSAGE_ACCEPTED,
            EventKind.APPLICATION_SAMPLE_RECEIVED,
        ) and event.outcome in ("succeeded", "accepted", "received"):
            if event.attributes.get("attacker_controlled") is True:
                integrity.append(sequence)
        if event.kind == "capability.availability" and event.outcome == "succeeded":
            availability.append(sequence)

    return CapabilityAssessment(
        confidentiality="high" if confidentiality else "not_demonstrated",
        integrity="high" if integrity else "not_demonstrated",
        availability="high" if availability else "not_demonstrated",
        evidence_events={
            "confidentiality": tuple(confidentiality),
            "integrity": tuple(integrity),
            "availability": tuple(availability),
        },
    )


def evaluate(scenario: Scenario, evidence: EvidenceBundle) -> EvaluationReport:
    if evidence.scenario_id != scenario.scenario_id:
        raise ValueError(
            f"evidence scenario {evidence.scenario_id!r} does not match {scenario.scenario_id!r}"
        )
    if evidence.scenario_digest != scenario.digest:
        raise ValueError("evidence was produced for a different scenario revision")
    if evidence.implementation != scenario.implementation:
        raise ValueError("evidence implementation does not match the scenario")
    for index, event in enumerate(evidence.events):
        if event.implementation != scenario.implementation:
            raise ValueError(f"event {index} implementation does not match the scenario")
        if event.actor not in scenario.participants:
            raise ValueError(f"event {index} references unknown actor {event.actor!r}")
        if event.sequence != index:
            raise ValueError(f"event {index} has a non-canonical sequence")

    results: list[OracleResult] = []
    for assertion in scenario.assertions:
        oracle = _ORACLES.get(assertion.oracle)
        if oracle is None:
            results.append(
                OracleResult(
                    assertion_id=assertion.assertion_id,
                    oracle=assertion.oracle,
                    status=OracleStatus.NOT_APPLICABLE,
                    summary="No oracle implementation is registered",
                )
            )
            continue
        results.append(oracle.evaluate(scenario, assertion, evidence))

    failed_processes: dict[str, int] = {}
    exited_processes: set[str] = set()
    for event in evidence.events:
        if event.kind == EventKind.PROCESS_EXIT:
            exited_processes.add(event.actor)
            if event.outcome == "failed":
                exit_code = event.attributes.get("exit_code")
                failed_processes[event.actor] = exit_code if isinstance(exit_code, int) else -1

    expected_processes = (
        {role.actor for role in scenario.execution.roles}
        if scenario.execution is not None
        else set()
    )
    incomplete_processes = tuple(sorted(expected_processes - exited_processes))

    if any(result.status == OracleStatus.VIOLATION for result in results):
        verdict = "violation"
    elif failed_processes or incomplete_processes:
        verdict = "inconclusive"
    elif any(result.status == OracleStatus.NOT_APPLICABLE for result in results):
        verdict = "inconclusive"
    else:
        verdict = "pass"

    return EvaluationReport(
        schema_version=1,
        scenario_id=scenario.scenario_id,
        scenario_digest=scenario.digest,
        run_id=evidence.run_id,
        verdict=verdict,
        failed_processes=failed_processes,
        incomplete_processes=incomplete_processes,
        oracle_results=tuple(results),
        capabilities=_capabilities(scenario, evidence),
    )
