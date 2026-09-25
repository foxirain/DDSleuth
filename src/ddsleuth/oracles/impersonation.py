from __future__ import annotations

from ..evidence import EvidenceBundle
from ..models import AssertionSpec, EventKind, Scenario
from .base import OracleResult, OracleStatus, event_sequence


class ApplicationImpersonationOracle:
    name = "application_writer_impersonation"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        receiver = assertion.parameters.get("receiver")
        attacker = assertion.parameters.get("attacker")
        deliveries: list[tuple[int, object]] = []
        attempts: list[int] = []
        for index, event in enumerate(evidence.events):
            sequence = event_sequence(index, event.sequence)
            if event.kind in (EventKind.FORGE_CAPABILITY, EventKind.PACKET_SENT):
                if isinstance(attacker, str) and event.actor != attacker:
                    continue
                if event.outcome == "succeeded" and event.attributes.get("attacker_controlled") is True:
                    attempts.append(sequence)
            if event.kind != EventKind.APPLICATION_SAMPLE_RECEIVED:
                continue
            if isinstance(receiver, str) and event.actor != receiver:
                continue
            if event.outcome == "received" and event.attributes.get("attacker_controlled") is True:
                deliveries.append((sequence, event))

        if deliveries:
            first_sequence, first = deliveries[0]
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary=(
                    f"{first.actor}'s application DataReader returned attacker-controlled data "
                    "under the protected writer identity"
                ),
                evidence_events=tuple(sequence for sequence, _ in deliveries),
                details={
                    "receiver": first.actor,
                    "sample_index": first.attributes.get("sample_index"),
                    "message": first.attributes.get("message"),
                    "first_delivery_event": first_sequence,
                },
            )

        if attempts:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.PASS,
                summary="An attacker-controlled forgery was attempted but no application delivery was observed",
                evidence_events=tuple(attempts),
            )

        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.NOT_APPLICABLE,
            summary="No attacker-controlled forgery attempt was observed",
        )
