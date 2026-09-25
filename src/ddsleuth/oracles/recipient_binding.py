from __future__ import annotations

from ..evidence import EvidenceBundle
from ..models import AssertionSpec, EventKind, Scenario
from .base import OracleResult, OracleStatus, event_sequence


class RecipientBindingOracle:
    name = "crypto_token_recipient_binding"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        observer = assertion.parameters.get("observer")
        token_class = assertion.parameters.get("token_class")
        candidates: list[tuple[int, object]] = []
        violations: list[tuple[int, object]] = []

        for index, event in enumerate(evidence.events):
            if event.kind != EventKind.CRYPTO_TOKEN_OBSERVED:
                continue
            if isinstance(observer, str) and event.actor != observer:
                continue
            if isinstance(token_class, str) and event.attributes.get("token_class") != token_class:
                continue
            sequence = event_sequence(index, event.sequence)
            candidates.append((sequence, event))
            local = event.attributes.get("local_participant_guid")
            destination = event.attributes.get("destination_participant_guid")
            if isinstance(local, str) and isinstance(destination, str) and local != destination:
                violations.append((sequence, event))

        if violations:
            first_sequence, first = violations[0]
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary=(
                    f"{first.actor} observed a plaintext CryptoToken addressed to a different participant"
                ),
                evidence_events=tuple(sequence for sequence, _ in violations),
                details={
                    "observer": first.actor,
                    "local_participant_guid": first.attributes.get("local_participant_guid"),
                    "destination_participant_guid": first.attributes.get("destination_participant_guid"),
                    "destination_endpoint_guid": first.attributes.get("destination_endpoint_guid"),
                    "source_endpoint_guid": first.attributes.get("source_endpoint_guid"),
                    "first_violation_event": first_sequence,
                },
            )

        if candidates:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.PASS,
                summary="All observed CryptoTokens were addressed to the observing participant",
                evidence_events=tuple(sequence for sequence, _ in candidates),
            )

        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.NOT_APPLICABLE,
            summary="No matching plaintext CryptoToken observation was available",
        )
