from __future__ import annotations

from ..evidence import EvidenceBundle
from ..models import AssertionSpec, EventKind, Scenario
from ..semantics import actor_has_any_permission
from .base import OracleResult, OracleStatus, event_sequence


class UnauthorizedKeyDisclosureOracle:
    name = "unauthorized_key_disclosure"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        actor = assertion.parameters.get("actor")
        if not isinstance(actor, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="The assertion does not name an actor",
            )

        denials: list[int] = []
        key_events: list[tuple[int, object]] = []
        for index, event in enumerate(evidence.events):
            if event.actor != actor:
                continue
            sequence = event_sequence(index, event.sequence)
            if event.kind == EventKind.ACCESS_CONTROL_DECISION and event.outcome == "denied":
                denials.append(sequence)
            elif event.kind == EventKind.KEY_MATERIAL_OBSERVED and event.outcome == "observed":
                sender = event.attributes.get("sender_key_present") is True
                receiver = event.attributes.get("receiver_specific_key_present") is True
                observed_user_token = (
                    event.attributes.get("observation_phase") == "received"
                    and event.attributes.get("endpoint_class") == "user"
                    and isinstance(event.attributes.get("key_fingerprint"), str)
                )
                if sender or receiver or observed_user_token:
                    key_events.append((sequence, event))

        denied_by_declared_policy = not actor_has_any_permission(
            scenario,
            actor,
            "subscribe",
        )

        if (denials or denied_by_declared_policy) and key_events:
            first_sequence, first = key_events[0]
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary=(
                    f"{actor} obtained user-endpoint key material despite lacking subscribe authority"
                ),
                evidence_events=tuple(denials + [sequence for sequence, _ in key_events]),
                details={
                    "actor": actor,
                    "sender_key_present": first.attributes.get("sender_key_present"),
                    "receiver_specific_key_present": first.attributes.get(
                        "receiver_specific_key_present"
                    ),
                    "key_fingerprint": first.attributes.get("key_fingerprint"),
                    "destination_endpoint_guid": first.attributes.get(
                        "destination_endpoint_guid"
                    ),
                    "source_endpoint_guid": first.attributes.get("source_endpoint_guid"),
                    "first_key_event": first_sequence,
                    "declared_policy_denied": denied_by_declared_policy,
                },
            )

        if denials or denied_by_declared_policy:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.PASS,
                summary=f"{actor} lacked subscribe authority and no user-endpoint key material was observed",
                evidence_events=tuple(denials),
            )

        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.NOT_APPLICABLE,
            summary=f"No access-control denial was observed for {actor}",
        )
