from __future__ import annotations

from ..evidence import EvidenceBundle
from ..models import AssertionSpec, EventKind, Scenario
from .base import OracleResult, OracleStatus, event_sequence


class RevokedAuthorityReuseOracle:
    name = "revoked_authority_reuse"

    _CAPABILITY_KINDS = {
        EventKind.DECRYPT_CAPABILITY,
        EventKind.FORGE_CAPABILITY,
        EventKind.PROTECTED_MESSAGE_ACCEPTED,
        EventKind.APPLICATION_SAMPLE_RECEIVED,
        "capability.availability",
    }

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        actor = assertion.parameters.get("actor")
        if actor is not None and not isinstance(actor, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="actor must be a string",
            )

        revocations: dict[str, tuple[int, object]] = {}
        for index, event in enumerate(evidence.events):
            if event.kind != EventKind.AUTHORITY_REVOKED or event.outcome != "succeeded":
                continue
            if isinstance(actor, str) and event.actor != actor:
                continue
            authority_id = event.attributes.get("authority_id")
            if isinstance(authority_id, str):
                revocations[authority_id] = (event_sequence(index, event.sequence), event)

        if not revocations:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="No matching authority revocation was observed",
            )

        stale_uses: list[tuple[int, object, int]] = []
        for index, event in enumerate(evidence.events):
            if event.kind not in self._CAPABILITY_KINDS:
                continue
            if event.outcome not in ("succeeded", "accepted", "received"):
                continue
            authority_id = event.attributes.get("authority_id")
            if not isinstance(authority_id, str) or authority_id not in revocations:
                continue
            sequence = event_sequence(index, event.sequence)
            revoked_at, _ = revocations[authority_id]
            if sequence > revoked_at:
                stale_uses.append((sequence, event, revoked_at))

        if stale_uses:
            sequence, first, revoked_at = stale_uses[0]
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary="A revoked authority still produced an accepted security capability",
                evidence_events=tuple(
                    sorted(
                        {revoked_at for _, _, revoked_at in stale_uses}
                        | {item_sequence for item_sequence, _, _ in stale_uses}
                    )
                ),
                details={
                    "authority_id": first.attributes.get("authority_id"),
                    "capability_kind": first.kind,
                    "revocation_event": revoked_at,
                    "first_stale_use_event": sequence,
                },
            )

        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.PASS,
            summary="No revoked authority was observed producing a later capability",
            evidence_events=tuple(sorted(sequence for sequence, _ in revocations.values())),
        )
