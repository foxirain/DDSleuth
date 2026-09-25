from __future__ import annotations

from collections import defaultdict

from ..evidence import EvidenceBundle
from ..fingerprints import FINGERPRINT_SCHEME
from ..models import AssertionSpec, EventKind, Scenario
from .base import OracleResult, OracleStatus, event_sequence


class EndpointKeyLifecycleOracle:
    """Require fresh user-endpoint key material after endpoint recreation."""

    name = "endpoint_key_lifecycle"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        actor = assertion.parameters.get("actor")
        if not isinstance(actor, str) or actor not in scenario.participants:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="actor must identify a scenario participant",
            )

        token_class = assertion.parameters.get("token_class", "datawriter")
        endpoint_class = assertion.parameters.get("endpoint_class", "user")
        observation_phase = assertion.parameters.get("observation_phase", "generated")
        filters = (token_class, endpoint_class, observation_phase)
        if not all(isinstance(value, str) and value for value in filters):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="lifecycle observation filters must be non-empty strings",
            )

        boundaries = [
            (index, event)
            for index, event in enumerate(evidence.events)
            if event.actor == actor and event.kind == EventKind.ENDPOINT_DESTROYED
        ]
        if len(boundaries) != 1:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="Exactly one endpoint destruction boundary is required",
                details={"boundary_count": len(boundaries)},
            )
        boundary_index, boundary = boundaries[0]

        observations: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for index, event in enumerate(evidence.events):
            if event.actor != actor or event.kind != EventKind.KEY_MATERIAL_OBSERVED:
                continue
            attributes = event.attributes
            if (
                attributes.get("token_class") != token_class
                or attributes.get("endpoint_class") != endpoint_class
                or attributes.get("observation_phase") != observation_phase
            ):
                continue
            fingerprint = attributes.get("key_fingerprint")
            if not isinstance(fingerprint, str) or not fingerprint.startswith(
                FINGERPRINT_SCHEME + ":"
            ):
                continue
            observations[fingerprint].append(
                (index, event_sequence(index, event.sequence))
            )

        pre = {
            fingerprint
            for fingerprint, positions in observations.items()
            if any(index < boundary_index for index, _ in positions)
        }
        post = {
            fingerprint
            for fingerprint, positions in observations.items()
            if any(index > boundary_index for index, _ in positions)
        }
        if not pre or not post:
            evidence_events = tuple(
                sorted(
                    {
                        sequence
                        for positions in observations.values()
                        for _, sequence in positions
                    }
                    | {event_sequence(boundary_index, boundary.sequence)}
                )
            )
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="Key observations were missing on one side of endpoint recreation",
                evidence_events=evidence_events,
                details={
                    "pre_fingerprint_count": len(pre),
                    "post_fingerprint_count": len(post),
                },
            )

        reused = sorted(pre & post)
        boundary_sequence = event_sequence(boundary_index, boundary.sequence)
        if reused:
            related = {boundary_sequence}
            for fingerprint in reused:
                related.update(sequence for _, sequence in observations[fingerprint])
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary="User-endpoint key material survived endpoint destruction and recreation",
                evidence_events=tuple(sorted(related)),
                details={
                    "actor": actor,
                    "reused_fingerprints": reused,
                    "pre_fingerprint_count": len(pre),
                    "post_fingerprint_count": len(post),
                },
            )

        considered = {boundary_sequence}
        for fingerprint in pre | post:
            considered.update(sequence for _, sequence in observations[fingerprint])
        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.PASS,
            summary="Endpoint recreation produced disjoint user-endpoint key material",
            evidence_events=tuple(sorted(considered)),
            details={
                "actor": actor,
                "pre_fingerprint_count": len(pre),
                "post_fingerprint_count": len(post),
            },
        )
