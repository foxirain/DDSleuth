from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ..evidence import EvidenceBundle
from ..fingerprints import FINGERPRINT_SCHEME
from ..models import AssertionSpec, EventKind, Scenario
from .base import OracleResult, OracleStatus, event_sequence


@dataclass(frozen=True, slots=True)
class _Observation:
    sequence: int
    actor: str
    phase: str
    fingerprint: str
    token_class: str
    local_participant: str
    destination_participant: str
    destination_endpoint: str
    source_endpoint: str

    @property
    def route(self) -> tuple[str, str, str, str, str]:
        return (
            self.fingerprint,
            self.token_class,
            self.destination_participant,
            self.destination_endpoint,
            self.source_endpoint,
        )


def _observation(index: int, event: object) -> _Observation | None:
    if getattr(event, "kind", None) != EventKind.KEY_MATERIAL_OBSERVED:
        return None
    if getattr(event, "outcome", None) != "observed":
        return None
    attributes = getattr(event, "attributes", {})
    phase = attributes.get("observation_phase")
    fingerprint = attributes.get("key_fingerprint")
    token_class = attributes.get("token_class")
    local_participant = attributes.get("local_participant_guid")
    destination_participant = attributes.get("destination_participant_guid")
    destination_endpoint = attributes.get("destination_endpoint_guid")
    source_endpoint = attributes.get("source_endpoint_guid")
    values = (
        phase,
        fingerprint,
        token_class,
        local_participant,
        destination_participant,
        destination_endpoint,
        source_endpoint,
    )
    if not all(isinstance(value, str) for value in values):
        return None
    if phase not in ("generated", "received"):
        return None
    if not fingerprint.startswith(FINGERPRINT_SCHEME + ":"):
        return None
    return _Observation(
        sequence=event_sequence(index, getattr(event, "sequence", None)),
        actor=getattr(event, "actor"),
        phase=phase,
        fingerprint=fingerprint,
        token_class=token_class,
        local_participant=local_participant,
        destination_participant=destination_participant,
        destination_endpoint=destination_endpoint,
        source_endpoint=source_endpoint,
    )


class CryptoTokenTransportConsistencyOracle:
    """Bind a received key token to the exact route on which it was generated."""

    name = "crypto_token_transport_consistency"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        selected_class = assertion.parameters.get("token_class")
        if selected_class is not None and not isinstance(selected_class, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="token_class must be a string",
            )
        require_all_generated = assertion.parameters.get("require_all_generated", True)
        if not isinstance(require_all_generated, bool):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="require_all_generated must be a boolean",
            )

        generated: list[_Observation] = []
        received: list[_Observation] = []
        for index, event in enumerate(evidence.events):
            item = _observation(index, event)
            if item is None:
                continue
            if isinstance(selected_class, str) and item.token_class != selected_class:
                continue
            if item.phase == "generated":
                # Same-participant associations do not traverse the token transport.
                if item.local_participant != item.destination_participant:
                    generated.append(item)
            else:
                received.append(item)

        if not generated and not received:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="No routed run-local key observations were available",
            )

        # CryptoToken retransmission is legitimate.  This oracle proves route
        # membership, not one-to-one packet delivery: an exact duplicate on an
        # already generated route must not become a false route-rebinding alert.
        generated_routes = {item.route for item in generated}
        received_routes = {item.route for item in received}
        generated_by_fingerprint: dict[str, list[_Observation]] = defaultdict(list)
        for item in generated:
            generated_by_fingerprint[item.fingerprint].append(item)

        misrouted: list[tuple[_Observation, list[_Observation]]] = []
        orphaned: list[_Observation] = []
        for item in received:
            if item.route in generated_routes:
                continue
            same_material = generated_by_fingerprint.get(item.fingerprint, [])
            if same_material:
                misrouted.append((item, same_material))
            else:
                orphaned.append(item)

        if misrouted:
            received_item, origins = misrouted[0]
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary="Received key material was rebound to a route on which it was not generated",
                evidence_events=tuple(
                    sorted(
                        {
                            item.sequence
                            for received_item, origins in misrouted
                            for item in (received_item, *origins)
                        }
                    )
                ),
                details={
                    "fingerprint": received_item.fingerprint,
                    "received_actor": received_item.actor,
                    "received_destination_participant": received_item.destination_participant,
                    "received_destination_endpoint": received_item.destination_endpoint,
                    "received_source_endpoint": received_item.source_endpoint,
                    "generated_routes": [
                        {
                            "actor": origin.actor,
                            "destination_participant": origin.destination_participant,
                            "destination_endpoint": origin.destination_endpoint,
                            "source_endpoint": origin.source_endpoint,
                        }
                        for origin in origins
                    ],
                },
            )

        unmatched_generated = [item for item in generated if item.route not in received_routes]
        if orphaned or (require_all_generated and unmatched_generated):
            incomplete = orphaned + (unmatched_generated if require_all_generated else [])
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="Token transport observation was incomplete in one or both directions",
                evidence_events=tuple(sorted({item.sequence for item in incomplete})),
                details={
                    "received_without_generation": len(orphaned),
                    "generated_without_receive": len(unmatched_generated),
                },
            )

        considered = tuple(sorted(item.sequence for item in generated + received))
        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.PASS,
            summary="Every received key fingerprint matched its exact generated token route",
            evidence_events=considered,
            details={
                "generated_observations": len(generated),
                "received_observations": len(received),
            },
        )
