from __future__ import annotations

from collections import defaultdict

from ..evidence import EvidenceBundle
from ..fingerprints import FINGERPRINT_SCHEME
from ..models import AssertionSpec, EventKind, Scenario
from .base import OracleResult, OracleStatus, event_sequence


class KeyScopeSeparationOracle:
    name = "key_scope_separation"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        key_class = assertion.parameters.get("key_class")
        scope_attribute = assertion.parameters.get("scope_attribute", "scope_id")
        observation_phase = assertion.parameters.get("observation_phase")
        endpoint_class = assertion.parameters.get("endpoint_class")
        material_semantics = assertion.parameters.get("material_semantics")
        if not isinstance(scope_attribute, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="scope_attribute must be a string",
            )
        if observation_phase is not None and not isinstance(observation_phase, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="observation_phase must be a string",
            )
        if endpoint_class is not None and not isinstance(endpoint_class, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="endpoint_class must be a string",
            )
        if material_semantics is not None and not isinstance(material_semantics, str):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="material_semantics must be a string",
            )
        if material_semantics is None and scope_attribute == "destination_participant_guid":
            # A sender's common master key is intentionally shared by every
            # authorized receiver. Recipient separation applies only to the
            # optional receiver-specific component.
            material_semantics = "recipient_specific"

        fingerprints: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
        considered: list[int] = []
        for index, event in enumerate(evidence.events):
            if event.kind != EventKind.KEY_MATERIAL_OBSERVED or event.outcome != "observed":
                continue
            if isinstance(key_class, str) and event.attributes.get("key_class") != key_class:
                continue
            if (
                isinstance(observation_phase, str)
                and event.attributes.get("observation_phase") != observation_phase
            ):
                continue
            if (
                isinstance(endpoint_class, str)
                and event.attributes.get("endpoint_class") != endpoint_class
            ):
                continue
            if (
                isinstance(material_semantics, str)
                and event.attributes.get("material_semantics") != material_semantics
            ):
                continue
            fingerprint = event.attributes.get("key_fingerprint")
            scope = event.attributes.get(scope_attribute)
            if not isinstance(fingerprint, str) or not isinstance(scope, str):
                continue
            if not fingerprint.startswith(FINGERPRINT_SCHEME + ":"):
                continue
            sequence = event_sequence(index, event.sequence)
            considered.append(sequence)
            fingerprints[fingerprint].append((sequence, scope, event.actor))

        collisions: list[tuple[str, list[tuple[int, str, str]]]] = []
        for fingerprint, observations in fingerprints.items():
            if len({scope for _, scope, _ in observations}) > 1:
                collisions.append((fingerprint, observations))

        if collisions:
            fingerprint, observations = collisions[0]
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary="The same key authority was observed in scopes required to be distinct",
                evidence_events=tuple(
                    sequence
                    for _, items in collisions
                    for sequence, _, _ in items
                ),
                details={
                    "key_class": key_class if isinstance(key_class, str) else "any",
                    "observation_phase": (
                        observation_phase if isinstance(observation_phase, str) else "any"
                    ),
                    "endpoint_class": endpoint_class if isinstance(endpoint_class, str) else "any",
                    "material_semantics": (
                        material_semantics if isinstance(material_semantics, str) else "any"
                    ),
                    "fingerprint": fingerprint,
                    "scopes": sorted({scope for _, scope, _ in observations}),
                    "actors": sorted({actor for _, _, actor in observations}),
                },
            )

        if considered:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.PASS,
                summary="No key fingerprint crossed a required scope boundary",
                evidence_events=tuple(considered),
            )

        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.NOT_APPLICABLE,
            summary="No scoped run-local key fingerprints were available",
        )
