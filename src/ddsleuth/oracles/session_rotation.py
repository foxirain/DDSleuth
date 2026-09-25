from __future__ import annotations

from ..evidence import EvidenceBundle
from ..models import AssertionSpec, EventKind, Scenario
from .base import OracleResult, OracleStatus, event_sequence


class SessionRotationDeliveryOracle:
    """Check session-id transitions and delivery of the samples that trigger them."""

    name = "session_rotation_delivery"

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        writer = assertion.parameters.get("writer")
        reader = assertion.parameters.get("reader")
        context = assertion.parameters.get("context", "serialized_payload")
        minimum_rotations = assertion.parameters.get("minimum_rotations", 1)
        expected_max_blocks = assertion.parameters.get("max_blocks_per_session")
        if (
            not isinstance(writer, str)
            or writer not in scenario.participants
            or not isinstance(reader, str)
            or reader not in scenario.participants
            or not isinstance(context, str)
            or not context
            or not isinstance(minimum_rotations, int)
            or isinstance(minimum_rotations, bool)
            or minimum_rotations < 1
            or (
                expected_max_blocks is not None
                and (
                    not isinstance(expected_max_blocks, int)
                    or isinstance(expected_max_blocks, bool)
                    or expected_max_blocks < 1
                )
            )
        ):
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="Invalid session-rotation assertion parameters",
            )

        rotations: list[tuple[int, object]] = []
        for index, event in enumerate(evidence.events):
            if (
                event.kind == EventKind.KEY_ROTATED
                and event.actor == writer
                and event.outcome == "rotated"
                and event.attributes.get("rotation_kind") == "session_key"
                and event.attributes.get("context") == context
            ):
                rotations.append((index, event))

        if len(rotations) < minimum_rotations:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="Too few observed session-key rotations",
                evidence_events=tuple(
                    event_sequence(index, event.sequence) for index, event in rotations
                ),
                details={
                    "observed_rotations": len(rotations),
                    "minimum_rotations": minimum_rotations,
                },
            )

        invalid_transitions: list[tuple[int, object]] = []
        configuration_mismatches: list[tuple[int, object]] = []
        rotation_samples: list[tuple[int, int, int]] = []
        incomplete: set[int] = set()
        for rotation_index, event in rotations:
            previous = event.attributes.get("previous_session_id")
            current = event.attributes.get("session_id")
            configured_max = event.attributes.get("max_blocks_per_session")
            if (
                not isinstance(previous, int)
                or isinstance(previous, bool)
                or not isinstance(current, int)
                or isinstance(current, bool)
                or current != ((previous + 1) & 0xFFFFFFFF)
            ):
                invalid_transitions.append((rotation_index, event))
            if expected_max_blocks is not None and configured_max != expected_max_blocks:
                configuration_mismatches.append((rotation_index, event))

            attempt_index = None
            sample_index = None
            for index in range(rotation_index - 1, -1, -1):
                candidate = evidence.events[index]
                if candidate.actor != writer:
                    continue
                if candidate.kind == EventKind.APPLICATION_WRITE_ATTEMPT:
                    value = candidate.attributes.get("sample_index")
                    if isinstance(value, int) and not isinstance(value, bool):
                        attempt_index = index
                        sample_index = value
                    break
                if candidate.kind == EventKind.APPLICATION_SAMPLE_WRITTEN:
                    break
            if attempt_index is None or sample_index is None:
                incomplete.add(event_sequence(rotation_index, event.sequence))
                continue

            receive_index = None
            for index in range(rotation_index + 1, len(evidence.events)):
                candidate = evidence.events[index]
                if (
                    candidate.actor == reader
                    and candidate.kind == EventKind.APPLICATION_SAMPLE_RECEIVED
                    and candidate.outcome == "received"
                    and candidate.attributes.get("sample_index") == sample_index
                ):
                    receive_index = index
                    break
            if receive_index is None:
                incomplete.update(
                    {
                        event_sequence(rotation_index, event.sequence),
                        event_sequence(
                            attempt_index, evidence.events[attempt_index].sequence
                        ),
                    }
                )
                continue
            rotation_samples.append((rotation_index, attempt_index, receive_index))

        if invalid_transitions:
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.VIOLATION,
                summary="A session-key rotation did not advance the 32-bit session identifier",
                evidence_events=tuple(
                    event_sequence(index, event.sequence)
                    for index, event in invalid_transitions
                ),
                details={"invalid_transition_count": len(invalid_transitions)},
            )

        if configuration_mismatches or incomplete:
            events = set(incomplete)
            events.update(
                event_sequence(index, event.sequence)
                for index, event in configuration_mismatches
            )
            return OracleResult(
                assertion_id=assertion.assertion_id,
                oracle=self.name,
                status=OracleStatus.NOT_APPLICABLE,
                summary="Session-rotation configuration or delivery evidence was incomplete",
                evidence_events=tuple(sorted(events)),
                details={
                    "configuration_mismatches": len(configuration_mismatches),
                    "rotations_without_delivery": len(rotations) - len(rotation_samples),
                },
            )

        considered = {
            event_sequence(index, evidence.events[index].sequence)
            for triple in rotation_samples
            for index in triple
        }
        return OracleResult(
            assertion_id=assertion.assertion_id,
            oracle=self.name,
            status=OracleStatus.PASS,
            summary="Every observed session-key rotation advanced its session id and delivered its triggering sample",
            evidence_events=tuple(sorted(considered)),
            details={
                "rotation_count": len(rotations),
                "delivered_rotation_samples": len(rotation_samples),
                "context": context,
            },
        )
