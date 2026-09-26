from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from .coverage import partial_order_projection, semantic_state
from .evidence import EvidenceBundle
from .models import EvidenceEvent, EventKind, JsonValue, Scenario


_BOUNDARY_KINDS = {
    EventKind.ACCESS_CONTROL_DECISION,
    EventKind.DECRYPT_CAPABILITY,
    EventKind.FORGE_CAPABILITY,
    EventKind.PROTECTED_MESSAGE_ACCEPTED,
    EventKind.CREDENTIAL_REVOKED,
    EventKind.AUTHORITY_REVOKED,
    EventKind.KEY_ROTATED,
    EventKind.ENDPOINT_DESTROYED,
    EventKind.ENDPOINT_RECREATED,
    EventKind.PARTICIPANT_DISCONNECTED,
    EventKind.PARTICIPANT_RECONNECTED,
    EventKind.TRANSPORT_DATAGRAM_DROPPED,
    EventKind.TRANSPORT_DATAGRAM_DELAYED,
    EventKind.TRANSPORT_DATAGRAM_DUPLICATED,
    EventKind.TRANSPORT_DATAGRAM_CAPTURED,
    EventKind.TRANSPORT_DATAGRAM_REPLAYED,
    EventKind.MEMORY_SAFETY_VIOLATION,
    EventKind.EXECUTION_DIVERGENCE,
}

_STANDALONE_BOUNDARY_KINDS = {
    EventKind.ACCESS_CONTROL_DECISION,
    EventKind.DECRYPT_CAPABILITY,
    EventKind.FORGE_CAPABILITY,
    EventKind.PROTECTED_MESSAGE_ACCEPTED,
    EventKind.MEMORY_SAFETY_VIOLATION,
    EventKind.EXECUTION_DIVERGENCE,
}

CONTEXT_ONLY_ARTIFACT_FAMILIES = frozenset(
    {
        "boundary_episode",
        "baseline_runtime_divergence",
    }
)

DIAGNOSTIC_ARTIFACT_FAMILIES = frozenset(
    {
        "instrumentation_divergence",
        "runtime_memory_diagnostic",
    }
)

_PHASE_BY_KIND = {
    EventKind.CREDENTIAL_AUTHENTICATED: "identity",
    EventKind.CREDENTIAL_REVOKED: "identity",
    EventKind.AUTHORITY_REVOKED: "authorization",
    EventKind.ACCESS_CONTROL_DECISION: "authorization",
    EventKind.CRYPTO_TOKEN_GENERATED: "key_distribution",
    EventKind.CRYPTO_TOKEN_OBSERVED: "key_distribution",
    EventKind.KEY_MATERIAL_OBSERVED: "key_distribution",
    EventKind.KEY_ROTATED: "key_lifecycle",
    EventKind.DECRYPT_CAPABILITY: "cryptographic_capability",
    EventKind.FORGE_CAPABILITY: "cryptographic_capability",
    EventKind.PROTECTED_MESSAGE_ACCEPTED: "cryptographic_capability",
    EventKind.ENDPOINT_CREATED: "endpoint_lifecycle",
    EventKind.ENDPOINT_DESTROYED: "endpoint_lifecycle",
    EventKind.ENDPOINT_RECREATED: "endpoint_lifecycle",
    EventKind.ENDPOINT_MATCHED: "endpoint_lifecycle",
    EventKind.PARTICIPANT_DISCONNECTED: "participant_lifecycle",
    EventKind.PARTICIPANT_RECONNECTED: "participant_lifecycle",
    EventKind.TRANSPORT_FAULT_ARMED: "transport",
    EventKind.TRANSPORT_DATAGRAM_DROPPED: "transport",
    EventKind.TRANSPORT_DATAGRAM_DELAYED: "transport",
    EventKind.TRANSPORT_DATAGRAM_DUPLICATED: "transport",
    EventKind.TRANSPORT_DATAGRAM_CAPTURED: "transport",
    EventKind.TRANSPORT_DATAGRAM_REPLAYED: "transport",
    EventKind.APPLICATION_WRITE_ATTEMPT: "application",
    EventKind.APPLICATION_SAMPLE_WRITTEN: "application",
    EventKind.APPLICATION_SAMPLE_RECEIVED: "application",
    EventKind.APPLICATION_OBSERVATION_WINDOW: "application",
    EventKind.MEMORY_SAFETY_VIOLATION: "runtime_diagnostic",
    EventKind.EXECUTION_DIVERGENCE: "instrumentation",
    EventKind.OBSERVER_ERROR: "instrumentation",
}

def _correlations(event: EvidenceEvent) -> tuple[tuple[str, str], ...]:
    values: list[tuple[str, str]] = []
    for name in ("action_id", "source_action_id"):
        value = event.attributes.get(name)
        if isinstance(value, str) and value:
            values.append(("action", value))
    for name in ("message", "key_fingerprint"):
        value = event.attributes.get(name)
        if isinstance(value, str) and value:
            values.append((name, value))
    return tuple(values)


@dataclass(frozen=True, slots=True)
class RuntimeArtifact:
    artifact_id: str
    fingerprint: str
    family: str
    title: str
    observation_class: str
    outcome: str
    actors: tuple[str, ...]
    resources: tuple[str, ...]
    evidence_events: tuple[int, ...]
    causal_signature: tuple[str, ...]
    boundary_phases: tuple[str, ...]
    boundary_depth: int
    evidence_quality: float
    execution_complete: bool
    observations: Mapping[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "artifact_id": self.artifact_id,
            "fingerprint": self.fingerprint,
            "family": self.family,
            "title": self.title,
            "observation_class": self.observation_class,
            "outcome": self.outcome,
            "actors": list(self.actors),
            "resources": list(self.resources),
            "evidence_events": list(self.evidence_events),
            "causal_signature": list(self.causal_signature),
            "boundary_phases": list(self.boundary_phases),
            "boundary_depth": self.boundary_depth,
            "evidence_quality": self.evidence_quality,
            "execution_complete": self.execution_complete,
            "observations": dict(self.observations),
        }


def is_semantic_artifact(artifact: RuntimeArtifact) -> bool:
    """Return whether an artifact is a domain observation, not trace context.

    Keeping this classification in the artifact model prevents the scheduler,
    confirmation loop, and aggregate report from disagreeing about whether an
    instrumentation failure or a generic differential is a semantic result.
    """

    return (
        artifact.family not in CONTEXT_ONLY_ARTIFACT_FAMILIES
        and artifact.family not in DIAGNOSTIC_ARTIFACT_FAMILIES
    )


def is_diagnostic_artifact(artifact: RuntimeArtifact) -> bool:
    return artifact.family in DIAGNOSTIC_ARTIFACT_FAMILIES


def artifact_class(artifact: RuntimeArtifact) -> str:
    if is_diagnostic_artifact(artifact):
        return "diagnostic"
    if artifact.family in CONTEXT_ONLY_ARTIFACT_FAMILIES:
        return "context"
    return "semantic"


@dataclass(frozen=True, slots=True)
class ArtifactBundle:
    schema_version: int
    scenario_id: str
    scenario_digest: str
    run_id: str
    artifacts: tuple[RuntimeArtifact, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "scenario_digest": self.scenario_digest,
            "run_id": self.run_id,
            "artifact_count": len(self.artifacts),
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }


def write_artifacts(bundle: ArtifactBundle, path: str | Path) -> None:
    artifact_path = Path(path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(
        json.dumps(bundle.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sequence(event: EvidenceEvent, fallback: int) -> int:
    return fallback if event.sequence is None else event.sequence


def _event_token(event: EvidenceEvent) -> str:
    state = semantic_state(event)
    return state.replace("|", ":", 2)


def _execution_complete(scenario: Scenario, evidence: EvidenceBundle) -> bool:
    if evidence.metadata.get("execution_error") is not None:
        return False
    failed = {
        event.actor
        for event in evidence.events
        if (
            event.kind in (EventKind.EXECUTION_DIVERGENCE, EventKind.OBSERVER_ERROR)
            or (event.kind == EventKind.PROCESS_EXIT and event.outcome != "succeeded")
        )
    }
    if failed:
        return False
    if scenario.execution is None:
        return True
    expected = {role.actor for role in scenario.execution.roles}
    exited = {
        event.actor
        for event in evidence.events
        if event.kind == EventKind.PROCESS_EXIT and event.outcome == "succeeded"
    }
    return expected <= exited


def execution_is_complete(scenario: Scenario, evidence: EvidenceBundle) -> bool:
    """Expose the single completeness contract to schedulers and reporters."""

    return _execution_complete(scenario, evidence)


def _phases(events: Iterable[EvidenceEvent]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                phase
                for event in events
                if (phase := _PHASE_BY_KIND.get(event.kind)) is not None
            }
        )
    )


def _causal_slice(
    evidence: EvidenceBundle,
    seeds: Iterable[int],
    *,
    actor_context: int = 1,
) -> tuple[int, ...]:
    """Return a compact evidence slice closed over explicit correlations.

    The slice never treats cross-process log adjacency as causality. It adds a
    bounded amount of actor-local context and every event sharing an explicit
    action, message, or run-local key identifier with a seed event.
    """

    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    by_sequence = {sequence: event for sequence, event in indexed}
    selected = {sequence for sequence in seeds if sequence in by_sequence}
    by_actor: dict[str, list[int]] = defaultdict(list)
    correlations: dict[tuple[str, str], set[int]] = defaultdict(set)
    for sequence, event in indexed:
        by_actor[event.actor].append(sequence)
        for correlation in _correlations(event):
            correlations[correlation].add(sequence)

    changed = True
    while changed:
        changed = False
        for sequence in tuple(selected):
            event = by_sequence[sequence]
            for correlation in _correlations(event):
                for related in correlations[correlation]:
                    if related not in selected:
                        selected.add(related)
                        changed = True
    correlated = tuple(selected)
    for sequence in correlated:
        event = by_sequence[sequence]
        actor_sequences = by_actor[event.actor]
        position = actor_sequences.index(sequence)
        start = max(0, position - actor_context)
        selected.update(actor_sequences[start:position])
    return tuple(sorted(selected))


def _make_artifact(
    *,
    evidence: EvidenceBundle,
    family: str,
    title: str,
    observation_class: str,
    outcome: str,
    actors: Iterable[str],
    resources: Iterable[str],
    seed_events: Iterable[int],
    execution_complete: bool,
    observations: Mapping[str, JsonValue] | None = None,
    signature: Iterable[str] | None = None,
) -> RuntimeArtifact:
    event_sequences = _causal_slice(evidence, seed_events)
    event_map = {
        _sequence(event, index): event for index, event in enumerate(evidence.events)
    }
    sliced_events = [event_map[item] for item in event_sequences if item in event_map]
    causal_signature = tuple(
        signature
        or dict.fromkeys(_event_token(event) for event in sliced_events)
    )
    phases = _phases(sliced_events)
    actor_tuple = tuple(sorted(set(actors)))
    resource_tuple = tuple(sorted(set(resources)))
    identity = {
        "family": family,
        "outcome": outcome,
        "actors": actor_tuple,
        "resources": resource_tuple,
        "causal_signature": causal_signature,
    }
    fingerprint = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    structured = sum(event.source is not None for event in sliced_events)
    structure_ratio = structured / len(sliced_events) if sliced_events else 0.0
    quality = 0.55 + 0.25 * structure_ratio + (0.2 if execution_complete else 0.0)
    return RuntimeArtifact(
        artifact_id=f"DDSLEUTH-ART-{family.upper().replace('_', '-')[:24]}-{fingerprint[:12]}",
        fingerprint=fingerprint,
        family=family,
        title=title,
        observation_class=observation_class,
        outcome=outcome,
        actors=actor_tuple,
        resources=resource_tuple,
        evidence_events=event_sequences,
        causal_signature=causal_signature,
        boundary_phases=phases,
        boundary_depth=len(phases),
        evidence_quality=round(min(1.0, quality), 3),
        execution_complete=execution_complete,
        observations=dict(observations or {}),
    )


def _boundary_episodes(
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    by_actor: dict[str, list[tuple[int, EvidenceEvent]]] = defaultdict(list)
    for item in indexed:
        by_actor[item[1].actor].append(item)

    artifacts: list[RuntimeArtifact] = []
    for sequence, trigger in indexed:
        if trigger.kind not in _BOUNDARY_KINDS:
            continue
        actor_tail = [
            (candidate_sequence, event)
            for candidate_sequence, event in by_actor[trigger.actor]
            if candidate_sequence >= sequence
            and event.kind not in (EventKind.ACTION_STARTED, EventKind.ACTION_COMPLETED)
        ][:5]
        seeds = [item[0] for item in actor_tail]
        if not seeds:
            continue
        phases = _phases(item[1] for item in actor_tail)
        if len(phases) < 2 and trigger.kind not in _STANDALONE_BOUNDARY_KINDS:
            continue
        resources = {
            value
            for _, event in actor_tail
            for name in ("topic", "resource")
            if isinstance((value := event.attributes.get(name)), str)
        }
        artifacts.append(
            _make_artifact(
                evidence=evidence,
                family="boundary_episode",
                title=f"Runtime behavior crossed {trigger.kind}",
                observation_class="boundary_trace",
                outcome=trigger.outcome,
                actors=(trigger.actor,),
                resources=resources,
                seed_events=seeds,
                execution_complete=execution_complete,
                observations={
                    "trigger_kind": trigger.kind,
                    "trigger_outcome": trigger.outcome,
                    "actor_local_events": len(actor_tail),
                },
            )
        )
    return artifacts


def _revocation_artifacts(
    scenario: Scenario,
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    artifacts: list[RuntimeArtifact] = []
    for revoked_sequence, revoked in indexed:
        if not (
            revoked.kind == EventKind.CREDENTIAL_REVOKED
            and revoked.outcome == "revoked"
            and revoked.attributes.get("local_identity") is True
        ):
            continue
        writes = [
            (sequence, event)
            for sequence, event in indexed
            if sequence > revoked_sequence
            and event.actor == revoked.actor
            and event.kind == EventKind.APPLICATION_SAMPLE_WRITTEN
            and event.outcome == "succeeded"
        ]
        for write_sequence, write in writes:
            message = write.attributes.get("message")
            deliveries = [
                (sequence, event)
                for sequence, event in indexed
                if sequence > write_sequence
                and event.kind == EventKind.APPLICATION_SAMPLE_RECEIVED
                and event.outcome == "received"
                and isinstance(message, str)
                and event.attributes.get("message") == message
            ]
            windows = [
                (sequence, event)
                for sequence, event in indexed
                if sequence > write_sequence
                and event.kind == EventKind.APPLICATION_OBSERVATION_WINDOW
            ]
            if not deliveries and not windows:
                continue
            topic = write.attributes.get("topic")
            resources = (topic,) if isinstance(topic, str) else tuple(scenario.topics)
            if deliveries:
                family = "post_revocation_delivery_observed"
                title = "Application delivery followed local credential revocation"
                outcome = "delivered"
                terminal = deliveries
            else:
                family = "split_enforcement_after_revocation"
                title = "Local write acceptance diverged from remote delivery after revocation"
                outcome = "locally_accepted_remotely_suppressed"
                terminal = windows
            artifacts.append(
                _make_artifact(
                    evidence=evidence,
                    family=family,
                    title=title,
                    observation_class="boundary_behavior",
                    outcome=outcome,
                    actors=(revoked.actor, *(event.actor for _, event in terminal)),
                    resources=resources,
                    seed_events=(
                        revoked_sequence,
                        write_sequence,
                        *(sequence for sequence, _ in terminal),
                    ),
                    execution_complete=execution_complete,
                    observations={
                        "write_result": write.outcome,
                        "remote_delivery_count": len(deliveries),
                        "observation_window_count": len(windows),
                    },
                    signature=(
                        f"credential.revoked:{revoked.actor}:local",
                        f"application.write:{revoked.actor}:{write.outcome}",
                        f"application.delivery:{outcome}",
                    ),
                )
            )
    return artifacts


def _replay_artifacts(
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    artifacts: list[RuntimeArtifact] = []
    deliveries: dict[tuple[str, str, int, str], list[int]] = defaultdict(list)
    for sequence, event in indexed:
        topic = event.attributes.get("topic")
        sample_index = event.attributes.get("sample_index")
        message = event.attributes.get("message")
        if (
            event.kind == EventKind.APPLICATION_SAMPLE_RECEIVED
            and event.outcome == "received"
            and isinstance(topic, str)
            and isinstance(sample_index, int)
            and isinstance(message, str)
        ):
            deliveries[(event.actor, topic, sample_index, message)].append(sequence)

    for replay_sequence, replay in indexed:
        if not (
            replay.kind == EventKind.TRANSPORT_DATAGRAM_REPLAYED
            and replay.outcome == "replayed"
        ):
            continue
        duplicated = [
            (key, sequences)
            for key, sequences in deliveries.items()
            if len(sequences) > 1
            and min(sequences) < replay_sequence < max(sequences)
        ]
        windows = [
            (sequence, event)
            for sequence, event in indexed
            if sequence > replay_sequence
            and event.kind == EventKind.APPLICATION_OBSERVATION_WINDOW
        ]
        if duplicated:
            family = "replay_redelivery_observed"
            title = "A replayed wire datagram coincided with repeated application delivery"
            outcome = "redelivered"
            seed_events = [replay_sequence]
            actors = {replay.actor}
            resources: set[str] = set()
            for (actor, topic, _, _), sequences in duplicated:
                actors.add(actor)
                resources.add(topic)
                seed_events.extend(sequences)
        elif windows:
            family = "replay_suppression_observed"
            title = "An exact wire replay produced no repeated application delivery"
            outcome = "suppressed"
            seed_events = [replay_sequence, *(sequence for sequence, _ in windows)]
            actors = {replay.actor, *(event.actor for _, event in windows)}
            resources = {
                value
                for _, event in indexed
                if event.kind in (
                    EventKind.APPLICATION_SAMPLE_WRITTEN,
                    EventKind.APPLICATION_SAMPLE_RECEIVED,
                )
                and isinstance((value := event.attributes.get("topic")), str)
            }
        else:
            continue
        artifacts.append(
            _make_artifact(
                evidence=evidence,
                family=family,
                title=title,
                observation_class="boundary_behavior",
                outcome=outcome,
                actors=actors,
                resources=resources,
                seed_events=seed_events,
                execution_complete=execution_complete,
                observations={
                    "replayed_bytes": replay.attributes.get("bytes"),
                    "source_capture_action": replay.attributes.get("source_action_id"),
                    "duplicate_sample_groups": len(duplicated),
                    "observation_window_count": len(windows),
                },
                signature=(
                    f"transport.replay:{replay.actor}",
                    f"application.delivery:{outcome}",
                ),
            )
        )
    return artifacts


def _key_epoch_artifacts(
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    artifacts: list[RuntimeArtifact] = []
    for reconnect_sequence, reconnect in indexed:
        if reconnect.kind != EventKind.PARTICIPANT_RECONNECTED:
            continue
        disconnects = [
            sequence
            for sequence, event in indexed
            if event.actor == reconnect.actor
            and event.kind == EventKind.PARTICIPANT_DISCONNECTED
            and sequence < reconnect_sequence
        ]
        if not disconnects:
            continue
        disconnect_sequence = max(disconnects)
        relevant_keys = [
            (sequence, event)
            for sequence, event in indexed
            if event.actor == reconnect.actor
            and event.kind == EventKind.KEY_MATERIAL_OBSERVED
            and event.outcome == "observed"
            and event.attributes.get("endpoint_class") == "user"
            and event.attributes.get("observation_phase") == "generated"
            and isinstance(event.attributes.get("key_fingerprint"), str)
        ]
        before = {
            str(event.attributes["key_fingerprint"])
            for sequence, event in relevant_keys
            if sequence < disconnect_sequence
        }
        after = {
            str(event.attributes["key_fingerprint"])
            for sequence, event in relevant_keys
            if sequence > reconnect_sequence
        }
        if not before and not after:
            continue
        shared = before & after
        outcome = "reused" if shared else "fresh" if before and after else "partially_observed"
        artifacts.append(
            _make_artifact(
                evidence=evidence,
                family="participant_key_epoch_transition",
                title="Participant reconnect changed the observed user-key epoch",
                observation_class="boundary_behavior",
                outcome=outcome,
                actors=(reconnect.actor,),
                resources=(),
                seed_events=(
                    disconnect_sequence,
                    reconnect_sequence,
                    *(sequence for sequence, _ in relevant_keys),
                ),
                execution_complete=execution_complete,
                observations={
                    "pre_reconnect_key_count": len(before),
                    "post_reconnect_key_count": len(after),
                    "shared_key_count": len(shared),
                },
                signature=(
                    f"participant.disconnect:{reconnect.actor}",
                    f"participant.reconnect:{reconnect.actor}",
                    f"user_key_epoch:{outcome}",
                ),
            )
        )
    return artifacts


def _key_recipient_artifacts(
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    """Describe the observed distribution topology without exporting key values."""

    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    by_fingerprint: dict[str, list[tuple[int, EvidenceEvent]]] = defaultdict(list)
    for sequence, event in indexed:
        fingerprint = event.attributes.get("key_fingerprint")
        if (
            event.kind == EventKind.KEY_MATERIAL_OBSERVED
            and event.outcome == "observed"
            and event.attributes.get("endpoint_class") == "user"
            and isinstance(fingerprint, str)
        ):
            by_fingerprint[fingerprint].append((sequence, event))

    artifacts: list[RuntimeArtifact] = []
    for members in by_fingerprint.values():
        generated = [item for item in members if item[1].attributes.get("observation_phase") == "generated"]
        received = [item for item in members if item[1].attributes.get("observation_phase") == "received"]
        if not generated:
            continue
        generators = {event.actor for _, event in generated}
        recipients = {event.actor for _, event in received}
        if not recipients:
            outcome = "no_received_observation"
        elif len(recipients) == 1:
            outcome = "single_recipient"
        else:
            outcome = "multiple_recipients"
        shape = {
            (
                str(event.attributes.get("token_class", "unknown")),
                str(event.attributes.get("key_class", "unknown")),
                str(event.attributes.get("material_semantics", "unknown")),
            )
            for _, event in members
        }
        artifacts.append(
            _make_artifact(
                evidence=evidence,
                family="key_recipient_topology",
                title="Observed user-key material followed a recipient topology",
                observation_class="boundary_topology",
                outcome=outcome,
                actors=generators | recipients,
                resources=(),
                seed_events=(sequence for sequence, _ in members),
                execution_complete=execution_complete,
                observations={
                    "generator_count": len(generators),
                    "recipient_count": len(recipients),
                    "key_shape_count": len(shape),
                },
                signature=(
                    f"key_topology:generators={len(generators)}",
                    f"key_topology:recipients={len(recipients)}",
                    *(f"key_shape:{':'.join(item)}" for item in sorted(shape)),
                ),
            )
        )
    return artifacts


def _identity_binding_artifacts(
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    authenticated = [
        (sequence, event)
        for sequence, event in indexed
        if event.kind == EventKind.CREDENTIAL_AUTHENTICATED
        and isinstance(event.attributes.get("participant_guid"), str)
    ]
    guid_actors: dict[str, set[str]] = defaultdict(set)
    actor_guids: dict[str, set[str]] = defaultdict(set)
    actor_sequences: dict[str, list[int]] = defaultdict(list)
    for sequence, event in authenticated:
        guid = str(event.attributes["participant_guid"])
        guid_actors[guid].add(event.actor)
        actor_guids[event.actor].add(guid)
        actor_sequences[event.actor].append(sequence)

    artifacts: list[RuntimeArtifact] = []
    collided_actors: set[str] = set()
    for actors in guid_actors.values():
        if len(actors) > 1:
            collided_actors.update(actors)
    if collided_actors:
        seeds = [
            sequence
            for sequence, event in authenticated
            if event.actor in collided_actors
        ]
        artifacts.append(
            _make_artifact(
                evidence=evidence,
                family="identity_guid_binding",
                title="One observed participant identity was associated with multiple actors",
                observation_class="boundary_binding",
                outcome="cross_actor_binding",
                actors=collided_actors,
                resources=(),
                seed_events=seeds,
                execution_complete=execution_complete,
                observations={
                    "colliding_guid_count": sum(len(actors) > 1 for actors in guid_actors.values()),
                    "actor_count": len(collided_actors),
                },
                signature=(
                    "identity_binding:cross_actor",
                    *(f"actor:{actor}" for actor in sorted(collided_actors)),
                ),
            )
        )
    for actor, guids in actor_guids.items():
        if len(guids) <= 1:
            continue
        reconnects = [
            sequence
            for sequence, event in indexed
            if event.actor == actor and event.kind == EventKind.PARTICIPANT_RECONNECTED
        ]
        outcome = "rebound_after_reconnect" if reconnects else "multiple_bindings_observed"
        artifacts.append(
            _make_artifact(
                evidence=evidence,
                family="identity_guid_binding",
                title="An actor was observed with multiple participant identity epochs",
                observation_class="boundary_binding",
                outcome=outcome,
                actors=(actor,),
                resources=(),
                seed_events=(*actor_sequences[actor], *reconnects),
                execution_complete=execution_complete,
                observations={"observed_guid_count": len(guids)},
                signature=(f"identity_binding:{actor}:{outcome}",),
            )
        )
    return artifacts


def _post_revocation_capability_artifacts(
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    capability_kinds = {
        EventKind.DECRYPT_CAPABILITY,
        EventKind.FORGE_CAPABILITY,
        EventKind.PROTECTED_MESSAGE_ACCEPTED,
    }
    artifacts: list[RuntimeArtifact] = []
    for revoked_sequence, revoked in indexed:
        if revoked.kind not in (EventKind.CREDENTIAL_REVOKED, EventKind.AUTHORITY_REVOKED):
            continue
        observed = [
            (sequence, event)
            for sequence, event in indexed
            if sequence > revoked_sequence
            and event.actor == revoked.actor
            and event.kind in capability_kinds
        ]
        if not observed:
            continue
        kinds = sorted({str(event.kind) for _, event in observed})
        artifacts.append(
            _make_artifact(
                evidence=evidence,
                family="post_revocation_capability",
                title="A cryptographic capability was observed after a revocation boundary",
                observation_class="boundary_capability",
                outcome="observed_after_revocation",
                actors=(revoked.actor,),
                resources=(),
                seed_events=(revoked_sequence, *(sequence for sequence, _ in observed)),
                execution_complete=execution_complete,
                observations={
                    "revocation_kind": str(revoked.kind),
                    "capability_event_count": len(observed),
                    "capability_kinds": kinds,
                },
                signature=(
                    f"revocation:{revoked.kind}:{revoked.actor}",
                    *(f"post_revocation:{kind}" for kind in kinds),
                ),
            )
        )
    return artifacts


def _delivery_cardinality_artifacts(
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    indexed = [(_sequence(event, index), event) for index, event in enumerate(evidence.events)]
    artifacts: list[RuntimeArtifact] = []
    for sequence, event in indexed:
        if event.kind != EventKind.APPLICATION_OBSERVATION_WINDOW:
            continue
        expected = event.attributes.get("expected_samples")
        observed = event.attributes.get("observed_samples")
        if not isinstance(expected, int) or not isinstance(observed, int):
            continue
        outcome = "exact" if observed == expected else "missing" if observed < expected else "excess"
        related = [
            candidate_sequence
            for candidate_sequence, candidate in indexed
            if candidate_sequence <= sequence
            and candidate.kind in (
                EventKind.APPLICATION_SAMPLE_WRITTEN,
                EventKind.APPLICATION_SAMPLE_RECEIVED,
                EventKind.TRANSPORT_DATAGRAM_REPLAYED,
                EventKind.CREDENTIAL_REVOKED,
            )
        ][-8:]
        topic = event.attributes.get("topic")
        artifacts.append(
            _make_artifact(
                evidence=evidence,
                family="delivery_cardinality",
                title="An observation window measured application delivery cardinality",
                observation_class="boundary_cardinality",
                outcome=outcome,
                actors=(event.actor,),
                resources=(topic,) if isinstance(topic, str) else (),
                seed_events=(*related, sequence),
                execution_complete=execution_complete,
                observations={
                    "expected_bucket": "zero" if expected == 0 else "one" if expected == 1 else "many",
                    "observed_bucket": "zero" if observed == 0 else "one" if observed == 1 else "many",
                    "delta_sign": 0 if observed == expected else -1 if observed < expected else 1,
                },
                signature=(
                    f"delivery_cardinality:{event.actor}:{outcome}",
                    f"expected:{'zero' if expected == 0 else 'one' if expected == 1 else 'many'}",
                    f"observed:{'zero' if observed == 0 else 'one' if observed == 1 else 'many'}",
                ),
            )
        )
    return artifacts


def _diagnostic_artifacts(
    evidence: EvidenceBundle,
    execution_complete: bool,
) -> list[RuntimeArtifact]:
    artifacts: list[RuntimeArtifact] = []
    for index, event in enumerate(evidence.events):
        sequence = _sequence(event, index)
        if event.kind == EventKind.MEMORY_SAFETY_VIOLATION:
            sanitizer = event.attributes.get("sanitizer", "unknown")
            violation = event.attributes.get("violation", "unknown")
            artifacts.append(
                _make_artifact(
                    evidence=evidence,
                    family="runtime_memory_diagnostic",
                    title=f"{sanitizer} reported {violation}",
                    observation_class="runtime_diagnostic",
                    outcome="detected",
                    actors=(event.actor,),
                    resources=(),
                    seed_events=(sequence,),
                    execution_complete=execution_complete,
                    observations={"sanitizer": sanitizer, "diagnostic": violation},
                    signature=(
                        f"memory_safety:{event.actor}:{sanitizer}:{violation}",
                    ),
                )
            )
        elif event.kind in (EventKind.EXECUTION_DIVERGENCE, EventKind.OBSERVER_ERROR):
            artifacts.append(
                _make_artifact(
                    evidence=evidence,
                    family="instrumentation_divergence",
                    title="Execution or observation diverged from the requested experiment",
                    observation_class="instrumentation_diagnostic",
                    outcome=event.outcome,
                    actors=(event.actor,),
                    resources=(),
                    seed_events=(sequence,),
                    execution_complete=False,
                    observations={"event_kind": event.kind},
                    signature=(f"instrumentation:{event.actor}:{event.kind}:{event.outcome}",),
                )
            )
    return artifacts


def discover_artifacts(
    scenario: Scenario,
    evidence: EvidenceBundle,
) -> ArtifactBundle:
    """Extract neutral, replayable runtime observations.

    This function deliberately does not assign vulnerability severity or claim
    exploitability. It records what crossed a runtime boundary and the compact
    causal evidence needed by a later researcher or analysis model.
    """

    complete = _execution_complete(scenario, evidence)
    discovered = [
        *_revocation_artifacts(scenario, evidence, complete),
        *_replay_artifacts(evidence, complete),
        *_key_epoch_artifacts(evidence, complete),
        *_key_recipient_artifacts(evidence, complete),
        *_identity_binding_artifacts(evidence, complete),
        *_post_revocation_capability_artifacts(evidence, complete),
        *_delivery_cardinality_artifacts(evidence, complete),
        *_diagnostic_artifacts(evidence, complete),
        *_boundary_episodes(evidence, complete),
    ]
    unique: dict[str, RuntimeArtifact] = {}
    for artifact in discovered:
        unique.setdefault(artifact.fingerprint, artifact)
    ordered = tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                -item.boundary_depth,
                -item.evidence_quality,
                item.family,
                item.artifact_id,
            ),
        )
    )
    return ArtifactBundle(
        schema_version=1,
        scenario_id=scenario.scenario_id,
        scenario_digest=scenario.digest,
        run_id=evidence.run_id,
        artifacts=ordered,
    )


def discover_matched_semantic_differential_artifacts(
    baseline_scenario: Scenario,
    baselines: Iterable[EvidenceBundle],
    current_scenario: Scenario,
    current: EvidenceBundle,
) -> tuple[RuntimeArtifact, ...]:
    """Describe stable semantic control outcomes removed by a mutation.

    Added outcomes are already represented by their native artifact family.
    This complementary projection makes disappearance and replacement first-
    class results instead of burying them in a generic trace differential.
    """

    baseline_bundles = tuple(baselines)
    if not baseline_bundles or not _execution_complete(current_scenario, current):
        return ()
    baseline_artifacts: list[tuple[RuntimeArtifact, ...]] = []
    for bundle in baseline_bundles:
        if not _execution_complete(baseline_scenario, bundle):
            continue
        baseline_artifacts.append(
            tuple(
                artifact
                for artifact in discover_artifacts(baseline_scenario, bundle).artifacts
                if artifact.execution_complete and is_semantic_artifact(artifact)
            )
        )
    if not baseline_artifacts:
        return ()

    support = Counter(
        artifact.fingerprint
        for artifacts in baseline_artifacts
        for artifact in artifacts
    )
    exemplars = {
        artifact.fingerprint: artifact
        for artifacts in baseline_artifacts
        for artifact in artifacts
    }
    stable_threshold = len(baseline_artifacts) // 2 + 1
    stable = {
        fingerprint
        for fingerprint, count in support.items()
        if count >= stable_threshold
    }
    current_semantic = tuple(
        artifact
        for artifact in discover_artifacts(current_scenario, current).artifacts
        if artifact.execution_complete and is_semantic_artifact(artifact)
    )
    current_fingerprints = {artifact.fingerprint for artifact in current_semantic}
    removed = sorted(stable - current_fingerprints)
    if not removed:
        return ()

    indexed = [(_sequence(event, index), event) for index, event in enumerate(current.events)]
    discovered: list[RuntimeArtifact] = []
    for fingerprint in removed:
        baseline = exemplars[fingerprint]
        replacements = sorted(
            {
                artifact.outcome
                for artifact in current_semantic
                if artifact.family == baseline.family
            }
        )
        mutation_outcome = ",".join(replacements) if replacements else "absent"
        relevant = [
            sequence
            for sequence, event in indexed
            if event.actor in baseline.actors
            and (
                event.kind in _BOUNDARY_KINDS
                or event.kind
                in {
                    EventKind.APPLICATION_SAMPLE_WRITTEN,
                    EventKind.APPLICATION_SAMPLE_RECEIVED,
                    EventKind.APPLICATION_OBSERVATION_WINDOW,
                    EventKind.KEY_MATERIAL_OBSERVED,
                    EventKind.PROCESS_EXIT,
                }
            )
        ][-12:]
        discovered.append(
            _make_artifact(
                evidence=current,
                family="semantic_outcome_transition",
                title="A stable control outcome changed under a causal mutation",
                observation_class="matched_semantic_differential",
                outcome=(
                    "replaced_under_mutation" if replacements else "absent_under_mutation"
                ),
                actors=baseline.actors,
                resources=baseline.resources,
                seed_events=relevant,
                execution_complete=True,
                observations={
                    "baseline_family": baseline.family,
                    "baseline_outcome": baseline.outcome,
                    "mutation_outcome": mutation_outcome,
                    "baseline_support": support[fingerprint],
                    "baseline_sample_count": len(baseline_artifacts),
                    "control_quality": (
                        "replicated" if len(baseline_artifacts) >= 3 else "limited"
                    ),
                },
                signature=(
                    f"semantic_delta:{baseline.family}",
                    f"baseline:{baseline.outcome}",
                    f"mutation:{mutation_outcome}",
                ),
            )
        )
    unique = {artifact.fingerprint: artifact for artifact in discovered}
    return tuple(unique[fingerprint] for fingerprint in sorted(unique))


def behavior_projection(evidence: EvidenceBundle) -> Mapping[str, int]:
    """Create a partial-order projection for differential discovery."""

    return partial_order_projection(evidence)


def discover_matched_differential_artifacts(
    _baseline_scenario: Scenario,
    baselines: Iterable[EvidenceBundle],
    current_scenario: Scenario,
    current: EvidenceBundle,
) -> tuple[RuntimeArtifact, ...]:
    """Compare a mutation with replicated controls and suppress control noise."""

    baseline_projections = [behavior_projection(item) for item in baselines]
    if not baseline_projections:
        return ()
    all_baseline_keys = set().union(*(set(item) for item in baseline_projections))
    modal_baseline: dict[str, int] = {}
    noisy: set[str] = set()
    for key in all_baseline_keys:
        values = [item.get(key, 0) for item in baseline_projections]
        counts = Counter(values)
        modal_baseline[key] = counts.most_common(1)[0][0]
        if len(counts) > 1:
            noisy.add(key)

    current_projection = behavior_projection(current)
    keys = set(modal_baseline) | set(current_projection)
    changed = sorted(
        key
        for key in keys
        if key not in noisy and modal_baseline.get(key, 0) != current_projection.get(key, 0)
    )
    if not changed:
        return ()
    added = [key for key in changed if modal_baseline.get(key, 0) == 0]
    removed = [key for key in changed if current_projection.get(key, 0) == 0]
    count_changed = [
        key
        for key in changed
        if modal_baseline.get(key, 0) and current_projection.get(key, 0)
    ]
    event_sequences = [
        _sequence(event, index)
        for index, event in enumerate(current.events)
        if f"state:{semantic_state(event)}" in changed or event.kind in _BOUNDARY_KINDS
    ]
    digest_input = json.dumps(
        {"baseline_mode": modal_baseline, "current": current_projection},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    artifact = _make_artifact(
        evidence=current,
        family="baseline_runtime_divergence",
        title="A mutation changed the partial-order runtime projection beyond control noise",
        observation_class="baseline_differential",
        outcome="different",
        actors={event.actor for event in current.events},
        resources=tuple(current_scenario.topics),
        seed_events=event_sequences,
        execution_complete=_execution_complete(current_scenario, current),
        observations={
            "baseline_sample_count": len(baseline_projections),
            "baseline_noise_feature_count": len(noisy),
            "effect_feature_count": len(changed),
            "control_quality": "replicated" if len(baseline_projections) >= 3 else "limited",
            "added_feature_count": len(added),
            "removed_feature_count": len(removed),
            "count_changed_feature_count": len(count_changed),
            "added_features": added[:64],
            "removed_features": removed[:64],
            "count_changed_features": count_changed[:64],
            "projection_pair_sha256": hashlib.sha256(digest_input).hexdigest(),
        },
        signature=(
            "partial_order_runtime_projection",
            *(f"added:{item}" for item in added[:16]),
            *(f"removed:{item}" for item in removed[:16]),
            *(f"count_changed:{item}" for item in count_changed[:16]),
        ),
    )
    return (artifact,)


def discover_differential_artifacts(
    _baseline_scenario: Scenario,
    baseline: EvidenceBundle,
    current_scenario: Scenario,
    current: EvidenceBundle,
) -> tuple[RuntimeArtifact, ...]:
    """Describe runtime differences without deciding whether either side is vulnerable."""

    return discover_matched_differential_artifacts(
        _baseline_scenario,
        (baseline,),
        current_scenario,
        current,
    )
