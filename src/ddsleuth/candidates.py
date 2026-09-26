from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from .evidence import EvidenceBundle
from .models import EventKind, JsonValue, Scenario
from .oracles.evaluate import EvaluationReport
from .semantics import actor_has_any_permission, event_resource, is_permitted


@dataclass(frozen=True, slots=True)
class DiscoveryCandidate:
    candidate_id: str
    fingerprint: str
    family: str
    title: str
    risk_tier: str
    score: int
    confidence: float
    actors: tuple[str, ...]
    resources: tuple[str, ...]
    evidence_events: tuple[int, ...]
    signals: tuple[str, ...]
    execution_complete: bool
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "candidate_id": self.candidate_id,
            "fingerprint": self.fingerprint,
            "family": self.family,
            "title": self.title,
            "risk_tier": self.risk_tier,
            "score": self.score,
            "confidence": self.confidence,
            "actors": list(self.actors),
            "resources": list(self.resources),
            "evidence_events": list(self.evidence_events),
            "signals": list(self.signals),
            "execution_complete": self.execution_complete,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class CandidateBundle:
    schema_version: int
    scenario_id: str
    scenario_digest: str
    run_id: str
    candidates: tuple[DiscoveryCandidate, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "scenario_digest": self.scenario_digest,
            "run_id": self.run_id,
            "candidate_count": len(self.candidates),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


def write_candidates(bundle: CandidateBundle, path: str | Path) -> None:
    candidate_path = Path(path)
    candidate_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_path.write_text(
        json.dumps(bundle.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _identity(
    family: str,
    actors: Iterable[str],
    resources: Iterable[str],
    discriminator: Mapping[str, JsonValue] | None = None,
) -> tuple[str, str]:
    normalized = {
        "family": family,
        "actors": sorted(set(actors)),
        "resources": sorted(set(resources)),
        "discriminator": dict(discriminator or {}),
    }
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    fingerprint = hashlib.sha256(encoded).hexdigest()
    readable = family.upper().replace("_", "-")[:28]
    return f"DDSLEUTH-{readable}-{fingerprint[:12]}", fingerprint


def _candidate(
    *,
    family: str,
    title: str,
    risk_tier: str,
    score: int,
    confidence: float,
    actors: Iterable[str],
    resources: Iterable[str],
    evidence_events: Iterable[int],
    signals: Iterable[str],
    execution_complete: bool,
    discriminator: Mapping[str, JsonValue] | None = None,
    details: Mapping[str, JsonValue] | None = None,
    penalize_incomplete: bool = True,
) -> DiscoveryCandidate:
    actor_tuple = tuple(sorted(set(actors)))
    resource_tuple = tuple(sorted(set(resources)))
    candidate_id, fingerprint = _identity(
        family,
        actor_tuple,
        resource_tuple,
        discriminator,
    )
    # An interrupted schedule is still a discovery signal, but it must not be
    # ranked as highly as the same semantic divergence in a complete run.
    adjusted_confidence = (
        confidence
        if execution_complete or not penalize_incomplete
        else max(0.1, confidence - 0.15)
    )
    return DiscoveryCandidate(
        candidate_id=candidate_id,
        fingerprint=fingerprint,
        family=family,
        title=title,
        risk_tier=risk_tier,
        score=max(
            0,
            min(100, score - (8 if not execution_complete and penalize_incomplete else 0)),
        ),
        confidence=round(adjusted_confidence, 3),
        actors=actor_tuple,
        resources=resource_tuple,
        evidence_events=tuple(sorted(set(evidence_events))),
        signals=tuple(dict.fromkeys(signals)),
        execution_complete=execution_complete,
        details=dict(details or {}),
    )


def discover_candidates(
    scenario: Scenario,
    evidence: EvidenceBundle,
    report: EvaluationReport,
) -> CandidateBundle:
    """Extract security leads without requiring a successful full execution.

    Oracles answer whether a declared invariant was proved or contradicted.
    Candidates retain runtime divergences worth investigating, including those
    observed immediately before a role exits or a later barrier cannot be met.
    """

    execution_complete = not report.failed_processes and not report.incomplete_processes
    candidates: list[DiscoveryCandidate] = []
    overgrants: dict[str, list[tuple[int, str, str]]] = {}
    unauthorized_user_keys: dict[tuple[str, str, str | None], list[int]] = {}
    unauthorized_deliveries: dict[tuple[str, str], list[int]] = {}
    local_revocations: dict[str, int] = {}
    writes_after_revocation: dict[str, list[tuple[int, str | None]]] = defaultdict(list)
    received_messages: dict[str, list[tuple[int, str]]] = defaultdict(list)
    received_samples: dict[tuple[str, str, int, str], list[int]] = defaultdict(list)
    replay_events: list[int] = []
    memory_safety_events: list[tuple[int, str, str, str]] = []
    applied_transport_faults: list[int] = []

    for index, event in enumerate(evidence.events):
        sequence = index if event.sequence is None else event.sequence
        if (
            event.kind == EventKind.CREDENTIAL_REVOKED
            and event.outcome == "revoked"
            and event.attributes.get("local_identity") is True
        ):
            local_revocations.setdefault(event.actor, sequence)

        if event.kind == EventKind.APPLICATION_SAMPLE_WRITTEN and event.actor in local_revocations:
            if sequence > local_revocations[event.actor]:
                message = event.attributes.get("message")
                writes_after_revocation[event.actor].append(
                    (sequence, message if isinstance(message, str) else None)
                )

        if event.kind == EventKind.ACCESS_CONTROL_DECISION and event.outcome == "allowed":
            operation = event.attributes.get("operation")
            resource = event.attributes.get("resource")
            if (
                isinstance(operation, str)
                and isinstance(resource, str)
                and not is_permitted(scenario, event.actor, operation, resource)
            ):
                overgrants.setdefault(event.actor, []).append((sequence, operation, resource))

        if (
            event.kind == EventKind.KEY_MATERIAL_OBSERVED
            and event.outcome == "observed"
            and event.attributes.get("observation_phase") == "received"
            and event.attributes.get("endpoint_class") == "user"
        ):
            # A local reader receives a remote datawriter token and therefore
            # needs subscribe authority.  Conversely, a local writer receives
            # a remote datareader token as part of the normal protected
            # writer/reader pairing and needs publish authority.  Treating all
            # received user keys as subscribe-capable creates a false positive
            # for every legitimate protected writer.
            token_class = event.attributes.get("token_class")
            required_operation = {
                "datawriter": "subscribe",
                "datareader": "publish",
            }.get(token_class)
            if required_operation is not None:
                resource = event_resource(
                    scenario,
                    event,
                    operation=required_operation,
                )
                permitted = (
                    is_permitted(scenario, event.actor, required_operation, resource)
                    if resource is not None
                    else actor_has_any_permission(
                        scenario,
                        event.actor,
                        required_operation,
                    )
                )
                if not permitted:
                    unauthorized_user_keys.setdefault(
                        (event.actor, required_operation, resource), []
                    ).append(sequence)

        if event.kind == EventKind.APPLICATION_SAMPLE_RECEIVED and event.outcome == "received":
            message = event.attributes.get("message")
            if isinstance(message, str):
                received_messages[message].append((sequence, event.actor))
                topic = event.attributes.get("topic")
                sample_index = event.attributes.get("sample_index")
                if isinstance(topic, str) and isinstance(sample_index, int):
                    received_samples[(event.actor, topic, sample_index, message)].append(sequence)
            resource = event_resource(scenario, event, operation="subscribe")
            if resource is not None and not is_permitted(
                scenario, event.actor, "subscribe", resource
            ):
                unauthorized_deliveries.setdefault((event.actor, resource), []).append(sequence)

        if (
            event.kind == EventKind.TRANSPORT_DATAGRAM_REPLAYED
            and event.outcome == "replayed"
        ):
            replay_events.append(sequence)

        if event.kind in (
            EventKind.TRANSPORT_DATAGRAM_DROPPED,
            EventKind.TRANSPORT_DATAGRAM_DELAYED,
            EventKind.TRANSPORT_DATAGRAM_DUPLICATED,
            EventKind.TRANSPORT_DATAGRAM_CAPTURED,
            EventKind.TRANSPORT_DATAGRAM_REPLAYED,
        ) and event.outcome not in ("failed", "not_applied"):
            applied_transport_faults.append(sequence)

        if (
            event.kind == EventKind.MEMORY_SAFETY_VIOLATION
            and event.outcome == "detected"
        ):
            sanitizer = event.attributes.get("sanitizer")
            violation = event.attributes.get("violation")
            if isinstance(sanitizer, str) and isinstance(violation, str):
                memory_safety_events.append((sequence, event.actor, sanitizer, violation))

    for sequence, actor, sanitizer, violation in memory_safety_events:
        stronger = any(
            marker in violation
            for marker in (
                "use-after-free",
                "buffer-overflow",
                "double-free",
                "container-overflow",
                "use-after-return",
            )
        )
        related_faults = [item for item in applied_transport_faults if item < sequence]
        signals = ["sanitizer_detected", "native_memory_safety_failure"]
        if related_faults:
            signals.append("applied_transport_mutation_preceded_failure")
        candidates.append(
            _candidate(
                family="sanitizer_memory_safety_failure",
                title=f"{sanitizer} sanitizer detected {violation} in {actor}",
                risk_tier="high_lead",
                score=96 if stronger else 90,
                confidence=0.99,
                actors=(actor,),
                resources=tuple(scenario.topics),
                evidence_events=(*related_faults, sequence),
                signals=signals,
                execution_complete=execution_complete,
                discriminator={
                    "actor": actor,
                    "sanitizer": sanitizer,
                    "violation": violation,
                },
                details={
                    "sanitizer": sanitizer,
                    "violation": violation,
                    "applied_transport_fault_count": len(related_faults),
                },
                penalize_incomplete=False,
            )
        )

    for (actor, topic, sample_index, message), deliveries in received_samples.items():
        if len(deliveries) < 2:
            continue
        related_replays = [
            sequence
            for sequence in replay_events
            if deliveries[0] < sequence < deliveries[-1]
        ]
        if not related_replays:
            continue
        candidates.append(
            _candidate(
                family="transport_replay_duplicate_delivery",
                title=f"Replayed protected sample was delivered again to {actor}",
                risk_tier="high_lead",
                score=93,
                confidence=0.98,
                actors=(actor,),
                resources=(topic,),
                evidence_events=(*deliveries, *related_replays),
                signals=(
                    "udp_datagram_replay_applied",
                    "duplicate_application_delivery",
                    "freshness_or_deduplication_failure",
                ),
                execution_complete=execution_complete,
                discriminator={"sample_index": sample_index, "topic": topic},
                details={
                    "sample_index": sample_index,
                    "message": message,
                    "delivery_count": len(deliveries),
                    "replay_count": len(related_replays),
                },
            )
        )

    for actor, writes in writes_after_revocation.items():
        deliveries = [
            (receive_sequence, receiver, write_sequence, message)
            for write_sequence, message in writes
            if message is not None
            for receive_sequence, receiver in received_messages.get(message, ())
            if receive_sequence > write_sequence
        ]
        if not deliveries:
            continue
        evidence_events = [local_revocations[actor]]
        evidence_events.extend(write_sequence for _, _, write_sequence, _ in deliveries)
        evidence_events.extend(receive_sequence for receive_sequence, _, _, _ in deliveries)
        receivers = {receiver for _, receiver, _, _ in deliveries}
        candidates.append(
            _candidate(
                family="credential_revocation_bypass",
                title=f"Data from revoked participant {actor} was delivered after revocation",
                risk_tier="critical_lead",
                score=99,
                confidence=0.99,
                actors=(actor, *receivers),
                resources=tuple(scenario.topics),
                evidence_events=evidence_events,
                signals=(
                    "local_identity_revoked",
                    "post_revocation_write_succeeded",
                    "post_revocation_application_delivery",
                ),
                execution_complete=execution_complete,
                discriminator={"revoked_actor": actor},
                details={
                    "revocation_event": local_revocations[actor],
                    "post_revocation_deliveries": len(deliveries),
                    "receivers": sorted(receivers),
                },
            )
        )

    covered_overgrants: set[str] = set()
    for (actor, resource), deliveries in unauthorized_deliveries.items():
        related = [
            sequence
            for sequence, operation, candidate_resource in overgrants.get(actor, [])
            if operation in ("create_datareader", "subscribe", "read")
            and candidate_resource == resource
        ]
        signals = ["policy_denied_actor_received_application_data"]
        if related:
            signals.insert(0, "policy_overgrant")
            covered_overgrants.add(actor)
        actor_key_events = [
            sequence
            for (key_actor, _, _), observations in unauthorized_user_keys.items()
            if key_actor == actor
            for sequence in observations
        ]
        if actor_key_events:
            signals.insert(1, "user_endpoint_key_received")
        candidates.append(
            _candidate(
                family="unauthorized_application_delivery",
                title=f"Policy-denied actor {actor} received protected application data",
                risk_tier="high_lead",
                score=98 if related and actor_key_events else 94,
                confidence=0.99 if related else 0.94,
                actors=(actor,),
                resources=(resource,),
                evidence_events=related + actor_key_events + deliveries,
                signals=signals,
                execution_complete=execution_complete,
                discriminator={"operation": "subscribe"},
                details={
                    "declared_subscribe_permissions": list(
                        scenario.participants[actor].permissions.get("subscribe", ())
                    ),
                    "delivery_count": len(deliveries),
                },
            )
        )

    for actor, observations in overgrants.items():
        if actor in covered_overgrants:
            continue
        resources = [resource for _, _, resource in observations]
        operations = sorted({operation for _, operation, _ in observations})
        candidates.append(
            _candidate(
                family="policy_overgrant",
                title=f"Runtime authorization exceeded the declared policy for {actor}",
                risk_tier="high_lead",
                score=84,
                confidence=0.97,
                actors=(actor,),
                resources=resources,
                evidence_events=(sequence for sequence, _, _ in observations),
                signals=("policy_overgrant",),
                execution_complete=execution_complete,
                discriminator={"operations": operations},
                details={"operations": operations, "decision_count": len(observations)},
            )
        )

    for (actor, required_operation, resource), observations in unauthorized_user_keys.items():
        if any(actor in candidate.actors for candidate in candidates):
            continue
        authority = f"{required_operation} authority"
        resources = (resource,) if resource is not None else tuple(scenario.topics)
        candidates.append(
            _candidate(
                family="unauthorized_user_key_delivery",
                title=f"Actor {actor} without {authority} received a user-endpoint key",
                risk_tier="high_lead",
                score=88,
                confidence=0.91,
                actors=(actor,),
                resources=resources,
                evidence_events=observations,
                signals=(
                    "user_endpoint_key_received",
                    f"no_declared_{required_operation}_authority",
                ),
                execution_complete=execution_complete,
                discriminator={"operation": required_operation},
                details={
                    "key_observation_count": len(observations),
                    "required_operation": required_operation,
                },
            )
        )

    existing_families = {candidate.family for candidate in candidates}
    for result in report.oracle_results:
        if result.status.value != "violation":
            continue
        family = f"invariant_{result.oracle}"
        if result.oracle == "policy_authorization_consistency" and (
            "policy_overgrant" in existing_families
            or "unauthorized_application_delivery" in existing_families
        ):
            continue
        score = {
            "crypto_token_transport_consistency": 90,
            "crypto_token_recipient_binding": 90,
            "revoked_authority_reuse": 92,
            "endpoint_key_lifecycle": 86,
            "application_writer_impersonation": 98,
            "session_rotation_delivery": 82,
        }.get(result.oracle, 75)
        candidates.append(
            _candidate(
                family=family,
                title=result.summary,
                risk_tier="high_lead" if score >= 84 else "investigate",
                score=score,
                confidence=0.9,
                actors=tuple(
                    str(value)
                    for key, value in result.details.items()
                    if key in ("actor", "observer", "receiver", "received_actor")
                    and isinstance(value, str)
                ),
                resources=(),
                evidence_events=result.evidence_events,
                signals=("temporal_invariant_violation", result.oracle),
                execution_complete=execution_complete,
                discriminator={"oracle": result.oracle},
                details=result.details,
            )
        )

    if not execution_complete and any(
        event.kind
        not in (EventKind.PROCESS_EXIT, EventKind.PROBE_READY)
        for event in evidence.events
    ):
        failed = sorted(set(report.failed_processes) | set(report.incomplete_processes))
        candidates.append(
            _candidate(
                family="stateful_execution_divergence",
                title="A stateful schedule diverged after producing security-relevant events",
                risk_tier="investigate",
                score=48,
                confidence=0.55,
                actors=failed,
                resources=(),
                evidence_events=tuple(range(len(evidence.events))),
                signals=("process_or_barrier_divergence", "partial_security_trace_preserved"),
                execution_complete=False,
                discriminator={"failed_actors": failed},
                details={
                    "failed_processes": dict(report.failed_processes),
                    "incomplete_processes": list(report.incomplete_processes),
                },
            )
        )

    ordered = tuple(
        sorted(candidates, key=lambda item: (-item.score, -item.confidence, item.candidate_id))
    )
    return CandidateBundle(
        schema_version=1,
        scenario_id=scenario.scenario_id,
        scenario_digest=scenario.digest,
        run_id=evidence.run_id,
        candidates=ordered,
    )


def _runtime_profile(
    scenario: Scenario,
    evidence: EvidenceBundle,
) -> tuple[Counter[tuple[str, ...]], Mapping[str, tuple[int, ...]]]:
    facts: Counter[tuple[str, ...]] = Counter()
    indexes: dict[str, list[int]] = defaultdict(list)
    for index, event in enumerate(evidence.events):
        sequence = index if event.sequence is None else event.sequence
        fact: tuple[str, ...] | None = None
        category: str | None = None
        if event.kind == EventKind.ACCESS_CONTROL_DECISION:
            operation = event.attributes.get("operation")
            resource = event.attributes.get("resource")
            if isinstance(operation, str) and isinstance(resource, str):
                category = "authorization"
                fact = (category, event.actor, operation, resource, event.outcome)
        elif event.kind == EventKind.APPLICATION_SAMPLE_RECEIVED:
            resource = event_resource(scenario, event, operation="subscribe") or "unknown"
            category = "application_delivery"
            fact = (category, event.actor, resource, event.outcome)
        elif event.kind in (EventKind.CRYPTO_TOKEN_GENERATED, EventKind.CRYPTO_TOKEN_OBSERVED):
            category = "token_route"
            fact = (
                category,
                event.actor,
                str(event.attributes.get("observation_phase", "unknown")),
                str(event.attributes.get("token_class", "unknown")),
                str(event.attributes.get("endpoint_class", "unknown")),
                str(event.attributes.get("addressed_to_local", "unknown")),
                event.outcome,
            )
        elif event.kind == EventKind.KEY_MATERIAL_OBSERVED:
            category = "key_route"
            fact = (
                category,
                event.actor,
                str(event.attributes.get("observation_phase", "unknown")),
                str(event.attributes.get("token_class", "unknown")),
                str(event.attributes.get("endpoint_class", "unknown")),
                str(event.attributes.get("material_semantics", "unknown")),
                str(event.attributes.get("addressed_to_local", "unknown")),
            )
        elif event.kind in (
            EventKind.ENDPOINT_CREATED,
            EventKind.ENDPOINT_DESTROYED,
            EventKind.ENDPOINT_RECREATED,
            EventKind.ENDPOINT_MATCHED,
        ):
            category = "endpoint_lifecycle"
            fact = (
                category,
                event.actor,
                event.kind,
                str(event.attributes.get("endpoint", "unknown")),
                str(event.attributes.get("topic", "unknown")),
                str(event.attributes.get("lifecycle_epoch", "unknown")),
                event.outcome,
            )
        elif event.kind in (
            EventKind.KEY_ROTATED,
            EventKind.AUTHORITY_REVOKED,
            EventKind.CREDENTIAL_REVOKED,
        ):
            category = "authority_lifecycle"
            fact = (
                category,
                event.actor,
                event.kind,
                str(event.attributes.get("rotation_kind", "unknown")),
                str(event.attributes.get("context", "unknown")),
                event.outcome,
            )
        elif event.kind in (
            EventKind.PARTICIPANT_DISCONNECTED,
            EventKind.PARTICIPANT_RECONNECTED,
        ):
            category = "participant_lifecycle"
            fact = (
                category,
                event.actor,
                event.kind,
                str(event.attributes.get("participant_epoch", "unknown")),
                event.outcome,
            )
        elif event.kind in (
            EventKind.TRANSPORT_DATAGRAM_DROPPED,
            EventKind.TRANSPORT_DATAGRAM_DELAYED,
            EventKind.TRANSPORT_DATAGRAM_DUPLICATED,
            EventKind.TRANSPORT_DATAGRAM_REPLAYED,
        ):
            category = "transport_fault"
            fact = (
                category,
                event.actor,
                event.kind,
                str(event.attributes.get("fault", "unknown")),
                event.outcome,
            )
        if fact is not None and category is not None:
            # Security routing coverage is set-like. Reliable DDS may
            # retransmit the same volatile-secure token without changing any
            # authority or recipient relation; treating retry count as a
            # semantic difference turns ordinary transport timing into noisy
            # schedule candidates. Lifecycle, authorization, and application
            # counts remain meaningful and are retained.
            if category in ("token_route", "key_route"):
                facts[fact] = 1
            else:
                facts[fact] += 1
            indexes[category].append(sequence)
    return facts, {name: tuple(values) for name, values in indexes.items()}


def discover_schedule_differences(
    baseline_scenario: Scenario,
    baseline_evidence: EvidenceBundle,
    baseline_report: EvaluationReport,
    scenario: Scenario,
    evidence: EvidenceBundle,
    report: EvaluationReport,
) -> tuple[DiscoveryCandidate, ...]:
    """Compare security semantics while ignoring GUIDs, timestamps, and key bytes."""

    baseline, _ = _runtime_profile(baseline_scenario, baseline_evidence)
    current, current_indexes = _runtime_profile(scenario, evidence)
    if baseline == current:
        return ()

    baseline_by_category: dict[str, Counter[tuple[str, ...]]] = defaultdict(Counter)
    current_by_category: dict[str, Counter[tuple[str, ...]]] = defaultdict(Counter)
    for fact, count in baseline.items():
        baseline_by_category[fact[0]][fact] = count
    for fact, count in current.items():
        current_by_category[fact[0]][fact] = count

    complete = (
        not baseline_report.failed_processes
        and not baseline_report.incomplete_processes
        and not report.failed_processes
        and not report.incomplete_processes
    )
    candidates: list[DiscoveryCandidate] = []
    categories = sorted(set(baseline_by_category) | set(current_by_category))
    for category in categories:
        before = baseline_by_category[category]
        after = current_by_category[category]
        if before == after:
            continue
        actors = {fact[1] for fact in set(before) | set(after) if len(fact) > 1}
        resources = {
            fact[3]
            for fact in set(before) | set(after)
            if category == "authorization" and len(fact) > 3
        }
        if category == "application_delivery":
            resources.update(
                fact[2] for fact in set(before) | set(after) if len(fact) > 2
            )
        family, title, score, risk = {
            "authorization": (
                "schedule_authorization_divergence",
                "Authorization decisions changed under a schedule-only mutation",
                88,
                "high_lead",
            ),
            "application_delivery": (
                "schedule_delivery_divergence",
                "Application delivery changed under a schedule-only mutation",
                78,
                "investigate",
            ),
            "token_route": (
                "schedule_token_route_divergence",
                "CryptoToken routing changed under a schedule-only mutation",
                74,
                "investigate",
            ),
            "key_route": (
                "schedule_key_route_divergence",
                "Key-material routing changed under a schedule-only mutation",
                78,
                "investigate",
            ),
            "endpoint_lifecycle": (
                "schedule_endpoint_lifecycle_divergence",
                "Endpoint lifecycle behavior changed under a schedule-only mutation",
                68,
                "investigate",
            ),
            "authority_lifecycle": (
                "schedule_authority_lifecycle_divergence",
                "Authority lifecycle behavior changed under a schedule-only mutation",
                78,
                "investigate",
            ),
            "participant_lifecycle": (
                "schedule_participant_lifecycle_divergence",
                "Participant reconnect behavior changed under a schedule-only mutation",
                76,
                "investigate",
            ),
            "transport_fault": (
                "schedule_transport_fault_divergence",
                "Transport fault handling changed under a schedule-only mutation",
                72,
                "investigate",
            ),
        }[category]
        removed = sorted((before - after).elements())
        added = sorted((after - before).elements())
        candidates.append(
            _candidate(
                family=family,
                title=title,
                risk_tier=risk,
                score=score,
                confidence=0.88 if complete else 0.6,
                actors=actors,
                resources=resources,
                evidence_events=current_indexes.get(category, ()),
                signals=("schedule_only_semantic_change", category),
                execution_complete=complete,
                discriminator={"category": category},
                details={
                    "baseline_run_id": baseline_evidence.run_id,
                    "current_run_id": evidence.run_id,
                    "removed_facts": [list(fact) for fact in removed[:20]],
                    "added_facts": [list(fact) for fact in added[:20]],
                    "removed_fact_count": len(removed),
                    "added_fact_count": len(added),
                },
            )
        )
    return tuple(
        sorted(candidates, key=lambda item: (-item.score, item.candidate_id))
    )
