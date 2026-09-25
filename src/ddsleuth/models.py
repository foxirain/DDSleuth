from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping


JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


class EventKind(StrEnum):
    PROBE_READY = "probe.ready"
    OBSERVER_ERROR = "probe.observer_error"
    ACCESS_CONTROL_DECISION = "access_control.decision"
    CRYPTO_TOKEN_GENERATED = "crypto_token.generated"
    CRYPTO_TOKEN_OBSERVED = "crypto_token.observed"
    KEY_MATERIAL_OBSERVED = "key_material.observed"
    AUTHORITY_REVOKED = "authorization.revoked"
    KEY_ROTATED = "key.rotated"
    ENDPOINT_PAIR_OBSERVED = "endpoint_pair.observed"
    DECRYPT_CAPABILITY = "capability.decrypt"
    FORGE_CAPABILITY = "capability.forge"
    PACKET_SENT = "network.packet_sent"
    PROTECTED_MESSAGE_ACCEPTED = "crypto.protected_message_accepted"
    ENDPOINT_MATCHED = "endpoint.matched"
    ENDPOINT_CREATED = "endpoint.created"
    ENDPOINT_DESTROYED = "endpoint.destroyed"
    ENDPOINT_RECREATED = "endpoint.recreated"
    APPLICATION_WRITE_ATTEMPT = "application.write_attempt"
    APPLICATION_SAMPLE_WRITTEN = "application.sample_written"
    APPLICATION_SAMPLE_RECEIVED = "application.sample_received"
    PROCESS_EXIT = "process.exit"


@dataclass(frozen=True, slots=True)
class EvidenceEvent:
    kind: str
    actor: str
    implementation: str
    outcome: str
    attributes: Mapping[str, JsonValue] = field(default_factory=dict)
    source: str | None = None
    sequence: int | None = None
    monotonic_ns: int | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "kind": self.kind,
            "actor": self.actor,
            "implementation": self.implementation,
            "outcome": self.outcome,
            "attributes": dict(self.attributes),
        }
        if self.source is not None:
            result["source"] = self.source
        if self.sequence is not None:
            result["sequence"] = self.sequence
        if self.monotonic_ns is not None:
            result["monotonic_ns"] = self.monotonic_ns
        return result

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "EvidenceEvent":
        required = ("kind", "actor", "implementation", "outcome")
        missing = [name for name in required if not isinstance(raw.get(name), str)]
        if missing:
            raise ValueError(f"event fields must be strings: {', '.join(missing)}")
        attributes = raw.get("attributes", {})
        if not isinstance(attributes, Mapping):
            raise ValueError("event attributes must be an object")
        sequence = raw.get("sequence")
        if sequence is not None and not isinstance(sequence, int):
            raise ValueError("event sequence must be an integer")
        monotonic_ns = raw.get("monotonic_ns")
        if monotonic_ns is not None and (
            not isinstance(monotonic_ns, int) or monotonic_ns < 0
        ):
            raise ValueError("event monotonic_ns must be a non-negative integer")
        source = raw.get("source")
        if source is not None and not isinstance(source, str):
            raise ValueError("event source must be a string")
        return cls(
            kind=raw["kind"],
            actor=raw["actor"],
            implementation=raw["implementation"],
            outcome=raw["outcome"],
            attributes=dict(attributes),
            source=source,
            sequence=sequence,
            monotonic_ns=monotonic_ns,
        )


@dataclass(frozen=True, slots=True)
class IdentitySpec:
    subject: str


@dataclass(frozen=True, slots=True)
class ParticipantSpec:
    name: str
    role: str
    permissions: Mapping[str, tuple[str, ...]]
    identity: IdentitySpec | None = None


@dataclass(frozen=True, slots=True)
class AssertionSpec:
    assertion_id: str
    oracle: str
    parameters: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class EventBarrier:
    actor: str
    kind: str
    outcome: str | None = None
    attributes: Mapping[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RoleCommand:
    actor: str
    command: tuple[str, ...]
    environment: Mapping[str, str] = field(default_factory=dict)
    start_after: tuple[EventBarrier, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionSpec:
    network: str
    timeout_seconds: float
    log_format: str
    roles: tuple[RoleCommand, ...]


@dataclass(frozen=True, slots=True)
class Scenario:
    schema_version: int
    scenario_id: str
    title: str
    implementation: str
    implementation_version: str | None
    domain_id: int
    participants: Mapping[str, ParticipantSpec]
    grant_order: tuple[str, ...]
    governance: Mapping[str, JsonValue]
    topics: Mapping[str, Mapping[str, JsonValue]]
    assertions: tuple[AssertionSpec, ...]
    execution: ExecutionSpec | None
    raw: Mapping[str, JsonValue]
    digest: str
