from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping, Protocol

from ..evidence import EvidenceBundle
from ..models import AssertionSpec, JsonValue, Scenario


class OracleStatus(StrEnum):
    PASS = "pass"
    VIOLATION = "violation"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class OracleResult:
    assertion_id: str
    oracle: str
    status: OracleStatus
    summary: str
    evidence_events: tuple[int, ...] = ()
    details: Mapping[str, JsonValue] = field(default_factory=dict)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "assertion_id": self.assertion_id,
            "oracle": self.oracle,
            "status": self.status.value,
            "summary": self.summary,
            "evidence_events": list(self.evidence_events),
            "details": dict(self.details),
        }


class Oracle(Protocol):
    name: str

    def evaluate(
        self,
        scenario: Scenario,
        assertion: AssertionSpec,
        evidence: EvidenceBundle,
    ) -> OracleResult:
        ...


def event_sequence(default_index: int, sequence: int | None) -> int:
    return default_index if sequence is None else sequence
