from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import EvidenceEvent, JsonValue


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    schema_version: int
    run_id: str
    scenario_id: str
    scenario_digest: str
    implementation: str
    events: tuple[EvidenceEvent, ...]
    metadata: Mapping[str, JsonValue]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "scenario_id": self.scenario_id,
            "scenario_digest": self.scenario_digest,
            "implementation": self.implementation,
            "metadata": dict(self.metadata),
            "events": [event.to_dict() for event in self.events],
        }

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        scenario_id: str,
        scenario_digest: str,
        implementation: str,
        events: Iterable[EvidenceEvent],
        metadata: Mapping[str, JsonValue] | None = None,
    ) -> "EvidenceBundle":
        sequenced = tuple(
            EvidenceEvent(
                kind=event.kind,
                actor=event.actor,
                implementation=event.implementation,
                outcome=event.outcome,
                attributes=event.attributes,
                source=event.source,
                sequence=index,
                monotonic_ns=event.monotonic_ns,
            )
            for index, event in enumerate(events)
        )
        return cls(
            schema_version=1,
            run_id=run_id,
            scenario_id=scenario_id,
            scenario_digest=scenario_digest,
            implementation=implementation,
            events=sequenced,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "EvidenceBundle":
        if raw.get("schema_version") != 1:
            raise ValueError("evidence schema_version must be 1")
        string_fields = ("run_id", "scenario_id", "scenario_digest", "implementation")
        invalid = [field for field in string_fields if not isinstance(raw.get(field), str)]
        if invalid:
            raise ValueError(f"invalid evidence string fields: {', '.join(invalid)}")
        events_raw = raw.get("events")
        if not isinstance(events_raw, list):
            raise ValueError("evidence events must be an array")
        metadata = raw.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError("evidence metadata must be an object")
        return cls(
            schema_version=1,
            run_id=raw["run_id"],
            scenario_id=raw["scenario_id"],
            scenario_digest=raw["scenario_digest"],
            implementation=raw["implementation"],
            events=tuple(EvidenceEvent.from_dict(event) for event in events_raw),
            metadata=dict(metadata),
        )


def write_evidence(bundle: EvidenceBundle, path: str | Path) -> None:
    evidence_path = Path(path)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(bundle.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_evidence(path: str | Path) -> EvidenceBundle:
    evidence_path = Path(path)
    raw = json.loads(evidence_path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("evidence root must be an object")
    return EvidenceBundle.from_dict(raw)
