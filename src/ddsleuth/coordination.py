from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Protocol

from .models import EventBarrier, JsonValue


class CoordinationError(RuntimeError):
    pass


class ProcessState(Protocol):
    def poll(self) -> int | None:
        ...


@dataclass(slots=True)
class StructuredLogMonitor:
    max_line_bytes: int = 1024 * 1024
    _offsets: dict[str, int] = field(default_factory=dict)
    _buffers: dict[str, bytes] = field(default_factory=dict)
    _events: list[dict[str, JsonValue]] = field(default_factory=list)

    @property
    def events(self) -> tuple[Mapping[str, JsonValue], ...]:
        return tuple(self._events)

    def poll(self, logs: Mapping[str, Path]) -> None:
        for actor, path in logs.items():
            offset = self._offsets.get(actor, 0)
            try:
                with path.open("rb") as stream:
                    stream.seek(offset)
                    chunk = stream.read()
                    self._offsets[actor] = stream.tell()
            except FileNotFoundError:
                continue
            if not chunk:
                continue
            buffered = self._buffers.get(actor, b"") + chunk
            lines = buffered.split(b"\n")
            self._buffers[actor] = lines.pop()
            if len(self._buffers[actor]) > self.max_line_bytes:
                raise CoordinationError(f"structured log line from {actor} exceeds size limit")
            for raw_line in lines:
                if len(raw_line) > self.max_line_bytes:
                    raise CoordinationError(f"structured log line from {actor} exceeds size limit")
                line = raw_line.strip()
                if not line.startswith(b"DDSLEUTH_EVENT "):
                    continue
                try:
                    event = json.loads(line.removeprefix(b"DDSLEUTH_EVENT "))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise CoordinationError(
                        f"invalid structured event from {actor}: {error}"
                    ) from error
                if not isinstance(event, dict):
                    raise CoordinationError(f"structured event from {actor} is not an object")
                declared_actor = event.get("actor", actor)
                if declared_actor != actor:
                    raise CoordinationError(
                        f"structured event actor {declared_actor!r} does not match log owner {actor!r}"
                    )
                event["actor"] = actor
                event["source"] = path.name
                self._events.append(event)


def _matches(event: Mapping[str, JsonValue], barrier: EventBarrier) -> bool:
    if event.get("actor") != barrier.actor or event.get("kind") != barrier.kind:
        return False
    if barrier.outcome is not None and event.get("outcome") != barrier.outcome:
        return False
    attributes = event.get("attributes", {})
    if not isinstance(attributes, Mapping):
        return False
    return all(attributes.get(name) == value for name, value in barrier.attributes.items())


def wait_for_barriers(
    barriers: tuple[EventBarrier, ...],
    monitor: StructuredLogMonitor,
    logs: Mapping[str, Path],
    processes: Mapping[str, ProcessState],
    deadline: float,
) -> None:
    pending = list(barriers)
    while pending:
        monitor.poll(logs)
        pending = [
            barrier
            for barrier in pending
            if not any(_matches(event, barrier) for event in monitor.events)
        ]
        if not pending:
            return
        failed_sources = sorted(
            {
                barrier.actor
                for barrier in pending
                if barrier.actor in processes and processes[barrier.actor].poll() is not None
            }
        )
        if failed_sources:
            raise CoordinationError(
                "barrier source exited before emitting the required event: "
                + ", ".join(failed_sources)
            )
        if time.monotonic() >= deadline:
            descriptions = [f"{item.actor}:{item.kind}" for item in pending]
            raise CoordinationError("timed out waiting for barriers: " + ", ".join(descriptions))
        time.sleep(0.02)
