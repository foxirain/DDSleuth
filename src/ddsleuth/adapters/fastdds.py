from __future__ import annotations

import gzip
import json
import re
from pathlib import Path
from typing import Iterable, Mapping

from ..evidence import EvidenceBundle
from ..fingerprints import FINGERPRINT_SCHEME
from ..models import EvidenceEvent, EventKind, JsonValue, Scenario
from ..runner import run_processes


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

_SANITIZER_PATTERNS = (
    (
        "address",
        re.compile(r"(?:ERROR|SUMMARY): AddressSanitizer:\s*([A-Za-z0-9_-]+)"),
    ),
    (
        "thread",
        re.compile(r"WARNING: ThreadSanitizer:\s*([^\r\n]+)"),
    ),
    (
        "memory",
        re.compile(r"WARNING: MemorySanitizer:\s*([^\r\n]+)"),
    ),
)

_UBSAN_MEMORY_TERMS = (
    "out of bounds",
    "misaligned address",
    "null pointer",
    "pointer index expression",
    "load of address",
    "store to address",
    "insufficient space",
    "member access within",
)


def _sanitizer_events(logs: Mapping[str, Path]) -> list[EvidenceEvent]:
    events: list[EvidenceEvent] = []
    seen: set[tuple[str, str, str]] = set()
    for actor, log_path in logs.items():
        archive = log_path.with_suffix(log_path.suffix + ".gz")
        source_path = archive if archive.is_file() else log_path
        opener = gzip.open if source_path.suffix == ".gz" else open
        with opener(source_path, "rt", encoding="utf-8", errors="replace") as stream:
            for raw_line in stream:
                line = _ANSI_ESCAPE.sub("", raw_line).strip()
                detected: tuple[str, str] | None = None
                for sanitizer, pattern in _SANITIZER_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        violation = match.group(1).strip().lower().replace(" ", "_")
                        if sanitizer == "thread":
                            violation = "data-race"
                        elif sanitizer == "memory":
                            violation = "use-of-uninitialized-value"
                        detected = (sanitizer, violation)
                        break
                if detected is None and "runtime error:" in line:
                    detail = line.split("runtime error:", 1)[1].strip()
                    if any(term in detail.lower() for term in _UBSAN_MEMORY_TERMS):
                        detected = ("undefined", "memory_undefined_behavior")
                if detected is None:
                    continue
                sanitizer, violation = detected
                key = (actor, sanitizer, violation)
                if key in seen:
                    continue
                seen.add(key)
                events.append(
                    EvidenceEvent(
                        kind=EventKind.MEMORY_SAFETY_VIOLATION,
                        actor=actor,
                        implementation="fastdds",
                        outcome="detected",
                        attributes={
                            "sanitizer": sanitizer,
                            "violation": violation,
                        },
                        source=source_path.name,
                    )
                )
    return events


class FastDDSLegacyTextImporter:
    """Translate the original Fast DDS research harness logs into core events."""

    implementation = "fastdds"

    _denial = re.compile(
        r"ACCESS_CONTROL_NEGATIVE\s+secret_topic_reader_denied=(?P<denied>[01])\s+"
        r"reader_created=(?P<created>[01])"
    )
    _token = re.compile(
        r"TOKEN_PLAINTEXT\s+observed=(?P<observed>[01])\s+"
        r"local=(?P<local>\S+)\s+"
        r"inner_destination_participant=(?P<destination_participant>\S+)\s+"
        r"inner_destination_endpoint=(?P<destination_endpoint>\S+)\s+"
        r"source_endpoint=(?P<source_endpoint>\S+)\s+"
        r"addressed_to_local=(?P<addressed>[01])\s+token_count=(?P<count>\d+)"
    )
    _key = re.compile(
        r"STOLEN_KEY\s+key_id=(?P<key_id>[0-9a-fA-F]+)\s+"
        r"receiver_key_id=(?P<receiver_key_id>[0-9a-fA-F]+)\s+"
        r"has_sender_key=(?P<sender>[01])\s+"
        r"has_receiver_specific_key=(?P<receiver>[01])"
    )
    _confidentiality = re.compile(
        r"CONFIDENTIALITY_BREACH\s+legitimate_cipher_decrypted=(?P<decrypted>[01])\s+"
        r"forged_as_victim_created=(?P<forged>[01])\s+forged_bytes=(?P<bytes>\d+)"
    )
    _packet = re.compile(
        r"UDP_FORGERY_SENT\s+packet_built=(?P<built>[01])\s+packet_sent=(?P<sent>[01])\s+"
        r"packet_bytes=(?P<bytes>\d+)\s+destination_port=(?P<port>\d+)"
    )
    _accepted = re.compile(
        r"FORGERY_AS_VICTIM_ACCEPTED\s+accepted=(?P<accepted>[01])\s+"
        r"actual_reader=(?P<reader>\S+)\s+actual_writer=(?P<writer>\S+)\s+"
        r"forged_bytes=(?P<bytes>\d+)"
    )
    _delivered = re.compile(
        r"UDP_FORGERY_DELIVERED\s+index=(?P<index>\d+)\s+message=(?P<message>.*)$"
    )
    _endpoint_pair = re.compile(
        r"PRODUCTION_PAIR\s+writer=(?P<writer>\S+)\s+intended_reader=(?P<reader>\S+)\s+"
        r"legitimate_cipher_saved=(?P<saved>[01])\s+application_write=(?P<wrote>[01])\s+"
        r"bytes=(?P<bytes>\d+)"
    )

    def _event(
        self,
        *,
        kind: str,
        actor: str,
        outcome: str,
        source: str,
        attributes: Mapping[str, object],
    ) -> EvidenceEvent:
        return EvidenceEvent(
            kind=kind,
            actor=actor,
            implementation=self.implementation,
            outcome=outcome,
            attributes=dict(attributes),
            source=source,
        )

    def parse_text(self, actor: str, text: str, source: str) -> list[EvidenceEvent]:
        events: list[EvidenceEvent] = []
        clean_text = _ANSI_ESCAPE.sub("", text)
        for raw_line in clean_text.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("DDSLEUTH_EVENT "):
                structured = json.loads(line.removeprefix("DDSLEUTH_EVENT "))
                if not isinstance(structured, dict):
                    raise ValueError(f"structured event in {source} is not an object")
                declared_actor = structured.get("actor", actor)
                if declared_actor != actor:
                    raise ValueError(
                        f"structured event actor {declared_actor!r} does not match log owner {actor!r}"
                    )
                declared_implementation = structured.get("implementation", self.implementation)
                if declared_implementation != self.implementation:
                    raise ValueError(
                        "structured event implementation does not match the Fast DDS adapter"
                    )
                structured["actor"] = actor
                structured["implementation"] = self.implementation
                structured["source"] = source
                events.append(EvidenceEvent.from_dict(structured))
                continue

            match = self._denial.search(line)
            if match:
                denied = match.group("denied") == "1" and match.group("created") == "0"
                events.append(
                    self._event(
                        kind=EventKind.ACCESS_CONTROL_DECISION,
                        actor=actor,
                        outcome="denied" if denied else "allowed",
                        source=source,
                        attributes={
                            "operation": "create_datareader",
                            "resource": "protected_topic",
                            "reader_created": match.group("created") == "1",
                        },
                    )
                )
                continue

            match = self._token.search(line)
            if match:
                events.append(
                    self._event(
                        kind=EventKind.CRYPTO_TOKEN_OBSERVED,
                        actor=actor,
                        outcome="observed" if match.group("observed") == "1" else "not_observed",
                        source=source,
                        attributes={
                            "token_class": "datawriter",
                            "local_participant_guid": match.group("local"),
                            "destination_participant_guid": match.group("destination_participant"),
                            "destination_endpoint_guid": match.group("destination_endpoint"),
                            "source_endpoint_guid": match.group("source_endpoint"),
                            "addressed_to_local": match.group("addressed") == "1",
                            "token_count": int(match.group("count")),
                        },
                    )
                )
                continue

            match = self._key.search(line)
            if match:
                events.append(
                    self._event(
                        kind=EventKind.KEY_MATERIAL_OBSERVED,
                        actor=actor,
                        outcome="observed",
                        source=source,
                        attributes={
                            "key_id": match.group("key_id"),
                            "receiver_key_id": match.group("receiver_key_id"),
                            "sender_key_present": match.group("sender") == "1",
                            "receiver_specific_key_present": match.group("receiver") == "1",
                        },
                    )
                )
                continue

            match = self._confidentiality.search(line)
            if match:
                events.extend(
                    (
                        self._event(
                            kind=EventKind.DECRYPT_CAPABILITY,
                            actor=actor,
                            outcome=(
                                "succeeded" if match.group("decrypted") == "1" else "failed"
                            ),
                            source=source,
                            attributes={"target": "legitimate_protected_writer_traffic"},
                        ),
                        self._event(
                            kind=EventKind.FORGE_CAPABILITY,
                            actor=actor,
                            outcome="succeeded" if match.group("forged") == "1" else "failed",
                            source=source,
                            attributes={
                                "claimed_identity": "protected_writer",
                                "protected_bytes": int(match.group("bytes")),
                                "attacker_controlled": True,
                            },
                        ),
                    )
                )
                continue

            match = self._packet.search(line)
            if match:
                succeeded = match.group("built") == "1" and match.group("sent") == "1"
                events.append(
                    self._event(
                        kind=EventKind.PACKET_SENT,
                        actor=actor,
                        outcome="succeeded" if succeeded else "failed",
                        source=source,
                        attributes={
                            "transport": "udp",
                            "packet_bytes": int(match.group("bytes")),
                            "destination_port": int(match.group("port")),
                            "loopback": True,
                            "attacker_controlled": True,
                        },
                    )
                )
                continue

            match = self._accepted.search(line)
            if match:
                events.append(
                    self._event(
                        kind=EventKind.PROTECTED_MESSAGE_ACCEPTED,
                        actor=actor,
                        outcome="accepted" if match.group("accepted") == "1" else "rejected",
                        source=source,
                        attributes={
                            "reader_guid": match.group("reader"),
                            "claimed_writer_guid": match.group("writer"),
                            "protected_bytes": int(match.group("bytes")),
                            "attacker_controlled": True,
                        },
                    )
                )
                continue

            match = self._delivered.search(line)
            if match:
                events.append(
                    self._event(
                        kind=EventKind.APPLICATION_SAMPLE_RECEIVED,
                        actor=actor,
                        outcome="received",
                        source=source,
                        attributes={
                            "sample_index": int(match.group("index")),
                            "message": match.group("message"),
                            "attacker_controlled": True,
                        },
                    )
                )
                continue

            match = self._endpoint_pair.search(line)
            if match:
                events.append(
                    self._event(
                        kind=EventKind.ENDPOINT_PAIR_OBSERVED,
                        actor=actor,
                        outcome="observed",
                        source=source,
                        attributes={
                            "writer_guid": match.group("writer"),
                            "reader_guid": match.group("reader"),
                            "legitimate_cipher_saved": match.group("saved") == "1",
                            "application_write": match.group("wrote") == "1",
                            "protected_bytes": int(match.group("bytes")),
                        },
                    )
                )
        return events

    def import_logs(
        self,
        logs: Mapping[str, Path],
        statuses: Mapping[str, int],
    ) -> list[EvidenceEvent]:
        events: list[EvidenceEvent] = []
        for actor, path in logs.items():
            events.extend(self.parse_text(actor, path.read_text(encoding="utf-8", errors="replace"), path.name))
        events.extend(self.process_exit_events(statuses))
        return events

    def process_exit_events(self, statuses: Mapping[str, int]) -> list[EvidenceEvent]:
        return [
            self._event(
                kind=EventKind.PROCESS_EXIT,
                actor=actor,
                outcome="succeeded" if status == 0 else "failed",
                source="process-status.json",
                attributes={"exit_code": status},
            )
            for actor, status in statuses.items()
        ]


class FastDDSAdapter:
    name = "fastdds"

    def __init__(self) -> None:
        self._legacy_importer = FastDDSLegacyTextImporter()

    def run(
        self,
        scenario: Scenario,
        run_dir: Path,
        environment: Mapping[str, str],
        *,
        allow_external: bool = False,
        overwrite: bool = False,
        configuration_binding: Mapping[str, JsonValue] | None = None,
        role_environments: Mapping[str, Mapping[str, str]] | None = None,
    ) -> EvidenceBundle:
        if scenario.execution is None:
            raise ValueError("scenario does not define execution roles")
        if scenario.execution.log_format not in ("fastdds-legacy-text", "ddssec-jsonl"):
            raise ValueError(f"unsupported Fast DDS log format: {scenario.execution.log_format}")
        artifacts = run_processes(
            scenario.execution,
            run_dir,
            environment,
            allow_external=allow_external,
            overwrite=overwrite,
            injected_role_environments=role_environments,
            preserve_partial=True,
        )
        if scenario.execution.log_format == "ddssec-jsonl":
            events = [EvidenceEvent.from_dict(raw) for raw in artifacts.structured_events]
            if events and all(event.monotonic_ns is not None for event in events):
                events.sort(key=lambda event: int(event.monotonic_ns or 0))
            events.extend(_sanitizer_events(artifacts.logs))
            events.extend(self._legacy_importer.process_exit_events(artifacts.statuses))
        else:
            events = self._legacy_importer.import_logs(artifacts.logs, artifacts.statuses)
        if artifacts.error is not None:
            affected = artifacts.error.get("affected_actors", [])
            actor = (
                affected[0]
                if isinstance(affected, list)
                and affected
                and isinstance(affected[0], str)
                and affected[0] in scenario.participants
                else artifacts.processes[-1].actor
            )
            events.append(
                EvidenceEvent(
                    kind=EventKind.EXECUTION_DIVERGENCE,
                    actor=actor,
                    implementation=self.name,
                    outcome="failed",
                    attributes=dict(artifacts.error),
                    source="runner-error.json",
                )
            )
        metadata: dict[str, JsonValue] = {
            "implementation_version": scenario.implementation_version,
            "network": scenario.execution.network,
            "log_format": scenario.execution.log_format,
            "all_processes_succeeded": all(status == 0 for status in artifacts.statuses.values()),
            "key_fingerprint_scheme": FINGERPRINT_SCHEME,
            "executables": {
                process.actor: {
                    "name": process.executable_name,
                    "sha256": process.executable_sha256,
                    "size": process.executable_size,
                }
                for process in artifacts.processes
            },
            "transport_fault_libraries": {
                process.actor: dict(process.transport_fault_library)
                for process in artifacts.processes
                if process.transport_fault_library is not None
            },
            "configuration_binding": dict(
                configuration_binding
                or {
                    "mode": "external_unverified",
                    "scenario_digest": scenario.digest,
                }
            ),
        }
        if artifacts.error is not None:
            metadata["execution_error"] = dict(artifacts.error)
        return EvidenceBundle.create(
            run_id=artifacts.run_dir.name,
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation=self.name,
            events=events,
            metadata=metadata,
        )
