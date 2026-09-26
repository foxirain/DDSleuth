from __future__ import annotations

import ctypes.util
import gzip
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Mapping

from .coordination import CoordinationError, StructuredLogMonitor, wait_for_barriers
from .models import ExecutionSpec, JsonValue, RoleCommand
from .fingerprints import FINGERPRINT_ENVIRONMENT


ACTION_PLAN_ENVIRONMENT = "DDSLEUTH_ACTION_PLAN"
ACTION_PLAN_HEADER = "# ddsleuth-action-plan-v1"
TRANSPORT_FAULT_LIBRARY_ENVIRONMENT = "DDSLEUTH_TRANSPORT_FAULT_LIBRARY"
TRANSPORT_FAULT_ENABLE_ENVIRONMENT = "DDSLEUTH_TRANSPORT_FAULTS"
FORCE_UDP_ONLY_ENVIRONMENT = "DDSLEUTH_FORCE_UDP_ONLY"


_TRANSPORT_FAULT_OUTCOMES = {
    "transport.drop_next": ("transport.datagram_dropped", "dropped"),
    "transport.delay_next": ("transport.datagram_delayed", "delayed"),
    "transport.duplicate_next": ("transport.datagram_duplicated", "duplicated"),
    "transport.capture_next": ("transport.datagram_captured", "captured"),
    "transport.replay_last": ("transport.datagram_replayed", "replayed"),
}


class RunnerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ProcessRun:
    actor: str
    command: tuple[str, ...]
    log_path: Path
    exit_code: int
    executable_name: str
    executable_sha256: str
    executable_size: int
    transport_fault_library: Mapping[str, JsonValue] | None = None


@dataclass(frozen=True, slots=True)
class RunArtifacts:
    run_dir: Path
    processes: tuple[ProcessRun, ...]
    structured_events: tuple[Mapping[str, JsonValue], ...] = ()
    error: Mapping[str, JsonValue] | None = None

    @property
    def logs(self) -> dict[str, Path]:
        return {process.actor: process.log_path for process in self.processes}

    @property
    def statuses(self) -> dict[str, int]:
        return {process.actor: process.exit_code for process in self.processes}


def _expand(value: str, environment: Mapping[str, str], context: str) -> str:
    try:
        return Template(value).substitute(environment)
    except KeyError as error:
        raise RunnerError(f"missing environment variable {error.args[0]!r} in {context}") from error


def _executable_provenance(
    command: tuple[str, ...],
    environment: Mapping[str, str],
) -> tuple[str, str, int]:
    executable = command[0]
    resolved = (
        Path(executable)
        if Path(executable).is_absolute() or "/" in executable
        else Path(shutil.which(executable, path=environment.get("PATH")) or executable)
    )
    try:
        resolved = resolved.resolve(strict=True)
        size = resolved.stat().st_size
        digest = hashlib.sha256()
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise RunnerError(f"cannot fingerprint executable {executable!r}: {error}") from error
    return resolved.name, digest.hexdigest(), size


def _write_action_plan(role: RoleCommand, run_dir: Path) -> Path | None:
    if not role.actions:
        return None
    path = run_dir / f"{role.actor}.actions.tsv"
    lines = [ACTION_PLAN_HEADER]
    for action in role.actions:
        at_ms = format(action.at_ms, ".12g")
        lines.append(
            "\t".join((at_ms, action.action_id, action.operation, *action.arguments))
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _compact_structured_log(path: Path, threshold_bytes: int = 512 * 1024) -> None:
    """Keep structured evidence readable while bounding repetitive vendor logs.

    The exact original stream remains available as gzip.  The plain log keeps
    every DDSleuth event plus bounded diagnostic head/tail sections, which is
    sufficient for fast barriers and post-run inspection without multi-GB
    campaign directories.
    """

    if path.stat().st_size <= threshold_bytes:
        return
    archive = path.with_suffix(path.suffix + ".gz")
    archive_tmp = archive.with_suffix(archive.suffix + ".tmp")
    with path.open("rb") as source, gzip.open(archive_tmp, "wb", compresslevel=6) as output:
        shutil.copyfileobj(source, output, length=1024 * 1024)
    os.replace(archive_tmp, archive)

    compact_tmp = path.with_suffix(path.suffix + ".compact.tmp")
    diagnostic_limit = 128 * 1024
    diagnostic_head = 0
    diagnostic_tail: list[bytes] = []
    diagnostic_tail_bytes = 0
    with path.open("rb") as source, compact_tmp.open("wb") as output:
        for line in source:
            if line.lstrip().startswith(b"DDSLEUTH_EVENT "):
                output.write(line)
            elif diagnostic_head < diagnostic_limit:
                output.write(line)
                diagnostic_head += len(line)
            else:
                diagnostic_tail.append(line)
                diagnostic_tail_bytes += len(line)
                while diagnostic_tail and diagnostic_tail_bytes > diagnostic_limit:
                    diagnostic_tail_bytes -= len(diagnostic_tail.pop(0))
        output.write(
            b"\n[DDSleuth compacted repetitive diagnostics; exact stream is in the .log.gz archive]\n"
        )
        for line in diagnostic_tail:
            output.write(line)
    os.replace(compact_tmp, path)


def _uses_transport_faults(role: RoleCommand) -> bool:
    return any(action.operation.startswith("transport.") for action in role.actions)


def _validate_transport_fault_actions(
    execution: ExecutionSpec,
    events: tuple[Mapping[str, JsonValue], ...],
) -> None:
    """Fail closed when a requested network mutation never reached the wire.

    A scheduled action is not evidence that the preload shim saw a UDP packet.
    Each action therefore needs its action-id-correlated applied event.  This
    prevents SHM fallback, socket failures, and late process exit from being
    counted as successful security experiments.
    """

    missing: list[str] = []
    failed: list[str] = []
    for role in execution.roles:
        for action in role.actions:
            expected = _TRANSPORT_FAULT_OUTCOMES.get(action.operation)
            if expected is None:
                continue
            kind, outcome = expected
            matches = [
                event
                for event in events
                if event.get("actor") == role.actor
                and event.get("kind") == kind
                and isinstance(event.get("attributes"), Mapping)
                and event["attributes"].get("action_id") == action.action_id
            ]
            label = f"{role.actor}:{action.action_id}:{action.operation}"
            if not matches:
                missing.append(label)
            elif not any(event.get("outcome") == outcome for event in matches):
                failed.append(label)
    if missing or failed:
        parts: list[str] = []
        if missing:
            parts.append("not applied=" + ", ".join(missing))
        if failed:
            parts.append("failed=" + ", ".join(failed))
        raise RunnerError("transport fault contract was not satisfied: " + "; ".join(parts))


def _transport_fault_provenance(
    role: RoleCommand,
    execution: ExecutionSpec,
    environment: Mapping[str, str],
) -> tuple[Path, dict[str, JsonValue]] | None:
    if not _uses_transport_faults(role):
        return None
    if execution.network != "loopback":
        raise RunnerError("transport fault actions are restricted to loopback scenarios")
    raw_path = environment.get(TRANSPORT_FAULT_LIBRARY_ENVIRONMENT)
    if not raw_path:
        raise RunnerError(
            f"role {role.actor} uses transport fault actions but "
            f"{TRANSPORT_FAULT_LIBRARY_ENVIRONMENT} is not set"
        )
    path = Path(raw_path)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RunnerError(f"cannot resolve transport fault library {path}: {error}") from error
    if not resolved.is_file():
        raise RunnerError(f"transport fault library is not a file: {resolved}")
    size = resolved.stat().st_size
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return resolved, {"name": resolved.name, "sha256": digest, "size": size}


def run_processes(
    execution: ExecutionSpec,
    run_dir: Path,
    environment: Mapping[str, str] | None = None,
    *,
    allow_external: bool = False,
    overwrite: bool = False,
    injected_role_environments: Mapping[str, Mapping[str, str]] | None = None,
    preserve_partial: bool = False,
) -> RunArtifacts:
    if execution.network != "loopback" and not allow_external:
        raise RunnerError(
            f"scenario requests network mode {execution.network!r}; pass explicit external authorization"
        )

    run_dir = run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    protected_outputs = [run_dir / "evidence.json", run_dir / "report.json"]
    if not overwrite and any(path.exists() for path in protected_outputs):
        raise RunnerError(f"run directory already contains results: {run_dir}")

    if environment is not None and ACTION_PLAN_ENVIRONMENT in environment:
        raise RunnerError(
            f"{ACTION_PLAN_ENVIRONMENT} is runner-reserved and cannot be supplied globally"
        )
    if environment is not None and TRANSPORT_FAULT_ENABLE_ENVIRONMENT in environment:
        raise RunnerError(
            f"{TRANSPORT_FAULT_ENABLE_ENVIRONMENT} is runner-reserved and cannot be supplied globally"
        )
    if environment is not None and FORCE_UDP_ONLY_ENVIRONMENT in environment:
        raise RunnerError(
            f"{FORCE_UDP_ONLY_ENVIRONMENT} is runner-reserved and cannot be supplied globally"
        )
    base_environment = dict(os.environ)
    # Never inherit a stale plan path from the parent shell. A plan exists only
    # when it was derived from this run's digested scenario.
    base_environment.pop(ACTION_PLAN_ENVIRONMENT, None)
    base_environment.pop(TRANSPORT_FAULT_ENABLE_ENVIRONMENT, None)
    base_environment.pop(FORCE_UDP_ONLY_ENVIRONMENT, None)
    base_environment.update(environment or {})
    base_environment["DDSLEUTH_RUN_DIR"] = str(run_dir)
    base_environment[FINGERPRINT_ENVIRONMENT] = secrets.token_hex(32)
    transport_experiment = any(_uses_transport_faults(role) for role in execution.roles)
    if transport_experiment:
        # Every participant must use the same transport topology.  Applying
        # LD_PRELOAD only to the mutating actor is still sufficient, but all
        # Fast DDS probes are forced away from SHM/DataSharing.
        base_environment[FORCE_UDP_ONLY_ENVIRONMENT] = "1"

    injected_role_environments = injected_role_environments or {}
    known_actors = {role.actor for role in execution.roles}
    unknown_injections = sorted(set(injected_role_environments) - known_actors)
    if unknown_injections:
        raise RunnerError(
            "injected environment references unknown actors: " + ", ".join(unknown_injections)
        )

    active: list[
        tuple[
            str,
            tuple[str, ...],
            Path,
            subprocess.Popen[bytes],
            object,
            tuple[str, str, int],
            Mapping[str, JsonValue] | None,
        ]
    ] = []
    monitor = StructuredLogMonitor()
    scenario_started = time.monotonic()
    deadline = time.monotonic() + execution.timeout_seconds
    partial_error: RunnerError | None = None
    try:
        for role in execution.roles:
            if FINGERPRINT_ENVIRONMENT in role.environment:
                raise RunnerError(
                    f"role {role.actor} may not override the shared run-local fingerprint secret"
                )
            if ACTION_PLAN_ENVIRONMENT in role.environment:
                raise RunnerError(
                    f"role {role.actor} may not override its runner-generated action plan"
                )
            if TRANSPORT_FAULT_ENABLE_ENVIRONMENT in role.environment:
                raise RunnerError(
                    f"role {role.actor} may not override runner-controlled transport faults"
                )
            if TRANSPORT_FAULT_LIBRARY_ENVIRONMENT in role.environment:
                raise RunnerError(
                    f"role {role.actor} may not select its own transport fault library"
                )
            if FORCE_UDP_ONLY_ENVIRONMENT in role.environment:
                raise RunnerError(
                    f"role {role.actor} may not override runner-controlled UDP-only mode"
                )
            if role.start_after:
                try:
                    wait_for_barriers(
                        role.start_after,
                        monitor,
                        {actor: log for actor, _, log, _, _, _, _ in active},
                        {actor: process for actor, _, _, process, _, _, _ in active},
                        deadline,
                    )
                except CoordinationError as error:
                    raise RunnerError(str(error)) from error
            launch_at = scenario_started + role.start_offset_ms / 1000.0
            while time.monotonic() < launch_at:
                try:
                    monitor.poll({actor: log for actor, _, log, _, _, _, _ in active})
                except CoordinationError as error:
                    raise RunnerError(str(error)) from error
                if time.monotonic() >= deadline:
                    raise RunnerError(
                        f"scenario exceeded {execution.timeout_seconds:g} seconds before "
                        f"starting {role.actor}"
                    )
                time.sleep(min(0.05, max(0.0, launch_at - time.monotonic())))
            role_environment = dict(base_environment)
            role_environment.update(
                {
                    key: _expand(value, base_environment, f"environment for {role.actor}")
                    for key, value in role.environment.items()
                }
            )
            role_environment.update(injected_role_environments.get(role.actor, {}))
            # Instrumentation obtains the normalized actor identity from the
            # runner, never from a role-controlled scenario value.
            role_environment["DDSLEUTH_ACTOR"] = role.actor
            action_plan = _write_action_plan(role, run_dir)
            if action_plan is not None:
                role_environment[ACTION_PLAN_ENVIRONMENT] = str(action_plan)
            transport_fault = _transport_fault_provenance(role, execution, role_environment)
            if transport_fault is not None:
                library, _ = transport_fault
                existing_preload = role_environment.get("LD_PRELOAD", "")
                if "ASAN_OPTIONS" in role_environment and "libasan" not in existing_preload:
                    # LD_PRELOAD libraries precede DT_NEEDED dependencies.  A
                    # sanitizer-instrumented probe therefore needs libasan
                    # explicitly restored to the first slot before our shim.
                    asan_runtime = ctypes.util.find_library("asan")
                    if asan_runtime:
                        existing_preload = (
                            f"{asan_runtime}:{existing_preload}"
                            if existing_preload
                            else asan_runtime
                        )
                    else:
                        options = role_environment.get("ASAN_OPTIONS", "")
                        if "verify_asan_link_order=" not in options:
                            role_environment["ASAN_OPTIONS"] = (
                                f"{options}:verify_asan_link_order=0"
                                if options
                                else "verify_asan_link_order=0"
                            )
                role_environment["LD_PRELOAD"] = (
                    f"{existing_preload}:{library}" if existing_preload else str(library)
                )
                role_environment[TRANSPORT_FAULT_ENABLE_ENVIRONMENT] = "1"
            command = tuple(
                _expand(value, role_environment, f"command for {role.actor}")
                for value in role.command
            )
            provenance = _executable_provenance(command, role_environment)
            log_path = run_dir / f"{role.actor}.log"
            log_handle = log_path.open("wb")
            try:
                process = subprocess.Popen(
                    command,
                    cwd=run_dir,
                    env=role_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    start_new_session=True,
                )
            except Exception:
                log_handle.close()
                raise
            active.append((
                role.actor,
                command,
                log_path,
                process,
                log_handle,
                provenance,
                transport_fault[1] if transport_fault is not None else None,
            ))

        while any(process.poll() is None for _, _, _, process, _, _, _ in active):
            try:
                monitor.poll({actor: log for actor, _, log, _, _, _, _ in active})
            except CoordinationError as error:
                raise RunnerError(str(error)) from error
            if time.monotonic() >= deadline:
                raise RunnerError(f"scenario exceeded {execution.timeout_seconds:g} seconds")
            time.sleep(0.05)

        try:
            monitor.poll({actor: log for actor, _, log, _, _, _, _ in active})
        except CoordinationError as error:
            raise RunnerError(str(error)) from error
        _validate_transport_fault_actions(execution, monitor.events)

    except RunnerError as error:
        if not preserve_partial or not active:
            raise
        partial_error = error
    finally:
        if partial_error is not None:
            for _, _, _, process, _, _, _ in active:
                if process.poll() is None:
                    process.terminate()
            for _, _, _, process, _, _, _ in active:
                if process.poll() is None:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        for _, _, _, process, log_handle, _, _ in active:
            if process.poll() is None:
                process.kill()
                process.wait()
            log_handle.close()

    if partial_error is not None:
        try:
            monitor.poll({actor: log for actor, _, log, _, _, _, _ in active})
        except CoordinationError:
            pass

    if execution.log_format == "ddssec-jsonl":
        for _, _, log_path, _, _, _, _ in active:
            _compact_structured_log(log_path)

    processes = tuple(
        ProcessRun(
            actor,
            command,
            log_path,
            int(process.returncode),
            provenance[0],
            provenance[1],
            provenance[2],
            transport_fault,
        )
        for actor, command, log_path, process, _, provenance, transport_fault in active
    )
    status_path = run_dir / "process-status.json"
    status_path.write_text(
        json.dumps({item.actor: item.exit_code for item in processes}, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    error_record: dict[str, JsonValue] | None = None
    if partial_error is not None:
        launched = [item.actor for item in processes]
        affected_actors = [
            role.actor
            for role in execution.roles
            if _uses_transport_faults(role)
        ]
        error_record = {
            "type": type(partial_error).__name__,
            "message": str(partial_error),
            "launched_actors": launched,
            "pending_actors": [
                role.actor for role in execution.roles if role.actor not in set(launched)
            ],
        }
        if affected_actors:
            error_record["affected_actors"] = affected_actors
        (run_dir / "runner-error.json").write_text(
            json.dumps(error_record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return RunArtifacts(
        run_dir=run_dir,
        processes=processes,
        structured_events=monitor.events,
        error=error_record,
    )
