from __future__ import annotations

import json
import hashlib
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
    base_environment = dict(os.environ)
    # Never inherit a stale plan path from the parent shell. A plan exists only
    # when it was derived from this run's digested scenario.
    base_environment.pop(ACTION_PLAN_ENVIRONMENT, None)
    base_environment.update(environment or {})
    base_environment["DDSLEUTH_RUN_DIR"] = str(run_dir)
    base_environment[FINGERPRINT_ENVIRONMENT] = secrets.token_hex(32)

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
            if role.start_after:
                try:
                    wait_for_barriers(
                        role.start_after,
                        monitor,
                        {actor: log for actor, _, log, _, _, _ in active},
                        {actor: process for actor, _, _, process, _, _ in active},
                        deadline,
                    )
                except CoordinationError as error:
                    raise RunnerError(str(error)) from error
            launch_at = scenario_started + role.start_offset_ms / 1000.0
            while time.monotonic() < launch_at:
                try:
                    monitor.poll({actor: log for actor, _, log, _, _, _ in active})
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
            active.append((role.actor, command, log_path, process, log_handle, provenance))

        while any(process.poll() is None for _, _, _, process, _, _ in active):
            try:
                monitor.poll({actor: log for actor, _, log, _, _, _ in active})
            except CoordinationError as error:
                raise RunnerError(str(error)) from error
            if time.monotonic() >= deadline:
                raise RunnerError(f"scenario exceeded {execution.timeout_seconds:g} seconds")
            time.sleep(0.05)

        try:
            monitor.poll({actor: log for actor, _, log, _, _, _ in active})
        except CoordinationError as error:
            raise RunnerError(str(error)) from error

    except RunnerError as error:
        if not preserve_partial or not active:
            raise
        partial_error = error
    finally:
        if partial_error is not None:
            for _, _, _, process, _, _ in active:
                if process.poll() is None:
                    process.terminate()
            for _, _, _, process, _, _ in active:
                if process.poll() is None:
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        for _, _, _, process, log_handle, _ in active:
            if process.poll() is None:
                process.kill()
                process.wait()
            log_handle.close()

    if partial_error is not None:
        try:
            monitor.poll({actor: log for actor, _, log, _, _, _ in active})
        except CoordinationError:
            pass

    processes = tuple(
        ProcessRun(
            actor,
            command,
            log_path,
            int(process.returncode),
            provenance[0],
            provenance[1],
            provenance[2],
        )
        for actor, command, log_path, process, _, provenance in active
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
        error_record = {
            "type": type(partial_error).__name__,
            "message": str(partial_error),
            "launched_actors": launched,
            "pending_actors": [
                role.actor for role in execution.roles if role.actor not in set(launched)
            ],
        }
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
