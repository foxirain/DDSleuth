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
from .models import ExecutionSpec, JsonValue
from .fingerprints import FINGERPRINT_ENVIRONMENT


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


def run_processes(
    execution: ExecutionSpec,
    run_dir: Path,
    environment: Mapping[str, str] | None = None,
    *,
    allow_external: bool = False,
    overwrite: bool = False,
    injected_role_environments: Mapping[str, Mapping[str, str]] | None = None,
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

    base_environment = dict(os.environ)
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
    deadline = time.monotonic() + execution.timeout_seconds
    try:
        for role in execution.roles:
            if FINGERPRINT_ENVIRONMENT in role.environment:
                raise RunnerError(
                    f"role {role.actor} may not override the shared run-local fingerprint secret"
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
                for _, _, _, process, _, _ in active:
                    if process.poll() is None:
                        process.terminate()
                try:
                    for _, _, _, process, _, _ in active:
                        process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    for _, _, _, process, _, _ in active:
                        if process.poll() is None:
                            process.kill()
                raise RunnerError(f"scenario exceeded {execution.timeout_seconds:g} seconds")
            time.sleep(0.05)

        try:
            monitor.poll({actor: log for actor, _, log, _, _, _ in active})
        except CoordinationError as error:
            raise RunnerError(str(error)) from error

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
        return RunArtifacts(
            run_dir=run_dir,
            processes=processes,
            structured_events=monitor.events,
        )
    finally:
        for _, _, _, process, log_handle, _ in active:
            if process.poll() is None:
                process.kill()
                process.wait()
            log_handle.close()
