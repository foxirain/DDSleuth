from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path

from ddsleuth.models import EventBarrier, ExecutionSpec, RoleCommand
from ddsleuth.fingerprints import FINGERPRINT_ENVIRONMENT
from ddsleuth.runner import RunnerError, run_processes


class RunnerTests(unittest.TestCase):
    def test_refuses_non_loopback_without_explicit_authorization(self) -> None:
        execution = ExecutionSpec(
            network="external",
            timeout_seconds=1,
            log_format="ddssec-jsonl",
            roles=(RoleCommand(actor="mallory", command=("/bin/true",)),),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RunnerError, "explicit external authorization"):
                run_processes(execution, Path(directory))

    def test_runs_commands_without_shell(self) -> None:
        execution = ExecutionSpec(
            network="loopback",
            timeout_seconds=5,
            log_format="ddssec-jsonl",
            roles=(
                RoleCommand(
                    actor="mallory",
                    command=("/bin/echo", "literal;not-a-shell-command"),
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            artifacts = run_processes(execution, Path(directory))
            self.assertEqual({"mallory": 0}, artifacts.statuses)
            self.assertEqual("echo", artifacts.processes[0].executable_name)
            self.assertEqual(64, len(artifacts.processes[0].executable_sha256))
            self.assertGreater(artifacts.processes[0].executable_size, 0)
            self.assertEqual(
                "literal;not-a-shell-command",
                artifacts.logs["mallory"].read_text().strip(),
            )

    def test_role_cannot_replace_shared_fingerprint_secret(self) -> None:
        execution = ExecutionSpec(
            network="loopback",
            timeout_seconds=1,
            log_format="ddssec-jsonl",
            roles=(
                RoleCommand(
                    actor="mallory",
                    command=("/bin/true",),
                    environment={FINGERPRINT_ENVIRONMENT: "00" * 32},
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RunnerError, "may not override"):
                run_processes(execution, Path(directory))

    def test_runner_binds_actor_environment(self) -> None:
        execution = ExecutionSpec(
            network="loopback",
            timeout_seconds=5,
            log_format="ddssec-jsonl",
            roles=(
                RoleCommand(
                    actor="alice",
                    command=(
                        sys.executable,
                        "-c",
                        "import os; print(os.environ['DDSLEUTH_ACTOR'])",
                    ),
                    environment={"DDSLEUTH_ACTOR": "spoofed"},
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            artifacts = run_processes(execution, Path(directory))
            self.assertEqual(
                "alice",
                artifacts.logs["alice"].read_text(encoding="utf-8").strip(),
            )

    def test_starts_role_after_structured_event_barrier(self) -> None:
        ready = (
            'DDSLEUTH_EVENT {"kind":"probe.ready","actor":"first",'
            '"implementation":"test","outcome":"ready","attributes":{"phase":2}}'
        )
        execution = ExecutionSpec(
            network="loopback",
            timeout_seconds=2,
            log_format="ddssec-jsonl",
            roles=(
                RoleCommand(actor="first", command=("/bin/echo", ready)),
                RoleCommand(
                    actor="second",
                    command=("/bin/true",),
                    start_after=(
                        EventBarrier(
                            actor="first",
                            kind="probe.ready",
                            outcome="ready",
                            attributes={"phase": 2},
                        ),
                    ),
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            artifacts = run_processes(execution, Path(directory))
            self.assertEqual({"first": 0, "second": 0}, artifacts.statuses)
            self.assertEqual(1, len(artifacts.structured_events))

    def test_missing_barrier_fails_instead_of_sleeping(self) -> None:
        execution = ExecutionSpec(
            network="loopback",
            timeout_seconds=1,
            log_format="ddssec-jsonl",
            roles=(
                RoleCommand(actor="first", command=("/bin/true",)),
                RoleCommand(
                    actor="second",
                    command=("/bin/true",),
                    start_after=(EventBarrier(actor="first", kind="probe.ready"),),
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RunnerError, "exited before emitting"):
                run_processes(execution, Path(directory))


if __name__ == "__main__":
    unittest.main()
