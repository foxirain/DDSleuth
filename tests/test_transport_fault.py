from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ddsleuth.models import ExecutionSpec, RoleAction, RoleCommand
from ddsleuth.runner import TRANSPORT_FAULT_LIBRARY_ENVIRONMENT, run_processes


@unittest.skipUnless(shutil.which("g++"), "g++ is required for transport shim tests")
class TransportFaultTests(unittest.TestCase):
    def test_replays_exact_loopback_datagram(self) -> None:
        try:
            capability_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            capability_probe.close()
        except PermissionError:
            self.skipTest("sandbox does not permit IPv4 sockets")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "libddsleuth_transport_fault.so"
            source = Path(__file__).parents[1] / "probes" / "transport_fault" / "transport_fault.cpp"
            subprocess.run(
                [
                    "g++", "-std=c++17", "-fPIC", "-shared", str(source),
                    "-ldl", "-pthread", "-o", str(library),
                ],
                check=True,
            )
            script = (
                "import socket; "
                "r=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                "r.bind(('127.0.0.1',0)); r.settimeout(2); "
                "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                "s.sendto(b'wire-image',r.getsockname()); "
                "a=r.recvfrom(128)[0]; b=r.recvfrom(128)[0]; "
                "assert a == b == b'wire-image'"
            )
            execution = ExecutionSpec(
                network="loopback",
                timeout_seconds=5,
                log_format="ddssec-jsonl",
                roles=(
                    RoleCommand(
                        actor="alice",
                        command=(sys.executable, "-c", script),
                        actions=(RoleAction("replay", 50, "transport.replay_last", ("1",)),),
                    ),
                ),
            )
            artifacts = run_processes(
                execution,
                root / "run",
                {TRANSPORT_FAULT_LIBRARY_ENVIRONMENT: str(library)},
            )
            self.assertEqual({"alice": 0}, artifacts.statuses)
            self.assertTrue(
                any(
                    event.get("kind") == "transport.datagram_replayed"
                    for event in artifacts.structured_events
                )
            )
            self.assertIsNotNone(artifacts.processes[0].transport_fault_library)


if __name__ == "__main__":
    unittest.main()
