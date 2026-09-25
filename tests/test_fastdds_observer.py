from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("g++"), "g++ is required for the Fast DDS observer test")
class FastDDSObserverTests(unittest.TestCase):
    def test_emits_routing_and_run_local_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "observer-test"
            compile_result = subprocess.run(
                [
                    "g++",
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wno-deprecated-declarations",
                    "-I",
                    str(ROOT / "probes/common"),
                    "-I",
                    str(ROOT / "probes/fastdds_instrumentation"),
                    str(ROOT / "tests/cpp/test_fastdds_observer.cpp"),
                    "-lcrypto",
                    "-o",
                    str(binary),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if compile_result.returncode != 0 and (
                "openssl/crypto.h: No such file" in compile_result.stderr
                or "cannot find -lcrypto" in compile_result.stderr
            ):
                if os.environ.get("DDSLEUTH_REQUIRE_NATIVE_TESTS") == "1":
                    self.fail(compile_result.stderr)
                self.skipTest("OpenSSL development headers are unavailable")
            self.assertEqual(0, compile_result.returncode, compile_result.stderr)
            completed = subprocess.run(
                [str(binary)],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        events = [
            json.loads(line.removeprefix("DDSLEUTH_EVENT "))
            for line in completed.stderr.splitlines()
            if line.startswith("DDSLEUTH_EVENT ")
        ]
        self.assertEqual(7, len(events))
        self.assertEqual(
            [
                "crypto_token.generated",
                "key_material.observed",
                "key_material.observed",
                "crypto_token.observed",
                "key_material.observed",
                "key_material.observed",
                "key.rotated",
            ],
            [event["kind"] for event in events],
        )
        fingerprints = [
            event["attributes"]["key_fingerprint"]
            for event in events
            if event["kind"] == "key_material.observed"
        ]
        self.assertEqual(fingerprints[0], fingerprints[2])
        self.assertEqual(fingerprints[1], fingerprints[3])
        self.assertTrue(fingerprints[0].startswith("hmac-sha256-run-local-v1:"))
        self.assertEqual("sender", events[1]["attributes"]["key_class"])
        self.assertEqual("receiver_specific", events[2]["attributes"]["key_class"])
        self.assertEqual("alice", events[0]["actor"])
        self.assertEqual("user", events[0]["attributes"]["endpoint_class"])
        self.assertEqual("serialized_payload", events[-1]["attributes"]["context"])
        self.assertEqual(42, events[-1]["attributes"]["session_id"])


if __name__ == "__main__":
    unittest.main()
