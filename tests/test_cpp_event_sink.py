from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ddsleuth.adapters.fastdds import FastDDSLegacyTextImporter


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("g++"), "g++ is required for the native probe test")
class NativeEventSinkTests(unittest.TestCase):
    def test_emits_valid_importable_json_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "event-sink-test"
            subprocess.run(
                [
                    "g++",
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "probes/common"),
                    str(ROOT / "tests/cpp/test_event_sink.cpp"),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            completed = subprocess.run(
                [str(binary)],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        self.assertTrue(completed.stdout.startswith("DDSLEUTH_EVENT "))
        raw = json.loads(completed.stdout.removeprefix("DDSLEUTH_EVENT "))
        self.assertEqual("SecretTopic\nquoted\"", raw["attributes"]["resource"])
        self.assertIsInstance(raw["monotonic_ns"], int)
        self.assertGreater(raw["monotonic_ns"], 0)

        events = FastDDSLegacyTextImporter().parse_text(
            "mallory",
            completed.stdout,
            "native-probe.log",
        )
        self.assertEqual(1, len(events))
        self.assertEqual("mallory", events[0].actor)
        self.assertEqual("denied", events[0].outcome)
        self.assertEqual(222, events[0].attributes["domain_id"])


if __name__ == "__main__":
    unittest.main()
