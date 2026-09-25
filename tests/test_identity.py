from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ddsleuth.identity import IdentityError, materialize_identities
from ddsleuth.scenario import load_scenario, parse_scenario


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("openssl"), "openssl is required for identity tests")
class IdentityTests(unittest.TestCase):
    def test_materializes_verified_ephemeral_identities(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/three_party_recipient_binding.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            artifacts = materialize_identities(scenario, Path(directory))
            self.assertEqual(set(scenario.participants), set(artifacts.participants))
            self.assertEqual(64, len(artifacts.ca_certificate_sha256))
            self.assertEqual(
                "O=DDSleuth,CN=mallory",
                artifacts.participants["mallory"].subject_name,
            )
            permissions = os.stat(artifacts.participants["mallory"].private_key).st_mode & 0o777
            self.assertEqual(0o600, permissions)
            manifest = json.loads(artifacts.manifest.read_text())
            self.assertNotIn("private", json.dumps(manifest).lower())

    def test_preserves_deliberate_subject_collision(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["participants"]["mallory"]["identity"]["subject"] = "/CN=collision"
        raw["participants"]["bob"]["identity"]["subject"] = "/CN=collision"
        scenario = parse_scenario(raw)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = materialize_identities(scenario, Path(directory))
            self.assertEqual(
                artifacts.participants["mallory"].subject_name,
                artifacts.participants["bob"].subject_name,
            )
            self.assertNotEqual(
                artifacts.participants["mallory"].certificate_sha256,
                artifacts.participants["bob"].certificate_sha256,
            )

    def test_refuses_nonempty_output(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/three_party_recipient_binding.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "existing").write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(IdentityError, "not empty"):
                materialize_identities(scenario, output)

    def test_rejects_non_slash_subject(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["participants"]["mallory"]["identity"]["subject"] = "CN=mallory"
        scenario = parse_scenario(raw)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(IdentityError, "slash-form"):
                materialize_identities(scenario, Path(directory))

    def test_generates_second_granularity_expiring_certificate(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["participants"]["mallory"]["identity"]["expires_after_seconds"] = 60
        scenario = parse_scenario(raw)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = materialize_identities(scenario, Path(directory))
            completed = subprocess.run(
                [
                    "openssl", "x509", "-in",
                    str(artifacts.participants["mallory"].certificate),
                    "-noout", "-checkend", "120",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(0, completed.returncode)


if __name__ == "__main__":
    unittest.main()
