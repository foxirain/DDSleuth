from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ddsleuth.fingerprints import FingerprintError, RunLocalFingerprinter


ROOT = Path(__file__).resolve().parents[1]


class FingerprintTests(unittest.TestCase):
    def test_same_run_compares_keys_without_exposing_them(self) -> None:
        first_run = RunLocalFingerprinter(bytes.fromhex("11" * 32))
        second_run = RunLocalFingerprinter(bytes.fromhex("22" * 32))
        key = b"not stored in evidence"
        self.assertEqual(first_run.fingerprint(key), first_run.fingerprint(key))
        self.assertNotEqual(first_run.fingerprint(key), first_run.fingerprint(key + b"!"))
        self.assertNotEqual(first_run.fingerprint(key), second_run.fingerprint(key))
        self.assertNotIn(key.hex(), first_run.fingerprint(key))

    def test_rejects_invalid_secret(self) -> None:
        with self.assertRaisesRegex(FingerprintError, "exactly 32 bytes"):
            RunLocalFingerprinter.from_hex("00")

    @unittest.skipUnless(shutil.which("g++"), "g++ is required for the native probe test")
    def test_cpp_and_python_fingerprints_match(self) -> None:
        secret = "42" * 32
        expected = RunLocalFingerprinter.from_hex(secret).fingerprint(
            b"same cryptographic key"
        )
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fingerprint-test"
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
                    str(ROOT / "tests/cpp/test_fingerprint.cpp"),
                    "-lcrypto",
                    "-o",
                    str(binary),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if compile_result.returncode != 0 and (
                "cannot find -lcrypto" in compile_result.stderr
                or "openssl/crypto.h: No such file" in compile_result.stderr
            ):
                if os.environ.get("DDSLEUTH_REQUIRE_NATIVE_TESTS") == "1":
                    self.fail(compile_result.stderr)
                self.skipTest("OpenSSL development headers or library are unavailable")
            self.assertEqual(0, compile_result.returncode, compile_result.stderr)
            environment = dict(os.environ)
            environment["DDSLEUTH_FINGERPRINT_SECRET"] = secret
            completed = subprocess.run(
                [str(binary)],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        self.assertEqual(expected, completed.stdout.strip())


if __name__ == "__main__":
    unittest.main()
