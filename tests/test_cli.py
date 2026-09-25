from __future__ import annotations

import contextlib
import io
import unittest

from ddsleuth import __version__
from ddsleuth.cli import main


class CliTests(unittest.TestCase):
    def test_version_matches_package(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--version"])
        self.assertEqual(0, raised.exception.code)
        self.assertEqual(f"ddsleuth {__version__}\n", output.getvalue())


if __name__ == "__main__":
    unittest.main()
