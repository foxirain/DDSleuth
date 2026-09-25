from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ddsleuth.matrix import MatrixError, expand_matrix, parse_dimension, write_matrix
from ddsleuth.scenario import load_scenario


ROOT = Path(__file__).resolve().parents[1]


class MatrixTests(unittest.TestCase):
    def test_expands_cartesian_matrix_and_writes_manifest(self) -> None:
        base = ROOT / "examples/fastdds/three_party_recipient_binding.json"
        dimensions = [
            parse_dimension('governance.rtps_protection=["sign","encrypt"]'),
            parse_dimension(
                'topics.SecretTopic.metadata_protection=["sign","encrypt_with_origin_authentication"]'
            ),
        ]
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = write_matrix(base, Path(directory), dimensions)
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(4, manifest["case_count"])
            scenario_files = sorted(Path(directory).glob("*.json"))
            self.assertEqual(5, len(scenario_files))
            for case in manifest["cases"]:
                scenario = load_scenario(Path(directory) / case["file"])
                self.assertEqual(case["digest"], scenario.digest)

    def test_enforces_case_limit(self) -> None:
        base = ROOT / "examples/fastdds/three_party_recipient_binding.json"
        dimensions = [
            parse_dimension('governance.rtps_protection=["none","sign","encrypt"]'),
            parse_dimension('topics.SecretTopic.data_protection=["none","sign","encrypt"]'),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MatrixError, "exceeding limit"):
                write_matrix(base, Path(directory), dimensions, max_cases=8)

    def test_rejects_missing_path(self) -> None:
        base = ROOT / "examples/fastdds/three_party_recipient_binding.json"
        dimensions = [parse_dimension('topics.SecretTopic.missing=[true,false]')]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MatrixError, "does not exist"):
                write_matrix(base, Path(directory), dimensions)

    def test_pairwise_strategy_covers_every_value_pair(self) -> None:
        base_path = ROOT / "examples/fastdds/three_party_recipient_binding.json"
        raw = json.loads(base_path.read_text())
        dimensions = (
            parse_dimension('governance.rtps_protection=["none","sign","encrypt"]'),
            parse_dimension('governance.discovery_protection=["none","sign","encrypt"]'),
            parse_dimension('governance.liveliness_protection=["none","sign","encrypt"]'),
            parse_dimension('topics.SecretTopic.data_protection=["none","sign","encrypt"]'),
        )
        cases = expand_matrix(raw, dimensions, strategy="pairwise", max_cases=30)
        self.assertLess(len(cases), 3**4)
        assignments = [case[1] for case in cases]
        for left in range(len(dimensions)):
            for right in range(left + 1, len(dimensions)):
                observed = {
                    (
                        assignment[dimensions[left].dotted_path],
                        assignment[dimensions[right].dotted_path],
                    )
                    for assignment in assignments
                }
                expected = {
                    (left_value, right_value)
                    for left_value in dimensions[left].values
                    for right_value in dimensions[right].values
                }
                self.assertEqual(expected, observed)

    def test_pairwise_strategy_is_deterministic(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        dimensions = (
            parse_dimension('governance.rtps_protection=["none","sign","encrypt"]'),
            parse_dimension('governance.discovery_protection=["none","sign","encrypt"]'),
            parse_dimension('governance.liveliness_protection=["none","sign","encrypt"]'),
        )
        first = expand_matrix(raw, dimensions, strategy="pairwise")
        second = expand_matrix(raw, dimensions, strategy="pairwise")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
