from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ddsleuth.scenario import ScenarioError, load_scenario, parse_scenario


ROOT = Path(__file__).resolve().parents[1]


class ScenarioTests(unittest.TestCase):
    def test_example_is_valid_and_stable(self) -> None:
        scenario = load_scenario(ROOT / "examples/fastdds/three_party_recipient_binding.json")
        self.assertEqual("fastdds-three-party-recipient-binding", scenario.scenario_id)
        self.assertEqual("fastdds", scenario.implementation)
        self.assertEqual(3, len(scenario.participants))
        self.assertEqual(3, len(scenario.assertions))
        self.assertEqual(64, len(scenario.digest))

    def test_native_secure_delivery_example_is_valid(self) -> None:
        scenario = load_scenario(ROOT / "examples/fastdds/native_secure_delivery.json")
        self.assertEqual("fastdds-native-secure-delivery", scenario.scenario_id)
        self.assertEqual(("reader", "writer"), scenario.grant_order)
        self.assertEqual(1, len(scenario.execution.roles[1].start_after))

    def test_native_key_distribution_example_is_valid(self) -> None:
        scenario = load_scenario(ROOT / "examples/fastdds/native_key_distribution.json")
        self.assertEqual("fastdds-native-key-distribution", scenario.scenario_id)
        self.assertEqual(5, len(scenario.assertions))
        self.assertEqual(
            "crypto_token_transport_consistency",
            scenario.assertions[3].oracle,
        )

    def test_native_denied_observer_example_is_valid(self) -> None:
        scenario = load_scenario(ROOT / "examples/fastdds/native_denied_observer.json")
        self.assertEqual("fastdds-native-denied-observer", scenario.scenario_id)
        self.assertEqual(3, len(scenario.participants))
        self.assertEqual("unauthorized_key_disclosure", scenario.assertions[2].oracle)

    def test_native_multi_recipient_example_is_valid(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_multi_recipient_distribution.json"
        )
        self.assertEqual(
            "fastdds-native-multi-recipient-distribution",
            scenario.scenario_id,
        )
        self.assertEqual(2, len(scenario.execution.roles[2].start_after))

    def test_native_endpoint_recreation_example_is_valid(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_endpoint_recreation.json"
        )
        self.assertEqual("fastdds-native-endpoint-recreation", scenario.scenario_id)
        self.assertEqual("recreate-writer", scenario.execution.roles[1].command[2])
        self.assertEqual("endpoint_key_lifecycle", scenario.assertions[-1].oracle)

    def test_native_late_denied_join_example_is_valid(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_late_denied_join.json"
        )
        self.assertEqual("fastdds-native-late-denied-join", scenario.scenario_id)
        self.assertEqual("late_denied", scenario.execution.roles[2].actor)
        self.assertEqual(
            "application.sample_written",
            scenario.execution.roles[2].start_after[0].kind,
        )

    def test_native_session_rotation_example_is_valid(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_session_rotation.json"
        )
        self.assertEqual("fastdds-native-session-rotation", scenario.scenario_id)
        self.assertEqual("session_rotation_delivery", scenario.assertions[-1].oracle)
        self.assertEqual(
            "6",
            scenario.execution.roles[1].environment["DDSLEUTH_SAMPLE_COUNT"],
        )

    def test_native_scripted_lifecycle_example_is_valid(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_scripted_lifecycle.json"
        )
        writer = scenario.execution.roles[1]
        self.assertEqual("scripted-writer", writer.command[2])
        self.assertEqual(7, len(writer.actions))
        self.assertEqual("endpoint.destroy", writer.actions[3].operation)

    def test_duplicate_assertion_id_is_rejected(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"].append(dict(raw["assertions"][0]))
        with self.assertRaisesRegex(ScenarioError, "duplicate assertion id"):
            parse_scenario(raw)

    def test_unknown_execution_actor_is_rejected(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["execution"]["roles"][0]["actor"] = "eve"
        with self.assertRaisesRegex(ScenarioError, "unknown actor"):
            parse_scenario(raw)

    def test_participant_name_cannot_escape_run_directory(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        participant = raw["participants"].pop("mallory")
        raw["participants"]["../mallory"] = participant
        raw["policy"]["grant_order"][0] = "../mallory"
        raw["execution"]["roles"][0]["actor"] = "../mallory"
        with self.assertRaisesRegex(ScenarioError, "filesystem-safe"):
            parse_scenario(raw)

    def test_barrier_must_reference_earlier_role(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["execution"]["roles"][0]["start_after"] = [
            {"actor": "bob", "kind": "probe.ready"}
        ]
        with self.assertRaisesRegex(ScenarioError, "earlier execution role"):
            parse_scenario(raw)

    def test_grant_order_is_an_exact_participant_permutation(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["policy"]["grant_order"] = ["mallory", "bob"]
        with self.assertRaisesRegex(ScenarioError, "every participant exactly once"):
            parse_scenario(raw)

    def test_role_actions_are_parsed_and_ordered(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["execution"]["roles"][0]["actions"] = [
            {"id": "create", "at_ms": 0, "operation": "endpoint.create"},
            {
                "id": "write",
                "at_ms": 12.5,
                "operation": "sample.write",
                "arguments": ["payload"],
            },
        ]
        scenario = parse_scenario(raw)
        actions = scenario.execution.roles[0].actions
        self.assertEqual(("create", "write"), tuple(action.action_id for action in actions))
        self.assertEqual(("payload",), actions[1].arguments)

    def test_role_actions_reject_time_reversal(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["execution"]["roles"][0]["actions"] = [
            {"id": "later", "at_ms": 10, "operation": "endpoint.create"},
            {"id": "earlier", "at_ms": 5, "operation": "endpoint.destroy"},
        ]
        with self.assertRaisesRegex(ScenarioError, "ordered by at_ms"):
            parse_scenario(raw)


if __name__ == "__main__":
    unittest.main()
