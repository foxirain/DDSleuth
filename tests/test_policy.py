from __future__ import annotations

import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from ddsleuth.policy import PolicyError, materialize_policies
from ddsleuth.scenario import load_scenario


ROOT = Path(__file__).resolve().parents[1]


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = load_scenario(
            ROOT / "examples/fastdds/three_party_recipient_binding.json"
        )
        self.subjects = {
            "mallory": "CN=mallory, O=DDSleuth",
            "bob": "CN=bob, O=DDSleuth",
            "alice": "CN=alice, O=DDSleuth",
        }

    def test_materializes_governance_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = materialize_policies(
                self.scenario,
                Path(directory),
                self.subjects,
            )
            governance = ET.parse(artifacts.governance_xml).getroot()
            permissions = ET.parse(artifacts.permissions_xml).getroot()

            self.assertEqual(
                "222",
                governance.findtext("./domain_access_rules/domain_rule/domains/id"),
            )
            topic_names = [
                element.text
                for element in governance.findall(
                    "./domain_access_rules/domain_rule/topic_access_rules/topic_rule/topic_expression"
                )
            ]
            self.assertEqual(["SecretTopic", "DecoyTopic"], topic_names)
            grants = permissions.findall("./permissions/grant")
            self.assertEqual(3, len(grants))
            self.assertEqual(
                [self.subjects["mallory"], self.subjects["bob"], self.subjects["alice"]],
                [grant.findtext("subject_name") for grant in grants],
            )
            self.assertEqual(64, len(artifacts.digests["governance.xml"]))
            self.assertIsNone(artifacts.governance_smime)

    def test_requires_exact_subject_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(PolicyError, "missing subject names for: mallory"):
                materialize_policies(
                    self.scenario,
                    Path(directory),
                    {"alice": self.subjects["alice"], "bob": self.subjects["bob"]},
                )

    def test_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            materialize_policies(self.scenario, output, self.subjects)
            with self.assertRaisesRegex(PolicyError, "already exists"):
                materialize_policies(self.scenario, output, self.subjects)

    def test_respects_explicit_grant_order(self) -> None:
        import json

        from ddsleuth.scenario import parse_scenario

        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["policy"]["grant_order"] = ["bob", "mallory", "alice"]
        scenario = parse_scenario(raw)
        with tempfile.TemporaryDirectory() as directory:
            artifacts = materialize_policies(scenario, Path(directory), self.subjects)
            grants = ET.parse(artifacts.permissions_xml).getroot().findall("./permissions/grant")
            self.assertEqual(
                [self.subjects["bob"], self.subjects["mallory"], self.subjects["alice"]],
                [grant.findtext("subject_name") for grant in grants],
            )


if __name__ == "__main__":
    unittest.main()
