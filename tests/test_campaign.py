from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ddsleuth.campaign import (
    CampaignError,
    IdentityMaterializationConfig,
    PolicyMaterializationConfig,
    load_manifest,
    run_campaign,
)
from ddsleuth.matrix import parse_dimension, write_matrix


def _scenario() -> dict[str, object]:
    event = {
        "kind": "crypto_token.observed",
        "actor": "observer",
        "implementation": "fastdds",
        "outcome": "observed",
        "attributes": {
            "token_class": "datawriter",
            "local_participant_guid": "same",
            "destination_participant_guid": "same",
        },
    }
    return {
        "schema_version": 1,
        "id": "campaign-base",
        "title": "Campaign base",
        "implementation": {"name": "fastdds", "version": "test"},
        "domain_id": 0,
        "participants": {
            "observer": {"role": "observer", "permissions": {}},
            "peer": {"role": "peer", "permissions": {}},
        },
        "governance": {"rtps_protection": "sign"},
        "topics": {},
        "assertions": [
            {
                "id": "recipient-binding",
                "oracle": "crypto_token_recipient_binding",
                "parameters": {"observer": "observer", "token_class": "datawriter"},
            }
        ],
        "execution": {
            "network": "loopback",
            "timeout_seconds": 5,
            "log_format": "ddssec-jsonl",
            "roles": [
                {
                    "actor": "observer",
                    "command": ["/bin/echo", "DDSLEUTH_EVENT " + json.dumps(event)],
                }
            ],
        },
    }


class CampaignTests(unittest.TestCase):
    def test_runs_and_resumes_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            base.write_text(json.dumps(_scenario()), encoding="utf-8")
            manifest = write_matrix(
                base,
                root / "matrix",
                [parse_dimension('governance.rtps_protection=["sign","encrypt"]')],
            )
            report = run_campaign(
                manifest,
                root / "runs",
                {},
                allow_unbound_configuration=True,
            )
            self.assertEqual(2, report.counts["completed"])
            self.assertEqual(2, report.counts["pass"])
            self.assertEqual(0, report.counts["error"])

            resumed = run_campaign(
                manifest,
                root / "runs",
                {},
                resume=True,
                allow_unbound_configuration=True,
            )
            self.assertTrue(all(case.resumed for case in resumed.cases))

    def test_repetitions_produce_reliability_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            base.write_text(json.dumps(_scenario()), encoding="utf-8")
            manifest = write_matrix(
                base,
                root / "matrix",
                [parse_dimension('governance.rtps_protection=["sign"]')],
            )
            report = run_campaign(
                manifest,
                root / "runs",
                {},
                allow_unbound_configuration=True,
                repetitions=3,
            )
            self.assertEqual(1, report.case_count)
            self.assertEqual(3, report.trial_count)
            self.assertEqual(3, report.counts["pass"])
            summary = report.scenario_summaries[0]
            self.assertEqual(3, summary["observed_trials"])
            self.assertEqual(0.0, summary["violation_rate"])
            self.assertFalse(summary["flaky"])
            self.assertEqual({0, 1, 2}, {case.repetition for case in report.cases})

    def test_policy_matrix_refuses_unbound_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            base.write_text(json.dumps(_scenario()), encoding="utf-8")
            manifest = write_matrix(
                base,
                root / "matrix",
                [parse_dimension('governance.rtps_protection=["sign"]')],
            )
            report = run_campaign(manifest, root / "runs", {})
            self.assertEqual(1, report.counts["error"])
            self.assertIn("policy-related matrix", report.cases[0].error["message"])

    def test_identity_matrix_refuses_policy_only_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            raw = _scenario()
            raw["participants"]["observer"]["identity"] = {"subject": "/CN=observer"}
            raw["participants"]["peer"]["identity"] = {"subject": "/CN=peer"}
            base.write_text(json.dumps(raw), encoding="utf-8")
            manifest = write_matrix(
                base,
                root / "matrix",
                [
                    parse_dimension(
                        'participants.observer.identity.subject=["/CN=observer","/CN=peer"]'
                    )
                ],
            )
            report = run_campaign(
                manifest,
                root / "runs",
                {},
                policy_config=PolicyMaterializationConfig(
                    subject_names={"observer": "CN=observer", "peer": "CN=peer"}
                ),
            )
            self.assertEqual(2, report.counts["error"])
            self.assertIn("identity-related matrix", report.cases[0].error["message"])

    def test_resume_verifies_materialized_policy_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            base.write_text(json.dumps(_scenario()), encoding="utf-8")
            manifest = write_matrix(
                base,
                root / "matrix",
                [parse_dimension('governance.rtps_protection=["sign"]')],
            )
            policy_config = PolicyMaterializationConfig(
                subject_names={"observer": "CN=observer", "peer": "CN=peer"}
            )
            first = run_campaign(
                manifest,
                root / "runs",
                {},
                policy_config=policy_config,
            )
            self.assertEqual("scenario_materialized", first.cases[0].configuration_binding)
            run_dir = root / "runs" / first.cases[0].run_dir
            with (run_dir / "policies" / "governance.xml").open("ab") as output:
                output.write(b"tampered")

            resumed = run_campaign(manifest, root / "runs", {}, resume=True)
            self.assertEqual(1, resumed.counts["error"])
            self.assertIn("digest mismatch", resumed.cases[0].error["message"])

    @unittest.skipUnless(__import__("shutil").which("openssl"), "openssl is required")
    def test_generated_identities_bind_certificates_and_policies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            raw = _scenario()
            raw["participants"]["observer"]["identity"] = {"subject": "/CN=shared"}
            raw["participants"]["peer"]["identity"] = {"subject": "/CN=shared"}
            base.write_text(json.dumps(raw), encoding="utf-8")
            manifest = write_matrix(
                base,
                root / "matrix",
                [parse_dimension('governance.rtps_protection=["sign"]')],
            )
            report = run_campaign(
                manifest,
                root / "runs",
                {},
                identity_config=IdentityMaterializationConfig(),
            )
            self.assertEqual(1, report.counts["completed"], report.cases[0].error)
            run_dir = root / "runs" / report.cases[0].run_dir
            evidence = json.loads((run_dir / "evidence.json").read_text())
            binding = evidence["metadata"]["configuration_binding"]
            self.assertTrue(binding["signed"])
            self.assertEqual(2, len(binding["identity_certificates"]))
            permissions = (run_dir / "policies" / "permissions.xml").read_text()
            self.assertEqual(2, permissions.count("CN=shared"))

    def test_manifest_rejects_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "case_count": 1,
                        "cases": [
                            {
                                "id": "escape",
                                "file": "../escape.json",
                                "digest": "0" * 64,
                                "assignments": {},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CampaignError, "escapes"):
                load_manifest(manifest)

    def test_tampered_case_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "base.json"
            base.write_text(json.dumps(_scenario()), encoding="utf-8")
            manifest = write_matrix(
                base,
                root / "matrix",
                [parse_dimension('governance.rtps_protection=["sign"]')],
            )
            manifest_raw = json.loads(manifest.read_text())
            scenario_path = manifest.parent / manifest_raw["cases"][0]["file"]
            scenario_raw = json.loads(scenario_path.read_text())
            scenario_raw["title"] = "tampered"
            scenario_path.write_text(json.dumps(scenario_raw), encoding="utf-8")

            report = run_campaign(
                manifest,
                root / "runs",
                {},
                allow_unbound_configuration=True,
            )
            self.assertEqual(1, report.counts["error"])
            self.assertEqual("inconclusive", report.cases[0].verdict)
            self.assertIn("digest mismatch", report.cases[0].error["message"])


if __name__ == "__main__":
    unittest.main()
