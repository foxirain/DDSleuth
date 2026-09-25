from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ddsleuth.campaign import run_campaign
from ddsleuth.explorer import analyze_exploration
from ddsleuth.matrix import MatrixDimension
from ddsleuth.trajectory import generate_trajectories, write_trajectory_manifest


class TrajectoryTests(unittest.TestCase):
    def _raw_scenario(self) -> dict[str, object]:
        ready = (
            'DDSLEUTH_EVENT {"kind":"probe.ready","actor":"reader",'
            '"implementation":"fastdds","outcome":"ready","attributes":{}}'
        )
        overgrant = (
            'DDSLEUTH_EVENT {"kind":"access_control.decision","actor":"denied",'
            '"implementation":"fastdds","outcome":"allowed",'
            '"attributes":{"operation":"create_datareader","resource":"Secret"}}'
        )
        return {
            "schema_version": 1,
            "id": "synthetic-stateful-discovery",
            "title": "Synthetic runtime discovery benchmark",
            "implementation": {"name": "fastdds", "version": "test"},
            "domain_id": 7,
            "participants": {
                "reader": {"role": "reader", "permissions": {"subscribe": ["Secret"]}},
                "denied": {"role": "denied", "permissions": {}},
            },
            "policy": {"grant_order": ["reader", "denied"]},
            "governance": {},
            "topics": {"Secret": {}},
            "assertions": [
                {
                    "id": "INV-POLICY",
                    "oracle": "policy_authorization_consistency",
                    "parameters": {},
                }
            ],
            "execution": {
                "network": "loopback",
                "timeout_seconds": 3,
                "log_format": "ddssec-jsonl",
                "roles": [
                    {"actor": "reader", "command": ["/bin/echo", ready]},
                    {
                        "actor": "denied",
                        "command": ["/bin/echo", overgrant],
                        "start_after": [{"actor": "reader", "kind": "probe.ready"}],
                    },
                ],
            },
        }

    def test_generation_is_deterministic_and_contains_dynamic_schedules(self) -> None:
        raw = self._raw_scenario()
        first = generate_trajectories(raw, budget=8, seed=19)
        second = generate_trajectories(raw, budget=8, seed=19)
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 8)
        assignments = [item[1] for item in first]
        self.assertTrue(
            any(item["trajectory.barrier_mode"] == "preserve" for item in assignments)
        )
        self.assertTrue(
            any(item["trajectory.barrier_mode"] == "relaxed" for item in assignments)
        )
        self.assertTrue(
            any(item["trajectory.order"] == ["denied", "reader"] for item in assignments)
        )

    def test_baseline_is_forced_for_relaxed_only_exploration(self) -> None:
        trajectories = generate_trajectories(
            self._raw_scenario(),
            budget=3,
            spacings_ms=(25,),
            barrier_modes=("relaxed",),
            seed=7,
        )
        assignments = [item[1] for item in trajectories]
        self.assertIn(
            {
                "trajectory.order": ["reader", "denied"],
                "trajectory.spacing_ms": 0,
                "trajectory.barrier_mode": "preserve",
            },
            assignments,
        )
        self.assertTrue(
            any(item["trajectory.barrier_mode"] == "relaxed" for item in assignments)
        )

    def test_end_to_end_exploration_ranks_runtime_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenario_path = root / "scenario.json"
            scenario_path.write_text(json.dumps(self._raw_scenario()), encoding="utf-8")
            manifest = write_trajectory_manifest(
                scenario_path,
                root / "trajectories",
                budget=4,
                spacings_ms=(0, 10),
                seed=3,
            )
            campaign = run_campaign(manifest, root / "runs", {})
            report = analyze_exploration(
                manifest,
                root / "runs",
                campaign,
                root / "exploration-report.json",
            )
            self.assertEqual(4, report["analyzed_trials"])
            self.assertGreaterEqual(report["high_or_critical_leads"], 1)
            families = {
                item["family"]
                for item in report["candidate_clusters"]
            }
            self.assertIn("policy_overgrant", families)
            for result in campaign.cases:
                self.assertTrue((root / "runs" / result.run_dir / "candidates.json").is_file())

    def test_semantic_specific_candidate_is_not_mislabeled_schedule_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = self._raw_scenario()
            overgrant = raw["execution"]["roles"][1]["command"][1]
            denial = (
                'DDSLEUTH_EVENT {"kind":"access_control.decision","actor":"denied",'
                '"implementation":"fastdds","outcome":"denied",'
                '"attributes":{"operation":"create_datareader","resource":"Secret"}}'
            )
            scenario_path = root / "scenario.json"
            scenario_path.write_text(json.dumps(raw), encoding="utf-8")
            manifest = write_trajectory_manifest(
                scenario_path,
                root / "trajectories",
                dimensions=(
                    MatrixDimension(
                        path=("execution", "roles", 1, "command", 1),
                        values=(overgrant, denial),
                    ),
                ),
                dimension_strategy="cartesian",
                spacings_ms=(0,),
                barrier_modes=("preserve", "relaxed"),
                budget=6,
                seed=5,
            )
            campaign = run_campaign(manifest, root / "runs", {})
            report = analyze_exploration(
                manifest,
                root / "runs",
                campaign,
                root / "exploration-report.json",
            )
            candidate = next(
                item
                for item in report["candidate_clusters"]
                if item["family"] == "policy_overgrant"
            )
            self.assertEqual(3, candidate["occurrences"])
            self.assertEqual(1, candidate["semantic_configuration_count"])
            self.assertFalse(candidate["schedule_sensitive"])
            self.assertEqual(0, candidate["schedule_sensitive_configuration_count"])


if __name__ == "__main__":
    unittest.main()
