from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ddsleuth.campaign import run_campaign
from ddsleuth.explorer import _wilson_lower, analyze_exploration
from ddsleuth.matrix import MatrixDimension
from ddsleuth.trajectory import generate_trajectories, write_trajectory_manifest


class TrajectoryTests(unittest.TestCase):
    def test_reproducibility_uses_a_confidence_bound_not_raw_one_shot_success(self) -> None:
        self.assertLess(_wilson_lower(1, 1), 0.25)
        self.assertGreater(_wilson_lower(10, 10), 0.70)

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
                "trajectory.action_jitter_ms": 0,
                "trajectory.boundary_offset_ms": 0,
                "trajectory.scheduler_seed": True,
            },
            assignments,
        )
        self.assertTrue(
            any(item["trajectory.barrier_mode"] == "relaxed" for item in assignments)
        )

    def test_end_to_end_exploration_clusters_runtime_artifacts(self) -> None:
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
            self.assertGreaterEqual(report["artifact_cluster_count"], 1)
            families = {
                item["family"]
                for item in report["artifact_clusters"]
            }
            self.assertIn("boundary_episode", families)
            for result in campaign.cases:
                self.assertTrue((root / "runs" / result.run_dir / "artifacts.json").is_file())

    def test_semantic_specific_artifact_is_not_mislabeled_schedule_sensitive(self) -> None:
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
            artifact = next(
                item
                for item in report["artifact_clusters"]
                if item["family"] == "boundary_episode" and item["outcome"] == "allowed"
            )
            self.assertEqual(3, artifact["occurrences"])
            self.assertEqual(1, artifact["semantic_configuration_count"])
            self.assertFalse(artifact["schedule_sensitive"])
            self.assertEqual(0, artifact["schedule_sensitive_configuration_count"])

    def test_runtime_coverage_guides_a_bounded_pool(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenario_path = root / "scenario.json"
            scenario_path.write_text(json.dumps(self._raw_scenario()), encoding="utf-8")
            manifest = write_trajectory_manifest(
                scenario_path,
                root / "trajectories",
                budget=6,
                execution_budget=3,
                spacings_ms=(0, 10, 20),
                seed=11,
            )
            campaign = run_campaign(
                manifest,
                root / "runs",
                {},
                selection_strategy="artifact-guided",
                execution_budget=3,
                selection_seed=11,
                corpus_path=root / "artifact-corpus.json",
            )
            self.assertEqual(3, campaign.case_count)
            self.assertEqual(3, len(campaign.cases))
            self.assertIsNotNone(campaign.selection)
            assert campaign.selection is not None
            self.assertEqual(
                "runtime-artifact-guided",
                campaign.selection["strategy"],
            )
            self.assertEqual(6, campaign.selection["pool_size"])
            trace = campaign.selection["selection_trace"]
            self.assertTrue(trace[0]["baseline"])
            self.assertGreater(campaign.selection["covered_runtime_features"], 0)
            corpus = json.loads((root / "artifact-corpus.json").read_text())
            self.assertEqual("ddsleuth_runtime_artifact_corpus", corpus["kind"])
            self.assertTrue(corpus["seen_runtime_features"])
            self.assertTrue(
                all(
                    item.startswith("runtime:sha256:")
                    for item in corpus["seen_runtime_features"]
                )
            )

    def test_action_jitter_mutates_plan_without_reordering_actions(self) -> None:
        raw = self._raw_scenario()
        raw["execution"]["roles"][0]["actions"] = [
            {"id": "first", "at_ms": 10, "operation": "endpoint.create"},
            {"id": "second", "at_ms": 20, "operation": "endpoint.destroy"},
        ]
        trajectories = generate_trajectories(
            raw,
            spacings_ms=(0,),
            barrier_modes=("preserve",),
            action_jitters_ms=(0, 25),
            budget=2,
        )
        mutated = next(
            case for case, assignments in trajectories
            if assignments["trajectory.action_jitter_ms"] == 25
        )
        action_times = [
            item["at_ms"] for item in mutated["execution"]["roles"][0]["actions"]
        ]
        self.assertEqual(sorted(action_times), action_times)

    def test_boundary_offset_targets_only_boundary_actions(self) -> None:
        raw = self._raw_scenario()
        raw["execution"]["roles"][0]["actions"] = [
            {"id": "ordinary", "at_ms": 20, "operation": "application.write"},
            {"id": "boundary", "at_ms": 50, "operation": "credential.revoke_local"},
        ]
        trajectories = generate_trajectories(
            raw,
            spacings_ms=(0,),
            barrier_modes=("preserve",),
            action_jitters_ms=(0,),
            boundary_offsets_ms=(0, 15),
            budget=2,
        )
        mutated = next(
            case for case, assignments in trajectories
            if assignments["trajectory.boundary_offset_ms"] == 15
        )
        actions = mutated["execution"]["roles"][0]["actions"]
        self.assertEqual(20, actions[0]["at_ms"])
        self.assertEqual(65, actions[1]["at_ms"])

    def test_baseline_and_new_artifact_receive_selective_repetitions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = self._raw_scenario()
            diagnostic = (
                'DDSLEUTH_EVENT {"kind":"memory_safety.violation","actor":"denied",'
                '"implementation":"fastdds","outcome":"detected",'
                '"attributes":{"sanitizer":"asan","violation":"synthetic"}}'
            )
            raw["execution"]["roles"][1]["command"] = ["/bin/echo", diagnostic]
            scenario_path = root / "scenario.json"
            scenario_path.write_text(json.dumps(raw), encoding="utf-8")
            manifest = write_trajectory_manifest(
                scenario_path,
                root / "trajectories",
                spacings_ms=(0,),
                barrier_modes=("preserve",),
                budget=1,
            )
            campaign = run_campaign(
                manifest,
                root / "runs",
                {},
                repetitions=1,
                baseline_repetitions=3,
                confirmation_repetitions=2,
            )
            self.assertEqual(5, campaign.trial_count)
            self.assertEqual(5, len(campaign.cases))
            self.assertIsNotNone(campaign.confirmation)
            assert campaign.confirmation is not None
            self.assertEqual(1, campaign.confirmation["confirmed_case_count"])
            self.assertEqual(2, campaign.confirmation["additional_trials"])
            report = analyze_exploration(
                manifest,
                root / "runs",
                campaign,
                root / "exploration-report.json",
            )
            diagnostic_cluster = next(
                item for item in report["artifact_clusters"]
                if item["family"] == "runtime_memory_diagnostic"
            )
            self.assertTrue(diagnostic_cluster["confirmed"])
            self.assertEqual(5, diagnostic_cluster["reproduction_trials"])

    def test_long_matrix_ids_remain_unique_after_trajectory_prefix_truncation(self) -> None:
        raw = self._raw_scenario()
        raw["id"] = "long-semantic-scenario-" + "x" * 120
        trajectories = generate_trajectories(
            raw,
            dimensions=(
                MatrixDimension(path=("domain_id",), values=(7, 8)),
            ),
            dimension_strategy="cartesian",
            spacings_ms=(0,),
            barrier_modes=("preserve",),
            budget=2,
        )
        identifiers = [case["id"] for case, _ in trajectories]
        self.assertEqual(2, len(identifiers))
        self.assertEqual(2, len(set(identifiers)))

    def test_semantic_matrix_cannot_fill_pool_with_baselines_only(self) -> None:
        trajectories = generate_trajectories(
            self._raw_scenario(),
            dimensions=(
                MatrixDimension(path=("domain_id",), values=tuple(range(10, 20))),
            ),
            dimension_strategy="cartesian",
            spacings_ms=(0, 10),
            barrier_modes=("preserve",),
            budget=4,
            seed=23,
        )
        assignments = [item[1] for item in trajectories]
        self.assertEqual(1, sum(item["trajectory.scheduler_seed"] is True for item in assignments))
        self.assertTrue(any(item["trajectory.spacing_ms"] == 10 for item in assignments))


if __name__ == "__main__":
    unittest.main()
