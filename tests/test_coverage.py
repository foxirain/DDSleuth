from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ddsleuth.campaign import load_manifest
from ddsleuth.coverage import (
    ArtifactGuidedScheduler,
    _artifact_potential,
    extract_runtime_coverage,
    semantic_state,
)
from ddsleuth.evidence import EvidenceBundle
from ddsleuth.models import EvidenceEvent
from ddsleuth.trajectory import write_trajectory_manifest


class RuntimeCoverageTests(unittest.TestCase):
    @staticmethod
    def _scheduler_scenario() -> dict[str, object]:
        return {
            "schema_version": 1,
            "id": "scheduler-causal-delta",
            "title": "Scheduler causal delta fixture",
            "implementation": {"name": "fastdds", "version": "test"},
            "domain_id": 9,
            "participants": {
                "reader": {"role": "reader", "permissions": {"subscribe": ["T"]}},
                "writer": {"role": "writer", "permissions": {"publish": ["T"]}},
            },
            "policy": {"grant_order": ["reader", "writer"]},
            "governance": {},
            "topics": {"T": {}},
            "assertions": [
                {"id": "INV", "oracle": "observer_health", "parameters": {}}
            ],
            "execution": {
                "network": "loopback",
                "timeout_seconds": 2,
                "log_format": "ddssec-jsonl",
                "roles": [
                    {
                        "actor": "reader",
                        "command": ["/bin/true"],
                    },
                    {
                        "actor": "writer",
                        "command": ["/bin/true"],
                        "actions": [
                            {"id": "before", "at_ms": 0, "operation": "sample.write"},
                            {
                                "id": "revoke",
                                "at_ms": 10,
                                "operation": "credential.wait_revoked",
                            },
                            {"id": "after", "at_ms": 20, "operation": "sample.write"},
                        ],
                    },
                ],
            },
        }

    def test_semantic_coverage_ignores_run_specific_guids_and_fingerprints(self) -> None:
        first = EvidenceEvent(
            kind="key_material.observed",
            actor="reader",
            implementation="fastdds",
            outcome="observed",
            attributes={
                "token_class": "datawriter",
                "key_class": "sender",
                "source_endpoint_guid": "01.02.03",
                "key_fingerprint": "run-one",
            },
        )
        second = EvidenceEvent(
            kind=first.kind,
            actor=first.actor,
            implementation=first.implementation,
            outcome=first.outcome,
            attributes={
                "token_class": "datawriter",
                "key_class": "sender",
                "source_endpoint_guid": "ff.ee.dd",
                "key_fingerprint": "run-two",
            },
        )
        self.assertEqual(semantic_state(first), semantic_state(second))

    def test_extracts_only_actor_local_transitions_without_causal_evidence(self) -> None:
        bundle = EvidenceBundle.create(
            run_id="run",
            scenario_id="scenario",
            scenario_digest="0" * 64,
            implementation="fastdds",
            events=(
                EvidenceEvent("participant.reconnected", "alice", "fastdds", "reconnected"),
                EvidenceEvent("endpoint.created", "bob", "fastdds", "created"),
                EvidenceEvent("endpoint.created", "alice", "fastdds", "created"),
            ),
        )
        coverage = extract_runtime_coverage(bundle)
        self.assertEqual(3, len(coverage.states))
        self.assertEqual(1, len(coverage.transitions))
        self.assertFalse(any(item.startswith("global:") for item in coverage.transitions))

    def test_cross_actor_log_interleaving_does_not_change_coverage(self) -> None:
        alice_first = EvidenceEvent("endpoint.created", "alice", "fastdds", "created")
        alice_second = EvidenceEvent("endpoint.matched", "alice", "fastdds", "matched")
        bob_first = EvidenceEvent("endpoint.created", "bob", "fastdds", "created")
        bob_second = EvidenceEvent("endpoint.matched", "bob", "fastdds", "matched")

        def bundle(events: tuple[EvidenceEvent, ...]) -> EvidenceBundle:
            return EvidenceBundle.create(
                run_id="run",
                scenario_id="scenario",
                scenario_digest="0" * 64,
                implementation="fastdds",
                events=events,
            )

        first = extract_runtime_coverage(
            bundle((alice_first, bob_first, alice_second, bob_second))
        )
        second = extract_runtime_coverage(
            bundle((bob_first, alice_first, bob_second, alice_second))
        )
        self.assertEqual(first.features, second.features)

    def test_tracks_causal_security_milestones_and_anomalies(self) -> None:
        bundle = EvidenceBundle.create(
            run_id="run",
            scenario_id="scenario",
            scenario_digest="0" * 64,
            implementation="fastdds",
            events=(
                EvidenceEvent(
                    "credential.revoked",
                    "writer",
                    "fastdds",
                    "revoked",
                    {"local_identity": True},
                ),
                EvidenceEvent(
                    "application.sample_written",
                    "writer",
                    "fastdds",
                    "succeeded",
                    {"message": "post", "topic": "T"},
                ),
                EvidenceEvent(
                    "application.sample_received",
                    "reader",
                    "fastdds",
                    "received",
                    {"message": "post", "topic": "T", "sample_index": 2},
                ),
            ),
        )
        coverage = extract_runtime_coverage(bundle)
        self.assertIn("writer:post_revocation_write", coverage.milestones)
        self.assertIn("reader:post_revocation_delivery", coverage.milestones)
        self.assertIn("post_revocation_application_delivery", coverage.anomalies)
        self.assertIn("causal:application:T:write->receive", coverage.transitions)
        self.assertGreater(_artifact_potential(coverage), 0.0)

    def test_actor_local_three_event_motif_is_stable_runtime_coverage(self) -> None:
        bundle = EvidenceBundle.create(
            run_id="run",
            scenario_id="scenario",
            scenario_digest="0" * 64,
            implementation="fastdds",
            events=(
                EvidenceEvent("participant.disconnected", "alice", "fastdds", "disconnected"),
                EvidenceEvent("participant.reconnected", "alice", "fastdds", "reconnected"),
                EvidenceEvent("endpoint.recreated", "alice", "fastdds", "created"),
            ),
        )
        coverage = extract_runtime_coverage(bundle)
        self.assertEqual(1, len(coverage.motifs))
        self.assertTrue(any(item.startswith("actor3:") for item in coverage.motifs))

    def test_scheduler_prioritizes_causal_crossing_and_rewards_semantic_delta(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenario_path = root / "scenario.json"
            scenario_path.write_text(
                json.dumps(self._scheduler_scenario()),
                encoding="utf-8",
            )
            manifest_path = write_trajectory_manifest(
                scenario_path,
                root / "trajectories",
                spacings_ms=(0, 25),
                barrier_modes=("preserve",),
                budget=4,
            )
            _, cases = load_manifest(manifest_path)
            scheduler = ArtifactGuidedScheduler(cases)
            baseline = scheduler.choose(cases)
            self.assertTrue(baseline.assignments["trajectory.scheduler_seed"])

            exits = (
                EvidenceEvent("process.exit", "reader", "fastdds", "succeeded"),
                EvidenceEvent("process.exit", "writer", "fastdds", "succeeded"),
            )
            baseline_evidence = EvidenceBundle.create(
                run_id="baseline",
                scenario_id=baseline.scenario_id,
                scenario_digest=baseline.scenario_digest,
                implementation="fastdds",
                events=exits,
            )
            scheduler.observe(baseline, (baseline_evidence, baseline_evidence, baseline_evidence))

            pending = [case for case in cases if case.index != baseline.index]
            mutation = scheduler.choose(pending)
            self.assertIn("trajectory.causal_mutation", mutation.assignments)
            mutated_evidence = EvidenceBundle.create(
                run_id="mutation",
                scenario_id=mutation.scenario_id,
                scenario_digest=mutation.scenario_digest,
                implementation="fastdds",
                events=(
                    EvidenceEvent(
                        "credential.revoked",
                        "writer",
                        "fastdds",
                        "revoked",
                        {"local_identity": True},
                    ),
                    EvidenceEvent(
                        "application.sample_written",
                        "writer",
                        "fastdds",
                        "succeeded",
                        {"message": "post", "topic": "T"},
                    ),
                    EvidenceEvent(
                        "application.observation_window",
                        "reader",
                        "fastdds",
                        "expired",
                        {"expected_samples": 1, "observed_samples": 0},
                    ),
                    *exits,
                ),
            )
            scheduler.observe(mutation, (mutated_evidence,))
            trace = scheduler.summary(len(cases), 2)["selection_trace"]
            self.assertGreater(trace[1]["mutation_only_semantic_artifact_count"], 0)
            self.assertGreater(trace[1]["matched_differential_artifact_count"], 0)

            remaining = [
                case
                for case in pending
                if case.index != mutation.index
            ]
            incomplete = scheduler.choose(remaining)
            failed_evidence = EvidenceBundle.create(
                run_id="incomplete",
                scenario_id=incomplete.scenario_id,
                scenario_digest=incomplete.scenario_digest,
                implementation="fastdds",
                events=(
                    EvidenceEvent("process.exit", "reader", "fastdds", "succeeded"),
                    EvidenceEvent("process.exit", "writer", "fastdds", "failed"),
                ),
            )
            scheduler.observe(incomplete, (failed_evidence,))
            trace = scheduler.summary(len(cases), 3)["selection_trace"]
            self.assertFalse(trace[2]["valid_execution"])
            self.assertEqual(0, trace[2]["new_runtime_features"])


if __name__ == "__main__":
    unittest.main()
