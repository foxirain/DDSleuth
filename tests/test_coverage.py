from __future__ import annotations

import unittest

from ddsleuth.coverage import _frontier_score, extract_runtime_coverage, semantic_state
from ddsleuth.evidence import EvidenceBundle
from ddsleuth.models import EvidenceEvent


class RuntimeCoverageTests(unittest.TestCase):
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
        self.assertEqual(64.0, _frontier_score(coverage))


if __name__ == "__main__":
    unittest.main()
