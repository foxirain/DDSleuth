from __future__ import annotations

import unittest

from ddsleuth.coverage import extract_runtime_coverage, semantic_state
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

    def test_extracts_actor_and_global_transitions(self) -> None:
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
        self.assertEqual(3, len(coverage.transitions))


if __name__ == "__main__":
    unittest.main()
