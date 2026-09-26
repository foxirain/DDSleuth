from __future__ import annotations

import json
import unittest
from pathlib import Path

from ddsleuth.artifacts import discover_artifacts, discover_differential_artifacts
from ddsleuth.evidence import EvidenceBundle
from ddsleuth.models import EvidenceEvent, EventKind
from ddsleuth.scenario import parse_scenario


ROOT = Path(__file__).resolve().parents[1]


class RuntimeArtifactTests(unittest.TestCase):
    def _scenario(self):
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        return parse_scenario(raw)

    @staticmethod
    def _event(kind: str, actor: str, outcome: str, **attributes: object):
        return EvidenceEvent(
            kind=kind,
            actor=actor,
            implementation="fastdds",
            outcome=outcome,
            attributes=attributes,
            source=f"{actor}.log",
        )

    def _bundle(self, events: list[EvidenceEvent], run_id: str = "artifact-run"):
        scenario = self._scenario()
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        return scenario, EvidenceBundle.create(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )

    def test_records_split_enforcement_without_calling_it_a_vulnerability(self) -> None:
        scenario, evidence = self._bundle(
            [
                self._event(
                    EventKind.CREDENTIAL_REVOKED,
                    "alice",
                    "revoked",
                    local_identity=True,
                ),
                self._event(
                    EventKind.APPLICATION_SAMPLE_WRITTEN,
                    "alice",
                    "succeeded",
                    topic="SecretTopic",
                    message="after-revocation",
                ),
                self._event(
                    EventKind.APPLICATION_OBSERVATION_WINDOW,
                    "bob",
                    "expired",
                    expected_samples=2,
                    observed_samples=1,
                ),
            ]
        )
        bundle = discover_artifacts(scenario, evidence)
        artifact = next(
            item
            for item in bundle.artifacts
            if item.family == "split_enforcement_after_revocation"
        )
        rendered = artifact.to_dict()
        self.assertEqual("locally_accepted_remotely_suppressed", artifact.outcome)
        self.assertNotIn("severity", rendered)
        self.assertNotIn("risk_tier", rendered)
        self.assertGreaterEqual(artifact.boundary_depth, 2)
        self.assertLess(len(artifact.evidence_events), len(evidence.events))

    def test_records_exact_replay_suppression_as_a_neutral_artifact(self) -> None:
        scenario, evidence = self._bundle(
            [
                self._event(
                    EventKind.TRANSPORT_DATAGRAM_CAPTURED,
                    "alice",
                    "captured",
                    action_id="capture",
                    fault="capture_next",
                    bytes=556,
                ),
                self._event(
                    EventKind.TRANSPORT_DATAGRAM_REPLAYED,
                    "alice",
                    "replayed",
                    action_id="replay",
                    source_action_id="capture",
                    fault="replay_last",
                    bytes=556,
                ),
                self._event(
                    EventKind.APPLICATION_OBSERVATION_WINDOW,
                    "bob",
                    "expired",
                    expected_samples=2,
                    observed_samples=1,
                ),
            ]
        )
        artifact = next(
            item
            for item in discover_artifacts(scenario, evidence).artifacts
            if item.family == "replay_suppression_observed"
        )
        self.assertEqual("suppressed", artifact.outcome)
        self.assertEqual(556, artifact.observations["replayed_bytes"])
        self.assertIn("capture", artifact.observations["source_capture_action"])

    def test_key_values_are_compared_but_not_exported(self) -> None:
        scenario, evidence = self._bundle(
            [
                self._event(
                    EventKind.KEY_MATERIAL_OBSERVED,
                    "alice",
                    "observed",
                    endpoint_class="user",
                    observation_phase="generated",
                    key_fingerprint="secret-before",
                ),
                self._event(EventKind.PARTICIPANT_DISCONNECTED, "alice", "disconnected"),
                self._event(EventKind.PARTICIPANT_RECONNECTED, "alice", "reconnected"),
                self._event(
                    EventKind.KEY_MATERIAL_OBSERVED,
                    "alice",
                    "observed",
                    endpoint_class="user",
                    observation_phase="generated",
                    key_fingerprint="secret-after",
                ),
            ]
        )
        artifact = next(
            item
            for item in discover_artifacts(scenario, evidence).artifacts
            if item.family == "participant_key_epoch_transition"
        )
        rendered = json.dumps(artifact.to_dict(), sort_keys=True)
        self.assertEqual("fresh", artifact.outcome)
        self.assertNotIn("secret-before", rendered)
        self.assertNotIn("secret-after", rendered)

    def test_differential_projection_detects_count_bucket_and_outcome_changes(self) -> None:
        scenario, baseline = self._bundle(
            [
                self._event(
                    EventKind.ACCESS_CONTROL_DECISION,
                    "mallory",
                    "denied",
                    operation="create_datareader",
                    resource="SecretTopic",
                )
            ],
            run_id="baseline",
        )
        _, current = self._bundle(
            [
                self._event(
                    EventKind.ACCESS_CONTROL_DECISION,
                    "mallory",
                    "allowed",
                    operation="create_datareader",
                    resource="SecretTopic",
                ),
                self._event(
                    EventKind.ACCESS_CONTROL_DECISION,
                    "mallory",
                    "allowed",
                    operation="create_datareader",
                    resource="SecretTopic",
                ),
            ],
            run_id="mutated",
        )
        artifacts = discover_differential_artifacts(
            scenario,
            baseline,
            scenario,
            current,
        )
        self.assertEqual(1, len(artifacts))
        artifact = artifacts[0]
        self.assertEqual("baseline_runtime_divergence", artifact.family)
        self.assertEqual("baseline_differential", artifact.observation_class)
        self.assertGreater(artifact.observations["added_feature_count"], 0)


if __name__ == "__main__":
    unittest.main()
