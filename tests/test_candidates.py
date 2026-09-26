from __future__ import annotations

import json
import unittest
from pathlib import Path

from ddsleuth.candidates import discover_candidates, discover_schedule_differences
from ddsleuth.evidence import EvidenceBundle
from ddsleuth.models import EvidenceEvent, EventKind
from ddsleuth.oracles.evaluate import evaluate
from ddsleuth.scenario import parse_scenario


ROOT = Path(__file__).resolve().parents[1]


class CandidateTests(unittest.TestCase):
    def _scenario(self):
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-POLICY-01",
                "oracle": "policy_authorization_consistency",
                "parameters": {},
            }
        ]
        return parse_scenario(raw)

    def _event(self, kind: str, actor: str, outcome: str, **attributes: object):
        return EvidenceEvent(
            kind=kind,
            actor=actor,
            implementation="fastdds",
            outcome=outcome,
            attributes=attributes,
        )

    def test_preserves_high_signal_candidate_when_execution_is_incomplete(self) -> None:
        scenario = self._scenario()
        evidence = EvidenceBundle.create(
            run_id="partial-overgrant",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.ACCESS_CONTROL_DECISION,
                    "mallory",
                    "allowed",
                    operation="create_datareader",
                    resource="SecretTopic",
                ),
                self._event(
                    EventKind.APPLICATION_SAMPLE_RECEIVED,
                    "mallory",
                    "received",
                    topic="SecretTopic",
                    sample_index=1,
                ),
                self._event(EventKind.PROCESS_EXIT, "mallory", "failed", exit_code=4),
            ],
        )
        report = evaluate(scenario, evidence)
        bundle = discover_candidates(scenario, evidence, report)

        self.assertEqual("violation", report.verdict)
        self.assertEqual("high", report.capabilities.confidentiality)
        primary = bundle.candidates[0]
        self.assertEqual("unauthorized_application_delivery", primary.family)
        self.assertEqual("high_lead", primary.risk_tier)
        self.assertFalse(primary.execution_complete)
        self.assertIn("policy_overgrant", primary.signals)
        self.assertTrue(
            any(item.family == "stateful_execution_divergence" for item in bundle.candidates)
        )

    def test_declared_policy_is_enough_to_flag_user_key_delivery(self) -> None:
        raw = dict(self._scenario().raw)
        raw["participants"] = {
            name: dict(participant)
            for name, participant in raw["participants"].items()
        }
        raw["participants"]["mallory"]["permissions"] = {}
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "mallory",
                "observed",
                observation_phase="received",
                endpoint_class="user",
                token_class="datawriter",
                key_fingerprint="hmac-sha256-run-local-v1:deadbeef",
            )
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="policy-key-route",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        bundle = discover_candidates(scenario, evidence, report)
        self.assertTrue(
            any(item.family == "unauthorized_user_key_delivery" for item in bundle.candidates)
        )

    def test_legitimate_writer_receiving_datareader_key_is_not_flagged(self) -> None:
        scenario = self._scenario()
        events = [
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "alice",
                "observed",
                observation_phase="received",
                endpoint_class="user",
                token_class="datareader",
                key_fingerprint="hmac-sha256-run-local-v1:reader-key",
            )
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="legitimate-writer-key-route",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        bundle = discover_candidates(scenario, evidence, evaluate(scenario, evidence))
        self.assertFalse(
            any(item.family == "unauthorized_user_key_delivery" for item in bundle.candidates)
        )

    def test_datareader_key_requires_publish_not_subscribe_authority(self) -> None:
        raw = dict(self._scenario().raw)
        raw["participants"] = {
            name: dict(participant)
            for name, participant in raw["participants"].items()
        }
        raw["participants"]["mallory"]["permissions"] = {
            "subscribe": ["SecretTopic"]
        }
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "mallory",
                "observed",
                observation_phase="received",
                endpoint_class="user",
                token_class="datareader",
                topic="SecretTopic",
                key_fingerprint="hmac-sha256-run-local-v1:reader-key",
            )
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="unauthorized-publisher-key-route",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        bundle = discover_candidates(scenario, evidence, evaluate(scenario, evidence))
        candidate = next(
            item
            for item in bundle.candidates
            if item.family == "unauthorized_user_key_delivery"
        )
        self.assertIn("no_declared_publish_authority", candidate.signals)
        self.assertEqual("publish", candidate.details["required_operation"])

    def test_delivery_after_local_credential_revocation_is_a_critical_lead(self) -> None:
        scenario = self._scenario()
        events = [
            self._event(
                EventKind.CREDENTIAL_REVOKED,
                "alice",
                "revoked",
                local_identity=True,
                reason="certificate_expired",
            ),
            self._event(
                EventKind.APPLICATION_SAMPLE_WRITTEN,
                "alice",
                "succeeded",
                topic="SecretTopic",
                message="after-revoke",
            ),
            self._event(
                EventKind.APPLICATION_SAMPLE_RECEIVED,
                "bob",
                "received",
                topic="SecretTopic",
                message="after-revoke",
            ),
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="post-revocation-delivery",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        bundle = discover_candidates(scenario, evidence, evaluate(scenario, evidence))
        candidate = next(
            item for item in bundle.candidates
            if item.family == "credential_revocation_bypass"
        )
        self.assertEqual("critical_lead", candidate.risk_tier)
        self.assertEqual(99, candidate.score)

    def test_replayed_sample_delivered_twice_is_a_high_lead(self) -> None:
        scenario = self._scenario()
        events = [
            self._event(
                EventKind.APPLICATION_SAMPLE_RECEIVED,
                "bob",
                "received",
                topic="SecretTopic",
                sample_index=7,
                message="same-protected-sample",
            ),
            self._event(
                EventKind.TRANSPORT_DATAGRAM_REPLAYED,
                "alice",
                "replayed",
                action_id="replay",
                fault="replay_last",
            ),
            self._event(
                EventKind.APPLICATION_SAMPLE_RECEIVED,
                "bob",
                "received",
                topic="SecretTopic",
                sample_index=7,
                message="same-protected-sample",
            ),
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="accepted-replay",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        bundle = discover_candidates(scenario, evidence, evaluate(scenario, evidence))
        candidate = next(
            item
            for item in bundle.candidates
            if item.family == "transport_replay_duplicate_delivery"
        )
        self.assertEqual("high_lead", candidate.risk_tier)
        self.assertEqual(93, candidate.score)

    def test_runner_divergence_cannot_be_reported_as_a_pass(self) -> None:
        scenario = self._scenario()
        events = [
            self._event(
                EventKind.EXECUTION_DIVERGENCE,
                "alice",
                "failed",
                message="transport fault contract was not satisfied",
            )
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="runner-divergence",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("inconclusive", report.verdict)
        self.assertIn("alice", report.incomplete_processes)

    def test_sanitizer_failure_is_ranked_as_a_high_memory_safety_lead(self) -> None:
        scenario = self._scenario()
        events = [
            self._event(
                EventKind.TRANSPORT_DATAGRAM_REPLAYED,
                "alice",
                "replayed",
                action_id="replay",
                fault="replay_last",
            ),
            self._event(
                EventKind.MEMORY_SAFETY_VIOLATION,
                "bob",
                "detected",
                sanitizer="address",
                violation="heap-buffer-overflow",
            ),
        ]
        events.extend(
            self._event(
                EventKind.PROCESS_EXIT,
                role.actor,
                "failed" if role.actor == "bob" else "succeeded",
                exit_code=1 if role.actor == "bob" else 0,
            )
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="asan-replay",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        bundle = discover_candidates(scenario, evidence, evaluate(scenario, evidence))
        candidate = next(
            item
            for item in bundle.candidates
            if item.family == "sanitizer_memory_safety_failure"
        )
        self.assertEqual("high_lead", candidate.risk_tier)
        self.assertEqual(96, candidate.score)
        self.assertEqual(0.99, candidate.confidence)
        self.assertIn("applied_transport_mutation_preceded_failure", candidate.signals)

    def test_schedule_only_authorization_change_is_a_high_lead(self) -> None:
        scenario = self._scenario()
        baseline_events = [
            self._event(
                EventKind.ACCESS_CONTROL_DECISION,
                "mallory",
                "denied",
                operation="create_datareader",
                resource="SecretTopic",
            )
        ]
        current_events = [
            self._event(
                EventKind.ACCESS_CONTROL_DECISION,
                "mallory",
                "allowed",
                operation="create_datareader",
                resource="SecretTopic",
            )
        ]
        for events in (baseline_events, current_events):
            events.extend(
                self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
                for role in scenario.execution.roles
            )
        baseline = EvidenceBundle.create(
            run_id="baseline",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=baseline_events,
        )
        current = EvidenceBundle.create(
            run_id="mutated",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=current_events,
        )
        differences = discover_schedule_differences(
            scenario,
            baseline,
            evaluate(scenario, baseline),
            scenario,
            current,
            evaluate(scenario, current),
        )
        self.assertEqual(1, len(differences))
        self.assertEqual("schedule_authorization_divergence", differences[0].family)
        self.assertEqual("high_lead", differences[0].risk_tier)

    def test_schedule_difference_ignores_token_retransmission_count(self) -> None:
        scenario = self._scenario()
        token = self._event(
            EventKind.CRYPTO_TOKEN_OBSERVED,
            "mallory",
            "observed",
            observation_phase="received",
            token_class="datawriter",
            endpoint_class="user",
            addressed_to_local=True,
        )
        exits = [
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        ]
        baseline = EvidenceBundle.create(
            run_id="one-token",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[token, *exits],
        )
        retransmitted = EvidenceBundle.create(
            run_id="two-identical-tokens",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[token, token, *exits],
        )
        differences = discover_schedule_differences(
            scenario,
            baseline,
            evaluate(scenario, baseline),
            scenario,
            retransmitted,
            evaluate(scenario, retransmitted),
        )
        self.assertEqual((), differences)


if __name__ == "__main__":
    unittest.main()
