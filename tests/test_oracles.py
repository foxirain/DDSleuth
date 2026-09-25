from __future__ import annotations

import json
import unittest
from pathlib import Path

from ddsleuth.evidence import EvidenceBundle
from ddsleuth.models import EvidenceEvent, EventKind
from ddsleuth.oracles import evaluate
from ddsleuth.scenario import load_scenario, parse_scenario


ROOT = Path(__file__).resolve().parents[1]


class OracleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = load_scenario(
            ROOT / "examples/fastdds/three_party_recipient_binding.json"
        )

    def _event(self, kind: str, actor: str, outcome: str, **attributes: object) -> EvidenceEvent:
        return EvidenceEvent(
            kind=kind,
            actor=actor,
            implementation="fastdds",
            outcome=outcome,
            attributes=attributes,
        )

    def test_detects_binding_disclosure_and_application_impersonation(self) -> None:
        events = [
            self._event(
                EventKind.ACCESS_CONTROL_DECISION,
                "mallory",
                "denied",
                operation="create_datareader",
                resource="SecretTopic",
            ),
            self._event(
                EventKind.CRYPTO_TOKEN_OBSERVED,
                "mallory",
                "observed",
                token_class="datawriter",
                local_participant_guid="mallory|participant",
                destination_participant_guid="bob|participant",
                destination_endpoint_guid="bob|reader",
                source_endpoint_guid="alice|writer",
            ),
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "mallory",
                "observed",
                sender_key_present=True,
                receiver_specific_key_present=True,
            ),
            self._event(
                EventKind.DECRYPT_CAPABILITY,
                "mallory",
                "succeeded",
                target="legitimate_protected_writer_traffic",
            ),
            self._event(
                EventKind.FORGE_CAPABILITY,
                "mallory",
                "succeeded",
                attacker_controlled=True,
            ),
            self._event(
                EventKind.APPLICATION_SAMPLE_RECEIVED,
                "bob",
                "received",
                attacker_controlled=True,
                sample_index=5902,
                message="attacker-controlled sample",
            ),
        ]
        evidence = EvidenceBundle.create(
            run_id="test-run",
            scenario_id=self.scenario.scenario_id,
            scenario_digest=self.scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(self.scenario, evidence)

        self.assertEqual("violation", report.verdict)
        self.assertEqual(3, sum(result.status.value == "violation" for result in report.oracle_results))
        self.assertEqual("high", report.capabilities.confidentiality)
        self.assertEqual("high", report.capabilities.integrity)
        self.assertEqual("not_demonstrated", report.capabilities.availability)

    def test_benign_recipient_binding_passes(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [raw["assertions"][0]]
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.ACCESS_CONTROL_DECISION,
                "mallory",
                "denied",
                operation="create_datareader",
                resource="SecretTopic",
            ),
            self._event(
                EventKind.CRYPTO_TOKEN_OBSERVED,
                "mallory",
                "observed",
                token_class="datawriter",
                local_participant_guid="mallory|participant",
                destination_participant_guid="mallory|participant",
                destination_endpoint_guid="mallory|reader",
                source_endpoint_guid="alice|writer",
            ),
            self._event(EventKind.PROCESS_EXIT, "mallory", "succeeded", exit_code=0),
            self._event(EventKind.PROCESS_EXIT, "bob", "succeeded", exit_code=0),
            self._event(EventKind.PROCESS_EXIT, "alice", "succeeded", exit_code=0),
        ]
        evidence = EvidenceBundle.create(
            run_id="benign-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_process_failure_is_inconclusive_not_pass(self) -> None:
        evidence = EvidenceBundle.create(
            run_id="failed-run",
            scenario_id=self.scenario.scenario_id,
            scenario_digest=self.scenario.digest,
            implementation="fastdds",
            events=[
                self._event(EventKind.PROCESS_EXIT, "mallory", "failed", exit_code=3),
                self._event(EventKind.PROCESS_EXIT, "bob", "failed", exit_code=3),
                self._event(EventKind.PROCESS_EXIT, "alice", "failed", exit_code=3),
            ],
        )
        report = evaluate(self.scenario, evidence)
        self.assertEqual("inconclusive", report.verdict)
        self.assertEqual({"mallory": 3, "bob": 3, "alice": 3}, report.failed_processes)

    def test_observer_health_fails_closed_on_observer_error(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-OBSERVER-HEALTH-01",
                "oracle": "observer_health",
                "parameters": {},
            }
        ]
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.OBSERVER_ERROR,
                "mallory",
                "error",
                phase="received",
                reason="test failure",
            ),
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "mallory",
                "observed",
                key_fingerprint="hmac-sha256-run-local-v1:test",
            ),
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="observer-error-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("inconclusive", report.verdict)
        self.assertEqual("not_applicable", report.oracle_results[0].status.value)

    def test_observer_health_passes_with_evidence_and_no_error(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-OBSERVER-HEALTH-01",
                "oracle": "observer_health",
                "parameters": {},
            }
        ]
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "mallory",
                "observed",
                key_fingerprint="hmac-sha256-run-local-v1:test",
            )
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="observer-health-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_endpoint_key_lifecycle_detects_reuse_after_recreation(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_endpoint_recreation.json"
        )
        raw = dict(scenario.raw)
        raw["assertions"] = [dict(scenario.raw["assertions"][-1])]
        scenario = parse_scenario(raw)
        common = {
            "token_class": "datawriter",
            "endpoint_class": "user",
            "observation_phase": "generated",
            "key_fingerprint": "hmac-sha256-run-local-v1:reused",
        }
        events = [
            self._event(EventKind.KEY_MATERIAL_OBSERVED, "writer", "observed", **common),
            self._event(
                EventKind.ENDPOINT_DESTROYED,
                "writer",
                "destroyed",
                endpoint="writer",
                lifecycle_epoch=1,
            ),
            self._event(EventKind.KEY_MATERIAL_OBSERVED, "writer", "observed", **common),
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="endpoint-key-reuse-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("violation", report.verdict)

    def test_endpoint_key_lifecycle_accepts_fresh_post_recreation_key(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_endpoint_recreation.json"
        )
        raw = dict(scenario.raw)
        raw["assertions"] = [dict(scenario.raw["assertions"][-1])]
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "writer",
                "observed",
                token_class="datawriter",
                endpoint_class="user",
                observation_phase="generated",
                key_fingerprint="hmac-sha256-run-local-v1:epoch-1",
            ),
            self._event(
                EventKind.ENDPOINT_DESTROYED,
                "writer",
                "destroyed",
                endpoint="writer",
                lifecycle_epoch=1,
            ),
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "writer",
                "observed",
                token_class="datawriter",
                endpoint_class="user",
                observation_phase="generated",
                key_fingerprint="hmac-sha256-run-local-v1:epoch-2",
            ),
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="endpoint-key-fresh-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_session_rotation_requires_increment_and_trigger_delivery(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_session_rotation.json"
        )
        raw = dict(scenario.raw)
        raw["assertions"] = [dict(scenario.raw["assertions"][-1])]
        scenario = parse_scenario(raw)
        events = []
        for sample_index, previous in ((1, 10), (3, 11), (5, 12)):
            events.extend(
                [
                    self._event(
                        EventKind.APPLICATION_WRITE_ATTEMPT,
                        "writer",
                        "attempted",
                        sample_index=sample_index,
                    ),
                    self._event(
                        EventKind.KEY_ROTATED,
                        "writer",
                        "rotated",
                        rotation_kind="session_key",
                        context="serialized_payload",
                        previous_session_id=previous,
                        session_id=previous + 1,
                        max_blocks_per_session=2,
                    ),
                    self._event(
                        EventKind.APPLICATION_SAMPLE_RECEIVED,
                        "reader",
                        "received",
                        sample_index=sample_index,
                    ),
                ]
            )
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="session-rotation-pass",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_session_rotation_detects_invalid_session_id_transition(self) -> None:
        scenario = load_scenario(
            ROOT / "examples/fastdds/native_session_rotation.json"
        )
        raw = dict(scenario.raw)
        assertion = dict(scenario.raw["assertions"][-1])
        assertion["parameters"] = dict(assertion["parameters"])
        assertion["parameters"]["minimum_rotations"] = 1
        raw["assertions"] = [assertion]
        scenario = parse_scenario(raw)
        evidence = EvidenceBundle.create(
            run_id="session-rotation-invalid-id",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.APPLICATION_WRITE_ATTEMPT,
                    "writer",
                    "attempted",
                    sample_index=1,
                ),
                self._event(
                    EventKind.KEY_ROTATED,
                    "writer",
                    "rotated",
                    rotation_kind="session_key",
                    context="serialized_payload",
                    previous_session_id=10,
                    session_id=15,
                    max_blocks_per_session=2,
                ),
                self._event(
                    EventKind.APPLICATION_SAMPLE_RECEIVED,
                    "reader",
                    "received",
                    sample_index=1,
                ),
            ],
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("violation", report.verdict)

    def test_missing_required_process_exit_is_inconclusive(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [raw["assertions"][0]]
        scenario = parse_scenario(raw)
        evidence = EvidenceBundle.create(
            run_id="incomplete-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.CRYPTO_TOKEN_OBSERVED,
                    "mallory",
                    "observed",
                    token_class="datawriter",
                    local_participant_guid="same",
                    destination_participant_guid="same",
                )
            ],
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("inconclusive", report.verdict)
        self.assertEqual(("alice", "bob", "mallory"), report.incomplete_processes)

    def test_unspecified_attacker_control_does_not_raise_integrity(self) -> None:
        evidence = EvidenceBundle.create(
            run_id="untrusted-label-run",
            scenario_id=self.scenario.scenario_id,
            scenario_digest=self.scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.PROTECTED_MESSAGE_ACCEPTED,
                    "bob",
                    "accepted",
                )
            ],
        )
        report = evaluate(self.scenario, evidence)
        self.assertEqual("not_demonstrated", report.capabilities.integrity)

    def test_detects_access_granted_beyond_declared_policy(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-POLICY-01",
                "oracle": "policy_authorization_consistency",
                "parameters": {"actor": "mallory", "operation": "subscribe"},
            }
        ]
        scenario = parse_scenario(raw)
        evidence = EvidenceBundle.create(
            run_id="policy-overgrant-run",
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
                )
            ],
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("violation", report.verdict)
        self.assertEqual("policy_authorization_consistency", report.oracle_results[0].oracle)

    def test_policy_consistency_understands_topic_wildcards(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["participants"]["mallory"]["permissions"]["subscribe"] = ["Telemetry*"]
        raw["assertions"] = [
            {
                "id": "INV-POLICY-01",
                "oracle": "policy_authorization_consistency",
                "parameters": {"actor": "mallory"},
            }
        ]
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.ACCESS_CONTROL_DECISION,
                "mallory",
                "allowed",
                operation="create_datareader",
                resource="TelemetrySecret",
            )
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="policy-wildcard-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_detects_key_scope_collision(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-KEYSEP-01",
                "oracle": "key_scope_separation",
                "parameters": {
                    "key_class": "sender",
                    "scope_attribute": "scope_id",
                },
            }
        ]
        scenario = parse_scenario(raw)
        evidence = EvidenceBundle.create(
            run_id="key-scope-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.KEY_MATERIAL_OBSERVED,
                    "bob",
                    "observed",
                    key_class="sender",
                    key_fingerprint="hmac-sha256-run-local-v1:17d8",
                    scope_id="domain=7/topic=A/reader=bob",
                ),
                self._event(
                    EventKind.KEY_MATERIAL_OBSERVED,
                    "mallory",
                    "observed",
                    key_class="sender",
                    key_fingerprint="hmac-sha256-run-local-v1:17d8",
                    scope_id="domain=7/topic=B/reader=mallory",
                ),
            ],
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("violation", report.verdict)
        self.assertEqual("key_scope_separation", report.oracle_results[0].oracle)

    def test_key_scope_filter_excludes_builtin_key_reuse(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-KEYSEP-01",
                "oracle": "key_scope_separation",
                "parameters": {
                    "scope_attribute": "destination_participant_guid",
                    "observation_phase": "received",
                    "endpoint_class": "user",
                },
            }
        ]
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                actor,
                "observed",
                observation_phase="received",
                endpoint_class="builtin",
                key_fingerprint="hmac-sha256-run-local-v1:shared",
                destination_participant_guid=f"{actor}|participant",
            )
            for actor in ("bob", "mallory")
        ]
        events.extend(
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                actor,
                "observed",
                observation_phase="received",
                endpoint_class="user",
                material_semantics="recipient_specific",
                key_fingerprint=f"hmac-sha256-run-local-v1:{actor}",
                destination_participant_guid=f"{actor}|participant",
            )
            for actor in ("bob", "mallory")
        )
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="key-scope-filter-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_token_transport_requires_exact_generated_route(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-TOKEN-TRANSPORT-01",
                "oracle": "crypto_token_transport_consistency",
                "parameters": {"token_class": "datawriter"},
            }
        ]
        scenario = parse_scenario(raw)
        common = {
            "token_class": "datawriter",
            "destination_participant_guid": "bob|participant",
            "destination_endpoint_guid": "bob|reader",
            "source_endpoint_guid": "alice|writer",
            "key_fingerprint": "hmac-sha256-run-local-v1:1234",
        }
        events = [
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "alice",
                "observed",
                observation_phase="generated",
                local_participant_guid="alice|participant",
                **common,
            ),
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "bob",
                "observed",
                observation_phase="received",
                local_participant_guid="bob|participant",
                **common,
            ),
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="token-route-pass",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_token_transport_detects_fingerprint_rebound_to_other_recipient(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-TOKEN-TRANSPORT-01",
                "oracle": "crypto_token_transport_consistency",
                "parameters": {},
            }
        ]
        scenario = parse_scenario(raw)
        fingerprint = "hmac-sha256-run-local-v1:abcd"
        evidence = EvidenceBundle.create(
            run_id="token-route-violation",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.KEY_MATERIAL_OBSERVED,
                    "alice",
                    "observed",
                    observation_phase="generated",
                    token_class="datawriter",
                    local_participant_guid="alice|participant",
                    destination_participant_guid="bob|participant",
                    destination_endpoint_guid="bob|reader",
                    source_endpoint_guid="alice|writer",
                    key_fingerprint=fingerprint,
                ),
                self._event(
                    EventKind.KEY_MATERIAL_OBSERVED,
                    "mallory",
                    "observed",
                    observation_phase="received",
                    token_class="datawriter",
                    local_participant_guid="mallory|participant",
                    destination_participant_guid="mallory|participant",
                    destination_endpoint_guid="mallory|reader",
                    source_endpoint_guid="alice|writer",
                    key_fingerprint=fingerprint,
                ),
            ],
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("violation", report.verdict)
        self.assertEqual(
            "crypto_token_transport_consistency",
            report.oracle_results[0].oracle,
        )

    def test_token_transport_allows_exact_route_retransmission(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-TOKEN-TRANSPORT-01",
                "oracle": "crypto_token_transport_consistency",
                "parameters": {},
            }
        ]
        scenario = parse_scenario(raw)
        common = {
            "token_class": "datawriter",
            "destination_participant_guid": "bob|participant",
            "destination_endpoint_guid": "bob|reader",
            "source_endpoint_guid": "alice|writer",
            "key_fingerprint": "hmac-sha256-run-local-v1:duplicate",
        }
        generated = self._event(
            EventKind.KEY_MATERIAL_OBSERVED,
            "alice",
            "observed",
            observation_phase="generated",
            local_participant_guid="alice|participant",
            **common,
        )
        received = self._event(
            EventKind.KEY_MATERIAL_OBSERVED,
            "bob",
            "observed",
            observation_phase="received",
            local_participant_guid="bob|participant",
            **common,
        )
        events = [generated, received, received]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="token-route-retransmission",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_token_transport_is_inconclusive_without_outbound_observation(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-TOKEN-TRANSPORT-01",
                "oracle": "crypto_token_transport_consistency",
                "parameters": {},
            }
        ]
        scenario = parse_scenario(raw)
        evidence = EvidenceBundle.create(
            run_id="token-route-incomplete",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.KEY_MATERIAL_OBSERVED,
                    "bob",
                    "observed",
                    observation_phase="received",
                    token_class="datawriter",
                    local_participant_guid="bob|participant",
                    destination_participant_guid="bob|participant",
                    destination_endpoint_guid="bob|reader",
                    source_endpoint_guid="alice|writer",
                    key_fingerprint="hmac-sha256-run-local-v1:beef",
                ),
            ],
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("inconclusive", report.verdict)

    def test_denied_actor_receiving_observed_user_key_is_a_disclosure(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-KEY-AUTH-01",
                "oracle": "unauthorized_key_disclosure",
                "parameters": {"actor": "mallory"},
            }
        ]
        scenario = parse_scenario(raw)
        evidence = EvidenceBundle.create(
            run_id="observed-user-key-disclosure",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.ACCESS_CONTROL_DECISION,
                    "mallory",
                    "denied",
                    operation="create_datareader",
                    resource="SecretTopic",
                ),
                self._event(
                    EventKind.KEY_MATERIAL_OBSERVED,
                    "mallory",
                    "observed",
                    observation_phase="received",
                    endpoint_class="user",
                    key_fingerprint="hmac-sha256-run-local-v1:cafe",
                    destination_endpoint_guid="mallory|reader",
                    source_endpoint_guid="alice|writer",
                ),
            ],
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("violation", report.verdict)

    def test_denied_actor_builtin_key_is_not_user_key_disclosure(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-KEY-AUTH-01",
                "oracle": "unauthorized_key_disclosure",
                "parameters": {"actor": "mallory"},
            }
        ]
        scenario = parse_scenario(raw)
        events = [
            self._event(
                EventKind.ACCESS_CONTROL_DECISION,
                "mallory",
                "denied",
                operation="create_datareader",
                resource="SecretTopic",
            ),
            self._event(
                EventKind.KEY_MATERIAL_OBSERVED,
                "mallory",
                "observed",
                observation_phase="received",
                endpoint_class="builtin",
                key_fingerprint="hmac-sha256-run-local-v1:babe",
            ),
        ]
        events.extend(
            self._event(EventKind.PROCESS_EXIT, role.actor, "succeeded", exit_code=0)
            for role in scenario.execution.roles
        )
        evidence = EvidenceBundle.create(
            run_id="observed-builtin-key",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=events,
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("pass", report.verdict)

    def test_detects_capability_after_revocation(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/three_party_recipient_binding.json").read_text()
        )
        raw["assertions"] = [
            {
                "id": "INV-REVOKE-01",
                "oracle": "revoked_authority_reuse",
                "parameters": {"actor": "mallory"},
            }
        ]
        scenario = parse_scenario(raw)
        evidence = EvidenceBundle.create(
            run_id="revocation-run",
            scenario_id=scenario.scenario_id,
            scenario_digest=scenario.digest,
            implementation="fastdds",
            events=[
                self._event(
                    EventKind.AUTHORITY_REVOKED,
                    "mallory",
                    "succeeded",
                    authority_id="writer-key-generation-4",
                ),
                self._event(
                    EventKind.FORGE_CAPABILITY,
                    "mallory",
                    "succeeded",
                    authority_id="writer-key-generation-4",
                    attacker_controlled=True,
                ),
            ],
        )
        report = evaluate(scenario, evidence)
        self.assertEqual("violation", report.verdict)
        self.assertEqual("revoked_authority_reuse", report.oracle_results[0].oracle)


if __name__ == "__main__":
    unittest.main()
