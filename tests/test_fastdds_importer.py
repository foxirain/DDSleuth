from __future__ import annotations

import unittest

from ddsleuth.adapters.fastdds import FastDDSLegacyTextImporter
from ddsleuth.models import EventKind


class FastDDSImporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.importer = FastDDSLegacyTextImporter()

    def test_imports_cross_recipient_chain(self) -> None:
        attacker = """
        SECURITY Error: SecretTopic topic not found in allow rule.
        attacker: CASE_ACCESS_CONTROL_NEGATIVE secret_topic_reader_denied=1 reader_created=0
        attacker: CASE_TOKEN_PLAINTEXT observed=1 local=mallory|participant inner_destination_participant=bob|participant inner_destination_endpoint=bob|reader source_endpoint=alice|writer addressed_to_local=0 token_count=1
        attacker: CASE_STOLEN_KEY key_id=01020304 receiver_key_id=05060708 has_sender_key=1 has_receiver_specific_key=1
        attacker: CASE_CONFIDENTIALITY_BREACH legitimate_cipher_decrypted=1 forged_as_victim_created=1 forged_bytes=92
        attacker: CASE_UDP_FORGERY_SENT packet_built=1 packet_sent=1 packet_bytes=232 destination_port=62913
        """
        intended = """
        intended: CASE_FORGERY_AS_VICTIM_ACCEPTED accepted=1 actual_reader=bob|reader actual_writer=alice|writer forged_bytes=92
        intended: CASE_UDP_FORGERY_DELIVERED index=5902 message=attacker-controlled sample
        """
        victim = """
        victim: CASE_PRODUCTION_PAIR writer=alice|writer intended_reader=bob|reader legitimate_cipher_saved=1 application_write=1 bytes=92
        """

        events = []
        events.extend(self.importer.parse_text("mallory", attacker, "mallory.log"))
        events.extend(self.importer.parse_text("bob", intended, "bob.log"))
        events.extend(self.importer.parse_text("alice", victim, "alice.log"))

        kinds = [event.kind for event in events]
        self.assertIn(EventKind.ACCESS_CONTROL_DECISION, kinds)
        self.assertIn(EventKind.CRYPTO_TOKEN_OBSERVED, kinds)
        self.assertIn(EventKind.KEY_MATERIAL_OBSERVED, kinds)
        self.assertIn(EventKind.DECRYPT_CAPABILITY, kinds)
        self.assertIn(EventKind.FORGE_CAPABILITY, kinds)
        self.assertIn(EventKind.PACKET_SENT, kinds)
        self.assertIn(EventKind.PROTECTED_MESSAGE_ACCEPTED, kinds)
        self.assertIn(EventKind.APPLICATION_SAMPLE_RECEIVED, kinds)
        self.assertIn(EventKind.ENDPOINT_PAIR_OBSERVED, kinds)

        token = next(event for event in events if event.kind == EventKind.CRYPTO_TOKEN_OBSERVED)
        self.assertEqual("mallory|participant", token.attributes["local_participant_guid"])
        self.assertEqual("bob|participant", token.attributes["destination_participant_guid"])
        self.assertFalse(token.attributes["addressed_to_local"])

    def test_accepts_native_structured_event(self) -> None:
        line = (
            'DDSLEUTH_EVENT {"kind":"access_control.decision","actor":"mallory",'
            '"outcome":"denied","attributes":{"resource":"SecretTopic"}}'
        )
        events = self.importer.parse_text("mallory", line, "structured.log")
        self.assertEqual(1, len(events))
        self.assertEqual("fastdds", events[0].implementation)
        self.assertEqual("mallory", events[0].actor)

    def test_rejects_structured_event_actor_spoofing(self) -> None:
        line = (
            'DDSLEUTH_EVENT {"kind":"probe.ready","actor":"victim",'
            '"implementation":"fastdds","outcome":"ready","attributes":{}}'
        )
        with self.assertRaisesRegex(ValueError, "does not match log owner"):
            self.importer.parse_text("attacker", line, "attacker.log")


if __name__ == "__main__":
    unittest.main()
