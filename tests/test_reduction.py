from __future__ import annotations

import json
import unittest
from pathlib import Path

from ddsleuth.artifacts import ArtifactBundle, RuntimeArtifact
from ddsleuth.reduction import minimize_action_plan


ROOT = Path(__file__).resolve().parents[1]


class ReductionTests(unittest.TestCase):
    def test_ddmin_executes_every_accepted_action_reduction(self) -> None:
        raw = json.loads(
            (ROOT / "examples/fastdds/native_scripted_lifecycle.json").read_text()
        )
        role = raw["execution"]["roles"][0]
        role["actions"] = [
            {"id": "setup", "at_ms": 0, "operation": "endpoint.create"},
            {"id": "target", "at_ms": 10, "operation": "credential.revoke_local"},
            {"id": "cleanup", "at_ms": 20, "operation": "endpoint.destroy"},
        ]
        target = "a" * 64
        artifact = RuntimeArtifact(
            artifact_id="DDSLEUTH-ART-TEST",
            fingerprint=target,
            family="test",
            title="test",
            observation_class="test",
            outcome="observed",
            actors=(str(role["actor"]),),
            resources=(),
            evidence_events=(),
            causal_signature=("test",),
            boundary_phases=(),
            boundary_depth=0,
            evidence_quality=1.0,
            execution_complete=True,
        )

        def execute(candidate):
            actions = candidate["execution"]["roles"][0].get("actions", [])
            preserved = any(item.get("id") == "target" for item in actions)
            return ArtifactBundle(1, "scenario", "b" * 64, "run", (artifact,) if preserved else ())

        result = minimize_action_plan(raw, target, execute)
        self.assertTrue(result.preserved)
        self.assertGreaterEqual(result.original_action_count, 3)
        self.assertEqual(1, result.minimized_action_count)
        actions = result.scenario["execution"]["roles"][0]["actions"]
        self.assertEqual("target", actions[0]["id"])
        self.assertGreater(result.execution_trials, 1)
        self.assertGreater(result.original_timing_sum_ms, result.minimized_timing_sum_ms)
        self.assertEqual(0.0, result.minimized_timing_sum_ms)


if __name__ == "__main__":
    unittest.main()
