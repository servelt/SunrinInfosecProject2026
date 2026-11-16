"""No LLM completion or success status may override broken stage invariants."""
from __future__ import annotations

import unittest
import hashlib
from dataclasses import replace

from harnesscreator.agents.scenario_harness import build_harness_plan
from harnesscreator.models import (
    RuntimeStepObservation, ScenarioStatus, ScenarioStep, ScenarioWitness,
)
from harnesscreator.runtime.contracts import audit_harness_plan


def witness(status=ScenarioStatus.PROVEN_RUNTIME):
    step = ScenarioStep(
        index=0, action_id="GET", entry_id="entry", request_hex=b"GET x\n".hex(),
        bindings={}, expected_success_markers_hex=[b"OK\n".hex()],
    )
    result = RuntimeStepObservation(
        index=0, action_id="GET", request_hex=step.request_hex,
        response_hex=b"OK\n".hex(), success=True, detail="fixture result",
        duration_seconds=0.01, response_success=True,
        entry_reached=status != ScenarioStatus.REPLAYED_RUNTIME,
        target_observed=status != ScenarioStatus.REPLAYED_RUNTIME,
        target_reached=status == ScenarioStatus.PROVEN_RUNTIME,
        target_probe=("request-correlated-jsonl-v1"
                      if status == ScenarioStatus.PROVEN_RUNTIME else ""),
        probe_trace=(["semantic-response:" + hashlib.sha256(b"OK\n").hexdigest()]
                     if status == ScenarioStatus.PROVEN_RUNTIME else []),
    )
    return ScenarioWitness(
        "witness", "scenario", "GET", [step], [result], ["fixture"],
        "stdin", 0, status, "fixture",
    )


class HarnessPlanContractTests(unittest.TestCase):
    def test_valid_proven_and_exploratory_levels_are_distinguished(self):
        for status in (ScenarioStatus.PROVEN_RUNTIME,
                       ScenarioStatus.OBSERVED_RUNTIME,
                       ScenarioStatus.REPLAYED_RUNTIME):
            with self.subTest(status=status):
                w = witness(status)
                p = build_harness_plan(
                    w, action_function_ids={"GET": ("f-entry", "f-handler")},
                    allow_observed=status != ScenarioStatus.PROVEN_RUNTIME,
                )
                audit = audit_harness_plan(w, p)
                self.assertTrue(audit.passed, audit.failures)
                self.assertEqual(audit.proof_level, str(status))

    def test_forged_proof_without_target_observation_is_rejected(self):
        w = witness()
        w.observations[0].target_reached = False
        p = build_harness_plan(w, action_function_ids={"GET": ("entry", "handler")})
        self.assertFalse(audit_harness_plan(w, p).passed)

    def test_malformed_response_record_is_rejected_without_audit_crash(self):
        w = witness()
        w.observations[0].response_hex = "not-hex"
        p = build_harness_plan(w, action_function_ids={"GET": ("entry", "handler")})
        self.assertFalse(audit_harness_plan(w, p).passed)

    def test_modified_input_and_step_order_are_rejected(self):
        w = witness()
        p = build_harness_plan(w, action_function_ids={"GET": ("entry", "handler")})
        p.fuzz_step = replace(p.fuzz_step, request_hex=b"GET y\n".hex())
        self.assertTrue(any("preserve" in item for item in audit_harness_plan(w, p).failures))

    def test_replayed_cannot_become_strict_runtime_proof(self):
        w = witness(ScenarioStatus.REPLAYED_RUNTIME)
        with self.assertRaises(ValueError):
            build_harness_plan(w, action_function_ids={"GET": ("entry", "handler")})
        w.observations[0].target_reached = True
        p = build_harness_plan(w, action_function_ids={"GET": ("entry", "handler")}, allow_observed=True)
        self.assertFalse(audit_harness_plan(w, p).passed)

    def test_inconsistent_action_and_response_fail_before_codegen(self):
        w = witness()
        w.observations[0].action_id = "DELETE"
        p = build_harness_plan(w, action_function_ids={"GET": ("entry", "handler")})
        self.assertFalse(audit_harness_plan(w, p).passed)


if __name__ == "__main__":
    unittest.main()
