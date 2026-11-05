from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harnesscreator.agents.harness import (
    CHECKLIST_NAMES,
    _code_only,
    _fuzzer_function_body,
)
from harnesscreator.agents.scenario_harness import (
    ScenarioStaticHarnessGate,
    _fuzz_request_delivery_position,
    _prelude_check_before_delivery,
    build_harness_plan,
)
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis.indexer import StaticAnalyzer
from harnesscreator.models import (
    CheckStatus,
    HarnessDraft,
    HarnessManifest,
    ScenarioStatus,
    ScenarioStep,
    ScenarioWitness,
)


class ScenarioSelfAuditTest(unittest.TestCase):
    def test_server_first_memcmp_guard_precedes_request_delivery(self) -> None:
        code = r'''
int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {
  const unsigned char *hc_fuzz_request = Data;
  unsigned long hc_fuzz_request_size = Size;
  static const char hc_connection_prelude_marker[] = "220 ready\r\n";
  unsigned char hc_connection_prelude_response[32] = {};
  unsigned long hc_connection_prelude_response_size = 0;
  recv(fd, hc_connection_prelude_response + hc_connection_prelude_response_size, 1, 0);
  if (hc_connection_prelude_response_size != sizeof(hc_connection_prelude_marker) - 1 ||
      std::memcmp(hc_connection_prelude_response, hc_connection_prelude_marker,
                  sizeof(hc_connection_prelude_marker) - 1) != 0) return 0;
  send(fd, hc_fuzz_request, hc_fuzz_request_size, 0);
  return 0;
}
'''
        marker_hex = b"220 ready\r\n".hex()

        def checked(source: str) -> bool:
            body = _fuzzer_function_body(_code_only(source))
            delivery = _fuzz_request_delivery_position(body, [])
            return _prelude_check_before_delivery(source, body, marker_hex, delivery)

        self.assertTrue(checked(code))
        self.assertFalse(checked(code.replace('"220 ready\\r\\n"', '"220 wrong\\r\\n"')))
        self.assertFalse(checked(code.replace("  recv(fd, hc_connection_prelude_response + hc_connection_prelude_response_size, 1, 0);", "")))
        self.assertFalse(checked(code.replace("!= 0) return 0;", "== 0) return 0;")))
        self.assertFalse(checked(code.replace("!= 0) return 0;", "!= 0 && false) return 0;")))
        request = "  send(fd, hc_fuzz_request, hc_fuzz_request_size, 0);"
        self.assertFalse(checked(code.replace(request, "").replace(
            "  if (hc_connection_prelude_response_size", request + "\n  if (hc_connection_prelude_response_size"
        )))

    def test_honest_warning_does_not_fail_audit_completeness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target.c").write_text(
                "int receive_one(const char *p) { return p[0]; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            function_id = next(iter(graph.bundle.functions))
            witness = ScenarioWitness(
                "witness", "scenario", "action",
                [ScenarioStep(0, "action", "entry", "58", {}, [])],
                [], ["target"], "stdin", 0, ScenarioStatus.PROVEN_RUNTIME,
                "request-correlated fixture",
            )
            plan = build_harness_plan(
                witness, action_function_ids={"action": (function_id, function_id)},
            )
            manifest = HarnessManifest(
                harness_id="harness", scenario_id="scenario", source_file="fuzz_target.c",
                build_target="fixture", engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=0, max_size=4096, dispatch_strategy="one_scenario_per_harness",
                expected_anchors=[function_id], expected_consumers=[function_id],
            )
            audit = [
                {"check_id": check_id, "status": "WARN" if check_id == "HC09" else "PASS",
                 "evidence": "startup order needs a runtime check" if check_id == "HC09" else "source checked"}
                for check_id in CHECKLIST_NAMES
            ]
            draft = HarnessDraft(
                manifest, "int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) { return 0; }",
                self_audit=audit, context_function_ids=[function_id],
            )
            gate = ScenarioStaticHarnessGate(graph)
            report = gate.check(draft, plan, witness)
            self.assertFalse(report.passed)
            self.assertFalse(any(check.check_id == "HC20" for check in report.checks))

            draft.generation_blockers = ["SCENARIO_STEP_BLOCKED: lifecycle unknown"]
            draft.self_audit = [
                *audit,
                {"check_id": "generation_blockers", "status": "FAIL",
                 "evidence": draft.generation_blockers[0]},
            ]
            blocked_report = gate.check(draft, plan, witness)
            self.assertTrue(any(check.check_id == "HC17" for check in blocked_report.checks))
            self.assertFalse(any(check.check_id == "HC20" for check in blocked_report.checks))
            draft.generation_blockers = []

            for changed in (
                [item for item in audit if item["check_id"] != "HC09"],
                [{**item, "status": "FAIL"} if item["check_id"] == "HC09" else item
                 for item in audit],
                [{**item, "evidence": ""} if item["check_id"] == "HC09" else item
                 for item in audit],
            ):
                draft.self_audit = changed
                report = gate.check(draft, plan, witness)
                self.assertTrue(any(
                    check.check_id == "HC20" and check.status is CheckStatus.FAIL
                    for check in report.checks
                ))


if __name__ == "__main__":
    unittest.main()
