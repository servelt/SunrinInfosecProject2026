from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

from harnesscreator.agents.harness import CHECKLIST_NAMES
from harnesscreator.agents.scenario_harness import (
    ScenarioStaticHarnessGate,
    build_harness_plan,
)
from harnesscreator.models import (
    CheckStatus,
    GateCheck,
    GateReport,
    HarnessDraft,
    HarnessManifest,
    ProjectSpec,
    RuntimeStepObservation,
    ScenarioStatus,
    ScenarioStep,
    ScenarioWitness,
)
from harnesscreator.orchestrator import (
    _scenario_independent_review_allows_deferred,
    _scenario_sibling_static_deferred,
)

from test_source_buffer_handoff import _index_source


def _fixture(tmp_path: Path):
    graph = _index_source(tmp_path, """
        #include <unistd.h>
        static int input_read(int fd, unsigned char *out) {
            return read(fd, out, 8);
        }
        static int target_handler(const unsigned char *data) {
            return data[0];
        }
        static int process_one(void) {
            unsigned char buf[8] = {0};
            if (input_read(0, buf) <= 0) return -1;
            return target_handler(buf);
        }
        int main(void) { return process_one(); }
    """)
    ids = {item.name: item.function_id for item in graph.bundle.functions.values()}
    request = b"HELLO\n"
    response = b"OK\n"
    step = ScenarioStep(0, "request", "entry", request.hex(), {}, [response.hex()])
    trace = [
        f"acquire:{ids['input_read']}:r1:conn1",
        f"handler:{ids['target_handler']}:r1",
        f"semantic-response:{hashlib.sha256(response).hexdigest()}",
    ]
    observation = RuntimeStepObservation(
        index=0, action_id="request", request_hex=request.hex(),
        response_hex=response.hex(), success=True, detail="observed",
        duration_seconds=0.1, target_function_id=ids["target_handler"],
        target_reached=True, target_probe="request-correlated-jsonl-v1",
        entry_function_id=ids["input_read"], entry_reached=True,
        probe_trace=trace,
    )
    witness = ScenarioWitness(
        witness_id="w1", scenario_id="s1", target_action_id="request",
        steps=[step], observations=[observation], command=["fixture"],
        channel="stdin", process_returncode=0,
        status=ScenarioStatus.PROVEN_RUNTIME, rationale="fixture",
    )
    plan = build_harness_plan(witness, action_function_ids={"request": (
        ids["input_read"], ids["process_one"], ids["target_handler"],
    )})
    draft = HarnessDraft(
        manifest=HarnessManifest(
            harness_id="h1", scenario_id="s1", source_file="fuzz_target.c",
            build_target="fixture", engine="libfuzzer", sanitizers=["address"],
            execution_model="loopback_network", headers=[], libraries=[],
            min_size=0, max_size=4096,
            dispatch_strategy="one_scenario_per_harness",
            expected_anchors=[ids["target_handler"]],
            expected_consumers=list(plan.required_function_ids),
            build_command=["python", "-m", "harnesscreator.runtime.native_build"],
        ),
        code=(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int send(int, const void *, size_t, int);\n"
            "int hc_native_original_main(void);\n"
            "static const uint8_t *hc_fuzz_request;\n"
            "static size_t hc_fuzz_request_size;\n"
            "static int deliver(void) { return send(1, hc_fuzz_request, hc_fuzz_request_size, 0); }\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { "
            "hc_fuzz_request = Data; hc_fuzz_request_size = Size; "
            "deliver(); return hc_native_original_main(); }\n"
        ),
        self_audit=[{"check_id": key, "status": "PASS", "evidence": "claimed"}
                    for key in CHECKLIST_NAMES],
        context_function_ids=list(plan.required_function_ids),
    )
    return graph, plan, witness, draft


def _checks(report: GateReport) -> dict[str, CheckStatus]:
    return {item.check_id: item.status for item in report.checks}


def test_sibling_flow_is_warn_only_with_exact_original_trace(tmp_path: Path) -> None:
    graph, plan, witness, draft = _fixture(tmp_path)
    report = ScenarioStaticHarnessGate(graph).check(draft, plan, witness)
    checks = _checks(report)
    assert checks["HC08"] is CheckStatus.WARN
    assert checks["HC10"] is CheckStatus.WARN
    assert not report.passed


def test_sibling_flow_fails_without_exact_trace_or_delivery(tmp_path: Path) -> None:
    graph, plan, witness, draft = _fixture(tmp_path)
    observation = witness.observations[0]
    witness.observations = [replace(observation, request_hex="00")]
    checks = _checks(ScenarioStaticHarnessGate(graph).check(draft, plan, witness))
    assert checks["HC08"] is CheckStatus.FAIL
    assert checks["HC10"] is CheckStatus.FAIL

    witness.observations = [observation]
    witness.observations = [replace(
        observation,
        probe_trace=[
            item.replace(":r1", ":r2") if item.startswith("handler:") else item
            for item in observation.probe_trace
        ],
    )]
    checks = _checks(ScenarioStaticHarnessGate(graph).check(draft, plan, witness))
    assert checks["HC08"] is CheckStatus.FAIL
    assert checks["HC10"] is CheckStatus.FAIL

    witness.observations = [replace(
        observation,
        probe_trace=[item for item in observation.probe_trace
                     if not item.startswith("semantic-response:")],
    )]
    checks = _checks(ScenarioStaticHarnessGate(graph).check(draft, plan, witness))
    assert checks["HC08"] is CheckStatus.FAIL
    assert checks["HC10"] is CheckStatus.FAIL

    witness.observations = [observation]
    draft.code = draft.code.replace("send(1, hc_fuzz_request, hc_fuzz_request_size, 0)", "deliver_missing()")
    checks = _checks(ScenarioStaticHarnessGate(graph).check(draft, plan, witness))
    assert checks["HC08"] is CheckStatus.WARN
    assert checks["HC10"] is CheckStatus.FAIL


def test_only_sibling_warnings_can_reach_differential_review(tmp_path: Path) -> None:
    project = ProjectSpec(
        source_root=tmp_path, output_root=tmp_path / "out",
        verification_backend="command", scenario_attribution="trace",
    )
    checks = [GateCheck(key, name, CheckStatus.WARN if key in {"HC08", "HC10"}
                        else CheckStatus.PASS, "evidence")
              for key, name in CHECKLIST_NAMES.items()]
    report = GateReport(checks)
    assert _scenario_sibling_static_deferred(report, project, True)
    assert _scenario_independent_review_allows_deferred(report)
    assert not _scenario_sibling_static_deferred(report, project, False)
    assert not _scenario_sibling_static_deferred(
        report, replace(project, scenario_attribution="gdb"), True,
    )
    assert not _scenario_sibling_static_deferred(
        report, replace(project, verification_backend="oss-fuzz"), True,
    )
    checks[0].status = CheckStatus.FAIL
    assert not _scenario_sibling_static_deferred(report, project, True)
    assert not _scenario_independent_review_allows_deferred(report)
