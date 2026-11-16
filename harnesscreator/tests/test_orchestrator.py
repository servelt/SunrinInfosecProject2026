from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from harnesscreator.agents.entry import EntryGeneratorAgent
from harnesscreator.agents.harness import CHECKLIST_NAMES
from harnesscreator.agents.scenario import SEMANTIC_INPUT_ACTION_SCHEMA
from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.llm import InvalidOutputSchemaError, ScriptedLLM
from harnesscreator.models import (
    CheckStatus,
    CommandReport,
    EntryRecord,
    Evidence,
    GateCheck,
    GateReport,
    HarnessDisposition,
    ProjectSpec,
    RetryDisposition,
    SmallFeatureSpec,
    VerificationFailureKind,
    VerificationResult,
    Verdict,
    large_feature_schedule_key,
    stable_id,
)
from harnesscreator.orchestrator import (
    HarnessCreator,
    _apply_backend_readiness,
    _build_failure_excerpt,
    _deduplicate_verified_entries,
    _gate_feedback,
    _independent_review_requires_stop,
    _ACTIVE_OUTPUT_SCHEMAS,
    validate_active_output_schemas,
)
from harnesscreator.cli import build_parser


FIXTURE = Path(__file__).parent / "fixtures" / "c_project"


class WorkflowSchemaPreflightTest(unittest.TestCase):
    def test_all_active_role_schemas_pass_before_workflow_start(self) -> None:
        validate_active_output_schemas()

    def test_action_preflight_checks_the_schema_used_by_active_walk(self) -> None:
        self.assertIs(
            _ACTIVE_OUTPUT_SCHEMAS["input_action"],
            SEMANTIC_INPUT_ACTION_SCHEMA,
        )
        self.assertNotIn("input_action_group", _ACTIVE_OUTPUT_SCHEMAS)

    def test_one_invalid_late_role_schema_fails_the_global_preflight(self) -> None:
        original = _ACTIVE_OUTPUT_SCHEMAS["scenario_seed"]
        _ACTIVE_OUTPUT_SCHEMAS["scenario_seed"] = {
            "type": "object",
            "additionalProperties": False,
            "properties": {"seeds": {"type": "array"}},
            "required": [],
        }
        try:
            with self.assertRaisesRegex(
                InvalidOutputSchemaError,
                "scenario_seed.*required/properties mismatch",
            ):
                validate_active_output_schemas("legacy_scenario")
        finally:
            _ACTIVE_OUTPUT_SCHEMAS["scenario_seed"] = original


class BuildFeedbackTest(unittest.TestCase):
    def test_generation_attempts_are_unbounded_by_default(self) -> None:
        args = build_parser().parse_args(["run", str(FIXTURE)])
        self.assertEqual(args.max_attempts, 0)
        creator = HarnessCreator(
            ProjectSpec(source_root=FIXTURE, output_root=FIXTURE / "runs"),
            ScriptedLLM([]),
        )
        self.assertEqual(creator.max_generation_attempts, 0)
        report = GateReport([
            GateCheck("HC03", "Stale state", CheckStatus.FAIL, "pending response"),
        ])
        self.assertFalse(_independent_review_requires_stop(
            report, attempt=100, max_attempts=0,
        ))

    def test_verification_results_have_typed_quartet_phase_routing(self) -> None:
        build = CommandReport(
            argv=["cc"], returncode=0, stdout="", stderr="",
            duration_seconds=0.1,
        )
        reachability = VerificationResult(
            qualified=False, build=build, replays=[], fuzz=None,
            harness_faults=["selector 0 did not reach target"],
            target_findings=[], coverage_grew=None,
            reason="expected application anchor reachability was not established",
            build_ok=True,
        )
        coverage = VerificationResult(
            qualified=False, build=build, replays=[], fuzz=None,
            harness_faults=["fresh-corpus growth was not established"],
            target_findings=[], coverage_grew=False,
            reason="application coverage qualification failed",
            build_ok=True,
        )
        infrastructure = VerificationResult(
            qualified=False, build=None, replays=[], fuzz=None,
            harness_faults=[], target_findings=[], coverage_grew=None,
            reason="OSS-Fuzz coverage infrastructure failed",
            infrastructure_error="docker daemon unavailable",
        )

        self.assertEqual(
            reachability.failure.kind, VerificationFailureKind.REACHABILITY
        )
        self.assertEqual(
            reachability.failure.disposition, RetryDisposition.REFINE_SEEDS
        )
        self.assertEqual(coverage.failure.kind, VerificationFailureKind.COVERAGE)
        self.assertEqual(
            coverage.failure.disposition, RetryDisposition.STOP
        )
        self.assertEqual(
            infrastructure.failure.kind, VerificationFailureKind.INFRASTRUCTURE
        )
        self.assertEqual(
            infrastructure.failure.disposition, RetryDisposition.STOP
        )

    def test_replanned_feature_competes_by_priority_not_discovery_order(self) -> None:
        def candidate(
            identifier: str, score: int, access_score: int
        ) -> SimpleNamespace:
            return SimpleNamespace(
                large_feature_id=identifier,
                security_priority=SimpleNamespace(
                    disposition=HarnessDisposition.KEEP,
                    priority_score=score,
                    access_score=access_score,
                ),
            )

        pending = [candidate("local", 30, 3)]
        pending.append(candidate("replanned-udp", 25, 5))
        pending.sort(key=large_feature_schedule_key)

        self.assertEqual(
            [item.large_feature_id for item in pending],
            ["replanned-udp", "local"],
        )

    def test_preserves_compiler_error_before_long_docker_summary(self) -> None:
        output = (
            "fuzzer.c:42:5: error: use of undeclared identifier 'max_fds'\n"
            + "docker status line\n" * 2000
        )

        excerpt = _build_failure_excerpt(output)

        self.assertIn("undeclared identifier 'max_fds'", excerpt)
        self.assertLess(len(excerpt), 20_001)

    def test_independent_warnings_are_returned_for_repair(self) -> None:
        report = GateReport([
            GateCheck("HC01", "Resource leaks", CheckStatus.WARN, "partial cleanup", "add cleanup"),
            GateCheck("HC03", "Stale state", CheckStatus.FAIL, "pending response", "drain response"),
        ])

        feedback = _gate_feedback(report, include_warnings=True)

        self.assertEqual(len(feedback), 2)
        self.assertIn("partial cleanup", feedback[0])

    def test_stale_state_retries_before_generation_stops(self) -> None:
        report = GateReport([
            GateCheck("HC03", "Stale state", CheckStatus.FAIL, "pending response"),
        ])

        self.assertFalse(_independent_review_requires_stop(
            report, attempt=1, max_attempts=8
        ))
        self.assertTrue(_independent_review_requires_stop(
            report, attempt=8, max_attempts=8
        ))


def clean_harness_review() -> dict:
    return {
        "checks": [
            {
                "check_id": check_id,
                "status": "PASS",
                "evidence": "independent fixture evidence",
                "remediation": "",
            }
            for check_id in CHECKLIST_NAMES
        ],
        "summary": "all fixture checks pass",
    }


def complete_harness_context() -> dict:
    return {
        "context_complete": True,
        "candidate_function_ids": [],
        "blocking_dependencies": [],
        "lifecycle_facts": ["fixture lifecycle is complete"],
        "type_and_build_facts": ["fixture declarations are visible"],
        "unresolved_questions": [],
        "rationale": "the Common Anchor is sufficient for this fixture",
    }


class EntryDeduplicationTest(unittest.TestCase):
    def test_merges_cpp_qualified_and_unqualified_alias_at_one_site(self) -> None:
        def record(identifier: str, api: str, line: int) -> EntryRecord:
            return EntryRecord(
                entry_id=identifier,
                candidate_id=f"candidate-{identifier}",
                status=Verdict.VERIFIED,
                entry_function_id="fn-cpp-reader",
                source_api=api,
                channel_kind="stdin",
                attacker_control="local",
                provenance_path=[],
                consumer_hints=[],
                evidence=[Evidence("source", "fn-cpp-reader", "server.cpp", line, api)],
                unknowns=[],
                verifier_confidence=0.9,
            )

        merged, diagnostics = _deduplicate_verified_entries([
            record("qualified", "std::getline", 20),
            record("unqualified", "getline", 20),
            record("different-site", "getline", 21),
        ])

        self.assertEqual(len(merged), 2)
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(
            set(diagnostics[0]["merged_entry_ids"]),
            {"qualified", "unqualified"},
        )

    def test_does_not_conflate_distinct_cpp_namespaces_on_same_line(self) -> None:
        def record(identifier: str, api: str) -> EntryRecord:
            return EntryRecord(
                entry_id=identifier, candidate_id=f"candidate-{identifier}",
                status=Verdict.VERIFIED,
                entry_function_id="fn-cpp-reader", source_api=api,
                channel_kind="stdin", attacker_control="local",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence("source", "fn-cpp-reader", "server.cpp", 20, api)],
                unknowns=[], verifier_confidence=0.9,
            )

        merged, diagnostics = _deduplicate_verified_entries([
            record("std", "std::getline"),
            record("custom", "custom::getline"),
            record("ambiguous", "getline"),
        ])

        self.assertEqual(len(merged), 3)
        self.assertEqual(diagnostics, [])

    def test_merges_only_the_same_concrete_entry_site(self) -> None:
        def record(identifier: str, line: int) -> EntryRecord:
            return EntryRecord(
                entry_id=identifier,
                candidate_id=f"candidate-{identifier}",
                status=Verdict.VERIFIED,
                entry_function_id="fn-reader",
                source_api="recv",
                channel_kind="network socket",
                attacker_control="full",
                provenance_path=[{"function_id": "fn-reader", "relation": "recv"}],
                consumer_hints=[],
                evidence=[Evidence("source", "fn-reader", "server.c", line, "recv bytes")],
                unknowns=[],
                verifier_confidence=0.9,
            )

        merged, diagnostics = _deduplicate_verified_entries([
            record("entry-a", 20),
            record("entry-b", 20),
            record("entry-c", 40),
        ])

        self.assertEqual(len(merged), 2)
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(set(diagnostics[0]["merged_entry_ids"]), {"entry-a", "entry-b"})


class BackendReadinessTest(unittest.TestCase):
    def test_oss_fuzz_keeps_a_proven_loopback_feature_ready(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        feature = SmallFeatureSpec(
            small_feature_id="sf-network",
            name="serve one client frame",
            description="socket bytes reach the normal server parser",
            root_entries=["entry-network"], supporting_entries=[],
            harness_anchor=serve.function_id,
            anchor_rationale="normal socket service boundary",
            boundary_preserved=True,
            preconditions=[], initialization=[],
            required_functions=[serve.function_id],
            actions=[{"action_id": "serve", "function_id": serve.function_id}],
            input_bindings=[{
                "source": "per-iteration fuzzer bytes",
                "destination": "loopback socket peer",
                "transform": "bounded write",
            }],
            cleanup_success=[], cleanup_failure=[],
            stable_post_state="connection closed",
            completion_oracle="serve_client returns",
            evidence=[Evidence(
                "completion", serve.function_id, serve.file,
                serve.start_line, "serve_client establishes completion",
            )], unknowns=[], confidence=0.95,
            completion_action_id="serve",
            build_target="frame-server",
            isolation_mode="loopback_network",
            input_binding_proven=True,
            entry_paths_complete=True,
            anchor_action_complete=True,
            action_order_complete=True,
            entry_order_complete=True,
            function_references_complete=True,
            planning_complete=True,
            planning_blockers=[],
        )
        project = ProjectSpec(
            source_root=FIXTURE,
            output_root=FIXTURE.parent / "runs",
            verification_backend="oss-fuzz",
            harness_source_filename="fixture_fuzzer.c",
            oss_fuzz_project="fixture",
            oss_fuzz_fuzzer="fixture_fuzzer",
            oss_fuzz_source_path="/src/fixture",
        ).normalized()

        checked = _apply_backend_readiness(feature, project, GraphStore(bundle))

        self.assertTrue(checked.planning_complete)
        self.assertEqual(checked.planning_blockers, [])

    def test_oss_fuzz_blocks_unlinked_anchor_and_required_subprocess(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        bundle.functions[serve.function_id] = replace(serve, build_targets=[])
        feature = SmallFeatureSpec(
            small_feature_id="sf-tool",
            name="standalone tool",
            description="standalone process operation",
            root_entries=["entry-tool"],
            supporting_entries=[],
            harness_anchor=serve.function_id,
            anchor_rationale="process entry",
            boundary_preserved=True,
            preconditions=[],
            initialization=[],
            required_functions=[serve.function_id],
            actions=[{"function_id": serve.function_id}],
            input_bindings=[{"source": "Data", "destination": "input", "transform": "none"}],
            cleanup_success=[],
            cleanup_failure=[],
            stable_post_state="process exited",
            completion_oracle="exit status",
            evidence=[],
            unknowns=[],
            confidence=0.9,
            build_target="tool",
            isolation_mode="subprocess",
        )
        project = ProjectSpec(
            source_root=FIXTURE,
            output_root=FIXTURE.parent / "runs",
            verification_backend="oss-fuzz",
            harness_source_filename="fixture_fuzzer.c",
            oss_fuzz_project="fixture",
            oss_fuzz_fuzzer="fixture_fuzzer",
            oss_fuzz_source_path="/src/fixture",
        ).normalized()

        blocked = _apply_backend_readiness(feature, project, GraphStore(bundle))

        self.assertFalse(blocked.planning_complete)
        self.assertTrue(any("fork/subprocess" in item for item in blocked.planning_blockers))
        self.assertTrue(any("build-target evidence" in item for item in blocked.planning_blockers))


class OrchestratorTest(unittest.IsolatedAsyncioTestCase):
    @unittest.skip("legacy Small/Large Feature workflow was replaced by runtime-proven scenarios")
    async def test_untyped_harness_blocker_does_not_restart_feature_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            output = Path(temporary) / "runs"
            root.mkdir()
            (root / "server.c").write_text(
                """
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
int serve_client(int fd) {
    uint8_t data[16];
    return recv(fd, data, sizeof(data), 0);
}
int run_server(int fd) { return serve_client(fd); }
""",
                encoding="utf-8",
            )
            (root / "server.h").write_text(
                "int serve_client(int fd);\nint run_server(int fd);\n",
                encoding="utf-8",
            )
            (root / "Makefile.am").write_text(
                "server_SOURCES = server.c server.h\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()
            by_name = {function.name: function for function in bundle.functions.values()}
            serve = by_name["serve_client"]
            higher = by_name["run_server"]
            candidate = EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)[0]
            entry_id = stable_id("entry", candidate.candidate_id, Verdict.VERIFIED)

            def small_feature(anchor, name: str) -> dict:
                return {
                    "name": name,
                    "description": name,
                    "root_entries": [entry_id],
                    "supporting_entries": [],
                    "entry_call_order": [entry_id],
                    "harness_anchor": anchor.function_id,
                    "anchor_rationale": "normal caller boundary",
                    "boundary_preserved": True,
                    "preconditions": [], "initialization": [],
                    "required_functions": [anchor.function_id, serve.function_id],
                    "actions": [{
                        "action_id": name,
                        "function_id": anchor.function_id,
                        "consumes": ["fuzz_input"], "produces": ["status"],
                        "allowed_after": [], "success_condition": f"{anchor.name} returns",
                    }],
                    "input_bindings": [{
                        "source": "fuzz.data", "destination": "socket input",
                        "transform": "bounded transport",
                    }],
                    "cleanup_success": [], "cleanup_failure": [],
                    "stable_post_state": "request complete",
                    "completion_oracle": f"{anchor.name} returns",
                    "evidence": [{
                        "kind": "source", "function_id": anchor.function_id,
                        "file": anchor.file, "line": anchor.start_line,
                        "detail": "normal request path",
                    }],
                    "unknowns": [], "confidence": 0.9,
                    "build_target": "server", "isolation_mode": "in_process_reset",
                }

            initial_raw = small_feature(serve, "direct receive")
            refined_raw = small_feature(higher, "server request")

            def final_small_id(raw: dict) -> str:
                signature = {
                    "actions": raw["actions"],
                    "completion_oracle": raw["completion_oracle"].casefold(),
                    "stable_post_state": raw["stable_post_state"].casefold(),
                    "input_bindings": raw["input_bindings"],
                }
                return stable_id(
                    "sf", raw["harness_anchor"], entry_id,
                    json.dumps(signature, sort_keys=True),
                )

            initial_small_id = final_small_id(initial_raw)
            refined_small_id = final_small_id(refined_raw)

            def large_response(small_id: str, anchor_id: str, name: str) -> dict:
                return {"large_features": [{
                    "name": name, "description": name,
                    "small_feature_ids": [small_id],
                    "common_anchor": anchor_id,
                    "common_initialization": [], "common_cleanup": [],
                    "prerequisite_state": [], "isolation_mode": "in_process_reset",
                    "isolation_rationale": "fresh request",
                    "dispatch_strategy": "one_job_per_feature",
                    "variants": [{"selector": "0", "small_feature_id": small_id}],
                    "required_functions": [anchor_id, serve.function_id],
                }]}

            manifest = {
                "build_target": "server", "engine": "libfuzzer",
                "sanitizers": ["address", "undefined"],
                "execution_model": "in_process_reset", "headers": ["server.h"],
                "libraries": [], "min_size": 1, "max_size": 16,
                "dispatch_strategy": "one_job_per_feature",
                "expected_anchors": [], "expected_consumers": [],
            }
            responses = [
                {"candidates": []},
                {
                    "status": "VERIFIED", "channel_kind": "network",
                    "attacker_control": "full",
                    "provenance_path": [{
                        "function_id": serve.function_id, "relation": "recv reads peer bytes",
                    }],
                    "consumer_hints": [],
                    "evidence": [{
                        "kind": "source", "function_id": serve.function_id,
                        "file": serve.file, "line": candidate.line, "detail": "recv input",
                    }],
                    "unknowns": [], "confidence": 0.95, "rationale": "network input",
                    "first_acquisition_confirmed": True,
                    "context_complete": True, "requested_function_ids": [],
                },
                {
                    "small_features": [initial_raw], "unrelated_entries": [],
                    "context_complete": True, "requested_function_ids": [],
                },
                large_response(initial_small_id, serve.function_id, "direct receive group"),
                {"subjects": [], "feature_subjects": []},
                complete_harness_context(),
                {
                    "code": "", "manifest": manifest,
                    "checklist": [
                        {"check_id": check_id, "status": "FAIL", "evidence": "missing lifecycle"}
                        for check_id in CHECKLIST_NAMES
                    ],
                    "generation_blockers": ["direct receive anchor lacks a reusable lifecycle"],
                },
                {
                    "small_features": [refined_raw], "unrelated_entries": [],
                    "context_complete": True, "requested_function_ids": [],
                },
                {
                    "small_features": [refined_raw], "unrelated_entries": [],
                    "context_complete": True, "requested_function_ids": [],
                },
                large_response(refined_small_id, higher.function_id, "server request group"),
                {"subjects": [], "feature_subjects": []},
                complete_harness_context(),
                {
                    "code": (
                        "#include <stddef.h>\n#include <stdint.h>\n#include \"server.h\"\n"
                        "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                        "  if (Size < 1) return 0;\n"
                        "  int status = run_server((int)Data[0]);\n"
                        "  if (status < 0) return 0;\n"
                        "  return 0;\n}\n"
                    ),
                    "manifest": manifest,
                    "checklist": [
                        {"check_id": check_id, "status": "PASS", "evidence": "fixture evidence"}
                        for check_id in CHECKLIST_NAMES
                    ],
                    "generation_blockers": [],
                },
                clean_harness_review(),
            ]
            provider = ScriptedLLM(responses)
            summary = await HarnessCreator(
                ProjectSpec(
                    source_root=root,
                    output_root=output,
                    name="backtrack-fixture",
                    require_fuzz_introspector=False,
                ),
                provider,
                max_generation_attempts=1,
                dynamic_verification=False,
            ).run()

            self.assertEqual(summary.generation_attempts, 1)
            self.assertEqual(summary.harnesses_generated, 0)
            self.assertEqual(summary.harnesses_static_passed, 0)
            self.assertEqual(summary.harnesses_build_passed, 0)
            self.assertEqual(summary.harnesses_blocked, 1)
            self.assertEqual(summary.large_features, 1)
            self.assertEqual(summary.status, "FAILED_NO_VALID_HARNESS")
            events = [
                json.loads(line)
                for line in (Path(summary.output_root) / "debug" / "agent-events.jsonl")
                .read_text(encoding="utf-8").splitlines()
            ]
            event_names = {(item["agent"], item["event"]) for item in events}
            self.assertNotIn(("orchestrator", "harness_backtrack_started"), event_names)
            self.assertNotIn(("orchestrator", "harness_backtrack_completed"), event_names)

    @unittest.skip("legacy Small/Large Feature workflow was replaced by runtime-proven scenarios")
    async def test_end_to_end_generation_without_dynamic_execution(self) -> None:
        if shutil.which("g++") is None:
            self.skipTest("g++ is required for the real build-path integration test")
        bundle = StaticAnalyzer(FIXTURE).index()
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        candidate = EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)[0]
        entry_id = stable_id("entry", candidate.candidate_id, Verdict.VERIFIED)
        operation_signature = {
            "actions": [{
                "action_id": "serve", "function_id": serve.function_id,
                "consumes": ["fuzz_input"], "produces": ["status"],
                "allowed_after": [], "success_condition": "status == 0",
            }],
            "completion_oracle": "serve_client returns",
            "stable_post_state": "no per-input allocation",
            "input_bindings": [{
                "source": "fuzz.data", "destination": "socket receive buffer",
                "transform": "bounded transport",
            }],
        }
        small_id = stable_id(
            "sf", serve.function_id, entry_id,
            json.dumps(operation_signature, sort_keys=True),
        )
        responses = [
            {"candidates": []},
            {
                "status": "VERIFIED",
                "channel_kind": "network",
                "attacker_control": "full",
                "provenance_path": [{"function_id": serve.function_id, "relation": "recv reads peer bytes"}],
                "consumer_hints": [parse.function_id],
                "evidence": [{
                    "kind": "source", "function_id": serve.function_id, "file": serve.file,
                    "line": candidate.line, "detail": "recv return length bounds buffer passed to parser",
                }],
                "unknowns": [],
                "confidence": 0.95,
                "rationale": "connected socket bytes are externally controlled",
                "first_acquisition_confirmed": True,
            },
            {
                "small_features": [],
                "unrelated_entries": [],
                "context_complete": False,
                "requested_function_ids": [parse.function_id],
            },
            {
                "small_features": [{
                "name": "receive and parse one frame",
                "description": "read one frame and pass it to the real parser",
                "root_entries": [entry_id],
                "supporting_entries": [],
                "entry_call_order": [entry_id],
                "harness_anchor": serve.function_id,
                "anchor_rationale": "preserves receive and parse sequence",
                "boundary_preserved": True,
                "preconditions": [],
                "initialization": [],
                "required_functions": [serve.function_id, parse.function_id],
                "actions": [{
                    "action_id": "serve", "function_id": serve.function_id,
                    "consumes": ["fuzz_input"], "produces": ["status"],
                    "allowed_after": [], "success_condition": "status == 0",
                }],
                "input_bindings": [{
                    "source": "fuzz.data", "destination": "socket receive buffer",
                    "transform": "bounded transport",
                }],
                "cleanup_success": [],
                "cleanup_failure": [],
                "stable_post_state": "no per-input allocation",
                "completion_oracle": "serve_client returns",
                "evidence": [{
                    "kind": "source", "function_id": serve.function_id, "file": serve.file,
                    "line": serve.start_line, "detail": "serve_client owns operation lifecycle",
                }],
                "unknowns": [],
                "confidence": 0.9,
                "build_target": "default",
                "isolation_mode": "loopback_network",
                }],
                "unrelated_entries": [],
            },
            {
                "large_features": [{
                    "name": "frame service",
                    "description": "one compatible frame lifecycle",
                    "small_feature_ids": [small_id],
                    "common_anchor": serve.function_id,
                    "common_initialization": [],
                    "common_cleanup": [],
                    "prerequisite_state": [],
                    "isolation_mode": "loopback_network",
                    "isolation_rationale": "fixture is reset per call",
                    "dispatch_strategy": "selector_byte",
                    "variants": [{"selector": "0", "small_feature_id": small_id}],
                    "required_functions": [serve.function_id, parse.function_id],
                }]
            },
            {"subjects": [], "feature_subjects": []},
            complete_harness_context(),
            {
                "code": (
                    "#include <stddef.h>\n#include <stdint.h>\n"
                    "#include <sys/socket.h>\n#include <unistd.h>\n#include \"target.h\"\n"
                    "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                    "  int fd[2] = {-1, -1};\n"
                    "  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0) return 0;\n"
                    "  ssize_t sent = write(fd[0], Data, Size);\n"
                    "  if (sent < 0) { close(fd[0]); close(fd[1]); return 0; }\n"
                    "  shutdown(fd[0], SHUT_WR);\n"
                    "  int status = serve_client(fd[1]);\n"
                    "  close(fd[0]); close(fd[1]);\n"
                    "  if (status != 0) return 0;\n"
                    "  return 0;\n}\n"
                ),
                "manifest": {
                    "build_target": "fuzz_target", "engine": "libfuzzer",
                    "sanitizers": ["address", "undefined"], "execution_model": "loopback_network",
                    "headers": [], "libraries": [], "min_size": 1, "max_size": 4096,
                    "dispatch_strategy": "selector_byte", "expected_anchors": ["serve_client"],
                    "expected_consumers": ["parse_frame"],
                },
                "checklist": [
                    {"check_id": check_id, "status": "PASS", "evidence": "fixture evidence"}
                    for check_id in CHECKLIST_NAMES
                ],
                "generation_blockers": [],
            },
            clean_harness_review(),
        ]
        provider = ScriptedLLM(responses)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            driver = Path(__file__).parent / "fixtures" / "fuzz_driver.cc"
            project = ProjectSpec(
                source_root=FIXTURE,
                output_root=output,
                name="fixture",
                require_fuzz_introspector=False,
                verification_backend="command",
                build_command=[
                    "g++", "-std=c++17", "-fsanitize=address,undefined",
                    "-I{source_root}", "{harness}",
                    str(FIXTURE / "target.c"), str(driver),
                    "-o", "{output}/fuzz_target",
                ],
                harness_binary="{output}/fuzz_target",
                harness_source_filename="fuzz_target.cc",
            )
            summary = await HarnessCreator(
                project, provider, max_generation_attempts=1,
                dynamic_verification=False,
            ).run()
            self.assertEqual(summary.analysis_functions, 2)
            self.assertEqual(summary.analysis_provider, "fuzz-introspector+bootstrap-source")
            self.assertTrue(summary.analysis_authoritative)
            self.assertTrue(summary.fuzz_introspector_used)
            self.assertEqual(summary.svf_status, "UNAVAILABLE")
            self.assertFalse(summary.svf_used)
            self.assertEqual(summary.svf_indirect_edges_reported, 0)
            self.assertEqual(summary.svf_indirect_edges_mapped, 0)
            self.assertEqual(summary.svf_indirect_edges_unmapped, 0)
            self.assertEqual(summary.candidates, 1)
            self.assertEqual(summary.verified_entries, 1)
            self.assertEqual(summary.small_features, 1)
            self.assertEqual(summary.large_features, 1)
            self.assertEqual(summary.generation_attempts, 1)
            self.assertEqual(summary.harnesses_generated, 1)
            static_audits = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in Path(summary.output_root).glob(
                    "harnesses/*/attempt-*/static-audit.json"
                )
            ]
            self.assertEqual(summary.harnesses_static_passed, 1, static_audits)
            self.assertEqual(summary.harnesses_build_passed, 1)
            self.assertEqual(summary.harnesses_blocked, 0)
            self.assertEqual(summary.status, "BUILD_VERIFIED_DRAFT_COMPLETE")
            run_root = Path(summary.output_root)
            self.assertTrue((run_root / "summary.json").is_file())
            event_path = run_root / "debug" / "agent-events.jsonl"
            human_path = run_root / "debug" / "agent-trace.log"
            self.assertTrue(event_path.is_file())
            self.assertTrue(human_path.is_file())
            manifests = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in run_root.glob("harnesses/*/attempt-*/manifest.json")
            ]
            self.assertEqual(len(manifests), 1)
            self.assertEqual(manifests[0]["build_target"], "frame-server")
            events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines()]
            names = {(event["agent"], event["event"]) for event in events}
            self.assertIn(("entry_verifier", "context_expanded"), names)
            self.assertIn(("entry_verifier", "final_verdict"), names)
            self.assertIn(("orchestrator", "verified_entries_selected"), names)
            self.assertIn(("small_feature", "context_walk"), names)
            self.assertIn(("small_feature", "feature_created"), names)
            self.assertIn(("large_feature", "feature_created"), names)
            self.assertEqual(len(provider.calls), 9)


if __name__ == "__main__":
    unittest.main()
