from pathlib import Path
import asyncio
import dataclasses
import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from harnesscreator.agents.entry import EntryGeneratorAgent, EntryVerifierAgent
from harnesscreator.agents.features import (
    LargeFeatureAgent,
    _large_feature_prerequisite_state,
    _security_priority_from_assessment,
)
from harnesscreator.agents.harness import (
    CHECKLIST_NAMES,
    HarnessGeneratorAgent,
    StaticHarnessGate,
    _call_result_handled,
    _execution_model_visible,
    _function_invoked,
    _has_mutable_static_object,
    _internal_linkage_references,
    _lifecycle_step_status,
    _bounded_harness_function_payloads,
    _local_build_contract_evidence,
    _resource_cleanup_issues,
    _without_named_function_body,
    _function_or_source_alias_invoked,
)
from harnesscreator.agents.small_feature import (
    SmallFeatureAgent,
    _Proposal,
    _bindings_cover_entries,
    _coalesce_reconciliation_groups,
    _compatible_reconciliation_partitions,
    _entry_orders_compatible,
    _operation_scope_blockers,
)
from harnesscreator.agents.common import function_payload_excerpts, prefer_product_build_targets
from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.llm import CachingLLM, ScriptedLLM
from harnesscreator.models import (
    AnalysisBundle,
    AttackAccess,
    AttackerFeasibility,
    CallEdge,
    CommandReport,
    CheckStatus,
    EntryRecord,
    EntrySiteKind,
    Evidence,
    FunctionMetadata,
    GateCheck,
    GateReport,
    HarnessDraft,
    HarnessManifest,
    HarnessDisposition,
    ImpactScope,
    LargeFeatureSpec,
    ProjectSpec,
    SeedSpec,
    SmallFeatureSpec,
    Verdict,
    stable_id,
)
from harnesscreator.runtime.runner import HarnessVerifier, _first_relevant_stack_frame, write_seed_suite


FIXTURE = Path(__file__).parent / "fixtures" / "c_project"


class AgentInvariantTest(unittest.IsolatedAsyncioTestCase):
    async def test_harness_payload_redistributes_unused_source_budget(self) -> None:
        short = FunctionMetadata.create(
            name="short_helper", signature="void short_helper(void)",
            file="target.c", start_line=1, end_line=1, source="return;",
        )
        long = FunctionMetadata.create(
            name="long_machine", signature="void long_machine(void)",
            file="target.c", start_line=2, end_line=402,
            source="x" * 20_000,
        )
        payloads = _bounded_harness_function_payloads(
            [short, long],
            primary_ids={short.function_id, long.function_id},
            focus_lines={},
            total_source_chars=21_000,
        )
        by_name = {item["name"]: item for item in payloads}
        self.assertFalse(by_name["short_helper"]["source_truncated"])
        self.assertFalse(by_name["long_machine"]["source_truncated"])

    async def test_local_build_contract_reports_exact_ndebug_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Makefile.am").write_text(
                "target_CPPFLAGS = -DNDEBUG\nother = ignored\n"
            )
            self.assertEqual(
                _local_build_contract_evidence(root),
                [{
                    "file": "Makefile.am",
                    "line": 1,
                    "text": "target_CPPFLAGS = -DNDEBUG",
                }],
            )

    async def test_gate_report_requires_all_checks_to_pass(self) -> None:
        self.assertTrue(GateReport([
            GateCheck("X", "check", CheckStatus.PASS, "proven"),
        ]).passed)
        warning = GateReport([
            GateCheck("X", "check", CheckStatus.WARN, "not proven"),
        ])
        self.assertFalse(warning.passed)
        self.assertFalse(warning.has_failures)

    async def test_harness_generator_reads_same_project_oss_fuzz_reference(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        with tempfile.TemporaryDirectory() as temporary:
            oss_fuzz = Path(temporary) / "oss-fuzz"
            project_dir = oss_fuzz / "projects" / "fixture"
            project_dir.mkdir(parents=True)
            (project_dir / "fixture_fuzzer.c").write_text(
                '#include "target.h"\n'
                "int LLVMFuzzerTestOneInput(const unsigned char*d, unsigned long n){return 0;}\n"
            )
            (project_dir / "build.sh").write_text("$CC fixture_fuzzer.c target.o\n")
            (project_dir / "Dockerfile").write_text("WORKDIR /src/fixture\n")
            project = ProjectSpec(
                source_root=FIXTURE,
                output_root=Path(temporary) / "out",
                verification_backend="oss-fuzz",
                harness_source_filename="fixture_fuzzer.c",
                oss_fuzz_project="fixture",
                oss_fuzz_fuzzer="fixture_fuzzer",
                oss_fuzz_source_path="/src/fixture",
                oss_fuzz_dir=oss_fuzz,
            ).normalized()
            agent = HarnessGeneratorAgent(ScriptedLLM([]), graph, project)

            reference = agent._load_canonical_oss_fuzz_reference()

            self.assertIn("fixture_fuzzer.c", reference["files"])
            self.assertIn("target.o", reference["files"]["build.sh"])
            self.assertFalse(reference["local_checkout_preflight"]["performed"])

            validated = dataclasses.replace(
                project,
                canonical_oss_fuzz_preflight_passed=True,
            )
            validated_reference = HarnessGeneratorAgent(
                ScriptedLLM([]), graph, validated
            )._load_canonical_oss_fuzz_reference()
            self.assertTrue(
                validated_reference["local_checkout_preflight"]["canonical_runtime_probe_passed"]
            )
            self.assertEqual(reference["application_source_path"], "/src/fixture")

    async def test_harness_context_blocks_only_evidenced_required_dependencies(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        large = LargeFeatureSpec(
            large_feature_id="lf-optional-lifecycle",
            name="stateless frame operation",
            description="call the real frame operation without invented lifecycle",
            small_feature_ids=[],
            small_feature_names=[],
            common_anchor=serve.function_id,
            common_initialization=[],
            common_cleanup=[],
            common_cleanup_failure=[],
            prerequisite_state=[],
            fixture_fingerprint="fixture",
            isolation_mode="in_process_reset",
            isolation_rationale="no persistent state",
            dispatch_strategy="one_job_per_feature",
            variants=[],
            entry_call_graph={"nodes": [], "edges": []},
            required_functions=[serve.function_id, parse.function_id],
            evidence=[],
        )

        optional_provider = ScriptedLLM([
            {
                # A valid model-selected function is opened one at a time even
                # before the missing fact is strong enough to become a hard
                # evidence-backed blocker.
                "context_complete": False,
                "candidate_function_ids": [parse.function_id],
                "blocking_dependencies": [],
                "lifecycle_facts": ["no separate initialization or cleanup is required"],
                "type_and_build_facts": [],
                "unresolved_questions": ["inspect the real parser called by the operation"],
                "rationale": "the parser body is the next useful source",
            },
            {
                "context_complete": True,
                "candidate_function_ids": [],
                "blocking_dependencies": [],
                "lifecycle_facts": ["the parser completes without a separate lifecycle"],
                "type_and_build_facts": ["target.h declares the operation"],
                "unresolved_questions": [],
                "rationale": "the cumulative source is sufficient",
            },
        ])
        optional_agent = HarnessGeneratorAgent(
            optional_provider,
            graph,
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/harness-test")),
        )
        functions, discovery = await optional_agent._discover_context(
            large, [], [serve.function_id, parse.function_id], []
        )
        self.assertEqual(
            [item.function_id for item in functions],
            [serve.function_id, parse.function_id],
        )
        self.assertEqual(len(optional_provider.calls), 2)
        self.assertTrue(discovery["context_complete"])
        self.assertFalse(discovery["generation_blocked"])

        blocked_provider = ScriptedLLM([{
            "context_complete": False,
            "candidate_function_ids": [],
            "blocking_dependencies": [{
                "description": "the source calls an unresolved required operation",
                "required_for": "invoking the real operation without reimplementation",
                "evidence_kind": "source",
                "evidence_id": serve.function_id,
                "evidence_line": serve.start_line,
            }],
            "lifecycle_facts": [],
            "type_and_build_facts": [],
            "unresolved_questions": [],
            "rationale": "no eligible project function resolves the dependency",
        }])
        blocked_agent = HarnessGeneratorAgent(
            blocked_provider,
            graph,
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/harness-test")),
        )
        draft = await blocked_agent.run(large, [])
        self.assertEqual(len(blocked_provider.calls), 1)
        self.assertEqual(draft.code, "")
        self.assertTrue(draft.generation_blockers)
        self.assertTrue(draft.generation_blockers[0].startswith("CONTEXT_BLOCKED:"))

    async def test_harness_context_opens_exactly_one_model_selected_function_per_turn(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        provider = ScriptedLLM([
            {
                "context_complete": False,
                "candidate_function_ids": [parse.function_id],
                "blocking_dependencies": [{
                    "description": "the operation calls parse_frame and its behavior is required",
                    "required_for": "completing the real application operation",
                    "evidence_kind": "source",
                    "evidence_id": serve.function_id,
                    "evidence_line": serve.end_line - 1,
                }],
                "lifecycle_facts": ["serve_client receives and dispatches one frame"],
                "type_and_build_facts": [],
                "unresolved_questions": ["inspect the parser target"],
                "rationale": "the direct callee is the next required source",
            },
            {
                "context_complete": True,
                "candidate_function_ids": [],
                "blocking_dependencies": [],
                "lifecycle_facts": ["parse_frame completes the operation"],
                "type_and_build_facts": ["target.h declares both functions"],
                "unresolved_questions": [],
                "rationale": "the selected sources are sufficient",
            },
            {
                "context_complete": True,
                "candidate_function_ids": [],
                "blocking_dependencies": [],
                "lifecycle_facts": ["the retained parser context remains sufficient"],
                "type_and_build_facts": ["target.h declares both functions"],
                "unresolved_questions": [],
                "rationale": "repair feedback needs no additional source",
            },
        ])
        large = LargeFeatureSpec(
            large_feature_id="lf-sequential",
            name="frame operation",
            description="receive and parse one frame",
            small_feature_ids=[],
            small_feature_names=[],
            common_anchor=serve.function_id,
            common_initialization=[],
            common_cleanup=[],
            common_cleanup_failure=[],
            prerequisite_state=[],
            fixture_fingerprint="fixture",
            isolation_mode="in_process_reset",
            isolation_rationale="stateless fixture",
            dispatch_strategy="one_job_per_feature",
            variants=[],
            entry_call_graph={"nodes": [], "edges": []},
            required_functions=[serve.function_id, parse.function_id],
            evidence=[],
        )
        trace_events: list[tuple[str, str, dict]] = []
        agent = HarnessGeneratorAgent(
            provider,
            graph,
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/harness-test")),
            max_context_turns=8,
            trace=lambda role, event, details: trace_events.append((role, event, details)),
        )

        functions, discovery = await agent._discover_context(
            large,
            [],
            [serve.function_id, parse.function_id],
            [],
        )

        self.assertEqual([item.function_id for item in functions], [serve.function_id, parse.function_id])
        self.assertEqual(len(provider.calls), 2)
        self.assertEqual(provider.calls[0]["payload"]["current_function"]["function_id"], serve.function_id)
        self.assertEqual(provider.calls[1]["payload"]["current_function"]["function_id"], parse.function_id)
        self.assertEqual(
            [call["session_key"] for call in provider.calls],
            ["harness_generator:lf-sequential", "harness_generator:lf-sequential"],
        )
        self.assertNotIn("functions", provider.calls[0]["payload"])
        self.assertTrue(discovery["one_function_per_turn"])
        opened = [
            details["function"]["function_id"]
            for role, event, details in trace_events
            if role == "harness_generator" and event == "context_function_opened"
        ]
        self.assertEqual(opened, [serve.function_id, parse.function_id])

        retained_functions, retained_discovery = await agent._discover_context(
            large,
            [],
            [serve.function_id, parse.function_id],
            ["previous generated source needs a local repair"],
        )
        self.assertEqual(len(provider.calls), 3)
        self.assertEqual(
            provider.calls[2]["payload"]["current_function"]["function_id"],
            parse.function_id,
        )
        self.assertEqual(
            [item.function_id for item in retained_functions],
            [serve.function_id, parse.function_id],
        )
        self.assertTrue(retained_discovery["resumed_prior_context"])

    async def test_harness_context_can_open_function_proven_by_canonical_reference(self) -> None:
        anchor = FunctionMetadata.create(
            name="event_handler", signature="void event_handler(void)",
            file="server.c", start_line=1, end_line=1,
            source="void event_handler(void) {}",
        )
        accessor = FunctionMetadata.create(
            name="get_worker_thread", signature="void *get_worker_thread(int)",
            file="thread.c", start_line=1, end_line=1,
            source="void *get_worker_thread(int i) { return 0; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={
                anchor.function_id: anchor,
                accessor.function_id: accessor,
            },
            edges=[],
        ))
        agent = HarnessGeneratorAgent(
            ScriptedLLM([]), graph,
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/harness-test")),
        )

        choice = agent._select_next_context_function(
            ["get_worker_thread"],
            [],
            anchor,
            {anchor.function_id},
            set(),
            {accessor.function_id},
        )

        self.assertIsNotNone(choice)
        assert choice is not None
        self.assertEqual(choice["function_id"], accessor.function_id)
        self.assertEqual(choice["relation"], "canonical_oss_fuzz_reference")

    async def test_declared_execution_model_must_be_visible_in_code(self) -> None:
        self.assertTrue(
            _execution_model_visible(
                "pid_t p = fork(); waitpid(p, 0, 0);", "fork_per_input"
            )
        )
        self.assertFalse(
            _execution_model_visible(
                "return target(data, size);", "fork_per_input"
            )
        )
        self.assertTrue(
            _execution_model_visible(
                "socketpair(AF_UNIX, SOCK_STREAM, 0, fd);",
                "loopback_network",
            )
        )

    async def test_line_leading_function_call_is_detected(self) -> None:
        self.assertTrue(_function_invoked("target();\n", "target"))
        self.assertTrue(_function_invoked("    target(value);\n", "target"))
        self.assertFalse(
            _function_invoked(
                "extern int target(\n    const unsigned char *data,\n    unsigned long size);\n",
                "target",
            )
        )

    async def test_source_included_main_alias_counts_as_real_anchor_call(self) -> None:
        code = (
            "#define main project_main\n"
            "#include \"tool.c\"\n"
            "#undef main\n"
            "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) {\n"
            "  char *argv[] = {(char *)\"tool\", 0};\n"
            "  return project_main(1, argv);\n"
            "}\n"
        )
        self.assertTrue(_function_or_source_alias_invoked(code, code, "main"))

    async def test_static_helper_is_not_mistaken_for_stale_mutable_state(self) -> None:
        self.assertFalse(_has_mutable_static_object("static int helper(int x) { return x; }"))
        self.assertFalse(_has_mutable_static_object("static int helper(int x);"))
        self.assertTrue(_has_mutable_static_object("static int counter = 0;"))

    async def test_file_scope_static_application_symbol_is_not_linkable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target.c"
            source.write_text(
                "static int internal_limit;\nint public_target(void) { return internal_limit; }\n",
                encoding="utf-8",
            )
            function = FunctionMetadata.create(
                name="public_target", qualified_name="public_target",
                signature="int public_target(void)", file="target.c",
                start_line=2, end_line=2,
                source="int public_target(void) { return internal_limit; }",
            )
            graph = GraphStore(AnalysisBundle(
                functions={function.function_id: function}, edges=[]
            ))

            references = _internal_linkage_references(
                "internal_limit = 1024; return public_target();",
                root,
                graph,
            )
            local_references = _internal_linkage_references(
                "static int internal_limit; internal_limit = 1024;",
                root,
                graph,
            )

        self.assertEqual(references, ["internal_limit"])
        self.assertEqual(local_references, [])

    async def test_file_scope_static_application_function_is_not_linkable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "static void conn_free(void *p);\n"
                "void public_target(void) {}\n"
                "static void conn_free(void *p) { (void)p; }\n",
                encoding="utf-8",
            )
            function = FunctionMetadata.create(
                name="public_target", qualified_name="public_target",
                signature="void public_target(void)", file="target.c",
                start_line=2, end_line=2, source="void public_target(void) {}",
            )
            graph = GraphStore(AnalysisBundle(
                functions={function.function_id: function}, edges=[]
            ))

            references = _internal_linkage_references(
                "conn_free(ptr); public_target();",
                root,
                graph,
            )

        self.assertEqual(references, ["conn_free"])

    async def test_process_lifetime_initializer_allocation_is_not_per_input_leak(self) -> None:
        code = (
            "int LLVMFuzzerInitialize(int *argc, char ***argv) { fixture = calloc(4, 8); return 0; }\n"
            "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return n > 0; }\n"
        )
        per_iteration = _without_named_function_body(code, "LLVMFuzzerInitialize")

        self.assertEqual(_resource_cleanup_issues(per_iteration), [])

    async def test_dispatcher_with_unopened_stateful_handlers_is_not_complete_operation(self) -> None:
        blockers = _operation_scope_blockers({
            "unknowns": [
                "Command-specific handlers below the dispatcher can further affect state and response contents."
            ]
        })

        self.assertEqual(len(blockers), 1)
        self.assertIn("operation boundary", blockers[0])

    async def test_compile_time_branch_is_not_mistaken_for_operation_dispatcher(self) -> None:
        blockers = _operation_scope_blockers({
            "unknowns": [
                "The active compile-time fallback branch and its state are unresolved."
            ]
        })

        self.assertEqual(blockers, [])

    async def test_every_nonvoid_action_call_must_handle_its_result(self) -> None:
        self.assertFalse(_call_result_handled("int rc = parse(data);", "parse"))
        self.assertTrue(
            _call_result_handled(
                "extern int parse(const char *);\nint rc = parse(data);\nif (rc < 0) return 0;",
                "parse",
            )
        )
        self.assertFalse(
            _call_result_handled("int rc = parse(data);\n(void)rc;", "parse")
        )
        self.assertFalse(
            _call_result_handled("int rc = parse(data);\nparse(other);", "parse")
        )
        self.assertTrue(
            _call_result_handled(
                "extern void *conn_new(\n"
                "    int fd, int state);\n"
                "void *connection = conn_new(3, 1);\n"
                "if (connection == 0) return 0;\n",
                "conn_new",
            )
        )

    async def test_static_gate_preserves_source_proven_callback_paths(self) -> None:
        indexed = StaticAnalyzer(FIXTURE).index()
        by_name = {function.name: function for function in indexed.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        # Reproduce an FI blind spot: the Small Feature source walk proved the
        # callback/action path, while the imported call graph has no edge.
        graph = GraphStore(AnalysisBundle(functions=indexed.functions, edges=[]))
        draft = HarnessDraft(
            manifest=HarnessManifest(
                harness_id="h-proven-path", large_feature_id="lf-proven-path",
                source_file="fuzz_target.cc", build_target="frame-server",
                engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=["target.h"], libraries=[],
                min_size=1, max_size=4096, dispatch_strategy="one_job_per_feature",
                expected_anchors=[serve.function_id], expected_consumers=[parse.function_id],
                build_command=["true"], binary="/tmp/fuzzer",
            ),
            code=(
                "#include \"target.h\"\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {\n"
                "  if (Size < 1) return 0; int rc = serve_client((int)Data[0]); return rc < -1;\n}\n"
            ),
            self_audit=[
                {"check_id": check_id, "status": "PASS", "evidence": "claimed"}
                for check_id in CHECKLIST_NAMES
            ],
            context_function_ids=[serve.function_id],
        )
        feature = SimpleNamespace(
            small_feature_id="sf-proven-path",
            input_bindings=[{"source": "fuzz data"}], input_binding_proven=True,
            boundary_preserved=True, entry_paths_complete=True,
            anchor_action_complete=True, action_order_complete=True,
            function_references_complete=True, entry_order_complete=True,
            planning_complete=True, planning_blockers=[],
            actions=[{"function_id": parse.function_id}],
            required_functions=[serve.function_id, parse.function_id],
            initialization=["parse_frame is reached by the real callback path"],
            cleanup_success=["parse_frame completion returns through the anchor"],
            cleanup_failure=["parse_frame failure returns through the anchor"],
        )
        large = SimpleNamespace(
            common_anchor=serve.function_id, common_initialization=[], common_cleanup=[],
            required_functions=[serve.function_id, parse.function_id], variants=[],
            prerequisite_state=["parse_frame receives the acquired bytes"],
            small_feature_ids=[feature.small_feature_id],
        )

        report = StaticHarnessGate(graph).check(draft, large, [feature])
        by_check = {check.check_id: check for check in report.checks}

        self.assertIs(by_check["HC09"].status, CheckStatus.PASS)
        self.assertIs(by_check["HC13"].status, CheckStatus.PASS)
        self.assertIs(by_check["HC15"].status, CheckStatus.PASS)
        self.assertIs(by_check["HC16"].status, CheckStatus.PASS)
        self.assertIs(by_check["HC23"].status, CheckStatus.PASS)

        draft.code = draft.code.replace(
            "int rc = serve_client((int)Data[0]);",
            "int rc = serve_client((int)Data[0]); int parsed = parse_frame(Data, Size);",
        )
        missing_context = StaticHarnessGate(graph).check(draft, large, [feature])
        missing_by_check = {
            check.check_id: check for check in missing_context.checks
        }
        self.assertIs(missing_by_check["HC23"].status, CheckStatus.FAIL)
        self.assertIn("parse_frame", missing_by_check["HC23"].evidence)

    async def test_lifecycle_gate_ignores_unselected_alternative_handler(self) -> None:
        anchor = FunctionMetadata.create(
            name="event_handler", qualified_name="event_handler",
            signature="void event_handler(void)", file="server.c",
            start_line=1, end_line=1,
            source="void event_handler(void) {}",
        )
        alternative = FunctionMetadata.create(
            name="process_bin_flush", qualified_name="process_bin_flush",
            signature="void process_bin_flush(void)", file="server.c",
            start_line=2, end_line=2,
            source="void process_bin_flush(void) {}",
        )
        graph = GraphStore(AnalysisBundle(
            functions={
                anchor.function_id: anchor,
                alternative.function_id: alternative,
            },
            edges=[],
        ))

        status, _ = _lifecycle_step_status(
            [
                "For success, settings.flush_enabled is true; otherwise "
                "process_bin_flush emits an auth error."
            ],
            "settings.sasl = false; event_handler();",
            graph,
            anchor.function_id,
            proven_function_ids={anchor.function_id},
            proven_anchor_path=True,
        )

        self.assertIs(status, CheckStatus.PASS)

    async def test_long_function_excerpts_cover_the_complete_source(self) -> None:
        source = "".join(f"line_{index:05d}\n" for index in range(5000))
        function = FunctionMetadata.create(
            name="huge", qualified_name="huge", signature="void huge(void)",
            file="huge.c", start_line=10, end_line=5009, source=source,
        )

        excerpts = function_payload_excerpts(function, source_limit=4096)

        self.assertGreater(len(excerpts), 1)
        reconstructed = "".join(
            payload["source"]
            .replace("/* HARNESSCREATOR_SOURCE_PREFIX_TRUNCATED */\n", "")
            .replace("\n/* HARNESSCREATOR_SOURCE_SUFFIX_TRUNCATED */", "")
            for payload in excerpts
        )
        self.assertEqual(reconstructed, source)

    async def test_entry_batches_are_bounded_by_prompt_size(self) -> None:
        functions = {}
        for index in range(12):
            function = FunctionMetadata.create(
                name=f"large_{index}",
                qualified_name=f"large_{index}",
                signature=f"void large_{index}(void)",
                file=f"large_{index}.c",
                start_line=1,
                end_line=2,
                source="x" * 16_000,
            )
            functions[function.function_id] = function
        bundle = AnalysisBundle(functions=functions, edges=[])

        batches = EntryGeneratorAgent(
            ScriptedLLM([]), chunk_size=32, max_batch_chars=40_000
        ).batches(bundle)

        self.assertGreater(len(batches), 1)
        self.assertEqual(sum(map(len, batches)), len(functions))

    async def test_deterministic_generator_preserves_repeated_api_sites(self) -> None:
        function = FunctionMetadata.create(
            name="two_reads", qualified_name="two_reads",
            signature="void two_reads(int fd)", file="repeat.c",
            start_line=10, end_line=14,
            source=(
                "void two_reads(int fd) {\n"
                "  read(fd, first, 4);\n"
                "  consume();\n"
                "  read(fd, second, 8);\n"
                "}\n"
            ),
        )
        function.external_calls = ["read"]
        bundle = AnalysisBundle(functions={function.function_id: function}, edges=[])

        candidates = EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)

        self.assertEqual(len(candidates), 2)
        self.assertEqual({candidate.line for candidate in candidates}, {11, 13})

    async def test_verifier_prioritizes_requested_context_without_losing_candidate(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        candidate = next(
            item for item in EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)
            if item.source_api == "recv"
        )
        requested = next(
            function for function in bundle.functions.values()
            if function.function_id != candidate.function_id
        )
        base = {
            "status": "UNRESOLVED",
            "channel_kind": "network",
            "attacker_control": "unknown",
            "provenance_path": [],
            "consumer_hints": [],
            "evidence": [],
            "unknowns": ["need requested function"],
            "confidence": 0.5,
            "rationale": "expand",
            "first_acquisition_confirmed": False,
        }
        provider = ScriptedLLM([
            {**base, "context_complete": False, "requested_function_ids": [requested.function_id]},
            {**base, "context_complete": True, "requested_function_ids": []},
        ])

        await EntryVerifierAgent(provider, graph, depth=2, budget=2).run(candidate)

        first_context = {
            item["function_id"] for item in provider.calls[0]["payload"]["context"]
        }
        self.assertEqual(first_context, {candidate.function_id})
        first_frontier = provider.calls[0]["payload"]["available_context_functions"]
        self.assertIn(requested.function_id, {
            item["function_id"] for item in first_frontier
        })
        self.assertTrue(all("source" not in item for item in first_frontier))
        second_context = {
            item["function_id"] for item in provider.calls[1]["payload"]["context"]
        }
        self.assertIn(candidate.function_id, second_context)
        self.assertIn(requested.function_id, second_context)

    async def test_product_build_targets_precede_test_targets(self) -> None:
        self.assertEqual(
            prefer_product_build_targets(["testapp", "memcached", "fuzz-server"]),
            ["memcached", "testapp", "fuzz-server"],
        )

    async def test_small_feature_name_request_prefers_unique_product_definition(self) -> None:
        product = FunctionMetadata.create(
            name="tcp_read", signature="int tcp_read(void)", file="server.c",
            start_line=1, end_line=1, source="int tcp_read(void) { return 1; }",
        )
        product.build_targets = ["memcached"]
        test_helper = FunctionMetadata.create(
            name="tcp_read", signature="int tcp_read(void)", file="testapp.c",
            start_line=1, end_line=1, source="int tcp_read(void) { return 0; }",
        )
        test_helper.build_targets = ["testapp"]
        graph = GraphStore(AnalysisBundle(
            functions={
                product.function_id: product,
                test_helper.function_id: test_helper,
            },
            edges=[],
        ))
        agent = SmallFeatureAgent(ScriptedLLM([]), graph)

        self.assertEqual(
            agent._resolve_function_requests(["tcp_read"]),
            [product.function_id],
        )
        self.assertEqual(
            agent._resolve_function_requests([
                f"{product.function_id} tcp_read"
            ]),
            [product.function_id],
        )
        self.assertEqual(
            agent._resolve_allowed_function_identifier(
                f"{product.function_id} tcp_read",
                {product.function_id: product},
            ),
            product.function_id,
        )

        harness_agent = HarnessGeneratorAgent(
            ScriptedLLM([]),
            graph,
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/harness-test")),
        )
        self.assertEqual(
            harness_agent._resolve_function_identifiers("tcp_read"),
            [product.function_id],
        )
        self.assertEqual(
            harness_agent._resolve_function_identifiers(
                f"{product.function_id} tcp_read"
            ),
            [product.function_id],
        )

    async def test_entry_generator_normalizes_approximate_llm_call_line(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        serve = next(function for function in bundle.functions.values() if function.name == "serve_client")
        provider = ScriptedLLM([{
            "candidates": [{
                "function_id": serve.function_id,
                "source_api": "recv",
                "line": serve.start_line,
                "site_kind": "DIRECT_ACQUISITION",
                "first_acquisition": True,
                "boundary_subject": "network peer",
                "channel_hint": "network",
                "rationale": "same recv call but approximate declaration line",
                "confidence": 0.99,
            }],
        }])

        candidates = await EntryGeneratorAgent(provider, chunk_size=32).run(bundle)

        recv_candidates = [item for item in candidates if item.source_api == "recv"]
        self.assertEqual(len(recv_candidates), 1)
        self.assertEqual(recv_candidates[0].line, 17)

    async def test_entry_generator_rejects_compound_entry_sites(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        serve = next(function for function in bundle.functions.values() if function.name == "serve_client")
        provider = ScriptedLLM([{
            "candidates": [{
                "function_id": serve.function_id,
                "source_api": "argv / recv / select",
                "line": serve.start_line,
                "site_kind": "DIRECT_ACQUISITION",
                "first_acquisition": True,
                "boundary_subject": "network peer",
                "channel_hint": "network and argv",
                "rationale": "combined guess",
                "confidence": 0.9,
            }],
        }])

        candidates = await EntryGeneratorAgent(provider, chunk_size=32).run(bundle)

        self.assertFalse(any("/" in item.source_api for item in candidates))

    async def test_entry_generator_rejects_runtime_getter_as_downstream_entry(self) -> None:
        function = FunctionMetadata.create(
            name="lua_command", qualified_name="lua_command",
            signature="int lua_command(lua_State *L)", file="src/lua.c",
            start_line=20, end_line=22,
            source="int lua_command(lua_State *L) {\n  return lua_getfield(L, 1, \"key\");\n}",
        )
        function.external_calls = ["lua_getfield"]
        bundle = AnalysisBundle(functions={function.function_id: function}, edges=[])
        provider = ScriptedLLM([{"candidates": [{
            "function_id": function.function_id,
            "source_api": "lua_getfield",
            "line": 21,
            "site_kind": "DIRECT_ACQUISITION",
            "first_acquisition": True,
            "boundary_subject": "Lua caller",
            "channel_hint": "callback",
            "rationale": "reads a value from the VM stack",
            "confidence": 0.9,
        }]}])

        candidates = await EntryGeneratorAgent(provider).run(bundle)

        self.assertEqual(candidates, [])

    async def test_entry_generator_rejects_caller_of_program_input_wrapper(self) -> None:
        wrapper = FunctionMetadata.create(
            name="receive_packet", qualified_name="receive_packet",
            signature="int receive_packet(int fd, void *buf)", file="src/net.c",
            start_line=1, end_line=3,
            source="int receive_packet(int fd, void *buf) {\n  return recv(fd, buf, 64, 0);\n}",
        )
        wrapper.external_calls = ["recv"]
        caller = FunctionMetadata.create(
            name="handle_packet", qualified_name="handle_packet",
            signature="int handle_packet(int fd)", file="src/net.c",
            start_line=5, end_line=8,
            source="int handle_packet(int fd) {\n  char buf[64];\n  return receive_packet(fd, buf);\n}",
        )
        caller.callees = [wrapper.function_id]
        wrapper.callers = [caller.function_id]
        bundle = AnalysisBundle(
            functions={wrapper.function_id: wrapper, caller.function_id: caller}, edges=[]
        )
        provider = ScriptedLLM([{"candidates": [{
            "function_id": caller.function_id,
            "source_api": "receive_packet",
            "line": 7,
            "site_kind": "DIRECT_ACQUISITION",
            "first_acquisition": True,
            "boundary_subject": "network peer",
            "channel_hint": "network",
            "rationale": "wrapper returns network data",
            "confidence": 0.9,
        }]}])

        candidates = await EntryGeneratorAgent(provider).run(bundle)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].function_id, wrapper.function_id)
        self.assertEqual(candidates[0].source_api, "recv")

    async def test_entry_generator_filters_non_product_sources_before_llm(self) -> None:
        test_function = FunctionMetadata.create(
            name="LLVMFuzzerTestOneInput", qualified_name="LLVMFuzzerTestOneInput",
            signature="int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)",
            file="tests/fuzz_target.c", start_line=1, end_line=3,
            source="int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {\n return 0;\n}",
        )
        test_function.external_calls = ["read"]
        bundle = AnalysisBundle(functions={test_function.function_id: test_function}, edges=[])
        provider = ScriptedLLM([])

        candidates = await EntryGeneratorAgent(provider).run(bundle)

        self.assertEqual(candidates, [])
        self.assertEqual(provider.calls, [])

    async def test_entry_generator_recognizes_main_argv_as_process_start(self) -> None:
        function = FunctionMetadata.create(
            name="main", qualified_name="main",
            signature="int main(int argc, char **argv)", file="src/main.c",
            start_line=7, end_line=9,
            source="int main(int argc, char **argv) {\n  return argc > 1 && argv[1][0];\n}",
        )
        bundle = AnalysisBundle(functions={function.function_id: function}, edges=[])

        candidates = EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)

        self.assertEqual(len(candidates), 1)
        self.assertIs(candidates[0].site_kind, EntrySiteKind.PROCESS_START)
        self.assertEqual(candidates[0].source_api, "argv")

    async def test_entry_generator_rejects_accept_as_non_data_prerequisite(self) -> None:
        function = FunctionMetadata.create(
            name="accept_client", qualified_name="accept_client",
            signature="int accept_client(int listener)", file="src/server.c",
            start_line=10, end_line=12,
            source=(
                "int accept_client(int listener) {\n"
                "  return accept(listener, 0, 0);\n"
                "}\n"
            ),
        )
        function.external_calls = ["accept"]
        bundle = AnalysisBundle(functions={function.function_id: function}, edges=[])
        provider = ScriptedLLM([{"candidates": [{
            "function_id": function.function_id,
            "source_api": "accept",
            "line": 11,
            "site_kind": "DIRECT_ACQUISITION",
            "first_acquisition": True,
            "boundary_subject": "network peer",
            "channel_hint": "network",
            "rationale": "a peer creates a connection",
            "confidence": 0.99,
        }]}])

        candidates = await EntryGeneratorAgent(provider).run(bundle)

        self.assertEqual(candidates, [])

    async def test_entry_generator_rejects_project_member_named_read(self) -> None:
        function = FunctionMetadata.create(
            name="consume_body", qualified_name="consume_body",
            signature="int consume_body(conn *c)", file="src/server.c",
            start_line=20, end_line=22,
            source=(
                "int consume_body(conn *c) {\n"
                "  return c->read(c, c->buffer, c->size);\n"
                "}\n"
            ),
        )
        # This is the conservative shape emitted by the bootstrap analyzer.
        # The member call is a project callback, not a libc read boundary.
        function.external_calls = ["read"]
        bundle = AnalysisBundle(functions={function.function_id: function}, edges=[])

        candidates = EntryGeneratorAgent(
            ScriptedLLM([])
        )._deterministic_candidates(bundle)

        self.assertEqual(candidates, [])

    async def test_deterministic_generator_does_not_create_accept_entry(self) -> None:
        function = FunctionMetadata.create(
            name="accept_client", qualified_name="accept_client",
            signature="int accept_client(int listener)", file="src/server.c",
            start_line=10, end_line=12,
            source="int accept_client(int listener) { return accept(listener, 0, 0); }",
        )
        function.external_calls = ["accept"]
        bundle = AnalysisBundle(functions={function.function_id: function}, edges=[])

        candidates = EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)

        self.assertEqual(candidates, [])

    async def test_verifier_rejects_downstream_site_even_with_external_provenance(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        candidate = next(
            item for item in EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)
            if item.source_api == "recv"
        )
        function = bundle.functions[candidate.function_id]
        provider = ScriptedLLM([{
            "status": "VERIFIED", "channel_kind": "network", "attacker_control": "full",
            "provenance_path": [{"function_id": function.function_id, "relation": "peer data"}],
            "consumer_hints": [],
            "evidence": [{
                "kind": "source", "function_id": function.function_id,
                "file": function.file, "line": candidate.line,
                "detail": "the proposed site only consumes already acquired data",
            }],
            "unknowns": [], "confidence": 0.99,
            "rationale": "external provenance exists but this is not the first acquisition",
            "first_acquisition_confirmed": False,
            "context_complete": True, "requested_function_ids": [],
        }])

        record = await EntryVerifierAgent(provider, GraphStore(bundle)).run(candidate)

        self.assertIs(record.status, Verdict.REJECTED)
        self.assertTrue(any("first external acquisition" in item for item in record.unknowns))

    async def test_static_gate_rejects_generator_blockers(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(function for function in bundle.functions.values() if function.name == "serve_client")
        draft = HarnessDraft(
            manifest=HarnessManifest(
                harness_id="harness-test",
                large_feature_id="lf-test",
                source_file="fuzz_target.cc",
                build_target="frame-server",
                engine="libfuzzer",
                sanitizers=["address", "undefined"],
                execution_model="in_process_reset",
                headers=["target.h"],
                libraries=[],
                min_size=0,
                max_size=4096,
                dispatch_strategy="one_job_per_feature",
                expected_anchors=[serve.function_id],
                expected_consumers=[serve.function_id],
            ),
            code=(
                "extern int serve_client(int);\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {\n"
                "  if (Size < 1) return 0; int status = serve_client((int)Data[0]); return status != 0;\n}\n"
            ),
            generation_blockers=["required lifecycle initialization is unresolved"],
        )
        large = SimpleNamespace(
            common_anchor=serve.function_id,
            common_initialization=[],
            common_cleanup=[],
            required_functions=[serve.function_id],
            variants=[],
            prerequisite_state=[],
            small_feature_ids=[],
        )

        report = StaticHarnessGate(graph).check(draft, large, [])

        blockers = [check for check in report.checks if check.check_id == "HC18"]
        self.assertEqual(len(blockers), 1)
        self.assertIs(blockers[0].status, CheckStatus.FAIL)
        self.assertTrue(any(check.check_id == "HC20" for check in report.checks))
        self.assertFalse(report.passed)

    async def test_static_gate_does_not_count_abi_parameter_names_as_input_flow(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(function for function in bundle.functions.values() if function.name == "serve_client")
        draft = HarnessDraft(
            manifest=HarnessManifest(
                harness_id="h-unused", large_feature_id="lf-unused", source_file="fuzz_target.cc",
                build_target="frame-server", engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=[], libraries=[], min_size=0,
                max_size=4096, dispatch_strategy="one_job_per_feature",
                expected_anchors=[serve.function_id], expected_consumers=[serve.function_id],
            ),
            code=(
                "extern int serve_client(int);\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {\n"
                "  (void)Data; (void)Size; int status = serve_client(1); return status;\n}\n"
            ),
            self_audit=[
                {"check_id": check_id, "status": "PASS", "evidence": "claimed"}
                for check_id in CHECKLIST_NAMES
            ],
        )
        feature = SimpleNamespace(
            small_feature_id="sf-unused", input_bindings=[{"source": "fuzz data"}],
            input_binding_proven=True, boundary_preserved=True, entry_paths_complete=True,
            anchor_action_complete=True, action_order_complete=True,
            function_references_complete=True,
            entry_order_complete=True,
            planning_complete=True, planning_blockers=[],
            actions=[{"function_id": serve.function_id}],
            initialization=[],
            cleanup_success=[], cleanup_failure=[],
        )
        large = SimpleNamespace(
            common_anchor=serve.function_id, common_initialization=[], common_cleanup=[],
            required_functions=[serve.function_id], variants=[], prerequisite_state=[],
            small_feature_ids=[feature.small_feature_id],
        )

        report = StaticHarnessGate(graph).check(draft, large, [feature])
        flow = next(check for check in report.checks if check.check_id == "HC04")
        self.assertIs(flow.status, CheckStatus.FAIL)

    async def test_static_gate_accepts_real_public_caller_path_to_internal_anchor(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        draft = HarnessDraft(
            manifest=HarnessManifest(
                harness_id="h-caller", large_feature_id="lf-caller",
                source_file="fuzz_target.cc", build_target="frame-server",
                engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=["target.h"], libraries=[],
                min_size=1, max_size=4096, dispatch_strategy="one_job_per_feature",
                expected_anchors=[parse.function_id], expected_consumers=[parse.function_id],
                build_command=["true"], binary="/tmp/fuzzer",
            ),
            code=(
                "#include \"target.h\"\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {\n"
                "  if (Size < 1) return 0; int rc = serve_client((int)Data[0]); return rc < -1;\n}\n"
            ),
            self_audit=[
                {"check_id": check_id, "status": "PASS", "evidence": "claimed"}
                for check_id in CHECKLIST_NAMES
            ],
        )
        large = SimpleNamespace(
            common_anchor=parse.function_id, common_initialization=[], common_cleanup=[],
            required_functions=[parse.function_id, serve.function_id], variants=[],
            prerequisite_state=[], small_feature_ids=[],
        )

        report = StaticHarnessGate(graph).check(draft, large, [])

        anchor = next(check for check in report.checks if check.check_id == "HC08")
        self.assertIs(anchor.status, CheckStatus.PASS)
        self.assertIn("serve_client", anchor.evidence)

    async def test_static_gate_rejects_process_boundary_inside_libfuzzer_callback(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        draft = HarnessDraft(
            manifest=HarnessManifest(
                harness_id="h-child", large_feature_id="lf-child",
                source_file="fuzz_target.cc", build_target="frame-server",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="fork_per_input", headers=["target.h"], libraries=[],
                min_size=1, max_size=4096,
                dispatch_strategy="one_job_per_feature",
                expected_anchors=[serve.function_id], expected_consumers=[serve.function_id],
                build_command=["true"], binary="/tmp/fuzzer",
            ),
            code=(
                "extern int serve_client(int);\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {\n"
                "  if (Size < 1) return 0; pid_t p = fork(); if (p == 0) serve_client(Data[0]); "
                "waitpid(p, 0, 0); return 0;\n}\n"
            ),
            self_audit=[
                {"check_id": check_id, "status": "PASS", "evidence": "claimed"}
                for check_id in CHECKLIST_NAMES
            ],
        )
        large = SimpleNamespace(
            common_anchor=serve.function_id, common_initialization=[], common_cleanup=[],
            required_functions=[serve.function_id], variants=[], prerequisite_state=[],
            small_feature_ids=[],
        )

        report = StaticHarnessGate(graph).check(draft, large, [])

        boundary = next(check for check in report.checks if check.check_id == "HC21")
        self.assertIs(boundary.status, CheckStatus.FAIL)
        self.assertIn("fork", boundary.evidence)

    async def test_static_gate_rejects_including_application_implementation(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        draft = HarnessDraft(
            manifest=HarnessManifest(
                harness_id="h-include", large_feature_id="lf-include",
                source_file="fuzz_target.cc", build_target="frame-server",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="in_process_reset", headers=["target.h"], libraries=[],
                min_size=1, max_size=4096,
                dispatch_strategy="one_job_per_feature",
                expected_anchors=[serve.function_id], expected_consumers=[serve.function_id],
                build_command=["true"], binary="/tmp/fuzzer",
            ),
            code=(
                "#include \"target.c\"\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {\n"
                "  if (Size < 1) return 0; return serve_client(Data[0]);\n}\n"
            ),
            self_audit=[
                {"check_id": check_id, "status": "PASS", "evidence": "claimed"}
                for check_id in CHECKLIST_NAMES
            ],
        )
        large = SimpleNamespace(
            common_anchor=serve.function_id, common_initialization=[], common_cleanup=[],
            required_functions=[serve.function_id], variants=[], prerequisite_state=[],
            small_feature_ids=[],
        )

        report = StaticHarnessGate(graph).check(draft, large, [])

        boundary = next(check for check in report.checks if check.check_id == "HC22")
        self.assertIs(boundary.status, CheckStatus.FAIL)
        self.assertIn("target.c", boundary.evidence)

    async def test_verified_without_provenance_is_downgraded(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        candidate = EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)[0]
        function = bundle.functions[candidate.function_id]
        events = []
        provider = ScriptedLLM([{
            "status": "VERIFIED",
            "channel_kind": "network",
            "attacker_control": "full",
            "provenance_path": [],
            "consumer_hints": [],
            "evidence": [{
                "kind": "source", "function_id": function.function_id, "file": function.file,
                "line": candidate.line, "detail": "recv call",
            }],
            "unknowns": [],
            "confidence": 0.9,
            "rationale": "insufficient despite claimed verdict",
            "first_acquisition_confirmed": True,
            "context_complete": True,
            "requested_function_ids": [],
        }])
        record = await EntryVerifierAgent(
            provider,
            GraphStore(bundle),
            depth=2,
            trace=lambda agent, event, details: events.append((agent, event, details)),
        ).run(candidate)
        self.assertIs(record.status, Verdict.UNRESOLVED)
        self.assertTrue(any("provenance" in item for item in record.unknowns))
        event_names = [event for _, event, _ in events]
        self.assertIn("context_expanded", event_names)
        self.assertIn("round_decision", event_names)
        final = next(details for _, event, details in events if event == "final_verdict")
        self.assertEqual(final["model_status"], "VERIFIED")
        self.assertEqual(final["final_status"], "UNRESOLVED")
        self.assertTrue(final["downgrade_reasons"])

    async def test_low_confidence_verified_entry_is_not_accepted(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        candidate = next(
            item for item in EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)
            if item.source_api == "recv"
        )
        function = bundle.functions[candidate.function_id]
        provider = ScriptedLLM([{
            "status": "VERIFIED", "channel_kind": "network", "attacker_control": "full",
            "provenance_path": [{"function_id": function.function_id, "relation": "recv source"}],
            "consumer_hints": [],
            "evidence": [{
                "kind": "source", "function_id": function.function_id,
                "file": function.file, "line": candidate.line, "detail": "recv",
            }],
            "unknowns": [], "confidence": 0.50, "rationale": "weak conclusion",
            "first_acquisition_confirmed": True,
            "context_complete": True, "requested_function_ids": [],
        }])

        record = await EntryVerifierAgent(provider, GraphStore(bundle)).run(candidate)

        self.assertIs(record.status, Verdict.UNRESOLVED)
        self.assertTrue(any("confidence" in item for item in record.unknowns))

    async def test_verifier_cannot_promote_generator_evidence_to_verified(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        candidate = EntryGeneratorAgent(ScriptedLLM([]))._deterministic_candidates(bundle)[0]
        provider = ScriptedLLM([{
            "status": "VERIFIED",
            "channel_kind": "network",
            "attacker_control": "full",
            "provenance_path": [{
                "function_id": candidate.function_id,
                "relation": "claims external bytes",
            }],
            "consumer_hints": ["fn-invented"],
            "evidence": [{
                "kind": "source",
                "function_id": candidate.function_id,
                "file": "wrong-file.c",
                "line": 1,
                "detail": "invalid evidence",
            }],
            "unknowns": [],
            "confidence": 0.99,
            "rationale": "unsupported verification",
            "first_acquisition_confirmed": True,
            "context_complete": True,
            "requested_function_ids": [],
        }])

        record = await EntryVerifierAgent(provider, GraphStore(bundle), depth=1).run(candidate)

        self.assertIs(record.status, Verdict.UNRESOLVED)
        self.assertEqual(record.consumer_hints, [])
        self.assertTrue(any("line-level evidence" in item for item in record.unknowns))

    async def test_entry_batches_use_provider_concurrency(self) -> None:
        class ProbeProvider:
            max_concurrency = 3

            def __init__(self):
                self.active = 0
                self.maximum = 0

            async def complete_json(self, **kwargs):
                self.active += 1
                self.maximum = max(self.maximum, self.active)
                await asyncio.sleep(0.02)
                self.active -= 1
                return {"candidates": []}

            async def close(self):
                return None

        provider = ProbeProvider()
        bundle = StaticAnalyzer(FIXTURE).index()
        await EntryGeneratorAgent(provider, chunk_size=1).run(bundle)
        self.assertEqual(provider.maximum, 2)


class SmallFeaturePartitionTest(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_entry_site_is_valid_in_runtime_order(self) -> None:
        self.assertTrue(_entry_orders_compatible([
            ["entry-a", "entry-b", "entry-a"],
            ["entry-a", "entry-b"],
        ]))
        self.assertFalse(_entry_orders_compatible([
            ["entry-a", "entry-b"],
            ["entry-b", "entry-a"],
        ]))

    async def test_later_context_round_does_not_erase_other_operations(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        entry = EntryRecord(
            entry_id="entry-multi-round", candidate_id="candidate-multi-round",
            status=Verdict.VERIFIED, entry_function_id=serve.function_id,
            source_api="recv", channel_kind="network", attacker_control="full",
            provenance_path=[{"function_id": serve.function_id, "relation": "socket bytes"}],
            consumer_hints=[],
            evidence=[Evidence("source", serve.function_id, serve.file, 17, "recv")],
            unknowns=[], verifier_confidence=0.9,
        )

        def feature(name: str, *, bound: bool) -> dict:
            return {
                "name": name, "description": name,
                "root_entries": [entry.entry_id], "supporting_entries": [],
                "entry_call_order": [entry.entry_id], "harness_anchor": serve.function_id,
                "anchor_rationale": "normal boundary", "boundary_preserved": True,
                "preconditions": [], "initialization": [],
                "required_functions": [serve.function_id],
                "actions": [{
                    "action_id": name, "function_id": serve.function_id,
                    "consumes": ["bytes"], "produces": ["status"],
                    "allowed_after": [], "success_condition": name,
                }],
                "input_bindings": ([{
                    "source": "per-iteration fuzz data", "destination": "network recv",
                    "transform": "bounded loopback socket delivery",
                }] if bound else []),
                "cleanup_success": [], "cleanup_failure": [],
                "stable_post_state": name, "completion_oracle": name,
                "evidence": [{
                    "kind": "call", "function_id": serve.function_id, "file": serve.file,
                    "line": serve.start_line, "detail": name,
                }],
                "unknowns": [], "confidence": 0.9,
                "build_target": "frame-server", "isolation_mode": "in_process_reset",
            }

        provider = ScriptedLLM([
            {
                "small_features": [feature("operation-a", bound=False), feature("operation-b", bound=False)],
                "unrelated_entries": [], "context_complete": False,
                "requested_function_ids": [parse.function_id],
            },
            {
                "small_features": [feature("operation-a", bound=True)],
                "unrelated_entries": [], "context_complete": True,
                "requested_function_ids": [],
            },
            {"operation_groups": []},
        ])

        features = await SmallFeatureAgent(provider, graph, depth=2, budget=8).run([entry])

        self.assertEqual({item.name for item in features}, {"operation-a", "operation-b"})
        self.assertEqual(len(provider.calls), 3)

    async def test_expands_context_when_feature_model_requests_more_functions(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        entry = EntryRecord(
            entry_id="entry-expand",
            candidate_id="candidate-expand",
            status=Verdict.VERIFIED,
            entry_function_id=serve.function_id,
            source_api="recv",
            channel_kind="network",
            attacker_control="full",
            provenance_path=[{"function_id": serve.function_id, "relation": "socket bytes"}],
            consumer_hints=[parse.function_id],
            evidence=[Evidence("source", serve.function_id, serve.file, 17, "recv")],
            unknowns=[],
            verifier_confidence=0.9,
        )
        feature = {
            "name": "receive and parse",
            "description": "normal frame operation",
            "root_entries": [entry.entry_id],
            "supporting_entries": [],
            "entry_call_order": [entry.entry_id],
            "harness_anchor": serve.function_id,
            "anchor_rationale": "normal receive boundary",
            "boundary_preserved": True,
            "preconditions": [], "initialization": [],
            "required_functions": [serve.function_id, parse.function_id],
            "actions": [{
                "action_id": "serve", "function_id": serve.function_id,
                "consumes": ["socket bytes"], "produces": ["status"],
                "allowed_after": [], "success_condition": "serve_client returns",
            }],
            "input_bindings": [{
                "source": "per-iteration fuzzer bytes", "destination": "socket",
                "transform": "bounded socket delivery",
            }],
            "cleanup_success": [], "cleanup_failure": [],
            "stable_post_state": "request complete",
            "completion_oracle": "serve_client returns",
            "evidence": [{
                "kind": "call", "function_id": serve.function_id, "file": serve.file,
                "line": serve.start_line, "detail": "normal operation boundary",
            }],
            "unknowns": [], "confidence": 0.9,
            "build_target": "frame-server", "isolation_mode": "in_process_reset",
        }
        provider = ScriptedLLM([
            {
                "small_features": [], "unrelated_entries": [],
                "context_complete": False,
                "requested_function_ids": [parse.function_id],
            },
            {
                "small_features": [feature], "unrelated_entries": [],
                "context_complete": True, "requested_function_ids": [],
            },
        ])

        features = await SmallFeatureAgent(provider, graph, depth=2, budget=8).run([entry])

        self.assertEqual(len(features), 1)
        self.assertEqual(len(provider.calls), 2)
        self.assertEqual(
            [item["function_id"] for item in provider.calls[0]["payload"]["context"]],
            [serve.function_id],
        )
        first_frontier = provider.calls[0]["payload"]["available_context_functions"]
        self.assertIn(parse.function_id, {
            item["function_id"] for item in first_frontier
        })
        self.assertTrue(all("source" not in item for item in first_frontier))
        self.assertIn(parse.function_id, features[0].required_functions)
        self.assertTrue(provider.calls[1]["payload"]["previous_round"])
        self.assertEqual(
            [
                item["function_id"]
                for item in provider.calls[1]["payload"]["context"]
            ],
            [parse.function_id],
        )
        self.assertEqual(
            {
                item["function_id"]
                for item in provider.calls[1]["payload"][
                    "opened_context_functions"
                ]
            },
            {serve.function_id, parse.function_id},
        )

    async def test_context_turns_continue_beyond_graph_depth_until_model_decides(self) -> None:
        root = FunctionMetadata.create(
            name="root_receive", qualified_name="root_receive",
            signature="int root_receive(void)", file="server.c",
            start_line=1, end_line=3,
            source="int root_receive(void) { return middle_dispatch(); }",
        )
        middle = FunctionMetadata.create(
            name="middle_dispatch", qualified_name="middle_dispatch",
            signature="int middle_dispatch(void)", file="server.c",
            start_line=5, end_line=7,
            source="int middle_dispatch(void) { return deep_parse(); }",
        )
        deep = FunctionMetadata.create(
            name="deep_parse", qualified_name="deep_parse",
            signature="int deep_parse(void)", file="server.c",
            start_line=9, end_line=11,
            source="int deep_parse(void) { return 0; }",
        )
        bundle = AnalysisBundle(
            functions={item.function_id: item for item in (root, middle, deep)},
            edges=[
                CallEdge("edge-root-middle", root.function_id, middle.function_id),
                CallEdge("edge-middle-deep", middle.function_id, deep.function_id),
            ],
        )
        entry = EntryRecord(
            entry_id="entry-final-round", candidate_id="candidate-final-round",
            status=Verdict.VERIFIED, entry_function_id=root.function_id,
            source_api="recv", channel_kind="network", attacker_control="full",
            provenance_path=[{"function_id": root.function_id, "relation": "socket bytes"}],
            consumer_hints=[],
            evidence=[Evidence("source", root.function_id, root.file, 1, "entry")],
            unknowns=[], verifier_confidence=0.9,
        )
        feature = {
            "name": "receive through deep parser",
            "description": "normal request path",
            "root_entries": [entry.entry_id], "supporting_entries": [],
            "entry_call_order": [entry.entry_id],
            "harness_anchor": root.function_id,
            "anchor_rationale": "normal receive boundary", "boundary_preserved": True,
            "preconditions": [], "initialization": [],
            "required_functions": [root.function_id, middle.function_id, deep.function_id],
            "actions": [
                {
                    "action_id": "receive", "function_id": root.function_id,
                    "consumes": ["socket bytes"], "produces": ["dispatch"],
                    "allowed_after": [], "success_condition": "dispatches",
                },
                {
                    "action_id": "dispatch", "function_id": middle.function_id,
                    "consumes": ["dispatch"], "produces": ["parse request"],
                    "allowed_after": ["receive"], "success_condition": "calls parser",
                },
                {
                    "action_id": "parse", "function_id": deep.function_id,
                    "consumes": ["parse request"], "produces": ["result"],
                    "allowed_after": ["dispatch"], "success_condition": "returns",
                },
            ],
            "input_bindings": [{
                "source": "per-iteration fuzz data", "destination": "network recv",
                "transform": "bounded socket delivery",
            }],
            "cleanup_success": [], "cleanup_failure": [],
            "stable_post_state": "request complete",
            "completion_oracle": "deep parser returns",
            "evidence": [{
                "kind": "source", "function_id": root.function_id,
                "file": root.file, "line": root.start_line,
                "detail": "normal request boundary",
            }],
            "unknowns": [], "confidence": 0.9,
            "build_target": "server", "isolation_mode": "in_process_reset",
        }
        provider = ScriptedLLM([
            {
                "small_features": [], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": False,
                "requested_function_ids": [middle.function_id],
            },
            {
                "small_features": [], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": False,
                "requested_function_ids": [deep.function_id],
            },
            {
                "small_features": [feature], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": True,
                "requested_function_ids": [],
            },
        ])

        features = await SmallFeatureAgent(
            provider, GraphStore(bundle), depth=1, budget=8
        ).run([entry])

        self.assertEqual(len(provider.calls), 3)
        self.assertIn(deep.function_id, {
            item["function_id"] for item in provider.calls[2]["payload"]["context"]
        })
        self.assertEqual(len(features), 1)
        self.assertTrue(features[0].planning_complete)

    async def test_evicted_source_remains_valid_feature_evidence_in_same_session(self) -> None:
        entry_function = FunctionMetadata.create(
            name="read_packet", qualified_name="read_packet",
            signature="int read_packet(int fd)", file="server.c",
            start_line=10, end_line=12,
            source="int read_packet(int fd) { char b[8]; return recv(fd, b, 8, 0); }",
        )
        anchor = FunctionMetadata.create(
            name="event_handler", qualified_name="event_handler",
            signature="int event_handler(int fd)", file="server.c",
            start_line=1, end_line=4,
            source=(
                "int event_handler(int fd) {\n"
                "  int n = read_packet(fd);\n"
                "  return n > 0 ? parse_packet() : n;\n"
                "}"
            ),
        )
        parser = FunctionMetadata.create(
            name="parse_packet", qualified_name="parse_packet",
            signature="int parse_packet(void)", file="parser.c",
            start_line=1, end_line=1,
            source="int parse_packet(void) { return 0; }",
        )
        for function in (entry_function, anchor, parser):
            function.build_targets = ["server"]
        bundle = AnalysisBundle(
            functions={
                function.function_id: function
                for function in (entry_function, anchor, parser)
            },
            edges=[
                CallEdge("edge-anchor-read", anchor.function_id, entry_function.function_id),
                CallEdge("edge-anchor-parse", anchor.function_id, parser.function_id),
            ],
        )
        entry = EntryRecord(
            entry_id="entry-eviction", candidate_id="candidate-eviction",
            status=Verdict.VERIFIED,
            entry_function_id=entry_function.function_id,
            source_api="recv", channel_kind="network", attacker_control="full",
            provenance_path=[{
                "function_id": entry_function.function_id,
                "relation": "recv acquires socket bytes",
            }],
            consumer_hints=[parser.function_id],
            evidence=[Evidence(
                "source", entry_function.function_id, entry_function.file,
                entry_function.start_line, "recv acquires bytes",
            )],
            unknowns=[], verifier_confidence=0.95,
        )
        feature = {
            "name": "event-driven packet parsing",
            "description": "event callback receives and parses one packet",
            "root_entries": [entry.entry_id], "supporting_entries": [],
            "entry_call_order": [entry.entry_id],
            # Models may use the exact name exposed next to the ID. It must
            # resolve to the already-opened authoritative function.
            "harness_anchor": anchor.name,
            "anchor_rationale": "normal callback boundary",
            "boundary_preserved": True,
            "preconditions": [], "initialization": [],
            "required_functions": [
                f"{anchor.function_id}::{anchor.name}",
                entry_function.function_id,
                parser.function_id,
            ],
            "actions": [
                {
                    "action_id": "dispatch", "function_id": anchor.function_id,
                    "consumes": ["socket event"], "produces": ["read call"],
                    "allowed_after": [], "success_condition": "handler runs",
                },
                {
                    "action_id": "read", "function_id": entry_function.function_id,
                    "consumes": ["socket bytes"], "produces": ["packet"],
                    "allowed_after": ["dispatch"], "success_condition": "recv succeeds",
                },
                {
                    "action_id": "parse", "function_id": parser.function_id,
                    "consumes": ["packet"], "produces": ["status"],
                    "allowed_after": ["read"], "success_condition": "parser returns",
                },
            ],
            "input_bindings": [{
                "source": "per-iteration fuzzer bytes",
                "destination": "network recv socket",
                "transform": "bounded socket delivery",
            }],
            "cleanup_success": [], "cleanup_failure": [],
            "stable_post_state": "callback returned",
            "completion_oracle": "event_handler returns",
            "evidence": [{
                "kind": "source", "function_id": anchor.name,
                "file": anchor.file, "line": anchor.start_line,
                "detail": "normal event callback calls the Entry and parser",
            }],
            "unknowns": [], "confidence": 0.95,
            "build_target": "server", "isolation_mode": "loopback_network",
        }
        provider = ScriptedLLM([
            {
                "small_features": [], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": False,
                "requested_function_ids": [anchor.function_id],
            },
            {
                "small_features": [], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": False,
                "requested_function_ids": [parser.function_id],
            },
            {
                "small_features": [feature], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": True,
                "requested_function_ids": [],
            },
        ])

        features = await SmallFeatureAgent(
            provider, GraphStore(bundle), depth=2, budget=2
        ).run([entry])

        self.assertEqual(len(features), 1)
        self.assertTrue(features[0].planning_complete)
        self.assertEqual(features[0].harness_anchor, anchor.function_id)
        third_payload = provider.calls[2]["payload"]
        self.assertNotIn(anchor.function_id, {
            item["function_id"] for item in third_payload["opened_context_functions"]
        })
        self.assertIn(anchor.function_id, {
            item["function_id"]
            for item in third_payload["previously_opened_context_functions"]
        })

    async def test_small_feature_hard_turn_limit_only_stops_no_progress_loop(self) -> None:
        function = FunctionMetadata.create(
            name="stuck_receive", qualified_name="stuck_receive",
            signature="int stuck_receive(void)", file="stuck.c",
            start_line=1, end_line=3,
            source="int stuck_receive(void) { return 0; }",
        )
        entry = EntryRecord(
            entry_id="entry-stuck", candidate_id="candidate-stuck",
            status=Verdict.VERIFIED, entry_function_id=function.function_id,
            source_api="recv", channel_kind="network", attacker_control="full",
            provenance_path=[{"function_id": function.function_id, "relation": "socket"}],
            consumer_hints=[],
            evidence=[Evidence("source", function.function_id, function.file, 1, "entry")],
            unknowns=[], verifier_confidence=0.9,
        )
        unresolved = {
            "small_features": [], "entry_resolutions": [],
            "unrelated_entries": [], "context_complete": False,
            "requested_function_ids": [],
        }
        provider = ScriptedLLM([unresolved, unresolved, unresolved])
        agent = SmallFeatureAgent(
            provider,
            GraphStore(AnalysisBundle(
                functions={function.function_id: function}, edges=[]
            )),
            depth=1,
            budget=8,
            max_turns=3,
        )

        features = await agent.run([entry])

        self.assertEqual(features, [])
        self.assertEqual(len(provider.calls), 3)

    async def test_opens_known_function_pointer_target_outside_call_frontier(self) -> None:
        root = FunctionMetadata.create(
            name="install_reader", qualified_name="install_reader",
            signature="int install_reader(void)", file="callbacks.c",
            start_line=1, end_line=3,
            source="int install_reader(void) { reader = tcp_read; return 0; }",
        )
        target = FunctionMetadata.create(
            name="tcp_read", qualified_name="tcp_read",
            signature="int tcp_read(void)", file="callbacks.c",
            start_line=5, end_line=7,
            source="int tcp_read(void) { return 0; }",
        )
        retained = [
            FunctionMetadata.create(
                name=f"retained_{index}", qualified_name=f"retained_{index}",
                signature=f"int retained_{index}(void)", file="callbacks.c",
                start_line=10 + index * 2, end_line=11 + index * 2,
                source=f"int retained_{index}(void) {{ return {index}; }}",
            )
            for index in range(4)
        ]
        bundle = AnalysisBundle(
            functions={
                root.function_id: root,
                target.function_id: target,
                **{function.function_id: function for function in retained},
            },
            edges=[],
        )
        entry = EntryRecord(
            entry_id="entry-callback-target", candidate_id="candidate-callback-target",
            status=Verdict.VERIFIED, entry_function_id=root.function_id,
            source_api="recv", channel_kind="network", attacker_control="full",
            provenance_path=[{"function_id": root.function_id, "relation": "socket bytes"}],
            consumer_hints=[],
            evidence=[Evidence("source", root.function_id, root.file, 1, "entry")],
            unknowns=[], verifier_confidence=0.9,
            inspected_function_ids=[
                root.function_id,
                *(function.function_id for function in retained),
            ],
        )
        feature = {
            "name": "install and call socket reader", "description": "callback lifecycle",
            "root_entries": [entry.entry_id], "supporting_entries": [],
            "entry_call_order": [entry.entry_id],
            "harness_anchor": root.function_id,
            "anchor_rationale": "registration boundary", "boundary_preserved": True,
            "preconditions": [], "initialization": [],
            "required_functions": [root.function_id, target.function_id],
            "actions": [{
                "action_id": "install", "function_id": root.function_id,
                "consumes": ["reader callback"], "produces": ["installed reader"],
                "allowed_after": [], "success_condition": "callback installed",
            }],
            "input_bindings": [{
                "source": "per-iteration fuzz data", "destination": "network recv callback",
                "transform": "bounded socket delivery",
            }],
            "cleanup_success": [], "cleanup_failure": [],
            "stable_post_state": "reader installed", "completion_oracle": "install returns",
            "evidence": [{
                "kind": "source", "function_id": root.function_id,
                "file": root.file, "line": root.start_line,
                "detail": "function pointer assignment",
            }],
            "unknowns": [], "confidence": 0.9,
            "build_target": "server", "isolation_mode": "in_process_reset",
        }
        provider = ScriptedLLM([
            {
                "small_features": [], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": False,
                "requested_function_ids": [target.name],
            },
            {
                "small_features": [feature], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": True,
                "requested_function_ids": [],
            },
        ])

        features = await SmallFeatureAgent(
            provider, GraphStore(bundle), depth=1, budget=4
        ).run([entry])

        self.assertEqual(len(provider.calls), 2)
        self.assertEqual(provider.calls[0]["payload"]["available_context_functions"], [])
        self.assertIn(target.function_id, {
            item["function_id"] for item in provider.calls[1]["payload"]["context"]
        })
        self.assertEqual(len(features), 1)
        self.assertTrue(features[0].function_references_complete)

    async def test_unused_process_argv_cannot_prove_input_binding(self) -> None:
        function = FunctionMetadata.create(
            name="main", qualified_name="main",
            signature="int main(int argc, char **argv)", file="unused.c",
            start_line=1, end_line=3,
            source="int main(int argc, char **argv) { return run_fixed_suite(); }",
        )
        entry = EntryRecord(
            entry_id="entry-argv-unused", candidate_id="candidate-argv-unused",
            status=Verdict.VERIFIED, entry_function_id=function.function_id,
            source_api="argv", channel_kind="PROCESS_START argv",
            attacker_control="full", provenance_path=[], consumer_hints=[],
            evidence=[Evidence("source", function.function_id, function.file, 1, "argv")],
            unknowns=[], verifier_confidence=0.9,
            site_kind=EntrySiteKind.PROCESS_START,
            first_acquisition_confirmed=True,
        )
        binding = [{
            "source": "per-iteration fuzzer bytes",
            "destination": "main argc/argv",
            "transform": "construct argv strings and call main",
        }]

        self.assertFalse(_bindings_cover_entries(
            binding,
            [entry],
            {function.function_id: function},
        ))

    async def test_verified_entry_id_can_name_fuzzer_binding_source(self) -> None:
        function = FunctionMetadata.create(
            name="try_read_udp", qualified_name="try_read_udp",
            signature="int try_read_udp(conn *c)", file="udp.c",
            start_line=1, end_line=3,
            source=(
                "int try_read_udp(conn *c) { "
                "return recvfrom(c->fd, c->buf, sizeof(c->buf), 0, 0, 0); }"
            ),
        )
        entry = EntryRecord(
            entry_id="entry-udp-recvfrom", candidate_id="candidate-udp",
            status=Verdict.VERIFIED, entry_function_id=function.function_id,
            source_api="recvfrom", channel_kind="UDP socket datagram",
            attacker_control="full", provenance_path=[], consumer_hints=[],
            evidence=[Evidence(
                "source", function.function_id, function.file, 1, "recvfrom",
            )],
            unknowns=[], verifier_confidence=0.9,
            first_acquisition_confirmed=True,
        )
        binding = [{
            "source": entry.entry_id,
            "destination": "try_read_udp recvfrom(c->fd, c->buf, ...)",
            "transform": (
                "Per-iteration fuzzer bytes are delivered as one UDP datagram "
                "through the real socket transport."
            ),
        }]

        self.assertTrue(_bindings_cover_entries(
            binding,
            [entry],
            {function.function_id: function},
        ))

    async def test_reconciliation_merges_unresolved_and_concrete_views(self) -> None:
        anchor = FunctionMetadata.create(
            name="receive_udp", qualified_name="receive_udp",
            signature="int receive_udp(void)", file="udp.c",
            start_line=1, end_line=1,
            source="int receive_udp(void) { return 0; }",
        )
        anchor.build_targets = ["memcached"]
        entry = EntryRecord(
            entry_id="entry-udp", candidate_id="candidate-udp",
            status=Verdict.VERIFIED, entry_function_id=anchor.function_id,
            source_api="recvfrom", channel_kind="UDP socket datagram",
            attacker_control="full", provenance_path=[], consumer_hints=[],
            evidence=[Evidence("source", anchor.function_id, anchor.file, 1, "recvfrom")],
            unknowns=[], verifier_confidence=0.9,
            first_acquisition_confirmed=True,
        )

        def feature(identifier: str, target: str, complete: bool) -> SmallFeatureSpec:
            return SmallFeatureSpec(
                small_feature_id=identifier,
                name="receive one UDP datagram",
                description="same operation",
                root_entries=["entry-udp"], supporting_entries=[],
                harness_anchor=anchor.function_id, anchor_rationale="normal boundary",
                boundary_preserved=complete, preconditions=[], initialization=[],
                required_functions=[anchor.function_id],
                actions=[{
                    "action_id": "read", "function_id": anchor.function_id,
                    "consumes": ["datagram"], "produces": ["request"],
                    "allowed_after": [], "success_condition": "read returns",
                }],
                input_bindings=[{
                    "source": "per-iteration fuzzer bytes",
                    "destination": "UDP socket",
                    "transform": "bounded datagram delivery",
                }],
                cleanup_success=[], cleanup_failure=[],
                stable_post_state="request available", completion_oracle="read returns",
                evidence=[], unknowns=[], confidence=0.9 if complete else 0.6,
                channel_kind="network", build_target=target,
                isolation_mode="loopback_network",
                input_binding_proven=complete, entry_paths_complete=complete,
                anchor_action_complete=True, action_order_complete=True,
                function_references_complete=complete,
                entry_call_order=["entry-udp"], entry_order_complete=True,
                planning_complete=complete,
                planning_blockers=[] if complete else ["older incomplete view"],
            )

        stale = _Proposal("proposal-stale", "entry-udp", feature(
            "sf-stale", "UNRESOLVED", False
        ))
        stale.feature.required_functions.append("fn-stale-parser-sibling")
        complete = _Proposal("proposal-complete", "entry-udp", feature(
            "sf-complete", "memcached", True
        ))
        by_id = {item.proposal_id: item for item in (stale, complete)}

        partitions = _compatible_reconciliation_partitions(
            list(by_id), by_id, complete.proposal_id
        )
        groups = _coalesce_reconciliation_groups([[stale], [complete]])
        agent = SmallFeatureAgent(
            ScriptedLLM([]),
            GraphStore(AnalysisBundle(functions={anchor.function_id: anchor}, edges=[])),
        )
        merged = agent._merge_group(groups[0], {entry.entry_id: entry})

        self.assertEqual(len(partitions), 1)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0].proposal_id, complete.proposal_id)
        self.assertTrue(merged.planning_complete)
        self.assertEqual(merged.build_target, "memcached")
        self.assertEqual(merged.planning_blockers, [])
        self.assertEqual(merged.required_functions, [anchor.function_id])

        version_feature = feature("sf-version", "memcached", True)
        version_feature.name = "UDP binary VERSION request"
        version_feature.description = "dispatch VERSION and return version text"
        version_feature.completion_oracle = "VERSION response queued"
        flush_feature = feature("sf-flush", "memcached", True)
        flush_feature.name = "UDP binary FLUSH request"
        flush_feature.description = "dispatch FLUSH and flush items"
        flush_feature.completion_oracle = "FLUSH response queued"
        version = _Proposal("proposal-version", "entry-udp", version_feature)
        flush = _Proposal("proposal-flush", "entry-udp", flush_feature)
        command_views = {
            version.proposal_id: version,
            flush.proposal_id: flush,
        }

        self.assertEqual(
            _compatible_reconciliation_partitions(
                list(command_views), command_views, version.proposal_id
            ),
            [[version.proposal_id], [flush.proposal_id]],
        )

    async def test_unresolved_dependency_is_promoted_and_joined_to_feature(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        verified = EntryRecord(
            entry_id="entry-verified-network",
            candidate_id="candidate-verified-network",
            status=Verdict.VERIFIED,
            entry_function_id=serve.function_id,
            source_api="recv",
            channel_kind="network",
            attacker_control="full",
            provenance_path=[{"function_id": serve.function_id, "relation": "recv"}],
            consumer_hints=[parse.function_id],
            evidence=[Evidence("source", serve.function_id, serve.file, 17, "recv")],
            unknowns=[],
            verifier_confidence=0.95,
            first_acquisition_confirmed=True,
            inspected_function_ids=[serve.function_id],
            verification_rounds=1,
        )
        pending = EntryRecord(
            entry_id="entry-unresolved-callback",
            candidate_id="candidate-unresolved-callback",
            status=Verdict.UNRESOLVED,
            entry_function_id=parse.function_id,
            source_api="external_callback",
            channel_kind="callback",
            attacker_control="unknown",
            provenance_path=[],
            consumer_hints=[],
            evidence=[Evidence("source", parse.function_id, parse.file, parse.start_line, "candidate")],
            unknowns=["callback provenance incomplete"],
            verifier_confidence=0.5,
            inspected_function_ids=[parse.function_id],
            verification_rounds=1,
        )
        feature = {
            "name": "receive and parse callback data",
            "description": "network receive reaches the verified callback Entry",
            "root_entries": [verified.entry_id],
            "supporting_entries": [pending.entry_id],
            "entry_call_order": [verified.entry_id, pending.entry_id],
            "harness_anchor": serve.function_id,
            "anchor_rationale": "normal receive boundary",
            "boundary_preserved": True,
            "preconditions": [], "initialization": [],
            "required_functions": [serve.function_id, parse.function_id],
            "actions": [{
                "action_id": "serve", "function_id": serve.function_id,
                "consumes": ["network bytes"], "produces": ["parse status"],
                "allowed_after": [], "success_condition": "serve_client returns",
            }],
            "input_bindings": [{
                "source": "per-iteration fuzzer data",
                "destination": "network recv buffer",
                "transform": "bounded loopback socket delivery",
            }],
            "cleanup_success": [], "cleanup_failure": [],
            "stable_post_state": "request complete",
            "completion_oracle": "serve_client returns",
            "evidence": [{
                "kind": "call", "function_id": serve.function_id,
                "file": serve.file, "line": serve.start_line,
                "detail": "normal operation boundary",
            }],
            "unknowns": [], "confidence": 0.9,
            "build_target": "frame-server", "isolation_mode": "in_process_reset",
        }
        promoted_resolution = {
            "entry_id": pending.entry_id,
            "status": "VERIFIED",
            "channel_kind": "callback",
            "attacker_control": "full",
            "first_acquisition_confirmed": True,
            "provenance_path": [{
                "function_id": parse.function_id,
                "relation": "external runtime supplies callback bytes",
            }],
            "consumer_hints": [],
            "evidence": [{
                "kind": "source", "function_id": parse.function_id,
                "file": parse.file, "line": parse.start_line,
                "detail": "callback receives external bytes",
            }],
            "unknowns": [], "confidence": 0.95,
            "rationale": "external callback is the first acquisition boundary",
        }
        provider = ScriptedLLM([
            {
                "small_features": [], "entry_resolutions": [],
                "unrelated_entries": [], "context_complete": False,
                "requested_function_ids": [parse.function_id],
            },
            {
                "small_features": [feature],
                "entry_resolutions": [promoted_resolution],
                "unrelated_entries": [], "context_complete": True,
                "requested_function_ids": [],
            },
            {
                "small_features": [],
                "entry_resolutions": [{
                    **promoted_resolution,
                    "status": "UNRESOLVED",
                    "first_acquisition_confirmed": False,
                    "evidence": [],
                    "confidence": 0.6,
                    "rationale": "own context remains incomplete",
                }],
                "unrelated_entries": [], "context_complete": True,
                "requested_function_ids": [],
            },
        ])
        agent = SmallFeatureAgent(provider, graph, depth=2, budget=8)

        features = await agent.run([verified, pending])

        self.assertEqual(len(features), 1)
        self.assertEqual(features[0].supporting_entries, [pending.entry_id])
        self.assertEqual([item.entry_id for item in agent.last_promoted_entries], [pending.entry_id])
        self.assertEqual(agent.last_dropped_entry_outcomes, [])
        first_frontier = provider.calls[0]["payload"]["available_context_functions"]
        parse_choice = next(
            item for item in first_frontier if item["function_id"] == parse.function_id
        )
        self.assertEqual(
            parse_choice["pending_unresolved_entry_ids"],
            [pending.entry_id],
        )

    async def test_unresolved_entry_is_dropped_after_small_feature_rounds(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        pending = EntryRecord(
            entry_id="entry-still-unresolved",
            candidate_id="candidate-still-unresolved",
            status=Verdict.UNRESOLVED,
            entry_function_id=serve.function_id,
            source_api="recv",
            channel_kind="network",
            attacker_control="unknown",
            provenance_path=[], consumer_hints=[],
            evidence=[Evidence("source", serve.function_id, serve.file, 17, "candidate")],
            unknowns=["fd provenance incomplete"],
            verifier_confidence=0.5,
            inspected_function_ids=[serve.function_id],
            verification_rounds=1,
        )
        provider = ScriptedLLM([{
            "small_features": [],
            "entry_resolutions": [{
                "entry_id": pending.entry_id,
                "status": "UNRESOLVED",
                "channel_kind": "network",
                "attacker_control": "unknown",
                "first_acquisition_confirmed": False,
                "provenance_path": [], "consumer_hints": [], "evidence": [],
                "unknowns": ["still incomplete"], "confidence": 0.5,
                "rationale": "no external fd origin was proven",
            }],
            "unrelated_entries": [], "context_complete": True,
            "requested_function_ids": [],
        }])
        agent = SmallFeatureAgent(provider, graph, depth=1, budget=8)

        features = await agent.run([pending])

        self.assertEqual(features, [])
        self.assertEqual(agent.last_promoted_entries, [])
        self.assertEqual(len(agent.last_dropped_entry_outcomes), 1)
        self.assertEqual(
            agent.last_dropped_entry_outcomes[0]["drop_reason"],
            "small_feature_context_exhausted",
        )

    async def test_preserves_semantic_feature_when_input_adapter_is_unresolved(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(function for function in bundle.functions.values() if function.name == "serve_client")
        entry = EntryRecord(
            entry_id="entry-unresolved-adapter",
            candidate_id="candidate-unresolved-adapter",
            status=Verdict.VERIFIED,
            entry_function_id=serve.function_id,
            source_api="recv",
            channel_kind="network",
            attacker_control="partial",
            provenance_path=[{"function_id": serve.function_id, "relation": "socket bytes"}],
            consumer_hints=[],
            evidence=[Evidence("source", serve.function_id, serve.file, 17, "recv")],
            unknowns=[],
            verifier_confidence=0.9,
        )
        provider = ScriptedLLM([{
            "small_features": [{
                "name": "receive request", "description": "one request",
                "root_entries": [entry.entry_id], "supporting_entries": [],
                "entry_call_order": [entry.entry_id],
                "harness_anchor": serve.function_id,
                "anchor_rationale": "normal receive boundary", "boundary_preserved": True,
                "preconditions": [], "initialization": [],
                "required_functions": [serve.function_id],
                "actions": [{
                    "action_id": "serve", "function_id": serve.function_id,
                    "consumes": ["network bytes"], "produces": ["status"],
                    "allowed_after": [], "success_condition": "serve_client returns",
                }],
                "input_bindings": [],
                "cleanup_success": [], "cleanup_failure": [],
                "stable_post_state": "request complete",
                "completion_oracle": "serve_client returns",
                "evidence": [{
                    "kind": "source", "function_id": serve.function_id,
                    "file": serve.file, "line": serve.start_line,
                    "detail": "request lifecycle",
                }],
                "unknowns": [], "confidence": 0.8,
                "build_target": "frame-server", "isolation_mode": "in_process_reset",
            }],
            "unrelated_entries": [], "context_complete": True,
            "requested_function_ids": [],
        }])

        features = await SmallFeatureAgent(provider, graph, depth=1, budget=8).run([entry])

        self.assertEqual(len(features), 1)
        self.assertTrue(features[0].input_bindings)
        self.assertTrue(any("not concretely bound" in item for item in features[0].unknowns))
        self.assertFalse(features[0].input_binding_proven)
        self.assertFalse(features[0].planning_complete)

    async def test_preserves_semantic_feature_when_lifecycle_boundary_is_unresolved(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        entry = EntryRecord(
            entry_id="entry-unresolved-boundary",
            candidate_id="candidate-unresolved-boundary",
            status=Verdict.VERIFIED,
            entry_function_id=serve.function_id,
            source_api="recv",
            channel_kind="network",
            attacker_control="full",
            provenance_path=[{"function_id": serve.function_id, "relation": "socket bytes"}],
            consumer_hints=[],
            evidence=[Evidence("source", serve.function_id, serve.file, 17, "recv")],
            unknowns=[],
            verifier_confidence=0.9,
        )
        provider = ScriptedLLM([{
            "small_features": [{
                "name": "receive request with unresolved setup",
                "description": "the request operation is known but setup is incomplete",
                "root_entries": [entry.entry_id], "supporting_entries": [],
                "entry_call_order": [entry.entry_id],
                "harness_anchor": serve.function_id,
                "anchor_rationale": "normal caller setup has not been recovered",
                "boundary_preserved": False,
                "preconditions": ["connection exists"],
                "initialization": ["UNRESOLVED: create normal connection lifecycle"],
                "required_functions": [serve.function_id],
                "actions": [{
                    "action_id": "serve", "function_id": serve.function_id,
                    "consumes": ["network bytes"], "produces": ["status"],
                    "allowed_after": [], "success_condition": "serve_client returns",
                }],
                "input_bindings": [{
                    "source": "per-iteration fuzzer bytes", "destination": "network recv",
                    "transform": "bounded loopback delivery",
                }],
                "cleanup_success": ["close connection"],
                "cleanup_failure": ["close connection if created"],
                "stable_post_state": "request complete",
                "completion_oracle": "serve_client returns",
                "evidence": [{
                    "kind": "source", "function_id": serve.function_id,
                    "file": serve.file, "line": serve.start_line,
                    "detail": "request operation exists",
                }],
                "unknowns": ["normal setup caller is unresolved"],
                "confidence": 0.8,
                "build_target": "frame-server", "isolation_mode": "loopback_network",
            }],
            "unrelated_entries": [], "context_complete": True,
            "requested_function_ids": [],
        }])

        features = await SmallFeatureAgent(provider, graph, depth=1, budget=8).run([entry])

        self.assertEqual(len(features), 1)
        self.assertFalse(features[0].boundary_preserved)
        self.assertFalse(features[0].planning_complete)
        self.assertIn(
            "normal lifecycle/security boundary preservation is unresolved",
            features[0].planning_blockers,
        )

    async def test_out_of_context_function_reference_blocks_harness_planning(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(function for function in bundle.functions.values() if function.name == "serve_client")
        entry = EntryRecord(
            entry_id="entry-unresolved-function", candidate_id="candidate-unresolved-function",
            status=Verdict.VERIFIED, entry_function_id=serve.function_id,
            source_api="recv", channel_kind="network", attacker_control="full",
            provenance_path=[{"function_id": serve.function_id, "relation": "socket bytes"}],
            consumer_hints=[],
            evidence=[Evidence("source", serve.function_id, serve.file, 17, "recv")],
            unknowns=[], verifier_confidence=0.9,
        )
        provider = ScriptedLLM([{
            "small_features": [{
                "name": "request with unknown helper", "description": "one operation",
                "root_entries": [entry.entry_id], "supporting_entries": [],
                "entry_call_order": [entry.entry_id], "harness_anchor": serve.function_id,
                "anchor_rationale": "normal boundary", "boundary_preserved": True,
                "preconditions": [], "initialization": [],
                "required_functions": [serve.function_id, "fn-not-in-context"],
                "actions": [{
                    "action_id": "serve", "function_id": serve.function_id,
                    "consumes": ["bytes"], "produces": ["status"],
                    "allowed_after": [], "success_condition": "returns",
                }],
                "input_bindings": [{
                    "source": "per-iteration fuzz data", "destination": "network recv",
                    "transform": "bounded loopback socket delivery",
                }],
                "cleanup_success": [], "cleanup_failure": [],
                "stable_post_state": "done", "completion_oracle": "returns",
                "evidence": [{
                    "kind": "call", "function_id": serve.function_id, "file": serve.file,
                    "line": serve.start_line, "detail": "normal boundary",
                }],
                "unknowns": [], "confidence": 0.9,
                "build_target": "frame-server", "isolation_mode": "in_process_reset",
            }],
            "unrelated_entries": [], "context_complete": True,
            "requested_function_ids": [],
        }])

        features = await SmallFeatureAgent(provider, graph, depth=1, budget=8).run([entry])

        self.assertEqual(len(features), 1)
        self.assertFalse(features[0].function_references_complete)
        self.assertFalse(features[0].planning_complete)
        self.assertTrue(any("function references" in item for item in features[0].planning_blockers))

    async def test_groups_multiple_entries_into_one_operation(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]

        def record(function: FunctionMetadata, suffix: str) -> EntryRecord:
            return EntryRecord(
                entry_id=f"entry-{suffix}",
                candidate_id=f"candidate-{suffix}",
                status=Verdict.VERIFIED,
                entry_function_id=function.function_id,
                source_api="recv",
                channel_kind="network",
                attacker_control="full",
                provenance_path=[{"function_id": function.function_id, "relation": "test"}],
                consumer_hints=[],
                evidence=[Evidence(
                    "source", function.function_id, function.file,
                    function.start_line, "test entry",
                )],
                unknowns=[],
                verifier_confidence=0.9,
            )

        parse_entry = record(parse, "parse")
        serve_entry = record(serve, "serve")
        feature_response = {
            "small_features": [{
            "name": "receive and parse one frame",
            "description": "one request lifecycle containing both entries",
            "root_entries": [serve_entry.entry_id],
            "supporting_entries": [parse_entry.entry_id],
            "entry_call_order": [serve_entry.entry_id, parse_entry.entry_id],
            "harness_anchor": serve.function_id,
            "anchor_rationale": "preserve receive before parse",
            "boundary_preserved": True,
            "preconditions": [],
            "initialization": [],
            "required_functions": [serve.function_id, parse.function_id],
            "actions": [{
                "action_id": "serve",
                "function_id": serve.function_id,
                "consumes": ["fuzz_input"],
                "produces": ["status"],
                "allowed_after": [],
                "success_condition": "serve_client returns",
            }],
            "input_bindings": [{
                "source": "fuzz.data",
                "destination": "socket input",
                "transform": "bounded transport",
            }],
            "cleanup_success": [],
            "cleanup_failure": [],
            "stable_post_state": "request complete",
            "completion_oracle": "serve_client returns",
            "evidence": [{
                "kind": "call",
                "function_id": serve.function_id,
                "file": serve.file,
                "line": serve.start_line,
                "detail": "serve_client owns the request",
            }],
            "unknowns": [],
            "confidence": 0.95,
            "build_target": "default",
            "isolation_mode": "in_process_reset",
            }],
            "unrelated_entries": [],
        }
        members = sorted([parse_entry.entry_id, serve_entry.entry_id])
        parse_proposal = stable_id(
            "sfp", parse_entry.entry_id, 0, *members, serve.function_id,
            json.dumps([serve.function_id]), "serve_client returns",
        )
        serve_proposal = stable_id(
            "sfp", serve_entry.entry_id, 0, *members, serve.function_id,
            json.dumps([serve.function_id]), "serve_client returns",
        )
        richer_response = json.loads(json.dumps(feature_response))
        richer = richer_response["small_features"][0]
        richer["preconditions"] = ["listener is active"]
        richer["initialization"] = ["create listener"]
        richer["cleanup_success"] = ["close listener"]
        richer["cleanup_failure"] = ["close listener if created"]
        provider = ScriptedLLM([
            feature_response,
            richer_response,
            {
                "operation_groups": [{
                    "canonical_proposal_id": parse_proposal,
                    "proposal_ids": [parse_proposal, serve_proposal],
                    "reason": "same request lifecycle seen from two Entry contexts",
                }]
            },
        ])

        features = await SmallFeatureAgent(provider, graph, depth=2, budget=8).run(
            [parse_entry, serve_entry]
        )

        self.assertEqual(len(features), 1)
        self.assertEqual(features[0].root_entries, [serve_entry.entry_id])
        self.assertEqual(features[0].supporting_entries, [parse_entry.entry_id])
        self.assertEqual(features[0].initialization, ["create listener"])
        self.assertEqual(features[0].cleanup_success, ["close listener"])
        self.assertEqual(features[0].cleanup_failure, ["close listener if created"])
        # Both Entry contexts are analyzed independently. The third call reconciles
        # the two views of the same operation.
        self.assertEqual(len(provider.calls), 3)

    async def test_one_entry_can_participate_in_multiple_features(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(function for function in bundle.functions.values() if function.name == "serve_client")
        entry = EntryRecord(
            entry_id="entry-shared",
            candidate_id="candidate-shared",
            status=Verdict.VERIFIED,
            entry_function_id=serve.function_id,
            source_api="recv",
            channel_kind="network",
            attacker_control="full",
            provenance_path=[{"function_id": serve.function_id, "relation": "socket bytes"}],
            consumer_hints=[],
            evidence=[Evidence(
                "source", serve.function_id, serve.file, serve.start_line, "shared input Entry",
            )],
            unknowns=[],
            verifier_confidence=0.9,
        )

        def feature(name: str, completion: str) -> dict:
            return {
                "name": name,
                "description": name,
                "root_entries": [entry.entry_id],
                "supporting_entries": [],
                "entry_call_order": [entry.entry_id],
                "harness_anchor": serve.function_id,
                "anchor_rationale": "preserve real dispatch",
                "boundary_preserved": True,
                "preconditions": [],
                "initialization": [],
                "required_functions": [serve.function_id],
                "actions": [{
                    "action_id": name,
                    "function_id": serve.function_id,
                    "consumes": ["fuzz_input"],
                    "produces": ["status"],
                    "allowed_after": [],
                    "success_condition": completion,
                }],
                "input_bindings": [{
                    "source": "fuzz.data",
                    "destination": "socket input",
                    "transform": "bounded transport",
                }],
                "cleanup_success": [],
                "cleanup_failure": [],
                "stable_post_state": completion,
                "completion_oracle": completion,
                "evidence": [{
                    "kind": "dispatch",
                    "function_id": serve.function_id,
                    "file": serve.file,
                    "line": serve.start_line,
                    "detail": name,
                }],
                "unknowns": [],
                "confidence": 0.9,
                "build_target": "default",
                "isolation_mode": "in_process_reset",
            }

        accept = feature("store frame", "store operation completes")
        reject = feature("delete frame", "delete operation completes")
        accept_id = stable_id(
            "sfp", entry.entry_id, 0, entry.entry_id, serve.function_id,
            json.dumps([serve.function_id]), "store operation completes",
        )
        reject_id = stable_id(
            "sfp", entry.entry_id, 1, entry.entry_id, serve.function_id,
            json.dumps([serve.function_id]), "delete operation completes",
        )
        provider = ScriptedLLM([
            {"small_features": [accept, reject], "unrelated_entries": []},
            {
                "operation_groups": [
                    {
                        "canonical_proposal_id": accept_id,
                        "proposal_ids": [accept_id],
                        "reason": "store is a distinct requested operation",
                    },
                    {
                        "canonical_proposal_id": reject_id,
                        "proposal_ids": [reject_id],
                        "reason": "delete is a distinct requested operation",
                    },
                ]
            },
        ])

        features = await SmallFeatureAgent(provider, graph, depth=2, budget=8).run([entry])

        self.assertEqual(len(features), 2)
        self.assertTrue(all(feature.root_entries == [entry.entry_id] for feature in features))
        self.assertEqual({feature.name for feature in features}, {"store frame", "delete frame"})

    async def test_retains_feature_but_blocks_anchor_below_the_entry_boundary(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        entry = EntryRecord(
            entry_id="entry-network",
            candidate_id="candidate-network",
            status=Verdict.VERIFIED,
            entry_function_id=serve.function_id,
            source_api="recv",
            channel_kind="network",
            attacker_control="full",
            provenance_path=[{"function_id": serve.function_id, "relation": "recv"}],
            consumer_hints=[parse.function_id],
            evidence=[Evidence("source", serve.function_id, serve.file, serve.start_line, "recv")],
            unknowns=[],
            verifier_confidence=0.9,
        )
        response = {
            "small_features": [{
                "name": "bypassed parser",
                "description": "incorrectly starts below recv",
                "root_entries": [entry.entry_id],
                "supporting_entries": [],
                "entry_call_order": [entry.entry_id],
                "harness_anchor": parse.function_id,
                "anchor_rationale": "direct parser is cheaper",
                "boundary_preserved": True,
                "preconditions": [],
                "initialization": [],
                "required_functions": [parse.function_id],
                "actions": [{
                    "action_id": "parse", "function_id": parse.function_id,
                    "consumes": ["fuzz_input"], "produces": ["status"],
                    "allowed_after": [], "success_condition": "parse returns",
                }],
                "input_bindings": [{
                    "source": "fuzz.data", "destination": "parser buffer", "transform": "bounded",
                }],
                "cleanup_success": [], "cleanup_failure": [],
                "stable_post_state": "parse returned", "completion_oracle": "parse returns",
                "evidence": [{
                    "kind": "call", "function_id": parse.function_id, "file": parse.file,
                    "line": parse.start_line, "detail": "parser call",
                }],
                "unknowns": [], "confidence": 0.9,
                "build_target": "default", "isolation_mode": "in_process_reset",
            }],
            "unrelated_entries": [],
        }
        provider = ScriptedLLM([response, response])

        features = await SmallFeatureAgent(provider, graph, depth=2, budget=8).run([entry])

        self.assertEqual(len(features), 1)
        self.assertFalse(features[0].boundary_preserved)
        self.assertFalse(features[0].planning_complete)
        self.assertTrue(any(
            "boundary" in blocker for blocker in features[0].planning_blockers
        ))


class LargeFeatureInvariantTest(unittest.IsolatedAsyncioTestCase):
    def test_request_shape_is_not_large_feature_prerequisite_state(self) -> None:
        feature = SmallFeatureSpec(
            small_feature_id="sf-udp-version",
            name="UDP VERSION",
            description="serve VERSION",
            root_entries=["entry-udp"],
            supporting_entries=[],
            entry_call_order=["entry-udp"],
            harness_anchor="fn-event",
            anchor_rationale="normal event boundary",
            boundary_preserved=True,
            preconditions=[
                "UDP conn initialized by conn_new and in conn_read.",
                "Request opcode is VERSION with extlen == 0 and bodylen == 0.",
                "Accepted single-packet UDP datagram containing a complete binary request.",
                "settings.sasl is false or authenticated(c) is true.",
            ],
            initialization=[],
            required_functions=["fn-event"],
            actions=[],
            input_bindings=[],
            cleanup_success=[],
            cleanup_failure=[],
            stable_post_state="response queued",
            completion_oracle="VERSION response queued",
            evidence=[],
            unknowns=[],
            confidence=0.9,
        )

        self.assertEqual(
            _large_feature_prerequisite_state(feature),
            [
                "UDP conn initialized by conn_new and in conn_read.",
                "settings.sasl is false or authenticated(c) is true.",
            ],
        )

    async def test_semantically_equivalent_prerequisite_wording_can_share_group(self) -> None:
        def feature(identifier: str, prerequisite: str) -> SmallFeatureSpec:
            return SmallFeatureSpec(
                small_feature_id=identifier, name=identifier, description=identifier,
                root_entries=["entry-root"], supporting_entries=[],
                entry_call_order=["entry-root"], harness_anchor="fn-anchor",
                anchor_rationale="normal", boundary_preserved=True,
                preconditions=[prerequisite], initialization=[],
                required_functions=["fn-anchor"], actions=[], input_bindings=[],
                cleanup_success=[], cleanup_failure=[], stable_post_state="done",
                completion_oracle="done", evidence=[], unknowns=[], confidence=0.9,
            )

        first = feature("sf-first", "an authenticated session exists")
        second = feature("sf-second", "session authentication has completed")
        provider = ScriptedLLM([{"large_features": [{
            "name": "authenticated operations", "description": "same prerequisite",
            "small_feature_ids": [first.small_feature_id, second.small_feature_id],
            "common_anchor": "fn-anchor", "common_initialization": [],
            "common_cleanup": [], "prerequisite_state": ["authenticated session"],
            "isolation_mode": "in_process_reset", "isolation_rationale": "same fixture",
            "dispatch_strategy": "selector_byte",
            "variants": [
                {"selector": "0", "small_feature_id": first.small_feature_id},
                {"selector": "1", "small_feature_id": second.small_feature_id},
            ],
            "required_functions": ["fn-anchor"],
        }]}, {"subjects": [], "feature_subjects": []}])

        groups = await LargeFeatureAgent(provider).run([first, second])

        self.assertEqual(len(provider.calls), 2)
        self.assertEqual(len(groups), 1)
        self.assertEqual(set(groups[0].small_feature_ids), {"sf-first", "sf-second"})

    async def test_model_can_split_but_cannot_rewrite_proven_lifecycle(self) -> None:
        def feature(identifier: str) -> SmallFeatureSpec:
            return SmallFeatureSpec(
                small_feature_id=identifier,
                name=identifier,
                description=identifier,
                root_entries=["entry-root"],
                supporting_entries=[],
                harness_anchor="fn-anchor",
                anchor_rationale="normal entry path",
                boundary_preserved=True,
                preconditions=["session ready"],
                initialization=["init session"],
                required_functions=["fn-anchor", f"fn-{identifier}"],
                actions=[{"function_id": "fn-anchor"}],
                input_bindings=[{"source": "fuzz.data", "destination": "request", "transform": "bounded"}],
                cleanup_success=["close session"],
                cleanup_failure=["close session"],
                stable_post_state="closed",
                completion_oracle="request returns",
                evidence=[],
                unknowns=[],
                confidence=0.9,
                channel_kind="network",
                build_target="server",
                isolation_mode="in_process_reset",
            )

        first = feature("sf-a")
        second = feature("sf-b")
        provider = ScriptedLLM([{
            "large_features": [{
                "name": "combined",
                "description": "combined lifecycle",
                "small_feature_ids": [first.small_feature_id, second.small_feature_id],
                "common_anchor": "fn-invented",
                "common_initialization": ["invented init"],
                "common_cleanup": ["invented cleanup"],
                "prerequisite_state": ["invented state"],
                "isolation_mode": "subprocess",
                "isolation_rationale": "model proposal",
                "dispatch_strategy": "selector_byte",
                "variants": [{"selector": "0", "small_feature_id": first.small_feature_id}],
                "required_functions": ["fn-invented"],
            }]
        }, {"subjects": [], "feature_subjects": []}])

        result = await LargeFeatureAgent(provider).run([first, second])

        self.assertEqual(len(result), 1)
        large = result[0]
        self.assertEqual(large.common_anchor, "fn-anchor")
        self.assertEqual(large.common_initialization, ["init session"])
        self.assertEqual(large.common_cleanup, ["close session"])
        self.assertEqual(large.prerequisite_state, ["session ready"])
        self.assertEqual(large.isolation_mode, "in_process_reset")
        self.assertNotIn("fn-invented", large.required_functions)
        self.assertEqual(
            {variant["small_feature_id"] for variant in large.variants},
            {first.small_feature_id, second.small_feature_id},
        )
        self.assertEqual(large.small_feature_names, [first.name, second.name])
        self.assertEqual(large.common_cleanup_failure, ["close session"])

    async def test_entry_call_graph_contains_entry_order_and_analysis_edges(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        feature = SmallFeatureSpec(
            small_feature_id="sf-graph", name="request", description="request",
            root_entries=["entry-root"], supporting_entries=["entry-parse"],
            entry_call_order=["entry-root", "entry-parse"],
            harness_anchor=serve.function_id, anchor_rationale="normal", boundary_preserved=True,
            preconditions=[], initialization=[], required_functions=[serve.function_id, parse.function_id],
            actions=[{"function_id": serve.function_id}],
            input_bindings=[{"source": "fuzz data", "destination": "network recv", "transform": "send"}],
            cleanup_success=[], cleanup_failure=[], stable_post_state="done",
            completion_oracle="returns", evidence=[], unknowns=[], confidence=0.9,
            channel_kind="network", build_target="frame-server",
        )
        provider = ScriptedLLM([{
            "large_features": [{
                "name": "request", "description": "request",
                "small_feature_ids": [feature.small_feature_id],
                "common_anchor": serve.function_id, "common_initialization": [],
                "common_cleanup": [], "prerequisite_state": [],
                "isolation_mode": "in_process_reset", "isolation_rationale": "safe",
                "dispatch_strategy": "one_job_per_feature",
                "variants": [{"selector": "0", "small_feature_id": feature.small_feature_id}],
                "required_functions": [serve.function_id, parse.function_id],
            }]
        }, {"subjects": [], "feature_subjects": []}])

        result = await LargeFeatureAgent(provider, graph).run([feature])

        self.assertTrue(result[0].entry_call_graph["edges"])
        self.assertTrue(any(
            edge["from_entry_id"] == "entry-root"
            and edge["to_entry_id"] == "entry-parse"
            for edge in result[0].entry_call_graph["edges"]
        ))
        self.assertTrue(any(
            edge["caller_id"] == serve.function_id and edge["callee_id"] == parse.function_id
            for edge in result[0].entry_call_graph["function_edges"]
        ))

    async def test_security_priority_is_access_times_impact(self) -> None:
        priority = _security_priority_from_assessment({
            "input_subject": "unauthenticated remote client",
            "subject_capabilities": ["read public item"],
            "other_subjects": [{
                "subject": "authenticated administrator",
                "capabilities": [
                    "read public item", "write item", "delete item",
                ],
            }],
            "attack_access": "UNAUTHENTICATED_REMOTE",
            "impact_scope": "SENSITIVE_DATA",
            "rationale": "remote clients are realistic attackers",
            "confidence": 0.95,
        }, fallback_capabilities=[])

        self.assertEqual(priority.capability_ratio, 0.3333)
        self.assertEqual(priority.capability_scarcity_score, 67)
        self.assertEqual(priority.base_risk_score, 50)
        self.assertEqual(priority.priority_score, 50)
        self.assertEqual(priority.disposition, HarnessDisposition.KEEP)
        self.assertEqual(priority.attack_access, AttackAccess.UNAUTHENTICATED_REMOTE)
        self.assertEqual(priority.impact_scope, ImpactScope.SENSITIVE_DATA)
        self.assertEqual(priority.attacker_feasibility, AttackerFeasibility.HIGH)

    async def test_impossible_all_capability_subject_is_discarded(self) -> None:
        priority = _security_priority_from_assessment({
            "input_subject": "trusted server",
            "subject_capabilities": ["read", "write", "delete"],
            "other_subjects": [
                {"subject": "guest client", "capabilities": ["read"]},
                {"subject": "member client", "capabilities": ["read", "write"]},
            ],
            "attack_access": "IMPLAUSIBLE",
            "impact_scope": "SYSTEM_WIDE",
            "rationale": "the protected client pins and trusts this server",
            "confidence": 0.95,
        }, fallback_capabilities=[])

        self.assertEqual(priority.priority_score, 0)
        self.assertTrue(priority.capability_superset_of_all_others)
        self.assertEqual(priority.disposition, HarnessDisposition.DISCARD)
        self.assertTrue(priority.discard_reason)

    async def test_large_feature_agent_ranks_and_discards_by_subject(self) -> None:
        def feature(identifier: str, entry: str) -> SmallFeatureSpec:
            return SmallFeatureSpec(
                small_feature_id=identifier, name=identifier, description=identifier,
                root_entries=[entry], supporting_entries=[], entry_call_order=[entry],
                harness_anchor="fn-anchor", anchor_rationale="normal",
                boundary_preserved=True, preconditions=[], initialization=[],
                required_functions=["fn-anchor"], actions=[], input_bindings=[],
                cleanup_success=[], cleanup_failure=[], stable_post_state="done",
                completion_oracle="done", evidence=[], unknowns=[], confidence=0.9,
            )

        class SubjectProvider:
            max_concurrency = 1

            def __init__(self) -> None:
                self.calls = []

            async def complete_json(
                self, *, role, instructions, payload, output_schema, session_key=None
            ):
                self.calls.append(payload)
                if "compatibility_fingerprint" in payload:
                    small = payload["small_features"][0]
                    return {"large_features": [{
                        "name": small["name"], "description": small["description"],
                        "small_feature_ids": [small["small_feature_id"]],
                        "common_anchor": small["harness_anchor"],
                        "common_initialization": [], "common_cleanup": [],
                        "prerequisite_state": [], "isolation_mode": "in_process_reset",
                        "isolation_rationale": "same fixture",
                        "dispatch_strategy": "one_job_per_feature",
                        "variants": [{
                            "selector": "0", "small_feature_id": small["small_feature_id"],
                        }],
                        "required_functions": ["fn-anchor"],
                    }]}
                candidates = payload["candidate_large_features"]
                mappings = []
                for candidate in candidates:
                    subject_id = "guest" if candidate["name"] == "sf-guest" else "server"
                    mappings.append({
                        "large_feature_id": candidate["large_feature_id"],
                        "subject_id": subject_id,
                        "impact_scope": (
                            "SENSITIVE_DATA" if subject_id == "guest" else "SYSTEM_WIDE"
                        ),
                        "rationale": "deployment role",
                        "impact_rationale": "reachable assets",
                        "confidence": 0.95,
                    })
                return {
                    "subjects": [
                        {
                            "subject_id": "guest", "name": "guest client",
                            "capabilities": ["read"],
                            "attack_access": "UNAUTHENTICATED_REMOTE",
                            "rationale": "remote peer", "confidence": 0.95,
                        },
                        {
                            "subject_id": "server", "name": "trusted server",
                            "capabilities": ["read", "write"],
                            "attack_access": "IMPLAUSIBLE",
                            "rationale": "requires trusted-server control", "confidence": 0.95,
                        },
                    ],
                    "feature_subjects": mappings,
                }

            async def close(self):
                return None

        provider = SubjectProvider()
        result = await LargeFeatureAgent(provider).run([
            feature("sf-guest", "entry-guest"),
            feature("sf-server", "entry-server"),
        ])

        self.assertEqual(len(provider.calls), 3)
        self.assertEqual(result[0].name, "sf-guest")
        self.assertEqual(result[0].security_priority.priority_score, 50)
        self.assertEqual(result[0].security_priority.disposition, HarnessDisposition.KEEP)
        self.assertEqual(result[1].name, "sf-server")
        self.assertEqual(result[1].security_priority.priority_score, 0)
        self.assertEqual(result[1].security_priority.disposition, HarnessDisposition.DISCARD)


class CacheTest(unittest.IsolatedAsyncioTestCase):
    async def test_replays_exact_trajectory_call(self) -> None:
        role = "probe"
        instructions = "return a probe"
        payload = {"value": 1}
        schema = {"type": "object"}
        record = {
            "role": role,
            "instructions": instructions,
            "payload": payload,
            "output_schema": schema,
            "status": "completed",
            "response": {"ok": True},
        }
        with tempfile.TemporaryDirectory() as temporary:
            trajectory = Path(temporary) / "llm.jsonl"
            trajectory.write_text(json.dumps(record) + "\n", encoding="utf-8")
            cache = CachingLLM(ScriptedLLM([]), trajectory)
            result = await cache.complete_json(
                role=role,
                instructions=instructions,
                payload=payload,
                output_schema=schema,
            )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(cache.hits, 1)


class SeedSuiteTest(unittest.TestCase):
    def test_seed_suite_and_fuzz_limit_respect_manifest_max_size(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = write_seed_suite(
                Path(temporary), 1, 2,
                [SeedSpec("too-large", "010203", "must be rejected")],
                max_size=2,
            )
            self.assertTrue(paths)
            self.assertTrue(all(len(path.read_bytes()) <= 2 for path in paths))
            self.assertFalse(any(path.name.startswith("llm-too-large") for path in paths))

    def test_adds_and_deduplicates_llm_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = write_seed_suite(
                Path(temporary),
                min_size=1,
                variants=1,
                llm_seeds=[
                    SeedSpec("nul", "00", "duplicate deterministic seed"),
                    SeedSpec("frame-edge", "010203", "short frame"),
                ],
            )
            payloads = [path.read_bytes() for path in paths]
            self.assertEqual(payloads.count(b"\x00"), 1)
            self.assertIn(b"\x01\x02\x03", payloads)

    def test_distinct_payloads_with_the_same_seed_name_get_distinct_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = write_seed_suite(
                Path(temporary), 1, 1,
                [
                    SeedSpec("same", "dead", "first"),
                    SeedSpec("same", "beef", "second"),
                ],
            )
            matching = [path for path in paths if path.name.startswith("llm-same")]
            self.assertEqual(len(matching), 2)
            self.assertEqual(len({path.name for path in matching}), 2)
            self.assertEqual(
                {path.read_bytes() for path in matching},
                {bytes.fromhex("dead"), bytes.fromhex("beef")},
            )


class _SuccessfulRunner:
    async def run(self, argv, *, cwd, timeout_seconds, env=None):
        is_fuzz = any(str(item).startswith("-max_total_time=") for item in argv)
        return CommandReport(
            argv=list(argv),
            returncode=0,
            stdout="#1 cov: 3\n#2 cov: 8\n" if is_fuzz else "",
            stderr="",
            duration_seconds=0.01,
        )


class _RaisingRunner:
    async def run(self, argv, *, cwd, timeout_seconds, env=None):
        raise FileNotFoundError("missing compiler")


class DynamicVerifierTest(unittest.IsolatedAsyncioTestCase):
    async def test_command_runner_exception_is_infrastructure_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = HarnessManifest(
                harness_id="h-infra", large_feature_id="lf-infra",
                source_file="fuzz_target.cc", build_target="fuzz_target",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=1, max_size=4096,
                dispatch_strategy="one_job_per_feature",
                expected_anchors=["anchor"], expected_consumers=["consumer"],
                build_command=["missing-compiler"], binary=str(root / "fuzzer"),
            )
            draft = HarnessDraft(manifest=manifest, code="LLVMFuzzerTestOneInput")
            project = ProjectSpec(
                source_root=FIXTURE, output_root=root,
                build_command=["missing-compiler"], fuzz_seconds=1,
            ).normalized()

            result = await HarnessVerifier(_RaisingRunner(), project).verify(
                draft, root / "artifacts", runtime_checks=False
            )

        self.assertFalse(result.qualified)
        self.assertFalse(result.build_ok)
        self.assertEqual(result.reason, "command verification infrastructure failed")
        self.assertIn("missing compiler", result.infrastructure_error or "")
        self.assertEqual(result.harness_faults, [])

    async def test_no_dynamic_mode_still_requires_and_records_a_real_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fuzzer"
            binary.write_bytes(b"__asan_init __ubsan_handle_ LLVMFuzzerRunDriver")
            manifest = HarnessManifest(
                harness_id="h-build-only", large_feature_id="lf-build-only",
                source_file="fuzz_target.cc", build_target="fuzz_target",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=1, max_size=4096,
                dispatch_strategy="one_job_per_feature",
                expected_anchors=["anchor"], expected_consumers=["consumer"],
                build_command=["true"], binary=str(binary),
            )
            draft = HarnessDraft(manifest=manifest, code="LLVMFuzzerTestOneInput")
            project = ProjectSpec(
                source_root=FIXTURE, output_root=root, build_command=["true"],
                harness_binary=binary, fuzz_seconds=1,
            ).normalized()

            result = await HarnessVerifier(_SuccessfulRunner(), project).verify(
                draft, root / "artifacts", runtime_checks=False
            )

        self.assertTrue(result.build_ok)
        self.assertFalse(result.qualified)
        self.assertEqual(result.replays, [])
        self.assertIsNone(result.fuzz)
        self.assertIn("build-only validation passed", result.reason)

    async def test_rejects_build_without_declared_sanitizer_instrumentation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fuzzer"
            binary.write_bytes(b"ordinary unsanitized executable")
            manifest = HarnessManifest(
                harness_id="h-unsanitized", large_feature_id="lf-unsanitized",
                source_file="fuzz_target.cc", build_target="fuzz_target",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=1, max_size=4096,
                dispatch_strategy="one_job_per_feature",
                expected_anchors=["anchor"], expected_consumers=["consumer"],
                build_command=["true"], binary=str(binary),
            )
            draft = HarnessDraft(manifest=manifest, code="LLVMFuzzerTestOneInput")
            project = ProjectSpec(
                source_root=FIXTURE, output_root=root, build_command=["true"],
                harness_binary=binary, fuzz_seconds=1,
            ).normalized()

            result = await HarnessVerifier(_SuccessfulRunner(), project).verify(
                draft, root / "artifacts"
            )

        self.assertFalse(result.qualified)
        self.assertIn("lacks required sanitizer instrumentation", result.reason)
        self.assertEqual(result.replays, [])

    async def test_reachability_rejects_binary_that_omits_generated_harness(self) -> None:
        class WrongBinaryRunner:
            async def run(self, argv, *, cwd, timeout_seconds, env=None):
                return CommandReport(
                    argv=list(argv), returncode=0, stdout="", stderr="",
                    duration_seconds=0.01,
                )

        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        verifier = HarnessVerifier(
            WrongBinaryRunner(),
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/hc-test")).normalized(),
            graph,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "fuzz_target.cc"
            source.write_text(
                'extern "C" int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long) { return 0; }',
                encoding="utf-8",
            )
            seed = root / "seed"
            seed.write_bytes(b"x")
            with patch("harnesscreator.runtime.runner.shutil.which", return_value="/usr/bin/gdb"):
                reports, reached, error = await verifier._verify_reachability(
                    root / "wrong-fuzzer",
                    [seed],
                    [serve.function_id],
                    harness_source=source,
                )

        self.assertEqual(reached, 0)
        self.assertEqual(len(reports), 1)
        self.assertIn("did not execute the generated", error or "")

    async def test_reachability_checks_each_variant_target_with_its_selector_seed(self) -> None:
        class ReachRunner:
            def __init__(self):
                self.calls = []

            async def run(self, argv, *, cwd, timeout_seconds, env=None):
                self.calls.append(list(argv))
                return CommandReport(
                    argv=list(argv), returncode=0,
                    stdout="Breakpoint 1, selected_target ()\n#0 selected_target ()",
                    stderr="", duration_seconds=0.01,
                )

        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        runner = ReachRunner()
        verifier = HarnessVerifier(
            runner,
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/hc-test")).normalized(),
            graph,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seeds = []
            for index in range(5):
                seed = root / f"seed-{index}"
                seed.write_bytes(bytes([index + 1]))
                seeds.append(seed)
            variant_seed = root / "variant-0"
            variant_seed.write_bytes(b"\x00seed")
            seeds.append(variant_seed)
            with patch("harnesscreator.runtime.runner.shutil.which", return_value="/usr/bin/gdb"):
                reports, reached, error = await verifier._verify_reachability(
                    root / "fuzzer",
                    seeds,
                    [serve.function_id],
                    [{
                        "selector": "0",
                        "small_feature_id": "sf-0",
                        "function_id": parse.function_id,
                    }],
                )

        self.assertIsNone(error)
        self.assertEqual(reached, 5)
        self.assertEqual(len(reports), 6)
        self.assertIn(f"break {parse.file}:{parse.start_line}", runner.calls[-1])
        self.assertIn(str(variant_seed), runner.calls[-1])

    async def test_variant_reachability_tries_llm_seed_after_generic_seed(self) -> None:
        class ReachRunner:
            def __init__(self):
                self.calls = []

            async def run(self, argv, *, cwd, timeout_seconds, env=None):
                self.calls.append(list(argv))
                seed = next(
                    (str(item) for item in argv if "variant-0" in str(item)), ""
                )
                reached = not seed or "llm-variant-0-reach" in seed
                return CommandReport(
                    argv=list(argv), returncode=0,
                    stdout=("Breakpoint 1, selected_target ()\n#0 selected_target ()" if reached else ""),
                    stderr="", duration_seconds=0.01,
                )

        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        by_name = {function.name: function for function in bundle.functions.values()}
        serve = by_name["serve_client"]
        parse = by_name["parse_frame"]
        runner = ReachRunner()
        verifier = HarnessVerifier(
            runner,
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/hc-test")).normalized(),
            graph,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seeds = []
            for index in range(5):
                seed = root / f"seed-{index}"
                seed.write_bytes(bytes([index + 1]))
                seeds.append(seed)
            generic = root / "variant-0"
            generic.write_bytes(b"\x00seed")
            llm_seed = root / "llm-variant-0-reach"
            llm_seed.write_bytes(b"\x00structured-request")
            seeds.extend([generic, llm_seed])
            with patch("harnesscreator.runtime.runner.shutil.which", return_value="/usr/bin/gdb"):
                reports, reached, error = await verifier._verify_reachability(
                    root / "fuzzer", seeds, [serve.function_id], [{
                        "selector": "0",
                        "small_feature_id": "sf-0",
                        "function_id": parse.function_id,
                    }],
                )

        self.assertIsNone(error)
        self.assertEqual(reached, 5)
        self.assertEqual(len(reports), 7)
        self.assertIn(str(generic), runner.calls[-2])
        self.assertIn(str(llm_seed), runner.calls[-1])

    async def test_reachability_requires_five_seed_anchor_hits(self) -> None:
        class ReachRunner:
            def __init__(self):
                self.calls = []

            async def run(self, argv, *, cwd, timeout_seconds, env=None):
                self.calls.append(list(argv))
                return CommandReport(
                    argv=list(argv), returncode=0,
                    stdout="Breakpoint 1, serve_client ()\n#0 serve_client ()",
                    stderr="", duration_seconds=0.01,
                )

        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(function for function in bundle.functions.values() if function.name == "serve_client")
        runner = ReachRunner()
        verifier = HarnessVerifier(
            runner,
            ProjectSpec(source_root=FIXTURE, output_root=Path("/tmp/hc-test")).normalized(),
            graph,
        )
        with tempfile.TemporaryDirectory() as temporary:
            seeds = []
            for index in range(7):
                seed = Path(temporary) / f"seed-{index}"
                seed.write_bytes(bytes([index]))
                seeds.append(seed)
            with patch("harnesscreator.runtime.runner.shutil.which", return_value="/usr/bin/gdb"):
                reports, reached, error = await verifier._verify_reachability(
                    Path(temporary) / "fuzzer", seeds, [serve.function_id]
                )

        self.assertIsNone(error)
        self.assertEqual(reached, 5)
        self.assertEqual(len(reports), 5)
        self.assertEqual(len(runner.calls), 5)

    async def test_qualifies_only_when_coverage_grows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fuzzer"
            binary.write_bytes(b"__asan_init __ubsan_handle_ LLVMFuzzerRunDriver")
            manifest = HarnessManifest(
                harness_id="h-1", large_feature_id="lf-1", source_file="fuzz_target.cc",
                build_target="fuzz_target", engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=[], libraries=[], min_size=1,
                max_size=4096, dispatch_strategy="selector_byte", expected_anchors=["anchor"],
                expected_consumers=["consumer"], build_command=["true"], binary=str(binary),
            )
            draft = HarnessDraft(manifest=manifest, code="LLVMFuzzerTestOneInput")
            project = ProjectSpec(
                source_root=FIXTURE,
                output_root=root,
                build_command=["true"],
                harness_binary=binary,
                fuzz_seconds=1,
            ).normalized()
            result = await HarnessVerifier(_SuccessfulRunner(), project).verify(draft, root / "artifacts")
            self.assertTrue(result.qualified)
            self.assertTrue(result.coverage_grew)

    async def test_crash_attribution_uses_first_project_frame(self) -> None:
        harness = Path("/tmp/run/fuzz_target.cc")
        target = FIXTURE.resolve() / "target.c"
        target_first = (
            "#0 0x1 in parse_frame " + str(target) + ":8\n"
            "#1 0x2 in LLVMFuzzerTestOneInput /tmp/run/fuzz_target.cc:20\n"
        )
        harness_first = (
            "#0 0x1 in adapter_copy /tmp/run/fuzz_target.cc:12\n"
            "#1 0x2 in parse_frame " + str(target) + ":8\n"
        )

        self.assertEqual(
            _first_relevant_stack_frame(target_first, harness, FIXTURE),
            "target",
        )
        self.assertEqual(
            _first_relevant_stack_frame(harness_first, harness, FIXTURE),
            "harness",
        )
        self.assertEqual(
            _first_relevant_stack_frame(
                "#0 0x1 in parse_frame tests/fixtures/c_project/target.c:8\n",
                harness,
                Path(__file__).parents[1],
            ),
            "target",
        )

    async def test_attributed_target_seed_is_a_finding_not_a_harness_failure(self) -> None:
        class CrashRunner:
            def __init__(self):
                self.calls = 0

            async def run(self, argv, *, cwd, timeout_seconds, env=None):
                self.calls += 1
                is_build = argv == ["true"]
                is_fuzz = any(str(item).startswith("-max_total_time=") for item in argv)
                crashed = self.calls == 2 and not is_build
                return CommandReport(
                    argv=list(argv), returncode=1 if crashed else 0,
                    stdout="#1 cov: 3\n#2 cov: 8\n" if is_fuzz else "",
                    stderr="AddressSanitizer" if crashed else "",
                    duration_seconds=0.01,
                )

        class TargetVerifier(HarnessVerifier):
            async def _attribute(self, binary, seed, report, source_path):
                return "target", "target frame"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fuzzer"
            binary.write_bytes(b"__asan_init __ubsan_handle_ LLVMFuzzerRunDriver")
            manifest = HarnessManifest(
                harness_id="h-target", large_feature_id="lf-target", source_file="fuzz_target.cc",
                build_target="fuzz_target", engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=[], libraries=[], min_size=1,
                max_size=4096, dispatch_strategy="one_job_per_feature", expected_anchors=["anchor"],
                expected_consumers=["consumer"], build_command=["true"], binary=str(binary),
            )
            draft = HarnessDraft(manifest=manifest, code="LLVMFuzzerTestOneInput")
            project = ProjectSpec(
                source_root=FIXTURE, output_root=root, build_command=["true"],
                harness_binary=binary, fuzz_seconds=1,
            ).normalized()

            result = await TargetVerifier(CrashRunner(), project).verify(
                draft, root / "artifacts"
            )

            self.assertTrue(result.qualified)
            self.assertFalse(result.harness_faults)
            self.assertTrue(result.target_findings)
            self.assertIsNotNone(result.fuzz)
            self.assertTrue(result.coverage_grew)

    async def test_harness_crash_seed_is_preserved_for_repair_regression(self) -> None:
        class CrashRunner:
            def __init__(self):
                self.calls = 0

            async def run(self, argv, *, cwd, timeout_seconds, env=None):
                self.calls += 1
                crashed = self.calls == 2 and argv != ["true"]
                return CommandReport(
                    argv=list(argv), returncode=1 if crashed else 0,
                    stdout="", stderr="AddressSanitizer" if crashed else "",
                    duration_seconds=0.01,
                )

        class HarnessFaultVerifier(HarnessVerifier):
            async def _attribute(self, binary, seed, report, source_path):
                return "harness", "generated adapter frame"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fuzzer"
            binary.write_bytes(b"__asan_init __ubsan_handle_ LLVMFuzzerRunDriver")
            manifest = HarnessManifest(
                harness_id="h-fault", large_feature_id="lf-fault",
                source_file="fuzz_target.cc", build_target="fuzz_target",
                engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=1, max_size=4096, dispatch_strategy="one_job_per_feature",
                expected_anchors=["anchor"], expected_consumers=["consumer"],
                build_command=["true"], binary=str(binary),
            )
            draft = HarnessDraft(manifest=manifest, code="LLVMFuzzerTestOneInput")
            project = ProjectSpec(
                source_root=FIXTURE, output_root=root, build_command=["true"],
                harness_binary=binary, fuzz_seconds=1,
            ).normalized()

            result = await HarnessFaultVerifier(CrashRunner(), project).verify(
                draft, root / "artifacts"
            )

        self.assertFalse(result.qualified)
        self.assertTrue(result.harness_faults)
        self.assertEqual(len(result.harness_fault_seeds), 1)
        self.assertTrue(result.harness_fault_seeds[0].name.startswith("regression-"))
        self.assertTrue(result.harness_fault_seeds[0].data_hex)


if __name__ == "__main__":
    unittest.main()
