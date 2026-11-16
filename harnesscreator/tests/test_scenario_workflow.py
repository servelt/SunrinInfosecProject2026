from __future__ import annotations

import sys
from dataclasses import replace
import asyncio
import socket
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from harnesscreator.agents.scenario import (
    InputActionAgent as _InputActionAgent,
    ScenarioPlanner,
    StateDependencyAgent,
)
from harnesscreator.agents.scenario_harness import (
    ScenarioHarnessGeneratorAgent,
    ScenarioStaticHarnessGate,
    _binding_symbol,
    build_harness_plan,
)
from harnesscreator.agents.harness import CHECKLIST_NAMES
from harnesscreator.analysis import (
    GraphStore,
    StaticAnalyzer,
    discover_usage_artifacts,
    load_netlifter_grammars,
    relevant_usage_functions,
)
from harnesscreator.analysis.usage_evidence import UsageConstraint, UsageEvidenceBundle
from harnesscreator.llm.base import InvalidOutputSchemaError, ScriptedLLM
from harnesscreator.llm.codex_app_server import CodexAppServerError
from harnesscreator.models import (
    ActionExample,
    ActionOrderingConstraint,
    ActionStateContract,
    AnalysisBundle,
    CallEdge,
    CheckStatus,
    CrashReproductionStatus,
    EntryRecord,
    EntrySiteKind,
    Evidence,
    ExternalActionSchema,
    FunctionMetadata,
    HarnessDraft,
    HarnessManifest,
    InputFieldConstraint,
    OperationSeed,
    ProjectSpec,
    ProofStatus,
    RequestBindingUse,
    ResponseBindingExtractor,
    ScenarioCandidate,
    ScenarioStatus,
    ScenarioStep,
    ScenarioWitness,
    SeedSpec,
    StateDependencyGraph,
    StateRequirement,
    Verdict,
)
from harnesscreator.runtime.scenario import (
    OriginalCrashReproducer,
    ScenarioRuntimeVerifier,
    _GdbTargetProbe,
    _ordered_trace_hits,
)
from harnesscreator.runtime.crash import (
    crash_signatures_match,
    extract_crash_signature,
)


class InputActionAgent(_InputActionAgent):
    """Exercise the retained branch worker compatibility path in this fixture."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("semantic_action_mode", False)
        super().__init__(*args, **kwargs)


def _action(identifier: str, request: bytes, marker: bytes) -> ExternalActionSchema:
    evidence = [Evidence("source", "fn", "target.c", 1, "fixture evidence")]
    return ExternalActionSchema(
        action_id=identifier,
        entry_id="entry-stdin",
        name=identifier,
        description=identifier,
        dispatcher_function_id="fn-dispatch",
        handler_function_id=f"fn-{identifier}",
        discriminator=identifier,
        channel_kind="stdin",
        fields=[],
        examples=[ActionExample(request.hex(), {"key": b"k".hex()})],
        success_markers_hex=[marker.hex()],
        failure_markers_hex=[b"MISS\n".hex()],
        evidence=evidence,
        inspected_function_ids=["fn-dispatch", f"fn-{identifier}"],
        status=ProofStatus.PROVEN_STATIC,
        confidence=0.99,
        source_api="read",
        success_evidence=evidence,
        failure_evidence=evidence,
    )


def _observed_verifier(
    project: ProjectSpec,
    actions: list[ExternalActionSchema],
) -> ScenarioRuntimeVerifier:
    """Transport fixtures explicitly stand in for an exact target probe."""

    return ScenarioRuntimeVerifier(
        project,
        actions,
        target_observer=lambda _step, _action, _request, _response: True,
    )


class ScenarioPlannerTest(unittest.TestCase):
    def test_variant_budget_is_not_reported_as_complete(self) -> None:
        action = _action("READ", b"A", b"OK")
        action.examples.append(ActionExample(b"B".hex(), {"key": b"k".hex()}))
        contract = ActionStateContract(
            action.action_id, [], [], [], "completed", action.evidence,
            [action.handler_function_id], ProofStatus.PROVEN_STATIC,
        )
        planner = ScenarioPlanner(
            max_candidates=1, max_variants_per_action=1, max_search_states=10,
        )
        candidates = planner.plan(
            [action], StateDependencyGraph([contract], [], []),
        )
        self.assertEqual(len(candidates), 1)
        self.assertTrue(any(
            "variant work budget" in item and "READ" in item
            for item in planner.obligations
        ))

    def test_default_depth_does_not_cut_a_source_proven_ten_step_chain(self) -> None:
        actions = [_action(f"stage-{index}", bytes([65 + index]), b"OK")
                   for index in range(10)]
        contracts = []
        for index, item in enumerate(actions):
            consumes = ([StateRequirement(
                f"state-{index - 1}", "", "present", item.evidence,
                ProofStatus.PROVEN_STATIC,
            )] if index else [])
            produces = ([StateRequirement(
                f"state-{index}", "", "present", item.evidence,
                ProofStatus.PROVEN_STATIC,
            )] if index < len(actions) - 1 else [])
            contracts.append(ActionStateContract(
                item.action_id, consumes, produces, [], "completed",
                item.evidence, [item.handler_function_id],
                ProofStatus.PROVEN_STATIC,
            ))
        dependency_graph = StateDependencyGraph(contracts, [], [])

        candidates = ScenarioPlanner().plan(actions, dependency_graph)

        target = [item for item in candidates if item.target_action_id == "stage-9"]
        self.assertTrue(target)
        self.assertEqual(target[0].status, ScenarioStatus.CANDIDATE)
        self.assertEqual(len(target[0].steps), 10)

    def test_concrete_initial_binding_selects_only_the_matching_request(self) -> None:
        query = _action("query", b"GET a\n", b"VALUE\n")
        query.examples = [
            ActionExample(b"GET a\n".hex(), {"key": b"a".hex()}),
            ActionExample(b"GET b\n".hex(), {"key": b"b".hex()}),
        ]
        resource = StateRequirement(
            "item", "key", "exists", query.evidence,
            ProofStatus.PROVEN_STATIC,
            binding_value_hex=b"b".hex(),
        )
        graph = StateDependencyGraph(
            contracts=[ActionStateContract(
                "query", [resource], [], [], "value", query.evidence,
                ["fn-query"], ProofStatus.PROVEN_STATIC,
            )],
            initial_resources=[resource],
            open_obligations=[],
        )

        candidate = ScenarioPlanner(max_steps=2).plan([query], graph)[0]

        self.assertEqual(candidate.status, ScenarioStatus.CANDIDATE)
        self.assertEqual(
            bytes.fromhex(candidate.steps[0].request_hex), b"GET b\n"
        )

    def test_symbolic_initial_binding_without_a_value_is_not_used(self) -> None:
        query = _action("query", b"GET a\n", b"VALUE\n")
        resource = StateRequirement(
            "item", "key", "exists", query.evidence,
            ProofStatus.PROVEN_STATIC,
        )
        graph = StateDependencyGraph(
            contracts=[ActionStateContract(
                "query", [resource], [], [], "value", query.evidence,
                ["fn-query"], ProofStatus.PROVEN_STATIC,
            )],
            initial_resources=[resource],
            open_obligations=[],
        )
        planner = ScenarioPlanner(max_steps=2)

        candidate = planner.plan([query], graph)[0]

        self.assertEqual(candidate.status, ScenarioStatus.UNPROVEN)
        self.assertTrue(any(
            "without a concrete value" in item for item in planner.obligations
        ))

    def test_preserves_bounded_alternative_request_examples(self) -> None:
        action = _action("query", b"BAD\n", b"OK\n")
        action.examples = [
            ActionExample(b"BAD\n".hex(), {}),
            ActionExample(b"GOOD\n".hex(), {}),
        ]
        dependencies = StateDependencyGraph([
            ActionStateContract(
                "query", [], [], [], "ok", action.evidence,
                ["fn-query"], ProofStatus.PROVEN_STATIC,
            )
        ], [], [])

        candidates = ScenarioPlanner(
            max_steps=2, max_variants_per_action=2
        ).plan([action], dependencies)

        self.assertEqual(
            [bytes.fromhex(item.steps[0].request_hex) for item in candidates],
            [b"BAD\n", b"GOOD\n"],
        )

    def test_candidate_budget_preserves_one_outcome_per_target(self) -> None:
        actions = [
            _action("one", b"ONE\n", b"OK\n"),
            _action("two", b"TWO\n", b"OK\n"),
            _action("three", b"THREE\n", b"OK\n"),
        ]
        dependencies = StateDependencyGraph(
            contracts=[
                ActionStateContract(
                    action.action_id, [], [], [], "ok", action.evidence,
                    [action.handler_function_id], ProofStatus.PROVEN_STATIC,
                )
                for action in actions
            ],
            initial_resources=[],
            open_obligations=[],
        )
        planner = ScenarioPlanner(max_steps=2, max_candidates=1)

        candidates = planner.plan(actions, dependencies)

        self.assertEqual(
            [item.target_action_id for item in candidates],
            ["one", "two", "three"],
        )
        self.assertTrue(any(
            "retaining one planning outcome per target" in item
            for item in planner.obligations
        ))

    def test_candidate_budget_preserves_late_unresolved_target(self) -> None:
        actions = [
            _action("one", b"ONE\n", b"OK\n"),
            _action("two", b"TWO\n", b"OK\n"),
        ]
        dependencies = StateDependencyGraph(
            contracts=[ActionStateContract(
                "one", [], [], [], "ok", actions[0].evidence,
                [actions[0].handler_function_id], ProofStatus.PROVEN_STATIC,
            )],
            initial_resources=[], open_obligations=[],
        )
        candidates = ScenarioPlanner(max_candidates=1).plan(actions, dependencies)

        self.assertEqual(
            [(item.target_action_id, item.status) for item in candidates],
            [("one", ScenarioStatus.CANDIDATE),
             ("two", ScenarioStatus.UNPROVEN)],
        )
        self.assertIn("state contract", candidates[1].blocker)

    def test_default_has_no_four_variant_action_cutoff(self) -> None:
        action = _action("formats", b"FORMAT-0\n", b"OK\n")
        action.examples = [
            ActionExample(data_hex=f"FORMAT-{index}\n".encode().hex(),
                          bindings={}, rationale="source example")
            for index in range(5)
        ]
        dependencies = StateDependencyGraph(
            contracts=[ActionStateContract(
                action.action_id, [], [], [], "ok", action.evidence,
                [action.handler_function_id], ProofStatus.PROVEN_STATIC,
            )],
            initial_resources=[], open_obligations=[],
        )

        candidates = ScenarioPlanner(max_candidates=6).plan([action], dependencies)

        self.assertEqual(len(candidates), 5)
        self.assertEqual(
            {bytes.fromhex(item.steps[0].request_hex) for item in candidates},
            {f"FORMAT-{index}\n".encode() for index in range(5)},
        )

    def test_candidate_budget_distributes_remainder_to_other_targets(self) -> None:
        actions = [
            _action(name, f"{name}-0\n".encode(), b"OK\n")
            for name in ("one", "two", "three")
        ]
        for action in actions:
            action.examples = [
                ActionExample(data_hex=f"{action.action_id}-{index}\n".encode().hex(),
                              bindings={}, rationale="source example")
                for index in range(3)
            ]
        dependencies = StateDependencyGraph(
            contracts=[ActionStateContract(
                action.action_id, [], [], [], "ok", action.evidence,
                [action.handler_function_id], ProofStatus.PROVEN_STATIC,
            ) for action in actions],
            initial_resources=[], open_obligations=[],
        )

        candidates = ScenarioPlanner(max_candidates=5).plan(actions, dependencies)

        self.assertEqual(len(candidates), 5)
        self.assertEqual(
            [sum(item.target_action_id == action.action_id for item in candidates)
             for action in actions],
            [2, 2, 1],
        )

    def test_exploratory_budget_is_not_monopolized_by_first_action(self) -> None:
        actions = [
            _action(name, f"{name}-0\n".encode(), b"OK\n")
            for name in ("one", "two")
        ]
        for action in actions:
            action.entry_function_id = "fn-entry"
            action.examples = [
                ActionExample(data_hex=f"{action.action_id}-{index}\n".encode().hex(),
                              bindings={}, rationale="source example")
                for index in range(5)
            ]

        candidates = ScenarioPlanner(max_candidates=4).exploratory_candidates(
            actions, [],
        )

        self.assertEqual(len(candidates), 4)
        self.assertEqual(
            [sum(item.target_action_id == action.action_id for item in candidates)
             for action in actions],
            [2, 2],
        )

    def test_finds_set_before_get_from_state_contracts(self) -> None:
        set_action = _action("set", b"SET k\n", b"STORED\n")
        get_action = _action("get", b"GET k\n", b"VALUE\n")
        resource = StateRequirement(
            resource="item", binding="key", predicate="exists",
            evidence=set_action.evidence, status=ProofStatus.PROVEN_STATIC,
        )
        dependencies = StateDependencyGraph(
            contracts=[
                ActionStateContract(
                    "set", [], [resource], [], "stored", set_action.evidence,
                    ["fn-set"], ProofStatus.PROVEN_STATIC,
                ),
                ActionStateContract(
                    "get", [resource], [], [], "value", get_action.evidence,
                    ["fn-get"], ProofStatus.PROVEN_STATIC,
                ),
            ],
            initial_resources=[],
            open_obligations=[],
        )

        candidates = ScenarioPlanner(max_steps=4).plan(
            [set_action, get_action], dependencies
        )
        get_candidate = next(item for item in candidates if item.target_action_id == "get")

        self.assertEqual(get_candidate.status, ScenarioStatus.CANDIDATE)
        self.assertEqual([item.action_id for item in get_candidate.steps], ["set", "get"])

    def test_search_budget_exhaustion_is_reported_as_an_obligation(self) -> None:
        set_action = _action("set", b"SET k\n", b"STORED\n")
        get_action = _action("get", b"GET k\n", b"VALUE\n")
        resource = StateRequirement(
            resource="item", binding="key", predicate="exists",
            evidence=set_action.evidence, status=ProofStatus.PROVEN_STATIC,
        )
        dependencies = StateDependencyGraph(
            contracts=[
                ActionStateContract(
                    "set", [], [resource], [], "stored", set_action.evidence,
                    ["fn-set"], ProofStatus.PROVEN_STATIC,
                ),
                ActionStateContract(
                    "get", [resource], [], [], "value", get_action.evidence,
                    ["fn-get"], ProofStatus.PROVEN_STATIC,
                ),
            ],
            initial_resources=[],
            open_obligations=[],
        )
        planner = ScenarioPlanner(max_steps=4, max_search_states=1)

        candidates = planner.plan([set_action, get_action], dependencies)
        get_candidate = next(
            item for item in candidates if item.target_action_id == "get"
        )

        self.assertEqual(get_candidate.status, ScenarioStatus.UNPROVEN)
        self.assertIn("producer sequence unresolved", get_candidate.blocker)
        self.assertIn("unexplored states remaining", get_candidate.blocker)
        self.assertNotIn("no producer sequence satisfies", get_candidate.blocker)
        self.assertTrue(any("get:" in item for item in planner.obligations))
        self.assertTrue(any("1-state safety limit" in item for item in planner.obligations))

    def test_does_not_invent_an_unavailable_producer(self) -> None:
        get_action = _action("get", b"GET k\n", b"VALUE\n")
        resource = StateRequirement(
            resource="item", binding="key", predicate="exists",
            evidence=get_action.evidence, status=ProofStatus.PROVEN_STATIC,
        )
        dependencies = StateDependencyGraph(
            [ActionStateContract(
                "get", [resource], [], [], "value", get_action.evidence,
                ["fn-get"], ProofStatus.PROVEN_STATIC,
            )], [], [],
        )

        candidate = ScenarioPlanner(max_steps=4).plan([get_action], dependencies)[0]

        self.assertEqual(candidate.status, ScenarioStatus.UNPROVEN)
        self.assertIn("no producer sequence", candidate.blocker)

    def test_backtracks_over_examples_to_preserve_shared_binding(self) -> None:
        set_action = _action("set", b"SET a\n", b"STORED\n")
        set_action.examples = [
            ActionExample(b"SET a\n".hex(), {"key": b"a".hex()}),
            ActionExample(b"SET b\n".hex(), {"key": b"b".hex()}),
        ]
        get_action = _action("get", b"GET b\n", b"VALUE\n")
        get_action.examples = [
            ActionExample(b"GET b\n".hex(), {"key": b"b".hex()})
        ]
        resource = StateRequirement(
            "item", "key", "exists", set_action.evidence,
            ProofStatus.PROVEN_STATIC,
        )
        graph = StateDependencyGraph([
            ActionStateContract(
                "set", [], [resource], [], "stored", set_action.evidence,
                ["fn-set"], ProofStatus.PROVEN_STATIC,
            ),
            ActionStateContract(
                "get", [resource], [], [], "value", get_action.evidence,
                ["fn-get"], ProofStatus.PROVEN_STATIC,
            ),
        ], [], [])

        candidate = next(
            item for item in ScenarioPlanner(max_steps=4).plan(
                [set_action, get_action], graph
            )
            if item.target_action_id == "get"
        )

        self.assertEqual(
            [bytes.fromhex(step.request_hex) for step in candidate.steps],
            [b"SET b\n", b"GET b\n"],
        )

    def test_enforces_exact_upstream_required_order(self) -> None:
        login = _action("login", b"LOGIN\n", b"OK\n")
        query = _action("query", b"QUERY\n", b"RESULT\n")
        graph = StateDependencyGraph(
            contracts=[
                ActionStateContract(
                    "login", [], [], [], "ok", login.evidence,
                    ["fn-login"], ProofStatus.PROVEN_STATIC,
                ),
                ActionStateContract(
                    "query", [], [], [], "result", query.evidence,
                    ["fn-query"], ProofStatus.PROVEN_STATIC,
                ),
            ],
            initial_resources=[],
            open_obligations=[],
            ordering_constraints=[ActionOrderingConstraint(
                "order-login-query", "login", "query", "REQUIRED",
                "Hopper", "fixture rule",
            )],
        )

        candidate = next(
            item for item in ScenarioPlanner(max_steps=4).plan(
                [login, query], graph
            )
            if item.target_action_id == "query"
        )

        self.assertEqual(
            [step.action_id for step in candidate.steps], ["login", "query"]
        )


class EvidenceBoundaryTest(unittest.TestCase):
    def test_project_test_client_is_separate_ranked_usage_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "server.c").write_text(
                "int dispatch(int opcode) { return opcode == 7; }\n",
                encoding="utf-8",
            )
            (root / "testapp.c").write_text(
                "int test_cmd_get(int fd) { unsigned char p[2] = {7, 0}; "
                "return send(fd, p, 2, 0); }\n",
                encoding="utf-8",
            )
            analysis = StaticAnalyzer(root).index()
            artifacts = discover_usage_artifacts(root, analysis)

        self.assertEqual([item.path for item in artifacts], ["testapp.c"])
        selected = relevant_usage_functions(
            artifacts,
            analysis,
            discriminators=["CMD_GET", "test_cmd_get"],
            opened=[],
        )
        self.assertEqual(len(selected), 1)
        self.assertEqual(analysis.functions[selected[0]].name, "test_cmd_get")
        self.assertNotIn(
            next(item.function_id for item in analysis.functions.values() if item.name == "dispatch"),
            selected,
        )

    def test_crash_identity_requires_fault_class_and_common_target_frame(self) -> None:
        expected = extract_crash_signature(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 0x1 in parse_packet /src/parser.c:42\n"
        )
        same = extract_crash_signature(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 0x999 in parse_packet /different/root/parser.c:42\n"
        )
        wrong_frame = extract_crash_signature(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 0x2 in harness_copy /src/fuzz_target.c:12\n"
        )
        wrong_class = extract_crash_signature(
            "ERROR: AddressSanitizer: heap-use-after-free\n"
            "#0 0x3 in parse_packet /src/parser.c:42\n"
        )

        self.assertTrue(crash_signatures_match(expected, same))
        self.assertFalse(crash_signatures_match(expected, wrong_frame))
        self.assertFalse(crash_signatures_match(expected, wrong_class))


class ScenarioRuntimeTest(unittest.IsolatedAsyncioTestCase):
    async def test_unframed_stdin_reply_is_retained_without_success_proof(self) -> None:
        script = (
            "import sys,time\n"
            "sys.stdin.buffer.readline()\n"
            "sys.stdout.buffer.write(b'READY'); sys.stdout.buffer.flush()\n"
            "time.sleep(0.3)\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
                scenario_require_target_reach=False,
                scenario_step_timeout=1.0,
            ).normalized()
            action = _action("unframed", b"X\n", b"READY")
            action.success_markers_hex = []
            action.failure_markers_hex = []
            candidate = ScenarioCandidate(
                "unframed-trial", action.action_id,
                [ScenarioStep(0, action.action_id, action.entry_id,
                              b"X\n".hex(), {}, [])],
                [action.entry_id], [], [],
            )

            witness = await ScenarioRuntimeVerifier(project, [action]).verify(candidate)

        self.assertEqual(witness.status, ScenarioStatus.UNPROVEN)
        self.assertEqual(bytes.fromhex(witness.observations[0].response_hex), b"READY")
        self.assertFalse(witness.observations[0].response_success)
        self.assertIn("origin and frame boundary unknown", witness.observations[0].detail)
        self.assertLess(witness.observations[0].duration_seconds, 0.3)

    async def test_disabled_target_check_does_not_manufacture_runtime_proof(self) -> None:
        script = (
            "import sys\n"
            "sys.stdin.buffer.readline()\n"
            "sys.stdout.buffer.write(b'OK\\n'); sys.stdout.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
                scenario_require_target_reach=False,
            ).normalized()
            action = _action("checked", b"X\n", b"OK\n")
            candidate = ScenarioCandidate(
                "disabled-probe", action.action_id,
                [ScenarioStep(0, action.action_id, action.entry_id,
                              b"X\n".hex(), {}, [b"OK\n".hex()])],
                [action.entry_id], [], [],
            )

            witness = await ScenarioRuntimeVerifier(project, [action]).verify(candidate)

        self.assertEqual(witness.status, ScenarioStatus.UNPROVEN)
        self.assertTrue(witness.observations[0].response_success)
        self.assertFalse(witness.observations[0].entry_reached)
        self.assertFalse(witness.observations[0].target_reached)

    async def test_file_replay_marker_cannot_prove_unbacked_or_experimental_input(self) -> None:
        script = (
            "import pathlib,sys\n"
            "pathlib.Path(sys.argv[1]).read_bytes()\n"
            "sys.stdout.buffer.write(b'OK\\n')\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-c", script, "{input_file}"],
                scenario_channel="file",
            ).normalized()
            action = replace(
                _action("read-file", b"A", b"OK\n"),
                entry_id="entry-file", channel_kind="file", success_evidence=[],
            )
            candidate = ScenarioCandidate(
                "file-marker", action.action_id,
                [ScenarioStep(0, action.action_id, "entry-file", b"A".hex(), {},
                              [b"OK\n".hex()])],
                ["entry-file"], [], [],
            )
            without_evidence = await _observed_verifier(project, [action]).verify(candidate)
            experimental_action = replace(
                action,
                examples=[replace(action.examples[0], origin="model_input_hypothesis")],
            )
            experimental = await _observed_verifier(
                project, [experimental_action]
            ).verify(candidate)
            experimental_with_evidence = await _observed_verifier(project, [replace(
                experimental_action, success_evidence=list(action.evidence),
            )]).verify(candidate)

        self.assertEqual(without_evidence.status, ScenarioStatus.UNPROVEN)
        self.assertFalse(without_evidence.observations)
        self.assertIn("no source-evidenced success oracle", without_evidence.rationale)
        for witness in (experimental, experimental_with_evidence):
            self.assertEqual(witness.status, ScenarioStatus.UNPROVEN)
            self.assertTrue(witness.observations, witness.rationale)
            self.assertTrue(witness.observations[0].response_success)
            self.assertTrue(witness.observations[0].target_reached)
            self.assertIn("NOT PROVEN_RUNTIME", witness.rationale)

    @staticmethod
    def _free_port(socket_type: int) -> int:
        try:
            probe = socket.socket(socket.AF_INET, socket_type)
        except PermissionError as exc:
            raise unittest.SkipTest(
                "the execution sandbox forbids local network sockets"
            ) from exc
        try:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])
        finally:
            probe.close()

    async def test_response_binding_is_extracted_and_patched_into_later_entry(self) -> None:
        login = _action("login", b"LOGIN\n", b"OK:")
        login.response_bindings = [ResponseBindingExtractor(
            binding="session_id",
            offset=3,
            width=4,
            evidence=login.evidence,
        )]
        use = _action("use", b"USE 0000\n", b"DONE\n")
        use.fields = [InputFieldConstraint(
            name="session_id",
            offset=4,
            width=4,
            encoding="bytes",
            binding="session_id",
            relation="equals login response session id",
            evidence=use.evidence,
        )]
        resource = StateRequirement(
            resource="authenticated_session",
            binding="session_id",
            predicate="exists",
            evidence=login.evidence,
            status=ProofStatus.PROVEN_STATIC,
        )
        dependencies = StateDependencyGraph(
            contracts=[
                ActionStateContract(
                    "login", [], [resource], [], "session returned",
                    login.evidence, ["fn-login"], ProofStatus.PROVEN_STATIC,
                ),
                ActionStateContract(
                    "use", [resource], [], [], "command accepted",
                    use.evidence, ["fn-use"], ProofStatus.PROVEN_STATIC,
                ),
            ],
            initial_resources=[],
            open_obligations=[],
        )
        candidate = next(
            item for item in ScenarioPlanner(max_steps=4).plan(
                [login, use], dependencies
            )
            if item.target_action_id == "use"
        )
        script = (
            "import sys\n"
            "token=b'ABCD'\n"
            "first=sys.stdin.buffer.readline()\n"
            "sys.stdout.buffer.write(b'OK:'+token+b'\\n' if first==b'LOGIN\\n' else b'ERR\\n')\n"
            "sys.stdout.buffer.flush()\n"
            "second=sys.stdin.buffer.readline()\n"
            "sys.stdout.buffer.write(b'DONE\\n' if second==b'USE '+token+b'\\n' else b'ERR\\n')\n"
            "sys.stdout.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            project = ProjectSpec(
                source_root=Path(temporary),
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                svf_enabled=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
                scenario_step_timeout=2.0,
            )
            witness = await _observed_verifier(
                project, [login, use]
            ).verify(candidate)

        self.assertEqual(candidate.steps[1].request_hex, b"USE 0000\n".hex())
        self.assertEqual(len(candidate.steps[1].request_binding_uses), 1)
        self.assertEqual(witness.status, ScenarioStatus.PROVEN_RUNTIME)
        self.assertEqual(
            witness.observations[0].extracted_bindings,
            {"session_id": b"ABCD".hex()},
        )
        self.assertEqual(witness.steps[1].request_hex, b"USE ABCD\n".hex())
        self.assertEqual(
            witness.steps[1].request_template_hex, b"USE 0000\n".hex()
        )

    async def test_tcp_original_executor_observes_a_split_success_response(self) -> None:
        port = self._free_port(socket.SOCK_STREAM)
        script = (
            "import socket,sys,time\n"
            "port=int(sys.argv[1])\n"
            "server=socket.socket(); server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            "server.bind(('127.0.0.1',port)); server.listen(1)\n"
            "conn,_=server.accept(); data=conn.recv(4096)\n"
            "if data == b'PING\\n':\n"
            "  conn.sendall(b'PO'); time.sleep(0.02); conn.sendall(b'NG\\n')\n"
            "else: conn.sendall(b'ERR\\n')\n"
            "conn.close(); server.close()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script, str(port)],
                scenario_channel="tcp",
                scenario_host="127.0.0.1",
                scenario_port=port,
                scenario_startup_timeout=2.0,
                scenario_step_timeout=1.0,
            ).normalized()
            action = _action("ping", b"PING\n", b"PONG\n")
            action.channel_kind = "network socket"
            action.source_api = "recv"
            candidate = ScenarioCandidate(
                "tcp-ping", "ping",
                [ScenarioStep(
                    0, "ping", "entry-tcp", b"PING\n".hex(), {},
                    [b"PONG\n".hex()],
                )],
                ["entry-tcp"], [], [],
            )

            witness = await _observed_verifier(project, [action]).verify(candidate)

        self.assertEqual(witness.status, ScenarioStatus.PROVEN_RUNTIME)
        self.assertEqual(bytes.fromhex(witness.observations[0].response_hex), b"PONG\n")
        self.assertIsNotNone(witness.tcp_connect_after_launch_seconds)
        self.assertGreaterEqual(witness.tcp_connect_after_launch_seconds, 0)

    async def test_udp_original_executor_retries_startup_and_observes_success(self) -> None:
        port = self._free_port(socket.SOCK_DGRAM)
        script = (
            "import socket,sys,time\n"
            "port=int(sys.argv[1]); time.sleep(0.05)\n"
            "server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            "server.bind(('127.0.0.1',port))\n"
            "data,peer=server.recvfrom(4096)\n"
            "server.sendto(b'PONG\\n' if data == b'PING\\n' else b'ERR\\n',peer)\n"
            "server.close()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script, str(port)],
                scenario_channel="udp",
                scenario_host="127.0.0.1",
                scenario_port=port,
                scenario_startup_timeout=2.0,
                scenario_step_timeout=1.0,
            ).normalized()
            action = _action("ping", b"PING\n", b"PONG\n")
            action.channel_kind = "udp network socket"
            action.source_api = "recvfrom"
            candidate = ScenarioCandidate(
                "udp-ping", "ping",
                [ScenarioStep(
                    0, "ping", "entry-udp", b"PING\n".hex(), {},
                    [b"PONG\n".hex()],
                )],
                ["entry-udp"], [], [],
            )

            witness = await _observed_verifier(project, [action]).verify(candidate)

        self.assertEqual(witness.status, ScenarioStatus.PROVEN_RUNTIME)
        self.assertEqual(bytes.fromhex(witness.observations[0].response_hex), b"PONG\n")

    async def test_runtime_feedback_can_promote_a_later_static_alternative(self) -> None:
        script = (
            "import sys\n"
            "for line in sys.stdin.buffer:\n"
            "  out = b'OK\\n' if line == b'GOOD\\n' else b'ERR\\n'\n"
            "  sys.stdout.buffer.write(out); sys.stdout.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
            ).normalized()
            action = _action("query", b"BAD\n", b"OK\n")
            action.failure_markers_hex = [b"ERR\n".hex()]
            action.examples = [
                ActionExample(b"BAD\n".hex(), {}),
                ActionExample(b"GOOD\n".hex(), {}),
            ]
            dependencies = StateDependencyGraph([
                ActionStateContract(
                    "query", [], [], [], "ok", action.evidence,
                    ["fn-query"], ProofStatus.PROVEN_STATIC,
                )
            ], [], [])
            candidates = ScenarioPlanner(
                max_steps=2, max_variants_per_action=2
            ).plan([action], dependencies)

            witnesses = await _observed_verifier(
                project, [action]
            ).verify_many(candidates)

        self.assertEqual(
            [item.status for item in witnesses],
            [ScenarioStatus.UNPROVEN, ScenarioStatus.PROVEN_RUNTIME],
        )

    async def test_only_original_execution_can_create_runtime_witness(self) -> None:
        script = (
            "import sys\n"
            "stored=False\n"
            "for line in sys.stdin.buffer:\n"
            "  if line.startswith(b'SET '): stored=True; out=b'STORED\\n'\n"
            "  elif line.startswith(b'GET '): out=b'VALUE\\n' if stored else b'MISS\\n'\n"
            "  else: out=b'ERROR\\n'\n"
            "  sys.stdout.buffer.write(out); sys.stdout.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            output = Path(temporary) / "runs"
            root.mkdir()
            project = ProjectSpec(
                source_root=root,
                output_root=output,
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
            ).normalized()
            actions = [_action("set", b"SET k\n", b"STORED\n"), _action("get", b"GET k\n", b"VALUE\n")]
            candidate = ScenarioCandidate(
                scenario_id="scenario-set-get",
                target_action_id="get",
                steps=[
                    ScenarioStep(0, "set", "entry-stdin", b"SET k\n".hex(), {"key": "6b"}, [b"STORED\n".hex()]),
                    ScenarioStep(1, "get", "entry-stdin", b"GET k\n".hex(), {"key": "6b"}, [b"VALUE\n".hex()]),
                ],
                required_entries=["entry-stdin"],
                satisfied_resources=["item"],
                planning_evidence=["set produces item consumed by get"],
            )

            witness = await _observed_verifier(project, actions).verify(candidate)

        self.assertEqual(witness.status, ScenarioStatus.PROVEN_RUNTIME)
        self.assertEqual([item.success for item in witness.observations], [True, True])

    async def test_matching_response_without_exact_handler_reach_is_unproven(self) -> None:
        script = (
            "import sys\n"
            "for line in sys.stdin.buffer:\n"
            "  sys.stdout.buffer.write(b'OK\\n'); sys.stdout.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
            ).normalized()
            action = _action("wanted", b"REQUEST\n", b"OK\n")
            candidate = ScenarioCandidate(
                "wrong-handler", "wanted",
                [ScenarioStep(
                    0, "wanted", "entry-stdin", b"REQUEST\n".hex(), {},
                    [b"OK\n".hex()],
                )],
                ["entry-stdin"], [], [],
            )
            witness = await ScenarioRuntimeVerifier(
                project,
                [action],
                target_observer=(
                    lambda _step, _action, _request, _response: False
                ),
            ).verify(candidate)

        self.assertEqual(witness.status, ScenarioStatus.UNPROVEN)
        self.assertTrue(witness.observations)
        self.assertFalse(witness.observations[0].target_reached)
        self.assertTrue(witness.observations[0].response_success)
        self.assertFalse(witness.observations[0].success)
        self.assertIn("exact acquisition-to-handler chain", witness.observations[0].detail)

    def test_target_trace_requires_entry_before_handler(self) -> None:
        entry = "__HARNESSCREATOR_TARGET__:entry"
        handler = "__HARNESSCREATOR_TARGET__:handler"

        self.assertEqual(
            _ordered_trace_hits(f"{entry}\n{handler}\n".encode(), entry, handler),
            (True, True),
        )
        self.assertEqual(
            _ordered_trace_hits(f"{handler}\n{entry}\n".encode(), entry, handler),
            (True, False),
        )
        self.assertEqual(_ordered_trace_hits(b"", entry, handler), (False, False))
        self.assertEqual(
            _ordered_trace_hits(f"{entry}\n".encode(), entry, entry),
            (True, True),
        )

    def test_gdb_probe_records_exact_ordered_source_sites(self) -> None:
        compiler = shutil.which("cc")
        if not compiler or not shutil.which("gdb"):
            self.skipTest("C compiler and GDB are required")
        source = (
            "static void handler(void) { }\n"
            "static void acquire(void) { handler(); }\n"
            "int main(void) { acquire(); return 0; }\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "target.c"
            source_path.write_text(source, encoding="utf-8")
            binary = root / "target"
            subprocess.run(
                [compiler, "-g", "-O0", str(source_path), "-o", str(binary)],
                check=True,
                capture_output=True,
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            acquire = next(
                function for function in graph.bundle.functions.values()
                if function.name == "acquire"
            )
            handler = next(
                function for function in graph.bundle.functions.values()
                if function.name == "handler"
            )
            dispatcher = next(
                function for function in graph.bundle.functions.values()
                if function.name == "main"
            )
            action = _action("ordered", b"", b"OK")
            action.entry_function_id = acquire.function_id
            action.handler_function_id = handler.function_id
            action.dispatcher_function_id = dispatcher.function_id
            action.entry_probe_evidence = [Evidence(
                "verified_entry_acquisition_site",
                acquire.function_id,
                acquire.file,
                acquire.start_line,
                "exact acquisition line",
            )]
            action.dispatch_probe_evidence = [Evidence(
                "source_dispatch_site",
                dispatcher.function_id,
                dispatcher.file,
                dispatcher.start_line,
                "the caller executes before acquisition",
            )]
            project = ProjectSpec(
                source_root=root,
                output_root=root / "runs",
                require_fuzz_introspector=False,
                svf_enabled=False,
                scenario_command=[str(binary)],
                scenario_channel="tcp",
                scenario_port=1,
            ).normalized()
            probe = _GdbTargetProbe(
                project,
                graph,
                [action],
                redirect_inferior_stdio=False,
            )
            try:
                completed = subprocess.run(
                    probe.launch_argv([str(binary)]),
                    capture_output=True,
                    timeout=10,
                )
                diagnostics = completed.stdout + completed.stderr
                if b"Operation not permitted" in diagnostics:
                    self.skipTest("ptrace is unavailable in this environment")
                self.assertEqual(
                    probe.ordered_chain_reached(action, 0),
                    (True, True),
                    msg=diagnostics.decode("utf-8", errors="replace"),
                )
            finally:
                probe.close()

    async def test_unattributed_ordered_trace_cannot_prove_request(self) -> None:
        class Probe:
            mechanism = "GDB"
            def ordered_chain_observation(self, action, offset):
                return True, True, ["entry", "handler"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = ProjectSpec(source_root=root, output_root=root / "runs",
                                  require_fuzz_introspector=False).normalized()
            action = _action("wanted", b"W\n", b"OK\n")
            verifier = ScenarioRuntimeVerifier(project, [action])
            step = ScenarioStep(0, "wanted", "entry", b"W\n".hex(), {}, [b"OK\n".hex()])
            entry, target, mechanism, trace = await verifier._target_reached(
                step, action, b"W\n", b"OK\n", Probe(), 0)
            self.assertTrue(entry)
            self.assertFalse(target)
            self.assertIn("request attribution unavailable", mechanism)
            self.assertEqual(trace, ["entry", "handler"])

    async def test_gdb_probe_distinguishes_two_handlers_with_the_same_response(self) -> None:
        compiler = shutil.which("cc")
        if not compiler or not shutil.which("gdb"):
            self.skipTest("C compiler and GDB are required")
        port = self._free_port(socket.SOCK_STREAM)
        source = (
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "#include <unistd.h>\n"
            "#include <arpa/inet.h>\n"
            "#include <sys/socket.h>\n"
            "static void wanted(int fd) { send(fd, \"OK\\n\", 3, 0); }\n"
            "static void decoy(int fd) { send(fd, \"OK\\n\", 3, 0); }\n"
            "static int acquire(int fd, char *b) { return recv(fd,b,16,0); }\n"
            "int main(int argc, char **argv) { int one=1; int s=socket(AF_INET,SOCK_STREAM,0); "
            "setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one)); struct sockaddr_in a={0}; "
            "a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons(atoi(argv[1])); "
            "if (bind(s,(struct sockaddr*)&a,sizeof(a)) || listen(s,1)) return 2; int c=accept(s,0,0); "
            "char b[16]={0}; acquire(c,b); if (b[0]=='W') wanted(c); else decoy(c); "
            "close(c); close(s); return argc < 2; }\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "target.c"
            source_path.write_text(source, encoding="utf-8")
            binary = root / "target"
            subprocess.run(
                [compiler, "-g", "-O0", str(source_path), "-o", str(binary)],
                check=True,
                capture_output=True,
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            wanted = next(
                function for function in graph.bundle.functions.values()
                if function.name == "wanted"
            )
            acquire = next(
                function for function in graph.bundle.functions.values()
                if function.name == "acquire"
            )
            action = _action("wanted", b"W\n", b"OK\n")
            action.handler_function_id = wanted.function_id
            action.entry_function_id = acquire.function_id
            action.entry_probe_evidence = [Evidence(
                "verified_entry_acquisition_site",
                acquire.function_id,
                acquire.file,
                acquire.start_line,
                "test acquisition probe",
            )]
            project = ProjectSpec(
                source_root=root,
                output_root=root / "runs",
                require_fuzz_introspector=False,
                svf_enabled=False,
                scenario_command=[str(binary), str(port)],
                scenario_channel="tcp",
                scenario_host="127.0.0.1",
                scenario_port=port,
                scenario_startup_timeout=3.0,
                scenario_step_timeout=3.0,
            ).normalized()
            action.channel_kind = "network socket"
            action.source_api = "recv"

            correct = await asyncio.wait_for(ScenarioRuntimeVerifier(
                project, [action], graph
            ).verify(ScenarioCandidate(
                "gdb-correct", "wanted",
                [ScenarioStep(
                    0, "wanted", "entry", b"W\n".hex(), {}, [b"OK\n".hex()],
                )],
                ["entry"], [], [],
            )), timeout=8.0)
            wrong_port = self._free_port(socket.SOCK_STREAM)
            wrong_project = replace(project, scenario_port=wrong_port,
                                    scenario_command=[str(binary), str(wrong_port)])
            wrong = await asyncio.wait_for(ScenarioRuntimeVerifier(
                wrong_project, [action], graph
            ).verify(ScenarioCandidate(
                "gdb-wrong", "wanted",
                [ScenarioStep(
                    0, "wanted", "entry", b"D\n".hex(), {}, [b"OK\n".hex()],
                )],
                ["entry"], [], [],
            )), timeout=8.0)

        # Ordered process-wide breakpoints alone do not identify which
        # request caused them. Strict mode rejects the unprovable probe
        # before launching the program, so there is no execution observation.
        self.assertEqual(correct.status, ScenarioStatus.UNPROVEN)
        self.assertEqual(correct.observations, [])
        self.assertIn("strict request attribution is unavailable from GDB", correct.rationale)
        self.assertEqual(wrong.status, ScenarioStatus.UNPROVEN, msg=f"{wrong.rationale}; observations={wrong.observations}")
        self.assertEqual(wrong.observations, [])

    async def test_crash_must_reproduce_in_original_program(self) -> None:
        diagnostic = (
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 0x1 in target_bug /src/target.c:42\n"
        )
        script = (
            "import os,sys\n"
            "for line in sys.stdin.buffer:\n"
            f"  if line.startswith(b'CRASH'): sys.stderr.write({diagnostic!r}); sys.stderr.flush(); os.abort()\n"
            "  sys.stdout.buffer.write(b'OK\\n'); sys.stdout.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
                scenario_exploratory_drafts=True,
            ).normalized()
            action = _action("request", b"OK\n", b"OK\n")
            verifier = _observed_verifier(project, [action])
            witness_candidate = ScenarioCandidate(
                "normal", "request",
                [ScenarioStep(0, "request", "entry-stdin", b"OK\n".hex(), {}, [b"OK\n".hex()])],
                ["entry-stdin"], [], [],
            )
            normal = await verifier.verify(witness_candidate)
            plan = build_harness_plan(
                normal,
                action_function_ids={"request": ("fn-entry", "fn-dispatch", "fn-request")},
                allow_observed=True,
            )
            replays = await OriginalCrashReproducer(verifier).reproduce(
                "harness-fixture",
                plan,
                [SeedSpec(
                    "crash",
                    b"CRASH\n".hex(),
                    "fixture",
                    crash_signature=extract_crash_signature(diagnostic),
                )],
            )

        self.assertEqual(normal.status, ScenarioStatus.OBSERVED_RUNTIME)
        self.assertEqual(replays[0].status, CrashReproductionStatus.ORIGINAL_REPRODUCED)
        self.assertFalse(replays[0].input_attributed)

    async def test_crash_replay_bypasses_the_normal_witness_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            launch_marker = Path(temporary) / "first-run-completed"
            script = (
                "import os,pathlib,sys\n"
                "marker=pathlib.Path(sys.argv[1])\n"
                "for line in sys.stdin.buffer:\n"
                "  if marker.exists(): sys.stderr.write('ERROR: AddressSanitizer: use-after-free\\n#0 0x1 in target_again /src/target.c:77\\n'); sys.stderr.flush(); os.abort()\n"
                "  marker.write_text('seen')\n"
                "  sys.stdout.buffer.write(b'OK\\n'); sys.stdout.buffer.flush()\n"
            )
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                scenario_command=[
                    sys.executable, "-u", "-c", script, str(launch_marker),
                ],
                scenario_channel="stdin",
            ).normalized()
            action = _action("request", b"OK\n", b"OK\n")
            verifier = _observed_verifier(project, [action])
            normal_candidate = ScenarioCandidate(
                "normal-cache", "request",
                [ScenarioStep(
                    0, "request", "entry-stdin", b"OK\n".hex(), {},
                    [b"OK\n".hex()],
                )],
                ["entry-stdin"], [], [],
            )
            normal = await verifier.verify(normal_candidate)
            plan = build_harness_plan(
                normal,
                action_function_ids={
                    "request": ("fn-entry", "fn-dispatch", "fn-request")
                },
                allow_unproven=True,
            )
            replay = (await OriginalCrashReproducer(verifier).reproduce(
                "harness-cache-bypass",
                plan,
                [SeedSpec(
                    "same-request",
                    b"OK\n".hex(),
                    "cache collision",
                    crash_signature=extract_crash_signature(
                        "ERROR: AddressSanitizer: use-after-free\n"
                        "#0 0x1 in target_again /src/target.c:77\n"
                    ),
                )],
            ))[0]

        self.assertEqual(normal.status, ScenarioStatus.UNPROVEN)
        self.assertEqual(
            replay.status, CrashReproductionStatus.ORIGINAL_REPRODUCED
        )

    async def test_waits_for_a_split_success_marker(self) -> None:
        script = (
            "import sys,time\n"
            "for line in sys.stdin.buffer:\n"
            "  sys.stdout.buffer.write(b'STO'); sys.stdout.buffer.flush()\n"
            "  time.sleep(0.02)\n"
            "  sys.stdout.buffer.write(b'RED\\n'); sys.stdout.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
            ).normalized()
            action = _action("set", b"SET k\n", b"STORED\n")
            candidate = ScenarioCandidate(
                "split", "set",
                [ScenarioStep(
                    0, "set", "entry-stdin", b"SET k\n".hex(), {},
                    [b"STORED\n".hex()],
                )],
                ["entry-stdin"], [], [],
            )

            witness = await _observed_verifier(project, [action]).verify(candidate)

        self.assertEqual(witness.status, ScenarioStatus.PROVEN_RUNTIME)
        self.assertEqual(
            bytes.fromhex(witness.observations[0].response_hex), b"STORED\n"
        )

    async def test_non_reproducing_harness_crash_is_an_artifact(self) -> None:
        script = (
            "import sys\n"
            "for line in sys.stdin.buffer:\n"
            "  sys.stdout.buffer.write(b'OK\\n'); sys.stdout.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
                scenario_command=[sys.executable, "-u", "-c", script],
                scenario_channel="stdin",
            ).normalized()
            action = _action("request", b"OK\n", b"OK\n")
            verifier = _observed_verifier(project, [action])
            normal = await verifier.verify(ScenarioCandidate(
                "normal-artifact", "request",
                [ScenarioStep(
                    0, "request", "entry-stdin", b"OK\n".hex(), {},
                    [b"OK\n".hex()],
                )],
                ["entry-stdin"], [], [],
            ))
            plan = build_harness_plan(
                normal,
                action_function_ids={
                    "request": ("fn-entry", "fn-dispatch", "fn-request")
                },
            )
            replay = (await OriginalCrashReproducer(verifier).reproduce(
                "harness-artifact",
                plan,
                [SeedSpec(
                    "bad",
                    b"BAD\n".hex(),
                    "harness-only crash",
                    crash_signature=extract_crash_signature(
                        "ERROR: AddressSanitizer: heap-use-after-free\n"
                        "#0 0x1 in target_bug /src/target.c:42\n"
                    ),
                )],
            ))[0]

        self.assertEqual(replay.status, CrashReproductionStatus.UNCONFIRMED)


class InputAndStateAgentTest(unittest.IsolatedAsyncioTestCase):
    async def test_inline_switch_operation_is_analyzed_at_the_dispatcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: p[1] ^= 1; return p[1];\n"
                "  }\n"
                "  return 0;\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[2]; read(fd,b,2); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            entry = EntryRecord(
                entry_id="entry-inline", candidate_id="candidate-inline",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[dispatch.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            action = {
                "name": "inline opcode one", "description": "inline state change",
                "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": dispatch.function_id,
                "discriminator": "1", "fields": [],
                "examples": [{
                    "data_hex": "0100",
                    "bindings": [{"name": "key", "value_hex": "6b"}],
                    "rationale": "complete two-byte request",
                }],
                "success_markers_hex": ["4f4b"],
                "failure_markers_hex": ["455252"],
                "success_evidence": [{
                    "kind": "source", "function_id": dispatch.function_id,
                    "line": dispatch.start_line + 2,
                    "detail": "inline case returns the mutated value",
                }],
                "failure_evidence": [],
                "evidence": [{
                    "kind": "source", "function_id": dispatch.function_id,
                    "line": dispatch.start_line + 2,
                    "detail": "case one performs the inline operation",
                }],
                "unknowns": [], "confidence": 0.95,
            }
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [action], "context_complete": True,
                    "requested_function_ids": [], "rationale": "inline action",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source",
                        "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "request byte selects the inline operation",
                    }],
                },
                {
                    # Inline cases still use the isolated branch session: the
                    # dispatcher is also the selected handler here.
                    "actions": [action], "context_complete": True,
                    "requested_function_ids": [],
                    "rationale": "validated inline branch",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source",
                        "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "request byte selects the inline operation",
                    }],
                },
            ])
            agent = InputActionAgent(llm, graph, budget=4)

            actions = await agent.run([entry])

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].handler_function_id, dispatch.function_id)
        self.assertEqual(actions[0].status, ProofStatus.PROVEN_STATIC)
        self.assertEqual(actions[0].examples[0].bindings, {"key": "6b"})
        self.assertFalse(agent.inventory_obligations)
        self.assertEqual(len(llm.calls), 3)

    async def test_invalid_schema_failure_aborts_branch_queue(self) -> None:
        class InvalidSchemaLLM:
            max_concurrency = 1

            def __init__(self) -> None:
                self.calls = 0

            async def complete_json(self, **kwargs):
                self.calls += 1
                raise InvalidOutputSchemaError("invalid_json_schema fixture")

            async def close_session(self, session_key):
                return None

            async def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int op_a(unsigned char *p) { return p[1]; }\n"
                "int op_b(unsigned char *p) { return p[2]; }\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return op_a(p);\n"
                "    case 2: return op_b(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[4]; read(fd,b,4); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="entry-fail-fast", candidate_id="candidate-fail-fast",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[by_name["dispatch"].function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            llm = InvalidSchemaLLM()
            agent = InputActionAgent(llm, graph, budget=4)

            with self.assertRaises(InvalidOutputSchemaError):
                await agent.run([entry])

        self.assertEqual(llm.calls, 1)
        self.assertEqual(len(agent.infrastructure_failures), 1)

    async def test_usage_limit_failure_aborts_branch_queue(self) -> None:
        class UsageLimitedLLM:
            max_concurrency = 1

            def __init__(self) -> None:
                self.calls = 0

            async def complete_json(self, **kwargs):
                self.calls += 1
                raise CodexAppServerError(
                    "You've hit your usage limit. Purchase more credits."
                )

            async def close_session(self, session_key):
                return None

            async def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int op_a(unsigned char *p) { return p[1]; }\n"
                "int op_b(unsigned char *p) { return p[2]; }\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return op_a(p);\n"
                "    case 2: return op_b(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[4]; read(fd,b,4); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="entry-usage-limit", candidate_id="candidate-usage-limit",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            llm = UsageLimitedLLM()
            agent = InputActionAgent(llm, graph, budget=4)

            with self.assertRaisesRegex(CodexAppServerError, "usage limit"):
                await agent.run([entry])

        self.assertEqual(llm.calls, 1)
        self.assertEqual(len(agent.infrastructure_failures), 1)

    async def test_reconnect_failure_does_not_expand_unclassified_branches(self) -> None:
        class ReconnectingLLM:
            max_concurrency = 1

            def __init__(self) -> None:
                self.calls = 0

            async def complete_json(self, **kwargs):
                self.calls += 1
                raise CodexAppServerError("Reconnecting... 2/5")

            async def close_session(self, session_key):
                return None

            async def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int op_a(unsigned char *p) { return p[1]; }\n"
                "int op_b(unsigned char *p) { return p[2]; }\n"
                "int op_c(unsigned char *p) { return p[3]; }\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return op_a(p);\n"
                "    case 2: return op_b(p);\n"
                "    case 3: return op_c(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[4]; read(fd,b,4); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="entry-reconnect", candidate_id="candidate-reconnect",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            llm = ReconnectingLLM()
            agent = InputActionAgent(
                llm, graph, budget=4, max_branch_validations=8,
            )

            actions = await agent.run([entry])

        self.assertEqual(actions, [])
        self.assertEqual(llm.calls, 1)
        self.assertEqual(len(agent.infrastructure_failures), 1)
        self.assertEqual(agent.planned_branch_validations, 0)
        self.assertTrue(any(
            "action reconstruction produced no" in item
            for item in agent.inventory_obligations
        ))

    async def test_repeated_reconnect_failures_stop_direct_entry_fanout(self) -> None:
        class ReconnectingLLM:
            max_concurrency = 1

            def __init__(self) -> None:
                self.calls = 0

            async def complete_json(self, **kwargs):
                self.calls += 1
                raise CodexAppServerError("Reconnecting... 2/5")

            async def close_session(self, session_key):
                return None

            async def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int receive_one(int fd) { unsigned char b; return read(fd,&b,1); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            receive = next(iter(graph.bundle.functions.values()))
            entries = [
                EntryRecord(
                    entry_id=f"entry-direct-{index}",
                    candidate_id=f"candidate-direct-{index}",
                    status=Verdict.VERIFIED,
                    entry_function_id=receive.function_id,
                    source_api="read", channel_kind="stdin",
                    attacker_control="full", provenance_path=[],
                    consumer_hints=[],
                    evidence=[Evidence(
                        "source", receive.function_id, receive.file,
                        receive.start_line, "read acquires a request byte",
                    )],
                    unknowns=[], verifier_confidence=0.99,
                    first_acquisition_confirmed=True,
                    site_kind=EntrySiteKind.DIRECT_ACQUISITION,
                )
                for index in range(3)
            ]
            llm = ReconnectingLLM()
            agent = InputActionAgent(llm, graph, budget=4)

            actions = await agent.run(entries)

        self.assertEqual(actions, [])
        self.assertEqual(llm.calls, 2)
        self.assertEqual(len(agent.infrastructure_failures), 2)
        self.assertTrue(any(
            "remaining direct Entry analyses" in item
            for item in agent.inventory_obligations
        ))

    async def test_repeated_reconnect_failures_stop_state_action_fanout(self) -> None:
        class ReconnectingLLM:
            max_concurrency = 1

            def __init__(self) -> None:
                self.calls = 0

            async def complete_json(self, **kwargs):
                self.calls += 1
                raise CodexAppServerError("Reconnecting... 2/5")

            async def close_session(self, session_key):
                return None

            async def close(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int operation(const unsigned char *p) { return p[0]; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            operation = next(iter(graph.bundle.functions.values()))
            evidence = Evidence(
                "source", operation.function_id, operation.file,
                operation.start_line, "operation consumes a request byte",
            )
            actions = [
                ExternalActionSchema(
                    action_id=f"action-{index}", entry_id=f"entry-{index}",
                    name=f"action {index}", description="operation",
                    dispatcher_function_id=operation.function_id,
                    handler_function_id=operation.function_id,
                    discriminator=str(index), channel_kind="stdin",
                    fields=[], examples=[ActionExample("00", {})],
                    success_markers_hex=["4f4b"],
                    failure_markers_hex=[], evidence=[evidence],
                    inspected_function_ids=[operation.function_id],
                    status=ProofStatus.PROVEN_STATIC, confidence=0.99,
                    source_api="read", success_evidence=[evidence],
                )
                for index in range(3)
            ]
            llm = ReconnectingLLM()
            agent = StateDependencyAgent(
                llm, graph, UsageEvidenceBundle(), budget=4,
            )

            dependencies = await agent.run(actions)

        self.assertEqual(llm.calls, 2)
        self.assertEqual(len(agent.infrastructure_failures), 2)
        self.assertEqual(len(dependencies.contracts), 2)
        self.assertTrue(any(
            "remaining state-dependency analyses" in item
            for item in dependencies.open_obligations
        ))

    async def test_abnormal_branch_plan_stops_before_branch_llm_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int op_a(unsigned char *p) { return p[1]; }\n"
                "int op_b(unsigned char *p) { return p[2]; }\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return op_a(p);\n"
                "    case 2: return op_b(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[4]; read(fd,b,4); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="entry-overflow", candidate_id="candidate-overflow",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[],
                consumer_hints=[by_name["dispatch"].function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            dispatch = by_name["dispatch"]
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "request dispatcher",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "external request byte selects an operation",
                    }],
                },
            ])
            agent = InputActionAgent(
                llm, graph, budget=4, max_branch_validations=1
            )

            actions = await agent.run([entry])

        self.assertFalse(actions)
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(
            {call["session_key"] for call in llm.calls},
            {"input_action:entry-overflow"},
        )
        self.assertGreater(agent.planned_branch_validations, 1)
        self.assertTrue(any(
            "exceeding the configured safety limit" in item
            for item in agent.inventory_obligations
        ))

    async def test_abnormal_entry_plan_does_not_discard_other_entries(self) -> None:
        bad = FunctionMetadata.create(
            name="bad_reader", signature="int bad_reader(void)",
            file="bad.c", start_line=1, end_line=1,
            source="int bad_reader(void) { return 0; }",
        )
        good = FunctionMetadata.create(
            name="good_reader", signature="int good_reader(void)",
            file="good.c", start_line=1, end_line=1,
            source="int good_reader(void) { return 0; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={bad.function_id: bad, good.function_id: good},
            edges=[],
        ))

        def entry(identifier: str, function: FunctionMetadata) -> EntryRecord:
            return EntryRecord(
                entry_id=identifier, candidate_id=f"candidate-{identifier}",
                status=Verdict.VERIFIED,
                entry_function_id=function.function_id, source_api="read",
                channel_kind="network tcp socket", attacker_control="full",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence(
                    "source", function.function_id, function.file,
                    function.start_line, "fixture acquisition",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )

        class InventoryAgent(InputActionAgent):
            def _inventory_entry(self, current, *, function_limit=4096):
                count = 2 if current.entry_id == "entry-bad" else 1
                return ([
                    OperationSeed(
                        operation_seed_id=f"seed-{current.entry_id}-{index}",
                        dispatcher_function_id=current.entry_function_id,
                        discriminator=str(index), line=1,
                        handler_function_ids=[current.entry_function_id],
                    )
                    for index in range(count)
                ], False)

            async def _run_entry(self, current):
                # This fixture stands in for the focused Entry walk having
                # already confirmed these source branches as request actions.
                seeds, _truncated = self._inventory_entry(current)
                return [], seeds

        llm = ScriptedLLM([{
            "actions": [], "branch_disposition": "NOT_ACTION",
            "branch_disposition_evidence": [], "context_complete": True,
            "requested_function_ids": [], "rationale": "fixture branch",
        }])
        agent = InventoryAgent(
            llm, graph, budget=1, max_branch_validations=1
        )

        await agent.run([
            entry("entry-bad", bad), entry("entry-good", good),
        ])

        self.assertEqual(len(llm.calls), 1)
        self.assertIn("entry-good", llm.calls[0]["session_key"])
        self.assertTrue(any(
            item.startswith("entry-bad:")
            and "only this Entry was skipped" in item
            for item in agent.inventory_obligations
        ))

    async def test_lifecycle_switch_stays_audit_only_after_not_action_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int lifecycle(int phase, unsigned char *p) {\n"
                "  switch (phase) {\n"
                "    case 0: return p[0];\n"
                "    case 1: return -1;\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b; read(fd,&b,1); return lifecycle(0,&b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            lifecycle = by_name["lifecycle"]
            entry = EntryRecord(
                entry_id="entry-lifecycle", candidate_id="candidate-lifecycle",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[lifecycle.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires one external byte",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open consumer",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [],
                    "rationale": "phase is internal lifecycle state",
                    "branch_disposition": "NOT_ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": lifecycle.function_id,
                        "line": lifecycle.start_line + 1,
                        "detail": "switch selects an internal lifecycle phase",
                    }],
                },
            ])
            agent = InputActionAgent(llm, graph, budget=4)

            actions = await agent.run([entry])

        self.assertFalse(actions)
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(agent.planned_branch_validations, 0)
        self.assertTrue(agent.operation_seeds)
        self.assertTrue(all(
            seed.status is ProofStatus.REFUTED
            for seed in agent.operation_seeds
        ))
        self.assertTrue(any(
            "action reconstruction produced no" in item
            for item in agent.inventory_obligations
        ))

    async def test_unresolved_dispatcher_cannot_be_promoted_by_action_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return p[1];\n"
                "  }\n"
                "  return 0;\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[2]; read(fd,b,2); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            entry = EntryRecord(
                entry_id="entry-unresolved-dispatcher",
                candidate_id="candidate-unresolved-dispatcher",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[dispatch.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the external request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            claimed_action = {
                "name": "opcode one", "description": "claimed operation",
                "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": dispatch.function_id,
                "discriminator": "1", "fields": [],
                "examples": [{
                    "data_hex": "0100", "bindings": [],
                    "rationale": "complete request",
                }],
                "success_markers_hex": ["4f4b"],
                "failure_markers_hex": [],
                "success_evidence": [{
                    "kind": "source", "function_id": dispatch.function_id,
                    "line": dispatch.start_line + 2,
                    "detail": "case one returns the selected value",
                }],
                "failure_evidence": [], "response_bindings": [],
                "evidence": [{
                    "kind": "source", "function_id": dispatch.function_id,
                    "line": dispatch.start_line + 2,
                    "detail": "case one is present in source",
                }],
                "unknowns": [], "confidence": 0.99,
            }
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [claimed_action], "context_complete": True,
                    "requested_function_ids": [],
                    "rationale": "action claim without dispatcher classification",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
            ])
            agent = InputActionAgent(llm, graph, budget=4)

            actions = await agent.run([entry])

        self.assertFalse(actions)
        self.assertEqual(agent.planned_branch_validations, 0)
        self.assertEqual(len(llm.calls), 2)

    async def test_action_dispatcher_payload_cannot_skip_isolated_branch_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return p[1];\n"
                "  }\n"
                "  return 0;\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[2]; read(fd,b,2); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            entry = EntryRecord(
                entry_id="entry-isolated-dispatcher",
                candidate_id="candidate-isolated-dispatcher",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[dispatch.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the external request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            action = {
                "name": "opcode one", "description": "selected operation",
                "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": dispatch.function_id,
                "discriminator": "1", "fields": [],
                "examples": [{
                    "data_hex": "0100", "bindings": [],
                    "rationale": "complete request",
                }],
                "success_markers_hex": ["4f4b"],
                "failure_markers_hex": [],
                "success_evidence": [{
                    "kind": "source", "function_id": dispatch.function_id,
                    "line": dispatch.start_line + 2,
                    "detail": "case one is the successful operation",
                }],
                "failure_evidence": [], "response_bindings": [],
                "evidence": [{
                    "kind": "source", "function_id": dispatch.function_id,
                    "line": dispatch.start_line + 2,
                    "detail": "case one consumes the request",
                }],
                "unknowns": [], "confidence": 0.99,
            }
            disposition = [{
                "kind": "source", "function_id": dispatch.function_id,
                "line": dispatch.start_line + 1,
                "detail": "the external request byte selects an operation",
            }]
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    # Supplying the completed action here must not cover the
                    # seed before its isolated branch session runs.
                    "actions": [action], "context_complete": True,
                    "requested_function_ids": [], "rationale": "dispatcher",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": disposition,
                },
                {
                    "actions": [action], "context_complete": True,
                    "requested_function_ids": [], "rationale": "isolated branch",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": disposition,
                },
            ])
            agent = InputActionAgent(llm, graph, budget=4)

            actions = await agent.run([entry])

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].status, ProofStatus.PROVEN_STATIC)
        self.assertEqual(agent.planned_branch_validations, 1)
        self.assertEqual(len(llm.calls), 3)
        self.assertNotEqual(
            llm.calls[-1]["session_key"],
            "input_action:entry-isolated-dispatcher",
        )

    async def test_entry_walk_stops_after_first_evidenced_request_dispatcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int operation(unsigned char *p) { return p[1]; }\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return operation(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int housekeeping(void) { return 0; }\n"
                "int receive_one(int fd) { unsigned char b[2]; read(fd,b,2); return dispatch(b) + housekeeping(); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            housekeeping = by_name["housekeeping"]
            entry = EntryRecord(
                entry_id="entry-stop-at-dispatcher",
                candidate_id="candidate-stop-at-dispatcher",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[],
                consumer_hints=[dispatch.function_id, housekeeping.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the external request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "request dispatcher",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "request opcode selects an operation",
                    }],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "branch classified",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 2,
                        "detail": "fixture ends branch validation",
                    }],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "handler classified",
                    "branch_disposition": "NOT_ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source",
                        "function_id": by_name["operation"].function_id,
                        "line": by_name["operation"].start_line,
                        "detail": "handler has no nested dispatcher",
                    }],
                },
            ])
            agent = InputActionAgent(llm, graph, budget=6)

            await agent.run([entry])

        direct_calls = [
            call for call in llm.calls
            if call["session_key"] == "input_action:entry-stop-at-dispatcher"
        ]
        self.assertEqual(len(direct_calls), 2)
        self.assertNotIn(
            housekeeping.function_id,
            {
                call["payload"]["current_function"]["function_id"]
                for call in direct_calls
            },
        )

    async def test_unconfirmed_nested_lifecycle_switch_is_not_scheduled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int server_phase;\n"
                "int operation(unsigned char *p) {\n"
                "  switch (server_phase) {\n"
                "    case 0: return p[1];\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return operation(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[2]; read(fd,b,2); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            operation = by_name["operation"]
            entry = EntryRecord(
                entry_id="entry-nested-lifecycle",
                candidate_id="candidate-nested-lifecycle",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[dispatch.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the external request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            action = {
                "name": "opcode one", "description": "selected operation",
                "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": operation.function_id,
                "discriminator": "1", "fields": [],
                "examples": [{
                    "data_hex": "0100", "bindings": [],
                    "rationale": "complete two-byte request",
                    "origin": "product_source", "evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 2,
                        "detail": "case one consumes the request",
                    }],
                }],
                "success_markers_hex": ["4f4b"],
                "failure_markers_hex": [],
                "success_evidence": [{
                    "kind": "source", "function_id": operation.function_id,
                    "line": operation.start_line + 2,
                    "detail": "selected operation returns its result",
                }],
                "failure_evidence": [], "response_bindings": [],
                "evidence": [
                    {
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 2,
                        "detail": "opcode one invokes operation",
                    },
                    {
                        "kind": "source", "function_id": operation.function_id,
                        "line": operation.start_line + 2,
                        "detail": "operation consumes the payload",
                    },
                ],
                "unknowns": [], "confidence": 0.99,
            }
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "request dispatcher",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "request opcode selects an operation",
                    }],
                },
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "selected branch",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 2,
                        "detail": "case one selects operation",
                    }],
                },
                {
                    "actions": [action], "context_complete": True,
                    "requested_function_ids": [],
                    "rationale": "server phase is not a request operation selector",
                    "branch_disposition": "NOT_ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": operation.function_id,
                        "line": operation.start_line + 1,
                        "detail": "switch selects internal server phase",
                    }],
                },
            ])
            agent = InputActionAgent(llm, graph, budget=6)

            actions = await agent.run([entry])

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].status, ProofStatus.PROVEN_STATIC)
        self.assertEqual(agent.planned_branch_validations, 1)
        self.assertFalse(any(
            seed.dispatcher_function_id == operation.function_id
            for seed in agent.operation_seeds
        ))

    async def test_confirmed_nested_dispatcher_seed_is_scheduled_once(self) -> None:
        reader = FunctionMetadata.create(
            name="reader", signature="int reader(void)",
            file="target.c", start_line=1, end_line=1,
            source="int reader(void) { return 0; }",
        )
        dispatcher = FunctionMetadata.create(
            name="dispatcher", signature="int dispatcher(void)",
            file="target.c", start_line=2, end_line=2,
            source="int dispatcher(void) { return 0; }",
        )
        nested_handler = FunctionMetadata.create(
            name="nested_handler", signature="int nested_handler(void)",
            file="target.c", start_line=3, end_line=3,
            source="int nested_handler(void) { return 0; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={
                item.function_id: item
                for item in (reader, dispatcher, nested_handler)
            },
            edges=[],
        ))
        entry = EntryRecord(
            entry_id="entry-nested", candidate_id="candidate-nested",
            status=Verdict.VERIFIED,
            entry_function_id=reader.function_id, source_api="read",
            channel_kind="network tcp socket", attacker_control="full",
            provenance_path=[], consumer_hints=[dispatcher.function_id],
            evidence=[Evidence(
                "source", reader.function_id, reader.file,
                reader.start_line, "read acquires the request",
            )],
            unknowns=[], verifier_confidence=0.99,
            first_acquisition_confirmed=True,
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
        )
        root_seed = OperationSeed(
            operation_seed_id="seed-root",
            dispatcher_function_id=dispatcher.function_id,
            discriminator="ROOT", line=2,
            handler_function_ids=[dispatcher.function_id],
        )
        nested_seed = OperationSeed(
            operation_seed_id="seed-nested",
            dispatcher_function_id=dispatcher.function_id,
            discriminator="INTERNAL", line=3,
            handler_function_ids=[nested_handler.function_id],
        )

        class NestedSeedAgent(InputActionAgent):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.branch_calls = 0

            def _inventory_entry(self, current, *, function_limit=4096):
                return [root_seed], False

            async def _run_entry(self, current):
                return [], [root_seed]

            async def _run_seed_branch(self, item):
                self.branch_calls += 1
                return [], [nested_seed], ProofStatus.POSSIBLE, "fixture"

        agent = NestedSeedAgent(
            ScriptedLLM([]), graph, budget=1, max_branch_validations=8,
        )

        await agent.run([entry])

        self.assertEqual(agent.planned_branch_validations, 2)
        self.assertEqual(agent.branch_calls, 2)
        self.assertIn(
            nested_seed.operation_seed_id,
            {item.operation_seed_id for item in agent.operation_seeds},
        )

    async def test_branch_frontier_only_exposes_selected_handler_callees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int response_helper(int v) { return v + 1; }\n"
                "int selected_handler(int v) { return response_helper(v); }\n"
                "int sibling_handler(int v) { return v - 1; }\n"
                "int dispatch(int op) {\n"
                "  switch (op) {\n"
                "    case 1: return selected_handler(op);\n"
                "    default: return sibling_handler(op);\n"
                "  }\n"
                "}\n"
                "int event_loop(int op) { return dispatch(op); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {
                item.name: item for item in graph.bundle.functions.values()
            }
            agent = InputActionAgent(ScriptedLLM([]), graph, budget=4)

            choices = agent._branch_choices(
                [
                    by_name["dispatch"].function_id,
                    by_name["selected_handler"].function_id,
                ],
                dispatcher_function_id=by_name["dispatch"].function_id,
                handler_function_id=by_name["selected_handler"].function_id,
            )

        choice_names = {str(item["name"]) for item in choices}
        self.assertEqual(choice_names, {"response_helper"})
        self.assertNotIn("event_loop", choice_names)
        self.assertNotIn("sibling_handler", choice_names)

    async def test_branch_frontier_admits_only_proven_response_return_caller(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int response_helper(int v) { return v + 1; }\n"
                "int selected_handler(int v) { return response_helper(v); }\n"
                "int dispatch(int op) { return selected_handler(op); }\n"
                "int proven_entry_path(int op) { return dispatch(op); }\n"
                "int unrelated_lifecycle(int op) { return dispatch(op); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {
                item.name: item for item in graph.bundle.functions.values()
            }
            agent = InputActionAgent(ScriptedLLM([]), graph, budget=4)

            choices = agent._branch_choices(
                [
                    by_name["dispatch"].function_id,
                    by_name["selected_handler"].function_id,
                ],
                dispatcher_function_id=by_name["dispatch"].function_id,
                handler_function_id=by_name["selected_handler"].function_id,
                return_path_function_ids=[
                    by_name["proven_entry_path"].function_id,
                ],
            )

        choice_names = {str(item["name"]) for item in choices}
        self.assertEqual(
            choice_names,
            {"response_helper", "proven_entry_path"},
        )
        self.assertNotIn("unrelated_lifecycle", choice_names)

    async def test_selected_late_dispatch_branch_is_visible_in_bounded_source(self) -> None:
        start_line = 100
        lines = ["int dispatch(unsigned char *p) {"]
        lines.extend(
            f"  /* filler line {index:04d} padding padding padding */"
            for index in range(3000)
        )
        lines.extend([
            "  /* SELECTED_LATE_BRANCH */",
            "  return p[0];",
            "}",
        ])
        selected_line = start_line + 3001
        dispatcher = FunctionMetadata.create(
            name="dispatch", signature="int dispatch(unsigned char *p)",
            file="large.c", start_line=start_line,
            end_line=start_line + len(lines) - 1,
            source="\n".join(lines),
        )
        graph = GraphStore(AnalysisBundle(
            functions={dispatcher.function_id: dispatcher}, edges=[]
        ))
        entry = EntryRecord(
            entry_id="entry-large", candidate_id="candidate-large",
            status=Verdict.VERIFIED,
            entry_function_id=dispatcher.function_id, source_api="read",
            channel_kind="stdin", attacker_control="full",
            provenance_path=[], consumer_hints=[dispatcher.function_id],
            evidence=[Evidence(
                "source", dispatcher.function_id, dispatcher.file,
                dispatcher.start_line, "fixture acquisition",
            )],
            unknowns=[], verifier_confidence=0.99,
            first_acquisition_confirmed=True,
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
        )
        seed = OperationSeed(
            operation_seed_id="seed-late",
            dispatcher_function_id=dispatcher.function_id,
            discriminator="late", line=selected_line,
            handler_function_ids=[dispatcher.function_id],
            entry_path_function_ids=[dispatcher.function_id],
        )
        llm = ScriptedLLM([{
            "actions": [], "branch_disposition": "NOT_ACTION",
            "branch_disposition_evidence": [], "context_complete": True,
            "requested_function_ids": [], "rationale": "fixture",
        }])
        agent = InputActionAgent(llm, graph, budget=1)

        await agent._run_seed_branch((entry, seed, dispatcher.function_id))

        current = llm.calls[0]["payload"]["current_function"]
        self.assertFalse(current["source_truncated"])
        self.assertIn("SELECTED_LATE_BRANCH", current["source"])
        self.assertLessEqual(current["source_excerpt_start_line"], selected_line)
        self.assertGreaterEqual(current["source_excerpt_end_line"], selected_line)

    async def test_action_progress_is_checkpointed_before_and_after_llm_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int receive_one(int fd) { char b; return read(fd, &b, 1); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            receive = next(iter(graph.bundle.functions.values()))
            entry = EntryRecord(
                entry_id="entry-checkpoint", candidate_id="candidate-checkpoint",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires one byte",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            checkpoints = []
            llm = ScriptedLLM([{
                "actions": [], "branch_disposition": "NOT_ACTION",
                "branch_disposition_evidence": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "no dispatcher",
            }])
            agent = InputActionAgent(
                llm, graph, budget=2,
                checkpoint=lambda payload: checkpoints.append(payload),
            )

            await agent.run([entry])

        phases = [item["phase"] for item in checkpoints]
        self.assertEqual(phases[0], "inventory_complete")
        self.assertIn("direct_entries_complete", phases)
        self.assertEqual(phases[-1], "complete")
        self.assertEqual(checkpoints[-1]["remaining_branch_validations"], 0)

    async def test_dispatcher_found_during_callback_walk_becomes_inventory_work(self) -> None:
        reader = FunctionMetadata.create(
            name="tcp_read", signature="int tcp_read(int fd, unsigned char *p)",
            file="target.c", start_line=1, end_line=1,
            source="int tcp_read(int fd, unsigned char *p) { return read(fd,p,1); }",
        )
        registration = FunctionMetadata.create(
            name="setup", signature="void setup(struct conn *c)",
            file="target.c", start_line=3, end_line=3,
            source="void setup(struct conn *c) { c->read = tcp_read; }",
        )
        pump = FunctionMetadata.create(
            name="pump", signature="int pump(struct conn *c)",
            file="target.c", start_line=5, end_line=5,
            source="int pump(struct conn *c) { return c->read(c->fd, c->buf); }",
        )
        operation = FunctionMetadata.create(
            name="operation", signature="int operation(unsigned char *p)",
            file="target.c", start_line=7, end_line=7,
            source="int operation(unsigned char *p) { return p[1]; }",
        )
        dispatcher = FunctionMetadata.create(
            name="dispatch", signature="int dispatch(unsigned char *p)",
            file="target.c", start_line=9, end_line=14,
            source=(
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return operation(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}"
            ),
        )
        loop = FunctionMetadata.create(
            name="loop", signature="int loop(struct conn *c)",
            file="target.c", start_line=16, end_line=16,
            source="int loop(struct conn *c) { pump(c); return dispatch(c->buf); }",
        )
        functions = {
            item.function_id: item
            for item in (reader, registration, pump, operation, dispatcher, loop)
        }
        bundle = AnalysisBundle(functions=functions, edges=[
            CallEdge(
                edge_id="registration", caller_id=registration.function_id,
                callee_id=reader.function_id, line=registration.start_line,
                kind="function_reference",
            ),
            CallEdge(
                edge_id="callback", caller_id=pump.function_id,
                callee_id=reader.function_id, line=None,
                kind="indirect_possible",
            ),
            CallEdge(
                edge_id="loop-pump", caller_id=loop.function_id,
                callee_id=pump.function_id, line=loop.start_line, kind="direct",
            ),
            CallEdge(
                edge_id="loop-dispatch", caller_id=loop.function_id,
                callee_id=dispatcher.function_id, line=loop.start_line, kind="direct",
            ),
            CallEdge(
                edge_id="dispatch-operation", caller_id=dispatcher.function_id,
                callee_id=operation.function_id, line=dispatcher.start_line + 2,
                kind="direct",
            ),
        ])
        entry = EntryRecord(
            entry_id="entry-callback-inventory",
            candidate_id="candidate-callback-inventory",
            status=Verdict.VERIFIED,
            entry_function_id=reader.function_id,
            source_api="read", channel_kind="network tcp socket",
            attacker_control="full", provenance_path=[], consumer_hints=[],
            evidence=[Evidence(
                "source", reader.function_id, reader.file,
                reader.start_line, "read acquires bytes",
            )],
            unknowns=[], verifier_confidence=0.99,
            first_acquisition_confirmed=True,
            inspected_function_ids=[
                reader.function_id, registration.function_id, pump.function_id,
            ],
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
        )
        ordinary = {
            "actions": [], "context_complete": False,
            "requested_function_ids": [], "rationale": "continue",
            "branch_disposition": "UNRESOLVED",
            "branch_disposition_evidence": [],
        }
        llm = ScriptedLLM([
            ordinary,
            ordinary,
            {**ordinary, "requested_function_ids": [loop.function_id]},
            {**ordinary, "requested_function_ids": [dispatcher.function_id]},
            {
                "actions": [], "context_complete": False,
                # Once this dispatcher is proven, handler interpretation is
                # owned by the focused branch worker and must not be repeated
                # in the Entry-wide session.
                "requested_function_ids": [operation.function_id],
                "rationale": "request dispatcher then handler",
                "branch_disposition": "ACTION",
                "branch_disposition_evidence": [{
                    "kind": "source", "function_id": dispatcher.function_id,
                    "line": dispatcher.start_line + 1,
                    "detail": "input byte selects the request operation",
                }],
            },
        ])
        agent = InputActionAgent(llm, GraphStore(bundle), budget=8)

        actions, discovered = await agent._run_entry(entry)

        self.assertFalse(actions)
        self.assertEqual(len(llm.calls), 5)
        self.assertEqual(len(discovered), 2)
        selected = next(item for item in discovered if item.discriminator == "1")
        self.assertEqual(selected.dispatcher_function_id, dispatcher.function_id)
        self.assertEqual(
            selected.entry_path_function_ids,
            [
                reader.function_id,
                registration.function_id,
                pump.function_id,
                loop.function_id,
                dispatcher.function_id,
            ],
        )

    async def test_scheduled_branch_cannot_disappear_without_an_obligation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int operation(unsigned char *p) { return p[1]; }\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return operation(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[2]; read(fd,b,2); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            entry = EntryRecord(
                entry_id="entry-silent-branch", candidate_id="candidate-silent-branch",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[dispatch.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "entry",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "dispatcher",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "request byte selects the operation",
                    }],
                },
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "selected branch",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "selected dispatcher branch",
                    }],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "no action emitted",
                    "branch_disposition": "NOT_ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source",
                        "function_id": by_name["operation"].function_id,
                        "line": by_name["operation"].start_line,
                        "detail": "handler has no nested operation dispatcher",
                    }],
                },
            ])
            agent = InputActionAgent(llm, graph, budget=6)

            actions = await agent.run([entry])

        self.assertFalse(actions)
        self.assertTrue(any(
            "semantic branch validation produced no statically proven" in item
            for item in agent.inventory_obligations
        ))

    async def test_unproven_state_contract_cannot_leak_an_initial_resource(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int query(const unsigned char *p) { return p[0] == 'Q'; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            query = next(iter(graph.bundle.functions.values()))
            evidence = Evidence(
                "source", query.function_id, query.file,
                query.start_line, "query guard",
            )
            action = ExternalActionSchema(
                action_id="query", entry_id="entry", name="query",
                description="query", dispatcher_function_id=query.function_id,
                handler_function_id=query.function_id, discriminator="Q",
                channel_kind="stdin", fields=[],
                examples=[ActionExample("51", {})],
                success_markers_hex=["4f4b"], failure_markers_hex=[],
                evidence=[evidence], inspected_function_ids=[query.function_id],
                status=ProofStatus.PROVEN_STATIC, confidence=0.99,
                source_api="read", success_evidence=[evidence],
            )
            requirement = {
                "resource": "configured", "binding": "",
                "predicate": "enabled",
                "evidence": [{
                    "kind": "source", "function_id": query.function_id,
                    "line": query.start_line, "detail": "configuration guard",
                }],
            }
            llm = ScriptedLLM([{
                "consumes": [requirement], "produces": [], "invalidates": [],
                "initial_resources": [requirement],
                "success_condition": "query returns one",
                "evidence": [{
                    "kind": "source", "function_id": query.function_id,
                    "line": query.start_line, "detail": "query return",
                }],
                "unknowns": ["startup configuration provenance is unresolved"],
                "context_complete": True, "requested_function_ids": [],
                "rationale": "the guard exists but startup provenance is unknown",
            }])

            dependency_graph = await StateDependencyAgent(
                llm, graph, UsageEvidenceBundle(), budget=2
            ).run([action])

        self.assertEqual(
            dependency_graph.contracts[0].status, ProofStatus.POSSIBLE
        )
        self.assertFalse(dependency_graph.initial_resources)

    async def test_state_dependency_retains_source_proven_facts_across_turns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int item_exists(const unsigned char *p) { return p[0] != 0; }\n"
                "int query(const unsigned char *p) { return item_exists(p); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {
                item.name: item for item in graph.bundle.functions.values()
            }
            query = by_name["query"]
            item_exists = by_name["item_exists"]
            action_evidence = Evidence(
                "source", query.function_id, query.file,
                query.start_line, "query invokes item lookup",
            )
            action = ExternalActionSchema(
                action_id="query", entry_id="entry", name="query",
                description="query existing item",
                dispatcher_function_id=query.function_id,
                handler_function_id=query.function_id, discriminator="Q",
                channel_kind="stdin", fields=[],
                examples=[ActionExample("51", {})],
                success_markers_hex=["31"], failure_markers_hex=["30"],
                evidence=[action_evidence],
                inspected_function_ids=[query.function_id],
                status=ProofStatus.PROVEN_STATIC, confidence=0.99,
                source_api="read", success_evidence=[action_evidence],
                failure_evidence=[action_evidence],
            )
            requirement = {
                "resource": "item", "binding": "",
                "predicate": "exists",
                "evidence": [{
                    "kind": "source", "function_id": query.function_id,
                    "line": query.start_line,
                    "detail": "query requires the lookup result",
                }],
            }
            llm = ScriptedLLM([
                {
                    "consumes": [requirement], "produces": [],
                    "invalidates": [], "initial_resources": [],
                    "success_condition": "",
                    "evidence": [{
                        "kind": "source", "function_id": query.function_id,
                        "line": query.start_line,
                        "detail": "query calls item_exists",
                    }],
                    "unknowns": ["lookup body is unopened"],
                    "context_complete": False,
                    "requested_function_ids": [item_exists.function_id],
                    "rationale": "open the lookup",
                },
                {
                    "consumes": [requirement], "produces": [], "invalidates": [],
                    "initial_resources": [],
                    "success_condition": "item_exists returns true",
                    "evidence": [{
                        "kind": "source",
                        "function_id": query.function_id,
                        "line": query.start_line,
                        "detail": "query calls item_exists",
                    }, {
                        "kind": "source",
                        "function_id": item_exists.function_id,
                        "line": item_exists.start_line,
                        "detail": "nonzero item byte is the success condition",
                    }],
                    "unknowns": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "complete",
                },
            ])

            dependency_graph = await StateDependencyAgent(
                llm, graph, UsageEvidenceBundle(), budget=2
            ).run([action])

        contract = dependency_graph.contracts[0]
        self.assertIs(contract.status, ProofStatus.PROVEN_STATIC)
        self.assertEqual([item.resource for item in contract.consumes], ["item"])
        self.assertEqual(
            {item.function_id for item in contract.evidence},
            {query.function_id, item_exists.function_id},
        )

    async def test_initial_resource_binding_requires_a_source_proven_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int query(const unsigned char *p) { return p[0] == 'Q'; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            query = next(iter(graph.bundle.functions.values()))
            evidence = Evidence(
                "source", query.function_id, query.file,
                query.start_line, "query guard",
            )
            action = ExternalActionSchema(
                action_id="query", entry_id="entry", name="query",
                description="query", dispatcher_function_id=query.function_id,
                handler_function_id=query.function_id, discriminator="Q",
                channel_kind="stdin", fields=[],
                examples=[ActionExample("51", {"key": "6b"})],
                success_markers_hex=["4f4b"], failure_markers_hex=[],
                evidence=[evidence], inspected_function_ids=[query.function_id],
                status=ProofStatus.PROVEN_STATIC, confidence=0.99,
                source_api="read", success_evidence=[evidence],
            )
            requirement = {
                "resource": "item", "binding": "key", "predicate": "exists",
                "evidence": [{
                    "kind": "source", "function_id": query.function_id,
                    "line": query.start_line, "detail": "item lookup",
                }],
            }
            llm = ScriptedLLM([{
                "consumes": [requirement], "produces": [], "invalidates": [],
                "initial_resources": [requirement],
                "success_condition": "query returns one",
                "evidence": [{
                    "kind": "source", "function_id": query.function_id,
                    "line": query.start_line, "detail": "query return",
                }],
                "unknowns": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "symbolic initial item",
            }])

            dependency_graph = await StateDependencyAgent(
                llm, graph, UsageEvidenceBundle(), budget=2
            ).run([action])

        contract = dependency_graph.contracts[0]
        self.assertEqual(contract.status, ProofStatus.POSSIBLE)
        self.assertFalse(dependency_graph.initial_resources)
        self.assertTrue(any(
            "without concrete value" in item for item in contract.unknowns
        ))

    async def test_unresolved_callback_branch_becomes_an_inventory_obligation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "typedef int (*operation_fn)(unsigned char *);\n"
                "int dispatch(unsigned char *p, operation_fn callback) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return callback(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd, operation_fn callback) {\n"
                "  unsigned char b[2]; read(fd,b,2); return dispatch(b, callback);\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            entry = EntryRecord(
                entry_id="entry-unresolved-callback",
                candidate_id="candidate-unresolved-callback",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id,
                source_api="read", channel_kind="stdin",
                attacker_control="full", provenance_path=[],
                consumer_hints=[dispatch.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line + 1, "read acquires the request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "target unresolved",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "request opcode selects the callback operation",
                    }],
                },
            ])
            agent = InputActionAgent(llm, graph, budget=4)

            actions = await agent.run([entry])

        self.assertFalse(actions)
        self.assertEqual(agent.planned_branch_validations, 0)
        self.assertTrue(any(
            "callback" in item and "no resolved direct or possible indirect" in item
            for item in agent.inventory_obligations
        ))

    async def test_svf_possible_callback_target_is_validated_as_its_own_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "typedef int (*operation_fn)(unsigned char *);\n"
                "int operation(unsigned char *p) { return p[1] == 'X'; }\n"
                "int dispatch(unsigned char *p, operation_fn callback) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return callback(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) {\n"
                "  unsigned char b[2]; read(fd,b,2); return dispatch(b, operation);\n"
                "}\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()
            by_name = {item.name: item for item in bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            operation = by_name["operation"]
            bundle.edges.append(CallEdge(
                edge_id="svf-callback",
                caller_id=dispatch.function_id,
                callee_id=operation.function_id,
                line=dispatch.start_line + 2,
                kind="indirect_possible",
                confidence=0.5,
                providers=["SVF-Andersen"],
            ))
            graph = GraphStore(bundle)
            entry = EntryRecord(
                entry_id="entry-callback", candidate_id="candidate-callback",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[dispatch.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line + 1, "read acquires the request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            raw_action = {
                "name": "callback operation",
                "description": "opcode one invokes the configured callback",
                "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": operation.function_id,
                "discriminator": "1",
                "fields": [],
                "examples": [{
                    "data_hex": b"\x01X".hex(), "bindings": {},
                    "rationale": "complete callback request",
                }],
                "success_markers_hex": [b"OK".hex()],
                "failure_markers_hex": [b"ERR".hex()],
                "success_evidence": [{
                    "kind": "source", "function_id": operation.function_id,
                    "line": operation.start_line,
                    "detail": "handler return represents the accepted branch",
                }],
                "failure_evidence": [],
                "evidence": [
                    {
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 2,
                        "detail": "case one invokes the callback",
                    },
                    {
                        "kind": "source", "function_id": operation.function_id,
                        "line": operation.start_line,
                        "detail": "possible callback target consumes the request",
                    },
                ],
                "unknowns": [], "confidence": 0.95,
            }
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "dispatcher",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "opcode selects a callback operation",
                    }],
                },
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "selected branch",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "opcode selects a callback operation",
                    }],
                },
                {
                    "actions": [raw_action], "context_complete": True,
                    "requested_function_ids": [], "rationale": "callback target checked",
                    "branch_disposition": "NOT_ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": operation.function_id,
                        "line": operation.start_line,
                        "detail": "callback target implements the selected operation",
                    }],
                },
            ])
            agent = InputActionAgent(llm, graph, budget=6)

            actions = await agent.run([entry])

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].handler_function_id, operation.function_id)
        self.assertEqual(actions[0].status, ProofStatus.PROVEN_STATIC)
        self.assertFalse(agent.inventory_obligations)
        self.assertTrue(any(
            operation.function_id in seed.handler_function_ids
            for seed in agent.operation_seeds
        ))

    async def test_incomplete_or_unknown_action_context_cannot_be_statically_proven(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int handle(const unsigned char *p) { return p[0] == 'X'; }\n"
                "int dispatch(const unsigned char *p) { return handle(p); }\n"
                "int receive_one(int fd) { unsigned char b[1]; read(fd,b,1); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            handle = by_name["handle"]
            entry = EntryRecord(
                entry_id="entry", candidate_id="candidate", status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read acquires the byte",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            raw = {
                "name": "X", "description": "X operation",
                "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": handle.function_id,
                "discriminator": "X", "fields": [],
                "examples": [{"data_hex": "58", "bindings": {}, "rationale": "X"}],
                "success_markers_hex": ["4f4b"], "failure_markers_hex": [],
                "success_evidence": [{
                    "kind": "source", "function_id": handle.function_id,
                    "line": handle.start_line, "detail": "successful handler return",
                }],
                "failure_evidence": [],
                "evidence": [
                    {"kind": "source", "function_id": dispatch.function_id,
                     "line": dispatch.start_line, "detail": "dispatcher calls handler"},
                    {"kind": "source", "function_id": handle.function_id,
                     "line": handle.start_line, "detail": "handler consumes X"},
                ],
                "unknowns": [], "confidence": 0.99,
            }
            agent = InputActionAgent(ScriptedLLM([]), graph)
            opened = [receive.function_id, dispatch.function_id, handle.function_id]

            incomplete = agent._validate_actions(
                entry, [raw], opened, set(), context_complete=False
            )[0]
            unresolved_raw = {**raw, "unknowns": ["response framing is unresolved"]}
            unresolved = agent._validate_actions(
                entry, [unresolved_raw], opened, set(), context_complete=True
            )[0]

        self.assertEqual(incomplete.status, ProofStatus.POSSIBLE)
        self.assertIn("this Action's source context is incomplete", incomplete.unknowns)
        self.assertEqual(unresolved.status, ProofStatus.POSSIBLE)
        self.assertIn("response framing is unresolved", unresolved.unknowns)

    async def test_unmapped_required_predecessor_blocks_the_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int query(const unsigned char *p) { return p[0] == 'Q'; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            query = next(iter(graph.bundle.functions.values()))
            evidence = Evidence(
                "source", query.function_id, query.file,
                query.start_line, "query success return",
            )
            action = ExternalActionSchema(
                action_id="query", entry_id="entry", name="query",
                description="query", dispatcher_function_id=query.function_id,
                handler_function_id=query.function_id, discriminator="Q",
                channel_kind="stdin", fields=[],
                examples=[ActionExample("51", {})],
                success_markers_hex=["4f4b"], failure_markers_hex=[],
                evidence=[evidence], inspected_function_ids=[query.function_id],
                status=ProofStatus.PROVEN_STATIC, confidence=0.99,
                source_api="read", success_evidence=[evidence],
            )
            usage = UsageEvidenceBundle(constraints=[UsageConstraint(
                constraint_id="missing-login", provider="FuzzGen",
                relation="data_dependency", strength="REQUIRED",
                producer="login", consumer="query",
                producer_function_ids=["fn-not-mapped"],
                consumer_function_ids=[query.function_id],
                detail="query consumes a value produced by login",
            )])
            llm = ScriptedLLM([{
                "consumes": [], "produces": [], "invalidates": [],
                "initial_resources": [], "success_condition": "query returns one",
                "evidence": [{
                    "kind": "source", "function_id": query.function_id,
                    "line": query.start_line, "detail": "query result",
                }],
                "unknowns": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "locally stateless",
            }])

            dependency_graph = await StateDependencyAgent(
                llm, graph, usage, budget=2
            ).run([action])
            candidate = ScenarioPlanner(max_steps=2).plan(
                [action], dependency_graph
            )[0]

        self.assertEqual(
            dependency_graph.contracts[0].status, ProofStatus.POSSIBLE
        )
        self.assertTrue(any(
            "mapping is incomplete" in item
            for item in dependency_graph.contracts[0].unknowns
        ))
        self.assertEqual(candidate.status, ScenarioStatus.UNPROVEN)

    async def test_produced_dynamic_binding_requires_a_response_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int login(const unsigned char *p) { return p[0] == 'L'; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            login_function = next(iter(graph.bundle.functions.values()))
            evidence = [Evidence(
                "source", login_function.function_id, login_function.file,
                login_function.start_line, "login response serializes session id",
            )]
            action = _action("login", b"L", b"OK")
            action.dispatcher_function_id = login_function.function_id
            action.handler_function_id = login_function.function_id
            action.inspected_function_ids = [login_function.function_id]
            action.evidence = evidence
            action.success_evidence = evidence
            action.response_bindings = [ResponseBindingExtractor(
                "session_id", 2, 4, "bytes", evidence
            )]
            response = {
                "consumes": [],
                "produces": [{
                    "resource": "authenticated_session",
                    "binding": "session_id",
                    "predicate": "exists",
                    "evidence": [{
                        "kind": "source",
                        "function_id": login_function.function_id,
                        "line": login_function.start_line,
                        "detail": "successful login produces returned session id",
                    }],
                }],
                "invalidates": [], "initial_resources": [],
                "success_condition": "login succeeds and returns the id",
                "evidence": [{
                    "kind": "source",
                    "function_id": login_function.function_id,
                    "line": login_function.start_line,
                    "detail": "login success",
                }],
                "unknowns": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "complete",
            }
            proven = await StateDependencyAgent(
                ScriptedLLM([response]), graph, UsageEvidenceBundle(), budget=2
            ).run([action])
            action.response_bindings = []
            blocked = await StateDependencyAgent(
                ScriptedLLM([response]), graph, UsageEvidenceBundle(), budget=2
            ).run([action])

        self.assertEqual(
            proven.contracts[0].status, ProofStatus.PROVEN_STATIC
        )
        self.assertEqual(blocked.contracts[0].status, ProofStatus.POSSIBLE)
        self.assertTrue(any(
            "no request or response source" in item
            for item in blocked.contracts[0].unknowns
        ))

    async def test_invalid_state_claim_cannot_be_silently_dropped_as_stateless(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int lookup(const unsigned char *p) { return p[0] == 'G'; }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            lookup = next(iter(graph.bundle.functions.values()))
            source_evidence = Evidence(
                "source", lookup.function_id, lookup.file,
                lookup.start_line, "lookup return is the success result",
            )
            action = ExternalActionSchema(
                action_id="get", entry_id="entry", name="get",
                description="lookup", dispatcher_function_id=lookup.function_id,
                handler_function_id=lookup.function_id, discriminator="G",
                channel_kind="stdin", fields=[],
                examples=[ActionExample("47", {})],
                success_markers_hex=["31"], failure_markers_hex=["30"],
                evidence=[source_evidence], inspected_function_ids=[lookup.function_id],
                status=ProofStatus.PROVEN_STATIC, confidence=0.99,
                source_api="read", success_evidence=[source_evidence],
                failure_evidence=[source_evidence],
            )
            llm = ScriptedLLM([{
                "consumes": [{
                    "resource": "item",
                    "binding": "key",
                    "predicate": "exists",
                    "evidence": [{
                        "kind": "source",
                        "function_id": lookup.function_id,
                        "line": lookup.end_line + 100,
                        "detail": "invalid evidence outside the function",
                    }],
                }],
                "produces": [], "invalidates": [], "initial_resources": [],
                "success_condition": "lookup returns one",
                "evidence": [{
                    "kind": "source", "function_id": lookup.function_id,
                    "line": lookup.start_line, "detail": "real handler result",
                }],
                "unknowns": [], "context_complete": True,
                "requested_function_ids": [], "rationale": "claimed complete",
            }])

            graph_result = await StateDependencyAgent(
                llm, graph, UsageEvidenceBundle(), budget=2
            ).run([action])

        self.assertEqual(graph_result.contracts[0].status, ProofStatus.POSSIBLE)
        self.assertTrue(any(
            "lacked valid opened-source evidence" in item
            for item in graph_result.contracts[0].unknowns
        ))

    async def test_forward_action_and_backward_state_are_separate_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target.c"
            source.write_text(
                "int handle(const unsigned char *p) { return p[0] == 'X'; }\n"
                "int dispatch(const unsigned char *p) { return handle(p); }\n"
                "int receive_one(int fd) { unsigned char b[4]; read(fd,b,4); return dispatch(b); }\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(root).index()
            graph = GraphStore(bundle)
            by_name = {item.name: item for item in bundle.functions.values()}
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            handle = by_name["handle"]
            entry = EntryRecord(
                entry_id="entry-one", candidate_id="candidate-one", status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read", channel_kind="stdin",
                attacker_control="full", provenance_path=[], consumer_hints=[dispatch.function_id],
                evidence=[Evidence("source", receive.function_id, receive.file, receive.start_line, "read")],
                unknowns=[], verifier_confidence=0.99, first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            action_raw = {
                "name": "X request", "description": "dispatch X", "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": handle.function_id, "discriminator": "X",
                "fields": [{
                    "name": "opcode", "offset": 0, "width": 1, "encoding": "byte",
                    "binding": "", "relation": "equals X",
                    "evidence": [{"kind": "source", "function_id": handle.function_id, "line": handle.start_line, "detail": "checks X"}],
                }],
                "examples": [{"data_hex": "58000000", "bindings": {}, "rationale": "X request"}],
                "success_markers_hex": ["31"], "failure_markers_hex": ["30"],
                "success_evidence": [{"kind": "source", "function_id": handle.function_id, "line": handle.start_line, "detail": "return value 1 means accepted"}],
                "failure_evidence": [{"kind": "source", "function_id": handle.function_id, "line": handle.start_line, "detail": "return value 0 means rejected"}],
                "evidence": [
                    {"kind": "source", "function_id": dispatch.function_id, "line": dispatch.start_line, "detail": "dispatcher invokes handler"},
                    {"kind": "source", "function_id": handle.function_id, "line": handle.start_line, "detail": "real handler"},
                ],
                "unknowns": [], "confidence": 0.95,
            }
            action_llm = ScriptedLLM([
                {"actions": [], "context_complete": False, "requested_function_ids": [dispatch.function_id], "rationale": "open dispatcher"},
                {"actions": [], "context_complete": False, "requested_function_ids": [handle.function_id], "rationale": "open handler"},
                {"actions": [action_raw], "context_complete": True, "requested_function_ids": [], "rationale": "complete"},
            ])
            actions = await InputActionAgent(action_llm, graph, budget=8).run([entry])
            state_llm = ScriptedLLM([{
                "consumes": [], "produces": [], "invalidates": [], "initial_resources": [],
                "success_condition": "handle returns 1",
                "evidence": [{"kind": "source", "function_id": handle.function_id, "line": handle.start_line, "detail": "stateless return"}],
                "unknowns": [], "context_complete": True, "requested_function_ids": [], "rationale": "stateless",
            }])
            dependencies = await StateDependencyAgent(
                state_llm, graph, UsageEvidenceBundle(), budget=8
            ).run(actions)

        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].status, ProofStatus.PROVEN_STATIC)
        self.assertEqual(dependencies.contracts[0].status, ProofStatus.PROVEN_STATIC)
        self.assertTrue(all(call["session_key"].startswith("input_action:") for call in action_llm.calls))
        self.assertTrue(all(call["session_key"].startswith("state_dependency:") for call in state_llm.calls))

    async def test_inventory_validates_every_switch_handler_in_its_own_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int op_a(unsigned char *p) { return p[1]; }\n"
                "int op_b(unsigned char *p) { return p[2]; }\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return op_a(p);\n"
                "    case 2: return op_b(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[4]; read(fd,b,4); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            entry_function = by_name["receive_one"]
            dispatcher = by_name["dispatch"]
            entry = EntryRecord(
                entry_id="entry-switch", candidate_id="candidate-switch",
                status=Verdict.VERIFIED,
                entry_function_id=entry_function.function_id,
                source_api="read", channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[dispatcher.function_id],
                evidence=[Evidence(
                    "source", entry_function.function_id, entry_function.file,
                    entry_function.start_line, "read",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )

            responses = [
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "request dispatcher",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatcher.function_id,
                        "line": dispatcher.start_line + 1,
                        "detail": "external request byte selects an operation",
                    }],
                },
            ]
            for opcode, name in ((1, "op_a"), (2, "op_b")):
                handler = by_name[name]
                responses.extend([
                    {
                        "actions": [], "context_complete": False,
                        "requested_function_ids": [], "rationale": "dispatcher",
                        "branch_disposition": "ACTION",
                        "branch_disposition_evidence": [{
                            "kind": "source", "function_id": dispatcher.function_id,
                            "line": dispatcher.start_line + opcode,
                            "detail": "selected request branch",
                        }],
                    },
                    {
                        "actions": [{
                            "name": name, "description": name,
                            "dispatcher_function_id": dispatcher.function_id,
                            "handler_function_id": handler.function_id,
                            "discriminator": str(opcode),
                            "fields": [],
                            "examples": [{
                                "data_hex": f"0{opcode}000000", "bindings": {},
                                "rationale": "complete request",
                            }],
                            "success_markers_hex": ["4f4b"],
                            "failure_markers_hex": ["455252"],
                            "success_evidence": [{
                                "kind": "source", "function_id": handler.function_id,
                                "line": handler.start_line, "detail": "success path",
                            }],
                            "failure_evidence": [],
                            "evidence": [
                                {"kind": "source", "function_id": dispatcher.function_id,
                                 "line": dispatcher.start_line + opcode,
                                 "detail": "case dispatch"},
                                {"kind": "source", "function_id": handler.function_id,
                                 "line": handler.start_line, "detail": "handler"},
                            ],
                            "unknowns": [], "confidence": 0.99,
                        }],
                        "context_complete": True,
                        "requested_function_ids": [],
                        "rationale": "validated branch",
                        "branch_disposition": "NOT_ACTION",
                        "branch_disposition_evidence": [{
                            "kind": "source", "function_id": handler.function_id,
                            "line": handler.start_line,
                            "detail": "handler contains no nested request dispatcher",
                        }],
                    },
                ])
            llm = ScriptedLLM(responses)
            agent = InputActionAgent(llm, graph, budget=8)
            actions = await agent.run([entry])

        self.assertEqual({item.name for item in actions}, {"op_a", "op_b"})
        self.assertTrue(all(item.status is ProofStatus.PROVEN_STATIC for item in actions))
        self.assertEqual(len(llm.calls), 6)
        branch_sessions = {
            call["session_key"] for call in llm.calls
            if call["session_key"] != "input_action:entry-switch"
        }
        self.assertEqual(len(branch_sessions), 2)
        self.assertTrue(all("input_action:entry-switch:" in key for key in branch_sessions))

    async def test_action_cannot_claim_a_different_dispatcher_discriminator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int op_one(unsigned char *p) { return p[1]; }\n"
                "int dispatch(unsigned char *p) {\n"
                "  switch (p[0]) {\n"
                "    case 1: return op_one(p);\n"
                "    default: return 0;\n"
                "  }\n"
                "}\n"
                "int receive_one(int fd) { unsigned char b[4]; read(fd,b,4); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {
                item.name: item for item in graph.bundle.functions.values()
            }
            receive = by_name["receive_one"]
            dispatch = by_name["dispatch"]
            handler = by_name["op_one"]
            entry = EntryRecord(
                entry_id="entry-discriminator",
                candidate_id="candidate-discriminator",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id,
                source_api="read", channel_kind="stdin",
                attacker_control="full", provenance_path=[],
                consumer_hints=[dispatch.function_id],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "read request",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            raw_action = {
                "name": "invented opcode", "description": "wrong case",
                "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": handler.function_id,
                # The source branch is case 1. Every other field is made
                # superficially valid to ensure this mismatch is the blocker.
                "discriminator": "9", "fields": [],
                "examples": [{
                    "data_hex": "09000000", "bindings": {},
                    "rationale": "invented request",
                }],
                "success_markers_hex": ["4f4b"],
                "failure_markers_hex": [],
                "success_evidence": [{
                    "kind": "source", "function_id": handler.function_id,
                    "line": handler.start_line, "detail": "handler return",
                }],
                "failure_evidence": [], "response_bindings": [],
                "evidence": [
                    {"kind": "source", "function_id": dispatch.function_id,
                     "line": dispatch.start_line + 2, "detail": "real case"},
                    {"kind": "source", "function_id": handler.function_id,
                     "line": handler.start_line, "detail": "real handler"},
                ],
                "unknowns": [], "confidence": 0.99,
            }
            llm = ScriptedLLM([
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "open dispatcher",
                    "branch_disposition": "UNRESOLVED",
                    "branch_disposition_evidence": [],
                },
                {
                    "actions": [], "context_complete": True,
                    "requested_function_ids": [], "rationale": "dispatcher",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 1,
                        "detail": "request byte selects an operation",
                    }],
                },
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [], "rationale": "selected branch",
                    "branch_disposition": "ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": dispatch.function_id,
                        "line": dispatch.start_line + 2,
                        "detail": "real case one branch",
                    }],
                },
                {
                    "actions": [raw_action], "context_complete": True,
                    "requested_function_ids": [], "rationale": "claimed action",
                    "branch_disposition": "NOT_ACTION",
                    "branch_disposition_evidence": [{
                        "kind": "source", "function_id": handler.function_id,
                        "line": handler.start_line,
                        "detail": "handler contains no nested dispatcher",
                    }],
                },
            ])

            actions = await InputActionAgent(
                llm, graph, budget=6
            ).run([entry])

        self.assertEqual(len(actions), 1)
        self.assertIs(actions[0].status, ProofStatus.POSSIBLE)
        self.assertTrue(any(
            "does not match" in item for item in actions[0].unknowns
        ))
        self.assertEqual(actions[0].operation_seed_ids, [])


    async def test_tcp_scenario_skips_backend_response_entry_before_llm_work(self) -> None:
        connector = FunctionMetadata.create(
            name="open_peer", signature="int open_peer(int fd)",
            file="transport.c", start_line=1, end_line=3,
            source=(
                "int open_peer(int fd) {\n"
                "  return connect(fd, address, address_len);\n"
                "}\n"
            ),
        )
        backend = FunctionMetadata.create(
            name="backend_read", signature="int backend_read(void)",
            file="proxy.c", start_line=10, end_line=13,
            source=(
                "int backend_read(void) {\n"
                "  int fd = open_peer(socket_fd);\n"
                "  return recv(fd, buffer, sizeof(buffer), 0);\n"
                "}\n"
            ),
        )
        graph = GraphStore(AnalysisBundle(
            functions={
                connector.function_id: connector,
                backend.function_id: backend,
            },
            edges=[CallEdge(
                edge_id="edge-open-peer",
                caller_id=backend.function_id,
                callee_id=connector.function_id,
                line=backend.start_line + 1,
                kind="direct",
                confidence=1.0,
                providers=["test"],
            )],
        ))
        entry = EntryRecord(
            entry_id="entry-backend", candidate_id="candidate-backend",
            status=Verdict.VERIFIED, entry_function_id=backend.function_id,
            source_api="recv", channel_kind="TCP socket bytes",
            attacker_control="unknown",
            provenance_path=[{
                "function_id": connector.function_id,
                "relation": "descriptor creation is evidenced in this function",
            }],
            consumer_hints=[],
            evidence=[
                Evidence(
                    "source", connector.function_id, connector.file,
                    connector.start_line + 1, "descriptor is connected to a peer",
                ),
                Evidence(
                    "source", backend.function_id, backend.file,
                    backend.start_line + 2, "bytes enter the receive buffer",
                ),
            ],
            unknowns=[], verifier_confidence=0.99,
            rationale="first bytes from the connected descriptor",
            boundary_subject="network peer",
            first_acquisition_confirmed=True,
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            inspected_function_ids=[backend.function_id, connector.function_id],
        )
        llm = ScriptedLLM([])
        agent = InputActionAgent(
            llm, graph, scenario_channel="tcp"
        )

        actions = await agent.run([entry])

        self.assertEqual(actions, [])
        # Outbound input is discovered; a later runtime adapter may decline
        # its execution, but that must not erase it before source analysis.
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(agent.skipped_entries, [])
        self.assertTrue(agent.inventory_obligations)

    async def test_backend_wording_without_connect_proof_does_not_skip_entry(self) -> None:
        reader = FunctionMetadata.create(
            name="peer_read", signature="int peer_read(int fd, char *buffer)",
            file="transport.c", start_line=1, end_line=3,
            source=(
                "int peer_read(int fd, char *buffer) {\n"
                "  return recv(fd, buffer, 8, 0);\n"
                "}\n"
            ),
        )
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[]
        ))
        entry = EntryRecord(
            entry_id="entry-wording-only", candidate_id="candidate-wording-only",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="recv", channel_kind="TCP socket bytes",
            attacker_control="unknown", provenance_path=[], consumer_hints=[],
            evidence=[Evidence(
                "source", reader.function_id, reader.file,
                reader.start_line + 1, "backend response recv",
            )],
            unknowns=[], verifier_confidence=0.99,
            rationale="first response bytes from backend peer",
            boundary_subject="backend peer",
            first_acquisition_confirmed=True,
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            inspected_function_ids=[reader.function_id],
        )
        agent = InputActionAgent(
            ScriptedLLM([]), graph, scenario_channel="tcp"
        )

        self.assertEqual(agent.scenario_incompatibility(entry), "")

    async def test_stdin_scope_accepts_standard_input_provenance_but_not_file_read(self) -> None:
        reader = FunctionMetadata.create(
            name="process_once", signature="int process_once(FILE *input)",
            file="target.c", start_line=1, end_line=3,
            source="int process_once(FILE *input) { char c; return fread(&c, 1, 1, input); }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={reader.function_id: reader}, edges=[]
        ))
        entry = EntryRecord(
            entry_id="entry-stdin", candidate_id="candidate-stdin",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="fread", channel_kind="stdio standard input",
            attacker_control="full", provenance_path=[], consumer_hints=[],
            evidence=[Evidence(
                "source", reader.function_id, reader.file,
                reader.start_line, "main passes stdin as input",
            )],
            unknowns=[], verifier_confidence=0.99,
            rationale="fread copies a byte from standard input",
            boundary_subject="external byte from FILE *input stream",
            first_acquisition_confirmed=True,
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            inspected_function_ids=[reader.function_id],
        )
        agent = InputActionAgent(ScriptedLLM([]), graph, scenario_channel="stdin")
        self.assertEqual(agent.scenario_incompatibility(entry), "")

        entry.channel_kind = "file contents"
        entry.rationale = "fread copies a byte from a disk file"
        entry.evidence = []
        self.assertIn("stdin channel", agent.scenario_incompatibility(entry))

    async def test_unrelated_inspected_connect_does_not_hide_inbound_tcp_entry(self) -> None:
        reader = FunctionMetadata.create(
            name="tcp_read", signature="int tcp_read(int fd, char *buf)",
            file="server.c", start_line=1, end_line=3,
            source="int tcp_read(int fd, char *buf) {\n  return read(fd, buf, 8);\n}",
        )
        unrelated = FunctionMetadata.create(
            name="healthcheck", signature="int healthcheck(void)",
            file="server.c", start_line=10, end_line=12,
            source="int healthcheck(void) {\n  return connect(3, 0, 0);\n}",
        )
        graph = GraphStore(AnalysisBundle(
            functions={
                reader.function_id: reader,
                unrelated.function_id: unrelated,
            },
            edges=[],
        ))
        entry = EntryRecord(
            entry_id="entry-inbound", candidate_id="candidate-inbound",
            status=Verdict.VERIFIED, entry_function_id=reader.function_id,
            source_api="read", channel_kind="TCP socket bytes",
            attacker_control="full",
            provenance_path=[{
                "function_id": reader.function_id,
                "relation": "accepted client socket bytes enter buf",
            }],
            consumer_hints=[],
            evidence=[Evidence(
                "source", reader.function_id, reader.file,
                reader.start_line + 1, "read from accepted TCP client socket",
            )],
            unknowns=[], verifier_confidence=0.99,
            first_acquisition_confirmed=True,
            inspected_function_ids=[reader.function_id, unrelated.function_id],
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            boundary_subject="network client",
        )
        llm = ScriptedLLM([{
            "actions": [], "branch_disposition": "NOT_ACTION",
            "branch_disposition_evidence": [], "context_complete": True,
            "requested_function_ids": [], "rationale": "no dispatcher",
        }])
        agent = InputActionAgent(
            llm, graph, budget=1, scenario_channel="tcp"
        )

        await agent.run([entry])

        self.assertEqual(agent.skipped_entries, [])
        self.assertEqual(len(llm.calls), 1)

    async def test_raw_tcp_scenario_skips_tls_application_data_entry(self) -> None:
        tls_reader = FunctionMetadata.create(
            name="tls_read", signature="int tls_read(void)",
            file="tls.c", start_line=1, end_line=3,
            source=(
                "int tls_read(void) {\n"
                "  return SSL_read(ssl, buffer, sizeof(buffer));\n"
                "}\n"
            ),
        )
        graph = GraphStore(AnalysisBundle(
            functions={tls_reader.function_id: tls_reader}, edges=[]
        ))
        entry = EntryRecord(
            entry_id="entry-tls", candidate_id="candidate-tls",
            status=Verdict.VERIFIED, entry_function_id=tls_reader.function_id,
            source_api="SSL_read", channel_kind="TLS network socket",
            attacker_control="full", provenance_path=[], consumer_hints=[],
            evidence=[Evidence(
                "source", tls_reader.function_id, tls_reader.file,
                tls_reader.start_line + 1, "decrypted TLS application bytes",
            )],
            unknowns=[], verifier_confidence=0.99,
            rationale="TLS record payload reaches the command parser",
            boundary_subject="remote client",
            first_acquisition_confirmed=True,
            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            inspected_function_ids=[tls_reader.function_id],
        )
        llm = ScriptedLLM([])
        agent = InputActionAgent(llm, graph, scenario_channel="tcp")

        actions = await agent.run([entry])

        self.assertEqual(actions, [])
        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(agent.skipped_entries, [])
        self.assertTrue(agent.inventory_obligations)

    async def test_inventory_does_not_treat_all_reachable_switches_as_external_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int internal_a(void) { return 1; }\n"
                "int internal_dispatch(int state) {\n"
                "  switch (state) { case 1: return internal_a(); default: return 0; }\n"
                "}\n"
                "int receive_one(int fd) { char b; read(fd, &b, 1); return internal_dispatch(7); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="entry-no-hint", candidate_id="candidate-no-hint",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line, "external byte read",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
            )
            agent = InputActionAgent(ScriptedLLM([]), graph)

            seeds, truncated = agent._inventory_entry(entry)

        self.assertEqual(seeds, [])
        self.assertFalse(truncated)

    async def test_inventory_keeps_inline_input_effect_but_not_unrelated_state_if(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int state;\n"
                "int parse_request(const unsigned char *buf) {\n"
                "  if (buf[0] == 1) { state = 7; }\n"
                "  return state;\n"
                "}\n"
                "int internal_tick(int phase) { if (phase == 2) { state = 9; } return state; }\n"
                "int receive_one(int fd) {\n"
                "  unsigned char buf[1];\n"
                "  read(fd, buf, 1);\n"
                "  internal_tick(2);\n"
                "  return parse_request(buf);\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            receive = by_name["receive_one"]
            entry = EntryRecord(
                entry_id="entry-inline", candidate_id="candidate-inline",
                status=Verdict.VERIFIED,
                entry_function_id=receive.function_id, source_api="read",
                channel_kind="stdin", attacker_control="full",
                provenance_path=[], consumer_hints=[],
                evidence=[Evidence(
                    "source", receive.function_id, receive.file,
                    receive.start_line + 2, "read acquires the request byte",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                entry_line=receive.start_line + 2,
            )
            seeds, truncated = InputActionAgent(
                ScriptedLLM([]), graph,
            )._inventory_entry(entry)
        self.assertFalse(truncated)
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0].dispatcher_function_id,
                         by_name["parse_request"].function_id)
        self.assertEqual(seeds[0].handler_function_ids, [])

    async def test_consumer_hint_is_navigation_not_dispatcher_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int tcp_read(char *buf) { return read(3, buf, 1); }\n"
                "int close_conn(void) { return 0; }\n"
                "int drive_machine(int state) {\n"
                "  switch (state) { case 1: return close_conn(); default: return 0; }\n"
                "}\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            reader = by_name["tcp_read"]
            driver = by_name["drive_machine"]
            entry = EntryRecord(
                entry_id="entry-callback-reader",
                candidate_id="candidate-callback-reader",
                status=Verdict.VERIFIED,
                entry_function_id=reader.function_id,
                source_api="read", channel_kind="network_tcp",
                attacker_control="full", provenance_path=[],
                consumer_hints=[driver.function_id],
                evidence=[Evidence(
                    "source", reader.function_id, reader.file,
                    reader.start_line, "read acquires a client byte",
                )],
                unknowns=[], verifier_confidence=0.99,
                first_acquisition_confirmed=True,
                site_kind=EntrySiteKind.DIRECT_ACQUISITION,
            )
            agent = InputActionAgent(ScriptedLLM([]), graph)

            seeds, truncated = agent._inventory_entry(entry)

        self.assertEqual(seeds, [])
        self.assertFalse(truncated)

    def test_callback_return_path_requires_open_registration_evidence(self) -> None:
        reader = FunctionMetadata.create(
            name="tcp_read", signature="int tcp_read(void)", file="server.c",
            start_line=1, end_line=1, source="int tcp_read(void) { return 1; }",
        )
        registration = FunctionMetadata.create(
            name="conn_new", signature="void conn_new(void)", file="server.c",
            start_line=10, end_line=10,
            source="void conn_new(void) { callback = tcp_read; }",
        )
        read_driver = FunctionMetadata.create(
            name="try_read", signature="int try_read(void)", file="server.c",
            start_line=20, end_line=20,
            source="int try_read(void) { return callback(); }",
        )
        state_machine = FunctionMetadata.create(
            name="drive", signature="int drive(void)", file="server.c",
            start_line=30, end_line=30,
            source="int drive(void) { try_read(); return dispatch(); }",
        )
        dispatcher = FunctionMetadata.create(
            name="dispatch", signature="int dispatch(void)", file="server.c",
            start_line=40, end_line=40,
            source="int dispatch(void) { return 0; }",
        )
        bundle = AnalysisBundle(
            functions={item.function_id: item for item in (
                reader, registration, read_driver, state_machine, dispatcher
            )},
            edges=[
                CallEdge("register", registration.function_id, reader.function_id,
                         registration.start_line, "function_reference", 0.8),
                CallEdge("callback", read_driver.function_id, reader.function_id,
                         None, "indirect_possible", 0.8),
                CallEdge("read", state_machine.function_id, read_driver.function_id,
                         state_machine.start_line, "direct", 1.0),
                CallEdge("dispatch", state_machine.function_id, dispatcher.function_id,
                         state_machine.start_line, "direct", 1.0),
            ],
        )
        graph = GraphStore(bundle)
        without_registration = {
            reader.function_id, read_driver.function_id,
            state_machine.function_id, dispatcher.function_id,
        }
        with_registration = {*without_registration, registration.function_id}

        self.assertEqual(
            graph.causal_path_from_entry(
                reader.function_id, dispatcher.function_id,
                opened_function_ids=without_registration,
            ),
            [],
        )
        self.assertEqual(
            graph.causal_path_from_entry(
                reader.function_id, dispatcher.function_id,
                opened_function_ids=with_registration,
            ),
            [
                reader.function_id, read_driver.function_id,
                state_machine.function_id, dispatcher.function_id,
            ],
        )

    def test_callback_return_path_rejects_mismatched_callback_slot(self) -> None:
        reader = FunctionMetadata.create(
            name="tcp_read", signature="int tcp_read(void)", file="server.c",
            start_line=1, end_line=1, source="int tcp_read(void) { return 1; }",
        )
        registration = FunctionMetadata.create(
            name="conn_new", signature="void conn_new(conn *c)", file="server.c",
            start_line=10, end_line=10,
            source="void conn_new(conn *c) { c->read = tcp_read; }",
        )
        wrong_driver = FunctionMetadata.create(
            name="write_driver", signature="int write_driver(conn *c)",
            file="server.c", start_line=20, end_line=20,
            source="int write_driver(conn *c) { return c->write(); }",
        )
        state_machine = FunctionMetadata.create(
            name="drive", signature="int drive(conn *c)", file="server.c",
            start_line=30, end_line=30,
            source="int drive(conn *c) { write_driver(c); return dispatch(); }",
        )
        dispatcher = FunctionMetadata.create(
            name="dispatch", signature="int dispatch(void)", file="server.c",
            start_line=40, end_line=40,
            source="int dispatch(void) { return 0; }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (
                reader, registration, wrong_driver, state_machine, dispatcher
            )},
            edges=[
                CallEdge("register", registration.function_id, reader.function_id,
                         registration.start_line, "function_reference", 0.8),
                CallEdge("wrong-points-to", wrong_driver.function_id,
                         reader.function_id, None, "indirect_possible", 0.4),
                CallEdge("drive", state_machine.function_id,
                         wrong_driver.function_id, state_machine.start_line,
                         "direct", 1.0),
                CallEdge("dispatch", state_machine.function_id,
                         dispatcher.function_id, state_machine.start_line,
                         "direct", 1.0),
            ],
        ))

        self.assertEqual(
            graph.causal_path_from_entry(
                reader.function_id, dispatcher.function_id,
                opened_function_ids={
                    reader.function_id, registration.function_id,
                    wrong_driver.function_id, state_machine.function_id,
                    dispatcher.function_id,
                },
            ),
            [],
        )

    def test_member_callback_does_not_match_bare_os_call(self) -> None:
        reader = FunctionMetadata.create(
            name="tcp_read", signature="int tcp_read(void)", file="server.c",
            start_line=1, end_line=1, source="int tcp_read(void) { return 1; }",
        )
        registration = FunctionMetadata.create(
            name="conn_new", signature="void conn_new(conn *c)", file="server.c",
            start_line=10, end_line=10,
            source="void conn_new(conn *c) { c->read = tcp_read; }",
        )
        member_driver = FunctionMetadata.create(
            name="member_driver", signature="int member_driver(conn *c)",
            file="server.c", start_line=20, end_line=20,
            source="int member_driver(conn *c) { return c->read(); }",
        )
        os_reader = FunctionMetadata.create(
            name="os_reader", signature="int os_reader(int fd)",
            file="server.c", start_line=30, end_line=30,
            source="int os_reader(int fd) { char b; return read(fd, &b, 1); }",
        )
        graph = GraphStore(AnalysisBundle(
            functions={item.function_id: item for item in (
                reader, registration, member_driver, os_reader
            )},
            edges=[
                CallEdge("register", registration.function_id, reader.function_id,
                         registration.start_line, "function_reference", 0.8),
                CallEdge("member-possible", member_driver.function_id,
                         reader.function_id, None, "indirect_possible", 0.4),
                CallEdge("os-possible", os_reader.function_id,
                         reader.function_id, None, "indirect_possible", 0.4),
            ],
        ))

        callers = graph.callback_invocation_callers(
            reader.function_id,
            registration_function_ids={registration.function_id},
        )

        self.assertEqual([item.name for item in callers], ["member_driver"])


class NetLifterAdapterTest(unittest.TestCase):
    def test_default_action_payload_keeps_rules_after_the_old_prefix_limit(self) -> None:
        from harnesscreator.analysis.netlifter import NetLifterGrammar

        grammar = NetLifterGrammar(
            source="popeye.log", source_sha256="example",
            productions=[
                {"nonterminal": f"Rule{index}", "expression": f"B[{index}]"}
                for index in range(130)
            ],
            assertions=[f"B[{index}] == {index}" for index in range(130)],
        )
        complete = grammar.prompt_payload()
        self.assertEqual(len(complete["productions"]), 130)
        self.assertEqual(len(complete["assertions"]), 130)
        self.assertEqual(complete["productions"][-1]["nonterminal"], "Rule129")
        self.assertEqual(complete["omitted_productions"], 0)
        self.assertEqual(complete["omitted_assertions"], 0)

        preview = grammar.prompt_payload(limit=2)
        self.assertEqual(len(preview["productions"]), 2)
        self.assertEqual(preview["omitted_productions"], 128)

    def test_imports_original_popeye_bnf_without_claiming_runtime_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "popeye.log"
            path.write_text(
                "<BNF>\n  S := B[0] B[1..3];\n     assert(B[0] == 88)\n</BNF>\n",
                encoding="utf-8",
            )
            grammar = load_netlifter_grammars([path])[0]

        payload = grammar.prompt_payload()
        self.assertEqual(payload["provider"], "NetLifter/Popeye")
        self.assertIn("runtime", payload["authority"])
        self.assertTrue(grammar.source_sha256)


class ScenarioHarnessContextTest(unittest.IsolatedAsyncioTestCase):
    async def test_dynamic_response_binding_must_be_extracted_then_patched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "#include <stddef.h>\n"
                "int handle(const unsigned char *p, size_t n) { return n && p[0]; }\n"
                "int dispatch(const unsigned char *p, size_t n) { return handle(p,n); }\n"
                "int receive_setup(const unsigned char *p, size_t n) { return dispatch(p,n); }\n"
                "int receive_final(const unsigned char *p, size_t n) { return dispatch(p,n); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            evidence = [Evidence(
                "source", by_name["handle"].function_id,
                by_name["handle"].file, by_name["handle"].start_line,
                "fixture response binding",
            )]
            extractor = ResponseBindingExtractor(
                "session_id", 2, 4, "bytes", evidence
            )
            use = RequestBindingUse("session_id", 1, 4, 0, "bytes")
            witness = ScenarioWitness(
                witness_id="witness-dynamic", scenario_id="scenario-dynamic",
                target_action_id="use",
                steps=[
                    ScenarioStep(
                        0, "login", "entry-setup", "4c", {}, ["4f4b"],
                        request_template_hex="4c",
                        response_binding_extractors=[extractor],
                    ),
                    ScenarioStep(
                        1, "use", "entry-final", b"UABCD".hex(), {}, ["444f4e45"],
                        request_template_hex=b"U0000".hex(),
                        request_binding_uses=[use],
                    ),
                ],
                observations=[], command=["fixture"], channel="stdin",
                process_returncode=None, status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture dynamic witness",
            )
            common_tail = (
                by_name["dispatch"].function_id,
                by_name["handle"].function_id,
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={
                    "login": (by_name["receive_setup"].function_id, *common_tail),
                    "use": (by_name["receive_final"].function_id, *common_tail),
                },
            )
            symbol = _binding_symbol("session_id")
            code = (
                "#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n"
                "extern \"C\" int receive_setup(const unsigned char *, size_t);\n"
                "extern \"C\" int receive_final(const unsigned char *, size_t);\n"
                "static int hc_response_contains(const uint8_t *r, size_t rn, "
                "const uint8_t *m, size_t mn) { return rn >= mn && memcmp(r,m,mn) == 0; }\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                "  const uint8_t hc_setup_step_0[] = {0x4c};\n"
                "  const uint8_t hc_success_step_0[] = {0x4f,0x4b};\n"
                "  receive_setup(hc_setup_step_0, sizeof(hc_setup_step_0));\n"
                "  uint8_t hc_response_step_0[64];\n"
                "  size_t hc_response_step_0_size = read(0, hc_response_step_0, sizeof(hc_response_step_0));\n"
                "  if (!hc_response_contains(hc_response_step_0, hc_response_step_0_size, "
                "hc_success_step_0, sizeof(hc_success_step_0))) return 0;\n"
                f"  uint8_t {symbol}[4];\n"
                "  if (hc_response_step_0_size < 6) return 0;\n"
                f"  memcpy({symbol}, hc_response_step_0 + 2, sizeof({symbol}));\n"
                "  if (Size < 5) return 0;\n"
                "  uint8_t *hc_fuzz_request_storage = (uint8_t *)malloc(Size);\n"
                "  if (hc_fuzz_request_storage == nullptr) return 0;\n"
                "  memcpy(hc_fuzz_request_storage, Data, Size);\n"
                f"  memcpy(hc_fuzz_request_storage + 1, {symbol}, sizeof({symbol}));\n"
                "  const uint8_t *hc_fuzz_request = hc_fuzz_request_storage;\n"
                "  size_t hc_fuzz_request_size = Size;\n"
                "  receive_final(hc_fuzz_request, hc_fuzz_request_size);\n"
                "  free(hc_fuzz_request_storage);\n"
                "  return 0;\n}\n"
            )
            audit = [{
                "check_id": check_id, "status": "PASS", "evidence": "claimed",
            } for check_id in CHECKLIST_NAMES]
            manifest = HarnessManifest(
                harness_id="harness-dynamic", scenario_id=plan.scenario_id,
                source_file="fuzz_target.cc", build_target="fixture",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=5, max_size=4096,
                dispatch_strategy="one_scenario_per_harness",
                expected_anchors=[by_name["handle"].function_id],
                expected_consumers=list(plan.required_function_ids),
            )
            draft = HarnessDraft(
                manifest=manifest,
                code=code,
                self_audit=audit,
                context_function_ids=list(dict.fromkeys([
                    by_name["receive_setup"].function_id,
                    by_name["receive_final"].function_id,
                    *common_tail,
                ])),
            )
            report = ScenarioStaticHarnessGate(graph).check(draft, plan, witness)
            hardcoded = HarnessDraft(
                manifest=manifest,
                code=code.replace(
                    f"memcpy({symbol}, hc_response_step_0 + 2, sizeof({symbol}));",
                    f"memcpy({symbol}, \"WXYZ\", sizeof({symbol}));",
                ),
                self_audit=audit,
                context_function_ids=draft.context_function_ids,
            )
            hardcoded_report = ScenarioStaticHarnessGate(graph).check(
                hardcoded, plan, witness
            )

        checks = {item.check_id: item for item in report.checks}
        self.assertEqual(
            plan.input_mapping, "raw_final_request_with_runtime_bindings"
        )
        self.assertEqual(checks["HC10"].status, CheckStatus.PASS)
        self.assertEqual(checks["HC15"].status, CheckStatus.PASS)
        self.assertEqual(checks["HC16"].status, CheckStatus.PASS)
        hardcoded_checks = {
            item.check_id: item for item in hardcoded_report.checks
        }
        self.assertEqual(hardcoded_checks["HC16"].status, CheckStatus.FAIL)

    async def test_final_fuzz_bytes_must_use_the_final_steps_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "#include <stddef.h>\n"
                "int handle(const unsigned char *p, size_t n) { return n && p[0]; }\n"
                "int dispatch(const unsigned char *p, size_t n) { return handle(p,n); }\n"
                "int receive_setup(const unsigned char *p, size_t n) { return dispatch(p,n); }\n"
                "int receive_final(const unsigned char *p, size_t n) { return dispatch(p,n); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                witness_id="witness-multi-entry", scenario_id="scenario-multi-entry",
                target_action_id="query",
                steps=[
                    ScenarioStep(0, "setup", "entry-setup", "53", {}, ["4f4b"]),
                    ScenarioStep(1, "query", "entry-final", "47", {}, ["56414c"]),
                ],
                observations=[], command=["fixture"], channel="stdin",
                process_returncode=None, status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture witness",
            )
            common_tail = (
                by_name["dispatch"].function_id,
                by_name["handle"].function_id,
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={
                    "setup": (by_name["receive_setup"].function_id, *common_tail),
                    "query": (by_name["receive_final"].function_id, *common_tail),
                },
            )
            code_prefix = (
                "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n#include <unistd.h>\n"
                "extern \"C\" int receive_setup(const unsigned char *, size_t);\n"
                "extern \"C\" int receive_final(const unsigned char *, size_t);\n"
                "static int hc_response_contains(const uint8_t *r, size_t rn, "
                "const uint8_t *m, size_t mn) { return rn >= mn && memcmp(r,m,mn) == 0; }\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                "  const uint8_t hc_setup_step_0[] = {0x53};\n"
                "  const uint8_t hc_success_step_0[] = {0x4f,0x4b};\n"
                "  receive_setup(hc_setup_step_0, sizeof(hc_setup_step_0));\n"
                "  uint8_t hc_response_step_0[32];\n"
                "  size_t hc_response_step_0_size = read(0, hc_response_step_0, sizeof(hc_response_step_0));\n"
                "  if (!hc_response_contains(hc_response_step_0, hc_response_step_0_size, "
                "hc_success_step_0, sizeof(hc_success_step_0))) return 0;\n"
                "  const uint8_t *hc_fuzz_request = Data;\n"
                "  size_t hc_fuzz_request_size = Size;\n"
            )
            code_suffix = "  return 0;\n}\n"
            audit = [{
                "check_id": check_id, "status": "PASS", "evidence": "claimed",
            } for check_id in CHECKLIST_NAMES]
            manifest = HarnessManifest(
                harness_id="harness-multi-entry", scenario_id=plan.scenario_id,
                source_file="fuzz_target.cc", build_target="fixture",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=1, max_size=4096,
                dispatch_strategy="one_scenario_per_harness",
                expected_anchors=[by_name["handle"].function_id],
                expected_consumers=list(plan.required_function_ids),
            )
            context_ids = list(dict.fromkeys([
                by_name["receive_setup"].function_id,
                by_name["receive_final"].function_id,
                *common_tail,
            ]))
            wrong = HarnessDraft(
                manifest=manifest,
                code=(code_prefix
                      + "  receive_setup(hc_fuzz_request, hc_fuzz_request_size);\n"
                      + code_suffix),
                self_audit=audit, context_function_ids=context_ids,
            )
            correct = HarnessDraft(
                manifest=manifest,
                code=(code_prefix
                      + "  receive_final(hc_fuzz_request, hc_fuzz_request_size);\n"
                      + code_suffix),
                self_audit=audit, context_function_ids=context_ids,
            )

            wrong_report = ScenarioStaticHarnessGate(graph).check(
                wrong, plan, witness
            )
            correct_report = ScenarioStaticHarnessGate(graph).check(
                correct, plan, witness
            )

        self.assertEqual(
            plan.setup_entry_function_ids,
            [by_name["receive_setup"].function_id],
        )
        self.assertEqual(
            plan.fuzz_entry_function_id,
            by_name["receive_final"].function_id,
        )
        wrong_checks = {item.check_id: item for item in wrong_report.checks}
        correct_checks = {item.check_id: item for item in correct_report.checks}
        self.assertEqual(wrong_checks["HC08"].status, CheckStatus.FAIL)
        self.assertEqual(wrong_checks["HC10"].status, CheckStatus.FAIL)
        self.assertEqual(correct_checks["HC08"].status, CheckStatus.PASS)
        self.assertEqual(correct_checks["HC10"].status, CheckStatus.PASS)

    async def test_setup_bytes_and_oracle_must_execute_in_order_not_merely_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "#include <stddef.h>\n"
                "int handle(const unsigned char *p, size_t n) { return n && p[0]; }\n"
                "int dispatch(const unsigned char *p, size_t n) { return handle(p,n); }\n"
                "int receive_one(const unsigned char *p, size_t n) { return dispatch(p,n); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                witness_id="witness-setup", scenario_id="scenario-setup",
                target_action_id="query",
                steps=[
                    ScenarioStep(0, "login", "entry", "53", {}, ["4f4b"]),
                    ScenarioStep(1, "query", "entry", "47", {}, ["56414c"]),
                ],
                observations=[], command=["fixture"], channel="stdin",
                process_returncode=None, status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture witness",
            )
            functions = (
                by_name["receive_one"].function_id,
                by_name["dispatch"].function_id,
                by_name["handle"].function_id,
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"login": functions, "query": functions},
            )
            audit = [{
                "check_id": check_id, "status": "PASS", "evidence": "claimed",
            } for check_id in CHECKLIST_NAMES]
            context_ids = list(functions)
            manifest = HarnessManifest(
                harness_id="harness-setup", scenario_id=plan.scenario_id,
                source_file="fuzz_target.cc", build_target="fixture",
                engine="libfuzzer", sanitizers=["address", "undefined"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=1, max_size=4096,
                dispatch_strategy="one_scenario_per_harness",
                expected_anchors=[by_name["handle"].function_id],
                expected_consumers=list(plan.required_function_ids),
            )
            fake = HarnessDraft(
                manifest=manifest,
                code=(
                    "#include <stddef.h>\n#include <stdint.h>\n"
                    "extern \"C\" int receive_one(const unsigned char *, size_t);\n"
                    "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                    "  const uint8_t hc_setup_step_0[] = {0x53};\n"
                    "  const uint8_t hc_success_step_0[] = {0x4f,0x4b};\n"
                    "  (void)hc_setup_step_0; (void)hc_success_step_0;\n"
                    "  const uint8_t *hc_fuzz_request = Data;\n"
                    "  size_t hc_fuzz_request_size = Size;\n"
                    "  receive_one(hc_fuzz_request, hc_fuzz_request_size);\n"
                    "  return 0;\n}\n"
                ),
                self_audit=audit, context_function_ids=context_ids,
            )
            proper = HarnessDraft(
                manifest=manifest,
                code=(
                    "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n#include <unistd.h>\n"
                    "extern \"C\" int receive_one(const unsigned char *, size_t);\n"
                    "static int hc_response_contains(const uint8_t *r, size_t rn, "
                    "const uint8_t *m, size_t mn) { return rn >= mn && memcmp(r,m,mn) == 0; }\n"
                    "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                    "  const uint8_t hc_setup_step_0[] = {0x53};\n"
                    "  const uint8_t hc_success_step_0[] = {0x4f,0x4b};\n"
                    "  receive_one(hc_setup_step_0, sizeof(hc_setup_step_0));\n"
                    "  uint8_t hc_response_step_0[32];\n"
                    "  size_t hc_response_step_0_size = read(0, hc_response_step_0, sizeof(hc_response_step_0));\n"
                    "  if (!hc_response_contains(hc_response_step_0, hc_response_step_0_size, "
                    "hc_success_step_0, sizeof(hc_success_step_0))) return 0;\n"
                    "  const uint8_t *hc_fuzz_request = Data;\n"
                    "  size_t hc_fuzz_request_size = Size;\n"
                    "  receive_one(hc_fuzz_request, hc_fuzz_request_size);\n"
                    "  return 0;\n}\n"
                ),
                self_audit=audit, context_function_ids=context_ids,
            )
            copied_but_not_delivered = HarnessDraft(
                manifest=manifest,
                code=(
                    "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n#include <unistd.h>\n"
                    "extern \"C\" int receive_one(const unsigned char *, size_t);\n"
                    "static int hc_response_contains(const uint8_t *r, size_t rn, "
                    "const uint8_t *m, size_t mn) { return rn >= mn && memcmp(r,m,mn) == 0; }\n"
                    "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                    "  const uint8_t hc_setup_step_0[] = {0x53};\n"
                    "  const uint8_t hc_success_step_0[] = {0x4f,0x4b};\n"
                    "  uint8_t unrelated_setup_copy[sizeof(hc_setup_step_0)];\n"
                    "  memcpy(unrelated_setup_copy, hc_setup_step_0, sizeof(hc_setup_step_0));\n"
                    "  uint8_t hc_response_step_0[32];\n"
                    "  size_t hc_response_step_0_size = read(0, hc_response_step_0, sizeof(hc_response_step_0));\n"
                    "  if (!hc_response_contains(hc_response_step_0, hc_response_step_0_size, "
                    "hc_success_step_0, sizeof(hc_success_step_0))) return 0;\n"
                    "  const uint8_t *hc_fuzz_request = Data;\n"
                    "  size_t hc_fuzz_request_size = Size;\n"
                    "  receive_one(hc_fuzz_request, hc_fuzz_request_size);\n"
                    "  return 0;\n}\n"
                ),
                self_audit=audit, context_function_ids=context_ids,
            )

            fake_report = ScenarioStaticHarnessGate(graph).check(fake, plan, witness)
            proper_report = ScenarioStaticHarnessGate(graph).check(
                proper, plan, witness
            )
            copied_report = ScenarioStaticHarnessGate(graph).check(
                copied_but_not_delivered, plan, witness
            )

        fake_checks = {item.check_id: item for item in fake_report.checks}
        proper_checks = {item.check_id: item for item in proper_report.checks}
        self.assertEqual(fake_checks["HC15"].status, CheckStatus.FAIL)
        self.assertEqual(fake_checks["HC16"].status, CheckStatus.FAIL)
        self.assertEqual(proper_checks["HC15"].status, CheckStatus.PASS)
        self.assertEqual(proper_checks["HC16"].status, CheckStatus.PASS)
        copied_checks = {item.check_id: item for item in copied_report.checks}
        self.assertEqual(copied_checks["HC15"].status, CheckStatus.FAIL)
        self.assertEqual(copied_checks["HC16"].status, CheckStatus.FAIL)

    async def test_verifier_feedback_can_expand_a_completed_cached_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            (root / "target.c").write_text(
                "int helper(const unsigned char *p) { return p[0]; }\n"
                "int handle(const unsigned char *p) { return helper(p); }\n"
                "int dispatch(const unsigned char *p) { return handle(p); }\n"
                "int receive_one(int fd) { unsigned char b[1]; read(fd,b,1); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                witness_id="witness-repair", scenario_id="scenario-repair",
                target_action_id="request",
                steps=[ScenarioStep(0, "request", "entry", "58", {}, ["4f4b"])],
                observations=[], command=["fixture"], channel="stdin",
                process_returncode=None, status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture witness",
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"request": (
                    by_name["receive_one"].function_id,
                    by_name["dispatch"].function_id,
                    by_name["handle"].function_id,
                )},
            )
            complete = {
                "context_complete": True, "requested_function_ids": [],
                "established_facts": ["base context"],
                "blocking_dependencies": [], "rationale": "base complete",
            }
            repair = {
                "context_complete": False,
                "requested_function_ids": [by_name["helper"].function_id],
                "established_facts": [], "blocking_dependencies": [],
                "rationale": "compiler feedback requires helper declaration",
            }
            repaired = {
                "context_complete": True, "requested_function_ids": [],
                "established_facts": ["helper declaration opened"],
                "blocking_dependencies": [], "rationale": "repair complete",
            }
            llm = ScriptedLLM([complete, complete, complete, repair, repaired])
            project = ProjectSpec(
                source_root=root, output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
            ).normalized()
            agent = ScenarioHarnessGeneratorAgent(llm, graph, project)

            first_opened, _ = await agent._discover_context(plan, witness, [])
            repaired_opened, discovery = await agent._discover_context(
                plan, witness, ["build failed: helper declaration missing"]
            )

        self.assertNotIn(
            by_name["helper"].function_id,
            {item.function_id for item in first_opened},
        )
        self.assertIn(
            by_name["helper"].function_id,
            {item.function_id for item in repaired_opened},
        )
        self.assertTrue(discovery["context_complete"])
        self.assertEqual(
            len([call for call in llm.calls if "current_function" in call["payload"]]),
            4,
        )

    async def test_context_completion_does_not_discard_a_function_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            (root / "target.c").write_text(
                "int helper(const unsigned char *p) { return p[0]; }\n"
                "int handle(const unsigned char *p) { return helper(p); }\n"
                "int receive_one(int fd) { unsigned char b[1]; read(fd,b,1); "
                "helper(b); return handle(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                witness_id="witness-context-request", scenario_id="scenario-context-request",
                target_action_id="request",
                steps=[ScenarioStep(0, "request", "entry", "58", {}, ["4f4b"])],
                observations=[], command=["fixture"], channel="stdin",
                process_returncode=None, status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture witness",
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"request": (
                    by_name["receive_one"].function_id,
                    by_name["handle"].function_id,
                )},
            )
            requested = {
                "context_complete": True,
                "requested_function_ids": [by_name["helper"].function_id],
                "established_facts": [], "blocking_dependencies": [],
                "rationale": "read helper before generation",
            }
            complete = {
                **requested, "requested_function_ids": [],
                "rationale": "all required source opened",
            }
            llm = ScriptedLLM([requested, complete, complete])
            project = ProjectSpec(
                source_root=root, output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
            ).normalized()
            agent = ScenarioHarnessGeneratorAgent(llm, graph, project)

            opened, discovery = await agent._discover_context(plan, witness, [])

        self.assertEqual(
            {item.function_id for item in opened},
            {item.function_id for item in by_name.values()},
        )
        self.assertEqual(len(llm.calls), 3)
        self.assertTrue(discovery["context_complete"])

    async def test_direct_handler_call_cannot_bypass_witnessed_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "int handle(const unsigned char *p) { return p[0]; }\n"
                "int dispatch(const unsigned char *p) { return handle(p); }\n"
                "int receive_one(int fd) { unsigned char b[1]; read(fd,b,1); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                witness_id="witness-entry-path",
                scenario_id="scenario-entry-path",
                target_action_id="request",
                steps=[ScenarioStep(0, "request", "entry", "58", {}, ["4f4b"])],
                observations=[],
                command=["fixture"],
                channel="stdin",
                process_returncode=None,
                status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture witness",
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"request": (
                    by_name["receive_one"].function_id,
                    by_name["dispatch"].function_id,
                    by_name["handle"].function_id,
                )},
            )
            draft = HarnessDraft(
                manifest=HarnessManifest(
                    harness_id="harness-direct-handler",
                    scenario_id=plan.scenario_id,
                    source_file="fuzz_target.cc",
                    build_target="fixture",
                    engine="libfuzzer",
                    sanitizers=["address", "undefined"],
                    execution_model="in_process_reset",
                    headers=[], libraries=[], min_size=1, max_size=4096,
                    dispatch_strategy="one_scenario_per_harness",
                    expected_anchors=[by_name["handle"].function_id],
                    expected_consumers=list(plan.required_function_ids),
                ),
                code=(
                    "#include <stddef.h>\n#include <stdint.h>\n"
                    "extern \"C\" int handle(const unsigned char *);\n"
                    "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                    "  if (Size < 1) return 0;\n"
                    "  return handle(Data);\n"
                    "}\n"
                ),
                self_audit=[{
                    "check_id": check_id,
                    "status": "PASS",
                    "evidence": "claimed",
                } for check_id in CHECKLIST_NAMES],
                context_function_ids=[
                    by_name["receive_one"].function_id,
                    by_name["dispatch"].function_id,
                    by_name["handle"].function_id,
                ],
            )

            report = ScenarioStaticHarnessGate(graph).check(draft, plan, witness)
            constant_draft = HarnessDraft(
                manifest=draft.manifest,
                code=(
                    "#include <stddef.h>\n#include <stdint.h>\n"
                    "extern \"C\" int receive_one(int);\n"
                    "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                    "  const uint8_t *hc_fuzz_request = Data;\n"
                    "  size_t hc_fuzz_request_size = Size;\n"
                    "  if (hc_fuzz_request_size && hc_fuzz_request[0]) receive_one(0);\n"
                    "  return 0;\n"
                    "}\n"
                ),
                self_audit=draft.self_audit,
                context_function_ids=draft.context_function_ids,
            )
            constant_report = ScenarioStaticHarnessGate(graph).check(
                constant_draft, plan, witness
            )
            copy_only_draft = HarnessDraft(
                manifest=draft.manifest,
                code=(
                    "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n"
                    "extern \"C\" int receive_one(int);\n"
                    "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                    "  const uint8_t *hc_fuzz_request = Data;\n"
                    "  size_t hc_fuzz_request_size = Size;\n"
                    "  uint8_t unrelated_copy[4096];\n"
                    "  if (hc_fuzz_request_size > sizeof(unrelated_copy)) return 0;\n"
                    "  memcpy(unrelated_copy, hc_fuzz_request, hc_fuzz_request_size);\n"
                    "  receive_one(0);\n"
                    "  return 0;\n"
                    "}\n"
                ),
                self_audit=draft.self_audit,
                context_function_ids=draft.context_function_ids,
            )
            copy_only_report = ScenarioStaticHarnessGate(graph).check(
                copy_only_draft, plan, witness
            )

        checks = {item.check_id: item for item in report.checks}
        self.assertEqual(checks["HC08"].status.value, "FAIL")
        self.assertEqual(checks["HC10"].status.value, "FAIL")
        self.assertIn("bypasses", checks["HC08"].evidence)
        constant_checks = {
            item.check_id: item for item in constant_report.checks
        }
        self.assertEqual(constant_checks["HC08"].status.value, "PASS")
        self.assertEqual(constant_checks["HC10"].status.value, "FAIL")
        copy_only_checks = {
            item.check_id: item for item in copy_only_report.checks
        }
        self.assertEqual(copy_only_checks["HC08"].status.value, "PASS")
        self.assertEqual(copy_only_checks["HC10"].status.value, "FAIL")

    async def test_sibling_read_and_handler_are_reported_as_unproven_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "#include <unistd.h>\n"
                "static int read_one(int fd, char *b) { return read(fd,b,1); }\n"
                "static int handle(char *b) { return b[0]; }\n"
                "static int process_one(int fd) { char b[1]; "
                "if (read_one(fd,b) != 1) return 0; return handle(b); }\n"
                "int main(void) { return process_one(0); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                witness_id="witness-siblings", scenario_id="scenario-siblings",
                target_action_id="request",
                steps=[ScenarioStep(0, "request", "entry", "58", {}, ["4f4b"])],
                observations=[], command=["fixture"], channel="stdin",
                process_returncode=None, status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture witness",
            )
            plan = build_harness_plan(
                witness, action_function_ids={"request": (
                    by_name["read_one"].function_id,
                    by_name["process_one"].function_id,
                    by_name["handle"].function_id,
                )},
            )
            draft = HarnessDraft(
                manifest=HarnessManifest(
                    harness_id="harness-siblings", scenario_id=plan.scenario_id,
                    source_file="fuzz_target.c", build_target="fixture",
                    engine="libfuzzer", sanitizers=["address"],
                    execution_model="loopback_network", headers=[], libraries=[],
                    min_size=0, max_size=4096,
                    dispatch_strategy="one_scenario_per_harness",
                    expected_anchors=[by_name["handle"].function_id],
                    expected_consumers=list(plan.required_function_ids),
                    build_command=["python", "-m", "harnesscreator.runtime.native_build"],
                ),
                code=(
                    "#include <stdint.h>\n#include <stddef.h>\n"
                    "int hc_native_original_main(void);\n"
                    "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) "
                    "{ (void)Data; (void)Size; return hc_native_original_main(); }\n"
                ),
                self_audit=[{"check_id": check_id, "status": "PASS", "evidence": "claimed"}
                            for check_id in CHECKLIST_NAMES],
                context_function_ids=list(plan.required_function_ids),
            )
            report = ScenarioStaticHarnessGate(graph).check(draft, plan, witness)
        check = next(item for item in report.checks if item.check_id == "HC08")
        self.assertEqual(check.status, CheckStatus.FAIL)
        self.assertIn("sibling calls", check.evidence)
        self.assertIn("process_one", check.evidence)
        self.assertNotIn("bypasses", check.evidence)

    async def test_native_builder_main_alias_preserves_real_entry_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target.c").write_text(
                "static int handle(const char *p) { return p[0]; }\n"
                "static int receive_one(const char *p) { return handle(p); }\n"
                "int main(void) { return receive_one(\"X\"); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                witness_id="witness-native-alias", scenario_id="scenario-native-alias",
                target_action_id="request",
                steps=[ScenarioStep(0, "request", "entry", "58", {}, ["4f4b"])],
                observations=[], command=["fixture"], channel="stdin",
                process_returncode=None, status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture witness",
            )
            plan = build_harness_plan(
                witness, action_function_ids={"request": (
                    by_name["receive_one"].function_id,
                    by_name["handle"].function_id,
                )},
            )
            manifest = HarnessManifest(
                harness_id="harness-native-alias", scenario_id=plan.scenario_id,
                source_file="fuzz_target.c", build_target="fixture",
                engine="libfuzzer", sanitizers=["address"],
                execution_model="in_process_reset", headers=[], libraries=[],
                min_size=0, max_size=4096,
                dispatch_strategy="one_scenario_per_harness",
                expected_anchors=[by_name["handle"].function_id],
                expected_consumers=list(plan.required_function_ids),
                build_command=["python", "-m", "harnesscreator.runtime.native_build"],
            )
            draft = HarnessDraft(
                manifest=manifest,
                code=(
                    "#include <stdint.h>\n#include <stddef.h>\n"
                    "int hc_native_original_main(void);\n"
                    "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) "
                    "{ (void)Data; (void)Size; return hc_native_original_main(); }\n"
                ),
                self_audit=[{"check_id": check_id, "status": "PASS", "evidence": "claimed"}
                            for check_id in CHECKLIST_NAMES],
                context_function_ids=list(plan.required_function_ids),
            )
            native = ScenarioStaticHarnessGate(graph).check(draft, plan, witness)
            manifest.build_command = []
            untrusted = ScenarioStaticHarnessGate(graph).check(draft, plan, witness)
        native_hc08 = next(item for item in native.checks if item.check_id == "HC08")
        untrusted_hc08 = next(item for item in untrusted.checks if item.check_id == "HC08")
        self.assertEqual(native_hc08.status, CheckStatus.PASS)
        self.assertEqual(untrusted_hc08.status, CheckStatus.FAIL)

    async def test_all_plan_roots_are_opened_before_context_can_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            (root / "target.c").write_text(
                "int handle(const unsigned char *p) { return p[0]; }\n"
                "int dispatch(const unsigned char *p) { return handle(p); }\n"
                "int receive_one(int fd) { unsigned char b[1]; read(fd,b,1); return dispatch(b); }\n",
                encoding="utf-8",
            )
            graph = GraphStore(StaticAnalyzer(root).index())
            by_name = {item.name: item for item in graph.bundle.functions.values()}
            witness = ScenarioWitness(
                witness_id="witness-context",
                scenario_id="scenario-context",
                target_action_id="request",
                steps=[ScenarioStep(
                    0, "request", "entry", b"X".hex(), {}, [b"OK".hex()],
                )],
                observations=[],
                command=["fixture"],
                channel="stdin",
                process_returncode=None,
                status=ScenarioStatus.PROVEN_RUNTIME,
                rationale="fixture witness",
            )
            plan = build_harness_plan(
                witness,
                action_function_ids={"request": (
                    by_name["receive_one"].function_id,
                    by_name["dispatch"].function_id,
                    by_name["handle"].function_id,
                )},
            )
            context_response = {
                "context_complete": True,
                "requested_function_ids": [],
                "established_facts": ["fixture"],
                "blocking_dependencies": [],
                "rationale": "enough",
            }
            generation_response = {
                "code": "int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) { return Size && Data[0]; }",
                "manifest": {
                    "build_target": "UNRESOLVED", "headers": [], "libraries": [],
                    "min_size": 0, "max_size": 4096,
                    "execution_model": "in_process_reset",
                },
                "checklist": [],
                "implemented_step_indexes": [0],
                "generation_blockers": [],
            }
            llm = ScriptedLLM([
                context_response, context_response, context_response,
                generation_response,
            ])
            project = ProjectSpec(
                source_root=root,
                output_root=Path(temporary) / "runs",
                require_fuzz_introspector=False,
            ).normalized()
            agent = ScenarioHarnessGeneratorAgent(
                llm, graph, project, max_context_turns=1
            )

            draft = await agent.run(plan, witness)

        context_calls = [
            call for call in llm.calls
            if "current_function" in call["payload"]
        ]
        self.assertEqual(len(context_calls), 3)
        self.assertEqual(set(draft.context_function_ids), {
            by_name["receive_one"].function_id,
            by_name["dispatch"].function_id,
            by_name["handle"].function_id,
        })


if __name__ == "__main__":
    unittest.main()
