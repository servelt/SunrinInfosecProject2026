"""Regressions from the 22-hour memcached boundary run."""

from __future__ import annotations

import tempfile
import unittest
import asyncio
import sys
from dataclasses import asdict
from pathlib import Path

from harnesscreator.agents.behavior import BehaviorCandidate, BehaviorRecoveryAgent
from harnesscreator.agents.execution_contract import ExecutionContract, ExecutionContractAgent
from harnesscreator.agents.input_surfaces import InputSurfaceCase
from harnesscreator.analysis import GraphStore
from harnesscreator.llm import ScriptedLLM
from harnesscreator.models import (
    AnalysisBundle, EntryRecord, EntrySiteKind, Evidence, FunctionMetadata, ProjectSpec,
    Verdict,
)
from harnesscreator.storage import ArtifactStore
from harnesscreator.orchestrator import _persist_imported_entries
from harnesscreator.workflow_boundary_v2 import _boundary_status, _load_completed_work
from harnesscreator.runtime.boundary_work import (
    WorkLedger, canonicalize_behaviors, plan_entries, prioritize_work_units,
)
from harnesscreator.runtime.boundary import BoundaryTrialRunner, source_transport


def entry(name: str, channel: str) -> EntryRecord:
    return EntryRecord(
        entry_id=name, candidate_id=name, status=Verdict.VERIFIED,
        entry_function_id=name, source_api="recvfrom" if channel == "udp" else "read",
        channel_kind=channel, attacker_control="client bytes", provenance_path=[],
        consumer_hints=[], evidence=[Evidence("source", name, "memcached.c", 1, "input")],
        unknowns=[], verifier_confidence=1.0, entry_line=1,
        site_kind=EntrySiteKind.DIRECT_ACQUISITION,
        first_acquisition_confirmed=True,
    )


class BoundaryWorkUnitTest(unittest.TestCase):
    def test_run_status_exposes_backend_and_evidence_blockers(self) -> None:
        status = _boundary_status(
            has_entries=True, has_behaviors=True, has_build=False,
            has_generated=False,
            blocked_statuses={"BLOCKED_UNSUPPORTED_BACKEND", "BLOCKED_EVIDENCE"},
        )
        self.assertEqual(status, "BLOCKED_UNSUPPORTED_BACKEND_AND_EVIDENCE")

    def test_fgets_transport_uses_stream_provenance_not_api_name(self) -> None:
        file_entry = entry("file-entry", "filesystem authentication-file contents")
        file_entry.source_api = "fgets"
        stdin_entry = entry("stdin-entry", "stdin stream")
        stdin_entry.source_api = "fgets"
        unknown_entry = entry("unknown-entry", "stream")
        unknown_entry.source_api = "fgets"
        self.assertEqual(source_transport(file_entry), "file")
        self.assertEqual(source_transport(stdin_entry), "stdin")
        self.assertEqual(source_transport(unknown_entry), "unknown")

    def test_socket_family_and_protocol_need_source_provenance(self) -> None:
        ambiguous = entry("ambiguous-read", "non-SSL accepted stream-socket payload read")
        plain = entry("tcp-read", "Internet TCP accepted stream-socket payload read")
        tls = entry("tls-read", "TLS accepted stream socket")
        tls.source_api = "SSL_read"
        self.assertEqual(source_transport(ambiguous), "unknown")
        self.assertEqual(source_transport(plain), "tcp")
        self.assertEqual(source_transport(tls), "unknown")

    def test_recvfrom_and_unix_socket_do_not_become_udp_or_tcp(self) -> None:
        unknown_datagram = entry("recvfrom-unknown", "network datagram")
        unknown_datagram.source_api = "recvfrom"
        unix_datagram = entry("recvfrom-unix", "AF_UNIX SOCK_DGRAM local socket")
        unix_datagram.source_api = "recvfrom"
        unix_stream = entry("recv-unix", "AF_UNIX SOCK_STREAM local socket")
        unix_stream.source_api = "recv"
        self.assertEqual(source_transport(unknown_datagram), "unknown")
        self.assertEqual(source_transport(unix_datagram), "unknown")
        self.assertEqual(source_transport(unix_stream), "unix_stream")

    def test_resume_rebuilds_cumulative_inventories_from_work_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(Path(temporary))
            behavior = BehaviorCandidate(
                behavior_id="b", entry_id="e", entry_function_id="fn",
                target_function_id="fn", kind="computation", summary="effect",
                path_function_ids=["fn"], effect="answer", input_flow="byte",
                prior_state="none", execution_mode="in-process",
            )
            contract = ExecutionContract(
                contract_id="c", behavior_id="b", entry_function_id="fn",
                target_function_id="fn", transport="stdin", input_binding="byte",
                calls=[], prerequisite_bytes_hex=[], isolation="unknown",
                result_condition="return", inspected_function_ids=["fn"],
                evidence_complete=False,
            )
            case = InputSurfaceCase(
                case_id="s", entry_id="e", entry_function_id="fn",
                source_api="fgets", channel_kind="stdin", data_hex="41",
                origin="test", rationale="case",
            )
            store.write_json("workflow/work-items/e/behavior.json", [behavior])
            store.write_json("workflow/work-items/e/input-surfaces.json", [case])
            store.write_json("workflow/work-items/e/fixed-vectors.json", [
                {**asdict(case), "case_id": "old-project-fixture"}
            ])
            store.write_json("workflow/work-items/w/contract.json", contract)
            store.write_json("workflow/work-items/s/original-trial.json",
                             {"trial_id": "t", "case_id": "s", "status": "OBSERVED_EXIT"})
            restored = _load_completed_work(store)
            self.assertEqual([len(rows) for rows in restored], [1, 1, 1, 1])
            self.assertEqual(restored[0][0].behavior_id, "b")
            self.assertEqual(restored[1][0].contract_id, "c")

    def test_imported_entry_artifacts_are_preserved_for_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = root / "old" / "entries"
            old.mkdir(parents=True)
            for name in ("candidates.jsonl", "verified.jsonl", "unresolved.jsonl",
                         "rejected.jsonl", "uninspected-functions.json"):
                (old / name).write_bytes(b'{"source":"old"}\n')
            new = ArtifactStore(root / "new")
            _persist_imported_entries(new, old)
            for source in old.iterdir():
                self.assertEqual(
                    (new.root / "entries" / source.name).read_bytes(),
                    source.read_bytes(),
                )

    def test_configured_network_entries_are_not_classified_by_function_name(self) -> None:
        entries = [entry("pid-file", "file")]
        entries.extend(entry(f"proxy-{index}", "tcp") for index in range(30))
        entries.extend([entry("tcp-read", "tcp"), entry("udp-read", "udp")])
        decisions = plan_entries(
            entries, scenario_channel="auto", scenario_command=["memcached", "-p", "23877", "-U", "23877"],
            scenario_port=23877,
        )
        chosen = {item.entry_id: item for item in decisions if item.disposition == "SELECTED"}
        self.assertIn("tcp-read", chosen)
        self.assertIn("udp-read", chosen)
        self.assertIn("proxy-0", chosen)
        self.assertEqual(chosen["tcp-read"].priority, chosen["proxy-0"].priority)
        self.assertTrue(all(item.reason for item in decisions))
        self.assertEqual({item.entry_id for item in decisions}, {item.entry_id for item in entries})

    def test_unconfigured_file_env_and_tls_are_deferred_independently_of_verdict(self) -> None:
        file_entry = entry("file-input", "filesystem")
        env_entry = entry("env-input", "environment")
        env_entry.source_api = "getenv"
        tls_entry = entry("tls-input", "TLS accepted TCP")
        tls_entry.source_api = "SSL_read"
        decisions = plan_entries(
            [file_entry, env_entry, tls_entry], scenario_channel="auto",
            scenario_command=["memcached", "-p", "23877", "-U", "23877"],
            scenario_port=23877,
        )
        self.assertTrue(all(item.source_verdict == "VERIFIED" for item in decisions))
        self.assertTrue(all(item.disposition == "DEFERRED" for item in decisions))
        self.assertEqual(
            {item.entry_id: item.activation for item in decisions},
            {"file-input": "NOT_CONFIGURED", "env-input": "NOT_CONFIGURED",
             "tls-input": "UNRESOLVED"},
        )

    def test_argv_requires_an_explicit_mutable_input_binding(self) -> None:
        startup = entry("main", "process argument vector")
        startup.site_kind = EntrySiteKind.PROCESS_START
        startup.source_api = "argv"
        implicit = plan_entries(
            [startup], scenario_channel="auto",
            scenario_command=["memcached", "-p", "23877"], scenario_port=23877,
        )[0]
        placeholder = plan_entries(
            [startup], scenario_channel="auto",
            scenario_command=["program", "{input}"], scenario_port=None,
        )[0]
        explicit = plan_entries(
            [startup], scenario_channel="argv",
            scenario_command=["program"], scenario_port=None,
        )[0]
        self.assertEqual(implicit.disposition, "DEFERRED")
        self.assertIn("argv", implicit.reason)
        self.assertEqual(placeholder.disposition, "SELECTED")
        self.assertEqual(explicit.disposition, "SELECTED")

    def test_effect_identity_merges_wording_and_line_variants_but_not_distinct_effects(self) -> None:
        common = dict(entry_id="tcp-read", entry_function_id="tcp-read", target_function_id="handler",
                      kind="state_change", path_function_ids=["tcp-read", "handler"])
        rows = [
            BehaviorCandidate("a", summary="store key", evidence=[Evidence("source", "handler", "m.c", 4, "first")],
                              input_flow="request bytes", effect="store item", prior_state="none",
                              execution_mode="network sequence", **common),
            BehaviorCandidate("b", summary="write cache", evidence=[Evidence("source", "handler", "m.c", 7, "second")],
                              input_flow="request bytes", effect="store item", prior_state="none",
                              execution_mode="network sequence", **common),
            BehaviorCandidate("c", summary="retrieve key", evidence=[Evidence("source", "handler", "m.c", 8, "third")],
                              input_flow="request bytes", effect="lookup item", prior_state="stored item",
                              execution_mode="network sequence", **common),
        ]
        units = canonicalize_behaviors(rows)
        self.assertEqual(len(units), 2)
        store = next(item for item in units if item.effect == "store item")
        self.assertEqual({item.line for item in store.evidence}, {4, 7})
        self.assertEqual(set(store.behavior_ids), {"a", "b"})

    def test_explanatory_flow_is_unresolved_identity_not_a_distinct_semantic_effect(self) -> None:
        common = dict(entry_id="tcp-read", entry_function_id="tcp-read", target_function_id="read",
                      kind="state_change", path_function_ids=["tcp-read", "read"],
                      effect="socket_payload_copy_into_buffer", prior_state="none",
                      execution_mode="network sequence")
        rows = [
            BehaviorCandidate("a", summary="copy", input_flow=(
                "tcp_read passes a socket descriptor to read and copies the returned bytes."
            ), **common),
            BehaviorCandidate("b", summary="same possible effect", input_flow=(
                "A proposed callback copies socket bytes into its destination buffer."
            ), **common),
        ]
        units = canonicalize_behaviors(rows)
        self.assertEqual(len(units), 2)
        self.assertTrue(all(unit.disposition == "UNRESOLVED" for unit in units))
        self.assertTrue(all("identity" in unit.reason for unit in units))

    def test_first_work_is_selected_by_evidence_not_model_output_position(self) -> None:
        unknown = BehaviorCandidate(
            "unknown", entry_id="tcp-read", entry_function_id="tcp-read",
            target_function_id="tcp-read", kind="unknown", summary="not located",
            path_function_ids=["tcp-read"], input_flow="unknown", effect="unknown",
            prior_state="unknown", execution_mode="unknown",
        )
        observed = BehaviorCandidate(
            "observed", entry_id="tcp-read", entry_function_id="tcp-read",
            target_function_id="handler", kind="output", summary="reply",
            path_function_ids=["tcp-read", "handler"], input_flow="request bytes",
            effect="reply staged", prior_state="none", execution_mode="network sequence",
            evidence=[Evidence("source", "handler", "m.c", 12, "reply write")],
        )
        source_only = BehaviorCandidate(
            "source-only", entry_id="tcp-read", entry_function_id="tcp-read",
            target_function_id="other", kind="output", summary="other reply",
            path_function_ids=["tcp-read", "other"], input_flow="request bytes",
            effect="other reply", prior_state="none", execution_mode="network sequence",
            evidence=[Evidence("source", "other", "m.c", 20, "other write")],
        )
        for behaviors in ([unknown, source_only, observed], [observed, unknown, source_only]):
            units = canonicalize_behaviors(behaviors)
            ranked = prioritize_work_units(units, behaviors, ["handler"])
            self.assertEqual(ranked[0][0].behavior_ids, ["observed"])
            self.assertTrue(ranked[0][1]["temporal_target_hint"])
            self.assertEqual(ranked[-1][0].behavior_ids, ["unknown"])

    def test_named_effect_precedes_unknown_effect_with_temporal_hint(self) -> None:
        unknown = BehaviorCandidate(
            "unknown", entry_id="tcp-read", entry_function_id="tcp-read",
            target_function_id="udp-handler", kind="unknown", summary="possibly reached",
            path_function_ids=["tcp-read", "udp-handler"],
            input_flow="datagram_to_rbuf", effect="unknown",
            prior_state="unknown", execution_mode="udp_receive",
            evidence=[Evidence("source", "udp-handler", "m.c", 20, "read")],
        )
        named = BehaviorCandidate(
            "named", entry_id="tcp-read", entry_function_id="tcp-read",
            target_function_id="tcp-handler", kind="output", summary="value response",
            path_function_ids=["tcp-read", "tcp-handler"],
            input_flow="key_to_lookup", effect="value_response_staged",
            prior_state="item_found", execution_mode="unknown",
            evidence=[Evidence("source", "tcp-handler", "m.c", 30, "response")],
        )
        ranked = prioritize_work_units(
            canonicalize_behaviors([unknown, named]), [unknown, named], ["udp-handler"],
        )
        self.assertEqual(ranked[0][0].behavior_ids, ["named"])
        self.assertTrue(ranked[0][1]["named_effect"])
        self.assertFalse(ranked[1][1]["named_effect"])

    def test_finished_unit_is_not_restarted_and_all_states_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ArtifactStore(Path(tmp))
            ledger = WorkLedger(store)
            ledger.mark("unit-a", "behavior", "STARTED", "source investigation")
            ledger.mark("unit-a", "behavior", "COMPLETED", "one effect found")
            ledger.mark("unit-b", "backend", "BLOCKED_UNSUPPORTED_BACKEND", "network engine absent")
            reopened = WorkLedger(store)
            self.assertTrue(reopened.finished("unit-a", "behavior"))
            self.assertFalse(reopened.finished("unit-b", "behavior"))
            self.assertEqual(reopened.latest("unit-b", "backend")["status"], "BLOCKED_UNSUPPORTED_BACKEND")


class ContractAccumulationTest(unittest.IsolatedAsyncioTestCase):
    async def test_explicit_argv_placeholder_receives_exact_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            item = entry("main", "process argument vector")
            item.site_kind = EntrySiteKind.PROCESS_START
            item.source_api = "argv"
            case = InputSurfaceCase(
                case_id="argv-case", entry_id=item.entry_id,
                entry_function_id=item.entry_function_id,
                source_api="argv", channel_kind=item.channel_kind,
                data_hex="4142", origin="test", rationale="exact argument",
            )
            project = ProjectSpec(
                source_root=root, output_root=root / "out",
                scenario_command=[sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])", "{input}"],
                scenario_channel="auto", scenario_step_timeout=2,
            )
            trial = await BoundaryTrialRunner(project).run(case, item)
            self.assertEqual(trial.status, "OBSERVED_EXIT", trial.failure_reason)
            self.assertEqual(bytes.fromhex(trial.response_hex), b"AB")

    async def test_behavior_summary_and_citation_variants_accumulate_as_one_candidate(self) -> None:
        fn = FunctionMetadata.create(
            name="consume", signature="int consume(void)", file="a.c",
            start_line=1, end_line=4,
            source="int consume(void) {\n int x = 1;\n return x;\n}\n",
        )
        graph = GraphStore(AnalysisBundle(
            functions={fn.function_id: fn}, edges=[], completeness={"provider": "test"},
        ))
        item = entry(fn.function_id, "stdin")
        common = {
            "target_function_id": fn.function_id, "kind": "computation",
            "path_function_ids": [fn.function_id],
            "input_flow": "input bytes", "effect": "return code",
            "prior_state": "none", "execution_mode": "in-process",
        }
        agent = BehaviorRecoveryAgent(ScriptedLLM([]), graph)
        results = agent.materialize(item, [fn.function_id], [
            {**common, "summary": "first wording", "evidence": [
                {"function_id": fn.function_id, "line": 2, "detail": "first line"}]},
            {**common, "summary": "second wording", "evidence": [
                {"function_id": fn.function_id, "line": 3, "detail": "second line"}]},
        ], True)
        self.assertEqual(len(results), 1)
        self.assertEqual({e.line for e in results[0].evidence}, {2, 3})

    async def test_corrected_behavior_evidence_resolves_earlier_invalid_variant(self) -> None:
        fn = FunctionMetadata.create(
            name="consume", signature="int consume(void)", file="a.c",
            start_line=1, end_line=3,
            source="int consume(void) {\n return 1;\n}\n",
        )
        graph = GraphStore(AnalysisBundle(
            functions={fn.function_id: fn}, edges=[], completeness={"provider": "test"},
        ))
        item = entry(fn.function_id, "stdin")
        common = {
            "target_function_id": fn.function_id, "kind": "computation",
            "path_function_ids": [fn.function_id],
            "input_flow": "input bytes", "effect": "return code",
            "prior_state": "none", "execution_mode": "in-process",
        }
        agent = BehaviorRecoveryAgent(ScriptedLLM([]), graph)
        results = agent.materialize(item, [fn.function_id], [
            {**common, "evidence": [{"function_id": fn.function_id,
                                    "line": 99, "detail": "incorrect citation"}]},
            {**common, "evidence": [{"function_id": fn.function_id,
                                    "line": 2, "detail": "corrected citation"}]},
        ], True)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].unknowns, [])
        self.assertEqual([e.line for e in results[0].evidence], [2])

    async def test_temporal_runtime_hit_is_navigation_hint_only(self) -> None:
        first = FunctionMetadata.create(
            name="read_bytes", signature="int read_bytes(void)", file="a.c",
            start_line=1, end_line=2, source="int read_bytes(void) {return 1;}\n",
        )
        handler = FunctionMetadata.create(
            name="handle", signature="int handle(void)", file="a.c",
            start_line=3, end_line=4, source="int handle(void) {return 1;}\n",
        )
        graph = GraphStore(AnalysisBundle(
            functions={first.function_id: first, handler.function_id: handler},
            edges=[], completeness={"provider": "test"},
        ))
        item = entry(first.function_id, "tcp")
        llm = ScriptedLLM([{
            "behaviors": [], "requested_function_ids": [],
            "context_complete": True, "rationale": "current source complete; inspect observed hit",
        }, {
            "behaviors": [], "requested_function_ids": [],
            "context_complete": True, "rationale": "no linked data flow",
        }])
        results = await BehaviorRecoveryAgent(
            llm, graph, max_function_turns=2,
            runtime_navigation_hints={item.entry_id: [handler.function_id]},
        ).run([item])
        self.assertIn(handler.function_id,
                      llm.calls[0]["payload"]["runtime_navigation_hints"])
        self.assertEqual(llm.calls[1]["payload"]["current_function"]["function_id"],
                         handler.function_id)
        self.assertEqual(results[0].status.value, "POSSIBLE")

    async def test_contract_checkpoint_resumes_requested_function_without_repeating_first_turn(self) -> None:
        first = FunctionMetadata.create(
            name="acquire", signature="int acquire(void)", file="a.c", start_line=1,
            end_line=3, source="int acquire(void) {\n return consume();\n}\n",
        )
        second = FunctionMetadata.create(
            name="consume", signature="int consume(void)", file="a.c", start_line=4,
            end_line=6, source="int consume(void) {\n return 1;\n}\n",
        )
        graph = GraphStore(AnalysisBundle(
            functions={first.function_id: first, second.function_id: second},
            edges=[], completeness={"provider": "test"},
        ))
        behavior = BehaviorCandidate(
            behavior_id="b", entry_id="e", entry_function_id=first.function_id,
            target_function_id=first.function_id, kind="computation", summary="return",
            path_function_ids=[first.function_id],
        )
        first_response = {
            "input_binding": "caller bytes", "calls": [], "prerequisite_bytes_hex": [],
            "isolation": "in_process_reset", "result_condition": "return",
            "repeatability_evidence": [{"function_id": first.function_id, "line": 2,
                                        "detail": "caller stack state"}],
            "requested_function_ids": [second.function_id], "unknowns": [],
            "rationale": "more source", "context_complete": False,
        }
        snapshots = []
        class SlowSecond:
            calls = 0
            async def complete_json(self, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    return first_response
                await asyncio.sleep(10)
        agent = ExecutionContractAgent(
            SlowSecond(), graph, max_function_turns=2,
            checkpoint=lambda _id, state: snapshots.append(state),
        )
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(agent.run([behavior], {"e": "stdin"}), timeout=0.02)
        self.assertEqual(snapshots[0]["queued_function_ids"], [second.function_id])
        resumed_llm = ScriptedLLM([{
            **first_response, "requested_function_ids": [],
            "repeatability_evidence": [], "context_complete": True,
        }])
        contract = (await ExecutionContractAgent(
            resumed_llm, graph, max_function_turns=2,
            initial_state=snapshots[0],
        ).run([behavior], {"e": "stdin"}))[0]
        self.assertEqual(len(resumed_llm.calls), 1)
        self.assertEqual(resumed_llm.calls[0]["payload"]["current_function"]["function_id"],
                         second.function_id)
        self.assertTrue(contract.evidence_complete, contract.unknowns)
        self.assertEqual(len(contract.repeatability_evidence), 1)

    async def test_timed_out_behavior_retains_completed_turn_and_resumes_next_function(self) -> None:
        first = FunctionMetadata.create(
            name="acquire", signature="int acquire(void)", file="a.c", start_line=1,
            end_line=3, source="int acquire(void) {\n return consume();\n}\n",
        )
        second = FunctionMetadata.create(
            name="consume", signature="int consume(void)", file="a.c", start_line=4,
            end_line=6, source="int consume(void) {\n return 1;\n}\n",
        )
        graph = GraphStore(AnalysisBundle(
            functions={first.function_id: first, second.function_id: second},
            edges=[], completeness={"provider": "test"},
        ))
        item = entry(first.function_id, "stdin")
        item.entry_function_id = first.function_id
        item.evidence = [Evidence("source", first.function_id, "a.c", 2, "input")]
        checkpoint = []
        first_response = {
            "behaviors": [{
                "target_function_id": first.function_id, "kind": "computation",
                "summary": "first effect", "input_flow": "caller input",
                "effect": "consume byte", "prior_state": "none",
                "execution_mode": "in_process_reset",
                "path_function_ids": [first.function_id],
                "evidence": [{"function_id": first.function_id, "line": 2,
                              "detail": "source observation"}],
            }],
            "requested_function_ids": [second.function_id],
            "context_complete": False, "rationale": "more source",
        }
        class SlowSecond:
            calls = 0
            async def complete_json(self, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    return first_response
                await asyncio.sleep(10)
        agent = BehaviorRecoveryAgent(
            SlowSecond(), graph, max_function_turns=2,
            checkpoint=lambda _id, state: checkpoint.append(state),
        )
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(agent.run([item]), timeout=0.02)
        self.assertEqual(len(checkpoint), 1)
        partial = agent.materialize(
            item, checkpoint[0]["opened_function_ids"],
            checkpoint[0]["raw_behaviors"], False,
        )
        self.assertEqual(len(partial), 1)
        self.assertIn("function context exploration incomplete", partial[0].unknowns)
        resumed_llm = ScriptedLLM([{
            "behaviors": [], "requested_function_ids": [],
            "context_complete": True, "rationale": "done",
        }])
        resumed = await BehaviorRecoveryAgent(
            resumed_llm, graph, max_function_turns=2,
            initial_state=checkpoint[0],
        ).run([item])
        self.assertEqual(len(resumed), 1)
        self.assertEqual(len(resumed_llm.calls), 1)
        self.assertEqual(resumed_llm.calls[0]["payload"]["current_function"]["function_id"],
                         second.function_id)

    async def test_later_function_turn_cannot_erase_earlier_reset_evidence(self) -> None:
        first = FunctionMetadata.create(
            name="acquire", signature="int acquire(void)", file="a.c", start_line=1,
            end_line=3, source="int acquire(void) {\n return consume();\n}\n",
        )
        second = FunctionMetadata.create(
            name="consume", signature="int consume(void)", file="a.c", start_line=4,
            end_line=6, source="int consume(void) {\n int local = 1;\n return local;\n}\n",
        )
        graph = GraphStore(AnalysisBundle(
            functions={first.function_id: first, second.function_id: second},
            edges=[], completeness={"provider": "test"},
        ))
        behavior = BehaviorCandidate(
            behavior_id="b", entry_id="e", entry_function_id=first.function_id,
            target_function_id=second.function_id, kind="computation", summary="return",
            path_function_ids=[first.function_id, second.function_id],
        )
        base = {
            "input_binding": "caller bytes", "calls": [], "prerequisite_bytes_hex": [],
            "isolation": "in_process_reset", "result_condition": "return",
            "requested_function_ids": [], "unknowns": [], "rationale": "source",
        }
        llm = ScriptedLLM([
            {**base, "context_complete": False,
             "repeatability_evidence": [{"function_id": first.function_id, "line": 2,
                                         "detail": "caller stack state"}]},
            {**base, "context_complete": True, "repeatability_evidence": []},
        ])
        snapshots = []
        contract = (await ExecutionContractAgent(
            llm, graph, max_function_turns=2,
            checkpoint=lambda _id, state: snapshots.append(state),
        ).run([behavior], {"e": "stdin"}))[0]
        self.assertTrue(contract.evidence_complete, contract.unknowns)
        self.assertEqual(len(contract.repeatability_evidence), 1)
        self.assertEqual(len(snapshots), 2)
        self.assertEqual(len(snapshots[-1]["accumulated"]["repeatability_evidence"]), 1)


if __name__ == "__main__":
    unittest.main()
