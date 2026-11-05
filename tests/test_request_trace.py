"""Positive and adversarial tests for request-correlated runtime evidence."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.models import (
    ActionActor, ActionExample, AnalysisBundle, Evidence, ExternalActionSchema, HarnessPlan, ProjectSpec,
    ProofStatus, ScenarioCandidate, ScenarioStatus, ScenarioStep,
)
from harnesscreator.runtime.contracts import audit_harness_plan
from harnesscreator.runtime.request_trace import RequestTraceJournal
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def events(data: bytes, *, function: str = "handler", connection: str = "client-1") -> list[dict]:
    return [
        dict(event="acquire", request_id="request-1", connection_id=connection,
             entry_function_id="input", request_sha256=digest(data)),
        dict(event="handler", request_id="request-1", connection_id=connection,
             handler_function_id=function),
    ]


class RequestTraceContractTests(unittest.TestCase):
    def test_split_request_is_attributed_only_with_complete_ordered_fragments(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            request = b"HELLO\n"
            first = dict(
                event="acquire_fragment", request_id="r-1", connection_id="c-1",
                entry_function_id="input", offset=0, data_hex=b"HE".hex(),
            )
            second = dict(
                event="acquire_fragment", request_id="r-1", connection_id="c-1",
                entry_function_id="input", offset=2, data_hex=b"LLO\n".hex(),
            )
            handler = dict(
                event="handler", request_id="r-1", connection_id="c-1",
                handler_function_id="handler",
            )

            def observe(rows):
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                return RequestTraceJournal(path).observe(
                    0, request, "input", "handler",
                )

            self.assertTrue(observe([first, second, handler]).target_reached)
            self.assertFalse(observe([first, handler]).target_reached)
            self.assertFalse(observe([first, handler, second]).target_reached)
            self.assertFalse(observe([second, first, handler]).target_reached)
            self.assertFalse(observe([
                first, {**second, "offset": 1}, handler,
            ]).target_reached)
            self.assertFalse(observe([
                first, {**second, "data_hex": b"LXO\n".hex()}, handler,
            ]).target_reached)
            self.assertFalse(observe([
                first, {**second, "connection_id": "other"}, handler,
            ]).target_reached)
            self.assertFalse(observe([
                first, {**second, "data_hex": ["invalid"]}, handler,
            ]).target_reached)
            self.assertFalse(observe([
                first, second, dict(
                    event="acquire", request_id="r-1", connection_id="c-1",
                    entry_function_id="input", request_sha256=digest(request),
                ), handler,
            ]).target_reached)
            another = [
                {**first, "request_id": "r-2"},
                {**second, "request_id": "r-2"},
                {**handler, "request_id": "r-2"},
            ]
            self.assertFalse(observe([first, second, handler, *another]).target_reached)

    def test_explicit_result_outcome_requires_matching_response(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            journal = RequestTraceJournal(path)
            request = b"S\n"
            rows = events(request) + [
                dict(event="result", request_id="request-1", connection_id="client-1",
                     response_sha256=digest(b""), state_digest=digest(b"updated"),
                     outcome="success", success_function_id="handler", success_line=42),
            ]
            def observe():
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                return journal.observe(
                    0, request, "input", "handler", response=b"",
                    success_sites=(("handler", 42),),
                )
            self.assertIn("semantic-outcome:success", observe().trace)
            self.assertFalse(journal.observe(
                0, request, "input", "handler", response=b"",
            ).target_reached)
            rows[-1]["success_line"] = 43
            self.assertFalse(observe().target_reached)
            rows[-1]["success_line"] = 42
            rows[-1]["connection_id"] = "other-client"
            self.assertNotIn("semantic-outcome:success", observe().trace)
            rows[-1]["connection_id"] = "client-1"
            observe()
            self.assertFalse(journal.observe(
                0, request, "input", "handler", response=b"different",
            ).target_reached)
            rows[-1]["outcome"] = "failure"
            self.assertNotIn("semantic-outcome:success", observe().trace)
            rows[-1]["outcome"] = "uncertain"
            self.assertFalse(observe().target_reached)
            rows.pop()
            self.assertNotIn("semantic-outcome:success", observe().trace)

    def test_stateless_result_does_not_require_state_digest(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            request = b"NOOP\r\n"
            rows = events(request) + [
                dict(
                    event="result", request_id="request-1", connection_id="client-1",
                    response_sha256=digest(b"200 OK\r\n"), outcome="success",
                    success_function_id="handler", success_line=42,
                ),
            ]

            def observe():
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                return RequestTraceJournal(path).observe(
                    0, request, "input", "handler", response=b"200 OK\r\n",
                    success_sites=(("handler", 42),),
                )

            result = observe()
            self.assertTrue(result.target_reached)
            self.assertFalse(result.pending)
            self.assertIn("semantic-outcome:success", result.trace)
            self.assertNotIn("semantic-state:None", result.trace)
            rows[-1]["state_digest"] = "bad"
            self.assertFalse(observe().target_reached)

    def test_exact_request_and_handler_are_required(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            journal = RequestTraceJournal(path)
            def write(rows):
                path.write_text("".join(json.dumps(r) + "\n" for r in rows))
            write(events(b"GET a\n"))
            ok = journal.observe(0, b"GET a\n", "input", "handler")
            self.assertTrue(ok.entry_reached and ok.target_reached)
            self.assertFalse(journal.observe(0, b"GET b\n", "input", "handler").target_reached)
            self.assertFalse(journal.observe(0, b"GET a\n", "input", "other").target_reached)
            write(events(b"GET a\n", connection="A") + [
                dict(event="handler", request_id="request-1", connection_id="B",
                     handler_function_id="handler")
            ])
            # One request ID cannot identify both connection A and B, even
            # when a matching A handler event is also present.
            cross_connection = journal.observe(0, b"GET a\n", "input", "handler")
            self.assertFalse(cross_connection.target_reached)
            self.assertIn("multiple connections", cross_connection.problem)
            write([events(b"GET a\n")[0],
                   dict(event="handler", request_id="request-1", connection_id="B",
                        handler_function_id="handler")])
            self.assertFalse(journal.observe(0, b"GET a\n", "input", "handler").target_reached)

    def test_duplicate_id_and_missing_dispatch_cannot_be_proof(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            journal = RequestTraceJournal(path)
            path.write_text("".join(json.dumps(r) + "\n" for r in events(b"GET a\n")))
            self.assertFalse(journal.observe(
                0, b"GET a\n", "input", "handler", "dispatcher", require_dispatch=True,
            ).target_reached)
            dup = events(b"GET a\n")
            dup.insert(1, dict(dup[0]))
            path.write_text("".join(json.dumps(r) + "\n" for r in dup))
            self.assertFalse(journal.observe(0, b"GET a\n", "input", "handler").target_reached)
            rows = events(b"GET a\n")
            rows.insert(1, dict(event="dispatch", request_id="request-1",
                                connection_id="client-1", dispatcher_function_id="dispatcher"))
            path.write_text("".join(json.dumps(r) + "\n" for r in rows))
            self.assertTrue(journal.observe(
                0, b"GET a\n", "input", "handler", "dispatcher", require_dispatch=True,
            ).target_reached)

    def test_request_id_reused_on_later_step_cannot_attribute_target(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            journal = RequestTraceJournal(path)
            first = events(b"GET a\n")
            path.write_text("".join(json.dumps(row) + "\n" for row in first))
            self.assertTrue(journal.observe(
                0, b"GET a\n", "input", "handler",
            ).target_reached)
            next_offset = journal.offset()
            later = events(b"GET b\n")
            with path.open("a") as stream:
                stream.writelines(json.dumps(row) + "\n" for row in later)
            second = journal.observe(
                next_offset, b"GET b\n", "input", "handler",
            )
            self.assertFalse(second.target_reached)
            self.assertIn("reused", second.problem)

    def test_malformed_and_partial_events_do_not_create_proof(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "events.jsonl"
            journal = RequestTraceJournal(path)
            for data in (b'{bad\n', b'{}', b'"string"\n'):
                path.write_bytes(data)
                self.assertFalse(journal.observe(0, b"X", "input", "handler").target_reached)


class RealOriginalFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_stdin_program_attributes_two_reads_to_one_request(self):
        cc = shutil.which("cc")
        if cc is None:
            self.skipTest("C compiler required")
        source = r'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
static void emit_fragment(int offset, unsigned char byte) {
    const char *path = getenv("HARNESSCREATOR_TRACE_JSONL");
    if (!path) return;
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "{\"event\":\"acquire_fragment\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"entry_function_id\":\"__ENTRY__\",\"offset\":%d,\"data_hex\":\"%02x\"}\n", offset, byte);
    fclose(f);
}
static void emit_handler(void) {
    const char *path = getenv("HARNESSCREATOR_TRACE_JSONL");
    if (!path) return;
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "{\"event\":\"handler\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"handler_function_id\":\"__HANDLER__\"}\n");
    fclose(f);
}
int read_site(char *buf) {
    if (read(0, buf, 1) != 1) return 0;
    emit_fragment(0, (unsigned char)buf[0]);
    if (read(0, buf + 1, 1) != 1) return 0;
    emit_fragment(1, (unsigned char)buf[1]);
    return 1;
}
int handler_site(const char *buf) { return buf[0] == 'X' && buf[1] == '\n'; }
int main(void) {
    char buf[2];
    if (!read_site(buf)) return 0;
    if (!handler_site(buf)) return 0;
    emit_handler();
    write(1, "OK\n", 3);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "daemon.c"
            path.write_text(source)
            graph = GraphStore(StaticAnalyzer(root).index())
            names = {item.name: item for item in graph.bundle.functions.values()}
            entry = names["read_site"]
            handler = names["handler_site"]
            path.write_text(source.replace("__ENTRY__", entry.function_id)
                            .replace("__HANDLER__", handler.function_id))
            binary = root / "daemon"
            build = subprocess.run([cc, str(path), "-o", str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            entry_evidence = [Evidence(
                "source", entry.function_id, entry.file, entry.start_line,
                "two source reads acquire one logical request",
            )]
            success_evidence = [Evidence(
                "source", handler.function_id, handler.file, handler.start_line,
                "handler accepts X newline",
            )]
            action = ExternalActionSchema(
                action_id="X", entry_id="external", name="X", description="accept X",
                dispatcher_function_id=handler.function_id,
                handler_function_id=handler.function_id,
                discriminator="X", channel_kind="stdin", fields=[],
                examples=[ActionExample(b"X\n".hex(), {}, evidence=entry_evidence)],
                success_markers_hex=[b"OK\n".hex()], failure_markers_hex=[],
                evidence=[*entry_evidence, *success_evidence],
                inspected_function_ids=[entry.function_id, handler.function_id],
                status=ProofStatus.PROVEN_STATIC, source_api="read",
                success_evidence=success_evidence,
                entry_function_id=entry.function_id,
                entry_probe_evidence=entry_evidence,
                actor=ActionActor.LOCAL_PROCESS_INPUT,
            )
            candidate = ScenarioCandidate("split-read", "X", [
                ScenarioStep(0, "X", "external", b"X\n".hex(), {}, [b"OK\n".hex()]),
            ], ["external"], [], ["source-derived split read"])
            project = ProjectSpec(
                source_root=root, output_root=root / "outputs",
                scenario_command=[str(binary)], scenario_channel="stdin",
                scenario_attribution="trace", scenario_step_timeout=3.0,
            ).normalized()
            witness = await ScenarioRuntimeVerifier(
                project, [action], graph,
            ).verify(candidate)
            self.assertEqual(witness.status, ScenarioStatus.UNPROVEN,
                             witness.rationale)
            self.assertTrue(witness.observations[0].target_reached)
            self.assertIn("not bound to this request", witness.rationale)

    async def test_strict_gdb_only_mode_fails_before_launching_original(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            project = ProjectSpec(
                source_root=root, output_root=root / "out",
                scenario_command=[str(root / "missing-original-binary")],
                scenario_channel="stdin", scenario_attribution="gdb",
            ).normalized()
            candidate = ScenarioCandidate(
                "unattributed", "input", [
                    ScenarioStep(0, "input", "entry", b"X".hex(), {}, []),
                ], ["entry"], [], [],
            )
            result = await ScenarioRuntimeVerifier(
                project, [], GraphStore(AnalysisBundle(functions={}, edges=[])),
            ).verify(candidate)
            self.assertEqual(result.status, ScenarioStatus.UNPROVEN)
            self.assertIn("request attribution is unavailable", result.rationale)
            self.assertFalse(result.observations)

    async def test_real_compiled_c_program_attribution_and_unattributed_fallback(self):
        cc = shutil.which("cc")
        if cc is None or not Path("/usr/include/openssl/sha.h").exists():
            self.skipTest("C compiler and OpenSSL development headers required")
        # The fixture has no external sample request source. The request is
        # constructed in the test from the source's one-byte protocol contract.
        source = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
static void emit(const char *event, const char *digest) {
    const char *path = getenv("HARNESSCREATOR_TRACE_JSONL");
    if (!path) return;
    FILE *f = fopen(path, "a");
    if (!f) return;
    if (!strcmp(event, "acquire"))
        fprintf(f,"{\"event\":\"acquire\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"entry_function_id\":\"__ENTRY__\",\"request_sha256\":\"%s\"}\n",digest);
    else if (!strcmp(event, "handler"))
        fprintf(f,"{\"event\":\"handler\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"handler_function_id\":\"__HANDLER__\"}\n");
    else if (!strcmp(event, "failure"))
        fprintf(f,"{\"event\":\"result\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"response_sha256\":\"__OK_RESPONSE_DIGEST__\",\"state_digest\":\"6b9d7a02e6f588d275eb4f4f94f48d08983967d0d6d8bd6bc63089d5fd71a502\",\"outcome\":\"failure\"}\n");
    else if (!strcmp(event, "ok"))
        fprintf(f,"{\"event\":\"result\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"response_sha256\":\"__OK_RESPONSE_DIGEST__\"}\n");
    else
        fprintf(f,"{\"event\":\"result\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"response_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"state_digest\":\"6b9d7a02e6f588d275eb4f4f94f48d08983967d0d6d8bd6bc63089d5fd71a502\",\"outcome\":\"success\",\"success_function_id\":\"__SUCCESS_FUNCTION__\",\"success_line\":__SUCCESS_LINE__}\n");
    fclose(f);
}
int read_site(char *buf, size_t capacity) {
    return fgets(buf, capacity, stdin) != NULL;
}
int handler_site(const char *buf) {
    return !strcmp(buf,"X\n") || !strcmp(buf,"U\n") || !strcmp(buf,"S\n") || !strcmp(buf,"E\n") || !strcmp(buf,"F\n");
}
int main(void) {
    char buf[256];
    if (!read_site(buf, sizeof(buf))) return 0;
    unsigned char raw[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buf, strlen(buf), raw);
    char hex[SHA256_DIGEST_LENGTH*2+1];
    for (int i=0;i<SHA256_DIGEST_LENGTH;i++) sprintf(hex+i*2,"%02x",raw[i]);
    emit("acquire",hex);
    if (handler_site(buf)) {
        emit("handler",hex);
        if (!strcmp(buf,"X\n")) { puts("OK"); fflush(stdout); emit("ok",hex); }
        else if (!strcmp(buf,"U\n")) puts("OK");
        else if (!strcmp(buf,"F\n")) { puts("OK"); fflush(stdout); emit("failure",hex); }
        else emit("result",hex);
    }
    else puts("ERR");
    fflush(stdout);
    return !strcmp(buf,"E\n") ? 7 : 0;
}
'''
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "daemon.c").write_text(source)
            graph = GraphStore(StaticAnalyzer(root).index())
            names = {f.name: f for f in graph.bundle.functions.values()}
            entry_id = names["read_site"].function_id
            handler_id = names["handler_site"].function_id
            success_line = next(
                index for index, line in enumerate(source.splitlines(), 1)
                if 'else emit("result",hex);' in line
            )
            (root / "daemon.c").write_text(
                source.replace("__ENTRY__", entry_id)
                .replace("__HANDLER__", handler_id)
                .replace("__SUCCESS_FUNCTION__", names["main"].function_id)
                .replace("__SUCCESS_LINE__", str(success_line))
                .replace("__OK_RESPONSE_DIGEST__", digest(b"OK\n"))
            )
            binary = root / "daemon"
            build = subprocess.run([cc, str(root / "daemon.c"), "-lcrypto", "-o", str(binary)],
                                   capture_output=True, text=True)
            if build.returncode:
                self.skipTest(f"OpenSSL compiler library unavailable: {build.stderr}")
            evidence = [Evidence("source", entry_id, "daemon.c", names["read_site"].start_line, "original input acquisition")]
            action = ExternalActionSchema(
                action_id="X", entry_id="external", name="X", description="accept X",
                dispatcher_function_id=handler_id, handler_function_id=handler_id,
                discriminator="X", channel_kind="stdin", fields=[],
                examples=[ActionExample(b"X\n".hex(), {}, evidence=evidence)],
                success_markers_hex=[b"OK\n".hex()],
                failure_markers_hex=[b"ERR\n".hex()], evidence=evidence,
                inspected_function_ids=[entry_id, handler_id],
                status=ProofStatus.PROVEN_STATIC, source_api="fgets",
                success_evidence=evidence, entry_function_id=entry_id,
                actor=ActionActor.LOCAL_PROCESS_INPUT,
            )
            candidate = ScenarioCandidate("scenario-x", "X", [
                ScenarioStep(0, "X", "external", b"X\n".hex(), {}, [b"OK\n".hex()]),
            ], ["external"], [], ["source-derived protocol"])
            project = ProjectSpec(
                source_root=root, output_root=root / "outputs",
                scenario_command=[str(binary)], scenario_channel="stdin",
                scenario_attribution="trace", scenario_step_timeout=3.0,
            ).normalized()
            # Trace mode does not use GDB: the actual C binary writes events
            # from its acquisition and handler source locations.
            action.entry_probe_evidence = evidence
            result = await ScenarioRuntimeVerifier(project, [action], graph).verify(candidate)
            self.assertEqual(result.status, ScenarioStatus.PROVEN_RUNTIME, result.rationale)
            self.assertEqual(result.observations[0].response_hex, b"OK\n".hex())
            self.assertTrue(result.observations[0].target_reached)
            self.assertFalse(any(
                item.startswith("semantic-state:")
                for item in result.observations[0].probe_trace
            ))
            unbound_action = replace(
                action, action_id="U", name="unbound response",
                examples=[ActionExample(b"U\n".hex(), {}, evidence=evidence)],
            )
            unbound_candidate = ScenarioCandidate("scenario-u", "U", [
                ScenarioStep(0, "U", "external", b"U\n".hex(), {}, [b"OK\n".hex()]),
            ], ["external"], [], ["source-derived response marker"])
            unbound = await ScenarioRuntimeVerifier(
                project, [unbound_action], graph,
            ).verify(unbound_candidate)
            self.assertEqual(unbound.status, ScenarioStatus.UNPROVEN, unbound.rationale)
            self.assertTrue(unbound.observations[0].target_reached)
            self.assertIn("not bound to this request", unbound.rationale)
            contradictory_action = replace(
                action, action_id="F", name="contradictory result",
                examples=[ActionExample(b"F\n".hex(), {}, evidence=evidence)],
            )
            contradictory_candidate = ScenarioCandidate("scenario-f", "F", [
                ScenarioStep(0, "F", "external", b"F\n".hex(), {}, [b"OK\n".hex()]),
            ], ["external"], [], ["source-derived response marker"])
            contradictory = await ScenarioRuntimeVerifier(
                project, [contradictory_action], graph,
            ).verify(contradictory_candidate)
            self.assertNotEqual(contradictory.status, ScenarioStatus.PROVEN_RUNTIME)
            self.assertIn("semantic-outcome:failure", contradictory.observations[0].probe_trace)
            silent_action = replace(
                action, action_id="S", name="silent S",
                examples=[ActionExample(b"S\n".hex(), {}, evidence=evidence)],
                success_markers_hex=[], failure_markers_hex=[],
                success_evidence=[
                    Evidence("source", names["main"].function_id, "daemon.c",
                             success_line, "S completion path"),
                ],
            )
            silent_candidate = ScenarioCandidate("scenario-s", "S", [
                ScenarioStep(0, "S", "external", b"S\n".hex(), {}, []),
            ], ["external"], [], ["source-derived completion"])
            silent = await ScenarioRuntimeVerifier(
                project, [silent_action], graph,
            ).verify(silent_candidate)
            self.assertEqual(silent.status, ScenarioStatus.PROVEN_RUNTIME, silent.rationale)
            self.assertFalse(silent.observations[0].response_success)
            self.assertIn("semantic-outcome:success", silent.observations[0].probe_trace)
            plan = HarnessPlan(
                "silent-plan", silent.witness_id, silent.scenario_id, "S",
                [], silent.steps[0], [handler_id], [entry_id],
                "raw_final_request", "fresh_process", "fixture", 0, 64,
                fuzz_step_index=0,
            )
            audit = audit_harness_plan(silent, plan)
            self.assertTrue(audit.passed, audit.failures)
            forged = replace(silent, observations=[
                replace(silent.observations[0], probe_trace=["semantic-outcome:success"],
                        target_probe="injected runtime target observer"),
            ])
            self.assertFalse(audit_harness_plan(forged, plan).passed)
            unsupported = replace(silent_action, success_evidence=[])
            without_source = await ScenarioRuntimeVerifier(
                project, [unsupported], graph,
            ).verify(silent_candidate)
            self.assertNotEqual(without_source.status, ScenarioStatus.PROVEN_RUNTIME)
            error_exit = ScenarioCandidate("scenario-e", "S", [
                ScenarioStep(0, "S", "external", b"E\n".hex(), {}, []),
            ], ["external"], [], [])
            failed_process = await ScenarioRuntimeVerifier(
                project, [silent_action], graph,
            ).verify(error_exit)
            self.assertEqual(failed_process.status, ScenarioStatus.UNPROVEN)
            self.assertIn("nonzero status", failed_process.rationale)
            bad = ScenarioCandidate("scenario-bad", "X", [
                ScenarioStep(0, "X", "external", b"Y\n".hex(), {}, [b"OK\n".hex()]),
            ], ["external"], [], [])
            rejected = await ScenarioRuntimeVerifier(project, [action], graph).verify(bad)
            self.assertNotEqual(rejected.status, ScenarioStatus.PROVEN_RUNTIME)
            # No GDB and no source trace: only an exploratory response-only
            # result may be preserved. Never call it a validated witness.
            no_trace = ProjectSpec(
                source_root=root, output_root=root / "outputs",
                scenario_command=[str(binary)], scenario_channel="stdin",
                scenario_attribution="gdb", scenario_exploratory_drafts=True,
            ).normalized()
            replay = await ScenarioRuntimeVerifier(no_trace, [action], graph).verify(candidate)
            self.assertEqual(replay.status, ScenarioStatus.REPLAYED_RUNTIME, replay.rationale)
            self.assertFalse(replay.observations[0].target_reached)
            injected = await ScenarioRuntimeVerifier(
                no_trace, [action], graph,
                target_observer=lambda *_args: True,
            ).verify(candidate)
            self.assertEqual(injected.status, ScenarioStatus.OBSERVED_RUNTIME, injected.rationale)
            self.assertEqual(
                injected.observations[0].target_probe,
                "injected runtime target observer",
            )
