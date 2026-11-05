from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harnesscreator.agents.harness import CHECKLIST_NAMES
from harnesscreator.agents.entry import EntryGeneratorAgent
from harnesscreator.agents.scenario import InputActionAgent
from harnesscreator.analysis import StaticAnalyzer
from harnesscreator.analysis.usage_evidence import UsageEvidenceBundle
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import ProjectSpec, ProofStatus
from harnesscreator.orchestrator import HarnessCreator, _scenario_transport_blocker
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier


class ScenarioOrchestratorIntegrationTest(unittest.IsolatedAsyncioTestCase):
    def test_transport_count_does_not_call_mismatched_cases_executable(self) -> None:
        actions = {
            "tcp": SimpleNamespace(channel_kind="IPv4 TCP socket", source_api="recv"),
            "file": SimpleNamespace(channel_kind="file", source_api="read"),
        }
        tcp = SimpleNamespace(steps=[SimpleNamespace(action_id="tcp")])
        file = SimpleNamespace(steps=[SimpleNamespace(action_id="file")])
        mixed = SimpleNamespace(steps=[
            SimpleNamespace(action_id="tcp"), SimpleNamespace(action_id="file"),
        ])
        self.assertEqual(_scenario_transport_blocker(tcp, actions, "tcp"), "")
        self.assertIn("selected original-program executor uses tcp",
                      _scenario_transport_blocker(file, actions, "tcp"))
        self.assertIn("different original-program transports",
                      _scenario_transport_blocker(mixed, actions, "auto"))

    async def test_network_build_mismatch_stops_before_source_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            afl = root / "afl-fuzz"
            afl.write_text("#!/bin/sh\nexit 0\n")
            afl.chmod(0o755)
            server = root / "server"
            server.write_bytes(b"instrumented fixture")
            server.chmod(0o755)
            build = root / "build.json"
            build.write_text(json.dumps({
                "source_root": str(root / "different-source"),
                "server_binary": str(server),
                "server_sha256": hashlib.sha256(server.read_bytes()).hexdigest(),
                "afl_coverage_object_detected": True,
                "afl_runtime_symbol_detected": True,
            }))
            config = root / "network.json"
            config.write_text(json.dumps({
                "afl_fuzz": str(afl), "server_build_manifest": str(build),
                "server_command": [str(server)], "transport": "tcp",
                "host": "127.0.0.1", "port": 9010, "seconds": 2,
                "seed_tier": "proven",
            }))
            provider = ScriptedLLM([])
            project = ProjectSpec(
                source_root=source, output_root=root / "runs",
                network_harness_config=config,
            )
            with patch.object(
                HarnessCreator, "_prepare_static_analysis",
                side_effect=AssertionError("source analysis must not start"),
            ):
                with self.assertRaisesRegex(ValueError, "different source checkout"):
                    await HarnessCreator(project, provider).run()
            self.assertFalse(provider.calls)

    async def test_strict_gdb_configuration_keeps_source_analysis_available(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provider = ScriptedLLM([])
            project = ProjectSpec(
                source_root=root, output_root=root / "runs",
                scenario_command=[str(root / "original")],
                scenario_channel="stdin", scenario_attribution="gdb",
            )
            with patch.object(
                HarnessCreator, "_prepare_static_analysis",
                side_effect=RuntimeError("source analysis reached"),
            ):
                with self.assertRaisesRegex(RuntimeError, "source analysis reached"):
                    await HarnessCreator(project, provider).run()
            self.assertFalse(provider.calls)
            self.assertTrue((root / "runs").exists())

    async def test_original_runtime_witness_drives_a_real_sanitized_build(self) -> None:
        cc = shutil.which("cc")
        cxx = shutil.which("g++") or shutil.which("clang++")
        if cc is None or cxx is None:
            self.skipTest("a C compiler and a C++ compiler are required")
        if not Path("/usr/include/openssl/sha.h").exists():
            self.skipTest("OpenSSL development headers are required for the real request trace")

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            source_root = temporary_root / "source"
            output_root = temporary_root / "runs"
            source_root.mkdir()
            target = source_root / "target.c"
            target.write_text(
                "#include <stddef.h>\n"
                "#include <stdio.h>\n"
                "#ifndef HARNESS_BUILD\n"
                "void trace_acquire(const unsigned char *, size_t);\n"
                "void trace_handler(void);\n"
                "void trace_result(void);\n"
                "#endif\n"
                "#ifdef __cplusplus\n"
                "extern \"C\" {\n"
                "#endif\n"
                "int handle(const unsigned char *data, size_t size) {\n"
                "    if (size == 0) return 0;\n"
                "    if (size > 32) return 0;\n"
                "    if (data[0] == 0) return 0;\n"
                "    return data[0] == 'X';\n"
                "}\n"
                "int dispatch(const unsigned char *data, size_t size) {\n"
                "    if (size == 0) return 0;\n"
                "    switch (data[0]) {\n"
                "    case 'X':\n"
                "        return handle(data, size);\n"
                "    default:\n"
                "        return 0;\n"
                "    }\n"
                "}\n"
                "int process_once(FILE *input, FILE *output) {\n"
                "    unsigned char byte = 0;\n"
                "    if (fread(&byte, 1, 1, input) != 1) return 0;\n"
                "#ifndef HARNESS_BUILD\n"
                "    trace_acquire(&byte, 1);\n"
                "#endif\n"
                "    if (dispatch(&byte, 1)) {\n"
                "#ifndef HARNESS_BUILD\n"
                "        trace_handler();\n"
                "        trace_result();\n"
                "#endif\n"
                "        fwrite(\"OK\\n\", 1, 3, output);\n"
                "    } else {\n"
                "        fwrite(\"ERR\\n\", 1, 4, output);\n"
                "    }\n"
                "    fflush(output);\n"
                "    return 1;\n"
                "}\n"
                "#ifdef __cplusplus\n"
                "}\n"
                "#endif\n"
                "#ifndef HARNESS_BUILD\n"
                "int main(void) {\n"
                "    while (process_once(stdin, stdout)) {}\n"
                "    return 0;\n"
                "}\n"
                "#endif\n",
                encoding="utf-8",
            )
            bundle = StaticAnalyzer(source_root).index()
            by_name = {function.name: function for function in bundle.functions.values()}
            process_once = by_name["process_once"]
            dispatch = by_name["dispatch"]
            handle = by_name["handle"]
            fread_line = next(
                process_once.start_line + index
                for index, line in enumerate(process_once.source.splitlines())
                if "fread(" in line
            )
            trace_source = r'''
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
static FILE *trace_file(void) {
    const char *path = getenv("HARNESSCREATOR_TRACE_JSONL");
    return path ? fopen(path, "a") : NULL;
}
void trace_acquire(const unsigned char *data, size_t size) {
    FILE *out = trace_file();
    if (!out) return;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256(data, size, digest);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hex + i * 2, "%02x", digest[i]);
    fprintf(out, "{\"event\":\"acquire\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"entry_function_id\":\"__ENTRY__\",\"request_sha256\":\"%s\"}\n", hex);
    fclose(out);
}
void trace_handler(void) {
    FILE *out = trace_file();
    if (!out) return;
    fprintf(out, "{\"event\":\"handler\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"handler_function_id\":\"__HANDLER__\"}\n");
    fclose(out);
}
void trace_result(void) {
    FILE *out = trace_file();
    if (!out) return;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256((const unsigned char *)"OK\n", 3, digest);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hex + i * 2, "%02x", digest[i]);
    fprintf(out, "{\"event\":\"result\",\"request_id\":\"r-1\",\"connection_id\":\"stdin-1\",\"response_sha256\":\"%s\",\"state_digest\":\"6b9d7a02e6f588d275eb4f4f94f48d08983967d0d6d8bd6bc63089d5fd71a502\"}\n", hex);
    fclose(out);
}
'''
            trace_file = temporary_root / "trace.c"
            trace_file.write_text(
                trace_source.replace("__ENTRY__", process_once.function_id).replace(
                    "__HANDLER__", handle.function_id,
                ),
                encoding="utf-8",
            )
            original = source_root / "original"
            subprocess.run(
                [cc, "-std=c11", "-g", "-O0", str(target), str(trace_file),
                 "-lcrypto", "-o", str(original)],
                check=True, capture_output=True, text=True,
            )

            evidence = lambda function, detail: {
                "kind": "source",
                "function_id": function.function_id,
                "line": function.start_line,
                "detail": detail,
            }
            action = {
                "name": "X request",
                "description": "send X through the real input dispatcher",
                "dispatcher_function_id": dispatch.function_id,
                "handler_function_id": handle.function_id,
                "discriminator": "'X'",
                "fields": [{
                    "name": "opcode",
                    "offset": 0,
                    "width": 1,
                    "encoding": "byte",
                    "binding": "",
                    "relation": "equals ASCII X",
                    "evidence": [evidence(handle, "handler checks the first byte for X")],
                }],
                "examples": [],
                "success_markers_hex": [b"OK\n".hex()],
                "failure_markers_hex": [b"ERR\n".hex()],
                "success_evidence": [
                    evidence(process_once, "successful dispatch emits literal OK response")
                ],
                "failure_evidence": [
                    evidence(process_once, "failed dispatch emits literal ERR response")
                ],
                "evidence": [
                    evidence(dispatch, "switch case X invokes handle"),
                    evidence(handle, "real handler consumes the request byte"),
                ],
                "unknowns": [],
                "confidence": 0.99,
                "action_context_complete": True,
            }
            context_response = {
                "context_complete": True,
                "requested_function_ids": [],
                "established_facts": ["the public handler accepts raw bytes and length"],
                "blocking_dependencies": [],
                "rationale": "all required source roots are available",
            }
            harness_code = (
                "#include <stddef.h>\n"
                "#include <stdint.h>\n"
                "#include <stdio.h>\n"
                "extern \"C\" int process_once(FILE *, FILE *);\n"
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n"
                "    if (Size < 1) return 0;\n"
                "    const uint8_t *hc_fuzz_request = Data;\n"
                "    size_t hc_fuzz_request_size = Size;\n"
                "    FILE *input = tmpfile();\n"
                "    FILE *output = tmpfile();\n"
                "    if (input == nullptr || output == nullptr) {\n"
                "        if (input != nullptr) fclose(input);\n"
                "        if (output != nullptr) fclose(output);\n"
                "        return 0;\n"
                "    }\n"
                "    if (fwrite(hc_fuzz_request, 1, hc_fuzz_request_size, input) != hc_fuzz_request_size) {\n"
                "        fclose(input);\n"
                "        fclose(output);\n"
                "        return 0;\n"
                "    }\n"
                "    rewind(input);\n"
                "    int status = process_once(input, output);\n"
                "    fclose(input);\n"
                "    fclose(output);\n"
                "    if (status < 0) return 0;\n"
                "    return 0;\n"
                "}\n"
            )
            generator_audit = [
                {"check_id": check_id, "status": "PASS", "evidence": "fixture source evidence"}
                for check_id in CHECKLIST_NAMES
            ]
            independent_audit = [
                {
                    "check_id": check_id,
                    "status": "PASS",
                    "evidence": "independent fixture audit",
                    "remediation": "",
                }
                for check_id in CHECKLIST_NAMES
            ]
            responses = [
                # Entry Generator broad pass. The deterministic fread candidate remains.
                *[
                    {
                        "candidates": [],
                        "inspected_function_ids": [
                            function.function_id for function, _ in batch
                        ],
                    }
                    for batch in EntryGeneratorAgent(
                        ScriptedLLM([]), chunk_size=32,
                    ).batches(bundle)
                ],
                {
                    "status": "VERIFIED",
                    "channel_kind": "stdin",
                    "attacker_control": "full",
                    "provenance_path": [{
                        "function_id": process_once.function_id,
                        "relation": "fread first copies stdin bytes into program storage",
                    }],
                    "consumer_hints": [],
                    "evidence": [{
                        "kind": "source",
                        "function_id": process_once.function_id,
                        "file": process_once.file,
                        "line": fread_line,
                        "detail": "fread acquires the external byte into byte",
                    }],
                    "unknowns": [],
                    "confidence": 0.99,
                    "rationale": "this fread call is the first data acquisition",
                    "first_acquisition_confirmed": True,
                    "context_complete": True,
                    "requested_function_ids": [],
                },
                # Discover the Action before constructing a trial request.
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [dispatch.function_id],
                    "rationale": "follow the acquired byte to the dispatcher",
                },
                {
                    "actions": [], "context_complete": False,
                    "requested_function_ids": [handle.function_id],
                    "rationale": "open the X handler before claiming an Action",
                },
                # One Entry-scoped source walk now produces the semantic
                # operation; no switch-case worker is launched.
                {
                    "actions": [action], "context_complete": True,
                    "requested_function_ids": [],
                    "rationale": "handler and response proven",
                },
                {
                    "decision": "KEEP", "reason": "the X request reaches a substantive handler",
                    "source_evidence": [],
                },
                {
                    "decision": "CONTINUE", "examples": [], "fields": [],
                    "requested_function_id": "", "reason": "open selector",
                    "drop_evidence": [],
                },
                {
                    "decision": "CONTINUE", "examples": [], "fields": [],
                    "requested_function_id": "", "reason": "open handler",
                    "drop_evidence": [],
                },
                {
                    "decision": "READY", "examples": [{
                        "data_hex": b"X".hex(), "bindings": [],
                        "rationale": "complete one-byte external request",
                        "origin": "model_input_hypothesis",
                        "evidence": [evidence(handle, "handler checks the request byte")],
                    }], "fields": [],
                    "requested_function_id": "", "reason": "X request is source-backed",
                    "drop_evidence": [],
                },
                context_response,
                context_response,
                context_response,
                {
                    "code": harness_code,
                    "manifest": {
                        "build_target": "UNRESOLVED",
                        "headers": [],
                        "libraries": [],
                        "min_size": 1,
                        "max_size": 4096,
                        "execution_model": "in_process_reset",
                    },
                    "checklist": generator_audit,
                    "implemented_step_indexes": [0],
                    "generation_blockers": [],
                },
                {
                    "consumes": [],
                    "produces": [],
                    "invalidates": [],
                    "initial_resources": [],
                    "success_condition": "handle returns one for X",
                    "evidence": [evidence(handle, "handler success is stateless")],
                    "unknowns": [],
                    "context_complete": True,
                    "requested_function_ids": [],
                    "rationale": "no predecessor state is required",
                },
                {
                    "context_complete": False, "requested_function_ids": [],
                    "rationale": "inspect the remaining required application functions",
                },
                {
                    "context_complete": False, "requested_function_ids": [],
                    "rationale": "inspect the remaining required application function",
                },
                {
                    "context_complete": True, "requested_function_ids": [],
                    "rationale": "independent source review complete",
                },
                {"checks": independent_audit, "summary": "all checks pass"},
            ]
            # A source-backed Action with a replayed original response can
            # also produce an explicitly unqualified draft before the
            # separate state analysis. Without source-draft mode, GDB-only
            # observations still do not trigger early generation.
            legacy_responses = list(responses)
            state_index = next(
                index for index, item in enumerate(legacy_responses)
                if "consumes" in item
            )
            state_response = legacy_responses.pop(state_index)
            first_harness_context = next(
                index for index, item in enumerate(legacy_responses)
                if item is context_response
            )
            legacy_responses.insert(first_harness_context, state_response)
            provider = ScriptedLLM(responses)
            driver = Path(__file__).parent / "fixtures" / "fuzz_driver.cc"
            project = ProjectSpec(
                source_root=source_root,
                output_root=output_root,
                name="scenario-integration",
                require_fuzz_introspector=False,
                svf_enabled=False,
                verification_backend="command",
                build_command=[
                    cxx,
                    "-std=c++17",
                    "-DHARNESS_BUILD",
                    "-fsanitize=address,undefined",
                    "{harness}",
                    "{source_root}/target.c",
                    str(driver),
                    "-o",
                    "{output}/fuzz_target",
                ],
                harness_binary="{output}/fuzz_target",
                harness_source_filename="fuzz_target.cc",
                scenario_command=[str(original)],
                scenario_channel="stdin",
                scenario_attribution="trace",
                max_context_functions=8,
                context_depth=2,
            )
            summary = await HarnessCreator(
                project,
                provider,
                max_generation_attempts=1,
                dynamic_verification=False,
                precomputed_analysis=bundle,
                precomputed_usage_evidence=UsageEvidenceBundle(),
            ).run()

            # The named X operation is built after Action selection and
            # per-Action request recovery.
            self.assertEqual(summary.status, "BUILD_VERIFIED_DRAFT_PARTIAL")
            selection_index = next(
                index for index, call in enumerate(provider.calls)
                if "source_functions" in call["payload"]
                and "action" in call["payload"]
            )
            self.assertLess(selection_index, next(
                index for index, call in enumerate(provider.calls)
                if call["role"] == "harness_generator"
            ))
            self.assertLess(selection_index, next(
                index for index, call in enumerate(provider.calls)
                if call["role"] == "state_dependency"
            ))
            request_index = next(
                index for index, call in enumerate(provider.calls)
                if "required_anchors_remaining" in call["payload"]
                and "action" in call["payload"]
            )
            self.assertLess(selection_index, request_index)
            self.assertLess(request_index, next(
                index for index, call in enumerate(provider.calls)
                if call["role"] == "harness_generator"
            ))
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in provider.calls if call["role"] == "input_surface"],
                [],
            )
            self.assertEqual(
                [call["payload"]["current_function"]["name"]
                 for call in provider.calls if call["role"] == "input_action"
                 and "round" in call["payload"]],
                # Several handler guards still describe one external X request.
                ["process_once", "dispatch", "handle"],
            )
            self.assertEqual(summary.verified_entries, 1)
            self.assertEqual(summary.action_schemas, 1)
            self.assertEqual(summary.state_contracts, 1)
            self.assertEqual(summary.scenario_candidates, 1)
            self.assertEqual(summary.scenario_witnesses, 1)
            self.assertEqual(summary.harness_plans, 1)
            self.assertEqual(summary.generation_attempts, 1)
            self.assertEqual(summary.harnesses_generated, 1)
            self.assertEqual(summary.harnesses_static_passed, 1)
            self.assertEqual(summary.harnesses_build_passed, 1)
            self.assertEqual(summary.harnesses_blocked, 0)
            self.assertFalse(provider.responses, "every scripted stage must be consumed")

            run_root = Path(summary.output_root)
            roles = [call["role"] for call in provider.calls]
            self.assertLess(
                roles.index("harness_generator"),
                roles.index("state_dependency"),
            )
            early = json.loads(
                (run_root / "workflow/early-harness-preflight.json").read_text()
            )
            self.assertEqual(early["runtime_proven"], 1)
            self.assertEqual(len(early["early_harness_drafts"]), 1)
            self.assertGreaterEqual(early["one_shot_candidates_tried"], 1)
            raw_trials = json.loads(
                (run_root / "input-surfaces/runtime-trials.json").read_text()
            )
            self.assertEqual(raw_trials["tried"], 0)
            self.assertEqual(raw_trials["witnesses"], [])
            action_inventory = [
                json.loads(line) for line in
                (run_root / "actions/inventory.jsonl").read_text().splitlines()
            ]
            self.assertEqual(
                {item["name"] for item in action_inventory},
                {"X request"},
            )
            self.assertEqual(
                json.loads((run_root / "workflow.json").read_text(encoding="utf-8"))[
                    "workflow_mode"
                ],
                "action",
            )
            witness_files = list(run_root.glob("scenarios/witnesses/*.json"))
            harness_files = list(run_root.glob("harnesses/*/attempt-*/fuzz_target.cc"))
            # The original is first tested after Action selection and
            # per-Action request recovery.
            self.assertEqual(len(witness_files), 1)
            self.assertEqual(len(harness_files), 1)
            witness = next(
                item for item in (
                    json.loads(path.read_text(encoding="utf-8"))
                    for path in witness_files
                ) if item["status"] == "PROVEN_RUNTIME"
            )
            self.assertEqual(witness["status"], "PROVEN_RUNTIME")
            self.assertEqual(witness["observations"][0]["response_hex"], b"OK\n".hex())
            # The new Scenario pipeline must update the Action ledger itself;
            # the earlier legacy pipeline's generated_by_action is unreachable.
            lifecycle_path = run_root / "workflow/candidate-lifecycle.jsonl"
            records = [json.loads(line) for line in lifecycle_path.read_text().splitlines()]
            self.assertEqual(len(records), 1)
            named_action_id = next(
                item["action_id"] for item in action_inventory
                if item["name"] == "X request"
            )
            named_record = next(
                item for item in records if item["action_id"] == named_action_id
            )
            self.assertEqual(named_record["disposition"], "BUILD_VERIFIED_EQUIVALENCE_UNKNOWN")
            self.assertEqual(len(named_record["generated_harness_ids"]), 1)
            self.assertEqual(len(named_record["build_verified_ids"]), 1)
            self.assertEqual(named_record["semantic_verified_ids"], [])
            self.assertEqual(json.loads(
                (run_root / "actions/selection.jsonl").read_text().splitlines()[0]
            )["disposition"], "KEEP")

            # A callback/points-to analysis can leave the same source-backed
            # Action POSSIBLE. The correlated original trace must still get a
            # chance to confirm its real request path before generation.
            original_validate = InputActionAgent._validate_actions

            def uncertain_static_path(agent, *args, **kwargs):
                return [replace(
                    item, status=ProofStatus.POSSIBLE,
                    unknowns=[*item.unknowns, "indirect call target unresolved"],
                ) for item in original_validate(agent, *args, **kwargs)]

            uncertain_project = replace(
                project, output_root=temporary_root / "uncertain-runs",
            )
            uncertain_provider = ScriptedLLM(responses)
            with patch.object(InputActionAgent, "_validate_actions", uncertain_static_path):
                uncertain_summary = await HarnessCreator(
                    uncertain_project,
                    uncertain_provider,
                    max_generation_attempts=1,
                    dynamic_verification=False,
                    precomputed_analysis=bundle,
                    precomputed_usage_evidence=UsageEvidenceBundle(),
                ).run()
            self.assertEqual(uncertain_summary.scenario_candidates, 1)
            self.assertEqual(uncertain_summary.scenario_witnesses, 1)
            self.assertEqual(uncertain_summary.harnesses_build_passed, 1)
            self.assertFalse(uncertain_provider.responses)
            uncertain_root = Path(uncertain_summary.output_root)
            uncertain_actions = [
                json.loads(line) for line in
                (uncertain_root / "actions/inventory.jsonl").read_text().splitlines()
            ]
            self.assertEqual(next(
                item["status"] for item in uncertain_actions
                if item["name"] == "X request"
            ), "POSSIBLE")
            uncertain_witnesses = [
                json.loads(path.read_text()) for path in
                uncertain_root.glob("scenarios/witnesses/*.json")
            ]
            self.assertTrue(any(
                item["status"] == "PROVEN_RUNTIME"
                for item in uncertain_witnesses
            ))

            # Without a request-correlated trace the same source-backed
            # POSSIBLE Action is still tried on the original, but its response
            # must never qualify a harness or impersonate handler proof.
            gdb_project = replace(
                project, output_root=temporary_root / "gdb-runs",
                scenario_attribution="gdb",
            )
            gdb_provider = ScriptedLLM(legacy_responses)
            with patch.object(InputActionAgent, "_validate_actions", uncertain_static_path):
                gdb_summary = await HarnessCreator(
                    gdb_project,
                    gdb_provider,
                    max_generation_attempts=1,
                    dynamic_verification=False,
                    precomputed_analysis=bundle,
                    precomputed_usage_evidence=UsageEvidenceBundle(),
                ).run()
            gdb_witnesses = [
                json.loads(path.read_text()) for path in
                Path(gdb_summary.output_root).glob("scenarios/witnesses/*.json")
            ]
            self.assertTrue(any(
                item["target_action_id"] == named_action_id
                and item["status"] == "UNPROVEN"
                and "strict request attribution is unavailable" in item["rationale"]
                for item in gdb_witnesses
            ))
            self.assertFalse(any(
                item["status"] == "PROVEN_RUNTIME" for item in gdb_witnesses
            ))
            state_calls = [
                call for call in gdb_provider.calls
                if call["role"] == "state_dependency"
            ]
            self.assertTrue(state_calls)
            self.assertTrue(
                state_calls[0]["payload"]["original_trial_feedback"]
            )
            self.assertEqual(gdb_summary.harnesses_generated, 0)
            gdb_early = json.loads(
                (Path(gdb_summary.output_root)
                 / "workflow/early-harness-preflight.json").read_text()
            )
            self.assertEqual(gdb_early["early_harness_drafts"], [])

            # A normal binary without request trace hooks can still yield a
            # buildable investigation draft when explicitly requested. The
            # draft must remain unqualified until original request causality
            # and semantic equivalence are independently established.
            no_trace_stub = temporary_root / "no_trace_stub.c"
            no_trace_stub.write_text(
                "#include <stddef.h>\n"
                "void trace_acquire(const unsigned char *p, size_t n) "
                "{ (void)p; (void)n; }\n"
                "void trace_handler(void) {}\n"
                "void trace_result(void) {}\n",
                encoding="utf-8",
            )
            original_no_trace = source_root / "original_no_trace"
            subprocess.run(
                [cc, "-std=c11", "-g", "-O0", str(target),
                 str(no_trace_stub), "-o", str(original_no_trace)],
                check=True, capture_output=True, text=True,
            )
            draft_project = replace(
                project,
                output_root=temporary_root / "source-draft-runs",
                scenario_command=[str(original_no_trace)],
                scenario_attribution="gdb",
                scenario_source_drafts=True,
            )
            draft_provider = ScriptedLLM(responses)
            draft_summary = await HarnessCreator(
                draft_project,
                draft_provider,
                max_generation_attempts=1,
                dynamic_verification=False,
                precomputed_analysis=bundle,
                precomputed_usage_evidence=UsageEvidenceBundle(),
            ).run()
            self.assertGreaterEqual(
                draft_summary.harnesses_generated, 1,
                msg=(
                    f"status={draft_summary.status}; roles={[call['role'] for call in draft_provider.calls]}; "
                    f"preflight={json.loads((Path(draft_summary.output_root) / 'workflow/early-harness-preflight.json').read_text())}"
                ),
            )
            self.assertGreaterEqual(draft_summary.harnesses_build_passed, 1)
            self.assertEqual(draft_summary.harnesses_qualified, 0)
            draft_roles = [call["role"] for call in draft_provider.calls]
            self.assertLess(
                draft_roles.index("harness_generator"),
                draft_roles.index("state_dependency"),
            )
            draft_root = Path(draft_summary.output_root)
            self.assertTrue(list(draft_root.glob("harnesses/preflight/*/fuzz_target.cc")))
            early_draft_report = json.loads(
                (draft_root / "workflow/early-harness-preflight.json").read_text()
            )
            self.assertEqual(len(early_draft_report["early_harness_drafts"]), 1)
            source_only_status_files = list(
                Path(draft_summary.output_root).glob(
                    "harnesses/*/attempt-*/source-only-status.json"
                )
            )
            self.assertTrue(source_only_status_files)
            self.assertTrue(all(
                json.loads(path.read_text())["qualified"] is False
                for path in source_only_status_files
            ))
            seed = temporary_root / "source-draft-seed"
            seed.write_bytes(b"X")
            draft_binaries = list(Path(draft_summary.output_root).glob(
                "harnesses/*/attempt-*/fuzz_target"
            ))
            self.assertTrue(draft_binaries)
            execution = subprocess.run(
                [str(draft_binaries[0]), str(seed)],
                capture_output=True, text=True, timeout=10,
                env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"},
            )
            self.assertEqual(execution.returncode, 0, execution.stderr)


if __name__ == "__main__":
    unittest.main()
