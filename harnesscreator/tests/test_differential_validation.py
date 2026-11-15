"""Actual libFuzzer binary compared against a source-supplied semantic oracle."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from harnesscreator.models import (
    CommandReport, HarnessDraft, HarnessManifest, HarnessPlan, RuntimeStepObservation,
    ScenarioStatus, ScenarioStep, ScenarioWitness,
)
from harnesscreator.runtime.differential import DifferentialVerifier


SOURCE = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

static void sha(const unsigned char *in, size_t size, char out[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(in, size, digest);
    for (unsigned i=0;i<SHA256_DIGEST_LENGTH;i++) sprintf(out+i*2,"%02x", digest[i]);
    out[64] = 0;
}

void instrumented_product_logic(const uint8_t *Data, size_t Size) {
    static unsigned invocation = 0;
    unsigned current = ++invocation;
    if (Size != 2 || Data[0] != 'X' || Data[1] != '\n') return;
    char input_hex[65], response_hex[65], state_hex[65];
    sha(Data, Size, input_hex);
    sha((const unsigned char *)"OK\n", 3, response_hex);
    sha((const unsigned char *)"__STATE__", strlen("__STATE__"), state_hex);
    const char *file = getenv("HARNESSCREATOR_TRACE_JSONL");
    if (!file) return;
    FILE *out = fopen(file, "a");
    if (!out) return;
    fprintf(out,"{\"event\":\"acquire\",\"request_id\":\"r%u\",\"connection_id\":\"conn1\",\"entry_function_id\":\"entry\",\"request_sha256\":\"%s\"}\n",current,input_hex);
    fprintf(out,"{\"event\":\"handler\",\"request_id\":\"r%u\",\"connection_id\":\"conn1\",\"handler_function_id\":\"handler\"}\n",current);
    fprintf(out,"{\"event\":\"result\",\"request_id\":\"r%u\",\"connection_id\":\"conn1\",\"response_sha256\":\"%s\",\"state_digest\":\"%s\"}\n",current,response_hex,state_hex);
    fclose(out);
}
'''


class DifferentialValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_deferred_static_flow_requires_distinct_input_delivery(self):
        request = b"X\n"
        response = b"OK\n"
        state_digest = hashlib.sha256(b"state").hexdigest()
        response_digest = hashlib.sha256(response).hexdigest()
        step = ScenarioStep(0, "X", "entry", request.hex(), {}, [response.hex()])
        observation = RuntimeStepObservation(
            0, "X", request.hex(), response.hex(), True,
            "original request-correlated result", 0.01,
            entry_reached=True, target_reached=True,
            entry_function_id="entry", target_function_id="handler",
            probe_trace=[
                f"semantic-state:{state_digest}",
                f"semantic-response:{response_digest}",
            ],
        )
        witness = ScenarioWitness(
            "w", "s", "X", [step], [observation], ["original"],
            "stdin", 0, ScenarioStatus.PROVEN_RUNTIME, "original trace",
        )
        plan = HarnessPlan(
            "p", "w", "s", "X", [], step, ["handler"], ["entry"],
            "raw_final_request", "in_process_reset", "unit", 1, 64,
            fuzz_entry_function_id="entry",
        )

        class DeliveryRunner:
            def __init__(self, *, hardcoded: bool):
                self.hardcoded = hardcoded

            async def run(self, argv, *, cwd, timeout_seconds, env):
                supplied = Path(argv[1]).read_bytes()
                acquired = request if self.hardcoded else supplied
                common = {"request_id": "unique-run-1", "connection_id": "conn-1"}
                events = [dict(
                    event="acquire", entry_function_id="entry",
                    request_sha256=hashlib.sha256(acquired).hexdigest(),
                    **common,
                )]
                if acquired == request:
                    events.extend([
                        dict(event="handler", handler_function_id="handler", **common),
                        dict(event="result", response_sha256=response_digest,
                             state_digest=state_digest, **common),
                    ])
                Path(env["HARNESSCREATOR_TRACE_JSONL"]).write_text(
                    "".join(json.dumps(row) + "\n" for row in events)
                )
                return CommandReport(argv, 0, "", "", 0.01)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fuzz_target"
            binary.write_bytes(b"fixture")
            draft = HarnessDraft(HarnessManifest(
                "h", "harness.c", "unit", "libfuzzer", ["address"],
                "in_process_reset", [], [], 1, 64, "single", ["handler"],
                ["handler"], binary=str(binary),
            ), "")
            honest = await DifferentialVerifier(DeliveryRunner(hardcoded=False)).verify(
                draft=draft, plan=plan, witness=witness,
                artifact_dir=root, source_root=root, probe_input_delivery=True,
            )
            self.assertEqual(honest.status, "MATCH", honest.detail)
            self.assertTrue(honest.delivery_challenge_hex)
            self.assertNotEqual(honest.delivery_challenge_hex, request.hex())
            stateless_reference = replace(witness, observations=[
                replace(observation, probe_trace=[f"semantic-response:{response_digest}"])
            ])
            no_state_comparison = await DifferentialVerifier(
                DeliveryRunner(hardcoded=False)
            ).verify(
                draft=draft, plan=plan, witness=stateless_reference,
                artifact_dir=root, source_root=root,
            )
            self.assertEqual(no_state_comparison.status, "INSUFFICIENT_EVIDENCE")
            fixed_seed = await DifferentialVerifier(DeliveryRunner(hardcoded=True)).verify(
                draft=draft, plan=plan, witness=witness,
                artifact_dir=root, source_root=root, probe_input_delivery=True,
            )
            self.assertEqual(fixed_seed.status, "INSUFFICIENT_EVIDENCE")
            self.assertIn("challenge bytes", fixed_seed.detail)
            self.assertTrue(fixed_seed.delivery_challenge_hex)

    async def test_complete_setup_fuzz_post_sequence_is_compared(self):
        cases = [
            (b"SET key\n", "set", "entry-set", "handler-set", b"OK\n", b"stored"),
            (b"UPDATE key\n", "update", "entry-update", "handler-update", b"OK\n", b"updated"),
            (b"GET key\n", "get", "entry-get", "handler-get", b"", b"updated"),
        ]
        steps = [
            ScenarioStep(index, action, entry, request.hex(), {}, [])
            for index, (request, action, entry, _, _, _) in enumerate(cases)
        ]
        observations = [
            RuntimeStepObservation(
                index, action, request.hex(), response.hex(), True,
                "correlated original result", 0.01,
                entry_reached=True, target_reached=True,
                entry_function_id=entry, target_function_id=target,
                probe_trace=[
                    "semantic-response:" + hashlib.sha256(response).hexdigest(),
                    "semantic-state:" + hashlib.sha256(state).hexdigest(),
                    *(["semantic-outcome:success",
                       "semantic-success-site:handler-get@42"] if index == 2 else []),
                ],
            )
            for index, (request, action, entry, target, response, state)
            in enumerate(cases)
        ]
        witness = ScenarioWitness(
            "w-sequence", "s-sequence", "update", steps, observations,
            ["original"], "stdin", 0, ScenarioStatus.PROVEN_RUNTIME,
            "correlated original results", fuzz_step_index=1,
        )
        plan = HarnessPlan(
            "p-sequence", "w-sequence", "s-sequence", "update",
            [steps[0]], steps[1], ["handler-update"],
            ["entry-set", "entry-update", "entry-get"],
            "raw_final_request", "in_process_reset", "unit", 1, 64,
            setup_entry_function_ids=["entry-set"],
            fuzz_entry_function_id="entry-update",
            post_steps=[steps[2]], post_entry_function_ids=["entry-get"],
            fuzz_step_index=1,
        )

        def sequence_events():
            events = []
            for iteration in range(2):
                for index, (request, _, entry, target, response, state) in enumerate(cases):
                    identity = f"run-{iteration}-step-{index}"
                    common = dict(request_id=identity, connection_id=f"c-{iteration}")
                    events.extend([
                        dict(event="acquire", entry_function_id=entry,
                             request_sha256=hashlib.sha256(request).hexdigest(), **common),
                        dict(event="handler", handler_function_id=target, **common),
                        dict(event="result",
                             response_sha256=hashlib.sha256(response).hexdigest(),
                             state_digest=hashlib.sha256(state).hexdigest(),
                             **({"outcome": "success", "success_function_id": target,
                                 "success_line": 42} if index == 2 else {}),
                             **common),
                    ])
            return events

        class SequenceRunner:
            def __init__(self, events):
                self.events = events

            async def run(self, argv, *, cwd, timeout_seconds, env):
                Path(env["HARNESSCREATOR_TRACE_JSONL"]).write_text(
                    "".join(json.dumps(row) + "\n" for row in self.events)
                )
                return CommandReport(argv, 0, "", "", 0.01)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fuzz_target"
            binary.write_bytes(b"fake runner fixture")
            draft = HarnessDraft(HarnessManifest(
                "h-sequence", "harness.c", "unit", "libfuzzer", ["address"],
                "in_process_reset", [], [], 1, 64, "single",
                ["handler-update"], ["handler-update"], binary=str(binary),
            ), "")
            scenarios = [
                ("complete", sequence_events(), "MATCH"),
                ("missing setup", sequence_events()[3:], "INSUFFICIENT_EVIDENCE"),
                ("missing post", sequence_events()[:-3], "INSUFFICIENT_EVIDENCE"),
            ]
            wrong_post = sequence_events()
            wrong_post[-1]["state_digest"] = hashlib.sha256(b"wrong").hexdigest()
            scenarios.append(("changed post state", wrong_post, "MISMATCH"))
            wrong_site = sequence_events()
            wrong_site[-1]["success_line"] = 43
            scenarios.append(("wrong post completion site", wrong_site, "INSUFFICIENT_EVIDENCE"))
            reordered = sequence_events()
            reordered[0:3], reordered[3:6] = reordered[3:6], reordered[0:3]
            scenarios.append(("wrong order", reordered, "INSUFFICIENT_EVIDENCE"))
            for label, events, expected in scenarios:
                with self.subTest(label=label):
                    result = await DifferentialVerifier(
                        SequenceRunner(events)
                    ).verify(
                        draft=draft, plan=plan, witness=witness,
                        artifact_dir=root, source_root=root,
                    )
                    self.assertEqual(result.status, expected, result.detail)

    async def test_unattributed_sanitizer_failures_are_not_semantic_mismatches(self):
        step = ScenarioStep(0, "X", "entry", b"X\n".hex(), {}, [])
        observation = RuntimeStepObservation(
            0, "X", step.request_hex, b"OK\n".hex(), True,
            "original trace", 0.01,
            entry_reached=True, target_reached=True,
            entry_function_id="entry", target_function_id="handler",
            probe_trace=[
                "semantic-state:" + hashlib.sha256(b"stored").hexdigest(),
                "semantic-response:" + hashlib.sha256(b"OK\n").hexdigest(),
            ],
        )
        witness = ScenarioWitness(
            "w", "s", "X", [step], [observation], ["original"], "stdin",
            0, ScenarioStatus.PROVEN_RUNTIME, "original trace",
        )
        plan = HarnessPlan(
            "p", "w", "s", "X", [], step, ["handler"], ["entry"],
            "raw_final_request", "in_process_reset", "unit", 1, 64,
            fuzz_entry_function_id="entry",
        )

        class FailingRunner:
            def __init__(self, code: int, stderr: str):
                self.code = code
                self.stderr = stderr

            async def run(self, argv, *, cwd, timeout_seconds, env):
                return CommandReport(argv, self.code, "", self.stderr, 0.01)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fuzz_target"
            binary.write_bytes(b"fixture")
            draft = HarnessDraft(HarnessManifest(
                "h", "harness.c", "unit", "libfuzzer", ["address"],
                "in_process_reset", [], [], 1, 64, "single", ["handler"],
                ["handler"], binary=str(binary),
            ), "")
            for code, stderr, expected in (
                (-11, "", "INSUFFICIENT_EVIDENCE"),
                (77, "LeakSanitizer has encountered a fatal error",
                 "INFRASTRUCTURE_FAILED"),
            ):
                with self.subTest(code=code):
                    result = await DifferentialVerifier(
                        FailingRunner(code, stderr)
                    ).verify(
                        draft=draft, plan=plan, witness=witness,
                        artifact_dir=root, source_root=root,
                    )
                    self.assertEqual(result.status, expected)

    async def test_fragmented_harness_trace_is_compared_with_original(self):
        request = b"X\n"
        response_digest = hashlib.sha256(b"OK\n").hexdigest()
        state_digest = hashlib.sha256(b"stored").hexdigest()
        step = ScenarioStep(0, "X", "entry", request.hex(), {}, [b"OK\n".hex()])
        observation = RuntimeStepObservation(
            0, "X", request.hex(), b"OK\n".hex(), True, "original trace", 0.01,
            response_success=True, entry_reached=True, target_reached=True,
            entry_function_id="entry", target_function_id="handler",
            probe_trace=[f"semantic-state:{state_digest}",
                         f"semantic-response:{response_digest}"],
        )
        witness = ScenarioWitness(
            "w", "s", "X", [step], [observation], ["original"], "stdin",
            0, ScenarioStatus.PROVEN_RUNTIME, "original trace",
        )
        plan = HarnessPlan(
            "p", "w", "s", "X", [], step, ["handler"], ["entry"],
            "raw_final_request", "in_process_reset", "unit", 1, 64,
            fuzz_entry_function_id="entry",
        )

        class FragmentRunner:
            async def run(self, argv, *, cwd, timeout_seconds, env):
                rows = [
                    dict(event="acquire_fragment", request_id="iteration-1",
                         connection_id="conn-1", entry_function_id="entry",
                         offset=0, data_hex=b"X".hex()),
                    dict(event="acquire_fragment", request_id="iteration-1",
                         connection_id="conn-1", entry_function_id="entry",
                         offset=1, data_hex=b"\n".hex()),
                    dict(event="handler", request_id="iteration-1",
                         connection_id="conn-1", handler_function_id="handler"),
                    dict(event="result", request_id="iteration-1",
                         connection_id="conn-1", response_sha256=response_digest,
                         state_digest=state_digest),
                ]
                Path(env["HARNESSCREATOR_TRACE_JSONL"]).write_text(
                    "".join(json.dumps(row) + "\n" for row in rows)
                )
                return CommandReport(argv, 0, "", "", 0.01)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binary = root / "fuzz_target"
            binary.write_bytes(b"stub executable represented by FragmentRunner")
            draft = HarnessDraft(HarnessManifest(
                "f", "harness.c", "unit", "libfuzzer", ["address"],
                "in_process_reset", [], [], 1, 64, "single", ["handler"],
                ["handler"], binary=str(binary),
            ), "int LLVMFuzzerTestOneInput(void) { return 0; }")
            result = await DifferentialVerifier(FragmentRunner()).verify(
                draft=draft, plan=plan, witness=witness,
                artifact_dir=root, source_root=root,
            )
        self.assertEqual(result.status, "MATCH", result.detail)

    async def test_real_compiled_fuzzer_semantics_match_and_mismatch(self):
        clang = shutil.which("clang")
        if not clang or not Path("/usr/include/openssl/sha.h").exists():
            self.skipTest("clang libFuzzer and OpenSSL headers required")
        request = b"X\n"
        step = ScenarioStep(0, "X", "entry", request.hex(), {}, [b"OK\n".hex()])
        response = hashlib.sha256(b"OK\n").hexdigest()
        state = hashlib.sha256(b"stored").hexdigest()
        observation = RuntimeStepObservation(
            index=0, action_id="X", request_hex=request.hex(), response_hex=b"OK\n".hex(),
            success=True, response_success=True, entry_reached=True,
            target_reached=True, detail="real original with semantic instrumentation",
            duration_seconds=0.01,
            entry_function_id="entry", target_function_id="handler",
            probe_trace=[f"semantic-state:{state}", f"semantic-response:{response}"],
        )
        witness = ScenarioWitness(
            "w", "s", "X", [step], [observation], ["original"], "stdin",
            0, ScenarioStatus.PROVEN_RUNTIME, "original trace",
        )
        plan = HarnessPlan(
            plan_id="plan", witness_id="w", scenario_id="s", target_action_id="X",
            setup_steps=[], fuzz_step=step, required_function_ids=["handler"],
            entry_function_ids=["entry"], input_mapping="raw_final_request",
            reset_strategy="in_process_reset", build_target="unit", min_size=1, max_size=64,
            fuzz_entry_function_id="entry",
        )
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for generated_state, expected_status in (("stored", "MATCH"), ("changed", "MISMATCH")):
                source = root / "harness.c"
                source.write_text(
                    "#include <stdint.h>\n#include <stddef.h>\n"
                    "void instrumented_product_logic(const uint8_t *, size_t);\n"
                    "int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { "
                    "instrumented_product_logic(Data, Size); return 0; }\n"
                )
                product_source = root / "instrumented_original.c"
                product_source.write_text(SOURCE.replace("__STATE__", generated_state))
                binary = root / "fuzz_target"
                link_flags = ["-no-pie"] if sys.platform.startswith("linux") else []
                build = subprocess.run(
                    [clang, *link_flags,
                     "-fsanitize=fuzzer,address", str(source), str(product_source),
                     "-lcrypto", "-o", str(binary)],
                    capture_output=True, text=True,
                )
                if build.returncode:
                    self.skipTest("libFuzzer runtime unavailable: " + build.stderr[-300:])
                draft = HarnessDraft(
                    HarnessManifest(
                        harness_id="test", source_file=str(source), build_target="unit",
                        engine="libfuzzer", sanitizers=["address"],
                        execution_model="in_process_reset", headers=[], libraries=[],
                        min_size=1, max_size=64, dispatch_strategy="single",
                        expected_anchors=["handler"], expected_consumers=["handler"],
                        binary=str(binary),
                    ),
                    source.read_text(),
                )
                # This fixture checks request-correlated semantic comparison.
                # Leak checking is a separate sanitizer gate and can fail at
                # process exit under ptrace before the comparison runs.
                with patch.dict(os.environ, {"ASAN_OPTIONS":
                       "detect_leaks=0:abort_on_error=1"}):
                    result = await DifferentialVerifier().verify(
                        draft=draft, plan=plan, witness=witness,
                        artifact_dir=root, source_root=root,
                    )
                self.assertEqual(result.status, expected_status, result.detail)

    async def test_generated_harness_cannot_self_assert_equivalence(self):
        step = ScenarioStep(0, "X", "entry", b"X\n".hex(), {}, [b"OK\n".hex()])
        original = RuntimeStepObservation(
            0, "X", step.request_hex, b"OK\n".hex(), True, "product evidence", 0.01,
            response_success=True, entry_reached=True, target_reached=True,
            probe_trace=["semantic-state:" + "a" * 64, "semantic-response:" + "b" * 64],
        )
        witness = ScenarioWitness("w", "s", "X", [step], [original],
                                  ["original"], "stdin", 0,
                                  ScenarioStatus.PROVEN_RUNTIME, "source witness")
        plan = HarnessPlan("p", "w", "s", "X", [], step, ["handler"], ["entry"],
                           "raw_final_request", "in_process_reset", "unit", 1, 64)
        draft = HarnessDraft(HarnessManifest(
            "f", "harness.c", "unit", "libfuzzer", ["address"], "in_process_reset",
            [], [], 1, 64, "single", ["handler"], ["handler"], binary="/none"),
            'puts("HARNESSCREATOR_TRACE_JSONL");')
        with tempfile.TemporaryDirectory() as td:
            result = await DifferentialVerifier().verify(
                draft=draft, plan=plan, witness=witness,
                artifact_dir=Path(td), source_root=Path(td),
            )
        self.assertEqual(result.status, "INSUFFICIENT_EVIDENCE")
        self.assertIn("generated harness", result.detail)

    async def test_replayed_without_source_attribution_cannot_pass(self):
        step = ScenarioStep(0, "X", "entry", b"X\n".hex(), {}, [b"OK\n".hex()])
        witness = ScenarioWitness("w", "s", "X", [step], [], ["original"],
                                  "stdin", 0, ScenarioStatus.REPLAYED_RUNTIME, "response only")
        plan = HarnessPlan("p", "w", "s", "X", [], step, ["handler"], ["entry"],
                           "raw_final_request", "in_process_reset", "unit", 1, 64)
        draft = HarnessDraft(HarnessManifest(
            "f", "harness.c", "unit", "libfuzzer", ["address"], "in_process_reset",
            [], [], 1, 64, "single", ["handler"], ["handler"], binary="/none"), "")
        with tempfile.TemporaryDirectory() as td:
            result = await DifferentialVerifier().verify(
                draft=draft, plan=plan, witness=witness,
                artifact_dir=Path(td), source_root=Path(td),
            )
            self.assertEqual(result.status, "INSUFFICIENT_EVIDENCE")
