import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.models import Evidence, FixedPoC, PoC, RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.runtime import CLEAN_RUNTIME_ENVIRONMENT, triage_crash
from vulnerabilityanalysis.scan import execute_poc
from vulnerabilityanalysis.scan import run_targeted_fuzz
from vulnerabilityanalysis.analysis import RetryLedger
from vulnerabilityanalysis.final_verification import (
    REPLAY_ASAN_OPTIONS, check_security_property, classify_crash_relation,
    crash_fingerprint, freeze_poc,
    independent_replay, observed_crash_hypothesis, promote_verified,
    verify_root_cause,
)

# Goal A.1.2: a real replay records the pinned sanitizer environment it ran in.
PINNED_PROFILE = {"pinned_asan_options": REPLAY_ASAN_OPTIONS,
                  "replay_asan_options": REPLAY_ASAN_OPTIONS,
                  "environment_policy": "CLEAN_REPLAY_ENV_V1",
                  "execution_environment": {**CLEAN_RUNTIME_ENVIRONMENT,
                                             "ASAN_OPTIONS": REPLAY_ASAN_OPTIONS}}


def point(location="src/parser.c:42", hypothesis="heap buffer overflow at indexed read"):
    return SuspiciousPoint("sp-1", "worker", "direction", "parse", "src/parser.c", location,
                           "indexed read", hypothesis, ["input index exceeds allocation"],
                           "first input byte controls index", [], [], [], [],
                           security_property="memory safety")


def crash(stderr):
    return RuntimeResult(-6, "", stderr, 6, False,
                         "AddressSanitizer: heap-buffer-overflow" if "heap-buffer-overflow" in stderr
                         else "AddressSanitizer: heap-use-after-free", None, "SANITIZER_CRASH")


class CrashRelationTest(unittest.TestCase):
    def test_exact_crash_line(self):
        text = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "#0 0x1 in parse /tmp/target/src/parser.c:42:7\n")
        self.assertEqual(classify_crash_relation(crash(text), point(),
                         Path("/tmp/target"), Path("/tmp/fuzzer.c")).relation, "EXACT")

    def test_asan_memmove_interceptor_does_not_hide_target_access(self):
        text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                "#0 0x1 in __asan_memmove "
                "/src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:71\n"
                "#1 0x2 in parse /tmp/target/src/parser.c:42:7\n")
        result = crash(text)
        relation = classify_crash_relation(result, point("src/parser.c:42", "use-after-free"),
                                           Path("/tmp/target"), Path("/tmp/fuzzer.c"))
        self.assertEqual(relation.relation, "EXACT")
        self.assertEqual(relation.top_source_frame, "/tmp/target/src/parser.c")
        triage = triage_crash(result, "/tmp/target", "/tmp/fuzzer.c",
                              "src/parser.c:42", "parse")
        self.assertEqual(triage["category"], "TARGET_CRASH")
        self.assertEqual(triage["top_source_frame"], "/tmp/target/src/parser.c")

    def test_asan_interceptor_without_application_frame_remains_unknown(self):
        text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                "#0 0x1 in __asan_memmove "
                "/src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:71\n")
        self.assertEqual(triage_crash(crash(text), "/tmp/target", "/tmp/fuzzer.c")
                         ["category"], "UNKNOWN")

    def test_copied_dwarf_harness_frame_is_not_target_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "target"
            observed = checkout / "test" / "fuzzers" / "fuzzer.c"
            observed.parent.mkdir(parents=True)
            observed.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
            harness = root / "qualified" / "fuzzer.c"
            harness.parent.mkdir()
            harness.write_bytes(observed.read_bytes())
            binary = root / "binary"
            binary.write_bytes(b"DWARF fixture")
            text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                    "#0 0x1 in __asan_memmove "
                    "/src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:71\n"
                    f"#1 0x2 in LLVMFuzzerTestOneInput {observed}:1\n"
                    "freed by thread T0 here:\n"
                    f"#0 0x3 in LLVMFuzzerTestOneInput {observed}:1\n"
                    "previously allocated by thread T0 here:\n"
                    f"#0 0x4 in LLVMFuzzerTestOneInput {observed}:1\n")
            result = crash(text)
            with patch("vulnerabilityanalysis.runtime._dwarf_sources",
                       return_value={observed.resolve()}):
                triage = triage_crash(result, str(checkout), str(harness),
                                      target_binary=binary)
                self.assertEqual(triage["category"], "HARNESS_CRASH")
                result.crash_triage = {"category": "TARGET_CRASH"}
                candidate, provenance = observed_crash_hypothesis(
                    result, checkout, binary, harness_path=harness)
            self.assertIsNone(candidate)
            self.assertEqual(provenance["reason"],
                             "invalid access belongs to qualified harness")

    def test_harness_free_is_not_laundered_through_target_caller(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            source = target / "src" / "parser.c"
            source.parent.mkdir(parents=True)
            source.write_text("void parse(void) {\n  use();\n}\n")
            harness = root / "fuzzer.c"
            harness.write_text("void LLVMFuzzerTestOneInput(void) { free(p); }\n")
            binary = root / "binary"
            binary.write_bytes(b"DWARF fixture")
            text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                    f"#0 0x1 in parse {source}:2\n"
                    "freed by thread T0 here:\n"
                    "#0 0x2 in realloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:81\n"
                    f"#1 0x3 in LLVMFuzzerTestOneInput {harness}:1\n"
                    f"#2 0x4 in parse {source}:2\n"
                    "previously allocated by thread T0 here:\n"
                    f"#0 0x5 in parse {source}:2\n")
            result = crash(text)
            result.crash_triage = {"category": "TARGET_CRASH"}
            with patch("vulnerabilityanalysis.runtime._dwarf_sources",
                       return_value={source.resolve(), harness.resolve()}):
                candidate, provenance = observed_crash_hypothesis(
                    result, target, binary, harness_path=harness)
            self.assertIsNone(candidate)
            self.assertIn("free application frame", provenance["reason"])

    def test_inlined_symbol_is_reconciled_to_unique_source_line_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            source = target / "src" / "parser.c"
            source.parent.mkdir(parents=True)
            source.write_text("void real(void) {\n  realloc(p, n);\n}\n"
                              "void wrong(void) {\n  return;\n}\n")
            harness = root / "fuzzer.c"
            harness.write_text("void LLVMFuzzerTestOneInput(void) {}\n")
            binary = root / "binary"
            binary.write_bytes(b"DWARF fixture")
            text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                    f"#0 0x1 in real {source}:2\n"
                    "freed by thread T0 here:\n"
                    "#0 0x2 in realloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:81\n"
                    f"#1 0x3 in wrong {source}:2\n"
                    "previously allocated by thread T0 here:\n"
                    f"#0 0x4 in real {source}:2\n")
            result = crash(text)
            result.crash_triage = {"category": "TARGET_CRASH"}
            with patch("vulnerabilityanalysis.runtime._dwarf_sources",
                       return_value={source.resolve()}):
                candidate, provenance = observed_crash_hypothesis(
                    result, target, binary, harness_path=harness)
            self.assertIsNotNone(candidate)
            self.assertEqual(candidate.function_name, "real")
            self.assertEqual(candidate.code_location, "src/parser.c:2")
            self.assertEqual(provenance["sanitizer_free_symbol"], "wrong")
            self.assertEqual(provenance["resolved_free_function"], "real")
            self.assertEqual(provenance["free_function_resolution"],
                             "VERIFIED_SOURCE_LINE_OWNER")

    def test_mismatched_symbol_outside_every_function_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            source = target / "src" / "parser.c"
            source.parent.mkdir(parents=True)
            source.write_text("int global_value;\nvoid real(void) {\n  return;\n}\n")
            harness = root / "fuzzer.c"
            harness.write_text("void LLVMFuzzerTestOneInput(void) {}\n")
            binary = root / "binary"
            binary.write_bytes(b"DWARF fixture")
            text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                    f"#0 0x1 in real {source}:3\n"
                    "freed by thread T0 here:\n"
                    "#0 0x2 in realloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:81\n"
                    f"#1 0x3 in wrong {source}:1\n"
                    "previously allocated by thread T0 here:\n"
                    f"#0 0x4 in real {source}:3\n")
            result = crash(text)
            result.crash_triage = {"category": "TARGET_CRASH"}
            with patch("vulnerabilityanalysis.runtime._dwarf_sources",
                       return_value={source.resolve()}):
                candidate, provenance = observed_crash_hypothesis(
                    result, target, binary, harness_path=harness)
            self.assertIsNone(candidate)
            self.assertIn("free function identity is unverified", provenance["reason"])

    def test_stack_related_when_root_and_crash_lines_differ(self):
        text = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "#0 0x1 in copy_bytes /tmp/target/src/copy.c:90:2\n"
                "#1 0x2 in parse /tmp/target/src/parser.c:50:3\n")
        self.assertEqual(classify_crash_relation(crash(text), point(),
                         Path("/tmp/target"), Path("/tmp/fuzzer.c")).relation, "STACK_RELATED")

    def test_prior_ubsan_stack_is_not_the_asan_invalid_access(self):
        text = ("src/parser.c:42:1: runtime error: implicit conversion changed value\n"
                "#0 0x1 in parse /tmp/target/src/parser.c:42:1\n"
                "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior\n"
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "WRITE of size 8 at 0x1008 thread T0\n"
                "#0 0x2 in parse /tmp/target/src/parser.c:90:1\n"
                "0x1008 is located 0 bytes after 8-byte region [0x1000,0x1008)\n"
                "allocated by thread T0 here:\n"
                "#0 0x3 in malloc /tmp/allocator.c:1\n"
                "#1 0x4 in parse /tmp/target/src/parser.c:42:1\n")
        relation = classify_crash_relation(crash(text), point(),
                                           Path("/tmp/target"), Path("/tmp/fuzzer.c"))
        self.assertEqual(relation.relation, "STACK_RELATED")
        self.assertIn("parser.c:90", relation.relevant_stack_frames[0])

    def test_lifetime_relation_from_free_stack(self):
        text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                "#0 0x1 in consume /tmp/target/src/consume.c:90:2\n"
                "freed by thread T0 here:\n"
                "#0 0x2 in free /lib/asan.c:9\n"
                "#1 0x3 in parse /tmp/target/src/parser.c:42:3\n"
                "previously allocated by thread T0 here:\n"
                "#0 0x4 in malloc /lib/asan.c:5\n")
        self.assertEqual(classify_crash_relation(crash(text), point("src/parser.c:42", "use-after-free"),
                         Path("/tmp/target"), Path("/tmp/fuzzer.c")).relation, "LIFETIME_RELATED")

    def test_lifetime_source_location_accepts_common_cpp_extensions(self):
        for suffix in ("cc", "cpp", "cxx", "hpp", "hxx"):
            with self.subTest(suffix=suffix):
                name = f"parser.{suffix}"
                text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                        "#0 0x1 in consume /tmp/target/src/consume.c:90:2\n"
                        "freed by thread T0 here:\n"
                        "#0 0x2 in free /lib/asan.c:9\n"
                        f"#1 0x3 in parse /tmp/target/src/{name}:42:3\n"
                        "previously allocated by thread T0 here:\n"
                        "#0 0x4 in malloc /lib/asan.c:5\n")
                result = crash(text)
                result.crash_triage = {"category": "TARGET_CRASH"}
                root = verify_root_cause(point(f"src/{name}:42", "use-after-free"), result,
                                         Path("/tmp/target"), Path("/tmp/fuzzer.c"))
                self.assertEqual(root.verdict, "CONFIRMED")

    def test_harness_crash_is_unrelated(self):
        text = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "#0 0x1 in LLVMFuzzerTestOneInput /tmp/fuzzer.c:10:2\n")
        result = crash(text)
        self.assertEqual(classify_crash_relation(result, point(), Path("/tmp/target"),
                         Path("/tmp/fuzzer.c")).relation, "UNRELATED")
        self.assertEqual(triage_crash(result, "/tmp/target", "/tmp/fuzzer.c",
                         "src/parser.c:42", "parse")["category"], "HARNESS_CRASH")

    def test_generic_trace_does_not_claim_dataflow_relation(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "trace.log"; artifact.write_text("function entry reached\n")
            text = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                    "#0 0x1 in consume /tmp/target/src/consume.c:90:2\n")
            generic = Evidence("e", "TRACE", str(artifact), "sp-1", "function entry",
                               str(artifact), True, False)
            relation = classify_crash_relation(crash(text), point(), Path("/tmp/target"),
                                               Path("/tmp/fuzzer.c"), [generic])
            self.assertEqual(relation.relation, "UNKNOWN")

    def test_unissued_dataflow_artifact_cannot_link_different_stack_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "dataflow.json"
            artifact.write_text('{"sp": "sp-1", "crash": "consume", "value": "ptr"}')
            text = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                    "#0 0x1 in consume /tmp/target/src/consume.c:90:2\n")
            link = Evidence("e-link", "DATAFLOW", str(artifact), "sp-1",
                            "SP value ptr consumed at crash", str(artifact), True, False)
            relation = classify_crash_relation(crash(text), point(), Path("/tmp/target"),
                                               Path("/tmp/fuzzer.c"), [link])
            self.assertEqual(relation.relation, "UNKNOWN")

    def test_allocation_stack_alone_does_not_prove_lifetime_root(self):
        text = ("ERROR: AddressSanitizer: heap-use-after-free\n"
                "#0 0x1 in consume /tmp/target/src/consume.c:90:2\n"
                "freed by thread T0 here:\n"
                "#0 0x2 in release /tmp/target/src/release.c:9:2\n"
                "previously allocated by thread T0 here:\n"
                "#0 0x3 in parse /tmp/target/src/parser.c:42:3\n")
        relation = classify_crash_relation(crash(text), point("src/parser.c:42", "use-after-free"),
                                           Path("/tmp/target"), Path("/tmp/fuzzer.c"))
        self.assertEqual(relation.relation, "UNKNOWN")


class FinalGateTest(unittest.TestCase):
    def test_sanitizer_report_without_completed_replay_stays_environment_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "binary"; binary.write_bytes(b"binary")
            seed = root / "seed"; seed.write_bytes(b"A")
            import hashlib
            fixed = FixedPoC("p", "sp", str(seed), "", str(binary),
                             [str(binary), "{input}"], "AddressSanitizer: heap-buffer-overflow",
                             "AddressSanitizer: heap-buffer-overflow", "main:target.c:3", "fixture",
                             hashlib.sha256(seed.read_bytes()).hexdigest(),
                             hashlib.sha256(binary.read_bytes()).hexdigest())
            incomplete = RuntimeResult(None, "", "ERROR: AddressSanitizer: heap-buffer-overflow",
                                       None, True, "AddressSanitizer: heap-buffer-overflow",
                                       None, "ENVIRONMENT_ERROR")
            with patch("vulnerabilityanalysis.final_verification.RuntimeExecutor.run",
                       return_value=incomplete):
                replay = independent_replay(fixed, root / "replay", timeout_seconds=10)
            self.assertEqual(replay.status, "ENVIRONMENT_ERROR")
            self.assertEqual(replay.actual_oracle, incomplete.sanitizer)

    def test_useful_noncrashing_sp_seed_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "binary"; binary.write_bytes(b"binary")
            seed = root / "seed"; seed.write_bytes(b"A")
            poc = PoC("p", "sp-1", "def build():\n    return b'A'\n", str(seed),
                      [str(binary), "{input}"], "reach")
            result = RuntimeResult(0, "", "", None, False, None, None, "UNKNOWN")
            with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run", return_value=result), \
                 patch("vulnerabilityanalysis.scan.trace_function_reached", return_value=(False, "normal exit")), \
                 patch("vulnerabilityanalysis.scan.trace_sp_location", return_value=(True, None, "Breakpoint 1")):
                evidence = execute_poc(poc, point(), [str(binary), "{input}"], root / "out",
                                       trace_reachability=True, sp_location="src/parser.c:42")
            self.assertEqual((root / "out/corpus/candidate/sp-1/seed").read_bytes(), b"A")
            self.assertEqual(len(list((root / "out/corpus/global").glob("*.bin"))), 1)
            self.assertTrue(any(item.type == "CORPUS_SEED" and item.supports for item in evidence))

    def test_targeted_fuzz_is_bounded_and_requires_new_evidence_for_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            corpus = root / "corpus/candidate/sp-1"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            ledger = RetryLedger(3)
            with patch("vulnerabilityanalysis.scan.fuzz_locally", return_value=RuntimeResult(
                    0, "", "#2 INITED cov: 1 ft: 1 corp: 1/1b\n"
                    "#10 NEW cov: 2 ft: 2 corp: 2/2b\n", None, False, None, None,
                    "UNKNOWN")) as fuzzer:
                first = run_targeted_fuzz(point(), binary, root, ledger, ["new-trace"], seconds=2)
                second = run_targeted_fuzz(point(), binary, root, ledger, ["new-trace"], seconds=2)
                third = run_targeted_fuzz(point(), binary, root, ledger,
                                          ["new-trace", "new-coverage"], seconds=2)
            self.assertIsNotNone(first)
            self.assertIsNone(second)
            self.assertIsNotNone(third)
            self.assertEqual(fuzzer.call_count, 2)

    def test_targeted_fuzz_without_mutation_does_not_consume_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            corpus = root / "corpus/candidate/sp-1"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            ledger = RetryLedger(2)
            with patch("vulnerabilityanalysis.scan.fuzz_locally", return_value=RuntimeResult(
                    0, "", "", None, False, None, None, "UNKNOWN")) as fuzzer:
                first = run_targeted_fuzz(point(), binary, root, ledger, ["e1"], seconds=1)
                second = run_targeted_fuzz(point(), binary, root, ledger, ["e1"], seconds=1)
            self.assertEqual(first["status"], "INCOMPLETE_NO_FUZZ_EVIDENCE")
            self.assertEqual(second["status"], "INCOMPLETE_NO_FUZZ_EVIDENCE")
            self.assertEqual(fuzzer.call_count, 2)
            self.assertEqual(ledger.records, [])

    def test_targeted_fuzz_environment_error_is_not_ran(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            corpus = root / "corpus/candidate/sp-1"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            ledger = RetryLedger(2)
            with patch("vulnerabilityanalysis.scan.fuzz_locally", return_value=RuntimeResult(
                    None, "", "", None, False, None, None, "ENVIRONMENT_ERROR")):
                result = run_targeted_fuzz(point(), binary, root, ledger, ["e1"], seconds=1)
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(ledger.records, [])

    def test_targeted_fuzz_timeout_is_recorded_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            corpus = root / "corpus/candidate/sp-1"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            ledger = RetryLedger(2)
            with patch("vulnerabilityanalysis.scan.fuzz_locally", return_value=RuntimeResult(
                    None, "", "", None, True, None, None, "ENVIRONMENT_ERROR")):
                result = run_targeted_fuzz(point(), binary, root, ledger, ["e1"], seconds=1)
            self.assertEqual(result["status"], "TIMED_OUT")
            self.assertEqual(ledger.records, [])

    def test_targeted_fuzz_nonzero_exit_is_not_completed_or_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            corpus = root / "corpus/candidate/sp-1"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            abnormal = RuntimeResult(1, "", "#2 INITED cov: 1 ft: 1\n#10 DONE cov: 2 ft: 2\n",
                                     None, False, None, None, "UNKNOWN")
            ledger = RetryLedger(2)
            with patch("vulnerabilityanalysis.scan.fuzz_locally", return_value=abnormal) as fuzzer:
                first = run_targeted_fuzz(point(), binary, root, ledger, ["e1"], seconds=1)
                second = run_targeted_fuzz(point(), binary, root, ledger, ["e1"], seconds=1)
            self.assertEqual(first["status"], "ERROR")
            self.assertEqual(second["status"], "ERROR")
            self.assertEqual(fuzzer.call_count, 2)
            self.assertEqual(ledger.records, [])

    def test_targeted_fuzz_new_seed_or_more_time_is_new_bounded_experiment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            corpus = root / "corpus/candidate/sp-1"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            completed = RuntimeResult(0, "", "#2 INITED cov: 1 ft: 1\n#10 DONE cov: 2 ft: 2\n",
                                      None, False, None, None, "UNKNOWN")
            ledger = RetryLedger(3)
            with patch("vulnerabilityanalysis.scan.fuzz_locally", return_value=completed) as fuzzer:
                self.assertIsNotNone(run_targeted_fuzz(point(), binary, root, ledger,
                                                        ["e1"], seconds=1))
                self.assertIsNotNone(run_targeted_fuzz(point(), binary, root, ledger,
                                                        ["e1"], seconds=60))
                (corpus / "seed-new").write_bytes(b"B")
                self.assertIsNotNone(run_targeted_fuzz(point(), binary, root, ledger,
                                                        ["e1"], seconds=60))
                self.assertIsNone(run_targeted_fuzz(point(), binary, root, ledger,
                                                     ["e1"], seconds=60))
            self.assertEqual(fuzzer.call_count, 3)
            self.assertEqual(len(ledger.records), 3)

    def test_targeted_fuzz_blocks_non_libfuzzer_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "process_harness"
            binary.write_text("#!/bin/sh\necho ordinary process\n")
            binary.chmod(0o755)
            corpus = root / "corpus/candidate/sp-1"
            corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            with patch("vulnerabilityanalysis.scan.fuzz_locally") as fuzzer:
                result = run_targeted_fuzz(point(), binary, root, RetryLedger(3),
                                           ["new-trace"], seconds=2)
            self.assertIsNone(result)
            fuzzer.assert_not_called()
            blocked = json.loads((root / "runtime/sp-1.targeted_fuzz.blocked.json").read_text())
            self.assertEqual(blocked["status"], "BLOCKED")

    def test_root_cause_requires_matching_oracle_and_target_origin(self):
        text = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "#0 0x1 in parse /tmp/target/src/parser.c:42:7\n")
        result = crash(text)
        result.crash_triage = triage_crash(result, "/tmp/target", "/tmp/fuzzer.c",
                                           "src/parser.c:42", "parse")
        root = verify_root_cause(point(), result, Path("/tmp/target"), Path("/tmp/fuzzer.c"))
        self.assertEqual(root.crash_relation, "EXACT")
        self.assertEqual(root.verdict, "CONFIRMED")
        mismatch = point(hypothesis="use-after-free after object release")
        self.assertEqual(verify_root_cause(mismatch, result, Path("/tmp/target"),
                         Path("/tmp/fuzzer.c")).verdict, "UNKNOWN")
        integer = point(hypothesis="integer overflow while calculating index")
        self.assertEqual(verify_root_cause(integer, result, Path("/tmp/target"),
                         Path("/tmp/fuzzer.c")).verdict, "UNKNOWN")

    def test_explicit_unreached_trace_blocks_exact_root_cause(self):
        text = ("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "#0 0x1 in parse /tmp/target/src/parser.c:42:7\n")
        for field, value in (("function_reached", False),
                             ("sp_location_reached", False),
                             ("sp_condition_reached", False),
                             ("sp_condition_reached", 0)):
            with self.subTest(field=field, value=value):
                result = crash(text)
                result.crash_triage = {"category": "TARGET_CRASH"}
                setattr(result, field, value)
                root = verify_root_cause(point(), result, Path("/tmp/target"),
                                         Path("/tmp/fuzzer.c"))
                self.assertEqual(root.crash_relation, "EXACT")
                self.assertEqual(root.verdict, "UNKNOWN")
                self.assertIsNone(root.root_cause_location)

    def test_fixed_poc_serializes_input_script_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "binary"
            binary.write_bytes(b"binary")
            seed = root / "seed.bin"
            seed.write_bytes(b"A")
            poc = PoC("p", "sp-1", "def build():\n    return b'A'\n", str(seed),
                      [str(binary), "{input}"], "crash")
            fixed = freeze_poc(poc, point(), binary, "AddressSanitizer: heap-buffer-overflow",
                               "src/parser.c:42", "parse:src/parser.c:42", root / "fixed")
            self.assertEqual(Path(fixed.input_path).read_bytes(), b"A")
            self.assertEqual(Path(fixed.generator_script).read_text(), poc.generator_script)
            self.assertEqual(json.loads(json.dumps(asdict(fixed)))["sp_id"], "sp-1")

    def test_fixed_poc_can_pin_target_binary_behind_local_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "tinyproxy"; target.write_bytes(b"target")
            runner = root / "runner"; runner.write_bytes(b"runner")
            seed = root / "seed.bin"; seed.write_bytes(b"A")
            poc = PoC("p", "sp-1", "def build():\n    return b'A'\n", str(seed),
                      [str(runner), str(target), "{input}"], "crash")
            fixed = freeze_poc(poc, point(), target, "AddressSanitizer: heap-buffer-overflow",
                               "src/parser.c:42", "parse:src/parser.c:42", root / "fixed")
            self.assertEqual(fixed.target_binary, str(target))
            self.assertEqual(fixed.run_command[1], str(target))

    def test_independent_replay_success_and_failure_are_not_refutations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "replay.py"
            script.write_text("import sys\n"
                "from pathlib import Path\n"
                "data = Path(sys.argv[1]).read_bytes()\n"
                "if data == b'A':\n"
                " print('ERROR: AddressSanitizer: heap-buffer-overflow', file=sys.stderr)\n"
                " print('#0 0x1 in parse /tmp/target/src/parser.c:42:7', file=sys.stderr)\n"
                " sys.exit(1)\n")
            seed = root / "seed.bin"; seed.write_bytes(b"A")
            poc = PoC("p", "sp-1", "def build():\n    return b'A'\n", str(seed),
                      [sys.executable, str(script), "{input}"], "crash")
            primary = crash("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                            "#0 0x1 in parse /tmp/target/src/parser.c:42:7\n")
            fixed = freeze_poc(poc, point(), Path(sys.executable),
                               "AddressSanitizer: heap-buffer-overflow", "src/parser.c:42",
                               "parse:src/parser.c:42", root / "fixed",
                               expected_crash_fingerprint=crash_fingerprint(primary))
            reproduced = independent_replay(fixed, root / "replay-1")
            self.assertEqual(reproduced.status, "REPRODUCED")
            self.assertEqual(reproduced.actual_crash_fingerprint,
                             crash_fingerprint(primary))
            # Goal A.1.2: without a frozen primary fingerprint a replay is
            # never REPRODUCED.
            unfrozen = freeze_poc(poc, point(), Path(sys.executable),
                                  "AddressSanitizer: heap-buffer-overflow",
                                  "src/parser.c:42", "parse:src/parser.c:42",
                                  root / "fixed-unfrozen")
            self.assertEqual(independent_replay(unfrozen, root / "replay-0").status,
                             "INCONSISTENT")
            script.write_text("import sys\n")
            no_crash = independent_replay(fixed, root / "replay-2")
            self.assertEqual(no_crash.status, "NOT_REPRODUCED")
            self.assertNotEqual(no_crash.status, "REFUTED")

    def test_security_property_unknown_without_source_backed_evidence(self):
        self.assertEqual(check_security_property(point(), []).status, "UNKNOWN")
        with tempfile.TemporaryDirectory() as tmp:
            proof = Path(tmp) / "proof.txt"; proof.write_text("unrelated candidate")
            evidence = [Evidence(f"e-{kind}", kind, str(proof), "another-sp", kind,
                                 str(proof), True, False) for kind in
                        ("EXTERNAL_INPUT", "HARNESS_VALIDITY", "SECURITY_IMPACT")]
            self.assertEqual(check_security_property(point(), evidence).status, "UNKNOWN")

    def test_verified_gate_needs_every_check_and_never_promotes_assertion_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "proof.txt"; source.write_text("fixture source proof")
            evidence = [Evidence(f"e-{kind}", kind, str(source), "sp-1", kind,
                                 str(source), True, False) for kind in
                        ("EXTERNAL_INPUT", "HARNESS_VALIDITY", "SECURITY_IMPACT")]
            security = check_security_property(point(), evidence)
            self.assertEqual(security.status, "CONFIRMED")
            result = crash("ERROR: AddressSanitizer: heap-buffer-overflow\n"
                           "#0 0x1 in parse /tmp/target/src/parser.c:42:7\n")
            result.crash_triage = triage_crash(result, "/tmp/target", "/tmp/fuzzer.c",
                                               "src/parser.c:42", "parse")
            root_cause = verify_root_cause(point(), result, Path("/tmp/target"), Path("/tmp/fuzzer.c"))
            binary = root / "binary"; binary.write_bytes(b"binary")
            seed = root / "seed"; seed.write_bytes(b"A")
            poc = PoC("p", "sp-1", "def build():\n    return b'A'\n", str(seed),
                      [str(binary), "{input}"], "crash")
            fingerprint = crash_fingerprint(result)
            fixed = freeze_poc(poc, point(), binary, result.sanitizer,
                               "src/parser.c:42", "parse:src/parser.c:42", root / "fixed",
                               expected_crash_fingerprint=fingerprint)
            from vulnerabilityanalysis.models import IndependentValidation
            replay = IndependentValidation("p", "sp-1", "REPRODUCED", result.sanitizer,
                                           "parse:src/parser.c:42", str(root / "replay.json"), "same oracle",
                                           actual_crash_fingerprint=fingerprint)
            replay_runtime = {**asdict(result), "runtime_profile": PINNED_PROFILE}
            (root / "replay.json").write_text(json.dumps(replay_runtime))
            candidate = point()
            self.assertTrue(promote_verified(candidate, result, root_cause, fixed, replay, security))
            self.assertEqual(candidate.status, "VERIFIED")
            # Goal A.1.2: the replay must be the same crash, recomputed from
            # both RuntimeResults; stored strings alone are not trusted.
            other_stack = {**replay_runtime, "stderr": result.stderr +
                           "freed by thread T0 here:\n"
                           "#0 0x2 in release_beta /tmp/target/src/lifetime.c:80:3\n"}
            for label, runtime_json, fixed_case, replay_case in (
                    ("replay stack differs", other_stack, fixed, replay),
                    ("fingerprint not frozen", replay_runtime,
                     replace(fixed, expected_crash_fingerprint=None), replay),
                    ("forged frozen fingerprint", replay_runtime,
                     replace(fixed, expected_crash_fingerprint="crash-forged"), replay),
                    ("receipt fingerprint missing", replay_runtime, fixed,
                     replace(replay, actual_crash_fingerprint=None)),
                    ("replay environment unpinned", asdict(result), fixed, replay)):
                with self.subTest(identity=label):
                    (root / "replay.json").write_text(json.dumps(runtime_json))
                    self.assertFalse(promote_verified(
                        point(), result, root_cause, fixed_case, replay_case, security))
            (root / "replay.json").write_text(json.dumps(replay_runtime))
            for field, value in (("function_reached", False),
                                 ("sp_location_reached", False),
                                 ("sp_condition_reached", False),
                                 ("sp_condition_reached", 0)):
                with self.subTest(field=field, value=value):
                    contradictory = replace(result, **{field: value})
                    candidate = point()
                    self.assertFalse(promote_verified(candidate, contradictory,
                                                      root_cause, fixed, replay, security))
                    self.assertNotEqual(candidate.status, "VERIFIED")
            self.assertFalse(promote_verified(point(), result,
                                              replace(root_cause, crash_id="different-crash"),
                                              fixed, replay, security))
            forged = IndependentValidation("p", "sp-1", "REPRODUCED", result.sanitizer,
                                           "parse:src/parser.c:42", str(root / "absent.json"), "claim")
            self.assertFalse(promote_verified(point(), result, root_cause, fixed, forged, security))
            for field, value in (("function_reached", False),
                                 ("sp_location_reached", False),
                                 ("sp_condition_reached", False),
                                 ("sp_condition_reached", 0)):
                with self.subTest(replay_field=field, value=value):
                    (root / "replay.json").write_text(json.dumps({
                        **replay_runtime, field: value}))
                    self.assertFalse(promote_verified(point(), result, root_cause,
                                                      fixed, replay, security))
            (root / "replay.json").write_text(json.dumps(replay_runtime))
            absent = point()
            self.assertFalse(promote_verified(absent, result, root_cause, fixed, replay,
                                              check_security_property(absent, [])))
            self.assertNotEqual(absent.status, "VERIFIED")
            result.stderr = "VA_ASSERTION_VIOLATION:a-1"
            result.crash_triage = {"category": "ASSERTION_VIOLATION"}
            assertion_candidate = point()
            self.assertFalse(promote_verified(assertion_candidate, result, root_cause,
                                              fixed, replay, security))
            self.assertNotEqual(assertion_candidate.status, "VERIFIED")

    @unittest.skipUnless(shutil.which("clang"), "clang required for real ASAN integration")
    def test_real_asan_crash_enters_root_replay_and_pending_security_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"; target.mkdir()
            source = target / "target.c"
            source.write_text(
                "#include <stdio.h>\n#include <stdlib.h>\n"
                "int main(int argc, char **argv) {\n"
                "  if (argc != 2) return 2;\n"
                "  FILE *f = fopen(argv[1], \"rb\");\n"
                "  if (!f) return 2;\n"
                "  int c = fgetc(f); fclose(f);\n"
                "  unsigned char *p = malloc(1);\n"
                "  volatile size_t index = c == 'A' ? 1 : 0;\n"
                "  unsigned char value = p[index];\n"
                "  fprintf(stderr, \"%u\\n\", value); free(p); return 0;\n"
                "}\n")
            line = next(i for i, text in enumerate(source.read_text().splitlines(), 1)
                        if "p[index]" in text)
            binary = target / "binary"
            built = subprocess.run(["clang", "-g", "-O0", "-fno-omit-frame-pointer",
                                    "-fsanitize=address", str(source), "-o", str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            seed = root / "seed.bin"; seed.write_bytes(b"A")
            poc = PoC("p-asan", "sp-1", "def build():\n    return b'A'\n", str(seed),
                      None, "ASAN heap overflow")
            candidate = point(f"target.c:{line}")
            candidate.function_name = "main"
            candidate.source_file = "target.c"
            result_dir = root / "result"
            execute_poc(poc, candidate, [str(binary), "{input}"], result_dir,
                        target_repository=target, harness_path=root / "harness.c",
                        runtime_sanitizers=["ASAN"], sp_location=f"{source}:{line}")
            self.assertEqual(json.loads((result_dir / "runtime/p-asan.json").read_text())
                             ["crash_triage"]["category"], "TARGET_CRASH")
            self.assertEqual(json.loads((result_dir / "root_cause/sp-1.json").read_text())
                             ["verdict"], "CONFIRMED")
            self.assertEqual(json.loads((result_dir / "independent/sp-1/validation.json").read_text())
                             ["status"], "REPRODUCED")
            self.assertEqual(json.loads((result_dir / "security/sp-1.json").read_text())
                             ["status"], "UNKNOWN")
            self.assertNotEqual(candidate.status, "VERIFIED")
            self.assertEqual(source.read_text().count("p[index]"), 1)


if __name__ == "__main__":
    unittest.main()
