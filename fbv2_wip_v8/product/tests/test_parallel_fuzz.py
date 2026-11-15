import asyncio
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from vulnerabilityanalysis.analysis import RetryLedger
from vulnerabilityanalysis.fuzzer_crash_consumer import _safe_corpus_input
from vulnerabilityanalysis.models import RuntimeResult, SuspiciousPoint
from vulnerabilityanalysis.scan import (_corpus_inputs, _plain_targeted_replay_input,
                                        _record_fuzzer_crash, _retain_corpus_input,
                                        record_targeted_fuzzer_observations,
                                        run_global_fuzz, run_targeted_fuzz, scan_selected,
                                        select_fuzzer_replays)
from vulnerabilityanalysis.workflow import run_phase1


class Provider:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    async def generate(self, request):
        self.calls += 1
        if self.calls == 1:
            # Give the already-started Global Fuzzer time to overlap SP analysis.
            await asyncio.sleep(0.5)
        if self.calls == 2:
            # Keep the first SP verification active during Global Fuzzing.
            await asyncio.sleep(0.5)
        if self.calls == 4:
            # The second SP Verifier is active while the first SP's fuzzers run.
            await asyncio.sleep(0.15)
        return self.responses.pop(0)


class ParallelFuzzTest(unittest.TestCase):
    def test_targeted_retry_retains_first_crash_and_runtime_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds", [], "bytes",
                                    [], [], [], [])
            corpus = root / "corpus/candidate/sp"
            corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_bytes(b"fake binary")
            ledger = RetryLedger(2)
            launches = 0

            def fake_fuzz(_binary, _corpus, **_kwargs):
                nonlocal launches
                launches += 1
                if launches == 1:
                    (corpus / "crash-witness").write_bytes(b"X")
                    return RuntimeResult(None, "", "", None, True, None, None,
                                         "ENVIRONMENT_ERROR")
                # libFuzzer can reuse the same crash filename on a retry.
                (corpus / "crash-witness").write_bytes(b"Y")
                (corpus / "new-second").write_bytes(b"B")
                return RuntimeResult(0, "", "#3 NEW\n", None, False, None,
                                     None, "COMPLETED")

            def fake_probe(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, "max_total_time", "")

            with patch("vulnerabilityanalysis.scan.fuzz_locally", side_effect=fake_fuzz):
                first = run_targeted_fuzz(point, binary, root, ledger, [],
                                          seconds=1, guarded_runner=fake_probe)
                first_report = json.loads((root / "runtime/sp.targeted_fuzz.seeds.json")
                                          .read_text())
                first_receipt = Path(first_report["attempt_runtime_artifact"])
                first_bytes = first_receipt.read_bytes()
                first_seeds = Path(first_report["attempt_seed_artifact"])
                first_seed_bytes = first_seeds.read_bytes()
                witness = Path(first_report["crash_input"]["attempt_witness_artifact"])
                ids = record_targeted_fuzzer_observations(root, "sp", first_report)
                second = run_targeted_fuzz(point, binary, root, ledger, [],
                                           seconds=1, guarded_runner=fake_probe)

            latest = json.loads((root / "runtime/sp.targeted_fuzz.seeds.json").read_text())
            second_ids = record_targeted_fuzzer_observations(root, "sp", latest)
            queued = json.loads((root / "runtime/fuzzer_crashes" /
                                 f"{next(iter(ids))}.json").read_text())
            self.assertEqual(first["status"], "TIMED_OUT")
            self.assertEqual(second["status"], "CRASH_OBSERVED_INCOMPLETE")
            self.assertEqual(launches, 2)
            self.assertEqual(first_receipt.read_bytes(), first_bytes)
            self.assertEqual(first_seeds.read_bytes(), first_seed_bytes)
            self.assertEqual(witness.read_bytes(), b"X")
            self.assertTrue(witness.is_relative_to(root / "corpus"))
            self.assertTrue(_safe_corpus_input(root, witness))
            self.assertEqual((corpus / "crash-witness").read_bytes(), b"Y")
            self.assertEqual(queued["observations"][0]["runtime_artifact"],
                             str(first_receipt))
            self.assertNotEqual(latest["attempt_id"], first_report["attempt_id"])
            self.assertEqual(latest["status"], "CRASH_OBSERVED_INCOMPLETE")
            self.assertEqual(Path(latest["crash_input"]["candidate_path"]).read_bytes(), b"Y")
            self.assertNotEqual(ids, second_ids)
            self.assertTrue(_plain_targeted_replay_input(
                root, "sp", first_report["crash_input"]))
            self.assertTrue(_plain_targeted_replay_input(
                root, "sp", latest["new_seeds"][0]))
            tampered = {**first_report, "attempt_runtime_sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "runtime receipt is invalid"):
                record_targeted_fuzzer_observations(root, "sp", tampered)

    def test_targeted_v2_claim_rejects_retry_before_next_physical_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds", [], "bytes",
                                    [], [], [], [])
            corpus = root / "corpus/candidate/sp"
            corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_bytes(b"fake binary")
            probe = subprocess.CompletedProcess([str(binary), "-help=1"], 0,
                                                "max_total_time", "")
            with patch("vulnerabilityanalysis.scan._guarded_run", return_value=probe) as guarded, \
                 patch("vulnerabilityanalysis.scan.fuzz_locally",
                       return_value=RuntimeResult(None, "", "", None, True,
                                                  None, None, "ENVIRONMENT_ERROR")) as fuzz:
                first = run_targeted_fuzz(point, binary, root, RetryLedger(2), [],
                                          seconds=1, process_envelope=object())
                self.assertEqual(first["status"], "TIMED_OUT")
                with self.assertRaises(FileExistsError):
                    run_targeted_fuzz(point, binary, root, RetryLedger(2), [],
                                      seconds=1, process_envelope=object())
            self.assertEqual(guarded.call_count, 1)
            self.assertEqual(fuzz.call_count, 1)

    def test_targeted_fuzz_charges_libfuzzer_probe_to_guarded_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds", [], "bytes",
                                    [], [], [], [])
            corpus = root / "corpus/candidate/sp"
            corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_bytes(b"fake binary")
            calls = []

            def guarded(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.CompletedProcess(argv, 0, "max_total_time", "")

            ledger = RetryLedger(2)
            with patch("vulnerabilityanalysis.scan._guarded_run",
                       side_effect=AssertionError("unaccounted process")), \
                 patch("vulnerabilityanalysis.scan.fuzz_locally",
                       return_value=RuntimeResult(0, "", "#2 NEW\n", None, False,
                                                  None, None, "COMPLETED")) as fuzz:
                run_targeted_fuzz(point, binary, root, ledger, [],
                                  seconds=1, guarded_runner=guarded)
                self.assertIsNone(run_targeted_fuzz(
                    point, binary, root, ledger, [], seconds=1,
                    guarded_runner=guarded))
            self.assertEqual(len(calls), 1)
            self.assertEqual(fuzz.call_count, 1)
            self.assertEqual(calls[0][0], [str(binary.resolve()), "-help=1"])
            self.assertEqual(calls[0][1]["timeout"], 5)
            self.assertIs(fuzz.call_args.kwargs["guarded_runner"], guarded)

    def test_targeted_fuzz_shares_new_seeds_with_one_global_corpus_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds", [], "bytes",
                                    [], [], [], [])
            candidate = root / "corpus/candidate/sp"
            candidate.mkdir(parents=True)
            (candidate / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)

            def generated(_binary, _corpus, **_kwargs):
                for number in range(30):
                    (candidate / f"new-{number}").write_bytes(bytes([number, 0x42]))
                return RuntimeResult(0, "", "#31 NEW\n", None, False,
                                     None, None, "COMPLETED")

            with patch("vulnerabilityanalysis.scan.fuzz_locally", side_effect=generated), \
                 patch("vulnerabilityanalysis.scan._corpus_inputs", wraps=_corpus_inputs) as indexed:
                outcome = run_targeted_fuzz(point, binary, root, RetryLedger(2), [], seconds=1)
            global_folder = root / "corpus/global"
            global_indexes = sum(call.args[0] == global_folder for call in indexed.call_args_list)
            self.assertEqual(global_indexes, 1)
            self.assertEqual(len(_corpus_inputs(global_folder)), 30)
            self.assertEqual(outcome.type, "FUZZING")

    def test_targeted_fuzz_refreshes_index_when_global_fuzzer_is_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds", [], "bytes",
                                    [], [], [], [])
            candidate = root / "corpus/candidate/sp"
            candidate.mkdir(parents=True)
            (candidate / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)
            global_folder = root / "corpus/global"

            def generated(_binary, _corpus, **_kwargs):
                (candidate / "new-0").write_bytes(b"B")
                (candidate / "new-1").write_bytes(b"C")
                return RuntimeResult(0, "", "#3 NEW\n", None, False,
                                     None, None, "COMPLETED")

            handoffs = 0

            def retain_with_external_seed(folder, source, name, known_inputs=None):
                nonlocal handoffs
                retained = _retain_corpus_input(folder, source, name,
                                                known_inputs=known_inputs)
                if folder == global_folder:
                    handoffs += 1
                    if handoffs == 1:
                        (global_folder / "external.bin").write_bytes(b"C")
                return retained

            with patch("vulnerabilityanalysis.scan.fuzz_locally", side_effect=generated), \
                 patch("vulnerabilityanalysis.scan._retain_corpus_input",
                       side_effect=retain_with_external_seed):
                run_targeted_fuzz(point, binary, root, RetryLedger(2), [], seconds=1,
                                  concurrent_global_fuzz=True)
            report = json.loads((root / "runtime/sp.targeted_fuzz.seeds.json").read_text())
            self.assertEqual(len(report["new_seeds"]), 2)
            self.assertFalse(report["new_seeds"][1]["new_to_global"])
            self.assertEqual(len(_corpus_inputs(global_folder)), 2)

    def test_timeout_with_crash_file_is_queued_per_input(self):
        from vulnerabilityanalysis.scan import record_targeted_fuzzer_observations
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds", [], "bytes",
                                    [], [], [], [])
            corpus = root / "corpus/candidate/sp"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)

            def interrupted(_binary, _corpus, **_kwargs):
                (corpus / "crash-witness").write_bytes(b"X")
                return RuntimeResult(None, "", "", None, True, None, None,
                                     "ENVIRONMENT_ERROR")

            with patch("vulnerabilityanalysis.scan.fuzz_locally", side_effect=interrupted):
                outcome = run_targeted_fuzz(point, binary, root, RetryLedger(2), [], seconds=1)
            report = json.loads((root / "runtime/sp.targeted_fuzz.seeds.json").read_text())
            ids = record_targeted_fuzzer_observations(root, "sp", report)
            self.assertEqual(outcome["status"], "TIMED_OUT")
            self.assertEqual(len(ids), 1)
            queued = json.loads((root / "runtime/fuzzer_crashes" /
                                 f"{next(iter(ids))}.json").read_text())
            self.assertEqual(queued["status"], "PENDING_RUNTIME_REPLAY_AND_TRIAGE")
            self.assertEqual(queued["observations"][0]["crash_input"]["sha256"],
                             hashlib.sha256(b"X").hexdigest())

    def test_oversized_sp_crash_stays_pending_and_observed(self):
        from vulnerabilityanalysis.scan import targeted_fuzzer_replay_plan, targeted_fuzzer_crash_inputs
        record = {"crash_inputs": [], "pending_crash_inputs": [{
            "candidate_path": "/tmp/oversized-crash", "sha256": "a" * 64,
            "size": 2_097_153}], "new_seeds": [], "observed_crash_id": "CRASH_A"}
        replay, pending = targeted_fuzzer_replay_plan(record, prior_attempts=0,
                                                       max_attempts=2)
        self.assertEqual(replay, [])
        self.assertEqual(pending[0]["reason"], "INPUT_EXCEEDS_RUNTIME_REPLAY_LIMIT")
        self.assertEqual(targeted_fuzzer_crash_inputs(record), record["pending_crash_inputs"])

    def test_generated_oversized_sp_crash_has_pending_witness_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds", [], "bytes",
                                    [], [], [], [])
            corpus = root / "corpus/candidate/sp"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_text("#!/bin/sh\necho max_total_time\n")
            binary.chmod(0o755)

            def oversized(_binary, _corpus, **_kwargs):
                (corpus / "crash-large").write_bytes(b"X" * 2_097_153)
                return RuntimeResult(1, "", "", None, False, None, None, "UNKNOWN")

            with patch("vulnerabilityanalysis.scan.fuzz_locally", side_effect=oversized):
                outcome = run_targeted_fuzz(point, binary, root, RetryLedger(2), [], seconds=1)
            report = json.loads((root / "runtime/sp.targeted_fuzz.seeds.json").read_text())
            self.assertEqual(outcome["status"], "CRASH_OBSERVED_INCOMPLETE")
            self.assertEqual(report["crash_inputs"], [])
            self.assertEqual(len(report["pending_crash_inputs"]), 1)
            self.assertEqual(report["observed_crash_id"],
                             report["pending_crash_inputs"][0]["observed_crash_id"])

    def test_multiple_crashes_replay_to_budget_and_keep_remainder_pending(self):
        crash_inputs = [{"sha256": str(i), "candidate_path": f"/tmp/crash-{i}"}
                        for i in range(3)]
        selected, pending = select_fuzzer_replays(crash_inputs, [],
                                                  prior_attempts=1, max_attempts=2)
        self.assertEqual(selected, crash_inputs[:1])
        self.assertEqual([row["reason"] for row in pending],
                         ["RUNTIME_ATTEMPT_LIMIT", "RUNTIME_ATTEMPT_LIMIT"])

    def test_targeted_fuzzer_keeps_every_new_crash_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds", [], "bytes",
                                    [], [], [], [])
            corpus = root / "corpus/candidate/sp"; corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_text("#!/usr/bin/env python3\nimport pathlib, sys\n"
                              "if '-help=1' in sys.argv:\n print('max_total_time')\n raise SystemExit(0)\n"
                              "folder = pathlib.Path(sys.argv[1])\n"
                              "(folder / 'crash-a').write_bytes(b'X')\n"
                              "(folder / 'crash-b').write_bytes(b'Y')\n"
                              "sys.stderr.write('ERROR: AddressSanitizer: heap-buffer-overflow\\n')\n"
                              "raise SystemExit(1)\n")
            binary.chmod(0o755)
            ledger = RetryLedger(2)
            outcome = run_targeted_fuzz(point, binary, root, ledger, [], seconds=1)
            report = json.loads((root / "runtime/sp.targeted_fuzz.seeds.json").read_text())
            self.assertEqual(outcome["status"], "CRASH_OBSERVED_INCOMPLETE")
            self.assertEqual(ledger.records, [])
            self.assertEqual({Path(row["candidate_path"]).read_bytes()
                              for row in report["crash_inputs"]}, {b"X", b"Y"})

    def test_targeted_fuzzer_records_exact_new_crash_input_for_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            point = SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                                    "target.c:1", "read", "bounds hypothesis", [],
                                    "harness bytes", [], [], [], [])
            corpus = root / "corpus/candidate/sp"
            corpus.mkdir(parents=True)
            (corpus / "seed").write_bytes(b"A")
            binary = root / "fake-fuzzer"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "if '-help=1' in sys.argv:\n"
                "    print('max_total_time')\n"
                "    raise SystemExit(0)\n"
                "(pathlib.Path(sys.argv[1]) / 'crash-abc').write_bytes(b'X')\n"
                "sys.stderr.write('ERROR: AddressSanitizer: heap-buffer-overflow\\n')\n"
                "raise SystemExit(1)\n")
            binary.chmod(0o755)
            run_targeted_fuzz(point, binary, root, RetryLedger(2), [], seconds=1)
            report = json.loads((root / "runtime/sp.targeted_fuzz.seeds.json").read_text())
            crash = report["crash_input"]
            self.assertEqual(Path(crash["candidate_path"]).read_bytes(), b"X")
            self.assertEqual(crash["sha256"], hashlib.sha256(b"X").hexdigest())
            self.assertEqual(crash["size"], 1)
            self.assertTrue(report["observed_crash_id"])

    def test_targeted_crash_mutation_origin_needs_exact_libfuzzer_log(self):
        base_sha1 = hashlib.sha1(b"A").hexdigest()
        artifact = "crash-" + hashlib.sha1(b"X").hexdigest()
        log = (f"MS: 1 ChangeByte-; base unit: {base_sha1}\n"
               f"artifact_prefix='./'; Test unit written to ./{artifact}\n")
        cases = (
            ("matching", artifact, log, "VERIFIED_LIBFUZZER_MUTATION"),
            ("no_mutation", artifact, "ERROR: AddressSanitizer\n", "UNPROVEN"),
            ("wrong_base", artifact, log.replace(base_sha1, "0" * 40),
             "UNPROVEN"),
            ("wrong_artifact", artifact, log.replace(artifact, "crash-other"),
             "UNPROVEN"),
            ("wrong_hash_name", "crash-witness",
             log.replace(artifact, "crash-witness"), "UNPROVEN"),
        )
        for label, filename, stderr, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                point = SuspiciousPoint("sp", "worker", "direction", "parse",
                                        "target.c", "target.c:1", "read",
                                        "bounds", [], "bytes", [], [], [], [])
                corpus = root / "corpus/candidate/sp"
                corpus.mkdir(parents=True)
                (corpus / "seed").write_bytes(b"A")
                binary = root / "fake-fuzzer"
                binary.write_bytes(b"fake binary")

                def fake_fuzz(_binary, _corpus, **_kwargs):
                    (corpus / filename).write_bytes(b"X")
                    return RuntimeResult(1, "", stderr,
                                         "AddressSanitizer: heap-buffer-overflow",
                                         False, None, None, "SANITIZER_CRASH")

                def fake_probe(argv, **_kwargs):
                    return subprocess.CompletedProcess(
                        argv, 0, "max_total_time", "")

                with patch("vulnerabilityanalysis.scan.fuzz_locally",
                           side_effect=fake_fuzz):
                    outcome = run_targeted_fuzz(
                        point, binary, root, RetryLedger(2), [], seconds=1,
                        guarded_runner=fake_probe)
                report = json.loads(
                    (root / "runtime/sp.targeted_fuzz.seeds.json").read_text())
                witness = report["crash_input"]
                self.assertEqual(outcome["status"], "CRASH_OBSERVED_INCOMPLETE")
                self.assertEqual(witness["mutation_origin_status"], expected)
                self.assertEqual(report["crash_mutation_observed"],
                                 expected == "VERIFIED_LIBFUZZER_MUTATION")
                if expected == "VERIFIED_LIBFUZZER_MUTATION":
                    self.assertEqual(witness["mutation_base_sha256"],
                                     hashlib.sha256(b"A").hexdigest())
                else:
                    self.assertNotIn("mutation_base_sha256", witness)
                ids = record_targeted_fuzzer_observations(root, "sp", report)
                queued = json.loads((root / "runtime/fuzzer_crashes" /
                                     f"{next(iter(ids))}.json").read_text())
                self.assertEqual(queued["observations"][0]["crash_input"]
                                 ["mutation_origin_status"], expected)
                self.assertEqual(queued["status"],
                                 "PENDING_RUNTIME_REPLAY_AND_TRIAGE")

    def test_concurrent_seed_handoff_deduplicates_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "seed"
            source.write_bytes(b"same candidate input")
            corpus = root / "global"
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(
                    lambda index: _retain_corpus_input(corpus, source, f"{index}.bin"),
                    range(16)))
            self.assertEqual(sum(added for _, added in results), 1)
            self.assertEqual(len(list(corpus.iterdir())), 1)

    def test_same_fuzzer_crash_keeps_one_observation_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = _record_fuzzer_crash(root, "same-fingerprint", "SP_FUZZER",
                                         root / "runtime/sp.json", "sp-one")
            second = _record_fuzzer_crash(root, "same-fingerprint", "SP_FUZZER",
                                          root / "runtime/sp.json", "sp-one")
            _record_fuzzer_crash(root, "same-fingerprint", "GLOBAL_FUZZER",
                                 root / "runtime/global.json", None)
            self.assertEqual(first, second)
            record = json.loads(first.read_text())
            self.assertEqual(len(record["observations"]), 2)
            self.assertEqual(record["status"], "PENDING_RUNTIME_REPLAY_AND_TRIAGE")

    def test_real_libfuzzer_overlap_corpus_handoff_and_runtime_replay(self):
        if not shutil.which("clang"):
            self.skipTest("clang with libFuzzer is required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "target.c").write_text(
                "#include <stddef.h>\n"
                "int parse(const unsigned char *data, size_t size) {\n"
                "  if (size && data[0] == 'A' && size > 1 && data[1] == 'B') return 1;\n"
                "  return 0;\n}\n")
            artifact = root / "hg"
            artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "#include <stddef.h>\n"
                "extern int parse(const unsigned char *, size_t);\n"
                "int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) "
                "{ (void)parse(data, size); return 0; }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "parallel-fixture", "source_file": "fuzz.c",
                "expected_consumers": ["parse"], "sanitizers": ["ASAN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            analysis = root / "analysis"
            analysis.mkdir()
            (analysis / "functions.jsonl").write_text(json.dumps({
                "function_id": "parse-id", "name": "parse", "file": "target.c"}) + "\n")
            binary = root / "fuzzer"
            subprocess.run(["clang", "-g", "-O0", "-fsanitize=fuzzer,address",
                            str(repo / "target.c"), str(artifact / "fuzz.c"),
                            "-o", str(binary)], check=True, capture_output=True)
            verdict = {"status": "PLAUSIBLE", "supporting_evidence": [],
                       "contradicting_evidence": [], "unknowns": ["trigger state"],
                       "rationale": "runtime evidence needed", "reachability": "UNKNOWN",
                       "controllability": "UNKNOWN", "guards": [], "required_state": [],
                       "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                       "context_requests": [], "recommended_next_action": "GENERATE_POC"}
            provider = Provider([
                {"suspicious_points": [{
                    "source_file": "target.c", "source_line": 3,
                    "source_excerpt": "if (size && data[0] == 'A' && size > 1 && data[1] == 'B') return 1;",
                    "sp_condition": "", "suspicious_operation": "data[1] read",
                    "vulnerability_hypothesis": "length guard may be incomplete",
                    "trigger_conditions": ["size > 1"],
                    "external_input_relation": "harness bytes determine data",
                    "required_state": [], "security_property": "memory safety",
                    "supporting_evidence": [], "contradicting_evidence": [],
                    "unknowns": ["runtime trigger"]}, {
                    "source_file": "target.c", "source_line": 3,
                    "source_excerpt": "if (size && data[0] == 'A' && size > 1 && data[1] == 'B') return 1;",
                    "sp_condition": "", "suspicious_operation": "data[0] read",
                    "vulnerability_hypothesis": "entry guard may be incomplete",
                    "trigger_conditions": ["size > 0"],
                    "external_input_relation": "harness bytes determine data",
                    "required_state": [], "security_property": "memory safety",
                    "supporting_evidence": [], "contradicting_evidence": [],
                    "unknowns": ["runtime trigger"]}]},
                verdict,
                {"generator_script": "def build():\n    return b'A'\n",
                 "expected_behavior": "probe", "trigger_rationale": "input"},
                verdict,
                {"generator_script": "def build():\n    return b'B'\n",
                 "expected_behavior": "probe", "trigger_rationale": "input"},
            ])
            run = run_phase1(artifact, root / "results", target_repository=repo)
            global_corpus = run / "corpus" / "global"
            global_corpus.mkdir(parents=True)
            (global_corpus / "baseline.bin").write_bytes(b"A")
            asyncio.run(scan_selected(
                run, provider, target_repository=repo,
                run_command=[str(binary), "{input}"],
                targeted_fuzzer_binary=binary, targeted_fuzz_seconds=2,
                global_fuzzer_binary=binary, global_fuzz_enabled=True,
                global_fuzz_seconds=3, max_candidates=2,
                hallucination_prevent="off"))
            self.assertFalse(provider.responses)
            overlap = json.loads((run / "runtime/fuzz_overlap.json").read_text())
            self.assertTrue(overlap["global_sp_overlap"], overlap)
            self.assertTrue(overlap["global_analysis_overlap"], overlap)
            self.assertFalse(overlap["global_function_analysis_overlap"], overlap)
            self.assertTrue(overlap["global_sp_generation_overlap"], overlap)
            self.assertLessEqual(overlap["allocated_fuzz_seconds"], overlap["budget_seconds"])
            jobs = {row["job"].split(":")[0]: row for row in overlap["jobs"]}
            self.assertEqual(jobs["GLOBAL"]["status"], "RAN")
            self.assertEqual(jobs["SP"]["status"], "RAN")
            self.assertLess(datetime.fromisoformat(jobs["GLOBAL"]["started_at"]),
                            datetime.fromisoformat(jobs["SP"]["finished_at"]))
            points = json.loads((run / "sp/candidates.json").read_text())
            sp_id = points[0]["sp_id"]
            sp_seeds = json.loads((run / "runtime" /
                                   f"{sp_id}.targeted_fuzz.seeds.json").read_text())
            self.assertEqual(len(sp_seeds["initial_seed_hashes"]), 1)
            self.assertTrue(sp_seeds["new_seeds"], sp_seeds)
            self.assertTrue(all(Path(row["global_path"]).is_file()
                                for row in sp_seeds["new_seeds"]))
            self.assertIsNone(sp_seeds["sp_condition_reached"])
            self.assertGreaterEqual(json.loads((run / "scan.json").read_text())["poc_count"], 2)
            self.assertEqual(points[0]["status"], "OPEN")
            evidence = json.loads((run / "evidence.json").read_text())
            self.assertTrue(any(row["related_candidate"] == sp_id and
                                row["type"] == "FUZZING" for row in evidence))
            self.assertFalse(any(row["type"] == "SP_CONDITION_REACHED" and row["supports"]
                                 for row in evidence))
            # A later campaign sees content-addressed seeds from the SP run.
            followup = run_global_fuzz(binary, run, RetryLedger(2),
                                       run_command=[str(binary), "{input}"],
                                       seconds=1, enabled=True)
            self.assertEqual(followup["status"], "RAN", followup)
            self.assertGreater(followup["seed_count"], 1)


if __name__ == "__main__":
    unittest.main()
