"""The opt-in development Scan revises one completed PoV under fixed budgets."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.models import PoC, RuntimeResult, VerificationResult, stable_id
from vulnerabilityanalysis.scan import (_completed_pov_feedback, execute_poc,
                                        scan_selected)
import vulnerabilityanalysis.scan as scan_module
from vulnerabilityanalysis.workflow import run_phase1

from test_direction_plan import fixture


SOURCE = """#include <stdio.h>
#include <stdlib.h>
static int marker;
int A(void) {
    if (marker != 'X') return 0;
    char *buffer = (char *)malloc(8);
    if (buffer == NULL) return 2;
    buffer[0] = 1;
    free(buffer);
    volatile char observed = buffer[0];
    return observed;
}
int main(int argc, char **argv) {
    if (argc != 2) return 3;
    FILE *stream = fopen(argv[1], "rb");
    if (stream == NULL) return 4;
    marker = fgetc(stream);
    fclose(stream);
    return A();
}
"""


class _Provider:
    def __init__(self, *, second_script: str | None = None) -> None:
        self.requests = []
        self.second_script = second_script or "def build():\n    return b'X'\n"

    async def generate(self, request):
        self.requests.append(request)
        if request.role == "sp_generation":
            line = next(row for row in request.payload["source"].splitlines()
                        if "volatile char observed" in row)
            line_number, excerpt = line.split(": ", 1)
            return {"suspicious_points": [{
                "source_file": "target.c", "source_line": int(line_number),
                "source_excerpt": excerpt, "sp_condition": "",
                "suspicious_operation": "read buffer after free",
                "vulnerability_hypothesis": "input may reach an invalid read",
                "trigger_conditions": ["input selects the marked path"],
                "external_input_relation": "harness input selects the marker",
                "required_state": [], "security_property": "memory safety",
                "supporting_evidence": [], "contradicting_evidence": [], "unknowns": [],
            }]}
        if request.role == "poc_generator":
            script = (self.second_script if "runtime_feedback" in request.payload else
                      "def build():\n    return b'Y'\n")
            return {"generator_script": script,
                    "expected_behavior": "probe the selected function",
                    "trigger_rationale": "bounded development control"}
        raise AssertionError(f"unexpected model role: {request.role}")


async def _verifier(self, point, *_args, **_kwargs):
    self.last_request_count = 1
    point.status = "POC_PENDING"
    point.status_history.append(point.status)
    self.verifications[point.sp_id] = VerificationResult(
        point.sp_id, "UNKNOWN", "UNKNOWN", [], [], [], [], [],
        "PLAUSIBLE", "GENERATE_POC", "development revision runtime test")
    return point


class PoVFeedbackScanDevTest(unittest.TestCase):
    def _run(self, root: Path, *, call_limit: int = 4, provider: _Provider | None = None,
             run_command: list[str] | None = None, timed_out: bool = False,
             revisions: int = 1, targeted_fuzz: bool = False):
        artifact, repo, plan = fixture(root)
        (repo / "target.c").write_text(SOURCE)
        binary = repo / "asan-target"
        if run_command is None:
            compiler = shutil.which("gcc-13") or shutil.which("gcc")
            if not compiler:
                self.skipTest("GCC unavailable")
            build = subprocess.run(
                [compiler, "-g", "-O0", "-fno-omit-frame-pointer",
                 "-fsanitize=address", "-static-libasan", str(repo / "target.c"),
                 "-o", str(binary)], capture_output=True, text=True)
            if build.returncode:
                self.skipTest("static ASan build unavailable: " + build.stderr[:160])
            run_command = [str(binary), "{input}"]
        run = run_phase1(artifact, repo / "runs", target_repository=repo,
                         direction_plan=plan,
                         selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
        provider = provider or _Provider()
        with patch.object(AgentPipeline, "verify_sp", _verifier):
            if timed_out:
                incomplete = RuntimeResult(None, "", "", None, True, None, None,
                                           "TIMEOUT")
                with patch("vulnerabilityanalysis.scan.RuntimeExecutor.run",
                           return_value=incomplete):
                    asyncio.run(scan_selected(
                        run, provider, target_repository=repo,
                        run_command=run_command, max_candidates=1,
                        sp_llm_call_limit=call_limit,
                        candidate_budget_policy="DRAIN_RANKED_DEV",
                        targeted_fuzzer_binary=(Path("/usr/bin/true")
                                                if targeted_fuzz else None),
                        targeted_fuzz_seconds=int(targeted_fuzz),
                        fuzz_budget_seconds=int(targeted_fuzz),
                        pov_feedback_revisions=revisions, hallucination_prevent="off"))
            else:
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    run_command=run_command, max_candidates=1,
                    sp_llm_call_limit=call_limit,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    targeted_fuzzer_binary=(Path("/usr/bin/true")
                                            if targeted_fuzz else None),
                    targeted_fuzz_seconds=int(targeted_fuzz),
                    fuzz_budget_seconds=int(targeted_fuzz),
                    pov_feedback_revisions=revisions, hallucination_prevent="off"))
        return run, provider

    def test_real_asan_runtime_first_benign_then_revision_crash(self):
        with TemporaryDirectory() as temp:
            run, provider = self._run(Path(temp))
            pocs = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual(len(pocs), 2)
            self.assertEqual([row["revision_attempt"] for row in pocs], [1, 2])
            first = json.loads(Path(pocs[0]["execution_log"]).read_text())
            second = json.loads(Path(pocs[1]["execution_log"]).read_text())
            self.assertEqual(first["exit_code"], 0)
            self.assertIsNone(first["sanitizer"])
            self.assertNotEqual(second["exit_code"], 0)
            self.assertIsNotNone(second["sanitizer"])
            requests = [row for row in provider.requests if row.role == "poc_generator"]
            self.assertEqual(len(requests), 2)
            feedback = requests[1].payload["runtime_feedback"]
            self.assertEqual(feedback["prior_poc_id"], pocs[0]["poc_id"])
            self.assertEqual(set(requests[1].payload), {
                "suspicious_point", "source", "harness_source",
                "runtime_feedback", "prior_generator_script"})
            self.assertNotIn("stderr", json.dumps(feedback))
            self.assertEqual(pocs[1]["prior_runtime_sha256"],
                             feedback["prior_runtime_sha256"])
            ledger = json.loads((run / "poc/retry_ledger.json").read_text())
            self.assertEqual(len(ledger), 2)
            self.assertIn(feedback["prior_runtime_sha256"], ledger[1]["evidence_ids"])
            self.assertEqual(json.loads((run / "scan.json").read_text())["sp_llm_calls"], 4)
            self.assertEqual(json.loads((run / "scan.json").read_text())
                             ["verified_crash_ids"], [])
            self.assertNotEqual(pocs[0]["poc_id"], pocs[1]["poc_id"])

    def test_sp_call_cap_blocks_revision_without_consuming_runtime(self):
        with TemporaryDirectory() as temp:
            run, provider = self._run(Path(temp), call_limit=3,
                                      run_command=["/usr/bin/true", "{input}"])
            pocs = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual(len(pocs), 1)
            self.assertEqual(pocs[0]["revision_feedback_status"],
                             "BLOCKED_SP_CALL_BUDGET")
            self.assertEqual(sum(row.role == "poc_generator" for row in provider.requests), 1)

    def test_unselected_revision_option_keeps_single_pov_contract(self):
        with TemporaryDirectory() as temp:
            run, provider = self._run(Path(temp), revisions=0,
                                      run_command=["/usr/bin/true", "{input}"])
            pocs = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual(len(pocs), 1)
            self.assertNotIn("revision_attempt", pocs[0])
            self.assertNotIn("pov_feedback_revisions",
                             json.loads((run / "scan.json").read_text()))
            self.assertFalse((run / "poc/retry_ledger.json").exists())
            self.assertEqual(sum(row.role == "poc_generator" for row in provider.requests), 1)

    def test_incomplete_runtime_cannot_become_revision_feedback(self):
        with TemporaryDirectory() as temp:
            run, provider = self._run(Path(temp), timed_out=True,
                                      run_command=["/usr/bin/true", "{input}"])
            pocs = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual(len(pocs), 1)
            self.assertEqual(pocs[0]["revision_feedback_status"],
                             "INCOMPLETE_FIRST_RUNTIME")
            self.assertEqual(sum(row.role == "poc_generator" for row in provider.requests), 1)

    def test_duplicate_second_input_keeps_first_seed_and_runtime_slot(self):
        with TemporaryDirectory() as temp:
            provider = _Provider(second_script="def build():\n    return bytes([89])\n")
            run, _ = self._run(Path(temp), provider=provider,
                               run_command=["/usr/bin/true", "{input}"])
            pocs = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual([row["status"] for row in pocs],
                             ["EXECUTED_UNRESOLVED", "DUPLICATE_PRIOR_INPUT"])
            self.assertIsNone(pocs[1]["execution_log"])
            self.assertTrue((run / "corpus/candidate" / pocs[0]["sp_id"]).is_dir())
            budget = json.loads((run / "sp/turn_budget.json").read_text())
            self.assertIn("targeted-fuzzer replay may remain pending",
                          budget["runtime_replay_capacity_note"])

    def test_duplicate_second_script_never_rewrites_first_artifacts(self):
        with TemporaryDirectory() as temp:
            provider = _Provider(second_script="def build():\n    return b'Y'\n")
            run, _ = self._run(Path(temp), provider=provider,
                               run_command=["/usr/bin/true", "{input}"])
            pocs = json.loads((run / "poc/pocs.json").read_text())
            self.assertEqual([row["status"] for row in pocs],
                             ["EXECUTED_UNRESOLVED", "DUPLICATE_PRIOR_SCRIPT"])
            self.assertEqual(pocs[0]["poc_id"], pocs[1]["poc_id"])
            self.assertIsNone(pocs[1]["execution_log"])
            self.assertEqual((run / "poc" / pocs[0]["poc_id"] /
                              "input.bin").read_bytes(), b"Y")
            self.assertEqual(json.loads(Path(pocs[0]["execution_log"]).read_text())
                             ["exit_code"], 0)

    def test_targeted_fuzzer_starts_after_second_completed_seed(self):
        with TemporaryDirectory() as temp:
            observed: list[set[bytes]] = []

            def inspect_corpus(point, _binary, run_dir, *_args, **_kwargs):
                corpus = run_dir / "corpus/candidate" / point.sp_id
                observed.append({path.read_bytes() for path in corpus.iterdir()
                                 if path.is_file()})
                return None

            with patch("vulnerabilityanalysis.scan.run_targeted_fuzz",
                       side_effect=inspect_corpus):
                run, _ = self._run(Path(temp),
                                   run_command=["/usr/bin/true", "{input}"],
                                   targeted_fuzz=True)
            self.assertEqual(observed, [{b"Y", b"X"}])
            self.assertEqual(len(json.loads((run / "poc/pocs.json").read_text())), 2)

    def test_targeted_replay_rejects_symlinked_sp_corpus_ancestor(self):
        with TemporaryDirectory() as temp:
            outside = Path(temp) / "external-corpus"
            observed = []

            def symlinked_crash(point, binary, run_dir, *_args, **_kwargs):
                corpus = run_dir / "corpus" / "candidate" / point.sp_id
                corpus.rename(outside)
                corpus.symlink_to(outside, target_is_directory=True)
                witness = corpus / "crash-synthetic"
                witness.write_bytes(b"synthetic crash")
                input_sha = hashlib.sha256(witness.read_bytes()).hexdigest()
                observed.append((point.sp_id, input_sha))
                (run_dir / "runtime" /
                 f"{point.sp_id}.targeted_fuzz.seeds.json").write_text(json.dumps({
                    "sp_id": point.sp_id,
                    "new_seeds": [], "pending_crash_inputs": [],
                    "crash_inputs": [{
                        "observed_crash_id": stable_id(
                            "sp-fuzzer-input", hashlib.sha256(binary.read_bytes()).hexdigest(),
                            input_sha),
                        "candidate_path": str(witness), "sha256": input_sha,
                        "size": witness.stat().st_size,
                    }],
                }))
                return {"status": "CRASH_OBSERVED_INCOMPLETE"}

            original_safe_load = scan_module.yaml.safe_load

            def allow_one_replay(value):
                config = original_safe_load(value)
                if isinstance(config, dict) and "budget" in config:
                    config["budget"]["max_runtime_attempts"] = 3
                return config

            with patch("vulnerabilityanalysis.scan.run_targeted_fuzz",
                       side_effect=symlinked_crash), \
                 patch("vulnerabilityanalysis.scan.yaml.safe_load",
                       side_effect=allow_one_replay), \
                 patch("vulnerabilityanalysis.scan.execute_poc",
                       wraps=execute_poc) as executed:
                run, _ = self._run(Path(temp),
                                   run_command=["/usr/bin/true", "{input}"],
                                   targeted_fuzz=True)
            self.assertEqual(len(observed), 1)
            sp_id, input_sha = observed[0]
            replay_id = stable_id("poc", sp_id, input_sha, "fuzzer-replay")
            self.assertNotIn(replay_id,
                             [call.args[0].poc_id for call in executed.call_args_list])
            pending = json.loads((run / "runtime" /
                f"{sp_id}.targeted_fuzz.pending_replay.json").read_text())
            self.assertEqual(pending["pending_inputs"][0]["reason"],
                             "INVALID_OR_OVERSIZE_INPUT")
            pocs = json.loads((run / "poc" / "pocs.json").read_text())
            self.assertNotIn(replay_id, {row["poc_id"] for row in pocs})

    def test_timed_out_targeted_replay_keeps_global_replay_opportunity(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo, plan = fixture(root)
            (repo / "target.c").write_text(SOURCE)
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            binary = Path(shutil.which("true") or "/usr/bin/true").resolve()
            input_bytes = b"same global and targeted input"
            input_sha = hashlib.sha256(input_bytes).hexdigest()
            crash_id = stable_id("global-fuzzer-input", input_sha)
            targeted_replay_id = []

            def targeted(point, _binary, run_dir, *_args, **_kwargs):
                candidate = run_dir / "corpus" / "candidate" / point.sp_id
                candidate.mkdir(parents=True, exist_ok=True)
                witness = candidate / "crash-same"
                witness.write_bytes(input_bytes)
                observed_id = stable_id("sp-fuzzer-input", input_sha)
                (run_dir / "runtime" /
                 f"{point.sp_id}.targeted_fuzz.seeds.json").write_text(json.dumps({
                    "sp_id": point.sp_id, "new_seeds": [],
                    "pending_crash_inputs": [],
                    "crash_inputs": [{"observed_crash_id": observed_id,
                                      "candidate_path": str(witness),
                                      "sha256": input_sha, "size": len(input_bytes)}],
                }))
                targeted_replay_id.append(stable_id("poc", point.sp_id,
                                                    input_sha, "fuzzer-replay"))
                return {"status": "CRASH_OBSERVED_INCOMPLETE"}

            def global_fuzz(_binary, run_dir, *_args, **_kwargs):
                return {"status": "RAN", "coverage_feedback": None,
                    "runtime_artifact": str(
                    run_dir / "runtime" / "global_fuzz.json"),
                    "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "observed_crashes": [{"observed_crash_id": crash_id,
                                          "sha256": input_sha}]}

            incomplete = RuntimeResult(None, "", "", None, True, None, None,
                                       "TIMEOUT")
            provider = _Provider()
            with patch.object(AgentPipeline, "verify_sp", _verifier), \
                 patch("vulnerabilityanalysis.scan.run_targeted_fuzz",
                       side_effect=targeted), \
                 patch("vulnerabilityanalysis.scan.run_global_fuzz",
                       side_effect=global_fuzz), \
                 patch("vulnerabilityanalysis.scan.RuntimeExecutor.run",
                       return_value=incomplete), \
                 patch("vulnerabilityanalysis.fuzzer_crash_consumer."
                       "consume_fuzzer_crash_observation",
                       return_value={"status": "PENDING_CAUSAL_EVIDENCE"}) as consume:
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    run_command=[str(binary), "{input}"], target_binary=binary,
                    max_candidates=1, sp_llm_call_limit=4,
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    targeted_fuzzer_binary=binary, targeted_fuzz_seconds=1,
                    global_fuzzer_binary=binary, global_fuzz_enabled=True,
                    global_fuzz_seconds=1, fuzz_budget_seconds=2,
                    hallucination_prevent="off"))
            self.assertEqual(len(targeted_replay_id), 1)
            targeted_runtime = json.loads((run / "runtime" /
                f"{targeted_replay_id[0]}.json").read_text())
            self.assertTrue(targeted_runtime["timed_out"])
            consume.assert_called_once()
            self.assertEqual(consume.call_args.args[1:3], (crash_id, input_sha))
            rows = json.loads((run / "runtime" /
                               "global_fuzzer_consumption.json").read_text())
            self.assertEqual(rows[0]["status"], "PENDING_CAUSAL_EVIDENCE")

    def test_non_dev_policy_rejects_feedback_before_any_provider_call(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _ = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo)
            provider = _Provider()
            with self.assertRaisesRegex(ValueError, "development queue"):
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    run_command=["/usr/bin/true", "{input}"],
                    pov_feedback_revisions=1, hallucination_prevent="off"))
            self.assertEqual(provider.requests, [])

    def test_resume_cannot_reset_the_two_attempt_feedback_ledger(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            provider = _Provider()
            with self.assertRaisesRegex(ValueError, "fresh per-run retry ledger"):
                asyncio.run(scan_selected(
                    run, provider, target_repository=repo,
                    run_command=["/usr/bin/true", "{input}"],
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    pov_feedback_revisions=1, resume_from=repo / "prior"))
            self.assertEqual(provider.requests, [])

    def test_changed_persisted_runtime_cannot_enter_model_feedback(self):
        with TemporaryDirectory() as temp:
            run = Path(temp)
            script = "def build():\n    return b'Y'\n"
            poc_id = stable_id("poc", "sp-test", script)
            poc_dir = run / "poc" / poc_id
            runtime_dir = run / "runtime"
            poc_dir.mkdir(parents=True)
            runtime_dir.mkdir()
            (poc_dir / "generate.py").write_text(script)
            (poc_dir / "input.bin").write_bytes(b"Y")
            runtime_path = runtime_dir / f"{poc_id}.json"
            runtime_path.write_text(json.dumps({
                "exit_code": 0, "timed_out": False, "sanitizer": None,
                "crash_triage": None, "failure_classification": "UNKNOWN",
                "function_reached": None, "sp_location_reached": None,
                "sp_condition_reached": None}))
            expected_runtime_sha = hashlib.sha256(runtime_path.read_bytes()).hexdigest()
            poc = PoC(poc_id, "sp-test", script, str(poc_dir / "input.bin"),
                      ["/usr/bin/true", "{input}"], "no crash",
                      execution_log=str(runtime_path), status="EXECUTED_UNRESOLVED")
            runtime_path.write_bytes(runtime_path.read_bytes() + b"\n")
            feedback, status = _completed_pov_feedback(
                poc, run, input_sha256=hashlib.sha256(b"Y").hexdigest(),
                runtime_sha256=expected_runtime_sha)
            self.assertIsNone(feedback)
            self.assertEqual(status, "FIRST_ARTIFACT_SHA256_MISMATCH")

    def test_completed_runtime_passes_only_pinned_failure_classification(self):
        with TemporaryDirectory() as temp:
            run = Path(temp)
            script = "def build():\n    return b'Y'\n"
            poc_id = stable_id("poc", "sp-test", script)
            poc_dir = run / "poc" / poc_id
            runtime_dir = run / "runtime"
            poc_dir.mkdir(parents=True)
            runtime_dir.mkdir()
            (poc_dir / "generate.py").write_text(script)
            (poc_dir / "input.bin").write_bytes(b"Y")
            runtime_path = runtime_dir / f"{poc_id}.json"
            runtime_path.write_text(json.dumps({
                "exit_code": 0, "timed_out": False, "sanitizer": None,
                "crash_triage": None,
                "failure_classification": "TARGET_NOT_REACHED",
                "function_reached": False, "sp_location_reached": False,
                "sp_condition_reached": False,
            }))
            poc = PoC(poc_id, "sp-test", script, str(poc_dir / "input.bin"),
                      ["/usr/bin/true", "{input}"], "no crash",
                      execution_log=str(runtime_path), status="EXECUTED_UNRESOLVED")
            feedback, status = _completed_pov_feedback(
                poc, run, input_sha256=hashlib.sha256(b"Y").hexdigest(),
                runtime_sha256=hashlib.sha256(runtime_path.read_bytes()).hexdigest())
            self.assertEqual(status, "ELIGIBLE")
            self.assertEqual(feedback["failure_classification"], "TARGET_NOT_REACHED")
            self.assertNotIn("stderr", feedback)


if __name__ == "__main__":
    unittest.main()
