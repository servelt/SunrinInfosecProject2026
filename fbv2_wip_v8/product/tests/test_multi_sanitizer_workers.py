"""A Harness × Sanitizer pair owns its own function history and SP evidence."""
import asyncio
from contextlib import redirect_stdout
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from vulnerabilityanalysis.scan import scan_selected, worker_corpus_identity
from vulnerabilityanalysis.workflow import (continue_phase1, prepare_function_retry,
                                            prepare_sp_resume, run_phase1, write_json)


def fixture(root: Path, sanitizers: list[str], *, two_functions: bool = False) -> tuple[Path, Path]:
    repo = root / "repo"
    repo.mkdir()
    (repo / "target.c").write_text(
        "int parse(const unsigned char *data, unsigned long size) {\n"
        "  return size ? data[0] : 0;\n}\n"
        + ("int parse_other(void) { return 0; }\n" if two_functions else ""))
    artifact = root / "harness"
    artifact.mkdir()
    (artifact / "fuzz.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) "
        "{ return parse(data, size); }\n")
    functions = [{"function_id": "fn-parse", "name": "parse", "file": "target.c"}]
    if two_functions:
        functions.append({"function_id": "fn-other", "name": "parse_other",
                          "file": "target.c"})
    (artifact / "manifest.json").write_text(json.dumps({
        "harness_id": "same-harness", "source_file": "fuzz.c",
        "expected_consumers": [row["name"] for row in functions],
        "sanitizers": sanitizers}))
    (artifact / "validation.json").write_text('{"build_ok": true}')
    (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
    (root / "analysis").mkdir()
    (root / "analysis/functions.jsonl").write_text(
        "\n".join(json.dumps(row) for row in functions) + "\n")
    return artifact, repo


def read(path: Path):
    return json.loads(path.read_text())


def select_ubsan(run: Path) -> dict:
    """Persist a valid UBSan pool selection without depending on score tie order."""
    workers = read(run / "workers.json")
    directions = read(run / "directions.json")
    ubsan_id = next(row["worker_id"] for row in workers if row["sanitizer"] == "UBSAN")
    direction_id = next(row["direction_id"] for row in directions
                        if row["worker_id"] == ubsan_id)
    selected = next(row for row in read(run / "function_pool.json")
                    if row["direction_id"] == direction_id)
    write_json(run / "selection.json", selected)
    return {"worker_id": ubsan_id, "direction_id": direction_id,
            "selection": selected}


class SPPathProvider:
    """Deterministic fake LLM; RuntimeExecutor still runs the supplied command."""
    def __init__(self):
        self.roles = []

    async def generate(self, request):
        self.roles.append(request.role)
        if request.role == "sp_generation":
            return {"suspicious_points": [{
                "source_file": "target.c", "source_line": 2,
                "source_excerpt": "  return size ? data[0] : 0;", "sp_condition": "",
                "suspicious_operation": "data[0]",
                "vulnerability_hypothesis": "input access needs verification",
                "trigger_conditions": ["nonempty input"],
                "external_input_relation": "harness data reaches parse",
                "required_state": [], "security_property": "memory safety",
                "supporting_evidence": [], "contradicting_evidence": [], "unknowns": []}]}
        if request.role == "sp_verifier":
            return {"status": "PLAUSIBLE", "supporting_evidence": [],
                    "contradicting_evidence": [], "unknowns": ["runtime state"],
                    "rationale": "needs execution", "reachability": "UNKNOWN",
                    "controllability": "UNKNOWN", "guards": [], "required_state": [],
                    "contradiction_snippet": "", "contradiction_scope": "UNKNOWN",
                    "context_requests": [], "recommended_next_action": "GENERATE_POC"}
        if request.role == "poc_generator":
            return {"generator_script": "def build():\n    return b'A'\n",
                    "expected_behavior": "exercise parse", "trigger_rationale": "input"}
        raise AssertionError(request.role)


class MultiSanitizerWorkerTest(unittest.TestCase):
    def test_cli_binary_switches_worker_corpus_and_fuzz_budget(self):
        from vulnerabilityanalysis import __main__ as cli

        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "target.c"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=test",
                            "-c", "user.email=test@example.invalid", "commit", "-qm", "source"],
                           check=True)
            binary = root / "existing-binary"
            binary.write_bytes(b"test-binary-identity")
            first = run_phase1(artifact, root / "results", target_repository=repo)
            imported = []
            budgets = []
            original_sync = cli.sync_worker_corpus

            def capture_sync(run_dir, folder, *, direction, **kwargs):
                if direction == "import":
                    imported.append((run_dir.resolve(), folder.resolve()))
                return original_sync(run_dir, folder, direction=direction, **kwargs)

            async def fake_scan(run_dir, _client, **kwargs):
                budgets.append(kwargs["fuzz_budget_seconds"])
                selection = read(run_dir / "selection.json")
                write_json(run_dir / "scan.json", {
                    "selected_function": selection["function_name"],
                    "target_repository": str(repo), "llm_calls": 0,
                    "sp_count": 0, "poc_count": 0, "fuzz_seconds_allocated": 3})
                return run_dir

            argv = ["vulnerabilityanalysis", "scan", str(first),
                    "--target-repository", str(repo), "--binary", str(binary),
                    "--max-functions", "2", "--hallucination-prevent", "off"]
            with patch("sys.argv", argv), patch.object(cli, "configured_client",
                    return_value=(Client(), {})), patch.object(cli, "scan_selected", fake_scan), \
                    patch.object(cli, "sync_worker_corpus", capture_sync), \
                    redirect_stdout(io.StringIO()):
                cli.main()

            self.assertEqual(len(imported), 2)
            self.assertNotEqual(imported[0][1], imported[1][1])
            max_fuzz = yaml.safe_load((Path(cli.__file__).resolve().parents[2]
                                       / "config/default.yaml").read_text())["budget"]["max_fuzz_time"]
            self.assertEqual(budgets, [max_fuzz, max_fuzz])

    def test_same_worker_repeated_function_across_directions_keeps_previous_completion_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN"], two_functions=True)
            first = run_phase1(artifact, root / "results", target_repository=repo)
            selected = read(first / "selection.json")
            directions = read(first / "directions.json")
            pool = read(first / "function_pool.json")
            clone = {**next(row for row in pool
                            if row["function_id"] == selected["function_id"]),
                     "direction_id": "same-worker-other-direction"}
            pool.append(clone)
            directions.append({**directions[0], "direction_id": clone["direction_id"]})
            write_json(first / "function_pool.json", pool)
            write_json(first / "directions.json", directions)
            write_json(first / "scan.json", {"selected_function": selected["function_name"],
                                             "target_repository": str(repo)})

            second = continue_phase1(first)
            completed = [row for row in read(second / "function_pool.json")
                         if row["function_id"] == selected["function_id"]]
            self.assertEqual(len(completed), 2)
            self.assertTrue(all(row["analyzed"] for row in completed))
            self.assertNotEqual(read(second / "selection.json")["function_id"],
                                selected["function_id"])

    def test_multi_worker_unknown_direction_never_falls_back_to_first_worker(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                artifact, repo = fixture(root, ["ASAN", "UBSAN"])
                run = run_phase1(artifact, root / "results", target_repository=repo)
                selection = read(run / "selection.json")
                if missing:
                    selection.pop("direction_id")
                else:
                    selection["direction_id"] = "not-a-persisted-direction"
                write_json(run / "selection.json", selection)
                provider = SPPathProvider()
                with self.assertRaises(ValueError):
                    asyncio.run(scan_selected(run, provider, target_repository=repo,
                                              hallucination_prevent="off"))
                self.assertEqual(provider.roles, [])
                self.assertFalse((run / "sp/candidates.json").exists())

    def test_sp_resume_rejects_same_function_from_different_worker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            first = run_phase1(artifact, root / "results", target_repository=repo)
            selected = read(first / "selection.json")
            write_json(first / "scan.json", {"selected_function": selected["function_name"],
                                             "pending_sp_ids": ["sp-pending"]})
            write_json(first / "sp/candidates.json", [])
            write_json(first / "context.json", [])
            resumed = prepare_sp_resume(first, first.parent / "resumed")
            different_worker = next(row for row in read(resumed / "function_pool.json")
                                    if row["direction_id"] != selected["direction_id"])
            self.assertEqual(different_worker["function_id"], selected["function_id"])
            write_json(resumed / "selection.json", different_worker)
            provider = SPPathProvider()
            with self.assertRaises(ValueError):
                asyncio.run(scan_selected(resumed, provider, target_repository=repo,
                                          resume_from=first, hallucination_prevent="off"))
            self.assertEqual(provider.roles, [])

    def test_cli_function_budget_scans_both_sanitizer_workers(self):
        from vulnerabilityanalysis import __main__ as cli

        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            first = run_phase1(artifact, root / "results", target_repository=repo)
            scanned = []

            async def fake_scan(run_dir, _client, **_kwargs):
                selection = read(run_dir / "selection.json")
                scanned.append(selection["direction_id"])
                write_json(run_dir / "scan.json", {
                    "selected_function": selection["function_name"],
                    "target_repository": str(repo), "llm_calls": 0,
                    "sp_count": 0, "poc_count": 0, "fuzz_seconds_allocated": 0})
                return run_dir

            argv = ["vulnerabilityanalysis", "scan", str(first),
                    "--target-repository", str(repo), "--max-functions", "2",
                    "--hallucination-prevent", "off"]
            with patch("sys.argv", argv), patch.object(cli, "configured_client",
                    return_value=(Client(), {})), patch.object(cli, "scan_selected", fake_scan), \
                    redirect_stdout(io.StringIO()):
                cli.main()
            self.assertEqual(len(scanned), 2)
            self.assertEqual(len(set(scanned)), 2)
            self.assertEqual(len(read(first / "function_scan.json")["analyses"]), 2)

    def test_cli_all_scans_complete_pool_without_a_fixed_function_k(self):
        from vulnerabilityanalysis import __main__ as cli

        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            first = run_phase1(artifact, root / "results", target_repository=repo)
            scanned = []

            async def fake_scan(run_dir, _client, **_kwargs):
                selection = read(run_dir / "selection.json")
                scanned.append(selection["direction_id"])
                write_json(run_dir / "scan.json", {
                    "selected_function": selection["function_name"],
                    "target_repository": str(repo), "llm_calls": 0,
                    "sp_count": 0, "poc_count": 0, "fuzz_seconds_allocated": 0})
                return run_dir

            argv = ["vulnerabilityanalysis", "scan", str(first),
                    "--target-repository", str(repo), "--max-functions", "all",
                    "--max-scan-seconds", "60", "--hallucination-prevent", "off"]
            with patch("sys.argv", argv), patch.object(cli, "configured_client",
                    return_value=(Client(), {})), patch.object(cli, "scan_selected", fake_scan), \
                    redirect_stdout(io.StringIO()):
                cli.main()
            self.assertEqual(len(scanned), 2)
            self.assertEqual(len(set(scanned)), 2)
            setup = read(first / "experiment_setup.json")
            summary = read(first / "function_scan.json")
            self.assertIsNone(setup["max_functions"])
            self.assertIsNone(summary["function_budget"])
            self.assertEqual(summary["pool_candidates"], 2)
            self.assertEqual(summary["stop_reason"], "POOL_EXHAUSTED")
            self.assertEqual(summary["unanalysed_functions"], [])

    def test_cli_all_stops_at_wall_budget_between_functions(self):
        from vulnerabilityanalysis import __main__ as cli

        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            first = run_phase1(artifact, root / "results", target_repository=repo)
            elapsed = [0.0]
            scanned = []

            async def fake_scan(run_dir, _client, **_kwargs):
                selection = read(run_dir / "selection.json")
                scanned.append(selection["direction_id"])
                write_json(run_dir / "scan.json", {
                    "selected_function": selection["function_name"],
                    "target_repository": str(repo), "llm_calls": 0,
                    "sp_count": 0, "poc_count": 0, "fuzz_seconds_allocated": 0})
                elapsed[0] = 31.0
                return run_dir

            argv = ["vulnerabilityanalysis", "scan", str(first),
                    "--target-repository", str(repo), "--max-functions", "all",
                    "--max-scan-seconds", "30", "--hallucination-prevent", "off"]
            with patch("sys.argv", argv), patch.object(cli, "configured_client",
                    return_value=(Client(), {})), patch.object(cli, "scan_selected", fake_scan), \
                    patch.object(cli, "time", SimpleNamespace(monotonic=lambda: elapsed[0])), \
                    redirect_stdout(io.StringIO()):
                cli.main()
            self.assertEqual(len(scanned), 1)
            summary = read(first / "function_scan.json")
            self.assertEqual(summary["stop_reason"],
                             "WALL_BUDGET_EXHAUSTED_AFTER_COMPLETED_FUNCTION")
            self.assertIsNone(summary["selected_but_not_scanned"])
            self.assertEqual(len(summary["unanalysed_functions"]), 1)
            self.assertFalse((first / "scan_timeout.json").exists())

    def test_completed_function_remains_pending_in_other_sanitizer_worker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            first = run_phase1(artifact, root / "results", target_repository=repo)
            workers = read(first / "workers.json")
            directions = read(first / "directions.json")
            pool = read(first / "function_pool.json")
            self.assertEqual(len(workers), 2)
            self.assertEqual({row["sanitizer"] for row in workers}, {"ASAN", "UBSAN"})
            self.assertEqual(len(directions), 2)
            self.assertEqual(len(pool), 2)
            self.assertEqual({row["function_id"] for row in pool}, {"fn-parse"})
            selected = read(first / "selection.json")
            write_json(first / "scan.json", {"selected_function": selected["function_name"],
                                             "target_repository": str(repo)})

            second = continue_phase1(first)
            second_selection = read(second / "selection.json")
            second_pool = read(second / "function_pool.json")
            self.assertEqual(second_selection["function_id"], selected["function_id"])
            self.assertNotEqual(second_selection["direction_id"], selected["direction_id"])
            self.assertEqual({row["direction_id"] for row in second_pool if row["analyzed"]},
                             {selected["direction_id"]})
            self.assertEqual({row["direction_id"] for row in second_pool if not row["analyzed"]},
                             {second_selection["direction_id"]})
            self.assertFalse(read(first / "function_pool.json")[0]["analyzed"])

    def test_scan_attributes_sp_pov_but_does_not_infer_runtime_sanitizer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            run = run_phase1(artifact, root / "results", target_repository=repo)
            selected = select_ubsan(run)
            provider = SPPathProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="off"))

            points = read(run / "sp/candidates.json")
            pocs = read(run / "poc/pocs.json")
            scan = read(run / "scan.json")
            self.assertEqual(provider.roles,
                             ["sp_generation", "sp_verifier", "poc_generator"])
            self.assertEqual(len(points), 1)
            self.assertEqual(len(pocs), 1)
            self.assertEqual(scan["poc_count"], 1)
            self.assertEqual(points[0]["worker_id"], selected["worker_id"])
            self.assertEqual(points[0]["direction_id"], selected["direction_id"])
            self.assertEqual(pocs[0]["sp_id"], points[0]["sp_id"])
            runtime = read(run / "runtime" / f"{pocs[0]['poc_id']}.json")
            # /usr/bin/true is a runtime stub, not a verified UBSan build.
            self.assertEqual(runtime["runtime_profile"]["sanitizers"], ["UNKNOWN"])
            self.assertEqual(runtime["runtime_profile"]["source"], "UNKNOWN")
            self.assertEqual(runtime["source_artifact_sanitizers"], ["ASAN", "UBSAN"])
            self.assertIsNone(runtime["sanitizer"])

    def test_two_worker_sp_and_pov_runs_keep_separate_histories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            current = run_phase1(artifact, root / "results", target_repository=repo)
            observed = []
            for index in range(2):
                selected = read(current / "selection.json")
                directions = read(current / "directions.json")
                workers = read(current / "workers.json")
                direction = next(row for row in directions
                                 if row["direction_id"] == selected["direction_id"])
                worker = next(row for row in workers
                              if row["worker_id"] == direction["worker_id"])
                provider = SPPathProvider()
                asyncio.run(scan_selected(current, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          hallucination_prevent="off"))
                points = read(current / "sp/candidates.json")
                pocs = read(current / "poc/pocs.json")
                self.assertEqual(provider.roles,
                                 ["sp_generation", "sp_verifier", "poc_generator"])
                self.assertEqual(len(points), 1)
                self.assertEqual(len(pocs), 1)
                self.assertEqual(points[0]["worker_id"], worker["worker_id"])
                self.assertEqual(points[0]["direction_id"], selected["direction_id"])
                self.assertEqual(pocs[0]["sp_id"], points[0]["sp_id"])
                self.assertTrue((current / "runtime" / f"{pocs[0]['poc_id']}.json").is_file())
                observed.append((worker["sanitizer"], selected["function_id"],
                                 points[0]["sp_id"], current))
                if index == 0:
                    current = continue_phase1(current)
            self.assertEqual({row[0] for row in observed}, {"ASAN", "UBSAN"})
            self.assertEqual({row[1] for row in observed}, {"fn-parse"})
            self.assertNotEqual(observed[0][2], observed[1][2])
            history = read(observed[1][3] / "function_pool.json")
            self.assertEqual(len([row for row in history if row["analyzed"]]), 1)
            self.assertEqual(len([row for row in history if not row["analyzed"]]), 1)
            with self.assertRaisesRegex(ValueError, "function pool exhausted"):
                continue_phase1(current)

    def test_mismatched_explicit_runtime_sanitizer_blocks_selected_worker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            run = run_phase1(artifact, root / "results", target_repository=repo)
            select_ubsan(run)
            provider = SPPathProvider()
            with self.assertRaisesRegex(ValueError, "sanitizer|Worker|worker"):
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          runtime_sanitizers=["ASAN"],
                                          hallucination_prevent="off"))
            self.assertFalse(list((run / "runtime").glob("poc*.json")))

    def test_unknown_worker_keeps_explicit_runtime_sanitizer_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["UNKNOWN"])
            run = run_phase1(artifact, root / "results", target_repository=repo)
            provider = SPPathProvider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      runtime_sanitizers=["ASAN"],
                                      hallucination_prevent="off"))
            poc = read(run / "poc/pocs.json")[0]
            runtime = read(run / "runtime" / f"{poc['poc_id']}.json")
            self.assertEqual(runtime["source_artifact_sanitizers"], ["UNKNOWN"])
            self.assertEqual(runtime["runtime_profile"]["sanitizers"], ["ASAN"])
            self.assertEqual(runtime["runtime_profile"]["source"],
                             "explicit_runtime_configuration")

    def test_worker_corpus_identity_uses_selected_sanitizer_worker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["ASAN", "UBSAN"])
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "target.c"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=test",
                            "-c", "user.email=test@example.invalid", "commit", "-qm", "source"],
                           check=True)
            run = run_phase1(artifact, root / "results", target_repository=repo)
            selected = select_ubsan(run)
            binary = root / "fuzzer-bin"
            binary.write_bytes(b"ubsan-validation-binary")
            identity = worker_corpus_identity(run, repo, binary, ["UBSAN"])
            self.assertEqual(identity["worker_id"], selected["worker_id"])
            self.assertEqual(identity["sanitizers"], ["UBSAN"])

    def test_single_worker_continuation_and_legacy_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, repo = fixture(root, ["UNKNOWN"], two_functions=True)
            first = run_phase1(artifact, root / "results", target_repository=repo)
            selected = read(first / "selection.json")
            self.assertEqual(len(read(first / "workers.json")), 1)
            # Historical runs could persist the Scheduler reservation before Scan.
            pool = read(first / "function_pool.json")
            next(row for row in pool if row["function_id"] == selected["function_id"])[
                "analyzed"] = True
            write_json(first / "function_pool.json", pool)
            write_json(first / "scan_timeout.json", {"status": "SCAN_WALL_TIME_EXCEEDED"})
            retried = prepare_function_retry(first, first.parent / "retry")
            self.assertFalse(next(row["analyzed"] for row in read(retried / "function_pool.json")
                                  if row["function_id"] == selected["function_id"]))
            write_json(retried / "scan.json", {"selected_function": selected["function_name"],
                                               "target_repository": str(repo)})
            continued = continue_phase1(retried, first.parent / "continued")
            self.assertNotEqual(read(continued / "selection.json")["function_id"],
                                selected["function_id"])
            self.assertEqual(read(continued / "workers.json")[0]["sanitizer"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
