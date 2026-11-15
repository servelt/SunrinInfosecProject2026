import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.models import NormalizedHarness
from vulnerabilityanalysis.scheduler import (Scheduler, build_directions, build_pool,
                                             build_workers, source_evidence_for_pool)
from vulnerabilityanalysis.workflow import (continue_phase1, prepare_function_retry,
                                             prepare_sp_resume, run_phase1)


ROOT = Path(__file__).resolve().parents[2]
QUARTET = ROOT / "reference/QuartetFuzz/QuartetFuzz/subset_25/precomputed/libyaml__libyaml_scanner_fuzzer"
PUGIXML = ROOT / "reference/QuartetFuzz/QuartetFuzz/subset_25/precomputed/pugixml__fuzz_xpath"


class RealArtifactTest(unittest.TestCase):
    def test_scan_cli_preserves_binary_command_during_assertion_option_validation(self):
        from vulnerabilityanalysis import __main__ as cli

        class Client:
            model_request_counts = {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

        class CapturedCommand(Exception):
            pass

        async def capture_scan(_run_dir, _client, **kwargs):
            self.assertEqual(kwargs["run_command"], ["/tmp/va-cli-regression", "{input}"])
            raise CapturedCommand

        with tempfile.TemporaryDirectory() as tmp:
            for with_assertion_options in (False, True):
                with self.subTest(with_assertion_options=with_assertion_options):
                    run_dir = run_phase1(QUARTET, Path(tmp))
                    argv = ["vulnerabilityanalysis", "scan", str(run_dir),
                            "--target-repository", str(ROOT),
                            "--binary", "/tmp/va-cli-regression", "--max-functions", "1"]
                    if with_assertion_options:
                        argv.extend(["--assertion-build-command",
                                     '["cc", "{source}", "-o", "{binary}"]',
                                     "--assertion-run-command", '["{binary}", "{input}"]'])
                    with patch("sys.argv", argv), patch.object(cli, "configured_client",
                            return_value=(Client(), {})), patch.object(cli, "scan_selected", capture_scan):
                        with self.assertRaises(CapturedCommand):
                            cli.main()

    def test_completed_function_advances_pool_without_reanalysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = run_phase1(QUARTET, root)
            names = []
            for index in range(3):
                selected = json.loads((previous / "selection.json").read_text())
                names.append(selected["function_name"])
                if index == 0:
                    with self.assertRaises(FileNotFoundError):
                        continue_phase1(previous)
                (previous / "scan.json").write_text(json.dumps({
                    "selected_function": selected["function_name"],
                    "target_repository": str(ROOT)}))
                if index < 2:
                    next_run = continue_phase1(previous)
                    with self.assertRaisesRegex(ValueError, "already has a continuation"):
                        continue_phase1(previous)
                    previous = next_run
            self.assertEqual(len(set(names)), 3)
            pool = json.loads((previous / "function_pool.json").read_text())
            self.assertEqual(sum(row["analyzed"] for row in pool), 2)
            self.assertEqual(sum(not row["analyzed"] for row in pool), len(pool) - 2)
            self.assertEqual(json.loads((previous / "run.json").read_text())["scheduler_turn"], 3)

    def test_pending_sp_resume_preserves_later_selected_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = run_phase1(QUARTET, root)
            first_selection = json.loads((first / "selection.json").read_text())
            (first / "scan.json").write_text(json.dumps({
                "selected_function": first_selection["function_name"],
                "target_repository": str(ROOT)}))
            second = continue_phase1(first)
            selected = json.loads((second / "selection.json").read_text())
            self.assertNotEqual(selected["function_id"], first_selection["function_id"])
            (second / "scan.json").write_text(json.dumps({
                "selected_function": selected["function_name"],
                "pending_sp_ids": ["sp-pending"]}))
            original = (second / "scan.json").read_bytes()
            resumed = prepare_sp_resume(second, root / "new-sp-run")
            self.assertEqual(json.loads((resumed / "selection.json").read_text())["function_id"],
                             selected["function_id"])
            self.assertEqual(json.loads((resumed / "run.json").read_text())["resume_source_run_id"],
                             second.name)
            self.assertEqual((second / "scan.json").read_bytes(), original)
            with self.assertRaisesRegex(ValueError, "fresh run"):
                prepare_sp_resume(second, resumed)

    def test_interrupted_function_retries_without_marking_it_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = run_phase1(QUARTET, root)
            selected = json.loads((first / "selection.json").read_text())
            # Older artifacts recorded Scheduler selection as analyzed before Scan.
            old_pool = json.loads((first / "function_pool.json").read_text())
            for row in old_pool:
                if row["function_id"] == selected["function_id"]:
                    row["analyzed"] = True
            (first / "function_pool.json").write_text(json.dumps(old_pool))
            (first / "scan_timeout.json").write_text('{"status":"SCAN_WALL_TIME_EXCEEDED"}')
            snapshot = (first / "selection.json").read_bytes()
            retried = prepare_function_retry(first, root / "retry")
            self.assertEqual((retried / "selection.json").read_bytes(), snapshot)
            self.assertEqual(json.loads((retried / "run.json").read_text())
                             ["retry_source_run_id"], first.name)
            pool = json.loads((retried / "function_pool.json").read_text())
            self.assertFalse(next(row["analyzed"] for row in pool
                                  if row["function_id"] == selected["function_id"]))
            self.assertFalse((first / "scan.json").exists())
            (retried / "scan.json").write_text(json.dumps({
                "selected_function": selected["function_name"],
                "target_repository": str(ROOT)}))
            next_run = continue_phase1(retried, root / "next")
            self.assertNotEqual(json.loads((next_run / "selection.json").read_text())
                                ["function_id"], selected["function_id"])
            with self.assertRaisesRegex(ValueError, "not recorded as interrupted"):
                prepare_function_retry(retried, root / "invalid")

    def test_worker_fuzz_budget_survives_timeout_and_retry(self):
        from vulnerabilityanalysis.__main__ import worker_fuzz_seconds_used

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = run_phase1(QUARTET, root)
            selected = json.loads((first / "selection.json").read_text())
            (first / "scan.json").write_text(json.dumps({
                "selected_function": selected["function_name"],
                "target_repository": str(ROOT), "fuzz_seconds_allocated": 5}))
            second = continue_phase1(first)
            (second / "scan_timeout.json").write_text('{"status":"SCAN_WALL_TIME_EXCEEDED"}')
            (second / "runtime").mkdir()
            (second / "runtime/fuzz_allocation.json").write_text('{"allocated_seconds":3}')
            retried = prepare_function_retry(second, root / "retry")
            self.assertEqual(worker_fuzz_seconds_used(retried, None), 8)

    def test_successful_reference_harness_reaches_explainable_selection(self):
        harness = HarnessAdapter().load(QUARTET)
        self.assertTrue(harness.build_verified)
        self.assertEqual(harness.harness_path, str((QUARTET / "libyaml_scanner_fuzzer.c").resolve()))
        self.assertIsNone(harness.run_command)
        self.assertIsNone(harness.runtime_reached_functions)
        workers = build_workers(harness)
        self.assertEqual(len(workers), 1)
        directions = build_directions(harness, workers[0])
        self.assertEqual(directions[0].name, "libyaml scanner")
        pool = build_pool(harness, directions)
        self.assertTrue(any(item.function_name == "yaml_parser_scan" for item in pool))
        selected = Scheduler.default().select(pool)
        self.assertTrue(selected.priority_reasons)

    def test_phase1_writes_json_from_real_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = run_phase1(QUARTET, Path(tmp))
            summary = json.loads((output / "run.json").read_text())
            self.assertEqual(summary["source_kind"], "quartet_reference")
            self.assertTrue(json.loads((output / "function_pool.json").read_text()))
            self.assertTrue(json.loads((output / "selection.json").read_text())["priority_reasons"])

    def test_quartet_pool_uses_only_unique_catalogued_function_names(self):
        harness = HarnessAdapter().load(PUGIXML)
        # The historical C++ feature uses qualified names, while its static
        # catalog records short names and also contains overloaded duplicates.
        self.assertFalse("main" in harness.function_catalog)
        with tempfile.TemporaryDirectory() as tmp:
            run = run_phase1(PUGIXML, Path(tmp))
            pool = json.loads((run / "function_pool.json").read_text())
            self.assertTrue(pool)
            self.assertTrue(all(item["function_name"] in harness.function_catalog
                                for item in pool))


class HarnessCreatorArtifactTest(unittest.TestCase):
    def _id_artifact(self, root: Path, *, consumer_id: str = "fn-parse",
                     duplicate_name: bool = False) -> tuple[Path, Path]:
        repo = root / "repo"
        repo.mkdir()
        (repo / "target.c").write_text(
            "int parse_input(const unsigned char *data) { return data[0]; }\n"
            "int entry_input(const unsigned char *data) { return parse_input(data); }\n")
        (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
        analysis = root / "analysis"
        analysis.mkdir()
        rows = [
            {"function_id": "fn-entry", "name": "entry_input", "file": "target.c",
             "start_line": 2},
            {"function_id": "fn-parse", "name": "parse_input", "file": "target.c",
             "start_line": 1},
        ]
        if duplicate_name:
            rows.append({"function_id": "fn-other", "name": "parse_input",
                         "file": "other.c", "start_line": 1})
        (analysis / "functions.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows))
        (analysis / "edges.jsonl").write_text(json.dumps({
            "caller_id": "fn-entry", "callee_id": "fn-parse"}) + "\n")
        entries = root / "entries"
        entries.mkdir()
        (entries / "verified-final.jsonl").write_text(json.dumps({
            "entry_function_id": "fn-entry"}) + "\n")
        artifact = root / "attempt"
        artifact.mkdir()
        (artifact / "fuzz.c").write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
        (artifact / "manifest.json").write_text(json.dumps({
            "harness_id": "h-id", "source_file": "fuzz.c",
            "expected_anchors": ["fn-entry"], "expected_consumers": [consumer_id],
            "sanitizers": ["address"], "build_command": ["cc", "fuzz.c"],
        }))
        (artifact / "validation.json").write_text('{"build_ok": true}')
        return artifact, repo

    def test_function_ids_resolve_to_catalog_names_source_and_call_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, repo = self._id_artifact(root)
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.entry_functions, ["entry_input"])
            self.assertEqual(harness.core_functions, ["parse_input"])
            self.assertEqual(harness.function_catalog["parse_input"]["function_id"], "fn-parse")
            self.assertEqual(harness.build_command, ["cc", "fuzz.c"])
            self.assertIsNone(harness.run_command)
            self.assertIsNone(harness.corpus_path)
            output = run_phase1(artifact, root / "results", target_repository=repo)
            workers = json.loads((output / "workers.json").read_text())
            directions = json.loads((output / "directions.json").read_text())
            pool = json.loads((output / "function_pool.json").read_text())
            self.assertEqual(workers[0]["entry_information"], ["entry_input"])
            self.assertEqual(directions[0]["entry_functions"], ["entry_input"])
            self.assertEqual(directions[0]["core_functions"], ["parse_input"])
            item = next(row for row in pool if row["function_name"] == "parse_input")
            self.assertEqual(item["function_id"], "fn-parse")
            self.assertEqual(item["source_file"], "target.c")
            self.assertTrue(item["static_reachable"])
            self.assertNotIn("fn-parse", [row["function_name"] for row in pool])
            normalized = HarnessAdapter().load(artifact, target_repository=repo)
            sources = source_evidence_for_pool(normalized, build_pool(
                normalized, build_directions(normalized, build_workers(normalized)[0])))
            self.assertIn("parse_input(const unsigned char *data)", sources["fn-parse"])

    def test_unknown_function_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact, _ = self._id_artifact(Path(tmp), consumer_id="fn-missing")
            with self.assertRaisesRegex(ValueError, "unknown function reference in expected_consumers"):
                HarnessAdapter().load(artifact)

    def test_project_manifest_without_function_catalog_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact, _ = self._id_artifact(Path(tmp))
            (Path(tmp) / "analysis/functions.jsonl").unlink()
            with self.assertRaisesRegex(ValueError, "Function Catalog is missing or empty"):
                HarnessAdapter().load(artifact)

    def test_duplicate_function_name_is_not_mapped_to_arbitrary_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact, _ = self._id_artifact(Path(tmp), duplicate_name=True)
            harness = HarnessAdapter().load(artifact)
            self.assertIn("fn-parse", harness.function_catalog)
            self.assertIn("fn-other", harness.function_catalog)
            self.assertEqual(harness.core_functions, ["fn-parse"])
            manifest = artifact / "manifest.json"
            spec = json.loads(manifest.read_text())
            spec["expected_consumers"] = ["parse_input"]
            manifest.write_text(json.dumps(spec))
            with self.assertRaisesRegex(ValueError, "ambiguous function reference in expected_consumers"):
                HarnessAdapter().load(artifact)

    def test_explicit_regression_fixture_is_not_reported_as_project_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "driver.py"; source.write_text("# local fixture\n")
            coverage = root / "coverage.json"; coverage.write_text("{}")
            (root / "project.json").write_text(json.dumps({"source_root": str(root)}))
            folder = root / "attempt"; folder.mkdir()
            (folder / "manifest.json").write_text(json.dumps({
                "harness_id": "fixture", "source_file": str(source),
                "artifact_kind": "REGRESSION_FIXTURE", "project_harness": False,
                "expected_consumers": ["parse"], "sanitizers": ["ASAN"]}))
            (folder / "validation.json").write_text(json.dumps({
                "build_ok": True, "coverage_artifact": str(coverage),
                "runtime_reached_functions": ["parse"]}))
            harness = HarnessAdapter().load(folder, target_repository=root)
            self.assertEqual(harness.source_kind, "regression_fixture")
            self.assertFalse(harness.metadata["project_harness"])
            self.assertEqual(harness.runtime_reached_functions, ["parse"])

    def test_missing_fields_are_unknown_and_never_imply_reachability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fuzz_target.cc").write_text('extern "C" int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long) {return 0;}')
            (root / "manifest.json").write_text(json.dumps({
                "harness_id": "h-1", "large_feature_id": "lf-1", "source_file": "fuzz_target.cc",
                "sanitizers": ["address"], "expected_anchors": ["parse_frame"],
                "expected_consumers": ["serve_client"], "build_command": ["clang++", "fuzz_target.cc"],
            }))
            (root / "build-validation.json").write_text(json.dumps({"build_ok": True}))
            harness = HarnessAdapter().load(root)
            self.assertEqual(harness.sanitizers, ["address"])
            self.assertIsNone(harness.runtime_reached_functions)
            self.assertIsNone(harness.corpus_path)
            self.assertIsNone(harness.run_command)


class SchedulerTest(unittest.TestCase):
    def test_direction_risk_uses_confirmed_core_source_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"; repo.mkdir()
            (repo / "target.c").write_text(
                "void parse(char *ptr) { free(ptr); ptr += strlen(ptr); }\n")
            artifact = root / "attempt"; artifact.mkdir()
            (artifact / "fuzz.c").write_text("void fuzz(void) {}\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c", "expected_consumers": ["parse"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            (root / "analysis").mkdir()
            (root / "analysis/functions.jsonl").write_text(json.dumps({
                "function_id": "1", "name": "parse", "file": "target.c"}) + "\n")
            output = run_phase1(artifact, root / "results", target_repository=repo)
            direction = json.loads((output / "directions.json").read_text())[0]
            self.assertEqual(direction["risk_level"], "HIGH")
            self.assertTrue(any(row["type"] == "SOURCE_RISK" for row in direction["evidence"]))

    def test_distinct_feature_flows_form_directions_and_expand_static_pool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "features/small").mkdir(parents=True)
            (root / "analysis").mkdir()
            for feature_id, name, entry, core in (
                ("parse", "Request parsing", "parse_entry", "parse_core"),
                ("reply", "Response writing", "reply_entry", "reply_core"),
            ):
                (root / "features/small" / f"{feature_id}.json").write_text(json.dumps({
                    "small_feature_id": feature_id, "name": name,
                    "root_entries": [entry], "required_functions": [core],
                }))
            rows = [
                {"caller_id": "1", "callee_id": "2"},
                {"caller_id": "2", "callee_id": "3"},
                {"caller_id": "4", "callee_id": "5"},
                {"caller_id": "5", "callee_id": "6"},
                {"caller_id": "7", "callee_id": "2"},
            ]
            (root / "analysis/edges.jsonl").write_text("".join(json.dumps(x) + "\n" for x in rows))
            names = ("parse_entry", "parse_core", "parse_helper", "reply_entry",
                     "reply_core", "reply_helper", "other_caller")
            catalog = {name: {"function_id": str(i), "name": name, "file": "target.c"}
                       for i, name in enumerate(names, 1)}
            harness = NormalizedHarness("h", str(root / "harness.c"), str(root), None, None,
                ["ASAN"], None, ["parse_entry", "reply_entry"],
                ["parse_core", "reply_core"], ["parse_core", "reply_core"], [],
                ["parse_core"], {"name": "Combined", "small_feature_ids": ["parse", "reply"]},
                {}, {}, catalog, "harnesscreator", True, {"run_root": str(root)})
            directions = build_directions(harness, build_workers(harness)[0])
            self.assertEqual({d.name for d in directions}, {"Request parsing", "Response writing"})
            pool = build_pool(harness, directions)
            parse = next(d for d in directions if d.name == "Request parsing")
            members = {p.function_name: p for p in pool if p.direction_id == parse.direction_id}
            self.assertEqual(members["parse_entry"].role, "ENTRY")
            self.assertEqual(members["parse_core"].role, "CORE")
            self.assertTrue(members["parse_helper"].static_reachable)
            self.assertEqual(members["parse_helper"].call_depth, 2)
            self.assertIsNone(members["parse_helper"].runtime_reachable)
            self.assertIsNone(members["other_caller"].static_reachable)
            self.assertTrue(members["parse_core"].runtime_reachable)
            with (root / "analysis/edges.jsonl").open("a") as stream:
                stream.write(json.dumps({"caller_id": "2", "callee_id": "4"}) + "\n")
            self.assertEqual(len(build_directions(harness, build_workers(harness)[0])), 1)
            (root / "analysis/edges.jsonl").unlink()
            self.assertEqual(len(build_directions(harness, build_workers(harness)[0])), 1)

    def test_single_feature_without_callgraph_stays_single_direction(self):
        harness = HarnessAdapter().load(QUARTET)
        directions = build_directions(harness, build_workers(harness)[0])
        self.assertEqual(len(directions), 1)
        self.assertEqual(directions[0].name, "libyaml scanner")

    def test_core_callees_remain_in_pool_when_harness_calls_core_after_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "analysis").mkdir()
            (root / "analysis/edges.jsonl").write_text("".join(json.dumps(row) + "\n" for row in [
                {"caller_id": "core", "callee_id": "check"},
                {"caller_id": "check", "callee_id": "consume"},
            ]))
            catalog = {name: {"function_id": ident, "name": name, "file": "target.c"}
                       for name, ident in (("acquire_input", "entry"), ("process", "core"),
                                           ("check_state", "check"), ("consume_state", "consume"))}
            harness = NormalizedHarness(
                "h", str(root / "harness.c"), str(root), None, None, ["ASAN"], None,
                ["acquire_input"], ["process"], ["process"], [], None,
                {"name": "input processing"}, {}, {}, catalog, "harnesscreator", True,
                {"run_root": str(root)})
            direction = build_directions(harness, build_workers(harness)[0])[0]
            pool = {item.function_name: item for item in build_pool(harness, [direction])}
            self.assertEqual(pool["check_state"].role, "RELATED")
            self.assertEqual(pool["consume_state"].role, "RELATED")
            self.assertIsNone(pool["check_state"].static_reachable)
            self.assertIsNone(pool["consume_state"].static_reachable)
            self.assertEqual(pool["consume_state"].source_file, "target.c")

    def test_confirmed_source_operations_break_equal_core_runtime_score(self):
        from vulnerabilityanalysis.models import FunctionPoolItem
        ordinary = FunctionPoolItem("fn-z", "ordinary", "target.c", "d", "CORE", True)
        mutating = FunctionPoolItem("fn-a", "mutating", "target.c", "d", "CORE", True)
        source = "void mutating(char *ptr) { orderedmap_remove(map, ptr); ptr += strlen(ptr) + 1; }"
        selected = Scheduler.default().select([ordinary, mutating], sources={"fn-a": source})
        self.assertEqual(selected.function_id, "fn-a")
        self.assertEqual(selected.risk_level, "HIGH")
        self.assertTrue(any("source" in reason for reason in selected.priority_reasons))
        self.assertIsNone(selected.tie_break_reason)

    def test_function_id_is_reported_only_for_true_evidence_tie(self):
        from vulnerabilityanalysis.models import FunctionPoolItem
        low_id = FunctionPoolItem("fn-a", "first", None, "d", "CORE", True)
        high_id = FunctionPoolItem("fn-z", "second", None, "d", "CORE", True)
        selected = Scheduler.default().select([low_id, high_id])
        self.assertEqual(selected.function_id, "fn-z")
        self.assertEqual(selected.risk_level, "UNKNOWN")
        self.assertIn("function_id", selected.tie_break_reason)

    def test_aging_selects_waiting_low_pool_every_fifth_turn(self):
        from vulnerabilityanalysis.models import FunctionPoolItem
        pool = [
            FunctionPoolItem(function_id=f"core-{i}", function_name=f"core_{i}", source_file=None,
                             direction_id="d", role="CORE", runtime_reachable=None)
            for i in range(6)
        ] + [FunctionPoolItem(function_id="related", function_name="related", source_file=None,
                              direction_id="d", role="RELATED", runtime_reachable=None)]
        scheduler = Scheduler.default()
        chosen = [scheduler.select(pool).function_id for _ in range(5)]
        self.assertEqual(chosen[4], "related")
        self.assertEqual(len(set(chosen)), 5)


if __name__ == "__main__":
    unittest.main()
