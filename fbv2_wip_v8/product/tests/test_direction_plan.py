"""Pinned model Direction proposals preserve the official Catalog boundary."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.direction_plan import build_dev_direction_index
from vulnerabilityanalysis.workflow import (continue_phase1, prepare_function_retry,
                                            prepare_sp_resume, run_phase1)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(root: Path) -> tuple[Path, Path, Path]:
    harness = root / "fuzz.c"
    harness.write_text("extern int A(void);\n"
                       "int LLVMFuzzerTestOneInput(void) { return A(); }\n")
    (root / "target.c").write_text("int A(void) { return 0; }\n")
    (root / "project.json").write_text(json.dumps({"source_root": str(root)}))
    analysis = root / "analysis"
    analysis.mkdir()
    (analysis / "functions.jsonl").write_text("".join(json.dumps({
        "function_id": f"fn-{name.lower()}", "name": name,
        "file": "target.c"}) + "\n" for name in "ABCDE"))
    (analysis / "edges.jsonl").write_text("".join(json.dumps({
        "caller_id": f"fn-{caller.lower()}",
        "callee_id": f"fn-{callee.lower()}",
        "kind": "SOURCE_DIRECT_COMPILED"}) + "\n"
        for caller, callee in (("A", "B"), ("C", "D"))))
    (analysis / "indirect_edges.jsonl").write_text(json.dumps({
        "caller_id": "fn-b", "callee_id": "fn-c",
        "kind": "function_reference",
        "status": "UNVERIFIED_INDIRECT_REFERENCE"}) + "\n")
    artifact = root / "attempt"
    artifact.mkdir()
    (artifact / "manifest.json").write_text(json.dumps({
        "harness_id": "official-plan-fixture", "source_file": str(harness),
        "artifact_kind": "OFFICIAL_OSS_FUZZ", "project_harness": True,
        "oss_fuzz_repository": "https://github.com/google/oss-fuzz",
        "oss_fuzz_revision": "a" * 40, "oss_fuzz_harness_path": "projects/example/fuzz.c",
        "harness_sha256": _sha(harness), "expected_anchors": ["fn-a"],
        "catalog_producer": "EVALUATOR_GENERATED"}))
    (artifact / "validation.json").write_text('{"build_ok": true}')
    proposal = root / "direction_plan.json"
    proposal.write_text(json.dumps({
        "kind": "DEVELOPMENT_DIRECTION_PLAN_V1",
        "harness_sha256": _sha(harness),
        "functions_sha256": _sha(analysis / "functions.jsonl"),
        "edges_sha256": _sha(analysis / "edges.jsonl"),
        "indirect_edges_sha256": _sha(analysis / "indirect_edges.jsonl"),
        "response": {"directions": [{
            "name": "Parsing feature", "risk_level": "HIGH",
            "entry_function_ids": ["fn-a"], "core_function_ids": ["fn-c"],
            "rationale": "A reaches C through a recorded indirect reference."}],
            "unknowns": []}}, sort_keys=True))
    return artifact, root, proposal


class DirectionPlanTests(unittest.TestCase):
    def test_core_count_uses_catalog_and_graph_boundary(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            analysis = repo / 'analysis'
            extra_ids = [f'fn-extra-{index}' for index in range(13)]
            with (analysis / 'functions.jsonl').open('a') as stream:
                for index, function_id in enumerate(extra_ids):
                    stream.write(json.dumps({'function_id': function_id,
                                             'name': f'Extra{index}',
                                             'file': 'target.c'}) + '\n')
            with (analysis / 'edges.jsonl').open('a') as stream:
                for function_id in extra_ids:
                    stream.write(json.dumps({'caller_id': 'fn-a',
                                             'callee_id': function_id,
                                             'kind': 'SOURCE_DIRECT_COMPILED'}) + '\n')
            proposal = json.loads(plan.read_text())
            proposal['functions_sha256'] = _sha(analysis / 'functions.jsonl')
            proposal['edges_sha256'] = _sha(analysis / 'edges.jsonl')
            proposal['response']['directions'][0]['core_function_ids'] = [
                'fn-b', *extra_ids]
            plan.write_text(json.dumps(proposal, sort_keys=True))
            run = run_phase1(artifact, repo / 'runs', target_repository=repo,
                             direction_plan=plan,
                             selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
            directions = json.loads((run / 'directions.json').read_text())
            pool = json.loads((run / 'function_pool.json').read_text())
            self.assertEqual(len(directions[0]['core_functions']), 14)
            self.assertEqual(len(pool), 18)

    def test_entry_core_overlap_keeps_raw_claim_and_one_effective_role(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            proposal = json.loads(plan.read_text())
            proposal["response"]["directions"][0]["core_function_ids"] = ["fn-a", "fn-b"]
            plan.write_text(json.dumps(proposal, sort_keys=True))
            original = plan.read_bytes()
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            directions = json.loads((run / "directions.json").read_text())
            pool = json.loads((run / "function_pool.json").read_text())
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            index = build_dev_direction_index(harness, directions)
            first = directions[0]
            self.assertEqual((run / "direction_plan.json").read_bytes(), original)
            self.assertEqual(json.loads(original)["response"]["directions"][0]
                             ["core_function_ids"], ["fn-a", "fn-b"])
            self.assertEqual(json.loads((run / "run.json").read_text())
                             ["direction_plan_sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(first["entry_functions"], ["A"])
            self.assertEqual(first["core_functions"], ["B"])
            self.assertEqual(len(pool), 5)
            self.assertEqual(len({row["function_id"] for row in pool}), 5)
            self.assertEqual(next(row for row in pool if row["function_id"] == "fn-a")
                             ["role"], "ENTRY")
            self.assertEqual([row["role"] for row in
                              index[(first["worker_id"], "fn-a")]], ["ENTRY"])

    def test_entry_only_overlap_keeps_small_pool_member_once(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            proposal = json.loads(plan.read_text())
            proposal["response"]["directions"][0]["core_function_ids"] = ["fn-a"]
            plan.write_text(json.dumps(proposal, sort_keys=True))
            original = plan.read_bytes()
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            directions = json.loads((run / "directions.json").read_text())
            pool = json.loads((run / "function_pool.json").read_text())
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            index = build_dev_direction_index(harness, directions)
            first = directions[0]
            self.assertEqual((run / "direction_plan.json").read_bytes(), original)
            self.assertEqual(first["entry_functions"], ["A"])
            self.assertEqual(first["core_functions"], [])
            self.assertEqual(len(pool), 5)
            self.assertEqual(len({row["function_id"] for row in pool}), 5)
            self.assertEqual([row["role"] for row in
                              index[(first["worker_id"], "fn-a")]], ["ENTRY"])
            self.assertEqual(next(row for row in pool if row["function_id"] == "fn-a")
                             ["role"], "ENTRY")

    def test_overlap_does_not_weaken_id_or_graph_validation(self):
        cases = (
            (["fn-a", "fn-a"], ["fn-a"], "invalid Direction feature identity"),
            (["fn-a"], ["fn-a", "fn-a"], "invalid Direction feature identity"),
            (["fn-a"], ["fn-a", "fn-missing"], "invalid Direction feature identity"),
            (["fn-a"], ["fn-a", "fn-e"], "Core lacks a recorded path"),
        )
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            original = json.loads(plan.read_text())
            for entries, cores, message in cases:
                with self.subTest(entries=entries, cores=cores):
                    proposal = json.loads(json.dumps(original))
                    proposal["response"]["directions"][0].update(
                        entry_function_ids=entries, core_function_ids=cores)
                    plan.write_text(json.dumps(proposal, sort_keys=True))
                    with self.assertRaisesRegex(ValueError, message):
                        run_phase1(artifact, repo / "runs", target_repository=repo,
                                   direction_plan=plan,
                                   selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")

    def test_pinned_plan_follows_continuation_retry_and_sp_resume(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan)
            selected = json.loads((run / "selection.json").read_text())
            (run / "scan.json").write_text(json.dumps({
                "selected_function": selected["function_name"],
                "selected_function_id": selected["function_id"],
                "target_repository": str(repo), "pending_sp_ids": ["sp-pending"]}))
            continued = continue_phase1(run)
            resumed = prepare_sp_resume(run, run.parent / "resumed")
            for child in (continued, resumed):
                self.assertEqual((child / "direction_plan.json").read_bytes(),
                                 plan.read_bytes())
                self.assertEqual(json.loads((child / "run.json").read_text())
                                 ["direction_plan_sha256"], _sha(plan))

            retry_source = run_phase1(artifact, repo / "runs", target_repository=repo,
                                      direction_plan=plan)
            (retry_source / "scan_timeout.json").write_text(
                '{"status":"SCAN_WALL_TIME_EXCEEDED"}')
            retried = prepare_function_retry(retry_source,
                                             retry_source.parent / "retried")
            self.assertEqual((retried / "direction_plan.json").read_bytes(),
                             plan.read_bytes())

    def test_tampered_pinned_plan_blocks_continuation(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan)
            selected = json.loads((run / "selection.json").read_text())
            (run / "scan.json").write_text(json.dumps({
                "selected_function": selected["function_name"],
                "selected_function_id": selected["function_id"],
                "target_repository": str(repo)}))
            (run / "direction_plan.json").write_text('{"tampered":true}')
            with self.assertRaisesRegex(ValueError, "Direction plan.*SHA-256"):
                continue_phase1(run)

    def test_valid_plan_preserves_indirect_unknown_and_unscoped_catalog(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan)
            meta = json.loads((run / "run.json").read_text())
            directions = json.loads((run / "directions.json").read_text())
            pool = json.loads((run / "function_pool.json").read_text())
            by_name = {item["function_name"]: item for item in pool}
            self.assertEqual(meta["direction_source_kind"], "PINNED_MODEL_PROPOSAL")
            self.assertEqual(meta["direction_plan_sha256"], _sha(plan))
            self.assertEqual((run / "direction_plan.json").read_bytes(), plan.read_bytes())
            self.assertEqual(len(directions), 2)
            self.assertEqual(directions[0]["entry_functions"], ["A"])
            self.assertEqual(directions[0]["core_functions"], ["C"])
            self.assertEqual(directions[0]["risk_level"], "HIGH")
            self.assertEqual({item["function_id"] for item in pool},
                             {f"fn-{name.lower()}" for name in "ABCDE"})
            self.assertEqual(len(pool), 5)
            self.assertEqual(by_name["C"]["role"], "CORE")
            self.assertEqual(by_name["C"]["graph_reachability"], "UNKNOWN")
            self.assertIsNone(by_name["C"]["static_reachable"])
            self.assertEqual(by_name["D"]["graph_reachability"], "UNKNOWN")
            self.assertEqual(by_name["E"]["role"], "RELATED")
            self.assertEqual(directions[1]["name"], "Unscoped Catalog candidates")

    def test_hash_mismatch_fails_before_selection(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            row = json.loads(plan.read_text())
            row["functions_sha256"] = "0" * 64
            plan.write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, "pinned Harness and Catalog"):
                run_phase1(artifact, repo / "runs", target_repository=repo,
                           direction_plan=plan)

    def test_core_without_recorded_entry_path_is_rejected(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            row = json.loads(plan.read_text())
            row["response"]["directions"][0]["core_function_ids"] = ["fn-e"]
            plan.write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, "Core lacks a recorded path"):
                run_phase1(artifact, repo / "runs", target_repository=repo,
                           direction_plan=plan)

    def test_source_observed_harness_entry_must_have_a_direction(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            row = json.loads(plan.read_text())
            row["response"]["directions"][0]["entry_function_ids"] = ["fn-c"]
            row["response"]["directions"][0]["core_function_ids"] = ["fn-d"]
            plan.write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, "omits a source-observed Harness Entry"):
                run_phase1(artifact, repo / "runs", target_repository=repo,
                           direction_plan=plan)

    def test_indirect_entry_does_not_claim_static_reachability(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            row = json.loads(plan.read_text())
            row["response"]["directions"][0]["entry_function_ids"] = ["fn-c"]
            row["response"]["directions"][0]["core_function_ids"] = ["fn-d"]
            row["response"]["directions"].append({
                "name": "Harness entry", "risk_level": "LOW",
                "entry_function_ids": ["fn-a"], "core_function_ids": ["fn-b"],
                "rationale": "The source-observed Harness call reaches B directly."})
            plan.write_text(json.dumps(row))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan)
            pool = json.loads((run / "function_pool.json").read_text())
            by_name = {item["function_name"]: item for item in pool}
            for name in ("C", "D"):
                self.assertIsNone(by_name[name]["static_reachable"])
                self.assertEqual(by_name[name]["graph_reachability"], "UNKNOWN")

    def test_plan_cannot_claim_indirect_runtime_confirmation(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            row = json.loads(plan.read_text())
            row["response"]["indirect_runtime_status"] = "VERIFIED"
            plan.write_text(json.dumps(row))
            with self.assertRaisesRegex(ValueError, "invalid Direction proposal response"):
                run_phase1(artifact, repo / "runs", target_repository=repo,
                           direction_plan=plan)

    def test_shared_entry_keeps_each_function_once_with_strongest_role(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            row = json.loads(plan.read_text())
            row["response"]["directions"].insert(0, {
                "name": "Entry parsing", "risk_level": "LOW",
                "entry_function_ids": ["fn-a"], "core_function_ids": ["fn-b"],
                "rationale": "A reaches B through a recorded direct edge."})
            plan.write_text(json.dumps(row))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan)
            pool = json.loads((run / "function_pool.json").read_text())
            directions = json.loads((run / "directions.json").read_text())
            self.assertEqual(len(pool), 5)
            self.assertEqual(len({item["function_id"] for item in pool}), 5)
            c = next(item for item in pool if item["function_id"] == "fn-c")
            self.assertEqual(c["role"], "CORE")
            self.assertEqual(c["direction_id"], directions[1]["direction_id"])
