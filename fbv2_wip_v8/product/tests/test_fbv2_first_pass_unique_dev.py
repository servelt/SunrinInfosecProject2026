"""Development-only Direction priority and HP membership regression tests."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.direction_plan import (build_dev_direction_index,
                                                  compact_dev_memberships,
                                                  dev_direction_index_sha256)
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.workflow import (_dev_priority_keys, continue_phase1,
                                            prepare_sp_resume, run_phase1)

from test_direction_plan import fixture
from test_sp_hp_independence import Provider


def two_direction_plan(path: Path) -> None:
    payload = json.loads(path.read_text())
    payload["response"]["directions"].insert(0, {
        "name": "Direct entry feature", "risk_level": "LOW",
        "entry_function_ids": ["fn-a"], "core_function_ids": ["fn-b"],
        "rationale": "The recorded direct call from A reaches B."})
    path.write_text(json.dumps(payload, sort_keys=True))


class FirstPassUniqueDevTests(unittest.TestCase):
    def test_default_score_selection_is_unchanged(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            two_direction_plan(plan)
            first = run_phase1(artifact, repo / "runs", target_repository=repo,
                               direction_plan=plan)
            second = run_phase1(artifact, repo / "runs", target_repository=repo,
                                direction_plan=plan, selection_policy="SCORE")
            self.assertEqual(json.loads((first / "selection.json").read_text())["function_id"],
                             json.loads((second / "selection.json").read_text())["function_id"])
            self.assertNotIn("selection_policy", json.loads((first / "run.json").read_text()))

    def test_opt_in_tiers_and_unknown_fallback_preserve_every_catalog_id(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            two_direction_plan(plan)
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            meta = json.loads((run / "run.json").read_text())
            pool = json.loads((run / "function_pool.json").read_text())
            self.assertEqual(meta["selection_policy"], "FBV2_FIRST_PASS_UNIQUE_DEV")
            self.assertEqual(len(pool), 5)
            self.assertEqual({row["function_id"] for row in pool},
                             {f"fn-{name.lower()}" for name in "ABCDE"})
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            directions = json.loads((run / "directions.json").read_text())
            index = build_dev_direction_index(harness, directions)
            self.assertEqual(index[(directions[1]["worker_id"], "fn-c")][0]["tier"],
                             "SMALL")
            self.assertTrue(any(row["tier"] == "UNKNOWN_CANDIDATE" for row in
                                index[(directions[1]["worker_id"], "fn-d")]))
            by_id = {row["function_id"]: row for row in pool}
            self.assertEqual(by_id["fn-d"]["graph_reachability"], "UNKNOWN")
            self.assertIsNone(by_id["fn-d"]["static_reachable"])

    def test_memberships_do_not_change_when_equal_risk_rows_exchange_places(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            two_direction_plan(plan)
            payload = json.loads(plan.read_text())
            payload["response"]["directions"][0]["risk_level"] = "HIGH"
            plan.write_text(json.dumps(payload, sort_keys=True))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            directions = json.loads((run / "directions.json").read_text())
            swapped = [directions[1], directions[0], *directions[2:]]
            first = build_dev_direction_index(harness, directions)
            second = build_dev_direction_index(harness, swapped)
            key = (directions[0]["worker_id"], "fn-a")
            self.assertEqual(compact_dev_memberships(first[key]),
                             compact_dev_memberships(second[key]))
            swapped_plan = repo / "swapped_direction_plan.json"
            payload = json.loads(plan.read_text())
            payload["response"]["directions"].reverse()
            swapped_plan.write_text(json.dumps(payload, sort_keys=True))
            swapped_run = run_phase1(artifact, repo / "runs", target_repository=repo,
                                     direction_plan=swapped_plan,
                                     selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            owners = [{row["function_id"]: row["direction_id"] for row in
                       json.loads((one_run / "function_pool.json").read_text())}
                      for one_run in (run, swapped_run)]
            self.assertEqual(owners[0], owners[1])
            original_selection = json.loads((run / "selection.json").read_text())
            swapped_selection = json.loads((swapped_run / "selection.json").read_text())
            self.assertEqual(original_selection["function_id"], swapped_selection["function_id"])
            self.assertEqual(original_selection["direction_id"],
                             swapped_selection["direction_id"])
            providers = [Provider(), Provider()]
            for one_run, provider in zip((run, swapped_run), providers):
                asyncio.run(scan_selected(one_run, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          hallucination_prevent="on"))
            self.assertEqual(json.dumps(providers[0].function_payload, sort_keys=True),
                             json.dumps(providers[1].function_payload, sort_keys=True))
            self.assertEqual(json.dumps(providers[0].sp_payload, sort_keys=True),
                             json.dumps(providers[1].sp_payload, sort_keys=True))

    def test_opt_in_hp_request_contains_complete_compact_memberships(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            two_direction_plan(plan)
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            provider = Provider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
            scope = provider.function_payload["analysis_scope"]
            self.assertEqual(len(scope["direction_memberships"]), 2)
            self.assertEqual({row["name"] for row in scope["direction_memberships"]},
                             {"Direct entry feature", "Parsing feature"})
            self.assertIn("direction", scope)  # existing evidence field remains

    def test_owner_and_block_key_follow_priority_membership(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            payload = json.loads(plan.read_text())
            payload["response"]["directions"] = [
                {"name": "Lower risk B entry", "risk_level": "LOW",
                 "entry_function_ids": ["fn-b"], "core_function_ids": ["fn-c"],
                 "rationale": "B reaches C by a recorded reference path."},
                {"name": "Higher risk A entry", "risk_level": "HIGH",
                 "entry_function_ids": ["fn-a"], "core_function_ids": ["fn-b"],
                 "rationale": "A directly reaches B by a recorded call."},
            ]
            plan.write_text(json.dumps(payload, sort_keys=True))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            directions = json.loads((run / "directions.json").read_text())
            pool = json.loads((run / "function_pool.json").read_text())
            by_id = {row["function_id"]: row for row in pool}
            high = next(row for row in directions
                        if row["name"] == "Higher risk A entry")
            self.assertEqual(by_id["fn-b"]["direction_id"], high["direction_id"])
            self.assertEqual(by_id["fn-b"]["role"], "CORE")
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            from vulnerabilityanalysis.models import FunctionPoolItem
            priority, _ = _dev_priority_keys(
                harness, directions, [FunctionPoolItem(**row) for row in pool])
            self.assertEqual(priority[(high["direction_id"], "fn-b")][:4],
                             (0, 0, high["direction_id"], "fn-b"))

    def test_policy_and_plan_hash_survive_continuation_and_tampering_fails(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            meta = json.loads((run / "run.json").read_text())
            selection = json.loads((run / "selection.json").read_text())
            self.assertEqual(meta["direction_plan_sha256"],
                             hashlib.sha256(plan.read_bytes()).hexdigest())
            (run / "scan.json").write_text(json.dumps({
                "selected_function": selection["function_name"],
                "selected_function_id": selection["function_id"],
                "target_repository": str(repo)}))
            child = continue_phase1(run)
            child_meta = json.loads((child / "run.json").read_text())
            self.assertEqual(child_meta["selection_policy"], meta["selection_policy"])
            self.assertEqual(child_meta["direction_index_sha256"],
                             meta["direction_index_sha256"])
            tamper_run = run_phase1(artifact, repo / "runs", target_repository=repo,
                                    direction_plan=plan,
                                    selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            tamper_meta = json.loads((tamper_run / "run.json").read_text())
            tamper_selection = json.loads((tamper_run / "selection.json").read_text())
            (tamper_run / "scan.json").write_text(json.dumps({
                "selected_function": tamper_selection["function_name"],
                "selected_function_id": tamper_selection["function_id"],
                "target_repository": str(repo)}))
            tamper_meta["direction_index_sha256"] = "0" * 64
            (tamper_run / "run.json").write_text(json.dumps(tamper_meta))
            with self.assertRaisesRegex(ValueError, "Direction index"):
                continue_phase1(tamper_run, run.parent / "tampered")

    def test_opt_in_requires_official_harness_and_pinned_plan(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _ = fixture(Path(temp))
            with self.assertRaisesRegex(ValueError, "official.*Direction plan"):
                run_phase1(artifact, repo / "runs", target_repository=repo,
                           selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")

    def test_unknown_persisted_policy_fails_before_any_provider_call(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            meta = json.loads((run / "run.json").read_text())
            meta["selection_policy"] = "UNRECOGNIZED"
            (run / "run.json").write_text(json.dumps(meta))
            provider = Provider()
            with self.assertRaisesRegex(ValueError, "unknown persisted.*policy"):
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          hallucination_prevent="on"))
            self.assertEqual(provider.roles, [])

    def test_same_graph_reordered_bytes_block_dev_continue_and_scan(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            selection = json.loads((run / "selection.json").read_text())
            (run / "scan.json").write_text(json.dumps({
                "selected_function": selection["function_name"],
                "selected_function_id": selection["function_id"],
                "target_repository": str(repo)}))
            edges = repo / "analysis/edges.jsonl"
            edges.write_text("\n".join(reversed(edges.read_text().splitlines())) + "\n")
            with self.assertRaisesRegex(ValueError, "input SHA-256"):
                continue_phase1(run)
            provider = Provider()
            with self.assertRaisesRegex(ValueError, "input SHA-256"):
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          hallucination_prevent="on"))
            self.assertEqual(provider.roles, [])

    def test_dev_sp_resume_rejects_source_policy_change(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            selection = json.loads((run / "selection.json").read_text())
            (run / "scan.json").write_text(json.dumps({
                "selected_function": selection["function_name"],
                "selected_function_id": selection["function_id"],
                "target_repository": str(repo), "pending_sp_ids": ["sp-pending"]}))
            resumed = prepare_sp_resume(run, run.parent / "resumed")
            old = json.loads((run / "run.json").read_text())
            old["selection_policy"] = "SCORE"
            (run / "run.json").write_text(json.dumps(old))
            provider = Provider()
            with self.assertRaisesRegex(ValueError, "resume policy"):
                asyncio.run(scan_selected(resumed, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          hallucination_prevent="on", resume_from=run))
            self.assertEqual(provider.roles, [])

    def test_dev_scan_rejects_selection_owner_tampering(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            two_direction_plan(plan)
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            selection = json.loads((run / "selection.json").read_text())
            directions = json.loads((run / "directions.json").read_text())
            selection["direction_id"] = next(
                row["direction_id"] for row in directions
                if row["direction_id"] != selection["direction_id"])
            (run / "selection.json").write_text(json.dumps(selection))
            provider = Provider()
            with self.assertRaisesRegex(ValueError, "selection owner"):
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          hallucination_prevent="on"))
            self.assertEqual(provider.roles, [])

    def test_recomputed_index_cannot_authorize_changed_direction_risk(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = fixture(Path(temp))
            run = run_phase1(artifact, repo / "runs", target_repository=repo,
                             direction_plan=plan,
                             selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            directions = json.loads((run / "directions.json").read_text())
            directions[0]["risk_level"] = "LOW"
            (run / "directions.json").write_text(json.dumps(directions))
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            meta = json.loads((run / "run.json").read_text())
            meta["direction_index_sha256"] = dev_direction_index_sha256(
                build_dev_direction_index(harness, directions))
            (run / "run.json").write_text(json.dumps(meta))
            selection = json.loads((run / "selection.json").read_text())
            (run / "scan.json").write_text(json.dumps({
                "selected_function": selection["function_name"],
                "selected_function_id": selection["function_id"],
                "target_repository": str(repo)}))
            with self.assertRaisesRegex(ValueError, "differ from pinned plan"):
                continue_phase1(run)
            provider = Provider()
            with self.assertRaisesRegex(ValueError, "differ from pinned plan"):
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                                          run_command=["/usr/bin/true", "{input}"],
                                          hallucination_prevent="on"))
            self.assertEqual(provider.roles, [])


if __name__ == "__main__":
    unittest.main()
