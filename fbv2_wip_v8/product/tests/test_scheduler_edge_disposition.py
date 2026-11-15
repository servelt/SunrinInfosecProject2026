"""Generic edge identity regression; no target-specific source or ranking."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vulnerabilityanalysis import scheduler


class SchedulerEdgeDispositionTests(unittest.TestCase):
    def test_official_feature_flows_walk_only_their_own_verified_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            analysis.mkdir()
            (analysis / "edges.jsonl").write_text("".join(json.dumps({
                "caller_id": f"fn-{caller}", "callee_id": f"fn-{callee}",
                "kind": "SOURCE_DIRECT_COMPILED"}) + "\n"
                for caller, callee in (("a", "b"), ("c", "d"))))
            small = root / "features/small"
            small.mkdir(parents=True)
            for feature_id, entry, core in (("first", "a", "b"),
                                             ("second", "c", "d")):
                (small / f"{feature_id}.json").write_text(json.dumps({
                    "small_feature_id": feature_id, "name": feature_id,
                    "root_entries": [f"fn-{entry}"],
                    "required_functions": [f"fn-{core}"]}))
            catalog = {name: {"function_id": f"fn-{name}", "name": name,
                              "file": "target.c"} for name in "abcd"}
            harness = SimpleNamespace(
                harness_id="fixture", harness_path=str(root / "fuzz.c"),
                function_catalog=catalog, source_kind="official_oss_fuzz",
                metadata={"run_root": str(root),
                          "official_direct_call_anchors": ["a", "c"]},
                feature_information={"small_feature_ids": ["first", "second"]},
                entry_functions=[], core_functions=["a", "c"],
                reachable_functions=[], runtime_reached_functions=None)
            directions = scheduler.build_directions(
                harness, SimpleNamespace(worker_id="worker"))
            self.assertEqual([row.entry_functions for row in directions], [["a"], ["c"]])
            self.assertEqual([row.core_functions for row in directions], [["b"], ["d"]])
            self.assertEqual([row.related_functions for row in directions], [[], []])
            pool = scheduler.build_pool(harness, directions)
            roles = {(item.direction_id, item.function_name): item for item in pool}
            self.assertEqual(roles[(directions[0].direction_id, "a")].role, "ENTRY")
            self.assertEqual(roles[(directions[0].direction_id, "b")].graph_reachability,
                             "STATIC_REACHED")
            self.assertNotIn((directions[0].direction_id, "c"), roles)
            self.assertNotIn((directions[1].direction_id, "a"), roles)

    def test_unowned_direct_anchor_keeps_one_complete_direction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            analysis.mkdir()
            (analysis / "edges.jsonl").write_text("".join(json.dumps({
                "caller_id": f"fn-{caller}", "callee_id": f"fn-{callee}"}) + "\n"
                for caller, callee in (("a", "b"), ("c", "d"))))
            small = root / "features/small"
            small.mkdir(parents=True)
            for feature_id, entry, core in (("first", "a", "b"),
                                             ("second", "c", "d")):
                (small / f"{feature_id}.json").write_text(json.dumps({
                    "small_feature_id": feature_id,
                    "root_entries": [f"fn-{entry}"],
                    "required_functions": [f"fn-{core}"]}))
            catalog = {name: {"function_id": f"fn-{name}", "name": name,
                              "file": "target.c"} for name in ("a", "b", "c", "d", "other")}
            harness = SimpleNamespace(
                harness_id="fixture", harness_path=str(root / "fuzz.c"),
                function_catalog=catalog, source_kind="official_oss_fuzz",
                metadata={"run_root": str(root),
                          "official_direct_call_anchors": ["a", "other"]},
                feature_information={"small_feature_ids": ["first", "second"]},
                entry_functions=["a", "c"], core_functions=["a", "other"],
                reachable_functions=[], runtime_reached_functions=None)
            directions = scheduler.build_directions(
                harness, SimpleNamespace(worker_id="worker"))
            self.assertEqual(len(directions), 1)
            self.assertEqual(directions[0].entry_functions, ["a", "other"])
            pool = scheduler.build_pool(harness, directions)
            self.assertIn("other", {item.function_name for item in pool})
            self.assertIn("c", {item.function_name for item in pool})

    def test_unverified_feature_entry_and_core_remain_unknown_candidates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "analysis").mkdir()
            (root / "analysis/edges.jsonl").write_text("".join(json.dumps({
                "caller_id": f"fn-{caller}", "callee_id": f"fn-{callee}",
                "kind": "SOURCE_DIRECT_COMPILED"}) + "\n"
                for caller, callee in (("a", "b"), ("c", "d"))))
            small = root / "features/small"
            small.mkdir(parents=True)
            for feature_id, entry, core in (("first", "a", "b"),
                                             ("second", "c", "d")):
                (small / f"{feature_id}.json").write_text(json.dumps({
                    "small_feature_id": feature_id,
                    "root_entries": [f"fn-{entry}"],
                    "required_functions": [f"fn-{core}"]}))
            catalog = {name: {"function_id": f"fn-{name}", "name": name,
                              "file": "target.c"} for name in "abcd"}
            harness = SimpleNamespace(
                harness_id="fixture", harness_path=str(root / "fuzz.c"),
                function_catalog=catalog, source_kind="official_oss_fuzz",
                metadata={"run_root": str(root),
                          "official_direct_call_anchors": ["a"]},
                feature_information={"small_feature_ids": ["first", "second"]},
                entry_functions=["a", "c"], core_functions=["b", "d"],
                reachable_functions=[], runtime_reached_functions=None)
            directions = scheduler.build_directions(
                harness, SimpleNamespace(worker_id="worker"))
            self.assertEqual(len(directions), 1)
            self.assertEqual(directions[0].entry_functions, ["a"])
            pool = {item.function_name: item for item in
                    scheduler.build_pool(harness, directions)}
            self.assertEqual(pool["b"].role, "CORE")
            self.assertEqual(pool["d"].role, "RELATED")
            self.assertIsNone(pool["d"].static_reachable)
            self.assertEqual(pool["d"].graph_reachability, "GRAPH_UNREACHED")

    def test_indirect_reference_from_directly_reached_caller_stays_unknown_pool_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            analysis.mkdir()
            (analysis / "edges.jsonl").write_text(json.dumps({
                "caller_id": "fn-entry", "callee_id": "fn-direct",
                "kind": "DIRECT_AST_ID"}) + "\n")
            (analysis / "indirect_edges.jsonl").write_text("".join(
                json.dumps(row) + "\n" for row in (
                    {"caller_id": "fn-direct", "callee_id": "fn-callback",
                     "kind": "function_reference", "status": "UNVERIFIED_INDIRECT_REFERENCE"},
                    {"caller_id": "fn-callback", "callee_id": "fn-deep",
                     "kind": "function_reference", "status": "UNVERIFIED_INDIRECT_REFERENCE"},
                    {"caller_id": "fn-deep", "callee_id": "fn-callback",
                     "kind": "function_reference", "status": "UNVERIFIED_INDIRECT_REFERENCE"},
                    {"caller_id": "fn-unused", "callee_id": "fn-decoy",
                     "kind": "function_reference", "status": "UNVERIFIED_INDIRECT_REFERENCE"},
                    {"caller_id": "fn-direct", "callee_id": "fn-invalid",
                     "kind": "function_reference", "status": "UNVERIFIED"},
                )))
            catalog = {name: {"function_id": f"fn-{name}", "name": name,
                              "file": "target.c"} for name in
                       ("entry", "direct", "callback", "deep", "unused", "decoy", "invalid")}
            harness = SimpleNamespace(
                function_catalog=catalog,
                metadata={"run_root": str(root),
                          "official_direct_call_anchors": ["entry"]},
                source_kind="official_oss_fuzz", feature_information={},
                entry_functions=[], core_functions=["entry"],
                reachable_functions=[], runtime_reached_functions=None,
                harness_id="fixture")
            directions = scheduler.build_directions(
                harness, SimpleNamespace(worker_id="worker"))
            pool = {item.function_name: item for item in
                    scheduler.build_pool(harness, directions)}
            self.assertIn("callback", pool)
            self.assertIn("deep", pool)
            self.assertNotIn("decoy", pool)
            self.assertNotIn("invalid", pool)
            self.assertEqual(pool["callback"].role, "RELATED")
            self.assertIsNone(pool["callback"].static_reachable)
            self.assertIsNone(pool["callback"].call_depth)
            self.assertEqual(pool["callback"].graph_reachability, "UNKNOWN")
            self.assertEqual(pool["deep"].graph_reachability, "UNKNOWN")
            self.assertEqual(pool["direct"].graph_reachability, "STATIC_REACHED")

    def test_only_direct_edges_establish_static_reachability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            analysis.mkdir()
            rows = [
                {"caller_id": "fn-a", "callee_id": "fn-b", "kind": "direct"},
                {"caller_id": "fn-a", "callee_id": "fn-c", "kind": "function_reference"},
                {"caller_id": "fn-a", "callee_id": "fn-d", "kind": "UNKNOWN_KIND"},
                {"caller_id": "fn-a", "callee_id": "fn-e", "kind": "DIRECT_AST_ID"},
                {"caller_id": "fn-a", "callee_id": "fn-f", "kind": "SOURCE_DIRECT_COMPILED"},
            ]
            (analysis / "edges.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows))
            catalog = {name: {"function_id": f"fn-{name.lower()}",
                              "name": name, "file": "target.c"} for name in "ABCDEF"}
            harness = SimpleNamespace(
                function_catalog=catalog,
                metadata={"run_root": str(root), "official_direct_call_anchors": ["A"]},
                source_kind="official_oss_fuzz", runtime_reached_functions=None)
            direction = SimpleNamespace(
                direction_id="direction", entry_functions=["A"], core_functions=[],
                related_functions=["B", "C", "D", "E", "F"], reachable_functions=[])
            pool = {item.function_name: item for item in
                    scheduler.build_pool(harness, [direction])}
            for name in "BEF":
                self.assertEqual(pool[name].graph_reachability, "STATIC_REACHED")
            for name in "CD":
                self.assertEqual(pool[name].graph_reachability, "GRAPH_UNREACHED")
                self.assertIsNone(pool[name].static_reachable)
            audit = scheduler.call_graph_audit(harness)
            self.assertEqual(audit["resolved_edges"], 3)
            self.assertEqual(audit["non_traversable_kind_rows"], 2)
            self.assertEqual(audit["legacy_untyped_rows"], 0)
            self.assertEqual([row["status"] for row in audit["rows"]],
                             ["RESOLVED_EDGE", "NON_TRAVERSABLE_EDGE_KIND",
                              "NON_TRAVERSABLE_EDGE_KIND", "RESOLVED_EDGE",
                              "RESOLVED_EDGE"])

    def test_ambiguous_name_and_unknown_id_never_become_edges(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            analysis = root / "analysis"
            analysis.mkdir()
            rows = [
                {"caller_id": "fn-entry", "callee_name": "parse"},
                {"caller_id": "fn-entry", "callee_id": "fn-a"},
                {"caller_id": "fn-absent", "caller_name": "entry",
                 "callee_id": "fn-b"},
            ]
            (analysis / "edges.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows))
            (analysis / "ambiguous_edges.jsonl").write_text(json.dumps({
                "status": "AMBIGUOUS_EDGE", "caller_id": "fn-entry",
                "called_name": "parse", "candidate_ids": ["fn-a", "fn-b"]}) + "\n")
            catalog = {
                "entry": {"function_id": "fn-entry", "name": "entry", "file": "entry.c"},
                "fn-a": {"function_id": "fn-a", "name": "parse", "file": "a.c"},
                "fn-b": {"function_id": "fn-b", "name": "parse", "file": "b.c"},
            }
            harness = SimpleNamespace(function_catalog=catalog,
                                      metadata={"run_root": str(root)})
            forward, reverse, _ = scheduler._call_graph(harness)
            self.assertEqual(forward["entry"], {"fn-a"})
            self.assertEqual(reverse["fn-a"], {"entry"})
            self.assertNotIn("fn-b", forward["entry"])
            audit = scheduler.call_graph_audit(harness)
            self.assertEqual(audit["resolved_edges"], 1)
            self.assertEqual(audit["ambiguous_graph_rows"], 1)
            self.assertEqual(audit["ambiguous_source_callsites"], 1)
            self.assertEqual(audit["unknown_id_rows"], 1)
            self.assertEqual(audit["legacy_untyped_rows"], 3)
            self.assertEqual([row["status"] for row in audit["rows"]],
                             ["AMBIGUOUS_EDGE", "RESOLVED_EDGE", "UNKNOWN_ID"])


if __name__ == "__main__":
    unittest.main()
