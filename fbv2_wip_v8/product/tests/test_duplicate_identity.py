"""Non-target fixtures for Function Catalog identity and source provenance."""
from __future__ import annotations

import json
import asyncio
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest, stable_id
from vulnerabilityanalysis.scheduler import build_directions, build_pool, build_workers, source_evidence_for_pool
from vulnerabilityanalysis.source import SourceRepository
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1
from vulnerabilityanalysis.scan import scan_selected


def _make_artifact(root: Path, *, ambiguous_manifest: bool = False) -> tuple[Path, Path]:
    repo = root / "repo"
    repo.mkdir()
    (repo / "first.c").write_text(
        "static int parse(const unsigned char *p) { return p[0] + 11; }\n"
        "int enter_first(const unsigned char *p) { return parse(p); }\n")
    (repo / "second.c").write_text(
        "static int parse(const unsigned char *p) { return p[0] + 22; }\n"
        "int enter_second(const unsigned char *p) { return parse(p); }\n")
    (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
    analysis = root / "analysis"
    analysis.mkdir()
    rows = [
        {"function_id": "fn-enter-first", "name": "enter_first", "file": "first.c", "start_line": 2},
        {"function_id": "fn-enter-second", "name": "enter_second", "file": "second.c", "start_line": 2},
        {"function_id": "fn-parse-first", "name": "parse", "file": "first.c", "start_line": 1},
        {"function_id": "fn-parse-second", "name": "parse", "file": "second.c", "start_line": 1},
    ]
    (analysis / "functions.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows))
    edges = [
        {"caller_id": "fn-enter-first", "callee_id": "fn-parse-first"},
        {"caller_id": "fn-enter-second", "callee_id": "fn-parse-second"},
    ]
    (analysis / "edges.jsonl").write_text("".join(json.dumps(row) + "\n" for row in edges))
    entries = root / "entries"
    entries.mkdir()
    (entries / "verified-final.jsonl").write_text("".join(
        json.dumps({"entry_function_id": fid}) + "\n"
        for fid in ("fn-enter-first", "fn-enter-second")))
    artifact = root / "attempt"
    artifact.mkdir()
    (artifact / "fuzz.c").write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
    (artifact / "manifest.json").write_text(json.dumps({
        "harness_id": "identity-fixture", "source_file": "fuzz.c",
        "expected_consumers": (["parse"] if ambiguous_manifest else
                               ["fn-parse-first", "fn-parse-second"]),
        "sanitizers": ["address"],
    }))
    (artifact / "validation.json").write_text('{"build_ok": true}')
    return artifact, repo


class DuplicateIdentityTests(unittest.TestCase):
    def test_scan_selected_keeps_duplicate_function_identity(self):
        class Provider:
            async def generate(self, request):
                if request.role == "sp_generation":
                    return {"suspicious_points": []}
                if request.role == "function_analysis":
                    return {"summary": "no claim", "input_flow": "unknown",
                            "state_dependencies": [], "context_requests": [],
                            "safe_assumptions": [], "unknowns": [], "input_sources": [],
                            "security_sensitive_operations": [], "validations": [],
                            "memory_operations": [], "evidence": [],
                            "hypothesis_evaluations": []}
                raise AssertionError(request.role)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, repo = _make_artifact(root)
            run = run_phase1(artifact, root / "results", target_repository=repo)
            selection = json.loads((run / "selection.json").read_text())
            self.assertEqual(selection["function_name"], "parse")
            asyncio.run(scan_selected(run, Provider(), target_repository=repo,
                                      run_command=["/usr/bin/true", "{input}"],
                                      hallucination_prevent="on"))
            scan = json.loads((run / "scan.json").read_text())
            self.assertEqual(scan["selected_function_id"], selection["function_id"])
            expected_file = ("first.c" if selection["function_id"] == "fn-parse-first"
                             else "second.c")
            self.assertEqual(Path(scan["source_path"]).name, expected_file)

    def test_legacy_unique_catalog_accepts_synthesized_pool_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "target.c").write_text("int decode(void) { return 11; }\n")
            repo = SourceRepository(root, {"decode": {"name": "decode", "file": "target.c"}})
            self.assertIn("return 11", repo.open_function(
                stable_id("fn", "decode", "target.c")))

    def test_unique_catalog_cannot_replace_missing_checkout_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = SourceRepository(Path(tmp), {"decode": {
                "name": "decode", "file": "unavailable.c", "start_line": 4,
                "source": "int decode(void) { return 11; }"}})
            with self.assertRaises(FileNotFoundError):
                repo.open_function("decode")

    def test_both_static_definitions_survive_pool_and_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact, repo = _make_artifact(Path(tmp))
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            self.assertEqual(len(harness.function_catalog), 4)
            workers = build_workers(harness)
            directions = build_directions(harness, workers[0])
            pool = build_pool(harness, directions)
            parsers = [row for row in pool if row.function_name == "parse"]
            self.assertEqual({row.function_id for row in parsers},
                             {"fn-parse-first", "fn-parse-second"})
            source = source_evidence_for_pool(harness, pool)
            self.assertIn("+ 11", source["fn-parse-first"])
            self.assertIn("+ 22", source["fn-parse-second"])
            self.assertNotEqual(source["fn-parse-first"], source["fn-parse-second"])
            run = run_phase1(artifact, Path(tmp) / "results", target_repository=repo)
            persisted = json.loads((run / "function_pool.json").read_text())
            self.assertEqual({row["function_id"] for row in persisted
                              if row["function_name"] == "parse"},
                             {"fn-parse-first", "fn-parse-second"})

    def test_context_accepts_explicit_ids_and_rejects_ambiguous_short_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact, repo = _make_artifact(Path(tmp))
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            resolver = ContextResolver(SourceRepository(repo, harness.function_catalog))
            request = ContextRequest("enter_first", "parse", "CALLEE", "test", "source")
            first = resolver._function_context("fn-parse-first", request)
            second = resolver._function_context("fn-parse-second", request)
            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            self.assertIn("+ 11", first["source"])
            self.assertIn("+ 22", second["source"])
            self.assertIsNone(resolver._function_context("parse", request))

    def test_duplicate_call_relation_requires_matching_function_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, repo = _make_artifact(root)
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            resolver = ContextResolver(SourceRepository(repo, harness.function_catalog),
                                       call_graph_path=root / "analysis/edges.jsonl")
            request = ContextRequest("fn-enter-first", "parse", "CALLEE", "test", "source")
            first = resolver._function_context("fn-parse-first", request,
                                               relation="CALLEE_OF", related="enter_first",
                                               call_type="direct")
            wrong = resolver._function_context("fn-parse-second", request,
                                               relation="CALLEE_OF", related="enter_first",
                                               call_type="direct")
            self.assertIsNotNone(first)
            self.assertIsNone(wrong)
            first_rows = resolver.resolve(request)
            second_rows = resolver.resolve(ContextRequest(
                "fn-enter-second", "parse", "CALLEE", "test", "source"))
            self.assertEqual(len(first_rows), 1)
            self.assertEqual(len(second_rows), 1)
            self.assertIn("+ 11", first_rows[0]["source"])
            self.assertIn("+ 22", second_rows[0]["source"])

    def test_unqualified_ambiguous_manifest_name_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact, repo = _make_artifact(Path(tmp), ambiguous_manifest=True)
            with self.assertRaisesRegex(ValueError, "ambiguous function reference"):
                HarnessAdapter().load(artifact, target_repository=repo)

    def test_same_file_overload_uses_exact_catalog_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "overload.cc").write_text(
                "int decode(int x) { return x + 11; }\n"
                "int decode(const char *x) { return x[0] + 22; }\n")
            catalog = {
                "fn-int": {"function_id": "fn-int", "name": "decode", "file": "overload.cc", "start_line": 1},
                "fn-str": {"function_id": "fn-str", "name": "decode", "file": "overload.cc", "start_line": 2},
            }
            repo = SourceRepository(root, catalog)
            self.assertIn("+ 11", repo.open_function("fn-int"))
            self.assertIn("+ 22", repo.open_function("fn-str"))
            catalog["fn-str"]["start_line"] = 99
            with self.assertRaises(ValueError):
                repo.open_function("fn-str")

    def test_ambiguous_name_never_falls_back_to_first_200_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a_first.c").write_text("int parse(void) { return 11; }\n")
            for index in range(201):
                (root / f"m_{index:03d}.c").write_text("int unrelated(void);\n")
            (root / "z_second.c").write_text("int parse(void) { return 22; }\n")
            catalog = {
                "fn-first": {"function_id": "fn-first", "name": "parse", "file": "a_first.c", "start_line": 1},
                "fn-second": {"function_id": "fn-second", "name": "parse", "file": "z_second.c", "start_line": 1},
            }
            resolver = ContextResolver(SourceRepository(root, catalog))
            request = ContextRequest("caller", "parse", "FUNCTION", "test", "source")
            self.assertIsNone(resolver._function_context("parse", request))

    def test_stale_catalog_line_does_not_resolve_to_other_overload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "overload.cc").write_text(
                "int decode(int x) { return x + 11; }\n"
                "int decode(const char *x) { return x[0] + 22; }\n")
            catalog = {
                "fn-int": {"function_id": "fn-int", "name": "decode",
                           "file": "overload.cc", "start_line": 99},
                "fn-str": {"function_id": "fn-str", "name": "decode",
                           "file": "overload.cc", "start_line": 2},
            }
            resolver = ContextResolver(SourceRepository(root, catalog))
            request = ContextRequest("caller", "decode", "FUNCTION", "test", "source")
            self.assertIsNone(resolver._function_context("fn-int", request))
            valid = resolver._function_context("fn-str", request)
            self.assertIsNotNone(valid)
            self.assertIn("+ 22", valid["source"])

    def test_continuation_requires_id_when_names_collide(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact, repo = _make_artifact(root)
            run = run_phase1(artifact, root / "results", target_repository=repo)
            selected = json.loads((run / "selection.json").read_text())
            self.assertEqual(selected["function_name"], "parse")
            scan = {"selected_function": "parse", "target_repository": str(repo)}
            (run / "scan.json").write_text(json.dumps(scan))
            with self.assertRaisesRegex(ValueError, "identity"):
                continue_phase1(run)
            scan["selected_function_id"] = "fn-wrong"
            (run / "scan.json").write_text(json.dumps(scan))
            with self.assertRaisesRegex(ValueError, "identity"):
                continue_phase1(run)
            scan["selected_function_id"] = selected["function_id"]
            (run / "scan.json").write_text(json.dumps(scan))
            next_run = continue_phase1(run)
            self.assertNotEqual(json.loads((next_run / "selection.json").read_text())["function_id"],
                                selected["function_id"])


if __name__ == "__main__":
    unittest.main()
