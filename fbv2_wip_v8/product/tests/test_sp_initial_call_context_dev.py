"""Recorded graph context is delivered only to the development SP first pass."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.source import SourceRepository
from vulnerabilityanalysis.sp_initial_context import initial_sp_call_context
from vulnerabilityanalysis.workflow import run_phase1

from test_direction_plan import fixture


class _CaptureProvider:
    def __init__(self):
        self.requests = []

    async def generate(self, request):
        self.requests.append(request)
        if request.role == "sp_generation":
            return {"suspicious_points": []}
        raise AssertionError(request.role)


class InitialSPCallContextDevTest(unittest.TestCase):
    def _fixture(self, root: Path):
        artifact, repo, plan = fixture(root)
        (repo / "target.c").write_text(
            "int B(void) { return 1; }\n"
            "int A(void) { return B(); }\n"
            "int C(void) { return 0; }\n"
            "int D(void) { return C(); }\n")
        return artifact, repo, plan

    def test_direct_caller_and_callee_are_recorded_without_runtime_claim(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _ = self._fixture(Path(temp))
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            resolver = ContextResolver(SourceRepository(repo, harness.function_catalog),
                                       call_graph_path=repo / "analysis/edges.jsonl")
            context, audit = initial_sp_call_context(harness, resolver, "fn-b")
            self.assertEqual(audit["status"], "DELIVERED")
            self.assertEqual(context[0]["callers"][0]["function_id"], "fn-a")
            self.assertEqual(context[0]["runtime_reachability"], "UNKNOWN")
            self.assertEqual(audit["caller_source_count"], 1)
            self.assertIn("return B();", context[1]["source"])
            self.assertEqual(context[1]["relation"], "CALLER_OF")

    def test_development_scan_sends_graph_context_but_score_scan_does_not(self):
        with TemporaryDirectory() as temp:
            artifact, repo, plan = self._fixture(Path(temp))
            for policy, expected in (("FBV2_FIRST_PASS_UNIQUE_DEV", True),
                                     ("SCORE", False)):
                with self.subTest(policy=policy):
                    run = run_phase1(artifact, repo / "runs", target_repository=repo,
                                     direction_plan=plan if expected else None,
                                     selection_policy=policy)
                    provider = _CaptureProvider()
                    asyncio.run(scan_selected(
                        run, provider, target_repository=repo,
                        hallucination_prevent="off",
                        candidate_budget_policy=("DRAIN_RANKED_DEV" if expected
                                                 else "PAIR_RESERVED"),
                        max_candidates=0, sp_llm_call_limit=1))
                    sp = [row for row in provider.requests
                          if row.role == "sp_generation"]
                    self.assertEqual(len(sp), 1)
                    context = sp[0].payload["context"]
                    self.assertEqual(bool(context), expected)
                    if expected:
                        self.assertEqual(context[0]["callees"][0]["function_id"], "fn-b")
                        record = json.loads((run / "scan.json").read_text())
                        self.assertEqual(record["initial_sp_call_context"]["status"],
                                         "DELIVERED")
                        self.assertIsNotNone(record["initial_sp_call_context_sha256"])
                    else:
                        self.assertFalse((run / "sp/initial_call_context.json").exists())

    def test_unavailable_graph_does_not_invent_neighbors(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _ = self._fixture(Path(temp))
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            (repo / "analysis/edges.jsonl").unlink()
            resolver = ContextResolver(SourceRepository(repo, harness.function_catalog),
                                       call_graph_path=repo / "analysis/edges.jsonl")
            context, audit = initial_sp_call_context(harness, resolver, "fn-a")
            self.assertEqual(context, [])
            self.assertEqual(audit["reason"], "DIRECT_GRAPH_UNAVAILABLE")

    def test_non_direct_rows_before_direct_edge_do_not_exhaust_caller_sources(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _ = self._fixture(Path(temp))
            (repo / "target.c").write_text(
                "int B(void) { return 1; }\n"
                "int A(void) { return B(); }\n"
                "int C(void) { return 0; }\n"
                "int D(void) { return 0; }\n"
                "int E(void) { return 0; }\n")
            edges = repo / "analysis/edges.jsonl"
            rows = [{"caller_id": f"fn-{name}", "callee_id": "fn-b",
                     "kind": "function_reference"} for name in ("c", "d", "e")]
            rows.append({"caller_id": "fn-a", "callee_id": "fn-b",
                         "kind": "SOURCE_DIRECT_COMPILED"})
            edges.write_text("".join(json.dumps(row) + "\n" for row in rows))
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            resolver = ContextResolver(SourceRepository(repo, harness.function_catalog),
                                       call_graph_path=edges)
            context, audit = initial_sp_call_context(harness, resolver, "fn-b")
            self.assertEqual(context[0]["callers"],
                             [{"function_id": "fn-a", "function_name": "A"}])
            self.assertEqual(audit["caller_source_count"], 1)
            self.assertEqual(context[1]["function_id"], "fn-a")
            self.assertIn("return B();", context[1]["source"])

    def test_harness_same_name_fallback_is_not_catalog_caller_source(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _ = self._fixture(Path(temp))
            harness_source = repo / "fuzz.c"
            harness_source.write_text(
                "int B(void);\n"
                "int A(void) { return B(); }\n"
                "int LLVMFuzzerTestOneInput(void) { return A(); }\n")
            manifest_path = artifact / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["harness_sha256"] = hashlib.sha256(harness_source.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            functions_path = repo / "analysis/functions.jsonl"
            functions = [json.loads(line) for line in functions_path.read_text().splitlines()]
            for row in functions:
                if row["function_id"] == "fn-a":
                    row["file"] = "missing.c"
            functions_path.write_text("".join(json.dumps(row) + "\n" for row in functions))
            (repo / "target.c").write_text("int B(void) { return 1; }\n")
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            resolver = ContextResolver(SourceRepository(repo, harness.function_catalog),
                                       call_graph_path=repo / "analysis/edges.jsonl",
                                       harness_path=harness_source)
            context, audit = initial_sp_call_context(harness, resolver, "fn-b")
            self.assertEqual(context[0]["callers"],
                             [{"function_id": "fn-a", "function_name": "A"}])
            self.assertEqual(audit["caller_source_count"], 0)
            self.assertEqual(len(context), 1)

    def test_caller_source_uses_original_1500_character_bound_with_audit(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _ = self._fixture(Path(temp))
            body = "\n".join(f"    int value_{i} = {i};" for i in range(140))
            (repo / "target.c").write_text(
                "int B(void) { return 1; }\n"
                "int A(void) {\n" + body + "\n    return B();\n}\n")
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            resolver = ContextResolver(SourceRepository(repo, harness.function_catalog),
                                       call_graph_path=repo / "analysis/edges.jsonl")
            context, audit = initial_sp_call_context(harness, resolver, "fn-b")
            self.assertEqual(audit["caller_source_count"], 1)
            self.assertLessEqual(len(context[1]["source"]), 1500)
            self.assertEqual(audit["caller_source_truncated_count"], 1)
            self.assertGreater(audit["caller_source_omitted_chars"], 0)

    def test_caller_source_does_not_escape_recorded_first_fifteen(self):
        with TemporaryDirectory() as temp:
            artifact, repo, _ = self._fixture(Path(temp))
            (repo / "target.c").write_text(
                (repo / "target.c").read_text()
                + "int Caller16(void) { return B(); }\n")
            functions_path = repo / "analysis/functions.jsonl"
            rows = [json.loads(line) for line in functions_path.read_text().splitlines()]
            rows.extend({"function_id": f"fn-caller-{number:02d}",
                         "name": f"Caller{number:02d}",
                         "file": "target.c" if number == 16 else "missing.c"}
                        for number in range(1, 17))
            functions_path.write_text("".join(json.dumps(row) + "\n" for row in rows))
            edges_path = repo / "analysis/edges.jsonl"
            edges_path.write_text("".join(json.dumps({
                "caller_id": f"fn-caller-{number:02d}", "callee_id": "fn-b",
                "kind": "SOURCE_DIRECT_COMPILED"}) + "\n"
                for number in range(1, 17)))
            harness = HarnessAdapter().load(artifact, target_repository=repo)
            resolver = ContextResolver(SourceRepository(repo, harness.function_catalog),
                                       call_graph_path=edges_path)
            context, audit = initial_sp_call_context(harness, resolver, "fn-b")
            self.assertEqual(len(context[0]["callers"]), 15)
            self.assertEqual(audit["omitted_callers"], 1)
            self.assertEqual(audit["caller_source_count"], 0)
            self.assertEqual(len(context), 1)

    def test_resume_rejects_changed_accumulated_context(self):
        from test_sp_queue_drain_dev import _ScriptedProvider

        with TemporaryDirectory() as temp:
            artifact, repo, plan = self._fixture(Path(temp))
            first = run_phase1(artifact, repo / "runs", target_repository=repo,
                               direction_plan=plan,
                               selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            asyncio.run(scan_selected(
                first, _ScriptedProvider(candidate_count=1),
                target_repository=repo, hallucination_prevent="off",
                candidate_budget_policy="DRAIN_RANKED_DEV",
                max_candidates=0, sp_llm_call_limit=1))
            context_path = first / "context.json"
            context_path.write_bytes(context_path.read_bytes() + b"\n")
            resumed = run_phase1(artifact, repo / "runs", target_repository=repo,
                                 direction_plan=plan,
                                 selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            with self.assertRaisesRegex(ValueError, "accumulated context lineage mismatch"):
                asyncio.run(scan_selected(
                    resumed, _ScriptedProvider(candidate_count=1),
                    target_repository=repo, resume_from=first,
                    hallucination_prevent="off",
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    max_candidates=0, sp_llm_call_limit=1))

    def test_resume_rejects_changed_initial_context_bytes(self):
        from test_sp_queue_drain_dev import _ScriptedProvider

        with TemporaryDirectory() as temp:
            artifact, repo, plan = self._fixture(Path(temp))
            first = run_phase1(artifact, repo / "runs", target_repository=repo,
                               direction_plan=plan,
                               selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            asyncio.run(scan_selected(
                first, _ScriptedProvider(candidate_count=1),
                target_repository=repo, hallucination_prevent="off",
                candidate_budget_policy="DRAIN_RANKED_DEV",
                max_candidates=0, sp_llm_call_limit=1))
            prior_context = first / "sp" / "initial_call_context.json"
            prior_context.write_bytes(prior_context.read_bytes() + b"\n")
            resumed = run_phase1(artifact, repo / "runs", target_repository=repo,
                                 direction_plan=plan,
                                 selection_policy="FBV2_FIRST_PASS_UNIQUE_DEV")
            with self.assertRaisesRegex(ValueError, "initial context lineage mismatch"):
                asyncio.run(scan_selected(
                    resumed, _ScriptedProvider(candidate_count=1),
                    target_repository=repo, resume_from=first,
                    hallucination_prevent="off",
                    candidate_budget_policy="DRAIN_RANKED_DEV",
                    max_candidates=0, sp_llm_call_limit=1))


if __name__ == "__main__":
    unittest.main()
