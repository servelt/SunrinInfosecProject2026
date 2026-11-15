"""Regression coverage for the Function Analyzer's requested context."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis import scan as scan_module
from vulnerabilityanalysis.source import SourceRepository
from vulnerabilityanalysis.workflow import run_phase1


def _unknown_hypothesis():
    return {
        "source_location": "target.c:1", "source_file": "target.c",
        "source_line": 1, "source_quote": "fixture source",
        "security_property": "fixture context contract",
        "input_influence": "INPUT_DEPENDENT",
        "hypothesis": "additional source may affect this fixture hypothesis",
        "judgment": "UNKNOWN", "reason": "context is requested",
        "safe_assumption": "",
    }


class FunctionContextExpansionTest(unittest.TestCase):
    def test_scan_delivers_late_caller_callsite_to_function_analyzer(self):
        class Provider:
            def __init__(self):
                self.requests = []

            async def generate(self, request):
                self.requests.append(request)
                if request.role == "sp_generation":
                    return {"suspicious_points": []}
                if request.role != "function_analysis":
                    raise AssertionError(request.role)
                first = sum(row.role == "function_analysis" for row in self.requests) == 1
                return {"summary": "inspect source relation", "input_flow": "input bytes",
                        "state_dependencies": [], "context_requests": ([{
                            "target": "caller", "request_type": "FUNCTION",
                            "reason": "inspect its callsites", "expected_information": "late callsite",
                            "hypothesis_index": 0}]
                            if first else []), "safe_assumptions": [], "unknowns": [],
                        "input_sources": [], "security_sensitive_operations": [],
                        "validations": [], "memory_operations": [], "evidence": [],
                        "safe_assumption_lifecycle": [],
                        "hypothesis_evaluations": [_unknown_hypothesis()]}

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            filler = "".join(f"  int value_{i} = {i};\n" for i in range(600))
            (repo / "target.c").write_text(
                "int target(void) { return 1; }\nint caller(void) {\n" + filler +
                "  int result = target();\n  return result;\n}\n")
            artifact = root / "artifact"
            artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char* data, size_t size) "
                "{ return size ? target() : 0; }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "late-callsite-fixture", "source_file": "fuzz.c",
                "expected_consumers": ["target"], "sanitizers": ["UNKNOWN"],
                "artifact_kind": "REGRESSION_FIXTURE", "project_harness": False}))
            (artifact / "validation.json").write_text(
                '{"build_ok": false, "qualified": false}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            analysis = root / "analysis"
            analysis.mkdir()
            (analysis / "functions.jsonl").write_text("\n".join(json.dumps({
                "function_id": name, "name": name, "file": "target.c"})
                for name in ("target", "caller")) + "\n")
            run = run_phase1(artifact, root / "results", target_repository=repo)
            provider = Provider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      hallucination_prevent="on"))
            hp = [request for request in provider.requests
                  if request.role == "function_analysis"]
            self.assertEqual(len(hp), 2)
            self.assertEqual(hp[0].payload["context"], [])
            row = hp[1].payload["context"][0]
            self.assertIn("int result = target();", row["callsite_excerpt"])
            self.assertLessEqual(len(row["source"]) + len(row["callsite_excerpt"]), 8000)
            self.assertEqual(json.loads((run / "hp_context_requests.json").read_text())
                             [0]["delivered_to_analysis"], True)

    def test_scan_never_sends_unrelated_or_unknown_branch_macro(self):
        class Provider:
            def __init__(self, target):
                self.contexts = []
                self.target = target

            async def generate(self, request):
                if request.role == "sp_generation":
                    return {"suspicious_points": []}
                if request.role != "function_analysis":
                    raise AssertionError(request.role)
                self.contexts.append(request.payload["context"])
                requests = ([{"target": self.target, "request_type": "MACRO",
                              "reason": "inspect macro", "expected_information": "active body",
                              "hypothesis_index": 0}]
                            if len(self.contexts) == 1 else [])
                return {"summary": "macro context", "input_flow": "harness input",
                        "state_dependencies": [], "context_requests": requests,
                        "safe_assumptions": [], "unknowns": [], "input_sources": [],
                        "security_sensitive_operations": [], "validations": [],
                        "memory_operations": [], "evidence": [],
                        "safe_assumption_lifecycle": [],
                        "hypothesis_evaluations": [_unknown_hypothesis()]}

        definitions = {
            "unique": ("PUSH", "PUSH(value)", "#define PUSH(x) correct(x)\n", True),
            "conditional": ("PUSH", "PUSH(value)",
                            "#ifdef __cplusplus\n#define PUSH(x) cpp(x)\n"
                            "#else\n#define PUSH(x) c(x)\n#endif\n", False),
            "object": ("MAX_ITEMS", "MAX_ITEMS", "#define MAX_ITEMS 4096\n", True),
            "object_conditional": ("MAX_ITEMS", "MAX_ITEMS",
                                   "#ifdef __cplusplus\n#define MAX_ITEMS 8192\n"
                                   "#else\n#define MAX_ITEMS 4096\n#endif\n", False),
        }
        for kind, (target, expression, macro_source, should_fetch) in definitions.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                repo = root / "repo"
                (repo / "src").mkdir(parents=True)
                (repo / "rust").mkdir()
                (repo / "rust" / "util.h").write_text(
                    "#define PUSH(x) unrelated_cpp_port(x)\n"
                    "#define MAX_ITEMS 9999\n")
                (repo / "src" / "util.h").write_text(macro_source)
                (repo / "src" / "target.c").write_text(
                    f'#include "util.h"\nint parse(int value) {{ return {expression}; }}\n')
                artifact = root / "artifact"
                artifact.mkdir()
                (artifact / "fuzz.c").write_text(
                    "int LLVMFuzzerTestOneInput(const unsigned char* data, size_t size) "
                    "{ return size ? parse(data[0]) : 0; }\n")
                (artifact / "manifest.json").write_text(json.dumps({
                    "harness_id": "macro-context-fixture", "source_file": "fuzz.c",
                    "expected_consumers": ["parse"], "sanitizers": ["UNKNOWN"],
                    "artifact_kind": "REGRESSION_FIXTURE", "project_harness": False}))
                (artifact / "validation.json").write_text(
                    '{"build_ok": false, "qualified": false}')
                (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
                analysis = root / "analysis"
                analysis.mkdir()
                (analysis / "functions.jsonl").write_text(json.dumps({
                    "function_id": "parse", "name": "parse",
                    "file": "src/target.c"}) + "\n")
                run = run_phase1(artifact, root / "results", target_repository=repo)
                provider = Provider(target)
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                                          hallucination_prevent="on"))
                requests = json.loads((run / "hp_context_requests.json").read_text())
                if should_fetch:
                    self.assertEqual(len(provider.contexts), 2)
                    self.assertEqual(requests[0]["status"], "FETCHED")
                    self.assertEqual(requests[0]["delivered_to_analysis"], True)
                    self.assertEqual(provider.contexts[1][0]["source_file"],
                                     str(repo / "src" / "util.h"))
                    self.assertIn("correct(x)" if target == "PUSH" else "4096",
                                  provider.contexts[1][0]["source"])
                    self.assertEqual(provider.contexts[1][0]["definition_kind"],
                                     "FUNCTION_LIKE_MACRO" if target == "PUSH" else
                                     "OBJECT_LIKE_MACRO")
                else:
                    self.assertEqual(requests[0]["status"], "NOT_FOUND")
                    self.assertTrue(all(not context for context in provider.contexts))
                self.assertTrue(all("unrelated_cpp_port" not in str(context) and
                                    "9999" not in str(context)
                                    for context in provider.contexts))

    def test_scan_delivers_registered_harness_callback_and_requested_context(self):
        class Provider:
            def __init__(self):
                self.requests = []

            async def generate(self, request):
                self.requests.append(request)
                if request.role == "sp_generation":
                    return {"suspicious_points": []}
                if request.role == "function_analysis":
                    seen = sum(row.role == "function_analysis" for row in self.requests)
                    requests = ([{"target": "helper", "request_type": "FUNCTION",
                                  "reason": "inspect the input contract",
                                  "expected_information": "helper body",
                                  "hypothesis_index": 0}]
                                if seen == 1 else [])
                    return {"summary": "input contract", "input_flow": "harness input",
                            "state_dependencies": [], "context_requests": requests,
                            "safe_assumptions": [], "unknowns": [], "input_sources": [],
                            "security_sensitive_operations": [], "validations": [],
                            "memory_operations": [], "evidence": [],
                            "safe_assumption_lifecycle": [],
                            "hypothesis_evaluations": [_unknown_hypothesis()]}
                raise AssertionError(f"unexpected role: {request.role}")

        variants = {
            "unconditional": ("void* limited_malloc(void* ctx, unsigned long size) {\n"
                              "  if (size > 8000000) return 0;\n"
                              "  return malloc(size);\n}\n", True),
            "ambiguous": ("#if FLAG\n"
                          "void* limited_malloc(void* ctx, unsigned long size) { return 0; }\n"
                          "#else\n"
                          "void* limited_malloc(void* ctx, unsigned long size) { return malloc(size); }\n"
                          "#endif\n", False),
            "inactive": ("#if 0\n"
                         "void* limited_malloc(void* ctx, unsigned long size) { return 0; }\n"
                         "#endif\n", False),
            "oversized": ("void* limited_malloc(void* ctx, unsigned long size) {\n" +
                          "  /* callback body exceeds the shared excerpt budget */\n" * 100 +
                          "  return malloc(size);\n}\n", False),
        }
        for name, (callback, should_include) in variants.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                repo = root / "repo"
                repo.mkdir()
                (repo / "target.c").write_text(
                    "int helper(void) { return 7; }\n"
                    "int parse(void) { return helper(); }\n")
                artifact = root / "hg"
                artifact.mkdir()
                harness_path = artifact / "fuzz.cc"
                harness_source = (
                    "/* unrelated prefix */\n" * 140 + callback +
                    "int LLVMFuzzerTestOneInput(const unsigned char* data, size_t size) {\n"
                    "  set_allocator(limited_malloc);\n"
                    "  if (size) parse();\n"
                    "  return 0;\n}\n" +
                    "/* unrelated suffix */\n" * 140)
                harness_path.write_text(harness_source)
                (artifact / "manifest.json").write_text(json.dumps({
                    "harness_id": "callback-fixture", "source_file": "fuzz.cc",
                    "expected_consumers": ["parse"], "sanitizers": ["UNKNOWN"],
                    "artifact_kind": "REGRESSION_FIXTURE", "project_harness": False}))
                (artifact / "validation.json").write_text('{"build_ok": false, "qualified": false}')
                (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
                analysis = root / "analysis"
                analysis.mkdir()
                (analysis / "functions.jsonl").write_text(json.dumps({
                    "function_id": "parse", "name": "parse", "file": "target.c"}) + "\n")

                run = run_phase1(artifact, root / "results", target_repository=repo)
                provider = Provider()
                asyncio.run(scan_selected(run, provider, target_repository=repo,
                                          hallucination_prevent="on"))
                self.assertEqual(json.loads((run / "selection.json").read_text())
                                 ["function_name"], "parse")
                hp_requests = [row for row in provider.requests
                               if row.role == "function_analysis"]
                self.assertEqual(len(hp_requests), 2)
                for request in hp_requests:
                    payload = request.payload
                    self.assertEqual(payload["harness_source_file"],
                                     str(harness_path.resolve()))
                    self.assertEqual(harness_path.read_text(), harness_source)
                    excerpt = payload["harness_source"]
                    self.assertIn("set_allocator(limited_malloc)", excerpt)
                    if should_include:
                        self.assertIn(callback, excerpt)
                        self.assertIn("size > 8000000", excerpt)
                    else:
                        self.assertNotIn("void* limited_malloc(", excerpt)
                    self.assertLessEqual(len(excerpt), 4096)
                    self.assertTrue(payload["harness_source_truncated"])
                self.assertEqual(hp_requests[0].payload["context"], [])
                self.assertEqual([row["target"] for row in
                                  hp_requests[1].payload["context"]], ["helper"])
                self.assertIn("return 7", hp_requests[1].payload["context"][0]["source"])
                self.assertEqual(hp_requests[1].payload["context"][0]["source_file"],
                                 str((repo / "target.c").resolve()))
                records = json.loads((run / "hp_context_requests.json").read_text())
                self.assertEqual([(row["status"], row["delivered_to_analysis"])
                                  for row in records], [("FETCHED", True)])
                sp_request = next(row for row in provider.requests
                                  if row.role == "sp_generation")
                self.assertEqual(sp_request.payload["harness_source_file"],
                                 str(harness_path.resolve()))
                self.assertEqual(sp_request.payload["harness_source"],
                                 hp_requests[0].payload["harness_source"])

    def test_explicit_function_request_finds_unique_uncatalogued_definition(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.c").write_text(
                "int helper(void) { return 1; }\n"
                "int parse(void) { return helper(); }\n")
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "target.c"}}))
            rows = resolver.resolve(ContextRequest(
                "parse", "helper", "FUNCTION", "inspect helper", "body"))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["function_name"], "helper")
            self.assertIn("return 1", rows[0]["source"])

    def test_explicit_function_request_rejects_ambiguous_definitions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "parse.c").write_text("int parse(void) { return helper(); }\n")
            (root / "a.c").write_text("int helper(void) { return 1; }\n")
            (root / "b.c").write_text("int helper(void) { return 2; }\n")
            resolver = ContextResolver(SourceRepository(root, {
                "parse": {"file": "parse.c"}}))
            self.assertEqual(resolver.resolve(ContextRequest(
                "parse", "helper", "FUNCTION", "inspect helper", "body")), [])

    def test_two_requested_functions_reach_the_same_reanalysis(self):
        class Provider:
            def __init__(self):
                self.analysis_contexts = []

            async def generate(self, request):
                if request.role == "function_analysis":
                    context = request.payload["context"]
                    self.analysis_contexts.append([dict(row) for row in context])
                    requests = ([
                        {"target": name, "request_type": "FUNCTION",
                         "reason": "inspect the call path", "expected_information": "body",
                         "hypothesis_index": 0}
                        for name in ("first_helper", "second_helper")
                    ] if len(self.analysis_contexts) == 1 else [])
                    return {"summary": "source path", "input_flow": "harness input",
                            "state_dependencies": [], "context_requests": requests,
                            "safe_assumptions": [], "unknowns": [], "input_sources": [],
                            "security_sensitive_operations": [], "validations": [],
                            "memory_operations": [], "evidence": [],
                            "safe_assumption_lifecycle": [],
                            "hypothesis_evaluations": [_unknown_hypothesis()]}
                if request.role == "sp_generation":
                    return {"suspicious_points": []}
                raise AssertionError(f"unexpected role: {request.role}")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "target.c").write_text(
                "int first_helper(void) { return 1; }\n"
                "int second_helper(void) { return 2; }\n"
                "int parse(void) { return first_helper() + second_helper(); }\n")
            artifact = root / "hg"
            artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "int LLVMFuzzerTestOneInput(void) { return parse(); }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c",
                "expected_consumers": ["parse"], "sanitizers": ["UNKNOWN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            analysis = root / "analysis"
            analysis.mkdir()
            (analysis / "functions.jsonl").write_text("\n".join(json.dumps({
                "function_id": name, "name": name, "file": "target.c"})
                for name in ("parse", "first_helper", "second_helper")) + "\n")

            run = run_phase1(artifact, root / "results", target_repository=repo)
            provider = Provider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      hallucination_prevent="on"))
            self.assertEqual(len(provider.analysis_contexts), 2)
            self.assertEqual({row["target"] for row in provider.analysis_contexts[1]},
                             {"first_helper", "second_helper"})

            limited_run = run_phase1(artifact, root / "results", target_repository=repo)
            limited_provider = Provider()
            original_load = scan_module.yaml.safe_load
            def limited_budget(config_text):
                config = original_load(config_text)
                config["budget"]["max_llm_calls_per_function"] = 2
                return config
            with patch.object(scan_module.yaml, "safe_load", side_effect=limited_budget):
                asyncio.run(scan_selected(limited_run, limited_provider,
                                          target_repository=repo, hallucination_prevent="on"))
            self.assertEqual(len(limited_provider.analysis_contexts), 1)
            self.assertEqual(json.loads((limited_run / "hp_context.json").read_text()), [])
            limited_requests = json.loads((limited_run / "hp_context_requests.json").read_text())
            self.assertEqual([row["status"] for row in limited_requests],
                             ["SKIPPED_LLM_BUDGET", "SKIPPED_LLM_BUDGET"])

    def test_second_expansion_round_resolves_a_new_contract(self):
        class Provider:
            def __init__(self):
                self.analysis_contexts = []

            async def generate(self, request):
                if request.role == "function_analysis":
                    context = request.payload["context"]
                    self.analysis_contexts.append([dict(row) for row in context])
                    targets = ("first_helper", "second_helper", "third_helper")
                    target = targets[len(self.analysis_contexts) - 1]
                    requests = ([] if target is None else [{
                        "target": target, "request_type": "FUNCTION",
                        "reason": "inspect the next contract",
                        "expected_information": "body",
                        "hypothesis_index": 0,
                    }])
                    return {"summary": "source path", "input_flow": "harness input",
                            "state_dependencies": [], "context_requests": requests,
                            "safe_assumptions": [], "unknowns": [], "input_sources": [],
                            "security_sensitive_operations": [], "validations": [],
                            "memory_operations": [], "evidence": [],
                            "safe_assumption_lifecycle": [],
                            "hypothesis_evaluations": [_unknown_hypothesis()]}
                if request.role == "sp_generation":
                    return {"suspicious_points": []}
                raise AssertionError(f"unexpected role: {request.role}")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "target.c").write_text(
                "int first_helper(void) { return 1; }\n"
                "int second_helper(void) { return 2; }\n"
                "int third_helper(void) { return 3; }\n"
                "int parse(void) { return first_helper() + second_helper(); }\n")
            artifact = root / "hg"
            artifact.mkdir()
            (artifact / "fuzz.c").write_text(
                "int LLVMFuzzerTestOneInput(void) { return parse(); }\n")
            (artifact / "manifest.json").write_text(json.dumps({
                "harness_id": "h", "source_file": "fuzz.c",
                "expected_consumers": ["parse"], "sanitizers": ["UNKNOWN"]}))
            (artifact / "validation.json").write_text('{"build_ok": true}')
            (root / "project.json").write_text(json.dumps({"source_root": str(repo)}))
            analysis = root / "analysis"
            analysis.mkdir()
            (analysis / "functions.jsonl").write_text("\n".join(json.dumps({
                "function_id": name, "name": name, "file": "target.c"})
                for name in ("parse", "first_helper", "second_helper", "third_helper")) + "\n")

            run = run_phase1(artifact, root / "results", target_repository=repo)
            provider = Provider()
            asyncio.run(scan_selected(run, provider, target_repository=repo,
                                      hallucination_prevent="on"))
            self.assertEqual(len(provider.analysis_contexts), 3)
            self.assertEqual([row["target"] for row in provider.analysis_contexts[1]],
                             ["first_helper"])
            self.assertEqual({row["target"] for row in provider.analysis_contexts[2]},
                             {"first_helper", "second_helper"})
            requests = json.loads((run / "hp_context_requests.json").read_text())
            self.assertEqual([row["status"] for row in requests],
                             ["FETCHED", "FETCHED", "SKIPPED_CONTEXT_ROUND_LIMIT"])
            self.assertTrue(all(row.get("delivered_to_analysis") for row in requests[:2]))
