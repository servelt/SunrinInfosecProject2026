"""Provider-free tests for the opt-in prebuilt adapter."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


MODULE = Path(__file__).resolve().parents[1] / "fuzzingbrain/analyzer/prebuilt_adapter.py"
spec = importlib.util.spec_from_file_location("prebuilt_adapter", MODULE)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
models_path = MODULE.with_name("models.py")
models_spec = importlib.util.spec_from_file_location("analyzer_models", models_path)
models = importlib.util.module_from_spec(models_spec)
models_spec.loader.exec_module(models)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PrebuiltAdapterTest(unittest.TestCase):
    def test_request_roundtrip_preserves_manifest_pin(self):
        request = models.AnalyzeRequest(
            task_id="0" * 24, task_path="/tmp/task", project_name="fixture",
            sanitizers=["address"], prebuilt_manifest="/tmp/manifest.json",
            prebuilt_manifest_sha256="a" * 64,
        )
        decoded = models.AnalyzeRequest.from_dict(request.to_dict())
        self.assertEqual(decoded.prebuilt_manifest, request.prebuilt_manifest)
        self.assertEqual(decoded.prebuilt_manifest_sha256, request.prebuilt_manifest_sha256)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.task = Path(self.temp.name)
        self.repo = self.task / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "test/fuzzers").mkdir(parents=True)
        (self.repo / "src/a.c").write_text("void entry(void) { child(); }\nvoid child(void) {}\n")
        (self.repo / "test/fuzzers/fuzz.c").write_text("int LLVMFuzzerTestOneInput(void) { entry(); return 0; }\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Test",
             "-c", "user.email=test@example.com", "commit", "-qm", "fixture"],
            check=True,
        )
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True
        ).strip()
        self.asan = self.task / "asan" / "fuzz"
        self.coverage = self.task / "coverage" / "fuzz"
        self.asan.parent.mkdir()
        self.coverage.parent.mkdir()
        self.asan.write_bytes(b"asan binary")
        self.coverage.write_bytes(b"coverage binary")
        self.functions = self.task / "functions.jsonl"
        self.edges = self.task / "edges.jsonl"
        source_sha = digest(self.repo / "src/a.c")
        functions = [
            {
                "function_id": identifier, "name": name, "file": "src/a.c",
                "start_line": line, "end_line": line, "source": source,
                "role_linkage": {
                    "asan": {"binary_sha256": digest(self.asan), "source_sha256": source_sha},
                    "coverage": {"binary_sha256": digest(self.coverage), "source_sha256": source_sha},
                },
            }
            for identifier, name, line, source in (
                ("fn-entry", "entry", 1, "void entry(void) { child(); }"),
                ("fn-child", "child", 2, "void child(void) {}"),
            )
        ]
        self.functions.write_text("".join(json.dumps(x) + "\n" for x in functions))
        self.edges.write_text(json.dumps({"caller_id": "fn-entry", "callee_id": "fn-child", "confidence": "COMPILER_AST_AND_OBJECT"}) + "\n")
        self.manifest = {
            "schema": "fbv2-prebuilt-v1", "project_name": "fixture",
            "fuzzer_name": "fuzz", "entry_function": "entry",
            "source_commit": self.commit,
            "source_files": {
                "src/a.c": source_sha,
                "test/fuzzers/fuzz.c": digest(self.repo / "test/fuzzers/fuzz.c"),
            },
            "harness_source": "test/fuzzers/fuzz.c",
            "asan_binary": {"path": str(self.asan), "sha256": digest(self.asan)},
            "coverage_binary": {"path": str(self.coverage), "sha256": digest(self.coverage)},
            "catalog": {
                "functions": {"path": str(self.functions), "sha256": digest(self.functions)},
                "edges": {"path": str(self.edges), "sha256": digest(self.edges)},
            },
        }
        self.manifest_path = self.task / "manifest.json"

    def prepare(self):
        self.manifest_path.write_text(json.dumps(self.manifest))
        return adapter.prepare_prebuilt(self.manifest_path, digest(self.manifest_path), self.task, "fixture", ["address"])

    def test_success_prepares_reachable_graph_and_harness_source(self):
        index = self.repo / ".git/index"
        index_before = index.read_bytes()
        result = self.prepare()
        self.assertEqual(index.read_bytes(), index_before)
        self.assertEqual(result["reachable_count"], 2)
        output = Path(result["prebuild_dir"]) / "mongodb"
        functions = json.loads((output / "functions.json").read_text())
        graph = json.loads((output / "callgraph.json").read_text())
        self.assertEqual(len(functions), 3)
        self.assertEqual(next(x for x in functions if x["name"] == "fuzz")
                         ["reached_by_fuzzers"], [])
        self.assertEqual(next(x for x in functions if x["name"] == "entry")
                         ["reached_by_fuzzers"], ["fuzz"])
        self.assertEqual({x["language"] for x in functions}, {"c"})
        self.assertEqual({x["function_name"]: x["call_depth"] for x in graph},
                         {"entry": 0, "child": 1})
        self.assertEqual(next(x for x in graph if x["function_name"] == "entry")["callers"],
                         ["fuzz"])
        self.assertEqual(result["harness_edge_provenance"],
                         "PINNED_MANIFEST_AND_HARNESS_LEXICAL_TOKEN_CANDIDATE")
        self.assertIn("LLVMFuzzerTestOneInput", functions[-1]["content"])

    def test_repeated_prepare_reuses_exact_content_addressed_outputs(self):
        first = self.prepare()
        output = Path(first["prebuild_dir"])
        expected_directories = (
            output, output / "binaries", output / "binaries/address",
            output / "binaries/coverage", output / "mongodb",
        )
        self.assertEqual(
            {path.stat().st_mode & 0o777 for path in expected_directories},
            {0o555})
        second = self.prepare()
        self.assertEqual(first, second)
        self.assertEqual(
            {path.stat().st_mode & 0o777 for path in expected_directories},
            {0o555})
        self.assertEqual(digest(Path(first["asan_binary"])),
                         self.manifest["asan_binary"]["sha256"])

    def test_prepare_ignores_inherited_git_repository_overrides(self):
        with mock.patch.dict(os.environ, {
                "GIT_DIR": str(self.task / "outside-git"),
                "GIT_INDEX_FILE": str(self.task / "outside-index"),
                "GIT_WORK_TREE": str(self.task / "outside-worktree")},
                clear=False):
            result = self.prepare()
        self.assertEqual(result["reachable_count"], 2)

    def test_prebuilt_output_root_symlink_is_rejected_without_redirection(self):
        outside_temp = tempfile.TemporaryDirectory()
        self.addCleanup(outside_temp.cleanup)
        outside = Path(outside_temp.name)
        (self.task / ".fbv2_prebuilt").symlink_to(
            outside, target_is_directory=True)
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError,
                                    "linked or unsafe"):
            self.prepare()
        self.assertEqual(list(outside.iterdir()), [])

    def test_every_derived_output_component_rejects_symlink(self):
        outside_temp = tempfile.TemporaryDirectory()
        self.addCleanup(outside_temp.cleanup)
        outside = Path(outside_temp.name)
        parent = self.task / "output-parent"
        parent.mkdir()
        descriptor = os.open(parent, adapter._DIRECTORY_FLAGS)
        self.addCleanup(os.close, descriptor)
        for name in (".fbv2_prebuilt", "0" * 64, "binaries", "address",
                     "coverage", "mongodb"):
            with self.subTest(name=name):
                alias = parent / name
                alias.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(adapter.PrebuiltIdentityError,
                                            "linked or unsafe"):
                    adapter._open_output_directory(descriptor, name)
                alias.unlink()

    def test_parent_replacement_during_publication_fails_closed(self):
        outside_temp = tempfile.TemporaryDirectory()
        self.addCleanup(outside_temp.cleanup)
        outside = Path(outside_temp.name)
        original = adapter._snapshot_binary_at
        swapped = False

        def swap_parent_then_snapshot(*args, **kwargs):
            nonlocal swapped
            if not swapped:
                root = self.task / ".fbv2_prebuilt"
                root.rename(self.task / "detached-prebuilt")
                root.symlink_to(outside, target_is_directory=True)
                swapped = True
            return original(*args, **kwargs)

        with mock.patch.object(adapter, "_snapshot_binary_at",
                               swap_parent_then_snapshot):
            with self.assertRaisesRegex(adapter.PrebuiltIdentityError,
                                        "changed during publication"):
                self.prepare()
        self.assertTrue(swapped)
        self.assertEqual(list(outside.iterdir()), [])

    def test_linked_object_ast_edge_is_accepted(self):
        edge = json.loads(self.edges.read_text())
        edge["confidence"] = "COMPILER_AST_AND_LINKED_OBJECT"
        self.edges.write_text(json.dumps(edge) + "\n")
        self.manifest["catalog"]["edges"]["sha256"] = digest(self.edges)
        self.assertEqual(self.prepare()["reachable_count"], 2)

    def test_multiple_pinned_harness_entries_are_reachable_roots(self):
        harness = self.repo / "test/fuzzers/fuzz.c"
        harness.write_text(
            "int LLVMFuzzerTestOneInput(void) { entry(); child(); return 0; }\n"
        )
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Test",
             "-c", "user.email=test@example.com", "commit", "-qm", "two harness entries"],
            check=True,
        )
        self.manifest["source_commit"] = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True,
        ).strip()
        self.manifest["source_files"]["test/fuzzers/fuzz.c"] = digest(harness)
        self.manifest["entry_functions"] = ["entry", "child"]
        result = self.prepare()
        graph = json.loads((Path(result["prebuild_dir"]) / "mongodb/callgraph.json").read_text())
        self.assertEqual(result["harness_entry_count"], 2)
        self.assertEqual({row["function_name"]: row["call_depth"] for row in graph},
                         {"entry": 0, "child": 0})
        self.assertEqual(next(row for row in graph if row["function_name"] == "child")
                         ["callers"], ["entry", "fuzz"])

    def test_extra_entry_without_harness_call_is_rejected(self):
        self.manifest["entry_functions"] = ["entry", "child"]
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError,
                                    "harness has no lexical direct call"):
            self.prepare()

    def test_duplicate_or_missing_primary_entry_is_rejected(self):
        for names in (["entry", "entry"], ["child"]):
            self.manifest["entry_functions"] = names
            with self.assertRaisesRegex(adapter.PrebuiltIdentityError,
                                        "entry_functions must be unique"):
                self.prepare()

    def test_uncompiled_edge_confidence_is_rejected(self):
        edge = json.loads(self.edges.read_text())
        edge["confidence"] = "TEXT_ONLY"
        self.edges.write_text(json.dumps(edge) + "\n")
        self.manifest["catalog"]["edges"]["sha256"] = digest(self.edges)
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError,
                                    "catalog edge lacks compiled confidence"):
            self.prepare()

    def test_cpp_sources_keep_cpp_language_in_imported_function_docs(self):
        source = self.repo / "src/a.c"
        harness = self.repo / "test/fuzzers/fuzz.c"
        source.rename(source.with_suffix(".cpp"))
        harness.rename(harness.with_suffix(".cpp"))
        functions = [json.loads(line) for line in self.functions.read_text().splitlines()]
        for row in functions:
            row["file"] = "src/a.cpp"
        self.functions.write_text("".join(json.dumps(row) + "\n" for row in functions))
        self.manifest["source_files"] = {
            "src/a.cpp": digest(self.repo / "src/a.cpp"),
            "test/fuzzers/fuzz.cpp": digest(self.repo / "test/fuzzers/fuzz.cpp"),
        }
        self.manifest["harness_source"] = "test/fuzzers/fuzz.cpp"
        self.manifest["catalog"]["functions"]["sha256"] = digest(self.functions)
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Test",
             "-c", "user.email=test@example.com", "commit", "-qm", "cpp fixture"],
            check=True,
        )
        self.manifest["source_commit"] = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True,
        ).strip()
        result = self.prepare()
        imported = json.loads((Path(result["prebuild_dir"]) / "mongodb/functions.json").read_text())
        self.assertEqual({row["language"] for row in imported}, {"cpp"})

    def test_header_language_is_rejected_when_unproven(self):
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError,
                                    "ambiguous source language"):
            adapter._source_language("src/inline.h")

    def test_comment_only_harness_entry_is_rejected(self):
        harness = self.repo / "test/fuzzers/fuzz.c"
        harness.write_text(
            "int LLVMFuzzerTestOneInput(void) { return 0; // entry(data)\n}\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Test",
             "-c", "user.email=test@example.com", "commit", "-qm", "comment only"],
            check=True,
        )
        self.manifest["source_commit"] = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.manifest["source_files"]["test/fuzzers/fuzz.c"] = digest(harness)
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError,
                                    "no lexical direct call"):
            self.prepare()

    def test_lexical_harness_check_ignores_string_and_other_function(self):
        source = (
            'void unrelated(void) { entry(data); }\n'
            'int LLVMFuzzerTestOneInput(void) {\n'
            '  const char *text = "entry(data)";\n'
            '  return 0; /* entry(data) */\n'
            '}\n'
        )
        self.assertFalse(adapter._harness_lexically_calls_entry(source, "entry"))
        self.assertTrue(adapter._harness_lexically_calls_entry(
            source.replace("return 0;", "entry(data); return 0;"), "entry"))

    def test_source_mutation_fails_before_prebuild_output(self):
        (self.repo / "src/a.c").write_text("changed\n")
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "source repository is not clean"):
            self.prepare()
        self.assertFalse((self.task / ".fbv2_prebuilt").exists())

    def test_binary_mutation_fails(self):
        self.asan.write_bytes(b"different")
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "ASan binary: SHA-256 mismatch"):
            self.prepare()

    def test_coverage_binary_name_must_match_fuzzer(self):
        renamed = self.coverage.with_name("wrong-fuzzer")
        self.coverage.rename(renamed)
        self.manifest["coverage_binary"] = {"path": str(renamed), "sha256": digest(renamed)}
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "coverage binary name"):
            self.prepare()

    def test_asan_binary_name_must_match_fuzzer(self):
        renamed = self.asan.with_name("wrong-fuzzer")
        self.asan.rename(renamed)
        self.manifest["asan_binary"] = {"path": str(renamed), "sha256": digest(renamed)}
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "ASan binary name"):
            self.prepare()

    def test_original_binary_mutation_does_not_change_execution_snapshot(self):
        result = self.prepare()
        snapshot = Path(result["asan_binary"])
        self.assertNotEqual(snapshot, self.asan)
        self.assertEqual(digest(snapshot), self.manifest["asan_binary"]["sha256"])
        self.asan.write_bytes(b"changed after prepare")
        self.assertEqual(digest(snapshot), self.manifest["asan_binary"]["sha256"])
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "ASan binary: SHA-256 mismatch"):
            self.prepare()

    def test_mutated_execution_snapshot_fails_dispatch_recheck(self):
        result = self.prepare()
        snapshot = Path(result["coverage_binary"])
        snapshot.chmod(0o755)
        snapshot.write_bytes(b"tampered snapshot")
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "pinned binary snapshot mismatch"):
            self.prepare()

    def test_catalog_linkage_fails(self):
        rows = [json.loads(line) for line in self.functions.read_text().splitlines()]
        rows[0]["role_linkage"]["coverage"]["binary_sha256"] = "0" * 64
        self.functions.write_text("".join(json.dumps(x) + "\n" for x in rows))
        self.manifest["catalog"]["functions"]["sha256"] = digest(self.functions)
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "linkage mismatch"):
            self.prepare()

    def test_unsupported_sanitizer_fails(self):
        self.manifest_path.write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "address only"):
            adapter.prepare_prebuilt(self.manifest_path, digest(self.manifest_path), self.task, "fixture", ["undefined"])

    def test_manifest_mutation_fails_before_artifact_processing(self):
        self.manifest_path.write_text(json.dumps(self.manifest))
        expected = digest(self.manifest_path)
        self.manifest_path.write_text(self.manifest_path.read_text() + " ")
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "manifest SHA-256 mismatch"):
            adapter.prepare_prebuilt(self.manifest_path, expected, self.task, "fixture", ["address"])

    def test_parent_directory_symlink_for_pinned_catalog_fails(self):
        real = self.task / "real-catalog"
        real.mkdir()
        moved = real / self.functions.name
        self.functions.replace(moved)
        alias = self.task / "catalog-alias"
        alias.symlink_to(real, target_is_directory=True)
        self.manifest["catalog"]["functions"] = {
            "path": str(alias / moved.name), "sha256": digest(moved)}
        with self.assertRaisesRegex(
                adapter.PrebuiltIdentityError, "absolute path or SHA-256"):
            self.prepare()

    def test_committed_source_symlink_fails(self):
        source = self.repo / "src/a.c"
        outside = self.task / "outside.c"
        outside.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(outside)
        subprocess.run(["git", "-C", str(self.repo), "add", "src/a.c"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "-c", "user.name=Test",
             "-c", "user.email=test@example.com", "commit", "-qm", "symlink"],
            check=True,
        )
        self.manifest["source_commit"] = subprocess.check_output(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True
        ).strip()
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "source missing or symlink"):
            self.prepare()

    def test_duplicate_function_name_fails(self):
        rows = [json.loads(line) for line in self.functions.read_text().splitlines()]
        rows[1]["name"] = "entry"
        self.functions.write_text("".join(json.dumps(x) + "\n" for x in rows))
        self.manifest["catalog"]["functions"]["sha256"] = digest(self.functions)
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "duplicate/ambiguous"):
            self.prepare()

    def test_catalog_line_numbers_must_match_excerpt(self):
        rows = [json.loads(line) for line in self.functions.read_text().splitlines()]
        rows[0]["start_line"] = rows[0]["end_line"] = 9999
        self.functions.write_text("".join(json.dumps(x) + "\n" for x in rows))
        self.manifest["catalog"]["functions"]["sha256"] = digest(self.functions)
        with self.assertRaisesRegex(adapter.PrebuiltIdentityError, "source line mismatch"):
            self.prepare()


if __name__ == "__main__":
    unittest.main()
