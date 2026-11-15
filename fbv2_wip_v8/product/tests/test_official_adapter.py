"""An official Harness artifact is not a HarnessCreator qualification."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vulnerabilityanalysis.adapter import HarnessAdapter, _observed_harness_call
from vulnerabilityanalysis.scheduler import build_directions, build_pool, build_workers


class OfficialAdapterTests(unittest.TestCase):
    def test_shadowed_helper_pointer_is_not_a_verified_call_chain(self):
        source = ("extern int dangerous(void);\n"
                  "static int helper(void) { return dangerous(); }\n"
                  "static int safe(void) { return 0; }\n"
                  "int LLVMFuzzerTestOneInput(const unsigned char *p, unsigned n) {\n"
                  "  int (*helper)(void) = safe; return helper();\n}\n")
        self.assertFalse(_observed_harness_call(source, "dangerous"))

    def test_shadowed_target_pointer_is_not_a_verified_direct_anchor(self):
        source = ("extern int target_api(void);\n"
                  "int safe(void) { return 0; }\n"
                  "int LLVMFuzzerTestOneInput(const unsigned char *p, unsigned n) {\n"
                  "  int (*target_api)(void) = safe; return target_api();\n}\n")
        self.assertFalse(_observed_harness_call(source, "target_api"))

    def test_function_macro_does_not_verify_target_call(self):
        source = ("extern int target_api(const unsigned char *, unsigned);\n"
                  "static int safe(const unsigned char *p, unsigned n) { return 0; }\n"
                  "#define target_api(...) safe(__VA_ARGS__)\n"
                  "int LLVMFuzzerTestOneInput(const unsigned char *p, unsigned n) {\n"
                  "  return target_api(p, n);\n}\n")
        self.assertFalse(_observed_harness_call(source, "target_api"))
        self.assertFalse(_observed_harness_call(
            "#define target_api safe\nint LLVMFuzzerTestOneInput(void) { return target_api(); }\n",
            "target_api"))
        self.assertTrue(_observed_harness_call(
            "// #define target_api safe\nint LLVMFuzzerTestOneInput(void) { return target_api(); }\n",
            "target_api"))

    def test_function_macro_anchor_stays_unverified_in_official_artifact(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text("static int safe(void) { return 0; }\n"
                              "#define target(...) safe(__VA_ARGS__)\n"
                              "int LLVMFuzzerTestOneInput(void) { return target(); }\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-target"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.metadata["official_direct_call_anchors"], [])
            self.assertEqual(harness.metadata["official_anchor_verification"][0]["status"],
                             "MACRO_BINDING_UNKNOWN")
            direction = build_directions(harness, build_workers(harness)[0])[0]
            pool = {item.function_id: item for item in build_pool(harness, [direction])}
            self.assertIsNone(pool["fn-target"].static_reachable)

    def test_same_name_catalog_definitions_do_not_verify_one_anchor_id(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text("extern int foo(void);\n"
                              "int LLVMFuzzerTestOneInput(void) { return foo(); }\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-decoy"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text("".join(json.dumps(row) + "\n" for row in (
                {"function_id": "fn-real", "name": "foo", "file": "real.c"},
                {"function_id": "fn-decoy", "name": "foo", "file": "decoy.c"},
                {"function_id": "fn-callee", "name": "bar", "file": "decoy.c"},
            )))
            (root / "analysis/edges.jsonl").write_text(json.dumps({
                "caller_id": "fn-decoy", "callee_id": "fn-callee"}) + "\n")
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.metadata["official_direct_call_anchors"], [])
            self.assertEqual(harness.metadata["official_anchor_verification"][0]["status"],
                             "AMBIGUOUS_ANCHOR_BINDING")
            direction = build_directions(harness, build_workers(harness)[0])[0]
            pool = {item.function_id: item for item in build_pool(harness, [direction])}
            self.assertIsNone(pool["fn-decoy"].static_reachable)
            self.assertIsNone(pool["fn-callee"].static_reachable)

    def test_official_artifact_entry_not_called_is_not_reachability_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            entries = root / "entries"; entries.mkdir()
            (entries / "verified-final.jsonl").write_text(json.dumps({
                "entry_id": "entry-1", "entry_function_id": "fn-entry"}) + "\n")
            (root / "analysis/functions.jsonl").write_text("".join(
                json.dumps({"function_id": "fn-" + name, "name": name,
                            "file": "target.c"}) + "\n"
                for name in ("entry", "callee")))
            (root / "analysis/edges.jsonl").write_text(json.dumps({
                "caller_id": "fn-entry", "callee_id": "fn-callee"}) + "\n")
            harness = HarnessAdapter().load(artifact)
            worker = build_workers(harness)[0]
            direction = build_directions(harness, worker)[0]
            pool = {item.function_name: item for item in build_pool(harness, [direction])}
            self.assertEqual(harness.metadata["official_direct_call_anchors"], [])
            self.assertEqual(worker.entry_information, [])
            self.assertIsNone(pool["entry"].static_reachable)
            self.assertIsNone(pool["callee"].static_reachable)
            self.assertEqual(pool["entry"].graph_reachability, "UNKNOWN")
            self.assertEqual(pool["entry"].role, "RELATED")

    def _artifact(self, root: Path) -> Path:
        source = root / "fuzz.c"
        source.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
        (root / "project.json").write_text(json.dumps({"source_root": str(root)}))
        analysis = root / "analysis"
        analysis.mkdir()
        (analysis / "functions.jsonl").write_text(json.dumps({
            "function_id": "fn-target", "name": "target", "file": "target.c",
            "start_line": 1}) + "\n")
        folder = root / "attempt"
        folder.mkdir()
        (folder / "manifest.json").write_text(json.dumps({
            "harness_id": "official-fixture", "source_file": str(source),
            "artifact_kind": "OFFICIAL_OSS_FUZZ", "project_harness": True,
            "oss_fuzz_repository": "https://github.com/google/oss-fuzz",
            "oss_fuzz_revision": "a" * 40,
            "oss_fuzz_harness_path": "projects/example/fuzz.c",
            "harness_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "catalog_producer": "EVALUATOR_GENERATED",
        }))
        (folder / "validation.json").write_text(json.dumps({"build_ok": True}))
        return folder

    def test_official_harness_has_independent_source_kind_and_no_team_qualification(self):
        with TemporaryDirectory() as tmp:
            artifact = self._artifact(Path(tmp))
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.source_kind, "official_oss_fuzz")
            self.assertIsNone(harness.metadata["qualified"])
            self.assertEqual(harness.metadata["catalog_source_kind"], "evaluator_generated")
            self.assertFalse(harness.metadata["official_provenance_verified"])
            self.assertEqual(harness.metadata["harness_validity"], "UNKNOWN")
            self.assertEqual(len(harness.function_catalog), 1)

    def test_official_direct_call_anchor_starts_static_walk_without_runtime_claim(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text("int LLVMFuzzerTestOneInput(void) { A(); return 0; }\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            data["expected_anchors"] = ["fn-a"]
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text("".join(
                json.dumps({"function_id": f"fn-{name.lower()}", "name": name,
                            "file": "target.c"}) + "\n" for name in "ABCX"))
            (root / "analysis/edges.jsonl").write_text("".join(
                json.dumps({"caller_id": caller, "callee_id": callee}) + "\n"
                for caller, callee in (("fn-a", "fn-b"), ("fn-b", "fn-c"),
                                       ("fn-x", "fn-a"))))
            harness = HarnessAdapter().load(artifact)
            direction = build_directions(harness, build_workers(harness)[0])[0]
            pool = {item.function_name: item for item in build_pool(harness, [direction])}
            self.assertEqual(pool["A"].call_depth, 0)
            self.assertEqual(pool["B"].call_depth, 1)
            self.assertEqual(pool["C"].call_depth, 2)
            self.assertTrue(pool["B"].static_reachable)
            self.assertIsNone(pool["X"].static_reachable)
            self.assertEqual(pool["X"].graph_reachability, "GRAPH_UNREACHED")
            self.assertEqual(pool["B"].graph_reachability, "STATIC_REACHED")
            self.assertTrue(all(item.runtime_reachable is None for item in pool.values()))

    def test_unreadable_static_graph_does_not_assert_graph_nonreachability(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-target"]
            data["expected_consumers"] = ["fn-other"]
            manifest.write_text(json.dumps(data))
            with (root / "analysis/functions.jsonl").open("a") as stream:
                stream.write(json.dumps({"function_id": "fn-other", "name": "other",
                                         "file": "target.c"}) + "\n")
            (root / "analysis/edges.jsonl").write_text("not json\n")
            harness = HarnessAdapter().load(artifact)
            direction = build_directions(harness, build_workers(harness)[0])[0]
            pool = {item.function_name: item for item in build_pool(harness, [direction])}
            self.assertEqual(pool["target"].graph_reachability, "UNKNOWN")
            self.assertEqual(pool["other"].graph_reachability, "UNKNOWN")
            self.assertIsNone(pool["other"].runtime_reachable)

    def test_manifest_anchor_without_harness_call_is_not_a_static_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text("// A();\nint LLVMFuzzerTestOneInput(void) { return 0; }\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-a"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text("".join(
                json.dumps({"function_id": f"fn-{name.lower()}", "name": name,
                            "file": "target.c"}) + "\n" for name in "AB"))
            (root / "analysis/edges.jsonl").write_text(
                json.dumps({"caller_id": "fn-a", "callee_id": "fn-b"}) + "\n")
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.metadata["official_direct_call_anchors"], [])
            direction = build_directions(harness, build_workers(harness)[0])[0]
            pool = {item.function_name: item for item in build_pool(harness, [direction])}
            self.assertIsNone(pool["A"].static_reachable)
            self.assertIsNone(pool["B"].static_reachable)
            self.assertEqual(pool["A"].role, "RELATED")

    def test_call_in_unused_harness_helper_is_not_a_static_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text(
                "static int unused_helper(void) { return A(); }\n"
                "int LLVMFuzzerTestOneInput(void) { return 0; }\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-a"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text(json.dumps({
                "function_id": "fn-a", "name": "A", "file": "target.c"}) + "\n")
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.metadata["official_direct_call_anchors"], [])
            self.assertEqual(harness.metadata["official_anchor_verification"][0]["status"],
                             "UNVERIFIED_MANIFEST_ANCHOR")

    def test_call_through_entry_helper_is_a_static_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text(
                "static int used_helper(void) { return A(); }\n"
                "int LLVMFuzzerTestOneInput(void) { return used_helper(); }\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-a"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text(json.dumps({
                "function_id": "fn-a", "name": "A", "file": "target.c"}) + "\n")
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.metadata["official_direct_call_anchors"], ["A"])

    def test_verified_harness_call_is_direction_entry_without_project_entry_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text(
                "extern int A(const unsigned char *, unsigned);\n"
                "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned size) {\n"
                "  return A(data, size);\n}\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-a"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text("".join(
                json.dumps({"function_id": f"fn-{name.lower()}", "name": name,
                            "file": "target.c"}) + "\n" for name in "ABC"))
            (root / "analysis/edges.jsonl").write_text(json.dumps({
                "caller_id": "fn-a", "callee_id": "fn-b",
                "kind": "SOURCE_DIRECT_COMPILED"}) + "\n")
            (root / "analysis/indirect_edges.jsonl").write_text(json.dumps({
                "caller_id": "fn-b", "callee_id": "fn-c",
                "kind": "function_reference", "status": "UNVERIFIED_INDIRECT_REFERENCE"}) + "\n")
            harness = HarnessAdapter().load(artifact)
            worker = build_workers(harness)[0]
            direction = build_directions(harness, worker)[0]
            pool = {item.function_name: item for item in build_pool(harness, [direction])}
            self.assertEqual(harness.entry_functions, [])
            self.assertEqual(worker.entry_information, ["A"])
            self.assertEqual(direction.entry_functions, ["A"])
            self.assertEqual(direction.core_functions, [])
            self.assertIn("OFFICIAL_DIRECT_CALL_ANCHOR",
                          {row["type"] for row in direction.evidence})
            self.assertEqual(pool["A"].role, "ENTRY")
            self.assertEqual(pool["B"].graph_reachability, "STATIC_REACHED")
            self.assertEqual(pool["C"].role, "RELATED")
            self.assertEqual(pool["C"].graph_reachability, "UNKNOWN")
            self.assertIsNone(pool["C"].runtime_reachable)

    def test_function_declaration_inside_harness_is_not_a_direct_call_anchor(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned size) {\n"
                "  extern int dangerous(void);\n"
                "  return (int)size;\n}\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-a"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text("".join(
                json.dumps({"function_id": f"fn-{name.lower()}", "name": name,
                            "file": "target.c"}) + "\n" for name in "AB"))
            (root / "analysis/edges.jsonl").write_text(
                json.dumps({"caller_id": "fn-a", "callee_id": "fn-b"}) + "\n")
            # The manifest names A, and its declaration occurs in executable
            # Harness scope, but neither A nor B can be a verified root.
            source.write_text(source.read_text().replace("dangerous", "A"))
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.metadata["official_direct_call_anchors"], [])
            direction = build_directions(harness, build_workers(harness)[0])[0]
            pool = {item.function_name: item for item in build_pool(harness, [direction])}
            self.assertIsNone(pool["A"].static_reachable)
            self.assertIsNone(pool["B"].static_reachable)

    def test_call_only_in_conditional_harness_code_is_not_a_verified_root(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text("int LLVMFuzzerTestOneInput(void) {\n#if 0\n A();\n#endif\n return 0;\n}\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-a"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text(json.dumps({
                "function_id": "fn-a", "name": "A", "file": "target.c"}) + "\n")
            harness = HarnessAdapter().load(artifact)
            self.assertEqual(harness.metadata["official_direct_call_anchors"], [])

    def test_static_graph_depth_cannot_override_unreached_status(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = self._artifact(root)
            source = root / "fuzz.c"
            source.write_text("int LLVMFuzzerTestOneInput(void) { A(); return 0; }\n")
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["expected_anchors"] = ["fn-a"]
            data["expected_consumers"] = ["fn-x"]
            data["harness_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            (root / "analysis/functions.jsonl").write_text("".join(
                json.dumps({"function_id": f"fn-{name.lower()}", "name": name,
                            "file": "target.c", "static_call_depth": 0}) + "\n"
                for name in "AX"))
            (root / "analysis/edges.jsonl").write_text("".join(
                json.dumps({"caller_id": caller, "callee_id": callee}) + "\n"
                for caller, callee in (("fn-a", "fn-a"),)))
            harness = HarnessAdapter().load(artifact)
            direction = build_directions(harness, build_workers(harness)[0])[0]
            pool = {item.function_name: item for item in build_pool(harness, [direction])}
            self.assertEqual(pool["X"].graph_reachability, "GRAPH_UNREACHED")
            self.assertIsNone(pool["X"].call_depth)
            self.assertEqual(pool["X"].role, "RELATED")
            self.assertIn("X", harness.metadata["official_declared_consumers"])

    def test_official_harness_hash_mismatch_is_rejected(self):
        with TemporaryDirectory() as tmp:
            artifact = self._artifact(Path(tmp))
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["harness_sha256"] = "0" * 64
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "Harness SHA"):
                HarnessAdapter().load(artifact)

    def test_official_harness_cannot_inherit_team_qualified_flag(self):
        with TemporaryDirectory() as tmp:
            artifact = self._artifact(Path(tmp))
            (artifact / "validation.json").write_text(json.dumps({
                "build_ok": True, "qualified": True}))
            with self.assertRaisesRegex(ValueError, "team qualification"):
                HarnessAdapter().load(artifact)

    def test_official_harness_requires_explicit_evaluator_catalog_origin(self):
        with TemporaryDirectory() as tmp:
            artifact = self._artifact(Path(tmp))
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data.pop("catalog_producer")
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "Catalog producer"):
                HarnessAdapter().load(artifact)

    def test_unknown_artifact_kind_is_not_treated_as_team_result(self):
        with TemporaryDirectory() as tmp:
            artifact = self._artifact(Path(tmp))
            manifest = artifact / "manifest.json"
            data = json.loads(manifest.read_text())
            data["artifact_kind"] = "UNREVIEWED_HARNESS"
            manifest.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "artifact_kind"):
                HarnessAdapter().load(artifact)

    def test_unpinned_or_path_traversing_official_claim_is_rejected(self):
        bad_values = (
            ("project_harness", False),
            ("oss_fuzz_repository", "https://example.invalid/not-oss-fuzz"),
            ("oss_fuzz_revision", "floating-main"),
            ("oss_fuzz_harness_path", "projects/../fuzz.c"),
        )
        for key, value in bad_values:
            with self.subTest(key=key), TemporaryDirectory() as tmp:
                artifact = self._artifact(Path(tmp))
                manifest = artifact / "manifest.json"
                data = json.loads(manifest.read_text())
                data[key] = value
                manifest.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError, "provenance"):
                    HarnessAdapter().load(artifact)


if __name__ == "__main__":
    unittest.main()
