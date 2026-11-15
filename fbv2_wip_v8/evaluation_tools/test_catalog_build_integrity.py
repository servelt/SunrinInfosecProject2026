"""Synthetic Catalog/build mismatches; no target ranking or real fuzzing."""
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import copy
import json
import unittest

from catalog_build_integrity import SCHEMA, audit_catalog_build


def pin(path: Path, root: Path) -> dict:
    return {"path": str(path.relative_to(root)),
            "sha256": sha256(path.read_bytes()).hexdigest()}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


class CatalogBuildIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources = self.root / "source"
        self.sources.mkdir()
        (self.sources / "sample.c").write_text(
            "int leaf(void) { return 1; }\n"
            "int parent(void) { return leaf(); }\n")
        self.rows = [
            {"function_id": "leaf", "name": "leaf", "file": "sample.c",
             "start_line": 1, "end_line": 1,
             "source": "int leaf(void) { return 1; }"},
            {"function_id": "parent", "name": "parent", "file": "sample.c",
             "start_line": 2, "end_line": 2,
             "source": "int parent(void) { return leaf(); }"},
        ]
        self.edges = [{"caller_id": "parent", "callee_id": "leaf"}]
        self.catalog = self.root / "functions.jsonl"
        self.graph = self.root / "edges.jsonl"
        self.catalog.write_text("".join(json.dumps(row) + "\n" for row in self.rows))
        self.graph.write_text("".join(json.dumps(row) + "\n" for row in self.edges))
        self.receipt_path = self.root / "receipt.json"
        self.receipt = {"schema": SCHEMA,
                        "catalog_sha256": pin(self.catalog, self.root)["sha256"],
                        "edges_sha256": pin(self.graph, self.root)["sha256"],
                        "roles": {}}
        for role in ("asan", "coverage"):
            binary = self.root / f"{role}.bin"
            binary.write_bytes(f"binary {role}".encode())
            obj = self.root / f"{role}.o"
            obj.write_bytes(f"object {role}".encode())
            ast = self.root / f"{role}.ast.json"
            write_json(ast, {"definitions": copy.deepcopy(self.rows),
                             "edges": copy.deepcopy(self.edges)})
            linkmap = self.root / f"{role}.link.json"
            write_json(linkmap, {"final_linked_function_ids": ["leaf", "parent"]})
            build = self.root / f"{role}.build.json"
            write_json(build, {
                "schema": "EVALUATOR_BUILD_CAPTURE_V1", "role": role,
                "final_binary_sha256": pin(binary, self.root)["sha256"],
                "compilation_units": [{
                    "source_file": "sample.c",
                    "source_sha256": pin(self.sources / "sample.c", self.sources)["sha256"],
                    "argv": ["clang", "-c", "sample.c"],
                    "object": pin(obj, self.root), "active_ast": pin(ast, self.root),
                }],
                "link": {"argv": ["clang", f"{role}.o"],
                         "input_object_sha256": [pin(obj, self.root)["sha256"]],
                         "map": pin(linkmap, self.root)},
            })
            self.receipt["roles"][role] = {
                "binary": pin(binary, self.root), "build_record": pin(build, self.root),
                "active_definitions": copy.deepcopy(self.rows),
                "active_edges": copy.deepcopy(self.edges),
                "final_linked_function_ids": ["leaf", "parent"],
            }

    def check(self, receipt: dict | None = None):
        if receipt is None:
            return audit_catalog_build(self.catalog, self.graph, self.sources,
                                       None, None, evaluator_root=self.root)
        write_json(self.receipt_path, receipt)
        return audit_catalog_build(
            self.catalog, self.graph, self.sources, self.receipt_path,
            pin(self.receipt_path, self.root)["sha256"], evaluator_root=self.root)

    def test_missing_build_receipt_blocks(self):
        self.assertEqual(self.check()["status"], "BLOCKED")

    def test_matching_pinned_receipt_is_only_attested_consistent(self):
        result = self.check(self.receipt)
        self.assertEqual(result["status"], "ATTESTED_RECEIPT_CONSISTENT")
        self.assertIn("independent evaluator review", result["trust_limit"])

    def test_inactive_asan_branch_blocks_even_if_catalog_names_match(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["roles"]["asan"]["active_definitions"][0]["source"] = (
            "int leaf(void) { return -1; }")
        result = self.check(receipt)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertGreater(result["counts"]["asan_catalog_source_mismatches"], 0)

    def test_existing_catalog_edge_requires_role_specific_active_call(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["roles"]["coverage"]["active_edges"] = []
        result = self.check(receipt)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["counts"]["coverage_catalog_edges_without_active_call"], 1)

    def test_archive_definition_without_final_linkage_blocks(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["roles"]["asan"]["final_linked_function_ids"] = ["parent"]
        result = self.check(receipt)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["counts"]["asan_catalog_rows_without_final_linkage"], 1)

    def test_changed_binary_or_build_record_blocks(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["roles"]["coverage"]["binary"]["sha256"] = "0" * 64
        result = self.check(receipt)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(any("coverage binary: FILE_HASH_MISMATCH" in reason
                            for reason in result["reasons"]))

    def test_receipt_does_not_override_independent_ast_or_link_evidence(self):
        receipt = copy.deepcopy(self.receipt)
        receipt["roles"]["asan"]["active_definitions"][0]["source"] = (
            "int leaf(void) { return -1; }")
        result = self.check(receipt)
        self.assertIn("asan: INSUFFICIENT_BUILD_CAPTURE", result["reasons"])

    def test_source_changed_after_build_capture_blocks(self):
        (self.sources / "sample.c").write_text(
            "int leaf(void) { return -1; }\n"
            "int parent(void) { return leaf(); }\n")
        result = self.check(self.receipt)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("asan: INSUFFICIENT_BUILD_CAPTURE", result["reasons"])
        self.assertGreater(result["counts"]["asan_catalog_source_file_mismatches"], 0)

    def test_receipt_hash_must_match_prior_freeze(self):
        write_json(self.receipt_path, self.receipt)
        result = audit_catalog_build(self.catalog, self.graph, self.sources,
                                     self.receipt_path, "0" * 64,
                                     evaluator_root=self.root)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("receipt: FROZEN_HASH_MISMATCH", result["reasons"])


if __name__ == "__main__":
    unittest.main()
