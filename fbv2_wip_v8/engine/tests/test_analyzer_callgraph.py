"""Call-graph traversal regression for original and prebuilt catalogs."""

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest

from bson import ObjectId
import mongomock

from fuzzingbrain.analyzer.server import AnalysisServer


class CallGraphTraversalTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.server = AnalysisServer.__new__(AnalysisServer)
        self.server.task_id = ObjectId()
        self.server._executor = ThreadPoolExecutor(max_workers=1)
        self.addCleanup(self.server._executor.shutdown)
        db = mongomock.MongoClient().db
        self.nodes = db.callgraph_nodes
        self.functions = db.functions
        self.server.repos = SimpleNamespace(
            callgraph_nodes=SimpleNamespace(collection=self.nodes),
            functions=SimpleNamespace(collection=self.functions),
        )

    def insert(self, function, callees, *, depth, fuzzer="fuzz"):
        self.nodes.insert_one({
            "task_id": self.server.task_id,
            "fuzzer_name": fuzzer,
            "function_name": function,
            "call_depth": depth,
            "callees": callees,
        })

    def insert_function(self, name, content):
        self.functions.insert_one({
            "task_id": self.server.task_id,
            "name": name,
            "content": content,
        })

    async def test_existing_callgraph_node_remains_authoritative(self):
        self.insert("target", [], depth=1)
        self.insert_function("target", "void target(void) {}")
        self.insert_function("lexical_caller", "void lexical_caller(void) { target(); }")

        result = await self.server._get_callers("target")

        self.assertEqual(result["callers"], [])
        self.assertEqual(result["evidence_source"], "STATIC_CALLGRAPH")
        self.assertFalse(result["lexical_fallback"])

    async def test_missing_callgraph_node_uses_pinned_catalog_lexical_fallback(self):
        self.insert_function("target", "void target(void) {}")
        self.insert_function("real_caller", "void real_caller(void) { target (); }")
        self.insert_function("comment_only", "void comment_only(void) { /* target(); */ }")
        self.insert_function("string_only", 'void string_only(void) { log("target()"); }')
        self.insert_function("other_identifier", "void other_identifier(void) { not_target(); }")

        result = await self.server._get_callers("target")

        self.assertEqual(result["callers"], ["real_caller"])
        self.assertEqual(
            result["evidence_source"],
            "PINNED_FUNCTION_CATALOG_LEXICAL_FALLBACK",
        )
        self.assertTrue(result["lexical_fallback"])

    async def test_unknown_function_does_not_search_unbound_catalog_symbol(self):
        self.insert_function("caller", "void caller(void) { external_symbol(); }")

        result = await self.server._get_callers("external_symbol")

        self.assertEqual(result["callers"], [])
        self.assertEqual(result["evidence_source"], "NONE")
        self.assertFalse(result["lexical_fallback"])

    async def test_existing_harness_root_traverses_real_edges(self):
        self.insert("fuzz", ["entry"], depth=0)
        self.insert("entry", ["child"], depth=1)
        self.insert("child", [], depth=2)

        graph = await self.server._get_call_graph("fuzz", 3)

        self.assertEqual(set(graph), {"fuzz", "entry", "child"})
        self.assertEqual(graph["fuzz"]["callees"], ["entry"])

    async def test_prebuilt_catalog_without_harness_root_uses_depth_zero_entries(self):
        self.insert("entry", ["child"], depth=0)
        self.insert("child", [], depth=1)

        graph = await self.server._get_call_graph("fuzz", 3)

        self.assertEqual(set(graph), {"fuzz", "entry", "child"})
        self.assertEqual(graph["fuzz"]["callees"], ["entry"])
        self.assertNotIn("callees", graph)
        self.assertNotIn("function", graph)

    async def test_unknown_fuzzer_does_not_get_a_synthetic_empty_graph(self):
        self.insert("entry", [], depth=0, fuzzer="another-fuzzer")

        self.assertEqual(await self.server._get_call_graph("fuzz", 3), {})

    async def test_same_function_name_from_other_fuzzer_does_not_cross_graphs(self):
        # Insert the unrelated node first so an unscoped find_one picks it.
        self.insert("entry", ["wrong"], depth=0, fuzzer="other")
        self.insert("wrong", [], depth=1, fuzzer="other")
        self.insert("entry", ["correct"], depth=0)
        self.insert("correct", [], depth=1)

        graph = await self.server._get_call_graph("fuzz", 3)

        self.assertEqual(set(graph), {"fuzz", "entry", "correct"})
        self.assertEqual(graph["entry"]["callees"], ["correct"])


if __name__ == "__main__":
    unittest.main()
