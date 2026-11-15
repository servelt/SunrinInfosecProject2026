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
        self.nodes = mongomock.MongoClient().db.callgraph_nodes
        self.server.repos = SimpleNamespace(
            callgraph_nodes=SimpleNamespace(collection=self.nodes))

    def insert(self, function, callees, *, depth, fuzzer="fuzz"):
        self.nodes.insert_one({
            "task_id": self.server.task_id,
            "fuzzer_name": fuzzer,
            "function_name": function,
            "call_depth": depth,
            "callees": callees,
        })

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
