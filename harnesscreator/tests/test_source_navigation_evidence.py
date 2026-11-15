"""Source navigation may inspect indexed functions without granting proof."""

from __future__ import annotations

import unittest

from harnesscreator.agents.common import resolve_source_linked_function
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.models import AnalysisBundle, CallEdge, FunctionMetadata


class SourceNavigationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = FunctionMetadata.create(
            name="handle_request", signature="int handle_request(void)",
            file="service.c", start_line=20, end_line=20,
            source="int handle_request(void) { return 1; }",
        )
        self.caller = FunctionMetadata.create(
            name="receive_request", signature="int receive_request(void)",
            file="service.c", start_line=1, end_line=4,
            source="int receive_request(void) { return 0; }",
        )

    def resolve(self, edges: list[CallEdge] | None = None) -> str:
        graph = GraphStore(AnalysisBundle(
            functions={
                self.caller.function_id: self.caller,
                self.target.function_id: self.target,
            }, edges=edges or [],
        ))
        return resolve_source_linked_function(
            self.target.function_id, [self.caller.function_id], [], graph,
        )

    def test_unrelated_source_mention_does_not_block_inspection(self) -> None:
        self.caller.source = (
            'int receive_request(void) {\n'
            '  // handle_request is mentioned in an old design.\n'
            '  const char *example = "handle_request(data)";\n'
            '  int handle_request = 1;\n'
            '  return handle_request + example[0];\n'
            '}\n'
        )
        self.assertEqual(self.resolve(), self.target.function_id)

    def test_ast_call_identity_opens_out_of_frontier_target(self) -> None:
        self.caller.direct_call_sites = [{
            "callee_function_id": self.target.function_id,
            "line": 3,
            "provider": "clang-ast-c",
        }]
        self.assertEqual(self.resolve(), self.target.function_id)

    def test_unparsed_call_spelling_remains_an_inspection_lead(self) -> None:
        self.caller.source = "int receive_request(void) { return handle_request(); }"
        self.assertEqual(self.resolve(), self.target.function_id)

    def test_parsed_call_without_matching_ast_target_can_be_inspected(self) -> None:
        self.caller.source = "int receive_request(void) { return handle_request(); }"
        self.caller.providers.append("clang-ast-c")
        self.assertEqual(self.resolve(), self.target.function_id)

    def test_located_reference_opens_target_without_claiming_execution(self) -> None:
        edge = CallEdge(
            edge_id="reference", caller_id=self.caller.function_id,
            callee_id=self.target.function_id, line=3,
            kind="function_reference", providers=["clang-ast-c"],
        )
        self.assertEqual(self.resolve([edge]), self.target.function_id)

    def test_referenced_table_string_does_not_block_inspection(self) -> None:
        self.caller.referenced_global_declarations = [{
            "name": "routes", "provider": "clang-ast-c",
            "source": 'const char *routes[] = {"handle_request"};',
        }]
        self.assertEqual(self.resolve(), self.target.function_id)

    def test_unindexed_function_still_cannot_be_opened(self) -> None:
        graph = GraphStore(AnalysisBundle(
            functions={self.caller.function_id: self.caller}, edges=[],
        ))
        self.assertEqual(resolve_source_linked_function(
            "missing_function", [self.caller.function_id], [], graph,
        ), "")

    def test_indexed_caller_can_be_opened_from_acquisition_function(self) -> None:
        edge = CallEdge(
            edge_id="caller", caller_id=self.caller.function_id,
            callee_id=self.target.function_id, line=3,
            kind="direct", providers=["clang-ast-c"],
        )
        graph = GraphStore(AnalysisBundle(
            functions={
                self.caller.function_id: self.caller,
                self.target.function_id: self.target,
            }, edges=[edge],
        ))
        self.assertEqual(resolve_source_linked_function(
            self.caller.function_id, [self.target.function_id], [], graph,
        ), self.caller.function_id)

    def test_referenced_table_with_function_identifier_is_navigation_lead(self) -> None:
        self.caller.referenced_global_declarations = [{
            "name": "routes", "provider": "clang-ast-c",
            "source": "Handler routes[] = {handle_request};",
        }]
        self.assertEqual(self.resolve(), self.target.function_id)


if __name__ == "__main__":
    unittest.main()
