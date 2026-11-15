from __future__ import annotations

import json
from pathlib import Path

import pytest

from harnesscreator.analysis.graph import GraphStore
from harnesscreator.analysis.indexer import StaticAnalyzer
from harnesscreator.analysis.value_flow import direct_sibling_buffer_handoffs


def _index_source(tmp_path: Path, source: str) -> GraphStore:
    file = tmp_path / "server.c"
    file.write_text(source, encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text(json.dumps([{
        "directory": str(tmp_path),
        "file": str(file),
        "arguments": ["clang", "-c", str(file), "-o", str(tmp_path / "server.o")],
    }]), encoding="utf-8")
    bundle = StaticAnalyzer(
        tmp_path, compile_database=tmp_path / "compile_commands.json",
    ).index()
    assert bundle.completeness["clang_c_ast_parsed_files"] == 1
    return GraphStore(bundle)


@pytest.mark.parametrize("handler_body,expected", [
    ("return target_handler(buf);", True),
    ("unsigned char other[8] = {0}; return target_handler(other);", False),
    ("{ unsigned char buf[8] = {0}; return target_handler(buf); }", False),
])
def test_direct_buffer_handoff_respects_clang_declaration_identity(
    tmp_path: Path, handler_body: str, expected: bool,
) -> None:
    graph = _index_source(tmp_path, """
        #include <unistd.h>
        static int input_read(unsigned char *out) { return read(0, out, 8); }
        static int target_handler(const unsigned char *data) { return data[0]; }
        int process_one(void) {
            unsigned char buf[8] = {0};
            if (input_read(buf) <= 0) return -1;
    """ + handler_body + "\n}\n")
    ids = {function.name: function.function_id
           for function in graph.bundle.functions.values()}
    candidates = direct_sibling_buffer_handoffs(
        graph, ids["input_read"], ids["target_handler"],
    )
    assert bool(candidates) is expected
    if expected:
        assert candidates[0].acquisition_api == "read"
        assert candidates[0].buffer_name == "buf"
        assert candidates[0].entry_call_line < candidates[0].target_call_line


def test_buffer_name_without_ast_arguments_is_not_handoff(tmp_path: Path) -> None:
    graph = _index_source(tmp_path, """
        #include <unistd.h>
        static int input_read(unsigned char *out) { return read(0, out, 8); }
        static int target_handler(const unsigned char *data) { return data[0]; }
        int process_one(void) {
            unsigned char buf[8] = {0};
            input_read(buf);
            return target_handler(buf);
        }
    """)
    ids = {function.name: function.function_id
           for function in graph.bundle.functions.values()}
    graph.get(ids["process_one"]).direct_call_sites.clear()
    assert direct_sibling_buffer_handoffs(
        graph, ids["input_read"], ids["target_handler"],
    ) == ()
