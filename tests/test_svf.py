from __future__ import annotations

import json
from pathlib import Path

from harnesscreator.analysis import (
    GraphStore,
    SVFEvidence,
    SVFIndirectEdge,
    augment_analysis_with_svf,
    load_svf_evidence,
    parse_svf_callgraph_dot,
)
from harnesscreator.models import AnalysisBundle, FunctionMetadata
from harnesscreator.analysis.svf import (
    SVF_SCHEMA, SVFRunner, default_svf_cache_root, discover_bitcode,
)


def test_bitcode_discovery_skips_run_artifacts_but_keeps_build_output(tmp_path: Path) -> None:
    built = tmp_path / "build" / "daemon.bc"
    built.parent.mkdir()
    built.write_bytes(b"build bitcode")
    run_artifact = tmp_path / "runs-old" / "daemon.bc"
    run_artifact.parent.mkdir()
    run_artifact.write_bytes(b"stale bitcode")

    assert discover_bitcode(tmp_path) == [built.resolve()]


def test_svf_digest_uses_bitcode_content_instead_of_temporary_path(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first" / "module.bc"
    second = tmp_path / "second" / "module.bc"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(b"same LLVM module")
    second.write_bytes(first.read_bytes())
    sources = [str(tmp_path / "server.c")]

    first_key = SVFRunner._digest(
        [first], sources, "locked-revision", "recipe", tmp_path,
    )
    second_key = SVFRunner._digest(
        [second], sources, "locked-revision", "recipe", tmp_path,
    )

    assert first_key == second_key
    second.write_bytes(b"changed LLVM module")
    assert SVFRunner._digest(
        [second], sources, "locked-revision", "recipe", tmp_path,
    ) != first_key
    assert SVFRunner._digest(
        [first], sources, "locked-revision", "recipe", tmp_path / "other",
    ) != first_key


def test_default_svf_cache_follows_source_checkout_not_run_directory(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    other = tmp_path / "other-source"
    source.mkdir()
    other.mkdir()

    assert default_svf_cache_root(source) == default_svf_cache_root(
        source / ".." / "source"
    )
    assert default_svf_cache_root(source) != default_svf_cache_root(other)


SVF_DOT = r'''
digraph "Call Graph" {
    Node0x1 [shape=record,label="{CallGraphNode ID: 1 {fun: drive_machine}}"];
    Node0x2 [shape=record,label="{CallGraphNode ID: 2 {fun: tcp_read}}"];
    Node0x3 [shape=record,label="{CallGraphNode ID: 3 {fun: ssl_read}}"];
    Node0x4 [shape=record,label="{CallGraphNode ID: 4 {fun: direct_helper}}"];
    Node0x1 -> Node0x2 [label="41",color=red];
    Node0x1 -> Node0x3 [label="41", color="red"];
    Node0x1 -> Node0x4 [label="12",color=black];
}
'''


def _function(name: str, file: str, line: int) -> FunctionMetadata:
    return FunctionMetadata.create(
        name=name,
        qualified_name=name,
        signature=f"int {name}(void)",
        file=file,
        start_line=line,
        end_line=line + 2,
        source=f"int {name}(void) {{ return 0; }}",
    )


def test_official_dot_adapter_keeps_only_indirect_edges() -> None:
    edges = parse_svf_callgraph_dot(SVF_DOT)

    assert [
        (edge.caller_symbol, edge.callee_symbol, edge.callsite_id)
        for edge in edges
    ] == [
        ("drive_machine", "ssl_read", "41"),
        ("drive_machine", "tcp_read", "41"),
    ]


def test_official_dot_adapter_accepts_escaped_labels_and_source_ports() -> None:
    edges = parse_svf_callgraph_dot(
        r'''
digraph "Call Graph" {
  Node0x1 [shape=record,label="{CallGraphNode ID: 1 \{fun: drive_machine\}|{<s0>7}}"];
  Node0x2 [shape=record,label="{CallGraphNode ID: 2 \{fun: tcp_read\}}"];
  Node0x1:s0 -> Node0x2[color=red];
}
'''
    )

    assert edges == [SVFIndirectEdge("drive_machine", "tcp_read", "s0")]


def test_svf_mapping_uses_compiled_sources_and_retains_all_targets(
    tmp_path: Path,
) -> None:
    caller = _function("drive_machine", "memcached.c", 3000)
    tcp = _function("tcp_read", "memcached.c", 130)
    tls = _function("ssl_read", "tls.c", 360)
    duplicate_test_helper = _function("tcp_read", "testapp.c", 900)
    bundle = AnalysisBundle(
        functions={
            item.function_id: item
            for item in (caller, tcp, tls, duplicate_test_helper)
        },
        edges=[],
        completeness={"provider": "fuzz-introspector+bootstrap-source"},
    )
    report = tmp_path / "svf.json"
    report.write_text(
        json.dumps(
            {
                "schema": SVF_SCHEMA,
                "provider": "SVF-Andersen",
                "analysis": "AndersenWaveDiff_WPA",
                "svf_revision": "locked",
                "compiled_sources": [
                    "/src/memcached/memcached.c",
                    "/src/memcached/tls.c",
                ],
                "edges": [
                    {
                        "caller_symbol": "drive_machine",
                        "callee_symbol": "tcp_read",
                        "callsite_id": "41",
                        "kind": "indirect_possible",
                    },
                    {
                        "caller_symbol": "drive_machine",
                        "callee_symbol": "ssl_read",
                        "callsite_id": "41",
                        "kind": "indirect_possible",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    result = augment_analysis_with_svf(
        bundle,
        load_svf_evidence(report),
        source_root=tmp_path,
    )

    assert result.mapped_edges == 2
    assert not result.mapping_failures
    mapped = {
        (edge.caller_id, edge.callee_id, edge.kind)
        for edge in result.bundle.edges
    }
    assert mapped == {
        (caller.function_id, tcp.function_id, "indirect_possible"),
        (caller.function_id, tls.function_id, "indirect_possible"),
    }
    assert result.bundle.completeness["svf_used"] is True
    assert result.bundle.completeness["svf_indirect_edges_mapped"] == 2
    assert tcp.callers == [caller.function_id]
    assert duplicate_test_helper.callers == []

    frontier = GraphStore(result.bundle).frontier([tcp.function_id])
    connection = frontier[0]["connections"][0]
    assert connection["possible_indirect_target"] is True
    assert connection["edge_kinds"] == ["indirect_possible"]
    assert connection["edge_providers"] == ["SVF-Andersen"]


def test_ambiguous_symbol_fails_closed_without_compiled_source_evidence(
    tmp_path: Path,
) -> None:
    caller = _function("dispatch", "server.c", 10)
    first = _function("tcp_read", "server.c", 30)
    second = _function("tcp_read", "tests.c", 40)
    bundle = AnalysisBundle(
        functions={item.function_id: item for item in (caller, first, second)},
        edges=[],
        completeness={"provider": "test"},
    )
    evidence = SVFEvidence(
        source=tmp_path / "callgraph_final.dot",
        edges=[SVFIndirectEdge("dispatch", "tcp_read", "7")],
    )

    result = augment_analysis_with_svf(bundle, evidence, source_root=tmp_path)

    assert result.mapped_edges == 0
    assert len(result.mapping_failures) == 1
    assert "ambiguous symbol" in result.mapping_failures[0]["callee_mapping"]
    assert result.bundle.edges == []


def test_zero_svf_edges_does_not_hide_ast_function_table(tmp_path: Path) -> None:
    dispatcher = _function("dispatch", "server.c", 10)
    target = _function("handle_request", "server.c", 30)
    dispatcher.indirect_table_call_sites = [{
        "table_name": "handlers",
        "call_line": 11,
        "candidate_function_ids": [target.function_id],
        "provider": "clang-ast-c",
    }]
    bundle = AnalysisBundle(
        functions={item.function_id: item for item in (dispatcher, target)},
        edges=[], completeness={"provider": "clang-ast-c"},
    )

    result = augment_analysis_with_svf(
        bundle, SVFEvidence(tmp_path / "empty-svf.json", []),
        source_root=tmp_path,
    )

    assert result.bundle.completeness["svf_status"] == "USED"
    assert result.bundle.completeness["indirect_callgraph"] == "partial"
    assert result.bundle.completeness["clang_ast_indirect_table_sites"] == 1
    assert result.bundle.completeness[
        "svf_ast_table_sites_without_matching_symbol_edges"
    ] == 1
    assert result.bundle.edges == []
