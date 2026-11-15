"""Provider-free boundaries for generic SP/HP Context closure V1."""

from pathlib import Path
from types import SimpleNamespace

import fuzzingbrain.analyzer as analyzer_package
from devtools.original_hp_preparation import _candidate_scoped_context_closure
from fuzzingbrain.analyzer.server import AnalysisServer
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


def _safe(candidate_id="safe-a", assumption="A", location="target.c:7",
          security_property="bounded read"):
    return {
        "assumption_id": candidate_id,
        "safe_assumption": assumption,
        "source_location": location,
        "security_property": security_property,
        "disposition": "VALIDATED_SAFE",
        "required_context": [],
    }


def _unresolved(**changes):
    row = {
        "target": "other_helper",
        "request_type": "FUNCTION",
        "round": 3,
        "status": "SKIPPED_CONTEXT_ROUND_LIMIT",
        "hypothesis_index": 1,
        "attribution_verified": True,
        "related_hypothesis": "other_helper may cause a state transition failure",
        "related_judgment": "POSSIBLE_BUG",
        "related_reason": "other_helper source is required",
        "related_source_location": "target.c:20",
        "related_security_property": "state consistency",
        "related_safe_assumption": "",
    }
    row.update(changes)
    return row


def test_unrelated_attributed_context_does_not_block_validated_safe():
    eligible, blocked = _candidate_scoped_context_closure(
        [_safe()], [_unresolved()], selected_source_file="target.c")
    assert eligible == ["safe-a"]
    assert blocked == {}


def test_same_safe_or_same_source_property_remains_fail_closed():
    eligible, blocked = _candidate_scoped_context_closure(
        [_safe()], [_unresolved(related_safe_assumption="A")],
        selected_source_file="target.c")
    assert eligible == []
    assert "NON_BUG_OR_SAFE_ATTRIBUTION" in blocked["safe-a"][0]

    eligible, blocked = _candidate_scoped_context_closure(
        [_safe()], [_unresolved(
            related_source_location="target.c:7",
            related_security_property="bounded read")],
        selected_source_file="target.c")
    assert eligible == []
    assert "SAME_SOURCE_LOCATION" in blocked["safe-a"][0]


def test_missing_request_attribution_blocks_every_candidate():
    eligible, blocked = _candidate_scoped_context_closure(
        [_safe(), _safe("safe-b", "B", "target.c:9")],
        [_unresolved(attribution_verified=False)],
        selected_source_file="target.c")
    assert eligible == []
    assert set(blocked) == {"safe-a", "safe-b"}
    assert all("UNVERIFIED_ATTRIBUTION" in reasons[0]
               for reasons in blocked.values())


def test_unknown_or_safe_index_binding_blocks_every_candidate():
    for judgment in ("UNKNOWN", "EXPLICIT_SAFE_JUDGMENT"):
        eligible, blocked = _candidate_scoped_context_closure(
            [_safe()], [_unresolved(related_judgment=judgment)],
            selected_source_file="target.c")
        assert eligible == []
        assert any("NON_BUG_OR_SAFE_ATTRIBUTION" in reason
                   for reason in blocked["safe-a"])


def test_target_substring_is_not_an_exact_lexical_binding():
    eligible, blocked = _candidate_scoped_context_closure(
        [_safe()], [_unresolved(
            target="helper",
            related_hypothesis="unrelated_helper may fail",
            related_reason="unrelated_helper source is missing")],
        selected_source_file="target.c")
    assert eligible == []
    assert any("UNVERIFIED_LEXICAL_BINDING" in reason
               for reason in blocked["safe-a"])


def test_location_aliases_and_property_spelling_are_canonicalized():
    eligible, blocked = _candidate_scoped_context_closure(
        [_safe(location="/qualified/src/target.c:7")],
        [_unresolved(
            related_source_location="src/target.c:7",
            related_security_property="BOUNDED-READ")],
        selected_source_file="/qualified/src/target.c")
    assert eligible == []
    assert any("SAME_SOURCE_LOCATION" in reason
               for reason in blocked["safe-a"])


def test_same_location_property_synonym_remains_fail_closed():
    eligible, blocked = _candidate_scoped_context_closure(
        [_safe(location="target.c:7")],
        [_unresolved(
            related_source_location="target.c:7",
            related_security_property="read remains within bounds")],
        selected_source_file="target.c")
    assert eligible == []
    assert any("SAME_SOURCE_LOCATION" in reason
               for reason in blocked["safe-a"])


def test_duplicate_safe_text_at_distinct_locations_is_ineligible():
    eligible, blocked = _candidate_scoped_context_closure(
        [_safe(), _safe("safe-b", "A", "target.c:9")],
        [_unresolved()], selected_source_file="target.c")
    assert eligible == []
    assert set(blocked) == {"safe-a", "safe-b"}
    assert all("AMBIGUOUS_SAFE_TEXT_IDENTITY" in reasons
               for reasons in blocked.values())


def test_exact_macro_source_fallback_is_unique_and_bounded(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "target.c").write_text(
        "#define exact_size(value) (sizeof(value) - 1)\n"
        "int target(void) { return exact_size(\"x\"); }\n",
        encoding="utf-8")
    server = object.__new__(AnalysisServer)
    server.task_path = tmp_path
    assert server._extract_unique_macro_source("exact_size") == (
        "#define exact_size(value) (sizeof(value) - 1)\n")
    assert server._extract_unique_macro_source("target") is None

    (repo / "duplicate.h").write_text(
        "#define exact_size(value) 1\n", encoding="utf-8")
    assert server._extract_unique_macro_source("exact_size") is None


def test_fullscan_connects_bounded_fuzzer_and_direct_caller_sources():
    rows = {
        "caller_a": SimpleNamespace(content="void caller_a(void) {}"),
        "caller_b": SimpleNamespace(content="void caller_b(void) {}"),
        "caller_c": SimpleNamespace(content="void caller_c(void) {}"),
        "caller_d": SimpleNamespace(content="void caller_d(void) {}"),
    }

    class Functions:
        def find_by_name(self, task_id, name):
            assert task_id == "task"
            return rows.get(name)

    fake = SimpleNamespace(
        task_id="task",
        repos=SimpleNamespace(functions=Functions()),
        _get_fuzzer_source_code=lambda: "int LLVMFuzzerTestOneInput(void) {}",
        _get_unique_caller_source=lambda name: str(
            getattr(rows.get(name), "content", "") or ""),
    )
    fuzzer, callers = POVFullscanStrategy._get_initial_sp_source_context(
        fake, ["caller_a", "caller_b", "caller_c", "caller_d"])
    assert fuzzer.startswith("int LLVMFuzzerTestOneInput")
    assert list(callers) == ["caller_a", "caller_b", "caller_c"]


def test_non_cjson_non_md4c_libyaml_fixture_uses_same_generic_boundaries(
        tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "yaml_reader.c").write_text(
        "#define YAML_HAS_BYTE(cursor, end) ((cursor) < (end))\n"
        "int yaml_scan_scalar(const unsigned char *cursor, "
        "const unsigned char *end) {\n"
        "  return YAML_HAS_BYTE(cursor, end) ? *cursor : 0;\n"
        "}\n", encoding="utf-8")
    server = object.__new__(AnalysisServer)
    server.task_path = tmp_path
    macro = server._extract_unique_macro_source("YAML_HAS_BYTE")
    assert macro == (
        "#define YAML_HAS_BYTE(cursor, end) ((cursor) < (end))\n")

    rows = {
        "yaml_parser_parse": SimpleNamespace(
            content="int yaml_parser_parse(void) { return 0; }"),
    }

    class Functions:
        def find_by_name(self, task_id, name):
            assert task_id == "libyaml-task"
            return rows.get(name)

    fake = SimpleNamespace(
        task_id="libyaml-task",
        repos=SimpleNamespace(functions=Functions()),
        _get_fuzzer_source_code=lambda: (
            "int LLVMFuzzerTestOneInput(const unsigned char *data, "
            "unsigned long size) { return size ? data[0] : 0; }"),
        _get_unique_caller_source=lambda name: str(
            getattr(rows.get(name), "content", "") or ""),
    )
    fuzzer, callers = POVFullscanStrategy._get_initial_sp_source_context(
        fake, ["yaml_parser_parse"])
    assert "LLVMFuzzerTestOneInput" in fuzzer
    assert callers == {
        "yaml_parser_parse":
            "int yaml_parser_parse(void) { return 0; }"}


def test_fullscan_uses_exact_selected_fuzzer_api(monkeypatch):
    calls = []

    class Client:
        def __init__(self, socket, client_id):
            assert socket == "/tmp/analyzer.sock"

        def get_fuzzer_source(self, name):
            calls.append(name)
            return {"fuzzer": name, "source": "/* exact harness */"}

        def get_function_source(self, name):
            raise AssertionError("name-only function lookup must not be used")

    monkeypatch.setattr(analyzer_package, "AnalysisClient", Client)
    fake = SimpleNamespace(
        executor=SimpleNamespace(analysis_socket_path="/tmp/analyzer.sock"),
        worker_id="worker", fuzzer="selected_fuzzer",
        log_warning=lambda message: None,
    )
    assert POVFullscanStrategy._get_fuzzer_source_code(fake) == (
        "/* exact harness */")
    assert calls == ["selected_fuzzer"]


def test_caller_preload_rejects_duplicate_static_symbol(tmp_path):
    workspace = tmp_path / "task"
    repo = workspace / "repo"
    (repo / "a").mkdir(parents=True)
    first = "static int helper(int x) { return x + 1; }\n"
    second = (
        "static auto helper(int x) noexcept [[deprecated(\"a;b\")]] -> int "
        "{ return x - 1; }\n")
    (repo / "a" / "one.c").write_text(first, encoding="utf-8")
    row = SimpleNamespace(
        content=first.strip(), file_path="a/one.c")

    class Functions:
        def find_by_name(self, task_id, name):
            return row

    fake = SimpleNamespace(
        task_id="task", executor=SimpleNamespace(
            task_workspace_path=workspace),
        repos=SimpleNamespace(functions=Functions()),
    )
    assert POVFullscanStrategy._get_unique_caller_source(
        fake, "helper") == first.strip()
    (repo / "b").mkdir()
    (repo / "b" / "two.c").write_text(second, encoding="utf-8")
    assert POVFullscanStrategy._get_unique_caller_source(
        fake, "helper") == ""
    (repo / "b" / "two.c").unlink()
    (repo / "b" / "default.ipp").write_text(
        'static int helper(const char *s = "a;b") { return *s; }\n',
        encoding="utf-8")
    assert POVFullscanStrategy._get_unique_caller_source(
        fake, "helper") == ""
    (repo / "b" / "default.ipp").unlink()
    (repo / "b" / "attribute.cpp").write_text(
        'static int helper(int x) [[deprecated("}")]] { return x; }\n',
        encoding="utf-8")
    assert POVFullscanStrategy._get_unique_caller_source(
        fake, "helper") == ""
    (repo / "b" / "attribute.cpp").unlink()
    (repo / "b" / "annotated.hxx").write_text(
        "#define API\nstatic int helper API(int x) { return x - 1; }\n",
        encoding="utf-8")
    assert POVFullscanStrategy._get_unique_caller_source(
        fake, "helper") == ""
    (repo / "b" / "annotated.hxx").unlink()
    (repo / "b" / "spliced.cpp").write_text(
        "static int helper\\\n(int x) { return x - 1; }\n",
        encoding="utf-8")
    assert POVFullscanStrategy._get_unique_caller_source(
        fake, "helper") == ""
    (repo / "b" / "spliced.cpp").unlink()
    outside = tmp_path / "outside-callers"
    outside.mkdir()
    (outside / "two.cpp").write_text(second, encoding="utf-8")
    (repo / "linked-callers").symlink_to(
        outside, target_is_directory=True)
    assert POVFullscanStrategy._get_unique_caller_source(
        fake, "helper") == ""


def test_macro_fallback_rejects_conditional_oversized_and_symlink_ambiguity(
        tmp_path):
    server = object.__new__(AnalysisServer)
    server.task_path = tmp_path
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "conditional.h").write_text(
        "#/**/if defined(ACTIVE)\n#define MAYBE_LIMIT 8\n#endif\n",
        encoding="utf-8")
    assert server._extract_unique_macro_source("MAYBE_LIMIT") is None
    (repo / "spliced.h").write_text(
        "#\\\nif defined(ACTIVE)\n#define SPLICED_LIMIT 8\n#endif\n",
        encoding="utf-8")
    assert server._extract_unique_macro_source("SPLICED_LIMIT") is None
    (repo / "comment_spliced.h").write_text(
        "#/* split\n*/if defined(ACTIVE)\n"
        "#define COMMENT_SPLIT_LIMIT 8\n#endif\n",
        encoding="utf-8")
    assert server._extract_unique_macro_source("COMMENT_SPLIT_LIMIT") is None
    (repo / "digraph.h").write_text(
        "%:if defined(ACTIVE)\n#define DIGRAPH_LIMIT 8\n%:endif\n",
        encoding="utf-8")
    assert server._extract_unique_macro_source("DIGRAPH_LIMIT") is None
    (repo / "trigraph.h").write_text(
        "??=if defined(ACTIVE)\n#define TRIGRAPH_LIMIT 8\n??=endif\n",
        encoding="utf-8")
    assert server._extract_unique_macro_source("TRIGRAPH_LIMIT") is None

    (repo / "unconditional.h").write_text(
        "#define EXACT_LIMIT 8\n", encoding="utf-8")
    duplicate_inc = repo / "duplicate.inc"
    duplicate_inc.write_text("#define EXACT_LIMIT 4\n", encoding="utf-8")
    assert server._extract_unique_macro_source("EXACT_LIMIT") is None
    duplicate_inc.unlink()
    oversized = repo / "oversized.c"
    oversized.write_bytes(b" " * 2_000_001)
    assert server._extract_unique_macro_source("EXACT_LIMIT") is None
    oversized.unlink()

    outside = tmp_path / "outside.h"
    outside.write_text("#define OTHER_LIMIT 4\n", encoding="utf-8")
    (repo / "linked.h").symlink_to(outside)
    assert server._extract_unique_macro_source("EXACT_LIMIT") is None
    (repo / "linked.h").unlink()
    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir()
    (outside_dir / "duplicate.h").write_text(
        "#define EXACT_LIMIT 2\n", encoding="utf-8")
    (repo / "linked-dir").symlink_to(outside_dir, target_is_directory=True)
    assert server._extract_unique_macro_source("EXACT_LIMIT") is None


def test_macro_fallback_rejects_spliced_directive_keyword(tmp_path):
    server = object.__new__(AnalysisServer)
    server.task_path = tmp_path
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "spliced-keyword.h").write_text(
        "#i\\\nf ACTIVE\n#define SPLIT_KEYWORD_LIMIT 8\n"
        "#en\\\ndif\n",
        encoding="utf-8")
    assert server._extract_unique_macro_source(
        "SPLIT_KEYWORD_LIMIT") is None


def test_macro_fallback_handles_alternate_directives_and_headers(tmp_path):
    server = object.__new__(AnalysisServer)
    server.task_path = tmp_path
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "primary.h").write_text("#define ALT_LIMIT 8\n", encoding="utf-8")
    (repo / "duplicate.hxx").write_text(
        "%:define ALT_LIMIT 4\n", encoding="utf-8")
    assert server._extract_unique_macro_source("ALT_LIMIT") is None

    (repo / "primary.h").unlink()
    (repo / "duplicate.hxx").write_text(
        "%\\\n:if ACTIVE\n#define ALT_LIMIT 4\n%\\\n:endif\n",
        encoding="utf-8")
    assert server._extract_unique_macro_source("ALT_LIMIT") is None

