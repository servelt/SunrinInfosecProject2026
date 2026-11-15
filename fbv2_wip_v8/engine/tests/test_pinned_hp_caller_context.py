"""A signed HP control can resolve a real caller from the issued V2 graph."""

import hashlib
import json
import shutil
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from devtools.original_hp_preparation import (
    _bounded_context, _context_pins_ok, _pinned_static_call_path,
    _qualified_context_process_envelope,
)
from vulnerabilityanalysis.context import ContextResolver
from vulnerabilityanalysis.models import ContextRequest
from vulnerabilityanalysis.runtime import ProcessEnvelopeStop, _guarded_run


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hp_context_account(tmp_path):
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "hp-context-process.json", wall_total_seconds=1800,
        fuzz_total_seconds=90)
    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id="hp-context-test", run_id="one"),
        process_ledger=ledger)
    physical = {"total_wall_seconds": 120, "output_limit_bytes": 4_000_000}
    return bound, physical


def test_context_process_window_excludes_model_wait_without_resetting_lease(
        tmp_path):
    bound, physical = _hp_context_account(tmp_path)
    with (patch("devtools.original_hp_preparation._qualified_context_build_command",
                return_value=(["cc", "{source}"], {}, {})),
          patch("devtools.original_hp_preparation._prepared_pins_ok",
                return_value=True)):
        envelope = _qualified_context_process_envelope(
            bound, SimpleNamespace(), object(), physical, lambda: None)
        command = [sys.executable, "-I", "-c", "print('context')"]
        for segment in ("hp_context.active_lines",
                        "hp_context.macro_definitions"):
            # The previous model turn may be longer than the context window.
            envelope.deadline_monotonic = time.monotonic() - 150
            result = _guarded_run(
                command, timeout=1, process_envelope=envelope,
                process_kind="AUX_PROCESS", process_segment=segment)
            assert result.stdout.strip() == "context"
        receipt, _ = bound.process_ledger.receipt_snapshot()
        assert receipt["stop_status"] is None
        assert len(receipt["finished"]) == 2
        assert [row["key"].split(":")[-2] for row in
                receipt["finished"]] == ["000000", "000001"]
        with pytest.raises(RuntimeError, match="cannot be resumed"):
            _qualified_context_process_envelope(
                bound, SimpleNamespace(), object(), physical, lambda: None)


def test_context_process_window_still_enforces_cumulative_physical_cap(
        tmp_path):
    bound, physical = _hp_context_account(tmp_path)
    with (patch("devtools.original_hp_preparation._qualified_context_build_command",
                return_value=(["cc", "{source}"], {}, {})),
          patch("devtools.original_hp_preparation._prepared_pins_ok",
                return_value=True)):
        envelope = _qualified_context_process_envelope(
            bound, SimpleNamespace(), object(), physical, lambda: None)
        for _ in range(7):
            lease = envelope.before_process(
                ["cc"], cwd=None, env=None, timeout=15,
                kind="AUX_PROCESS", segment="hp_context.active_lines")
            envelope.after_process(
                lease, elapsed_seconds=15, cleanup_complete=True,
                output_limited=False, error=None)
        with pytest.raises(ProcessEnvelopeStop) as stopped:
            envelope.before_process(
                ["cc"], cwd=None, env=None, timeout=15,
                kind="AUX_PROCESS", segment="hp_context.active_lines")
        assert stopped.value.status == "STOPPED_WALL_LIMIT"
        receipt, _ = bound.process_ledger.receipt_snapshot()
        assert receipt["stop_status"] == "STOPPED_WALL_LIMIT"
        assert receipt["active"] == {}
        assert len(receipt["finished"]) == 7


def test_context_process_window_rejects_active_attempt_and_global_exhaustion(
        tmp_path):
    bound, physical = _hp_context_account(tmp_path)
    with (patch("devtools.original_hp_preparation._qualified_context_build_command",
                return_value=(["cc", "{source}"], {}, {})),
          patch("devtools.original_hp_preparation._prepared_pins_ok",
                return_value=True)):
        envelope = _qualified_context_process_envelope(
            bound, SimpleNamespace(), object(), physical, lambda: None)
        envelope.before_process(
            ["cc"], cwd=None, env=None, timeout=1,
            kind="AUX_PROCESS", segment="hp_context.active_lines")
        with pytest.raises(RuntimeError, match="unsettled"):
            envelope.before_process(
                ["cc"], cwd=None, env=None, timeout=1,
                kind="AUX_PROCESS", segment="hp_context.active_lines")
        receipt, _ = bound.process_ledger.receipt_snapshot()
        assert len(receipt["active"]) == 1
        assert receipt["finished"] == []

    small = PersistentProcessLedgerV2.create(
        tmp_path / "small-process.json", wall_total_seconds=20,
        fuzz_total_seconds=0)
    bound.process_ledger = small
    bound.identity.run_id = "other"
    with (patch("devtools.original_hp_preparation._qualified_context_build_command",
                return_value=(["cc", "{source}"], {}, {})),
          patch("devtools.original_hp_preparation._prepared_pins_ok",
                return_value=True)):
        envelope = _qualified_context_process_envelope(
            bound, SimpleNamespace(), object(), physical, lambda: None)
        with pytest.raises(ProcessEnvelopeStop) as stopped:
            envelope.before_process(
                ["cc"], cwd=None, env=None, timeout=15,
                kind="AUX_PROCESS", segment="hp_context.active_lines")
        assert stopped.value.status == "PENDING_PHYSICAL_BUDGET"
        receipt, _ = small.receipt_snapshot()
        assert receipt["active"] == {}
        assert receipt["finished"] == []


def _case(tmp_path, *, prefix="", selected=None, caller=None,
          edge_token="parse_input("):
    root = tmp_path / "source"
    root.mkdir()
    path = root / "parser.c"
    selected = selected or "int parse_input(const char *p) {\n    return *p;\n}"
    caller = caller or "int caller(const char *p) {\n    return parse_input(p);\n}"
    path.write_text(prefix + selected + "\n" + caller + "\n")
    selected_start = prefix.count("\n") + 1
    caller_start = selected_start + selected.count("\n") + 1
    selected_id = "fn-" + "a" * 20
    caller_id = "fn-" + "b" * 20
    functions = tmp_path / "functions.jsonl"
    functions.write_text("\n".join(json.dumps(row) for row in (
        {"function_id": selected_id, "name": "parse_input", "file": "parser.c",
         "start_line": selected_start,
         "end_line": selected_start + selected.count("\n"), "source": selected},
        {"function_id": caller_id, "name": "caller", "file": "parser.c",
         "start_line": caller_start,
         "end_line": caller_start + caller.count("\n"), "source": caller},
    )) + "\n")
    edges = tmp_path / "edges.jsonl"
    call_offset = next(i for i, line in enumerate(caller.splitlines())
                       if edge_token in line)
    edges.write_text(json.dumps({"edge_id": "direct-1", "line": caller_start + call_offset,
                                 "caller_id": caller_id,
                                 "callee_id": selected_id,
                                 "kind": "DIRECT_AST_ID"}) + "\n")
    harness = root / "harness.c"
    harness.write_text("int test(void) { return caller(\"x\"); }\n")
    binary_sha = "2" * 64
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "catalog": {
            "functions": {"path": str(functions), "sha256": _sha(functions)},
            "edges": {"path": str(edges), "sha256": _sha(edges)},
        },
        "source_files": {"parser.c": _sha(path)},
        "asan_binary": {"sha256": binary_sha},
        "entry_function": "caller",
    }))
    work = SimpleNamespace(
        function_id="1" * 24, function_name="parse_input",
        source_file=str(path), source=selected,
        source_start_line=selected_start,
        source_end_line=selected_start + selected.count("\n"),
        source_file_sha256=_sha(path), binary_sha256=binary_sha,
        harness_path=str(harness), harness_sha256=_sha(harness))
    qualification = SimpleNamespace(source_root=root)
    request = ContextRequest(work.function_id, "parse_input", "CALLER",
                             "check caller", "argument construction")
    return work, qualification, request, manifest, edges


def test_pinned_graph_resolves_exact_caller_and_rechecks_pins(tmp_path):
    work, qualification, request, manifest, edges = _case(tmp_path)
    context, records, pins = _bounded_context(
        work, [request], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest))
    assert records[0]["status"] == "FETCHED"
    assert len(context) == 1
    assert context[0]["function_name"] == "caller"
    assert context[0]["relation"] == "CALLER_OF"
    assert "parse_input(p)" in context[0]["source"]
    assert _context_pins_ok(pins)
    edges.write_text(edges.read_text() + "\n")
    assert not _context_pins_ok(pins)


def test_named_function_request_uses_unique_pinned_catalog_id(tmp_path):
    work, qualification, _, manifest, _ = _case(tmp_path)
    request = ContextRequest(work.function_id, "caller", "FUNCTION",
                             "inspect caller", "argument construction")
    context, records, pins = _bounded_context(
        work, [request], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest))
    assert records[0]["status"] == "FETCHED"
    assert len(context) == 1
    assert context[0]["function_name"] == "caller"
    assert "parse_input(p)" in context[0]["source"]
    assert _context_pins_ok(pins)


def test_nohint_pinned_context_fetches_complete_long_function(tmp_path):
    caller = ("int caller(const char *p) {\n    int n = 0;\n"
              + "    n += 1;\n" * 1200
              + "    return parse_input(p) + n;\n}")
    assert 8_000 < len(caller) < 20_000
    work, qualification, _, manifest, _ = _case(tmp_path, caller=caller)
    request = ContextRequest(work.function_id, "caller", "FUNCTION",
                             "inspect input flow", "complete caller source")
    ordinary, ordinary_records, _ = _bounded_context(
        work, [request], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest))
    assert ordinary == []
    assert ordinary_records[0]["status"] == "UNSUPPORTED_COMPOSITE_CONTEXT"

    complete, records, pins = _bounded_context(
        work, [request], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert records[0]["status"] == "FETCHED"
    assert [row["source"] for row in complete] == [caller]
    assert _context_pins_ok(pins)


@pytest.mark.skipif(shutil.which("cc") is None, reason="C preprocessor required")
def test_pinned_hp_type_context_uses_active_conditional_header(tmp_path):
    work, qualification, _, manifest, _ = _case(
        tmp_path, prefix='#ifdef FEATURE\n#include "types.h"\n#endif\n',
        selected="int parse_input(MD_SIZE n) {\n    return n;\n}")
    header = qualification.source_root / "types.h"
    header.write_text("typedef unsigned MD_SIZE;\n")
    request = ContextRequest(work.function_id, "MD_SIZE", "TYPE",
                             "inspect size type", "active declaration")
    command = [shutil.which("cc"), "-DFEATURE", "{source}"]
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "process.json", wall_total_seconds=60,
        fuzz_total_seconds=0)
    envelope = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id="hp-context-test", assertion_id="hp_context",
        attempt_id="one", output_limit_bytes=4_000_000,
        total_wall_seconds=30, pin_hook=lambda _phase, _command: None)
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    from vulnerabilityanalysis import context as context_module
    original_run = context_module._guarded_run
    with patch.object(context_module, "_guarded_run", wraps=original_run) as run:
        context, records, pins = _bounded_context(
            work, [request], qualification,
            context_build_command=command,
            context_build_environment=environment,
            context_process_envelope=envelope,
            context_source_hashes={"types.h": _sha(header),
                                   "parser.c": _sha(Path(work.source_file))},
            catalog_manifest_path=manifest,
            catalog_manifest_sha256=_sha(manifest),
            enforce_manifest_source_pins=True)
    assert records[0]["status"] == "FETCHED"
    assert [row["source"] for row in context] == ["typedef unsigned MD_SIZE;"]
    assert _context_pins_ok(pins)
    assert run.call_args.kwargs["env"] == environment
    assert run.call_args.kwargs["process_envelope"] is envelope
    finished = ledger.snapshot()["finished"]
    assert len(finished) == 1
    assert finished[0]["kind"] == "AUX_PROCESS"
    assert finished[0]["physical_seconds"] >= 0
    assert ledger.snapshot()["active"] == {}
    without_flags, missing, _ = _bounded_context(
        work, [request], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest))
    assert without_flags == []
    assert missing[0]["status"] == "NOT_FOUND"
    with pytest.raises(ValueError, match="pin tables disagree"):
        _bounded_context(
            work, [request], qualification,
            context_build_command=command,
            context_source_hashes={"parser.c": "0" * 64},
            catalog_manifest_path=manifest,
            catalog_manifest_sha256=_sha(manifest),
            enforce_manifest_source_pins=True)


def test_pinned_hp_type_context_accepts_only_active_compound_fields(tmp_path):
    prefix = ('typedef struct tag_t alias_t;\n'
              'struct tag_t {\n#ifdef WIDE\nint wide[128];\n'
              '#else\nint narrow[8];\n#endif\n};\n')
    selected = ('int parse_input(alias_t *ctx) {\n'
                '    return ctx->wide[0];\n}')
    work, qualification, _, manifest, _ = _case(
        tmp_path, prefix=prefix, selected=selected)
    request = ContextRequest(work.function_id, 'alias_t', 'TYPE',
                             'inspect member extent', 'active complete body')
    context, records, pins = _bounded_context(
        work, [request], qualification,
        context_build_command=[shutil.which('cc'), '-DWIDE', '{source}'],
        context_source_hashes={'parser.c': _sha(Path(work.source_file))},
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert records[0]['status'] == 'FETCHED'
    assert len(context) == 2
    assert 'int wide[128];' in context[1]['source']
    assert 'int narrow[8];' not in context[1]['source']
    assert 'source_span_start' not in context[1]
    assert 'source_span_end' not in context[1]
    assert _context_pins_ok(pins)

    original_resolve = ContextResolver.resolve

    def shifted_span(resolver, requested):
        rows = original_resolve(resolver, requested)
        for row in rows:
            if 'source_span_end' in row:
                row['source_span_end'] = str(int(row['source_span_end']) - 1)
        return rows

    with patch.object(ContextResolver, 'resolve', shifted_span):
        rejected, _, _ = _bounded_context(
            work, [request], qualification,
            context_build_command=[shutil.which('cc'), '-DWIDE', '{source}'],
            context_source_hashes={'parser.c': _sha(Path(work.source_file))},
            catalog_manifest_path=manifest,
            catalog_manifest_sha256=_sha(manifest),
            enforce_manifest_source_pins=True)
    assert len(rejected) == 1
    assert 'int wide[128];' not in rejected[0]['source']


def test_type_request_can_show_referenced_pinned_object_macro_alias(tmp_path):
    work, qualification, _, manifest, _ = _case(
        tmp_path, prefix="#define SZ MD_SIZE\n#define OFF MD_OFFSET\n",
        selected="int parse_input(SZ n) {\n    OFF i = n;\n    return i;\n}")
    requests = [ContextRequest(work.function_id, target, "TYPE", "check alias",
                               "type declaration") for target in ("SZ", "OFF")]
    context, records, pins = _bounded_context(
        work, requests, qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert [row["status"] for row in records] == ["FETCHED", "FETCHED"]
    assert [row["source"] for row in context] == [
        "#define SZ MD_SIZE", "#define OFF MD_OFFSET"]
    assert all(row["request_type"] == "MACRO" and
               row["original_request_type"] == "TYPE" and
               row["type_layout_proven"] == "false" for row in context)
    assert all(row["provided_request_type"] == "MACRO" and
               row["evidence_kind"] == "OBJECT_MACRO_ALIAS_ONLY" and
               row["type_layout_proven"] is False for row in records)
    assert _context_pins_ok(pins)


@pytest.mark.parametrize("prefix, selected", [
    ("#define SZ MD_SIZE\n", "int parse_input(int n) {\n    return n;\n}"),
    ("#define SZ MD_SIZE\n#define SZ MD_SIZE\n",
     "int parse_input(SZ n) {\n    return n;\n}"),
    ("#if FEATURE\n#define SZ MD_SIZE\n#endif\n",
     "int parse_input(SZ n) {\n    return n;\n}"),
    ("#define SZ(n) n\n",
     "int parse_input(int n) {\n    return SZ(n);\n}"),
])
def test_type_macro_fallback_rejects_unproven_alias(
        tmp_path, prefix, selected):
    work, qualification, _, manifest, _ = _case(
        tmp_path, prefix=prefix, selected=selected)
    request = ContextRequest(work.function_id, "SZ", "TYPE", "check alias",
                             "type declaration")
    context, records, _ = _bounded_context(
        work, [request], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert context == []
    assert records[0]["status"] == "NOT_FOUND"


def test_type_macro_alias_repeated_request_is_not_fetched_twice(tmp_path):
    work, qualification, _, manifest, _ = _case(
        tmp_path, prefix="#define SZ MD_SIZE\n",
        selected="int parse_input(SZ n) {\n    return n;\n}")
    request = ContextRequest(work.function_id, "SZ", "TYPE", "check alias",
                             "type declaration")
    context, records, _ = _bounded_context(
        work, [request, request], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert len(context) == 1
    assert [row["status"] for row in records] == ["FETCHED", "ALREADY_REQUESTED"]
    explicit = ContextRequest(work.function_id, "SZ", "MACRO", "check alias",
                              "macro definition")
    seen = set()
    first, _, _ = _bounded_context(
        work, [request], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest), seen_requests=seen)
    second, later, _ = _bounded_context(
        work, [explicit], qualification,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest), seen_requests=seen, round_index=1)
    assert len(first) == 1 and second == []
    assert later[0]["status"] == "ALREADY_REQUESTED"


def _caller_macro_case(tmp_path, *, prefix="#define STR(x) (x)\n", caller=None):
    caller = caller or (
        "int caller(const char *p) {\n"
        "    return parse_input(STR(p));\n}"
    )
    work, qualification, _, manifest, edges = _case(
        tmp_path, prefix=prefix, caller=caller)
    context, records, _ = _bounded_context(
        work, [ContextRequest(work.function_id, "parse_input", "CALLER",
                              "check caller", "argument construction")],
        qualification, catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert records[0]["status"] == "FETCHED"
    assert len(context) == 1
    request = ContextRequest(work.function_id, "STR", "MACRO", "check macro",
                             "definition")
    return work, qualification, manifest, edges, context, request


def test_pinned_direct_caller_macro_uses_only_prior_verified_context(tmp_path):
    work, qualification, manifest, _, prior, request = _caller_macro_case(tmp_path)
    kwargs = {"catalog_manifest_path": manifest,
              "catalog_manifest_sha256": _sha(manifest),
              "enforce_manifest_source_pins": True}
    empty, missing, _ = _bounded_context(work, [request], qualification, **kwargs)
    assert empty == [] and missing[0]["status"] == "NOT_FOUND"
    context, records, pins = _bounded_context(
        work, [request], qualification, prior_context=prior, **kwargs)
    assert records[0]["status"] == "FETCHED"
    assert records[0]["evidence_kind"] == "PINNED_DIRECT_CALLER_MACRO_ONLY"
    assert len(context) == 1
    assert context[0]["source"] == "#define STR(x) (x)"
    assert context[0]["related_analyzed_function"] != context[0]["related_function"]
    assert context[0]["build_activation"] == "UNPROVEN"
    assert context[0]["runtime_reachability"] == "UNPROVEN_FOR_ANY_INPUT"
    assert _context_pins_ok(pins)


def test_pinned_compiler_macro_callsite_resolves_real_caller_macro(tmp_path):
    work, qualification, _, manifest, edges = _case(
        tmp_path, prefix="#define WRAP(p) parse_input(p)\n",
        caller="int caller(const char *p) {\n    return WRAP(p);\n}",
        edge_token="WRAP(")
    prior, prior_records, _ = _bounded_context(
        work, [ContextRequest(work.function_id, "parse_input", "CALLER",
                              "inspect caller", "input flow")],
        qualification, catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert prior_records[0]["status"] == "FETCHED"
    assert prior[0]["callsite_location"] == "UNKNOWN"
    request = ContextRequest(work.function_id, "WRAP", "MACRO",
                             "inspect macro", "definition")
    kwargs = {"catalog_manifest_path": manifest,
              "catalog_manifest_sha256": _sha(manifest),
              "enforce_manifest_source_pins": True,
              "prior_context": prior}
    context, records, pins = _bounded_context(
        work, [request], qualification, **kwargs)
    assert records[0]["status"] == "FETCHED"
    assert records[0]["evidence_kind"] == "PINNED_DIRECT_CALLER_MACRO_ONLY"
    assert context[0]["relation_evidence"] == "PINNED_COMPILER_EDGE_AND_MACRO_BODY"
    assert context[0]["source"] == "#define WRAP(p) parse_input(p)"
    assert context[0]["caller_callsite_location"].endswith("parser.c:6")
    assert _context_pins_ok(pins)

    edge = json.loads(edges.read_text())
    edge["line"] += 1
    edges.write_text(json.dumps(edge) + "\n")
    body = json.loads(manifest.read_text())
    body["catalog"]["edges"]["sha256"] = _sha(edges)
    manifest.write_text(json.dumps(body))
    rejected, rejected_records, _ = _bounded_context(
        work, [request], qualification, **{**kwargs,
              "catalog_manifest_sha256": _sha(manifest)})
    assert rejected == [] and rejected_records[0]["status"] == "NOT_FOUND"


def test_pinned_compiler_macro_edge_rejects_unrelated_macro_body(tmp_path):
    work, qualification, _, manifest, _ = _case(
        tmp_path, prefix="#define WRAP(p) helper(p)\n",
        caller="int caller(const char *p) {\n    return WRAP(p);\n}",
        edge_token="WRAP(")
    prior, _, _ = _bounded_context(
        work, [ContextRequest(work.function_id, "parse_input", "CALLER",
                              "inspect caller", "input flow")],
        qualification, catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert prior[0]["callsite_location"] == "UNKNOWN"
    context, records, _ = _bounded_context(
        work, [ContextRequest(work.function_id, "WRAP", "MACRO",
                              "inspect macro", "definition")],
        qualification, prior_context=prior,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert context == [] and records[0]["status"] == "NOT_FOUND"


@pytest.mark.parametrize("tamper", [
    "source", "function_id", "callsite_location", "call_type"])
def test_pinned_caller_macro_rejects_forged_prior_row(tmp_path, tamper):
    work, qualification, manifest, _, prior, request = _caller_macro_case(tmp_path)
    forged = [dict(prior[0])]
    forged[0][tamper] = ("SOURCE_DIRECT_COMPILED" if tamper == "call_type"
                         else "forged")
    context, records, _ = _bounded_context(
        work, [request], qualification, prior_context=forged,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert context == [] and records[0]["status"] == "NOT_FOUND"


def test_pinned_caller_macro_rejects_false_edge_line_with_fresh_pin(tmp_path):
    work, qualification, manifest, edges, prior, request = _caller_macro_case(tmp_path)
    edge = json.loads(edges.read_text())
    edge["line"] += 1
    edges.write_text(json.dumps(edge) + "\n")
    body = json.loads(manifest.read_text())
    body["catalog"]["edges"]["sha256"] = _sha(edges)
    manifest.write_text(json.dumps(body))
    context, records, _ = _bounded_context(
        work, [request], qualification, prior_context=prior,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert context == [] and records[0]["status"] == "NOT_FOUND"


def test_pinned_caller_macro_rejects_first_inactive_macro_call(tmp_path):
    caller = ("int caller(const char *p) {\n"
              "#if 0\n    STR(p);\n#endif\n"
              "    return parse_input(STR(p));\n}")
    work, qualification, manifest, _, prior, request = _caller_macro_case(
        tmp_path, caller=caller)
    context, records, _ = _bounded_context(
        work, [request], qualification, prior_context=prior,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert context == [] and records[0]["status"] == "NOT_FOUND"


def test_pinned_caller_macro_rejects_ambiguous_definitions(tmp_path):
    work, qualification, manifest, _, prior, request = _caller_macro_case(
        tmp_path, prefix="#define STR(x) (x)\n#define STR(x) ((x)+1)\n")
    context, records, _ = _bounded_context(
        work, [request], qualification, prior_context=prior,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert context == [] and records[0]["status"] == "NOT_FOUND"


def test_pinned_caller_macro_rejects_changed_source_and_manifest(tmp_path):
    work, qualification, manifest, _, prior, request = _caller_macro_case(tmp_path)
    Path(work.source_file).write_text(Path(work.source_file).read_text() + "\n")
    context, records, _ = _bounded_context(
        work, [request], qualification, prior_context=prior,
        catalog_manifest_path=manifest,
        catalog_manifest_sha256=_sha(manifest),
        enforce_manifest_source_pins=True)
    assert context == [] and records[0]["status"] == "NOT_FOUND"
    manifest.write_text(manifest.read_text() + "\n")
    with pytest.raises(ValueError, match="manifest changed"):
        _bounded_context(work, [request], qualification, prior_context=prior,
                         catalog_manifest_path=manifest,
                         catalog_manifest_sha256="0" * 64,
                         enforce_manifest_source_pins=True)


def test_changed_graph_or_manifest_rejected_before_context_use(tmp_path):
    work, qualification, request, manifest, edges = _case(tmp_path)
    digest = _sha(manifest)
    edges.write_text(edges.read_text() + "\n")
    with pytest.raises(ValueError, match="artifact changed"):
        _bounded_context(work, [request], qualification,
                         catalog_manifest_path=manifest,
                         catalog_manifest_sha256=digest)
    manifest.write_text(manifest.read_text() + "\n")
    with pytest.raises(ValueError, match="manifest changed"):
        _bounded_context(work, [request], qualification,
                         catalog_manifest_path=manifest,
                         catalog_manifest_sha256=digest)


def test_pinned_static_path_has_exact_callsite_and_no_runtime_claim(tmp_path):
    work, qualification, _, manifest, _ = _case(tmp_path)
    path, pins = _pinned_static_call_path(
        work, qualification, manifest, _sha(manifest))
    assert path["evidence_level"] == "PINNED_STATIC_DIRECT_CALL_PATH_ONLY"
    assert path["runtime_reachability"] == "UNPROVEN_FOR_ANY_INPUT"
    assert path["edges"] == [{
        "caller": "caller", "callee": "parse_input",
        "callsite": "parser.c:5", "edge_id": "direct-1",
        "edge_kind": "DIRECT_AST_ID",
        "source_file_sha256": work.source_file_sha256,
    }]
    assert _context_pins_ok(pins)
    Path(work.source_file).write_text(Path(work.source_file).read_text() + "\n")
    assert not _context_pins_ok(pins)


def test_pinned_harness_entry_needs_no_graph_edge(tmp_path):
    work, qualification, _, manifest, _ = _case(tmp_path)
    harness = Path(work.harness_path)
    harness.write_text('int test(void) { return parse_input("x"); }\n')
    work.harness_sha256 = _sha(harness)
    body = json.loads(manifest.read_text())
    body["entry_function"] = "parse_input"
    manifest.write_text(json.dumps(body))
    path, pins = _pinned_static_call_path(
        work, qualification, manifest, _sha(manifest))
    assert path["evidence_level"] == "PINNED_HARNESS_ENTRY_ONLY"
    assert path["runtime_reachability"] == "UNPROVEN_FOR_ANY_INPUT"
    assert path["edges"] == []
    assert _context_pins_ok(pins)
    harness.write_text('/* parse_input("x") */\nint test(void) { return 0; }\n')
    work.harness_sha256 = _sha(harness)
    with pytest.raises(ValueError, match="not in the pinned harness"):
        _pinned_static_call_path(work, qualification, manifest, _sha(manifest))


def test_pinned_static_path_accepts_plural_direct_harness_entry(tmp_path):
    work, qualification, _, manifest, _ = _case(tmp_path)
    harness = Path(work.harness_path)
    harness.write_text(
        'int test(void) { return caller("x") + parse_input("x"); }\n')
    work.harness_sha256 = _sha(harness)
    body = json.loads(manifest.read_text())
    body["entry_function"] = "caller"
    body["entry_functions"] = ["caller", "parse_input"]
    manifest.write_text(json.dumps(body))

    path, pins = _pinned_static_call_path(
        work, qualification, manifest, _sha(manifest))

    assert path["evidence_level"] == "PINNED_HARNESS_ENTRY_ONLY"
    assert path["entry_function"] == "parse_input"
    assert path["target_function"] == "parse_input"
    assert path["edges"] == []
    assert _context_pins_ok(pins)


def test_pinned_static_path_rejects_invalid_callsite_even_with_fresh_hashes(
        tmp_path):
    work, qualification, _, manifest, edges = _case(tmp_path)
    row = json.loads(edges.read_text())
    row["line"] = 4  # The declaration line has no direct call.
    edges.write_text(json.dumps(row) + "\n")
    body = json.loads(manifest.read_text())
    body["catalog"]["edges"]["sha256"] = _sha(edges)
    manifest.write_text(json.dumps(body))
    with pytest.raises(ValueError, match="callsite is absent"):
        _pinned_static_call_path(work, qualification, manifest, _sha(manifest))
