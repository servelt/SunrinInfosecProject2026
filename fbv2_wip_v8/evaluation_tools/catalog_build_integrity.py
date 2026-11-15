"""Fail-closed, role-specific Catalog/build provenance preflight.

This checks a *pinned evaluator build receipt*, not an arbitrary source index.
The receipt must be captured independently of the Catalog while compiling and
linking each sanitizer binary. A matching receipt is an attestation: this
module cannot prove that a compiler or linker produced its claims. In
particular, an archive's ``nm`` symbols or an object-to-source map alone are
not adequate evidence of active source branches or final binary linkage.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import argparse
import json
import re
import subprocess


SCHEMA = "EVALUATOR_CATALOG_BUILD_RECEIPT_V1"
SCHEMA_V2 = "EVALUATOR_CATALOG_BUILD_RECEIPT_V2"
ROLES = ("asan", "coverage")
_SECTION = re.compile(r"^\s*\[\s*\d+\]\s+\S+\s+\S+\s+([0-9a-fA-F]+)\s+"
                      r"[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([A-Z]+)\b")


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()
            if line.strip()]


def _path(root: Path, raw: object) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValueError("missing evidence path")
    candidate = (root / raw).resolve(strict=True)
    if not candidate.is_relative_to(root):
        raise ValueError("evidence path outside evaluator root")
    return candidate


def _file_pin(root: Path, item: object, label: str, failures: list[str]) -> None:
    if not isinstance(item, dict) or not isinstance(item.get("sha256"), str):
        failures.append(f"{label}: MISSING_FILE_PIN")
        return
    try:
        file = _path(root, item.get("path"))
        if _sha(file) != item["sha256"]:
            failures.append(f"{label}: FILE_HASH_MISMATCH")
    except (OSError, ValueError):
        failures.append(f"{label}: FILE_UNAVAILABLE")


def _source_span_matches(path: Path, row: dict) -> bool:
    source = row.get("source")
    start = row.get("start_line")
    end = row.get("end_line")
    if (not isinstance(source, str) or not source or
            not isinstance(start, int) or not isinstance(end, int) or
            start < 1 or end < start):
        return False
    raw = path.read_text()
    offset = raw.find(source)
    while offset >= 0:
        first_line = raw.count("\n", 0, offset) + 1
        last_line = raw.count("\n", 0, offset + len(source)) + 1
        if first_line == start and last_line == end:
            return True
        offset = raw.find(source, offset + 1)
    return False


def _expected_ast_argv(argv: list[str]) -> list[str]:
    """Keep every preprocessing flag from the observed object compilation."""
    output = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in {"-MT", "-MF", "-o"}:
            if index + 1 >= len(argv):
                raise ValueError("truncated output option")
            index += 2
            continue
        if token in {"-MD", "-c"}:
            index += 1
            continue
        output.append(token)
        index += 1
    return [*output, "-fsyntax-only", "-Xclang", "-ast-dump=json"]


def _check_build_record(root: Path, source_root: Path, role: str,
                        evidence: dict, failures: list[str], *, schema: str) -> None:
    """Require compile/object/AST/link pins, not just an object name map."""
    try:
        item = evidence["build_record"]
        record = json.loads(_path(root, item["path"]).read_text())
        binary_sha = evidence["binary"]["sha256"]
        if (record.get("schema") != "EVALUATOR_BUILD_CAPTURE_V1" or
                record.get("role") != role or
                record.get("final_binary_sha256") != binary_sha):
            raise ValueError("build record does not bind this role and binary")
        units = record.get("compilation_units")
        link = record.get("link")
        if not isinstance(units, list) or not units or not isinstance(link, dict):
            raise ValueError("compile or link record absent")
        if not isinstance(link.get("argv"), list) or not link["argv"]:
            raise ValueError("link command absent")
        _file_pin(root, link.get("map"), f"{role} linker map", failures)
        objects: set[str] = set()
        active_definitions: list[dict] = []
        active_edges: list[dict] = []
        captures = None
        if schema == SCHEMA_V2:
            capture_pin = evidence.get("ast_capture_commands")
            if record.get("ast_capture_commands") != capture_pin:
                raise ValueError("AST capture pin differs from build record")
            _file_pin(root, capture_pin, f"{role} AST capture commands", failures)
            captures = json.loads(_path(root, capture_pin["path"]).read_text())
            if not isinstance(captures, list) or len(captures) != len(units):
                raise ValueError("AST capture list incomplete")
            if any(not isinstance(item, dict) for item in captures):
                raise ValueError("malformed AST capture")
            captures = {item.get("source"): item for item in captures}
            if len(captures) != len(units):
                raise ValueError("duplicate AST capture source")
        for unit in units:
            if (not isinstance(unit, dict) or
                    not isinstance(unit.get("argv"), list) or not unit["argv"]):
                raise ValueError("compile command absent")
            source_file = _path(source_root, unit.get("source_file"))
            if _sha(source_file) != unit.get("source_sha256"):
                raise ValueError("compile source digest mismatch")
            if schema == SCHEMA_V2:
                compiled_source = _path(root, unit.get("compiled_role_source_file"))
                expected_source = _path(root, f"upstream_{role}_final/{unit['source_file']}")
                if (compiled_source != expected_source or
                        _sha(compiled_source) != unit.get("compiled_role_source_sha256") or
                        _sha(compiled_source) != _sha(source_file) or
                        unit["argv"].count(str(compiled_source)) != 1):
                    raise ValueError("role source is not the pinned compiled source")
            _file_pin(root, unit.get("object"), f"{role} object", failures)
            _file_pin(root, unit.get("active_ast"), f"{role} active AST", failures)
            active = json.loads(_path(root, unit["active_ast"]["path"]).read_text())
            if (not isinstance(active.get("definitions"), list) or
                    not isinstance(active.get("edges"), list)):
                raise ValueError("active AST evidence incomplete")
            if schema == SCHEMA_V2:
                raw_ast = active.get("raw_clang_ast")
                _file_pin(root, raw_ast, f"{role} raw compiler AST", failures)
                capture = captures.get(unit.get("compiled_role_source_file"))
                if (not isinstance(capture, dict) or
                        capture.get("compile_argv") != unit["argv"] or
                        capture.get("ast_argv") != _expected_ast_argv(unit["argv"]) or
                        _path(root, capture.get("ast_file")) !=
                        _path(root, raw_ast["path"])):
                    raise ValueError("AST flags or source differ from compile command")
            active_definitions.extend(active["definitions"])
            active_edges.extend(active["edges"])
            object_sha = unit["object"]["sha256"]
            if object_sha in objects:
                raise ValueError("duplicate object digest")
            objects.add(object_sha)
        if not objects.issubset(set(link.get("input_object_sha256") or [])):
            raise ValueError("compiled objects absent from link record")
        final_map = json.loads(_path(root, link["map"]["path"]).read_text())
        if schema == SCHEMA:
            link_ids_match = (final_map.get("final_linked_function_ids") ==
                              evidence.get("final_linked_function_ids"))
        else:
            link_ids_match = (
                final_map.get("final_out_of_line_function_ids") ==
                    evidence.get("final_out_of_line_function_ids") and
                final_map.get("final_executable_function_ids") ==
                    evidence.get("final_executable_function_ids") and
                final_map.get("inline_instances") == evidence.get("inline_instances"))
        if (sorted(active_definitions, key=lambda row: json.dumps(row, sort_keys=True)) !=
                sorted(evidence.get("active_definitions") or [],
                       key=lambda row: json.dumps(row, sort_keys=True)) or
            sorted(active_edges, key=lambda row: json.dumps(row, sort_keys=True)) !=
                sorted(evidence.get("active_edges") or [],
                       key=lambda row: json.dumps(row, sort_keys=True)) or
            not link_ids_match):
            raise ValueError("receipt differs from AST or final-link evidence")
    except (OSError, ValueError, KeyError, TypeError, AttributeError,
            json.JSONDecodeError):
        failures.append(f"{role}: INSUFFICIENT_BUILD_CAPTURE")


def _executable_sections(binary: Path) -> list[tuple[int, int]]:
    """Read only allocated executable ELF sections; no source-level claim here."""
    output = subprocess.run(["readelf", "-SW", str(binary)], capture_output=True,
                            text=True, check=True, timeout=30).stdout
    sections = []
    for line in output.splitlines():
        match = _SECTION.match(line)
        if match and {"A", "X"}.issubset(set(match.group(3))):
            start, size = int(match.group(1), 16), int(match.group(2), 16)
            if size > 0:
                sections.append((start, start + size))
    return sections


def _range_inside_exec(span: object, sections: list[tuple[int, int]]) -> bool:
    return (isinstance(span, list) and len(span) == 2 and
            all(type(value) is int for value in span) and
            any(lo <= span[0] < span[1] <= hi for lo, hi in sections))


def _check_v2_role(root: Path, source_root: Path, role: str, evidence: dict,
                   row_by_id: dict[str, dict], active_by_id: dict[str, dict],
                   failures: list[str]) -> set[str]:
    """Validate inline attestations without conflating them with ELF symbols.

    This checks receipt consistency, source and binary pins, and executable
    ranges. Independent DWARF and build producer review remains required.
    """
    try:
        out = evidence["final_out_of_line_function_ids"]
        executable = evidence["final_executable_function_ids"]
        linkage = evidence["role_linkage"]
        if (not isinstance(out, list) or not isinstance(executable, list) or
                not isinstance(linkage, dict) or
                len(out) != len(set(out)) or len(executable) != len(set(executable)) or
                not set(out).issubset(executable)):
            raise ValueError("invalid executable identity sets")
        binary = _path(root, evidence["binary"]["path"])
        binary_sha = evidence["binary"]["sha256"]
        if _sha(binary) != binary_sha:
            raise ValueError("binary changed")
        inline_pin = evidence["inline_instances"]
        _file_pin(root, inline_pin, f"{role} inline instances", failures)
        instances = json.loads(_path(root, inline_pin["path"]).read_text())
        inline = instances["functions"]
        if (instances.get("binary_sha256") != binary_sha or
                not isinstance(inline, dict) or
                set(executable) != set(out) | set(inline) or
                set(linkage) != set(executable) or set(out) & set(inline)):
            raise ValueError("inline/out-of-line role identities differ")
        sections = _executable_sections(binary) if inline else []
        if inline and not sections:
            raise ValueError("no executable section")
        for function_id, attestation in linkage.items():
            definition = active_by_id.get(function_id)
            if definition is None:
                raise ValueError("executable identity absent from role AST")
            if not isinstance(attestation, dict):
                raise ValueError("malformed role linkage")
            if (attestation.get("binary_sha256") != binary_sha or
                    (function_id in row_by_id and
                     row_by_id[function_id].get("role_linkage", {}).get(role) != attestation)):
                raise ValueError("catalog and receipt role linkage differ")
            source_file = definition.get("file")
            if function_id in out:
                source = _path(source_root, source_file)
                if (attestation.get("kind") != "OUT_OF_LINE_LINKED" or
                        attestation.get("source_file") != source_file or
                        attestation.get("source_sha256") != _sha(source) or
                        not isinstance(attestation.get("symbol"), str) or
                        not attestation["symbol"]):
                    raise ValueError("invalid linked role source")
            else:
                if attestation != inline.get(function_id):
                    raise ValueError("inline receipt differs from sidecar")
                source = _path(root, attestation.get("source_file"))
                model_source = _path(source_root, source_file)
                expected_role_source = _path(root, f"upstream_{role}_final/{source_file}")
                spans = attestation.get("ranges")
                offsets = attestation.get("instance_die_offsets")
                if (attestation.get("kind") != "INLINED_IN_EXECUTABLE" or
                        attestation.get("source_sha256") != _sha(source) or
                        _sha(source) != _sha(model_source) or
                        source != expected_role_source or
                        attestation.get("function_name") != definition.get("name") or
                        not isinstance(attestation.get("declaration_line"), int) or
                        not definition.get("start_line") <= attestation["declaration_line"] <= definition.get("end_line") or
                        not isinstance(attestation.get("cu_offset"), int) or
                        not isinstance(attestation.get("abstract_die_offset"), int) or
                        not isinstance(offsets, list) or not offsets or
                        any(not isinstance(x, int) or x < 0 for x in offsets) or
                        not isinstance(spans, list) or not spans):
                    raise ValueError("invalid inline DIE or source attestation")
                for span in spans:
                    if not _range_inside_exec(span, sections):
                        raise ValueError("inline range outside executable ELF section")
        return set(executable)
    except (OSError, ValueError, KeyError, TypeError, AttributeError,
            subprocess.SubprocessError,
            json.JSONDecodeError):
        failures.append(f"{role}: INVALID_V2_EXECUTABLE_EVIDENCE")
        return set()


def audit_catalog_build(catalog: Path, edges: Path, source_root: Path,
                        receipt_path: Path | None, frozen_receipt_sha256: str | None,
                        *, evaluator_root: Path) -> dict:
    """Return aggregate status only; do not publish target function names/rank.

    Required receipt shape::

      {"schema": SCHEMA, "catalog_sha256": ..., "edges_sha256": ...,
       "roles": {"asan": {"binary": {"path": ..., "sha256": ...},
                            "build_record": {"path": ..., "sha256": ...},
                            "active_definitions": [{"function_id": ...,
                              "file": ..., "start_line": ..., "end_line": ...,
                              "source": ...}],
                            "active_edges": [{"caller_id": ..., "callee_id": ...}],
                            "final_linked_function_ids": [...]},
                 "coverage": {...}}}

    ``build_record`` must be a build-system record of compile commands, object
    digests, and final link command. The active definitions and calls must come
    from those role-specific commands; final linkage must come from the final
    binary or linker map. This checker verifies internal coherence and pins,
    but does not independently establish the record's origin. The evaluator
    must freeze and review the receipt producer before using an ATTESTED result.
    """
    failures: list[str] = []
    counts: dict[str, object] = {}
    try:
        evaluator_root = evaluator_root.resolve(strict=True)
        source_root = source_root.resolve(strict=True)
        catalog = catalog.resolve(strict=True)
        edges = edges.resolve(strict=True)
        rows = _jsonl(catalog)
        edge_rows = _jsonl(edges)
        ids = [str(row["function_id"]) for row in rows]
        if not rows or len(ids) != len(set(ids)):
            failures.append("catalog: EMPTY_OR_DUPLICATE_FUNCTION_IDS")
        row_by_id = {str(row["function_id"]): row for row in rows}
        counts["catalog_rows"] = len(rows)
        counts["catalog_edges"] = len(edge_rows)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return {"status": "BLOCKED", "reasons": ["INVALID_CATALOG_INPUT"],
                "detail": type(error).__name__}

    if receipt_path is None or frozen_receipt_sha256 is None:
        failures.append("receipt: MISSING_FROZEN_BUILD_PROVENANCE")
        return {"status": "BLOCKED", "reasons": failures, "counts": counts}
    try:
        receipt_path = receipt_path.resolve(strict=True)
        if not receipt_path.is_relative_to(evaluator_root):
            raise ValueError("receipt outside evaluator root")
        actual_receipt_sha = _sha(receipt_path)
        if actual_receipt_sha != frozen_receipt_sha256:
            failures.append("receipt: FROZEN_HASH_MISMATCH")
        receipt = json.loads(receipt_path.read_text())
    except (OSError, ValueError, json.JSONDecodeError):
        failures.append("receipt: INVALID_OR_UNAVAILABLE")
        return {"status": "BLOCKED", "reasons": failures, "counts": counts}

    schema = receipt.get("schema")
    if schema not in {SCHEMA, SCHEMA_V2}:
        failures.append("receipt: WRONG_SCHEMA")
    if receipt.get("catalog_sha256") != _sha(catalog):
        failures.append("receipt: CATALOG_HASH_MISMATCH")
    if receipt.get("edges_sha256") != _sha(edges):
        failures.append("receipt: EDGES_HASH_MISMATCH")
    if schema == SCHEMA_V2:
        _file_pin(evaluator_root, receipt.get("indirect_edges"),
                  "indirect edge sidecar", failures)
        try:
            indirect = _jsonl(_path(evaluator_root, receipt["indirect_edges"]["path"]))
            if any(not isinstance(row, dict) or
                   row.get("kind") != "function_reference" or
                   row.get("status") != "UNVERIFIED_INDIRECT_REFERENCE"
                   for row in indirect):
                failures.append("indirect edge sidecar: INVALID_CLASSIFICATION")
            counts["preserved_indirect_references"] = len(indirect)
            valid_endpoints = sum(
                isinstance(row, dict) and
                str(row.get("caller_id")) in row_by_id and
                str(row.get("callee_id")) in row_by_id
                for row in indirect)
            counts["indirect_references_with_catalog_endpoints"] = valid_endpoints
            if valid_endpoints != len(indirect):
                failures.append("indirect edge sidecar: UNKNOWN_FUNCTION_ID")
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            failures.append("indirect edge sidecar: INVALID_OR_UNAVAILABLE")
        if any(edge.get("kind") not in {"DIRECT_AST_ID", "SOURCE_DIRECT_COMPILED"}
               or edge.get("resolution") !=
                  ("SAME_TU_AST_ID" if edge.get("kind") == "DIRECT_AST_ID"
                   else "CROSS_TU_OBJECT_SYMBOL")
               or not isinstance(edge.get("line"), int) or edge["line"] < 1
               for edge in edge_rows):
            failures.append("catalog: NON_DIRECT_OR_UNRESOLVED_TRAVERSABLE_EDGE")
    role_data = receipt.get("roles")
    if not isinstance(role_data, dict):
        role_data = {}

    for role in ROLES:
        evidence = role_data.get(role)
        if not isinstance(evidence, dict):
            failures.append(f"{role}: MISSING_ROLE_BUILD_EVIDENCE")
            continue
        _file_pin(evaluator_root, evidence.get("binary"), f"{role} binary", failures)
        _file_pin(evaluator_root, evidence.get("build_record"),
                  f"{role} build record", failures)
        _check_build_record(evaluator_root, source_root, role, evidence, failures,
                            schema=schema)
        definitions = evidence.get("active_definitions")
        active_edges = evidence.get("active_edges")
        linked = (evidence.get("final_linked_function_ids") if schema == SCHEMA
                  else evidence.get("final_executable_function_ids"))
        if not isinstance(definitions, list) or not isinstance(active_edges, list) or not isinstance(linked, list):
            failures.append(f"{role}: INCOMPLETE_ACTIVE_OR_LINK_EVIDENCE")
            continue
        by_id: dict[str, dict] = {}
        duplicate = False
        for item in definitions:
            if not isinstance(item, dict) or "function_id" not in item:
                duplicate = True
                continue
            key = str(item["function_id"])
            if key in by_id:
                duplicate = True
            by_id[key] = item
        if duplicate or len(linked) != len(set(map(str, linked))):
            failures.append(f"{role}: DUPLICATE_OR_INVALID_BUILD_IDENTITIES")
        linked_ids = set(map(str, linked))
        if schema == SCHEMA_V2:
            verified_ids = _check_v2_role(evaluator_root, source_root, role,
                                          evidence, row_by_id, by_id, failures)
            if verified_ids != linked_ids:
                failures.append(f"{role}: EXECUTABLE_IDENTITY_MISMATCH")
            linked_ids = verified_ids
        counts[f"{role}_active_definitions"] = len(by_id)
        counts[f"{role}_final_linked_functions"] = len(linked_ids)
        absent = 0
        span_mismatch = 0
        source_mismatch = 0
        unlinked = 0
        source_file_mismatch = 0
        for function_id, row in row_by_id.items():
            definition = by_id.get(function_id)
            if definition is None:
                absent += 1
                continue
            if (definition.get("file") != row.get("file") or
                    definition.get("start_line") != row.get("start_line") or
                    definition.get("end_line") != row.get("end_line") or
                    definition.get("name") != row.get("name")):
                span_mismatch += 1
            if definition.get("source") != row.get("source"):
                source_mismatch += 1
            try:
                path = _path(source_root, row.get("file"))
                if not _source_span_matches(path, row):
                    source_file_mismatch += 1
            except (OSError, ValueError, TypeError):
                source_file_mismatch += 1
            if function_id not in linked_ids:
                unlinked += 1
        counts[f"{role}_catalog_rows_without_active_definition"] = absent
        counts[f"{role}_catalog_span_mismatches"] = span_mismatch
        counts[f"{role}_catalog_source_mismatches"] = source_mismatch
        counts[f"{role}_catalog_source_file_mismatches"] = source_file_mismatch
        counts[f"{role}_catalog_rows_without_final_linkage"] = unlinked
        if absent or span_mismatch or source_mismatch or source_file_mismatch or unlinked:
            failures.append(f"{role}: CATALOG_ROWS_NOT_PROVEN_IN_FINAL_BINARY")
        active_pairs = {(str(e.get("caller_id")), str(e.get("callee_id")))
                        for e in active_edges if isinstance(e, dict)}
        active_calls = {(str(e.get("caller_id")), str(e.get("callee_id")),
                         e.get("line"), e.get("resolution"))
                        for e in active_edges if isinstance(e, dict)}
        unknown_active_edges = sum(caller not in by_id or callee not in by_id
                                   for caller, callee in active_pairs)
        if schema == SCHEMA_V2:
            missing_edges = sum((str(edge.get("caller_id")),
                                 str(edge.get("callee_id")), edge.get("line"),
                                 edge.get("resolution")) not in active_calls
                                for edge in edge_rows)
        else:
            missing_edges = sum((str(edge.get("caller_id")), str(edge.get("callee_id")))
                                not in active_pairs for edge in edge_rows)
        unlinked_edges = sum((str(edge.get("caller_id")) not in linked_ids or
                              str(edge.get("callee_id")) not in linked_ids)
                             for edge in edge_rows)
        counts[f"{role}_catalog_edges_without_active_call"] = missing_edges
        counts[f"{role}_catalog_edges_without_linked_endpoints"] = unlinked_edges
        counts[f"{role}_active_edges_with_unknown_endpoint"] = unknown_active_edges
        if missing_edges or unlinked_edges or unknown_active_edges:
            failures.append(f"{role}: CATALOG_EDGES_NOT_PROVEN_IN_FINAL_BINARY")
    # No partial pass: the current Function Pool has no per-role eligibility
    # filter, so an inactive row in either role can still be selected.
    return {"status": "BLOCKED" if failures else "ATTESTED_RECEIPT_CONSISTENT",
            "reasons": failures, "counts": counts,
            "receipt_sha256": actual_receipt_sha,
            "trust_limit": "Receipt origin, compiler/linker claims, and DWARF inline identity require independent evaluator review; matching hashes and ranges alone do not prove them."}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalog", type=Path)
    parser.add_argument("edges", type=Path)
    parser.add_argument("source_root", type=Path)
    parser.add_argument("evaluator_root", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--frozen-receipt-sha256")
    args = parser.parse_args()
    report = audit_catalog_build(args.catalog, args.edges, args.source_root,
                                 args.receipt, args.frozen_receipt_sha256,
                                 evaluator_root=args.evaluator_root)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if report["status"] == "BLOCKED":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
