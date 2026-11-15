"""Fill compile-scoped Catalog gaps using nm and Clang AST, without ranking.

The correction is applied to every defined C function absent from the source
Catalog, irrespective of target finding or function priority. Ambiguous AST
locations fail closed. The team indexer and target source are read-only.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from pathlib import Path
import argparse
import json
import re
import subprocess

from audit_catalog_edges import audit


NM_CODE = re.compile(r"^[0-9a-fA-F]+\s+[TtWw]\s+([A-Za-z_]\w*)$")
NM_OBJECT = re.compile(r"^(.+\.o):$")
COMPILER_PREFIXES = ("__asan", "__sanitizer", "__sancov", "llvm_")


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def stable_id(prefix: str, *parts: object) -> str:
    raw = "\x1f".join(str(part) for part in parts)
    return f"{prefix}-{sha256(raw.encode()).hexdigest()[:20]}"


def nm_code_pairs(archive: Path, nm: Path, source_names: dict[str, str],
                  object_map: dict[str, str] | None = None) -> set[tuple[str, str]]:
    result = subprocess.run([str(nm), "--defined-only", str(archive)],
                            capture_output=True, text=True, check=True, timeout=60)
    found: set[tuple[str, str]] = set()
    object_name: str | None = None
    observed_objects: set[str] = set()
    for line in result.stdout.splitlines():
        header = NM_OBJECT.fullmatch(line)
        if header:
            member = header.group(1)
            if not object_map or member not in object_map:
                raise ValueError(f"object-to-source mapping required: {member}")
            object_name = object_map[member]
            if object_name not in source_names:
                raise ValueError(f"compiled object outside registered scope: {member}")
            if object_name in observed_objects:
                raise ValueError(f"duplicate compiled object for source: {object_name}")
            observed_objects.add(object_name)
            continue
        if line.rstrip().endswith(":"):
            object_name = None
            raise ValueError(f"unsupported archive member header: {line}")
        match = NM_CODE.fullmatch(line)
        if match and object_name:
            name = match.group(1)
            if not name.startswith(COMPILER_PREFIXES):
                found.add((source_names[object_name], name))
    if observed_objects != set(source_names):
        raise ValueError("compiled object set differs from registered C source scope")
    return found


def _walk(node: dict):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.get("inner", [])))


def _definition(node: dict) -> bool:
    return node.get("kind") == "FunctionDecl" and any(
        child.get("kind") == "CompoundStmt" for child in node.get("inner", []))


def _span(node: dict, file_hint: Path, source_root: Path) -> tuple[Path, int, int, int, int]:
    loc = node.get("loc") or {}
    raw_begin = (node.get("range") or {}).get("begin") or {}
    raw_end = (node.get("range") or {}).get("end") or {}
    # A declaration may begin with a source macro such as an export marker.
    # Clang then nests the actual source position under expansionLoc.
    begin = raw_begin.get("expansionLoc") or raw_begin
    end = raw_end.get("expansionLoc") or raw_end
    source = Path(begin.get("file") or end.get("file") or
                  loc.get("file") or file_hint).resolve(strict=True)
    if not source.is_relative_to(source_root):
        raise ValueError("AST definition came from outside registered source tree")
    for endpoint in (begin, end):
        if endpoint.get("file") and Path(endpoint["file"]).resolve(strict=True) != source:
            raise ValueError("AST definition spans multiple source files")
    start_offset = begin.get("offset")
    end_offset = end.get("offset")
    end_len = end.get("tokLen")
    raw = source.read_bytes()
    if (not all(isinstance(value, int) for value in
                (start_offset, end_offset, end_len)) or
            start_offset < 0 or end_offset < start_offset or
            end_offset + end_len > len(raw)):
        raise ValueError("AST definition has no unambiguous source byte range")
    start_line = raw.count(b"\n", 0, start_offset) + 1
    end_line = raw.count(b"\n", 0, end_offset + end_len) + 1
    return source, start_line, end_line, start_offset, end_offset + end_len


def _location(node: dict, file_hint: Path, source_root: Path) -> tuple[str, int, int, int]:
    source, start_line, end_line, _, end_offset = _span(node, file_hint, source_root)
    return source.relative_to(source_root).as_posix(), start_line, end_line, end_offset


def _clang_ast(source: Path, clang: Path, source_root: Path,
               includes: list[Path], defines: list[str]) -> dict:
    command = [str(clang), "-fsyntax-only", "-Xclang", "-ast-dump=json",
               *["-D" + value for value in defines],
               *["-I" + str(path) for path in includes], str(source)]
    completed = subprocess.run(command, capture_output=True, timeout=120)
    if completed.returncode:
        raise ValueError(f"Clang AST parse failed for {source.name}")
    return json.loads(completed.stdout)


def _row_from_definition(node: dict, file_hint: Path, source_root: Path) -> dict:
    path, start_line, end_line, begin, end_offset = _span(node, file_hint, source_root)
    file = path.relative_to(source_root).as_posix()
    text = path.read_bytes()[begin:end_offset].decode("utf-8", errors="replace")
    if "{" not in text:
        raise ValueError(f"AST function body is absent from extracted source: {file}:{start_line} {node.get('name')}")
    name = node.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("unnamed AST function")
    signature = " ".join(text.split("{", 1)[0].split())
    if not signature:
        raise ValueError("empty AST function signature")
    return {
        "function_id": stable_id("fn", "c_cpp", name, file, start_line),
        "name": name, "qualified_name": name, "signature": signature,
        "language": "c_cpp", "file": file, "start_line": start_line,
        "end_line": end_line, "source": text, "declaration": "",
        "headers": [file] if file.endswith(".h") else [],
        "callers": [], "callees": [], "external_calls": [],
        "build_targets": [], "globals_read": [], "globals_written": [],
        "providers": ["clang-ast-compiled-nm"],
    }


def _top_level_definitions(ast: dict, main_file: Path) -> list[tuple[dict, Path]]:
    """Recover Clang JSON's omitted repeated file names in declaration order."""
    current_file = main_file
    result: list[tuple[dict, Path]] = []
    for node in ast.get("inner", []):
        loc = node.get("loc") or {}
        begin = (node.get("range") or {}).get("begin") or {}
        explicit = loc.get("file") or begin.get("file")
        if explicit:
            current_file = Path(explicit)
        if _definition(node):
            result.append((node, current_file))
    return result


def _called_name(call: dict) -> str | None:
    inner = call.get("inner") or []
    if not inner:
        return None
    for node in _walk(inner[0]):
        ref = node.get("referencedDecl") or {}
        if (node.get("kind") == "DeclRefExpr" and
                ref.get("kind") == "FunctionDecl" and
                isinstance(ref.get("name"), str)):
            return ref["name"]
    return None


def supplement(source_root: Path, compiled_sources: Path, original_analysis: Path,
               asan_archive: Path, coverage_archive: Path, clang: Path, nm: Path,
               output: Path, *, includes: list[Path], defines: list[str],
               object_map_path: Path | None = None) -> dict:
    source_root = source_root.resolve(strict=True)
    original_analysis = original_analysis.resolve(strict=True)
    if output.exists():
        raise FileExistsError("refusing to overwrite a Catalog output")
    registered = [line.strip() for line in compiled_sources.read_text().splitlines()
                  if line.strip()]
    source_names = {Path(name).name: name for name in registered}
    if (not registered or len(source_names) != len(registered) or
            any(Path(name).is_absolute() or ".." in Path(name).parts or
                not (source_root / name).is_file() for name in registered)):
        raise ValueError("compiled C scope is empty, ambiguous, or unavailable")
    rows = [json.loads(line) for line in
            (original_analysis / "functions.jsonl").read_text().splitlines()
            if line.strip()]
    original_edges = [json.loads(line) for line in
                      (original_analysis / "edges.jsonl").read_text().splitlines()
                      if line.strip()]
    if not rows or len({row["function_id"] for row in rows}) != len(rows):
        raise ValueError("invalid original Catalog")
    catalog_keys = {(row["file"], row["name"]) for row in rows}
    object_maps = (json.loads(object_map_path.read_text()) if object_map_path else {})
    if not isinstance(object_maps, dict):
        raise ValueError("invalid explicit object-to-source mapping")
    asan_pairs = nm_code_pairs(asan_archive, nm, source_names, object_maps.get("asan"))
    coverage_pairs = nm_code_pairs(coverage_archive, nm, source_names,
                                   object_maps.get("coverage"))
    all_pairs = asan_pairs | coverage_pairs
    missing_pairs = all_pairs - catalog_keys
    by_source: dict[str, set[str]] = defaultdict(set)
    for file, name in missing_pairs:
        by_source[file].add(name)
    asts: dict[str, dict] = {}
    new_rows: dict[tuple[str, int, str], dict] = {}
    pair_resolution: dict[tuple[str, str], str] = {}
    for file, names in sorted(by_source.items()):
        main_file = source_root / file
        ast = _clang_ast(main_file, clang, source_root, includes, defines)
        asts[file] = ast
        definitions: dict[str, list[tuple[dict, Path]]] = defaultdict(list)
        for node, file_hint in _top_level_definitions(ast, main_file):
            if _definition(node) and node.get("name") in names:
                definitions[node["name"]].append((node, file_hint))
        for name in sorted(names):
            options = definitions.get(name, [])
            if len(options) != 1:
                raise ValueError("nm symbol has zero or multiple AST definitions")
            row = _row_from_definition(options[0][0], options[0][1], source_root)
            key = (row["file"], row["start_line"], row["name"])
            previous = new_rows.get(key)
            if previous is not None and previous != row:
                raise ValueError("same AST source definition produced conflicting rows")
            new_rows[key] = row
            pair_resolution[(file, name)] = row["function_id"]
    existing_ids = {row["function_id"] for row in rows}
    if any(row["function_id"] in existing_ids for row in new_rows.values()):
        raise ValueError("supplemental function ID collides with existing Catalog")
    added_ids = {row["function_id"] for row in new_rows.values()}
    rows.extend(new_rows.values())
    row_by_id = {row["function_id"]: row for row in rows}
    by_file_name: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        by_file_name[(row["file"], row["name"])].append(row)
    edge_pairs = {(edge["caller_id"], edge["callee_id"]) for edge in original_edges}
    added_edges: list[dict] = []
    for file, ast in sorted(asts.items()):
        main_file = source_root / file
        definitions: dict[str, list[tuple[dict, Path]]] = defaultdict(list)
        function_nodes = _top_level_definitions(ast, main_file)
        for node, file_hint in function_nodes:
            definitions[str(node.get("name"))].append((node, file_hint))
        for caller_node, caller_hint in function_nodes:
            caller_name = caller_node.get("name")
            if not isinstance(caller_name, str):
                continue
            try:
                caller_file, _, _, _ = _location(caller_node, caller_hint, source_root)
            except ValueError:
                continue  # system header, outside the compile-scoped source tree
            caller_loc = (caller_node.get("loc") or {}).get("line")
            callers = [row for row in by_file_name[(caller_file, caller_name)]
                       if isinstance(caller_loc, int) and
                       row["start_line"] <= caller_loc <= row["end_line"]]
            if len(callers) != 1:
                continue
            caller = callers[0]
            body = next(child for child in caller_node.get("inner", [])
                        if child.get("kind") == "CompoundStmt")
            for call in _walk(body):
                if call.get("kind") != "CallExpr":
                    continue
                called = _called_name(call)
                if not called or len(definitions[called]) != 1:
                    continue
                callee_node, callee_hint = definitions[called][0]
                try:
                    callee_file, _, _, _ = _location(callee_node, callee_hint, source_root)
                except ValueError:
                    continue
                callee_loc = (callee_node.get("loc") or {}).get("line")
                callees = [row for row in by_file_name[(callee_file, called)]
                           if isinstance(callee_loc, int) and
                           row["start_line"] <= callee_loc <= row["end_line"]]
                if len(callees) != 1:
                    continue
                callee = callees[0]
                if (caller["function_id"] not in added_ids and
                        callee["function_id"] not in added_ids):
                    continue
                pair = (caller["function_id"], callee["function_id"])
                if pair in edge_pairs:
                    continue
                line = (call.get("range") or {}).get("begin", {}).get("line")
                if not isinstance(line, int):
                    line = caller["start_line"]
                added_edges.append({
                    "edge_id": stable_id("edge", *pair, line, "clang-ast-compiled-nm"),
                    "caller_id": pair[0], "callee_id": pair[1], "kind": "direct",
                    "line": line, "confidence": 0.95,
                    "providers": ["clang-ast-compiled-nm"],
                })
                edge_pairs.add(pair)
                caller["callees"] = sorted(set(caller.get("callees") or []) | {pair[1]})
                callee["callers"] = sorted(set(callee.get("callers") or []) | {pair[0]})
    rows.sort(key=lambda row: (row["file"], int(row["start_line"]), row["function_id"]))
    edges = sorted([*original_edges, *added_edges],
                   key=lambda edge: (edge["caller_id"], edge["callee_id"],
                                     int(edge.get("line") or 0), edge["edge_id"]))
    _, ambiguous, source_audit = audit(rows)
    ambiguous.sort(key=lambda row: (row["caller_id"], row.get("source_file") or "",
                                    row["source_line"], row["called_name"]))
    output.mkdir(parents=True)
    files = {"functions.jsonl": rows, "edges.jsonl": edges,
             "ambiguous_edges.jsonl": ambiguous}
    for name, data in files.items():
        (output / name).write_text("".join(json.dumps(row, ensure_ascii=False,
                                                     sort_keys=True) + "\n"
                                               for row in data))
    (output / "compiled_sources.txt").write_bytes(compiled_sources.read_bytes())
    if set(pair_resolution) != missing_pairs or any(
            function_id not in row_by_id for function_id in pair_resolution.values()):
        raise ValueError("compiled functions remain absent after generic supplement")
    report = {
        "kind": "SOURCE_ONLY_COMPILE_SCOPED_CATALOG_AST_NM_SUPPLEMENT_V1",
        "source_root": str(source_root),
        "source_scope_count": len(registered),
        "compiled_sources_sha256": digest(compiled_sources),
        "object_map_sha256": digest(object_map_path) if object_map_path else None,
        "base_catalog_sha256": digest(original_analysis / "functions.jsonl"),
        "base_edges_sha256": digest(original_analysis / "edges.jsonl"),
        "asan_archive_sha256": digest(asan_archive),
        "coverage_archive_sha256": digest(coverage_archive),
        "clang_sha256": digest(clang), "nm_sha256": digest(nm),
        "builder_file_sha256": digest(Path(__file__)),
        "indexer_mode": "team source Catalog plus compile-scoped nm/Clang AST supplement; no Function Pool or ranking",
        "asan_compiled_symbol_pairs": len(asan_pairs),
        "coverage_compiled_symbol_pairs": len(coverage_pairs),
        "missing_compiled_pairs_before": len(missing_pairs),
        "header_compiled_pairs_resolved": sum(
            row_by_id[function_id]["file"].endswith(".h")
            for function_id in pair_resolution.values()),
        "source_compiled_pairs_resolved": sum(
            row_by_id[function_id]["file"].endswith(".c")
            for function_id in pair_resolution.values()),
        "supplemented_total_definitions": len(new_rows),
        "supplemented_source_definitions": sum(
            row["file"].endswith(".c") for row in new_rows.values()),
        "supplemented_header_definitions": sum(row["file"].endswith(".h") for row in new_rows.values()),
        "supplemented_edges": len(added_edges),
        "missing_compiled_pairs_after": len(missing_pairs - set(pair_resolution)),
        "catalog_rows": len(rows), "producer_edge_rows": len(edges),
        "ambiguous_source_callsites": len(ambiguous),
        "unresolved_producer_callee_ids": source_audit["unresolved_producer_callee_ids"],
        "output_sha256": {name: digest(output / name) for name in files},
    }
    (output / "catalog_provenance.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("source_root", "compiled_sources", "original_analysis",
                 "asan_archive", "coverage_archive", "clang", "nm", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--include", action="append", type=Path, default=[])
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--object-map", type=Path)
    args = parser.parse_args()
    summary = supplement(args.source_root, args.compiled_sources,
                         args.original_analysis, args.asan_archive,
                         args.coverage_archive, args.clang, args.nm,
                         args.output, includes=args.include, defines=args.define,
                         object_map_path=args.object_map)
    print(json.dumps({key: value for key, value in summary.items()
                      if key in {"source_scope_count", "asan_compiled_symbol_pairs",
                                 "coverage_compiled_symbol_pairs",
                                 "missing_compiled_pairs_before",
                                 "supplemented_total_definitions",
                                 "supplemented_source_definitions",
                                 "supplemented_header_definitions",
                                 "supplemented_edges", "missing_compiled_pairs_after",
                                 "catalog_rows", "producer_edge_rows"}}, sort_keys=True))
