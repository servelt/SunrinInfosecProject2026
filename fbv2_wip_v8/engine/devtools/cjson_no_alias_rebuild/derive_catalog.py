"""Build a conservative cJSON Catalog candidate from no-alias role evidence.

Only functions executable in both ASan and coverage roles enter the Catalog.
Unresolved callback call sites stay in a separate audit, never direct edges.
This script does not create an approved V2 catalog receipt or API review.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from pathlib import Path
import json
import re
import shutil
import sys

BASE = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027/review/CJSON_V2_NO_ALIAS_REBUILD_20261102')
PREP = BASE.parents[1]
sys.path[:0] = [str(PREP / "review_tools"), str(PREP)]
from supplement_compiled_catalog import _top_level_definitions, _row_from_definition
from catalog_direct import _direct_decl_ref, _walk, collect_ast_calls

ROLES = {
    role: (f'{role}/src/cjson', f'{role}/out', f'{role}-source-ast.stdout',
           f'{role}-inline-probe.json', f'{role}-object-defined-only.stdout',
           f'{role}-binary-defined-only.stdout')
    for role in ('asan', 'coverage')
}
SYMBOL = re.compile(r"[0-9a-fA-F]+\s+[TtWw]\s+([A-Za-z_]\w*)")


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def symbols(path: Path) -> set[str]:
    return {match.group(1) for line in path.read_text().splitlines()
            if (match := SYMBOL.fullmatch(line))}


def rows_for_role(role: str):
    root_name, output_name, ast_name, inline_name, object_nm, binary_nm = ROLES[role]
    root = BASE / root_name
    source = root / "cJSON.c"
    ast = json.loads((BASE / ast_name).read_text())
    mapped = []
    for node, hint in _top_level_definitions(ast, source):
        try:
            row = _row_from_definition(node, hint, root)
        except (OSError, ValueError):
            continue  # C library headers are outside the pinned target source.
        if row["file"] == "cJSON.c":
            mapped.append((node, row))
    if len(mapped) != 112 or len({row["function_id"] for _, row in mapped}) != 112:
        raise ValueError(f"{role}: source definition set changed")
    object_symbols = symbols(BASE / object_nm)
    binary_symbols = symbols(BASE / binary_nm)
    if not object_symbols <= binary_symbols:
        raise ValueError(f"{role}: object function absent from final binary")
    map_file = BASE / output_name / "final_link.map"
    member = str(root / "build/libcjson.a") + "(cJSON.c.o)"
    receipt = json.loads((BASE / role / "build-receipt-candidate.json").read_text())
    if (receipt["source_checkout_identity"]["physical_directory"] is not True or
            receipt["build_steps"][1]["outputs"][0]["path"] != str(root / "build/libcjson.a") or
            receipt["build_steps"][1]["outputs"][0]["sha256"] != digest(root / "build/libcjson.a")):
        raise ValueError(f"{role}: physical archive and receipt are inconsistent")
    if member not in map_file.read_text().split("Discarded input sections", 1)[0]:
        raise ValueError(f"{role}: target archive member not extracted by final link")
    inline = json.loads((BASE / inline_name).read_text())
    inlined = {name: evidence for name, _, evidence in inline["inlined"]}
    missing = {name for name, _, _ in inline["not_found"]}
    linked = {row["name"] for _, row in mapped if row["name"] in object_symbols}
    if len(linked) != inline["object_code"] or linked & set(inlined) or \
            linked | set(inlined) | missing != {row["name"] for _, row in mapped}:
        raise ValueError(f"{role}: object/inline/optimized-out partition changed")
    binary_sha = digest(BASE / output_name / "cjson_read_fuzzer")
    if binary_sha != receipt["binary_sha256"]:
        raise ValueError(f"{role}: receipt refers to another binary")
    linkage = {}
    for _, row in mapped:
        name = row["name"]
        if name in linked:
            linkage[row["function_id"]] = {
                "kind": "OUT_OF_LINE_LINKED", "binary_sha256": binary_sha,
                "source_file": "cJSON.c", "source_sha256": digest(source),
                "symbol": name,
            }
        elif name in inlined:
            evidence = inlined[name]
            if evidence["binary_sha256"] != binary_sha:
                raise ValueError(f"{role}: inline evidence refers to a different binary")
            linkage[row["function_id"]] = evidence
    calls = collect_ast_calls(ast, mapped, source.read_bytes(), "cJSON.c")
    direct = {(call.caller_id, call.same_tu_id, call.line)
              for call in calls if call.same_tu_id is not None}
    external = [{"caller_id": call.caller_id, "line": call.line,
                 "symbol": call.symbol, "status": "EXTERNAL_DECLARATION"}
                for call in calls if call.same_tu_id is None]
    return {"mapped": mapped, "direct": direct, "external": external,
            "linkage": linkage, "optimized_out": sorted(missing),
            "object_code_count": len(linked), "inline_count": len(inlined),
            "binary_sha256": binary_sha, "ast_sha256": digest(BASE / ast_name),
            "map_sha256": digest(map_file)}


def indirect_audit(mapped, source: bytes):
    non_direct_refs = []
    indirect_calls = []
    internal_names = {row["name"] for _, row in mapped}
    for node, row in mapped:
        body = next(part for part in node["inner"] if part.get("kind") == "CompoundStmt")
        direct_expr_ids = set()
        for call in _walk(body):
            if call.get("kind") != "CallExpr":
                continue
            expr = (call.get("inner") or [None])[0]
            while isinstance(expr, dict) and expr.get("kind") in {"ImplicitCastExpr", "ParenExpr"}:
                inner = expr.get("inner") or []
                expr = inner[0] if len(inner) == 1 else None
            if isinstance(expr, dict) and expr.get("kind") == "DeclRefExpr" and \
                    (expr.get("referencedDecl") or {}).get("kind") == "FunctionDecl":
                direct_expr_ids.add(expr.get("id"))
        for child in _walk(body):
            kind = child.get("kind")
            ref = child.get("referencedDecl") or {}
            if kind == "DeclRefExpr" and ref.get("kind") == "FunctionDecl" and \
                    child.get("id") not in direct_expr_ids:
                name = ref.get("name")
                loc = (child.get("range") or {}).get("begin") or {}
                offset = (loc.get("expansionLoc") or loc).get("offset")
                line = source.count(b"\n", 0, offset) + 1 if isinstance(offset, int) else None
                non_direct_refs.append({"caller_id": row["function_id"],
                                        "callee_name": name, "line": line,
                                        "internal_catalog_name": name in internal_names})
            if kind == "CallExpr" and _direct_decl_ref(child) is None:
                loc = (child.get("range") or {}).get("begin") or {}
                offset = (loc.get("expansionLoc") or loc).get("offset")
                line = source.count(b"\n", 0, offset) + 1 if isinstance(offset, int) else None
                indirect_calls.append({"caller_id": row["function_id"], "line": line,
                                       "status": "UNRESOLVED_CALLBACK_CALL"})
    return non_direct_refs, indirect_calls


def main():
    roles = {role: rows_for_role(role) for role in ROLES}
    asan_rows = {row["function_id"]: row for _, row in roles["asan"]["mapped"]}
    coverage_rows = {row["function_id"]: row for _, row in roles["coverage"]["mapped"]}
    if asan_rows != coverage_rows:
        raise ValueError("ASan and coverage source AST rows differ")
    eligible = set.intersection(*(set(item["linkage"]) for item in roles.values()))
    shared_direct = roles["asan"]["direct"] & roles["coverage"]["direct"]
    edges = []
    for caller, callee, line in sorted(shared_direct):
        if caller not in eligible or callee not in eligible:
            continue
        identity = sha256(f"{caller}\x1f{callee}\x1f{line}".encode()).hexdigest()[:20]
        edges.append({"edge_id": f"compiled-direct-{identity}",
                      "caller_id": caller, "callee_id": callee, "line": line,
                      "kind": "DIRECT_AST_ID", "resolution": "SAME_TU_AST_ID",
                      "confidence": "COMPILER_AST_AND_LINKED_OBJECT",
                      "providers": ["asan-clang-ast-and-object", "coverage-clang-ast-and-object"]})
    forward, reverse = defaultdict(set), defaultdict(set)
    for edge in edges:
        forward[edge["caller_id"]].add(edge["callee_id"])
        reverse[edge["callee_id"]].add(edge["caller_id"])
    rows = []
    target_root = BASE.parent / "CJSON_V2_DEV_DRAFT_20261030/model_target"
    target_source = target_root / "cJSON.c"
    if digest(target_source) != digest(BASE / "asan/src/cjson/cJSON.c"):
        raise ValueError("clean model source differs from compiled cJSON source")
    for identity in sorted(eligible):
        row = dict(asan_rows[identity])
        row["role_linkage"] = {role: roles[role]["linkage"][identity] for role in ROLES}
        row["build_targets"] = ["cjson_read_fuzzer"]
        row["callers"] = sorted(reverse[identity])
        row["callees"] = sorted(forward[identity])
        raw = target_source.read_text()
        if row["source"] not in raw or raw.count("\n", 0, raw.index(row["source"])) + 1 != row["start_line"]:
            raise ValueError(f"source span differs from clean target: {row['name']}")
        rows.append(row)
    refs, callback_calls = indirect_audit(roles["asan"]["mapped"], target_source.read_bytes())
    if any(item["internal_catalog_name"] for item in refs):
        raise ValueError("internal function reference requires an indirect edge")
    # All observed function-pointer values are external hooks. They have no
    # target Catalog endpoint; a fake edge would incorrectly assert reachability.
    out = BASE / "artifact"
    analysis = out / "analysis"
    attempt = out / "attempt"
    analysis.mkdir(parents=True, exist_ok=True)
    attempt.mkdir(parents=True, exist_ok=True)
    files = {"functions.jsonl": rows, "edges.jsonl": edges,
             "indirect_edges.jsonl": []}
    for name, data in files.items():
        (analysis / name).write_text("".join(json.dumps(item, sort_keys=True) + "\n"
                                            for item in data))
    harness = BASE / "asan/src/cjson/fuzzing/cjson_read_fuzzer.c"
    staged_harness = attempt / harness.name
    shutil.copyfile(harness, staged_harness)
    harness_ast = json.loads((BASE / "harness-ast.stdout").read_text())
    names = {ref.get("name") for node in _walk(harness_ast)
             if node.get("kind") == "CallExpr"
             if (ref := _direct_decl_ref(node)) is not None}
    anchors = {row["name"]: row["function_id"] for row in rows if row["name"] in names}
    if len(anchors) != 6 or any(name not in anchors for name in
            ("cJSON_ParseWithOpts", "cJSON_PrintBuffered", "cJSON_Print",
             "cJSON_PrintUnformatted", "cJSON_Minify", "cJSON_Delete")):
        raise ValueError("official Harness source anchors incomplete")
    (out / "project.json").write_text(json.dumps({
        "source_kind": "official_oss_fuzz", "source_root": str(target_root),
        "draft_only": True}, indent=2, sort_keys=True) + "\n")
    manifest = {"artifact_kind": "CJSON_V2_NO_ALIAS_CATALOG_CANDIDATE_NOT_QUALIFIED",
                "status": "API_REVIEW_HOLD", "catalog_producer": "EVALUATOR_CANDIDATE",
                "project_harness": True, "sanitizers": ["address"],
                "source_file": str(staged_harness),
                "expected_anchors": sorted(anchors.values()),
                "official_contract_path": None}
    (attempt / "manifest_candidate_not_qualified.json").write_text(json.dumps(manifest, indent=2,
                                                              sort_keys=True) + "\n")
    audit = {"roles": {role: {key: value for key, value in info.items()
                             if key in {"optimized_out", "object_code_count",
                                        "inline_count", "binary_sha256", "ast_sha256",
                                        "map_sha256"}} for role, info in roles.items()},
             "source_ast_functions": len(asan_rows),
             "executable_both_roles": len(rows),
             "direct_source_calls_shared": len(shared_direct),
             "direct_edges_executable": len(edges),
             "direct_edges_excluded_optimized_out": len(shared_direct) - len(edges),
             "external_direct_calls": len(roles["asan"]["external"]),
             "non_direct_function_refs": refs,
             "unresolved_callback_call_sites": callback_calls,
             "internal_indirect_edges": 0,
             "official_harness_direct_anchors": anchors,
             "catalog_sha256": {name: digest(analysis / name) for name in files},
             "status": "CANDIDATE_REQUIRES_INDEPENDENT_CATALOG_AND_LINK_REVIEW"}
    (BASE / "CATALOG_DERIVATION_NO_ALIAS_CANDIDATE.json").write_text(json.dumps(audit, indent=2,
                                                              sort_keys=True) + "\n")
    print({"functions": len(rows), "direct_edges": len(edges), "indirect_edges": 0,
           "callback_sites": len(callback_calls), "anchors": len(anchors)})

if __name__ == "__main__":
    main()
