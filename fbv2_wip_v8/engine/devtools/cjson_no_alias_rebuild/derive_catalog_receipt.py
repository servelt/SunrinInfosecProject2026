"""Derive an unapproved V2 Catalog receipt from no-alias cJSON evidence.

This does not issue an API review, alter source/build evidence, or qualify a run.
All paths and commands come from the new independent rebuild and recapture.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import json
import subprocess
import sys

REVIEW = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027/review/CJSON_V2_NO_ALIAS_REBUILD_20261102')
HERE = REVIEW / "catalog_receipt_candidate"
sys.path.insert(0, str(REVIEW.parents[1] / "evaluation_tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from derive_catalog import rows_for_role  # noqa: E402


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def pin(path: Path) -> dict[str, str]:
    path = path.resolve(strict=True)
    return {"path": path.relative_to(REVIEW).as_posix(), "sha256": digest(path)}


def write(path: Path, value: object) -> None:
    if not path.is_relative_to(HERE):
        raise ValueError("candidate output escaped its folder")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def make_role(role: str) -> dict:
    info = rows_for_role(role)
    original_path = REVIEW / role / "build-receipt-candidate.json"
    original = json.loads(original_path.read_text())
    captured_path = REVIEW / "ast-nm-capture.json"
    capture = json.loads(captured_path.read_text())["roles"][role]["captures"]["source_ast"]
    root_name = f"{role}/src/cjson"
    output_name = f"{role}/out"
    ast_name = f"{role}-source-ast.stdout"
    log_name = f"{role}/build.log"
    source = REVIEW / root_name / "cJSON.c"
    model_source = REVIEW.parent / "CJSON_V2_DEV_DRAFT_20261030/model_target/cJSON.c"
    binary = REVIEW / output_name / "cjson_read_fuzzer"
    obj = Path(original["build_steps"][0]["outputs"][0]["path"])
    archive = Path(original["build_steps"][1]["outputs"][0]["path"])
    raw_map = REVIEW / output_name / "final_link.map"
    ast_argv = original["build_steps"][0]["argv"]
    from catalog_build_integrity import _expected_ast_argv
    if (digest(source) != digest(model_source) or
            capture["argv"][-len(_expected_ast_argv(ast_argv)):] != _expected_ast_argv(ast_argv) or
            capture["stdout_sha256"] != digest(REVIEW / ast_name) or
            original["binary_sha256"] != digest(binary) or
            original["build_steps"][-1]["inputs"][-1]["sha256"] != digest(archive)):
        raise ValueError(f"{role}: source, AST command, archive, or binary pin changed")
    member = subprocess.run(["ar", "p", str(archive), obj.name],
                            capture_output=True, check=True, timeout=30).stdout
    if sha256(member).hexdigest() != digest(obj):
        raise ValueError(f"{role}: archive member differs from compiled object")
    map_text = raw_map.read_text(errors="replace")
    if (original["source_checkout_identity"]["physical_directory"] is not True or
            original["build_steps"][1]["outputs"][0]["path"] != str(archive)):
        raise ValueError(f"{role}: archive does not map to pinned physical checkout")
    member_key = f"{archive}({obj.name})"
    if member_key not in map_text.split("Discarded input sections", 1)[0]:
        raise ValueError(f"{role}: archive member not extracted by final link")

    definitions = sorted((row for _, row in info["mapped"]),
                         key=lambda row: row["function_id"])
    active_edges = [{"caller_id": caller, "callee_id": callee,
                     "line": line, "resolution": "SAME_TU_AST_ID"}
                    for caller, callee, line in sorted(info["direct"])]
    side = HERE / role
    side.mkdir(exist_ok=True)
    active_ast = side / "cJSON.active.json"
    write(active_ast, {"definitions": definitions, "edges": active_edges,
                       "raw_clang_ast": pin(REVIEW / ast_name)})
    captures = side / "capture_commands.json"
    write(captures, [{"source": str(source),
                      "compile_argv": ast_argv,
                      "ast_argv": _expected_ast_argv(ast_argv),
                      "ast_file": str(REVIEW / ast_name),
                      "original_capture_record": pin(
                          captured_path)}])
    inline = {identity: evidence for identity, evidence in info["linkage"].items()
              if evidence["kind"] == "INLINED_IN_EXECUTABLE"}
    outlined = sorted(identity for identity, evidence in info["linkage"].items()
                      if evidence["kind"] == "OUT_OF_LINE_LINKED")
    executable = sorted(info["linkage"])
    inline_file = side / "inline_instances.json"
    write(inline_file, {"binary_sha256": digest(binary), "functions": inline})
    archive_check = side / "archive_member_check.json"
    write(archive_check, {"source_file": "cJSON.c", "object": pin(obj),
                          "archive": pin(archive), "member_sha256": digest(obj),
                          "linker_map_member": member_key,
                          "final_linker_map": pin(raw_map)})
    map_summary = side / "final_link_map.json"
    write(map_summary, {"final_out_of_line_function_ids": outlined,
                        "final_executable_function_ids": executable,
                        "inline_instances": pin(inline_file),
                        "archive_member_checks": pin(archive_check),
                        "final_linker_map": pin(raw_map),
                        "method": "observed object/archive/final link plus captured DWARF inline instances"})
    unit = {"source_file": "cJSON.c", "source_sha256": digest(model_source),
            "compiled_role_source_file": str(source),
            "compiled_role_source_sha256": digest(source),
            "argv": original["build_steps"][0]["argv"],
            "object": pin(obj), "active_ast": pin(active_ast)}
    build_record = side / "build_capture.json"
    write(build_record, {"schema": "EVALUATOR_BUILD_CAPTURE_V1", "role": role,
                         "final_binary_sha256": digest(binary),
                         "compilation_units": [unit],
                         "ast_capture_commands": pin(captures),
                         "link": {"argv": original["build_steps"][-1]["argv"],
                                  "input_object_sha256": [digest(obj)],
                                  "map": pin(map_summary),
                                  "archive_steps": [original["build_steps"][1]],
                                  "official_build_log": pin(REVIEW / log_name),
                                  "source_build_receipt": pin(original_path)}})
    return {"binary": pin(binary), "build_record": pin(build_record),
            "ast_capture_commands": pin(captures),
            "active_definitions": definitions, "active_edges": active_edges,
            "final_out_of_line_function_ids": outlined,
            "final_executable_function_ids": executable,
            "inline_instances": pin(inline_file),
            "role_linkage": info["linkage"]}


def main() -> None:
    HERE.mkdir(exist_ok=True)
    catalog = REVIEW / "artifact/analysis/functions.jsonl"
    edges = REVIEW / "artifact/analysis/edges.jsonl"
    indirect = REVIEW / "artifact/analysis/indirect_edges.jsonl"
    value = {"schema": "EVALUATOR_CATALOG_BUILD_RECEIPT_V2",
             "catalog_sha256": digest(catalog), "edges_sha256": digest(edges),
             "indirect_edges": pin(indirect),
             "roles": {role: make_role(role) for role in ("asan", "coverage")}}
    write(HERE / "catalog_build_receipt_candidate.json", value)
    print({"receipt_sha256": digest(HERE / "catalog_build_receipt_candidate.json"),
           "roles": {r: {"definitions": len(value["roles"][r]["active_definitions"]),
                          "active_edges": len(value["roles"][r]["active_edges"]),
                          "executable": len(value["roles"][r]["final_executable_function_ids"])}
                     for r in ("asan", "coverage")}})


if __name__ == "__main__":
    main()
