"""Conservative C++ AST supplement for source acquisition and call targets.

The bootstrap text index cannot distinguish a C++ member from a global
function with the same name. Clang's parsed references can. A translation
unit without its real compile flags supplies bootstrap navigation candidates
only when a compile database is present; failed or ambiguous builds never
become proof of executable call targets.
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import AnalysisBundle, CallEdge, FunctionMetadata, stable_id, unique_strings
from ..runtime.native_build import _find_compile_database, _flags_from_compile_record
from .clang_c import (
    _children, _direct_call_argument_declarations,
    _direct_call_argument_field_bindings,
    _direct_call_argument_identifiers, _direct_call_addressed_scalar_declarations,
    _guarded_call_sites, _indirect_array_declaration, _parameter_output_positions,
    _compiler_diagnostic, _linkage_declarations, _line, _loc, _walk,
)
from .indexer import _iter_project_files, _populate_adjacency


CPP_SUFFIXES = {".cc", ".cpp", ".cxx", ".c++"}
DEFINITION_KINDS = {
    "FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl",
}
CALL_KINDS = {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"}


@dataclass(frozen=True)
class CppAstResult:
    parsed_files: int = 0
    failed_files: int = 0
    unrecorded_files: int = 0
    added_functions: int = 0
    added_calls: int = 0
    budget_exhausted: bool = False
    failure_diagnostics: tuple[dict[str, str], ...] = ()


def _compile_context(
    root: Path, compile_database: Path | None = None,
) -> tuple[dict[Path, tuple[str, ...]], set[Path], bool]:
    db = compile_database or _find_compile_database(root)
    if db is None:
        return {}, set(), False
    try:
        records = json.loads(db.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        if compile_database is not None:
            raise ValueError(f"cannot read analysis compile database {db}: {exc}") from exc
        return {}, set(), False
    flags: dict[Path, tuple[str, ...]] = {}
    ambiguous: set[Path] = set()
    if not isinstance(records, list):
        if compile_database is not None:
            raise ValueError(f"analysis compile database is not an array: {db}")
        return flags, ambiguous, False
    for record in records:
        if not isinstance(record, dict):
            continue
        directory = Path(str(record.get("directory") or db.parent)).resolve()
        value = record.get("file")
        if not isinstance(value, str) or not value:
            continue
        path = Path(value)
        path = (path if path.is_absolute() else directory / path).resolve()
        if path.suffix.lower() not in CPP_SUFFIXES or not path.is_file():
            continue
        parsed = _flags_from_compile_record(record, directory)
        if path in flags and flags[path] != parsed:
            ambiguous.add(path)
        flags[path] = parsed
    for path in ambiguous:
        flags.pop(path, None)
    return flags, ambiguous, True


def _source_definitions(ast: dict[str, Any], path: Path, source: str):
    # Clang places out-of-line C++ method definitions at translation-unit
    # scope. Their lexical parent is therefore absent from the traversal
    # stack, but parentDeclContextId points to the declaring class.
    context_owners: dict[str, tuple[str, ...]] = {}

    def collect_contexts(node: dict[str, Any], owners: tuple[str, ...]) -> None:
        kind = node.get("kind")
        if kind in {"NamespaceDecl", "CXXRecordDecl", "ClassTemplateSpecializationDecl"}:
            name = str(node.get("name") or "")
            if name and not node.get("isImplicit"):
                owners = (*owners, name)
        context_id = node.get("id")
        if (kind in {"NamespaceDecl", "CXXRecordDecl", "ClassTemplateSpecializationDecl"}
            and isinstance(context_id, str) and owners):
            context_owners[context_id] = owners
        for child in _children(node):
            collect_contexts(child, owners)

    collect_contexts(ast, ())

    def visit(node: dict[str, Any], owners: tuple[str, ...]):
        kind = node.get("kind")
        if kind in {"NamespaceDecl", "CXXRecordDecl", "ClassTemplateSpecializationDecl"}:
            name = str(node.get("name") or "")
            if name and not node.get("isImplicit"):
                owners = (*owners, name)
        if kind in DEFINITION_KINDS and any(
            child.get("kind") == "CompoundStmt" for child in _children(node)
        ):
            position = _loc(node.get("loc") or {})
            file_name = position.get("file")
            if not position.get("includedFrom") and (
                not file_name or Path(str(file_name)).resolve() == path
            ):
                offset = position.get("offset")
                name = str(node.get("name") or "")
                # Header declarations often omit their file in a nested AST.
                # Require the name at the reported byte offset in the main
                # source before accepting a file-less node as local.
                if name and isinstance(offset, int) and (
                    0 <= offset < len(source)
                    and source[offset:offset + len(name)] == name
                ):
                    parent_id = node.get("parentDeclContextId")
                    yield node, context_owners.get(parent_id, owners)
        for child in _children(node):
            yield from visit(child, owners)

    yield from visit(ast, ())


def _virtual_context(
    ast: dict[str, Any],
) -> tuple[dict[str, set[str]], dict[str, tuple[str, str, str]]]:
    """Collect compiler-parsed inheritance and virtual declarations.

    Names are used only for later navigation candidate matching. Unresolved
    aliases or template specializations do not establish a hierarchy edge.
    """
    bases: dict[str, set[str]] = {}
    methods: dict[str, tuple[str, str, str]] = {}

    def visit(node: dict[str, Any], owners: tuple[str, ...]) -> None:
        kind = node.get("kind")
        if kind in {"NamespaceDecl", "CXXRecordDecl", "ClassTemplateSpecializationDecl"}:
            name = str(node.get("name") or "")
            if name and not node.get("isImplicit"):
                owners = (*owners, name)
        if kind in {"CXXRecordDecl", "ClassTemplateSpecializationDecl"} and owners:
            child = "::".join(owners)
            for base in node.get("bases") or []:
                base_type = base.get("type") or {}
                raw = str(base_type.get("desugaredQualType") or base_type.get("qualType") or "")
                parent = re.sub(r"^(?:class|struct)\s+", "", raw).strip()
                if parent and parent != child:
                    bases.setdefault(child, set()).add(parent)
        if kind == "CXXMethodDecl" and node.get("virtual") and owners:
            symbol = str(node.get("mangledName") or "")
            signature = str((node.get("type") or {}).get("qualType") or "")
            name = str(node.get("name") or "")
            if symbol and signature and name:
                methods[symbol] = ("::".join(owners), name, signature)
        for item in _children(node):
            visit(item, owners)

    visit(ast, ())
    return bases, methods


def _file_scope_initializers(
    ast: dict[str, Any], path: Path, root: Path, source: str,
    *, include_uninitialized: bool = False,
) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    """Index source-owned globals, not locals or header lookalikes."""

    def declarations(container: dict[str, Any]):
        for item in _children(container):
            if item.get('kind') == 'VarDecl':
                yield item
            elif item.get('kind') in {'NamespaceDecl', 'LinkageSpecDecl'}:
                yield from declarations(item)

    result: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for declaration in declarations(ast):
        name = str(declaration.get('name') or '')
        location = _loc(declaration.get('loc') or {})
        name_offset = location.get('offset')
        location_file = location.get('file')
        if (not name or not isinstance(name_offset, int)
            or not 0 <= name_offset < len(source)
            or source[name_offset:name_offset + len(name)] != name
            or location.get('includedFrom')
            or (location_file and Path(str(location_file)).resolve() != path)
            or (not include_uninitialized and not declaration.get('init'))):
            continue
        begin = (declaration.get('range') or {}).get('begin') or {}
        end = (declaration.get('range') or {}).get('end') or {}
        start = _loc(begin).get('offset')
        stop = _loc(end).get('offset')
        width = _loc(end).get('tokLen')
        if (not isinstance(start, int) or not isinstance(stop, int)
            or not isinstance(width, int)
            or not 0 <= start < stop + width <= len(source)):
            continue
        result[str(declaration.get('id'))] = (
            declaration,
            {
                'name': name,
                'file': path.relative_to(root).as_posix(),
                'start_line': _line(begin, source),
                'end_line': _line(end, source),
                'source': source[start:stop + width],
                'provider': 'clang-ast-cpp',
                'analysis_unit': str(path),
            },
        )
    return result


def _call_reference(call: dict[str, Any]) -> tuple[str, str, str] | None:
    operands = list(_children(call))
    if not operands:
        return None
    node = operands[0]
    while node.get("kind") in {
        "ImplicitCastExpr", "ParenExpr", "CStyleCastExpr",
        "CXXStaticCastExpr", "CXXReinterpretCastExpr",
        "CXXConstCastExpr", "ExprWithCleanups",
    }:
        children = list(_children(node))
        if len(children) != 1:
            return None
        node = children[0]
    if node.get("kind") == "DeclRefExpr":
        ref = node.get("referencedDecl") or {}
        if ref.get("kind") in DEFINITION_KINDS:
            return str(ref.get("id")), str(ref.get("name") or ""), "global"
    if node.get("kind") == "MemberExpr":
        member_id = node.get("referencedMemberDecl")
        if member_id:
            return str(member_id), str(node.get("name") or ""), "member"
    return None


def _json_documents(payload: str) -> list[dict[str, Any]]:
    """Clang's declaration filter writes adjacent JSON documents."""
    decoder = json.JSONDecoder()
    result: list[dict[str, Any]] = []
    position = 0
    while position < len(payload):
        while position < len(payload) and payload[position].isspace():
            position += 1
        if position == len(payload):
            break
        document, position = decoder.raw_decode(payload, position)
        if not isinstance(document, dict):
            raise ValueError("Clang AST document is not an object")
        result.append(document)
    return result


def _run_ast_dump(
    command: list[str], root: Path, timeout: float,
) -> tuple[int, str | None, str]:
    """Keep giant header AST dumps off the Python heap.

    ``None`` after a successful process means the dump exceeded the parser
    budget; callers can retry by local declaration name without treating the
    missing AST as evidence that an input site does not exist.
    """
    with tempfile.TemporaryFile(mode="w+b") as output:
        result = subprocess.run(
            command, cwd=root, stdout=output,
            stderr=subprocess.PIPE, timeout=timeout,
        )
        if result.returncode:
            return result.returncode, None, result.stderr.decode("utf-8", errors="replace")
        if os.fstat(output.fileno()).st_size > 45_000_000:
            return 0, None, ""
        output.seek(0)
        return 0, output.read().decode("utf-8"), ""


def _filtered_local_ast(
    compiler: str, root: Path, path: Path, flags: tuple[str, ...],
    local: list[FunctionMetadata], deadline: float,
) -> tuple[dict[str, Any] | None, bool]:
    """Recover local declarations when headers make the full AST too large.

    A name filter is only a source discovery fallback: it may match header
    declarations too, and an unfinished walk must be reported as incomplete.
    """
    names = unique_strings([
        function.name for function in sorted(
            local, key=lambda item: (
                not bool(item.external_calls), item.start_line, item.name,
            ),
        ) if function.name
    ])
    nodes: list[dict[str, Any]] = []
    complete = True
    for name in names:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            complete = False
            break
        try:
            returncode, payload, _stderr = _run_ast_dump(
                [compiler, "-fsyntax-only", "-Xclang", "-ast-dump=json",
                 "-Xclang", f"-ast-dump-filter={name}",
                 "-I", str(root), "-I", str(path.parent),
                 *flags, str(path)],
                root, min(8.0, max(0.1, remaining)),
            )
            if returncode or payload is None:
                complete = False
                continue
            nodes.extend(_json_documents(payload))
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
            complete = False
    return ({"kind": "TranslationUnitDecl", "inner": nodes} if nodes else None,
            complete)


def _standard_stdin_read(
    call: dict[str, Any], source: str, name: str, scope: str,
) -> bool:
    """Recognize only the standard stdin object's unformatted read member."""
    if scope != "member" or name != "read":
        return False
    begin = (call.get("range") or {}).get("begin") or {}
    end = (call.get("range") or {}).get("end") or {}
    start = begin.get("offset")
    stop = end.get("offset")
    if not isinstance(start, int) or not isinstance(stop, int):
        return False
    spelling = source[start:stop + int(end.get("tokLen") or 1)]
    if not re.match(r"std\s*::\s*(?:w?cin)\s*\.\s*read\s*\(", spelling):
        return False
    receiver_names = {
        str((node.get("referencedDecl") or {}).get("name") or "")
        for node in _walk(call)
        if node.get("kind") == "DeclRefExpr"
        and "basic_istream" in str((node.get("type") or {}).get("desugaredQualType") or "")
    }
    return bool(receiver_names & {"cin", "wcin"})


def augment_cpp_ast(
    bundle: AnalysisBundle, source_root: Path, *, excluded_paths: tuple[Path, ...] = (),
    compile_database: Path | None = None,
    target_binary: Path | None = None,
) -> CppAstResult:
    compiler = shutil.which("clang++")
    if not compiler:
        return CppAstResult()
    root = source_root.resolve()
    # Do not treat an implicit 45-second total work allowance as a complete
    # C++ source inventory. Operators can select a total budget explicitly;
    # a per-file timeout still records individual parser failures.
    selected_budget = os.environ.get("HC_CPP_AST_BUDGET_SECONDS")
    if selected_budget is not None:
        budget = float(selected_budget)
        if not math.isfinite(budget) or budget < 0:
            raise ValueError("HC_CPP_AST_BUDGET_SECONDS must be finite and nonnegative")
        if budget == 0:
            return CppAstResult()
        deadline = time.monotonic() + budget
    else:
        deadline = float("inf")
    flags, ambiguous, has_compile_db = _compile_context(root, compile_database)
    paths = [
        path for path in _iter_project_files(root, excluded_paths)
        if path.suffix.lower() in CPP_SUFFIXES and path.is_file()
    ]
    unrecorded = 0
    if has_compile_db:
        unrecorded = sum(path not in flags and path not in ambiguous for path in paths)
        paths = [path for path in paths if path in flags or path in ambiguous]
    from .compile_priority import order_translation_units
    paths = order_translation_units(paths, root, compile_database, target_binary)
    parsed = failed = added_functions = added_calls = 0
    adjacency_changed = False
    exhausted = False
    diagnostics: list[dict[str, str]] = []
    cross_unit_calls: list[tuple[str, int, str, str, dict[str, object]]] = []
    class_bases: dict[str, set[str]] = {}
    virtual_methods: dict[str, tuple[str, str, str]] = {}
    for path in paths:
        if path in ambiguous:
            failed += 1
            diagnostics.append({"file": str(path.relative_to(root)),
                                "reason": "ambiguous compile commands for this source"})
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            exhausted = True
            break
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            relative = str(path.relative_to(root))
            local = [f for f in bundle.functions.values() if f.file == relative]
            cmd = [
                compiler, "-fsyntax-only", "-Xclang", "-ast-dump=json",
                "-I", str(root), "-I", str(path.parent),
                *flags.get(path, ()), str(path),
            ]
            returncode, payload, stderr = _run_ast_dump(
                cmd, root, min(8.0, max(0.1, remaining)),
            )
            if returncode:
                failed += 1
                diagnostics.append({"file": relative,
                                    "reason": _compiler_diagnostic(stderr)})
                continue
            if payload is None:
                ast, complete = _filtered_local_ast(
                    compiler, root, path, flags.get(path, ()), local, deadline,
                )
                exhausted |= not complete
                if ast is None:
                    failed += 1
                    diagnostics.append({"file": relative,
                                        "reason": "large AST dump could not be recovered from local declarations"})
                    continue
            else:
                ast = json.loads(payload)
        except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as exc:
            failed += 1
            diagnostics.append({"file": str(path.relative_to(root)),
                                "reason": f"{type(exc).__name__}: {exc}"[:500]})
            continue
        parsed += 1
        parsed_bases, parsed_virtuals = _virtual_context(ast)
        for child, parents in parsed_bases.items():
            class_bases.setdefault(child, set()).update(parents)
        virtual_methods.update(parsed_virtuals)
        linkage_declarations = _linkage_declarations(ast)
        global_initializers = _file_scope_initializers(ast, path, root, source)
        global_declarations = _file_scope_initializers(
            ast, path, root, source, include_uninitialized=True,
        )
        definitions = list(_source_definitions(ast, path, source))
        by_ast_id: dict[str, FunctionMetadata] = {}
        member_function_ids: set[str] = set()
        for node, owners in definitions:
            name = str(node.get("name") or "")
            start = _line((node.get("range") or {}).get("begin") or {}, source)
            start = start or _line(node.get("loc") or {}, source)
            end = _line((node.get("range") or {}).get("end") or {}, source)
            if not start:
                continue
            end = max(start, end)
            # Source bootstrap may include a return-type prefix on the same
            # line. Match by source range before making a second record.
            existing = next((
                f for f in local if f.name == name
                and f.start_line <= start <= f.end_line
                and f.end_line >= end
            ), None)
            if existing is None:
                lines = source.splitlines(keepends=True)
                snippet = "".join(lines[start - 1:end])
                qualified = "::".join((*owners, name)) if owners else name
                existing = FunctionMetadata.create(
                    name=name, qualified_name=qualified,
                    signature=f"{qualified}: {(node.get('type') or {}).get('qualType', '')}",
                    file=relative, start_line=start, end_line=end,
                    source=snippet, provider="clang-ast-cpp",
                )
                bundle.functions[existing.function_id] = existing
                local.append(existing)
                added_functions += 1
            else:
                existing.providers = unique_strings([
                    *existing.providers, "clang-ast-cpp",
                ])
                if owners:
                    # Bootstrap extraction can lose C++ class ownership.
                    # Parsed AST ownership is needed to keep ::recv distinct
                    # from Session::recv during filtered-dump recovery.
                    existing.qualified_name = "::".join((*owners, name))
            existing.ast_parameter_declarations = [
                {
                    "name": str(item.get("name") or ""),
                    "declaration_id": str(item.get("id") or ""),
                    "type": str((item.get("type") or {}).get("qualType") or ""),
                    "analysis_unit": str(path),
                }
                for item in _children(node)
                if item.get("kind") == "ParmVarDecl" and item.get("id")
            ]
            existing.parameter_output_positions = _parameter_output_positions(node)
            linkage = linkage_declarations.get(str(node.get("id")), {})
            if linkage.get("external"):
                existing.linkage_symbol = str(linkage["symbol"])
                existing.linkage_type = str(linkage["type"])
                existing.linkage_external = True
            by_ast_id[str(node.get("id"))] = existing
            if node.get("kind") in {
                "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl",
            }:
                member_function_ids.add(existing.function_id)
        for node, _owners in definitions:
            caller = by_ast_id.get(str(node.get("id")))
            if caller is None:
                continue
            for site in _guarded_call_sites(node, source):
                site["analysis_unit"] = str(path)
                target = by_ast_id.get(site["callee_declaration_id"])
                site["callee_function_id"] = target.function_id if target else ""
                linkage = linkage_declarations.get(site["callee_declaration_id"], {})
                if linkage.get("external"):
                    site["callee_linkage_symbol"] = linkage["symbol"]
                    site["callee_linkage_type"] = linkage["type"]
                if site not in caller.guarded_call_sites:
                    caller.guarded_call_sites.append(site)
        for node, _owners in definitions:
            caller = by_ast_id.get(str(node.get("id")))
            if caller is None:
                continue
            for item in _walk(node):
                if item.get('kind') != 'DeclRefExpr':
                    continue
                declaration_id = str(
                    (item.get('referencedDecl') or {}).get('id') or ''
                )
                stored = global_declarations.get(declaration_id)
                if stored is None:
                    continue
                declaration = stored[1]
                if declaration not in caller.referenced_global_declarations:
                    caller.referenced_global_declarations.append(declaration)
            local_declaration_ids = {
                str(item.get("id")) for item in _walk(node)
                if item.get("kind") in {"VarDecl", "ParmVarDecl"}
            }
            local_declarations = {
                str(item.get("id")): item for item in _walk(node)
                if item.get("kind") in {"VarDecl", "ParmVarDecl"}
            }
            resolved_names: set[str] = set()
            external_names: set[str] = set()
            member_only_names: set[str] = set()
            unresolved_local_names: set[str] = set()
            for item in _walk(node):
                if item.get("kind") not in CALL_KINDS:
                    continue
                reference = _call_reference(item)
                if reference is None:
                    operands = list(_children(item))
                    table = _indirect_array_declaration(operands[0]) if operands else None
                    table_id = str((table or {}).get('id') or '')
                    stored = global_initializers.get(table_id)
                    if stored is not None:
                        initializer, declaration = stored
                        targets: list[str] = []
                        for member in _walk(initializer):
                            if member.get('kind') != 'DeclRefExpr':
                                continue
                            ref = member.get('referencedDecl') or {}
                            if ref.get('kind') not in DEFINITION_KINDS:
                                continue
                            target = by_ast_id.get(str(ref.get('id')))
                            if target and target.function_id not in targets:
                                targets.append(target.function_id)
                        site = {
                            'table_name': declaration['name'],
                            'table_declaration_id': table_id,
                            'table_file': declaration['file'],
                            'table_start_line': declaration['start_line'],
                            'call_line': _line((item.get('range') or {}).get('begin') or {}, source),
                            'candidate_function_ids': targets,
                            'provider': 'clang-ast-cpp',
                            'analysis_unit': str(path),
                        }
                        if site not in caller.indirect_table_call_sites:
                            caller.indirect_table_call_sites.append(site)
                        if declaration not in caller.referenced_global_declarations:
                            caller.referenced_global_declarations.append(declaration)
                    continue
                target_id, name, scope = reference
                if not name:
                    continue
                line = _line((item.get("range") or {}).get("begin") or {}, source)
                line = line or caller.start_line
                target = by_ast_id.get(target_id)
                target_from_filtered_name = False
                local_matches = (
                    [function for function in local
                     if function.name == name
                     and function.function_id not in member_function_ids]
                    if target is None and scope == "global" else []
                )
                if target is None and scope == "global":
                    # Filtered AST dumps come from separate Clang processes,
                    # so their pointer-shaped declaration IDs cannot be
                    # joined. A unique same-file name is a navigation edge,
                    # never an exact compiler-resolved call proof.
                    if len(local_matches) == 1:
                        target = local_matches[0]
                        target_from_filtered_name = True
                    elif local_matches:
                        unresolved_local_names.add(name)
                if target is None and path in flags:
                    declaration = linkage_declarations.get(target_id, {})
                    if declaration.get("external"):
                        cross_unit_calls.append((
                            caller.function_id, line,
                            str(declaration["symbol"]),
                            str(declaration["type"]),
                            {
                                'line': line,
                                'offset': _loc((item.get('range') or {}).get('begin') or {}).get('offset'),
                                'provider': 'clang-ast-cpp-cross-unit-navigation',
                                'analysis_unit': str(path),
                                'direct_argument_identifiers': _direct_call_argument_identifiers(
                                    item, local_declaration_ids),
                                'direct_argument_declaration_ids': _direct_call_argument_declarations(item),
                                'direct_argument_field_bindings': _direct_call_argument_field_bindings(item),
                            },
                        ))
                # A parsed C++ call gives stronger name-lookup evidence than
                # the text index. Remove only bootstrap edges for this caller,
                # line and spelling; never erase Fuzz Introspector reports.
                before = len(bundle.edges)
                bundle.edges = [
                    edge for edge in bundle.edges
                    if not (
                        edge.caller_id == caller.function_id
                        and edge.line == line
                        and edge.kind == "direct"
                        and edge.providers == ["bootstrap-source"]
                        and (bundle.functions.get(edge.callee_id) is not None)
                        and bundle.functions[edge.callee_id].name == name
                    )
                ]
                adjacency_changed |= len(bundle.edges) != before
                if target and target.function_id != caller.function_id:
                    direct_site = {
                        'callee_function_id': target.function_id,
                        'line': line,
                        'offset': _loc((item.get('range') or {}).get('begin') or {}).get('offset'),
                        'provider': 'clang-ast-cpp',
                        'analysis_unit': str(path),
                        'direct_argument_identifiers': _direct_call_argument_identifiers(
                            item, local_declaration_ids,
                        ),
                        'direct_argument_declaration_ids': _direct_call_argument_declarations(item),
                        'direct_argument_field_bindings': _direct_call_argument_field_bindings(item),
                    }
                    if direct_site not in caller.direct_call_sites:
                        caller.direct_call_sites.append(direct_site)
                    resolved_names.add(name)
                    kind = (
                        "direct" if path in flags and not target_from_filtered_name
                        else "source_candidate"
                    )
                    key = (caller.function_id, target.function_id, line, kind)
                    if not any((edge.caller_id, edge.callee_id, edge.line, edge.kind) == key
                               for edge in bundle.edges):
                        bundle.edges.append(CallEdge(
                            edge_id=stable_id("clang-ast-cpp-call", *key),
                            caller_id=caller.function_id,
                            callee_id=target.function_id,
                            line=line, kind=kind,
                            confidence=0.98 if kind == "direct" else 0.65,
                            providers=["clang-ast-cpp"],
                        ))
                        added_calls += 1
                        adjacency_changed = True
                elif target is None and (
                    (scope == "global" and not local_matches)
                    or _standard_stdin_read(item, source, name, scope)
                ):
                    # A member named recv/read may belong to an arbitrary
                    # class. Its name alone does not establish an OS input
                    # boundary, including when the member call is hidden by
                    # a macro. Leave it unresolved rather than label ingress.
                    standard_stdin = scope == "member"
                    api = "std::basic_istream::read" if standard_stdin else name
                    external_names.add(api)
                    if standard_stdin:
                        member_only_names.add(name)
                    caller.external_calls = unique_strings([
                        *caller.external_calls, api,
                    ])
                    begin = (item.get("range") or {}).get("begin") or {}
                    spelling = begin.get("spellingLoc") or begin
                    expansion = begin.get("expansionLoc") or begin
                    macro_expansion = bool(
                        begin.get("spellingLoc") and begin.get("expansionLoc")
                        and spelling.get("offset") != expansion.get("offset")
                    )
                    spelling_file = str(spelling.get("file") or path)
                    spelling_line = int(spelling.get("line") or line)
                    spelling_path = Path(spelling_file)
                    if not spelling_path.is_absolute():
                        spelling_path = (root / spelling_path).resolve()
                    lines = source.splitlines()
                    spelling_text = (
                        lines[spelling_line - 1]
                        if (spelling_path == path
                            and 1 <= spelling_line <= len(lines)) else ""
                    )
                    site = {
                        "api": api,
                        "line": line,
                        "offset": _loc(begin).get("offset"),
                        "provider": "clang-ast-cpp",
                        "analysis_unit": str(path),
                        "callee_linkage_symbol": str(
                            linkage_declarations.get(target_id, {}).get("symbol") or ""
                        ),
                        "callee_linkage_type": str(
                            linkage_declarations.get(target_id, {}).get("type") or ""
                        ),
                        "standard_library_input": standard_stdin,
                        "channel_hint": "stdin" if standard_stdin else "",
                        "destination_argument_positions": [0] if standard_stdin else [],
                        "compile_command_available": path in flags,
                        "macro_expansion": macro_expansion,
                        "direct_argument_identifiers": _direct_call_argument_identifiers(
                            item, local_declaration_ids,
                        ),
                        "direct_argument_declaration_ids": _direct_call_argument_declarations(item),
                        "direct_argument_field_bindings": _direct_call_argument_field_bindings(item),
                        "direct_argument_addressed_scalar_declaration_ids": (
                            _direct_call_addressed_scalar_declarations(
                                item, local_declarations,
                            )
                        ),
                        "spelling_file": spelling_file,
                        "spelling_line": spelling_line,
                        "spelling_source": spelling_text,
                    }
                    if site not in caller.external_call_sites:
                        caller.external_call_sites.append(site)
                elif target is None and scope == "member":
                    member_only_names.add(name)
            if resolved_names or member_only_names or unresolved_local_names:
                caller.external_calls = [
                    value for value in caller.external_calls
                    if (value.rsplit("::", 1)[-1] not in resolved_names
                        and value.rsplit("::", 1)[-1] not in member_only_names
                        and value.rsplit("::", 1)[-1] not in unresolved_local_names)
                    or value in external_names
                ]
    # Declaration IDs are local to one AST dump. Equal external linker
    # symbols and function types identify a possible cross-TU target, but
    # compilation alone does not prove that this executable links it.
    definitions_by_symbol: dict[tuple[str, str], list[FunctionMetadata]] = {}
    methods_by_name_type: dict[tuple[str, str], list[FunctionMetadata]] = {}
    for function in bundle.functions.values():
        if (function.linkage_external and function.linkage_symbol
            and function.linkage_type and "clang-ast-cpp" in function.providers):
            definitions_by_symbol.setdefault(
                (function.linkage_symbol, function.linkage_type), []
            ).append(function)
            methods_by_name_type.setdefault(
                (function.name, function.linkage_type), []
            ).append(function)
    edge_keys = {
        (edge.caller_id, edge.callee_id, edge.line, edge.kind)
        for edge in bundle.edges
    }
    for caller_id, line, symbol, signature, call_site in cross_unit_calls:
        matches = definitions_by_symbol.get((symbol, signature), [])
        if len(matches) != 1 or matches[0].function_id == caller_id:
            continue
        target = matches[0]
        caller = bundle.functions.get(caller_id)
        if caller is not None:
            navigation_site = {'callee_function_id': target.function_id,
                               **call_site}
            if navigation_site not in caller.direct_call_sites:
                caller.direct_call_sites.append(navigation_site)
        key = (caller_id, target.function_id, line, "source_candidate")
        if key in edge_keys:
            continue
        bundle.edges.append(CallEdge(
            edge_id=stable_id("clang-ast-cpp-cross-unit", *key),
            caller_id=caller_id, callee_id=target.function_id,
            line=line, kind="source_candidate", confidence=0.7,
            providers=["clang-ast-cpp", "linkage-symbol-match"],
        ))
        added_calls += 1
        adjacency_changed = True
        edge_keys.add(key)
    def derives_from(child: str, parent: str) -> bool:
        pending = list(class_bases.get(child, ()))
        seen: set[str] = set()
        while pending:
            current = pending.pop()
            if current == parent:
                return True
            if current not in seen:
                seen.add(current)
                pending.extend(class_bases.get(current, ()))
        return False

    # A virtual call through a base-class receiver may dispatch to any
    # compatible derived implementation. The AST hierarchy can locate those
    # implementations for source exploration, not select a runtime target.
    for caller_id, line, symbol, signature, _call_site in cross_unit_calls:
        virtual = virtual_methods.get(symbol)
        if virtual is None or virtual[2] != signature:
            continue
        owner, name, _method_type = virtual
        for target in methods_by_name_type.get((name, signature), []):
            if "::" not in target.qualified_name:
                continue
            target_owner = target.qualified_name.rsplit("::", 1)[0]
            if not derives_from(target_owner, owner):
                continue
            key = (caller_id, target.function_id, line, "source_candidate")
            if key in edge_keys:
                continue
            bundle.edges.append(CallEdge(
                edge_id=stable_id("clang-ast-cpp-virtual", *key),
                caller_id=caller_id, callee_id=target.function_id,
                line=line, kind="source_candidate", confidence=0.55,
                providers=["clang-ast-cpp", "virtual-override-candidate"],
            ))
            added_calls += 1
            adjacency_changed = True
            edge_keys.add(key)
    if added_functions or adjacency_changed:
        _populate_adjacency(bundle)
    return CppAstResult(
        parsed_files=parsed, failed_files=failed,
        unrecorded_files=unrecorded,
        added_functions=added_functions, added_calls=added_calls,
        budget_exhausted=exhausted,
        failure_diagnostics=tuple(diagnostics),
    )
