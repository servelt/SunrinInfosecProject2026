from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from ..models import AnalysisBundle, CallEdge, FunctionMetadata, stable_id, unique_strings


SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx"}
SKIP_DIRECTORY_NAMES = {
    ".git", ".harnesscreator", "build", "out", "runs", "harnesscreator-runs",
}
CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "return", "sizeof", "alignof"}
# C++ source can explicitly call a global API as ``::recv(...)``. Preserve
# its callee name when collecting external acquisition calls; the optional
# leading scope operator is syntax, not part of the function's short name.
CALL_RE = re.compile(r"(?<![\w:])(?:::)?([A-Za-z_~][\w]*(?:::[A-Za-z_~][\w]*)*)\s*\(")
IDENTIFIER_RE = re.compile(r"\b([A-Za-z_]\w*)\b")
FUNCTION_RE = re.compile(
    r"^[ \t]*(?P<header>(?:(?:template\s*<[^;{}]+>\s*)?)"
    # Keep pointer/reference declarators with the return type even when C
    # style places them directly beside the function name (``conn *conn_new``).
    # The previous expression required whitespace after ``*`` and therefore
    # omitted the whole function body that commonly owns callback assignment.
    r"(?:[A-Za-z_~][\w:<>,\[\] \t]*?(?:[ \t]+|(?=[*&]))(?:[*&][ \t]*)*)?"
    r"(?P<name>[A-Za-z_~][\w]*(?:::[A-Za-z_~][\w]*)*)[ \t]*"
    # The opening brace is frequently placed on the next line (Allman style).
    # The gap remains whitespace-only, so a prototype cannot consume a later
    # unrelated block.
    r"\((?P<params>[^;{}]*)\)\s*(?:const\s*)?(?:noexcept\s*)?\{)",
    re.MULTILINE,
)


class StaticAnalyzer:
    """Imports Fuzz Introspector output and fills gaps with a conservative C/C++ indexer."""

    def __init__(
        self,
        source_root: Path,
        fuzz_introspector: Path | None = None,
        *,
        require_fuzz_introspector: bool = False,
        excluded_paths: Iterable[Path] = (),
        compile_database: Path | None = None,
        target_binary: Path | None = None,
    ):
        self.source_root = source_root.resolve()
        self.fuzz_introspector = fuzz_introspector.resolve() if fuzz_introspector else None
        self.require_fuzz_introspector = require_fuzz_introspector
        self.excluded_paths = tuple(path.resolve() for path in excluded_paths)
        self.compile_database = compile_database.resolve() if compile_database else None
        self.target_binary = target_binary.resolve() if target_binary else None
        self.compile_database_files: set[str] = set()
        if self.compile_database is not None and not self.compile_database.is_file():
            raise ValueError(f"analysis compile database does not exist: {self.compile_database}")
        if self.compile_database is not None:
            try:
                records = json.loads(self.compile_database.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise ValueError(
                    f"cannot read analysis compile database {self.compile_database}: {exc}"
                ) from exc
            if not isinstance(records, list):
                raise ValueError(
                    f"analysis compile database is not an array: {self.compile_database}"
                )
            for record in records:
                if not isinstance(record, dict) or not record.get("file"):
                    continue
                directory = Path(str(record.get("directory") or self.compile_database.parent))
                source = Path(str(record["file"]))
                source = (source if source.is_absolute() else directory / source).resolve()
                if (source.is_file() and self.source_root in source.parents
                    and source.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".c++"}):
                    self.compile_database_files.add(
                        str(source.relative_to(self.source_root))
                    )
            if not self.compile_database_files:
                raise ValueError(
                    "analysis compile database has no existing C/C++ translation "
                    f"unit under source root {self.source_root}: {self.compile_database}"
                )

    def index(self) -> AnalysisBundle:
        report = self.resolve_fuzz_introspector_report()
        if not report:
            if self.require_fuzz_introspector:
                raise ValueError(
                    "Fuzz Introspector report not found. Pass --fuzz-introspector PATH, "
                    "or explicitly permit bootstrap analysis with --allow-source-analysis"
                )
            fallback = self._index_sources()
            fallback.completeness.update({
                "authoritative": False,
                "fuzz_introspector_used": False,
                "warning": (
                    "Fuzz Introspector was not used; caller/callee data comes from the "
                    "bootstrap source indexer"
                ),
            })
            return fallback
        fallback = self._index_sources()
        imported = self._import_fuzz_introspector(report)
        if not imported.functions:
            raise ValueError(f"no function records found in Fuzz Introspector report: {report}")
        merged = self._merge(imported, fallback)
        # --require-fuzz-introspector requires a usable report, not a claimed
        # complete call graph. FI's own calltree documentation describes
        # missing indirect edges even for compiled LLVM reports. The report's
        # function-name overlap is diagnostic and cannot prove graph closure.
        if (self.require_fuzz_introspector
            and fallback.functions
            and not merged.completeness.get(
                "fuzz_introspector_backed_source_functions", 0
            )):
            raise ValueError(
                "Fuzz Introspector report has no function matching this source "
                "checkout; pass the report for the requested project or use "
                "--allow-source-analysis"
            )
        return merged

    def resolve_fuzz_introspector_report(self) -> Path | None:
        """Resolve the exact report used by :meth:`index` without scanning sources."""
        if self.fuzz_introspector is not None:
            if not self.fuzz_introspector.exists():
                raise ValueError(
                    f"Fuzz Introspector report path does not exist: {self.fuzz_introspector}"
                )
            return self.fuzz_introspector
        return _discover_fuzz_introspector_report(self.source_root)

    def _index_sources(self) -> AnalysisBundle:
        functions: list[FunctionMetadata] = []
        paths = _iter_project_files(self.source_root, self.excluded_paths)
        for path in paths:
            try:
                if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                # A checkout can contain dangling or host-inaccessible links.
                # They are not source files and must not abort all indexing.
                continue
            functions.extend(self._parse_file(path, text))
        bundle = self._link(functions, provider="bootstrap-source")
        from .declarations import extract_declarations
        bundle.declarations = extract_declarations(self.source_root, paths).all()
        # Supplement the bootstrap index with real parsed C semantics when
        # Clang and usable compile flags are available. Unsupported or failed
        # TUs retain their original uncertain bootstrap evidence.
        from .clang_c import augment_c_ast
        stats = augment_c_ast(
            bundle, self.source_root, excluded_paths=self.excluded_paths,
            compile_database=self.compile_database,
            target_binary=self.target_binary,
        )
        from .clang_cpp import augment_cpp_ast
        cpp_stats = augment_cpp_ast(
            bundle, self.source_root, excluded_paths=self.excluded_paths,
            compile_database=self.compile_database,
            target_binary=self.target_binary,
        )
        # Include newly discovered macro-expanded FunctionDecls in the same
        # build-target/header lookup as ordinary source functions.
        self._augment_build_metadata(list(bundle.functions.values()))
        bundle.completeness.update({
            "analysis_compile_database": str(self.compile_database or ""),
            "analysis_target_binary": str(self.target_binary or ""),
            # A compile record is positive scheduling evidence for this
            # checkout, not proof that the object was linked into the target
            # executable. Bear can also record only an incremental build.
            "analysis_compile_database_files": sorted(self.compile_database_files),
            "analysis_compile_database_file_count": len(self.compile_database_files),
            "source_declaration_count": len(bundle.declarations),
            "clang_c_ast_parsed_files": stats.parsed_files,
            "clang_c_ast_failed_files": stats.failed_files,
            "clang_c_ast_unrecorded_files": stats.unrecorded_files,
            "clang_c_ast_failure_diagnostics": list(stats.failure_diagnostics),
            "clang_c_ast_added_functions": stats.added_functions,
            "clang_c_ast_added_calls": stats.added_calls,
            "clang_c_ast_budget_exhausted": stats.budget_exhausted,
            "clang_cpp_ast_parsed_files": cpp_stats.parsed_files,
            "clang_cpp_ast_failed_files": cpp_stats.failed_files,
            "clang_cpp_ast_unrecorded_files": cpp_stats.unrecorded_files,
            "clang_cpp_ast_failure_diagnostics": list(cpp_stats.failure_diagnostics),
            "clang_cpp_ast_added_functions": cpp_stats.added_functions,
            "clang_cpp_ast_added_calls": cpp_stats.added_calls,
            "clang_cpp_ast_budget_exhausted": cpp_stats.budget_exhausted,
        })
        return bundle

    def _parse_file(self, path: Path, text: str) -> list[FunctionMetadata]:
        relative = str(path.relative_to(self.source_root))
        results: list[FunctionMetadata] = []
        # Lexing and preprocessor-directive discovery are file-level work.
        # Repeating them once per function makes a large translation unit
        # quadratic and turned the correctness recovery in _matching_brace
        # into an avoidable indexing cost.
        lexical_view = _mask_comments_and_strings(text)
        declaration_view = _mask_preprocessor_lines(lexical_view)
        directives = _preprocessor_directives(lexical_view)
        for match in FUNCTION_RE.finditer(declaration_view):
            qualified = match.group("name")
            name = qualified.rsplit("::", 1)[-1]
            if name in CONTROL_WORDS:
                continue
            open_brace = match.end() - 1
            close_brace = _matching_brace(
                text,
                open_brace,
                structural_view=lexical_view,
                directives=directives,
            )
            if close_brace is None:
                continue
            start_line = text.count("\n", 0, match.start()) + 1
            end_line = text.count("\n", 0, close_brace) + 1
            source = text[match.start(): close_brace + 1]
            signature_text = text[match.start("header"):match.end("header") - 1]
            signature = " ".join(signature_text.split())
            results.append(
                FunctionMetadata.create(
                    name=name,
                    qualified_name=qualified,
                    signature=signature,
                    file=relative,
                    start_line=start_line,
                    end_line=end_line,
                    source=source,
                )
            )
        return results

    def _augment_build_metadata(self, functions: list[FunctionMetadata]) -> None:
        targets = _discover_build_targets(self.source_root, self.excluded_paths)
        declarations = _discover_header_declarations(self.source_root, self.excluded_paths)
        for function in functions:
            # A basename shared by two directories cannot establish that both
            # files are linked into the same executable. Preserve only exact
            # source-path membership; unknown membership remains unknown.
            function.build_targets = unique_strings(targets.get(function.file, []))
            matches = declarations.get(function.name, [])
            if matches:
                if 'clang-ast-c' in function.providers:
                    # Compiler-selected declarations were attached by the
                    # AST pass. A raw match is usable only when every visible
                    # variant agrees and its spelling exactly matches the
                    # parsed definition; otherwise it is navigation only.
                    function.headers = unique_strings([
                        *function.headers,
                        *(item[0] for item in matches),
                    ])
                    if not function.declaration:
                        variants = {item[1] for item in matches}
                        if len(variants) == 1:
                            lexical = next(iter(variants))
                            normalized = re.sub(r'^extern\s+', '', lexical).rstrip(';').strip()
                            if normalized == function.signature.strip():
                                function.declaration = lexical
                    continue
                same_directory = [
                    item for item in matches
                    if Path(item[0]).parent == Path(function.file).parent
                ]
                function.headers = unique_strings(item[0] for item in matches)
                selected_matches = same_directory or matches
                # A text scan cannot know which preprocessor branch was
                # active. Expose no selected prototype when it disagrees.
                if len({item[1] for item in selected_matches}) == 1:
                    function.declaration = selected_matches[0][1]

    def _link(self, functions: list[FunctionMetadata], provider: str) -> AnalysisBundle:
        by_name: dict[str, list[FunctionMetadata]] = {}
        for function in functions:
            by_name.setdefault(function.name, []).append(function)
            by_name.setdefault(function.qualified_name, []).append(function)

        edges: list[CallEdge] = []
        for function in functions:
            internal_callees: list[str] = []
            external: list[str] = []
            signature_end = function.source.find("{")
            body = function.source[signature_end + 1:] if signature_end >= 0 else function.source
            masked_body = _mask_comments_and_strings(body)
            direct_ranges: set[tuple[int, int]] = set()
            for call in CALL_RE.finditer(masked_body):
                called_name = call.group(1)
                direct_ranges.add((call.start(1), call.end(1)))
                short_name = called_name.rsplit("::", 1)[-1]
                if short_name in CONTROL_WORDS:
                    continue
                targets = by_name.get(called_name) or by_name.get(short_name) or []
                if call.group(0).startswith("::") and "::" not in called_name:
                    # ``::name`` explicitly requests the global scope. The
                    # bootstrap parser does not know whether an unqualified
                    # source definition named ``name`` is a global function
                    # or an inline class member. Avoid a fabricated direct
                    # edge to a same-named member; retain the external call
                    # for later compiler/source verification.
                    targets = []
                targets = _link_targets_for_caller(function, targets)
                call_line = function.start_line + body.count("\n", 0, call.start())
                if len(targets) == 1 and targets[0].function_id != function.function_id:
                    target = targets[0]
                    edge = CallEdge(
                        edge_id=stable_id("edge", function.function_id, target.function_id, call_line),
                        caller_id=function.function_id,
                        callee_id=target.function_id,
                        line=call_line,
                        confidence=0.75,
                        providers=[provider],
                    )
                    edges.append(edge)
                    internal_callees.append(target.function_id)
                elif not targets:
                    external.append(called_name)

            # Bootstrap analysis must retain callback registration and other
            # address-taken function relationships.  They are not proven direct
            # calls, so keep a lower-confidence, explicitly typed edge.  Without
            # this edge an event callback appears to have no callers and normal
            # lifecycle recovery incorrectly rejects the path as disconnected.
            for reference in IDENTIFIER_RE.finditer(masked_body):
                if (reference.start(1), reference.end(1)) in direct_ranges:
                    continue
                referenced_name = reference.group(1)
                targets = by_name.get(referenced_name) or []
                targets = _link_targets_for_caller(function, targets)
                if len(targets) != 1 or targets[0].function_id == function.function_id:
                    continue
                prefix = masked_body[max(0, reference.start() - 32):reference.start()]
                suffix = masked_body[reference.end():reference.end() + 8]
                if not _looks_like_function_reference(prefix, suffix):
                    continue
                target = targets[0]
                call_line = function.start_line + body.count("\n", 0, reference.start())
                edge = CallEdge(
                    edge_id=stable_id(
                        "edge-reference", function.function_id, target.function_id, call_line
                    ),
                    caller_id=function.function_id,
                    callee_id=target.function_id,
                    line=call_line,
                    kind="function_reference",
                    confidence=0.45,
                    providers=[provider],
                )
                edges.append(edge)
                internal_callees.append(target.function_id)
            function.callees = sorted(unique_strings(internal_callees))
            function.external_calls = unique_strings(external)

        callers: dict[str, list[str]] = {function.function_id: [] for function in functions}
        for edge in edges:
            callers[edge.callee_id].append(edge.caller_id)
        for function in functions:
            function.callers = sorted(unique_strings(callers[function.function_id]))
        return AnalysisBundle(
            functions={function.function_id: function for function in functions},
            edges=edges,
            completeness={
                "provider": provider,
                "source": True,
                "callers": "partial" if provider == "bootstrap-source" else "reported",
                "callees": "partial" if provider == "bootstrap-source" else "reported",
            },
        )
    def _import_fuzz_introspector(self, path: Path) -> AnalysisBundle:
        files = (
            [path]
            if path.is_file()
            else sorted([
                *path.rglob("*.json"),
                *path.rglob("*.yaml"),
                *path.rglob("*.yml"),
            ])
        )
        raw_functions: list[dict[str, Any]] = []
        for file in files:
            try:
                text = file.read_text(encoding="utf-8")
                if file.suffix.lower() == ".json":
                    payload = json.loads(text)
                else:
                    try:
                        import yaml  # type: ignore[import-untyped]
                    except ImportError as exc:
                        raise ValueError(
                            "PyYAML is required to import Fuzz Introspector YAML reports"
                        ) from exc
                    payload = yaml.safe_load(text)
            except (OSError, json.JSONDecodeError):
                continue
            raw_functions.extend(_find_function_records(payload))

        functions: list[FunctionMetadata] = []
        reported_callees: dict[str, list[str]] = {}
        for raw in raw_functions:
            name = _first(raw, "functionName", "Function name", "name", "func_name")
            source_file = _first(raw, "functionSourceFile", "Functions filename", "source_file", "file")
            if not name or not source_file:
                continue
            relative = _relative_source(str(source_file), self.source_root)
            start = _integer(_first(raw, "functionLinenumber", "Functions line number", "start_line"), 1)
            end = _integer(
                _first(
                    raw,
                    "functionLinenumberEnd",
                    "functionLineNumberEnd",
                    "Functions line number end",
                    "end_line",
                ),
                start,
            )
            source = str(_first(raw, "functionSource", "source", "source_code") or "")
            if not source:
                source = _read_source_slice(self.source_root / relative, start, end)
            # FI's build-free C/C++ frontend intentionally models function-like
            # macros as callable nodes.  They are useful to FI internally but
            # are not real functions and must not become Entry/Feature roots.
            if source.lstrip().startswith("#"):
                continue
            qualified_name = str(name)
            function = FunctionMetadata.create(
                name=_function_basename(qualified_name),
                qualified_name=qualified_name,
                signature=str(_first(raw, "functionSignature", "signature") or name),
                file=relative,
                start_line=start,
                end_line=max(start, end),
                source=source,
                provider="fuzz-introspector",
            )
            functions.append(function)
            reached = _first(raw, "Functions reached", "functionsReached", "callees") or []
            reported_callees[function.function_id] = [str(item) for item in reached if isinstance(item, str)]

        bundle = self._link(functions, provider="fuzz-introspector")
        by_name = {f.qualified_name: f for f in bundle.functions.values()} | {
            f.name: f for f in bundle.functions.values()
        }
        existing = {(edge.caller_id, edge.callee_id) for edge in bundle.edges}
        for caller_id, names in reported_callees.items():
            for name in names:
                callee = by_name.get(name) or by_name.get(name.rsplit("::", 1)[-1])
                if not callee or (caller_id, callee.function_id) in existing:
                    continue
                bundle.edges.append(
                    CallEdge(
                        edge_id=stable_id("edge", caller_id, callee.function_id, "fi"),
                        caller_id=caller_id,
                        callee_id=callee.function_id,
                        kind="reported",
                        confidence=0.9,
                        providers=["fuzz-introspector"],
                    )
                )
        _populate_adjacency(bundle)
        return bundle

    def _merge(self, primary: AnalysisBundle, fallback: AnalysisBundle) -> AnalysisBundle:
        by_location: dict[tuple[str, int, str], FunctionMetadata] = {}
        by_file_name: dict[tuple[str, str], list[tuple[str, int, str]]] = {}
        for function in fallback.function_list():
            key = (function.file, function.start_line, function.name)
            by_location[key] = function
            by_file_name.setdefault((function.file, function.name), []).append(key)
        for function in primary.function_list():
            key = (function.file, function.start_line, function.name)
            existing = by_location.get(key)
            if existing is None:
                compatible = by_file_name.get((function.file, function.name), [])
                if len(compatible) == 1:
                    key = compatible[0]
                    existing = by_location[key]
            if existing is None:
                by_location[key] = function
                by_file_name.setdefault((function.file, function.name), []).append(key)
                continue
            by_location[key] = replace(
                existing,
                source=function.source or existing.source,
                signature=function.signature or existing.signature,
                declaration=function.declaration or existing.declaration,
                headers=unique_strings([*existing.headers, *function.headers]),
                external_calls=unique_strings([*existing.external_calls, *function.external_calls]),
                external_call_sites=[
                    *existing.external_call_sites,
                    *[
                        site for site in function.external_call_sites
                        if site not in existing.external_call_sites
                    ],
                ],
                direct_call_sites=[
                    *existing.direct_call_sites,
                    *[
                        site for site in function.direct_call_sites
                        if site not in existing.direct_call_sites
                    ],
                ],
                guarded_call_sites=[
                    *existing.guarded_call_sites,
                    *[
                        site for site in function.guarded_call_sites
                        if site not in existing.guarded_call_sites
                    ],
                ],
                ast_parameter_declarations=(
                    function.ast_parameter_declarations
                    or existing.ast_parameter_declarations
                ),
                linkage_symbol=existing.linkage_symbol or function.linkage_symbol,
                linkage_type=existing.linkage_type or function.linkage_type,
                linkage_external=(existing.linkage_external or function.linkage_external),
                build_targets=unique_strings([*existing.build_targets, *function.build_targets]),
                providers=unique_strings([*existing.providers, *function.providers]),
            )
        merged = self._link(list(by_location.values()), provider="merged")
        merged_by_location = {
            (function.file, function.start_line, function.name): function.function_id
            for function in merged.functions.values()
        }
        merged_by_file_name: dict[tuple[str, str], list[str]] = {}
        for function in merged.functions.values():
            merged_by_file_name.setdefault((function.file, function.name), []).append(
                function.function_id
            )
        id_map: dict[str, str] = {}
        for source_bundle in (fallback, primary):
            for function in source_bundle.functions.values():
                target_id = merged_by_location.get((function.file, function.start_line, function.name))
                if target_id is None:
                    compatible_ids = merged_by_file_name.get((function.file, function.name), [])
                    if len(compatible_ids) == 1:
                        target_id = compatible_ids[0]
                if target_id:
                    id_map[function.function_id] = target_id
        for function in merged.functions.values():
            for site in function.direct_call_sites:
                target_id = site.get("callee_function_id")
                if target_id in id_map:
                    site["callee_function_id"] = id_map[target_id]
        edge_map = {(edge.caller_id, edge.callee_id, edge.line, edge.kind): edge for edge in merged.edges}
        for source_bundle in (fallback, primary):
            for edge in source_bundle.edges:
                caller = id_map.get(edge.caller_id)
                callee = id_map.get(edge.callee_id)
                if not caller or not callee:
                    continue
                edge_key = (caller, callee, edge.line, edge.kind)
                existing_edge = edge_map.get(edge_key)
                if existing_edge:
                    existing_edge.providers = unique_strings([*existing_edge.providers, *edge.providers])
                    existing_edge.confidence = max(existing_edge.confidence, edge.confidence)
                    continue
                copied = CallEdge(
                    edge_id=stable_id("edge", caller, callee, edge.line, edge.kind),
                    caller_id=caller,
                    callee_id=callee,
                    line=edge.line,
                    kind=edge.kind,
                    confidence=edge.confidence,
                    providers=list(edge.providers),
                )
                merged.edges.append(copied)
                edge_map[edge_key] = copied
        _populate_adjacency(merged)
        merged.declarations = list(fallback.declarations)
        fallback_functions = fallback.function_list()
        primary_counts = Counter(
            (function.file, function.name) for function in primary.functions.values()
        )
        fallback_counts = Counter(
            (function.file, function.name) for function in fallback_functions
        )
        fi_backed = sum(
            min(count, primary_counts[key]) for key, count in fallback_counts.items()
        )
        source_coverage = (
            fi_backed / len(fallback_functions)
            if fallback_functions
            else 1.0
        )
        fi_report_path = self.fuzz_introspector or _discover_fuzz_introspector_report(
            self.source_root
        )
        merged.completeness = {
            "provider": "fuzz-introspector+bootstrap-source",
            "authoritative": False,
            "fuzz_introspector_used": True,
            "fuzz_introspector_report": str(fi_report_path or ""),
            "source": True,
            "callers": "partial",
            "callees": "partial",
            "fuzz_introspector_functions": len(primary.functions),
            "bootstrap_source_functions": len(fallback.functions),
            "fuzz_introspector_backed_source_functions": fi_backed,
            "fuzz_introspector_source_coverage": round(source_coverage, 6),
            "graph_closure_proven": False,
        }
        if fi_report_path is not None:
            manifest = (
                fi_report_path / "manifest.json"
                if fi_report_path.is_dir()
                else fi_report_path.parent / "manifest.json"
            )
            try:
                metadata = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                metadata = {}
            if metadata.get("provider") == "fuzz-introspector-build-free-c-cpp":
                merged.completeness.update({
                    "fuzz_introspector_mode": "build-free-c-cpp",
                    "fuzz_introspector_version": metadata.get(
                        "fuzz_introspector_version", ""
                    ),
                    "fuzz_introspector_source_digest": metadata.get(
                        "source_digest", ""
                    ),
                    "fuzz_introspector_source_files": metadata.get("source_files", 0),
                })
        for key in (
            "analysis_compile_database", "analysis_target_binary",
            "analysis_compile_database_files",
            "analysis_compile_database_file_count",
            "source_declaration_count",
            "clang_c_ast_parsed_files", "clang_c_ast_failed_files",
            "clang_c_ast_unrecorded_files",
            "clang_c_ast_failure_diagnostics",
            "clang_c_ast_added_functions", "clang_c_ast_added_calls",
            "clang_c_ast_budget_exhausted",
            "clang_cpp_ast_parsed_files", "clang_cpp_ast_failed_files",
            "clang_cpp_ast_unrecorded_files",
            "clang_cpp_ast_failure_diagnostics",
            "clang_cpp_ast_added_functions", "clang_cpp_ast_added_calls",
            "clang_cpp_ast_budget_exhausted",
        ):
            if key in fallback.completeness:
                merged.completeness[key] = fallback.completeness[key]
        merged.completeness["warning"] = (
            "Fuzz Introspector was used; its function-name overlap covers "
            f"{source_coverage:.1%} of bootstrap-indexed source functions. "
            "This is not call-graph completeness: indirect calls and "
            "unparsed source may be missing"
        )
        return merged


def _discover_fuzz_introspector_report(root: Path) -> Path | None:
    """Find only well-known FI JSON artifacts; never ingest arbitrary run JSON."""
    patterns = (
        "allFunctions*.json",
        "allFunctionsWithMain-*.yaml",
        "allFunctionsWithMain-*.yml",
        "fuzzerLogFile*.data.yaml",
        "fuzzerLogFile*.data.yml",
        "fuzz-introspector*.json",
        "fuzz_introspector*.json",
    )
    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend(root.glob(pattern))
        candidates.extend(root.glob(f"build/**/{pattern}"))
        candidates.extend(root.glob(f"out/**/{pattern}"))
        candidates.extend(root.glob(f"inspector/**/{pattern}"))
        candidates.extend(root.glob(f"fuzz-introspector/**/{pattern}"))
        candidates.extend(root.glob(f"fuzz_introspector/**/{pattern}"))
    files = sorted({path.resolve() for path in candidates if path.is_file()})
    return files[0] if files else None


def _mask_preprocessor_lines(text: str) -> str:
    """Mask complete logical preprocessor directives while preserving offsets.

    A macro body such as ``#define DEBUG(...) fprintf(...)`` must never be
    mistaken for a function header that consumes the next real opening brace.
    """
    chars = list(text)
    offset = 0
    lines = text.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        line = lines[index]
        logical = [line]
        while logical[-1].rstrip("\r\n").rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            logical.append(lines[index])
        joined = "".join(logical)
        if line.lstrip().startswith("#"):
            for position in range(offset, offset + len(joined)):
                if chars[position] not in "\r\n":
                    chars[position] = " "
        offset += len(joined)
        index += 1
    return "".join(chars)


def _discover_build_targets(
    root: Path, excluded_paths: Iterable[Path] = ()
) -> dict[str, list[str]]:
    targets: dict[str, list[str]] = {}

    def add(source: str, target: str, directory: Path) -> None:
        if not Path(source).suffix.lower() in SOURCE_EXTENSIONS:
            return
        candidate = (directory / source).resolve()
        try:
            relative = str(candidate.relative_to(root))
        except ValueError:
            return
        targets.setdefault(relative, []).append(target)

    for makefile in _iter_project_files(root, excluded_paths):
        if makefile.name != "Makefile.am":
            continue
        try:
            text = makefile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        logical = re.sub(r"\\\r?\n", " ", text)
        for match in re.finditer(
            r"(?m)^[ \t]*(?P<target>[A-Za-z0-9_]+)_SOURCES[ \t]*(?:\+?=)[ \t]*(?P<sources>.*)$",
            logical,
        ):
            target = match.group("target").replace("_", "-")
            for token in re.split(r"\s+", match.group("sources").strip()):
                if token and not token.startswith("$("):
                    add(token, target, makefile.parent)

    cmake_call = re.compile(
        r"(?is)\badd_(?:executable|library)\s*\(\s*(?P<target>[^\s)]+)\s+(?P<sources>.*?)\)"
    )
    for cmake in _iter_project_files(root, excluded_paths):
        if cmake.name != "CMakeLists.txt":
            continue
        try:
            text = _mask_comments_and_strings(cmake.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for match in cmake_call.finditer(text):
            for token in re.split(r"\s+", match.group("sources").strip()):
                if token and "$" not in token:
                    add(token, match.group("target"), cmake.parent)

    # A JSON compilation database describes individual translation-unit
    # compile commands. Its `output` is usually an object file, not the
    # executable or library that links that object. The Clang AST indexer
    # reads the database separately; do not turn it into link membership.

    return {source: unique_strings(names) for source, names in targets.items()}


def _discover_header_declarations(
    root: Path, excluded_paths: Iterable[Path] = ()
) -> dict[str, list[tuple[str, str]]]:
    declarations: dict[str, list[tuple[str, str]]] = {}
    pattern = re.compile(
        r"(?m)^[ \t]*(?P<declaration>"
        r"(?:extern[ \t]+)?(?:[A-Za-z_~][\w:<>,*&\[\] \t]*?[ \t]+)"
        r"(?:[*&][ \t]*)*"
        r"(?P<name>[A-Za-z_~][\w]*(?:::[A-Za-z_~][\w]*)*)[ \t]*"
        r"\([^;{}]*\)[ \t]*(?:const[ \t]*)?;)"
    )
    for path in _iter_project_files(root, excluded_paths):
        try:
            if not path.is_file() or path.suffix.lower() not in {".h", ".hh", ".hpp", ".hxx"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # Broken or host-inaccessible links cannot provide declarations.
            continue
        view = _mask_preprocessor_lines(_mask_comments_and_strings(text))
        relative = str(path.relative_to(root))
        for match in pattern.finditer(view):
            name = match.group("name").rsplit("::", 1)[-1]
            declaration = " ".join(
                text[match.start("declaration"):match.end("declaration")].split()
            )
            declarations.setdefault(name, []).append((relative, declaration))
    return declarations


def _matching_brace(
    text: str,
    start: int,
    *,
    structural_view: str | None = None,
    directives: dict[int, tuple[str, int]] | None = None,
) -> int | None:
    """Return the closing brace while treating CPP branches as alternatives.

    Raw brace counting is wrong when equivalent ``#if`` and ``#else`` arms
    each open a common block: it observes both arms even though the compiler
    selects only one.  That previously made complete functions, including
    real program ``main`` functions, disappear from the source index.
    """
    if start < 0 or start >= len(text) or text[start] != "{":
        return None

    view = structural_view or _mask_comments_and_strings(text)
    if len(view) != len(text):
        return None
    directive_map = (
        directives
        if directives is not None
        else _preprocessor_directives(view, start)
    )
    depth = 0
    index = start
    # A frame records the structural depth before #if and the depth reached by
    # every alternative. zero_positions handles the uncommon valid form where
    # the function's final brace itself is duplicated inside each alternative.
    conditionals: list[dict[str, Any]] = []

    while index < len(view):
        directive = directive_map.get(index)
        if directive is not None:
            keyword, end = directive
            if keyword in {"if", "ifdef", "ifndef"}:
                conditionals.append({
                    "start_depth": depth,
                    "branches": [],
                    "saw_else": False,
                    "zero_positions": [],
                })
            elif keyword in {"elif", "else"} and conditionals:
                frame = conditionals[-1]
                frame["branches"].append(depth)
                depth = int(frame["start_depth"])
                if keyword == "else":
                    frame["saw_else"] = True
            elif keyword == "endif" and conditionals:
                frame = conditionals.pop()
                branches = [*frame["branches"], depth]
                if not frame["saw_else"]:
                    # No #else also has a condition-false alternative that
                    # leaves the structural depth unchanged.
                    branches.append(int(frame["start_depth"]))
                depth = _merge_conditional_depths(
                    branches, fallback=int(frame["start_depth"])
                )
                if conditionals:
                    conditionals[-1]["zero_positions"].extend(
                        frame["zero_positions"]
                    )
                elif depth == 0 and frame["zero_positions"]:
                    return max(frame["zero_positions"])
            index = end
            continue

        char = view[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                if not conditionals:
                    return index
                conditionals[-1]["zero_positions"].append(index)
            elif depth < 0:
                # Never absorb following functions when a source/configuration
                # view is structurally inconsistent.
                return None
        index += 1
    return None


def _preprocessor_directives(text: str, start: int = 0) -> dict[int, tuple[str, int]]:
    """Map directive hash offsets to ``(keyword, logical_line_end)``."""
    directives: dict[int, tuple[str, int]] = {}
    offset = 0
    lines = text.splitlines(keepends=True)
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        logical = [line]
        while (
            logical[-1].rstrip("\r\n").rstrip().endswith("\\")
            and line_index + 1 < len(lines)
        ):
            line_index += 1
            logical.append(lines[line_index])
        joined = "".join(logical)
        stripped = line.lstrip(" \t")
        if stripped.startswith("#"):
            hash_offset = offset + len(line) - len(stripped)
            if hash_offset >= start:
                match = re.match(r"#\s*([A-Za-z_]+)", stripped)
                if match:
                    directives[hash_offset] = (
                        match.group(1).lower(), offset + len(joined)
                    )
        offset += len(joined)
        line_index += 1
    return directives


def _merge_conditional_depths(depths: list[int], *, fallback: int) -> int:
    """Choose the best-supported structural depth across CPP alternatives."""
    if not depths:
        return fallback
    counts = Counter(depths)
    highest = max(counts.values())
    # Well-formed alternatives normally agree. Preserve source branch order
    # as a conservative deterministic recovery rule when configurations differ.
    return next(depth for depth in depths if counts[depth] == highest)


def _path_is_excluded(path: Path, excluded_paths: Iterable[Path]) -> bool:
    excluded = tuple(excluded_paths)
    if not excluded:
        return False
    resolved = path.resolve()
    return any(resolved == root or root in resolved.parents for root in excluded)


def _iter_project_files(root: Path, excluded_paths: Iterable[Path] = ()) -> list[Path]:
    """List source-tree files without entering excluded build/run directories.

    Filtering a completed ``rglob`` still traverses every run artifact.  A
    top-down walk prunes these directories before recursion.  This preserves
    the same included-file policy and deterministic global path order.
    """
    excluded = tuple(path.resolve() for path in excluded_paths)
    paths: list[Path] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        names[:] = sorted(
            name for name in names
            if name not in SKIP_DIRECTORY_NAMES
            and not name.startswith("runs-")
            and name != ".fuzz-introspector"
            and not (excluded and _path_is_excluded(current / name, excluded))
        )
        for name in files:
            path = current / name
            # Excluded output directories were already pruned above. Check
            # individual file/symlink exclusions only for inputs the indexer
            # can actually read; resolving every corpus or log file dominated
            # source discovery on result-heavy workspaces.
            relevant = (
                path.suffix.lower() in SOURCE_EXTENSIONS
                or name in {"Makefile.am", "CMakeLists.txt", "compile_commands.json"}
            )
            if excluded and relevant and _path_is_excluded(path, excluded):
                continue
            paths.append(path)
    return sorted(paths)


def _has_skipped_directory(path: Path, root: Path) -> bool:
    try:
        relative_parts = path.relative_to(root).parts[:-1]
    except ValueError:
        relative_parts = path.parts[:-1]
    return any(
        part in SKIP_DIRECTORY_NAMES
        or part.startswith("runs-")
        or part == ".fuzz-introspector"
        for part in relative_parts
    )


def _mask_comments_and_strings(text: str) -> str:
    pattern = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.DOTALL)
    return pattern.sub(lambda match: "".join("\n" if c == "\n" else " " for c in match.group(0)), text)


def _find_function_records(payload: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        keys = set(payload)
        if keys & {"functionName", "Function name", "func_name"} and keys & {
            "functionSourceFile", "Functions filename", "source_file", "file"
        }:
            records.append(payload)
        else:
            for value in payload.values():
                records.extend(_find_function_records(value))
    elif isinstance(payload, list):
        for item in payload:
            records.extend(_find_function_records(item))
    return records


def _first(raw: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in raw:
            return raw[name]
    return None


def _function_basename(value: str) -> str:
    without_parameters = value.split("(", 1)[0].strip()
    qualified = without_parameters.rsplit(" ", 1)[-1]
    return qualified.rsplit("::", 1)[-1]


def _looks_like_function_reference(prefix: str, suffix: str) -> bool:
    """Recognize common address-taking/registration syntax conservatively."""

    if suffix.lstrip().startswith("("):
        return False
    return bool(
        re.search(r"(?:&|=|,|\(|\{|\breturn)\s*$", prefix)
        or re.match(r"\s*[,)};]", suffix)
    )


def _link_targets_for_caller(
    caller: FunctionMetadata,
    candidates: Iterable[FunctionMetadata],
) -> list[FunctionMetadata]:
    """Disambiguate duplicate symbols with build-target ownership.

    Multi-target repositories often define the same callback name in a server
    and its test executable.  Global name uniqueness then suppresses the exact
    registration edge needed to recover normal callback flow.  FI build-target
    membership is authoritative enough to select a definition only when it
    leaves one candidate; otherwise the relationship remains unresolved.
    """

    targets = list({item.function_id: item for item in candidates}.values())
    targets = [item for item in targets if item.function_id != caller.function_id]
    if len(targets) <= 1:
        return targets
    caller_targets = set(caller.build_targets)
    if caller_targets:
        compatible = [
            item for item in targets
            if caller_targets.intersection(item.build_targets)
        ]
        if len(compatible) == 1:
            return compatible
        if compatible:
            targets = compatible
    same_file = [item for item in targets if item.file == caller.file]
    if len(same_file) == 1:
        return same_file
    return targets


def _integer(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@lru_cache(maxsize=8192)
def _relative_source(value: str, root: Path) -> str:
    candidate = Path(value)
    try:
        return str(candidate.resolve().relative_to(root))
    except (OSError, ValueError):
        pass

    # FI is frequently produced in a build container whose absolute source
    # prefix differs from the WSL/host checkout. Match the longest path suffix
    # against the current source root instead of treating that prefix as a new
    # project directory. Basename-only matches are accepted only when unique.
    parts = [part.casefold() for part in candidate.parts if part not in {"/", "\\"}]
    matches = [path for path in root.rglob(candidate.name) if path.is_file()]
    ranked: list[tuple[int, Path]] = []
    for match in matches:
        relative = match.relative_to(root)
        relative_parts = [part.casefold() for part in relative.parts]
        score = 0
        for left, right in zip(reversed(parts), reversed(relative_parts)):
            if left != right:
                break
            score += 1
        ranked.append((score, relative))
    if ranked:
        best_score = max(score for score, _ in ranked)
        best = sorted(
            {str(path) for score, path in ranked if score == best_score and score > 0}
        )
        if len(best) == 1:
            return best[0]
    return value.lstrip("/\\")


def _read_source_slice(path: Path, start: int, end: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[max(start - 1, 0): max(end, start)])


def _populate_adjacency(bundle: AnalysisBundle) -> None:
    callers: dict[str, list[str]] = {identifier: [] for identifier in bundle.functions}
    callees: dict[str, list[str]] = {identifier: [] for identifier in bundle.functions}
    for edge in bundle.edges:
        if edge.caller_id in callees and edge.callee_id in callers:
            callees[edge.caller_id].append(edge.callee_id)
            callers[edge.callee_id].append(edge.caller_id)
    for identifier, function in bundle.functions.items():
        function.callers = sorted(unique_strings(callers[identifier]))
        function.callees = sorted(unique_strings(callees[identifier]))
