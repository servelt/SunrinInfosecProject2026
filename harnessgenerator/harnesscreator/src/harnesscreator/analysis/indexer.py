from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from ..models import AnalysisBundle, CallEdge, FunctionMetadata, stable_id, unique_strings


SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
SKIP_DIRECTORY_NAMES = {
    ".git", ".harnesscreator", "build", "out", "runs", "harnesscreator-runs",
}
CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "return", "sizeof", "alignof"}
FI_AUTHORITATIVE_COVERAGE = 0.80
CALL_RE = re.compile(r"(?<![\w:])([A-Za-z_~][\w]*(?:::[A-Za-z_~][\w]*)*)\s*\(")
IDENTIFIER_RE = re.compile(r"\b([A-Za-z_]\w*)\b")
FUNCTION_RE = re.compile(
    r"^[ \t]*(?P<header>(?:(?:template\s*<[^;{}]+>\s*)?)"
    r"(?:[A-Za-z_~][\w:<>,*&\[\] \t]*?[ \t]+)?"
    r"(?P<name>[A-Za-z_~][\w]*(?:::[A-Za-z_~][\w]*)*)[ \t]*"
    r"\((?P<params>[^;{}]*)\)[ \t]*(?:const[ \t]*)?(?:noexcept[ \t]*)?\{)",
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
    ):
        self.source_root = source_root.resolve()
        self.fuzz_introspector = fuzz_introspector.resolve() if fuzz_introspector else None
        self.require_fuzz_introspector = require_fuzz_introspector
        self.excluded_paths = tuple(path.resolve() for path in excluded_paths)

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
        if self.require_fuzz_introspector and not merged.completeness.get("authoritative", False):
            coverage = float(merged.completeness.get("fuzz_introspector_source_coverage", 0.0))
            raise ValueError(
                "Fuzz Introspector report is present but insufficiently covers the indexed project "
                f"functions ({coverage:.1%} < {FI_AUTHORITATIVE_COVERAGE:.0%}). "
                "Pass a directory containing the complete project reports, or explicitly permit "
                "mixed bootstrap analysis with --allow-source-analysis"
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
        for path in sorted(self.source_root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            if _path_is_excluded(path, self.excluded_paths):
                continue
            if _has_skipped_directory(path, self.source_root):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            functions.extend(self._parse_file(path, text))
        self._augment_build_metadata(functions)
        return self._link(functions, provider="bootstrap-source")

    def _parse_file(self, path: Path, text: str) -> list[FunctionMetadata]:
        relative = str(path.relative_to(self.source_root))
        results: list[FunctionMetadata] = []
        declaration_view = _mask_preprocessor_lines(_mask_comments_and_strings(text))
        for match in FUNCTION_RE.finditer(declaration_view):
            qualified = match.group("name")
            name = qualified.rsplit("::", 1)[-1]
            if name in CONTROL_WORDS:
                continue
            open_brace = match.end() - 1
            close_brace = _matching_brace(text, open_brace)
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
        basename_targets: dict[str, list[str]] = {}
        for source_file, names in targets.items():
            basename_targets.setdefault(Path(source_file).name, []).extend(names)
        for function in functions:
            function.build_targets = unique_strings(
                [*targets.get(function.file, []), *basename_targets.get(Path(function.file).name, [])]
            )
            matches = declarations.get(function.name, [])
            if matches:
                same_directory = [
                    item for item in matches
                    if Path(item[0]).parent == Path(function.file).parent
                ]
                selected = (same_directory or matches)[0]
                function.headers = unique_strings(item[0] for item in matches)
                function.declaration = selected[1]

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
                targets = list({target.function_id: target for target in targets}.values())
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
                targets = list({target.function_id: target for target in targets}.values())
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
        edge_map = {(edge.caller_id, edge.callee_id, edge.line): edge for edge in merged.edges}
        for source_bundle in (fallback, primary):
            for edge in source_bundle.edges:
                caller = id_map.get(edge.caller_id)
                callee = id_map.get(edge.callee_id)
                if not caller or not callee:
                    continue
                edge_key = (caller, callee, edge.line)
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
            "authoritative": source_coverage >= FI_AUTHORITATIVE_COVERAGE,
            "fuzz_introspector_used": True,
            "fuzz_introspector_report": str(fi_report_path or ""),
            "source": True,
            "callers": "reported" if source_coverage >= FI_AUTHORITATIVE_COVERAGE else "partial",
            "callees": "reported" if source_coverage >= FI_AUTHORITATIVE_COVERAGE else "partial",
            "fuzz_introspector_functions": len(primary.functions),
            "bootstrap_source_functions": len(fallback.functions),
            "fuzz_introspector_backed_source_functions": fi_backed,
            "fuzz_introspector_source_coverage": round(source_coverage, 6),
            "authoritative_coverage_threshold": FI_AUTHORITATIVE_COVERAGE,
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
        if source_coverage < FI_AUTHORITATIVE_COVERAGE:
            merged.completeness["warning"] = (
                "Fuzz Introspector was used, but its file/function records cover only "
                f"{source_coverage:.1%} of bootstrap-indexed source functions; remaining graph "
                "metadata is non-authoritative"
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

    for makefile in sorted(root.rglob("Makefile.am")):
        if _path_is_excluded(makefile, excluded_paths):
            continue
        if _has_skipped_directory(makefile, root):
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
    for cmake in sorted(root.rglob("CMakeLists.txt")):
        if _path_is_excluded(cmake, excluded_paths):
            continue
        if _has_skipped_directory(cmake, root):
            continue
        try:
            text = _mask_comments_and_strings(cmake.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for match in cmake_call.finditer(text):
            for token in re.split(r"\s+", match.group("sources").strip()):
                if token and "$" not in token:
                    add(token, match.group("target"), cmake.parent)

    compile_databases = [root / "compile_commands.json", *root.glob("build/**/compile_commands.json")]
    for database in compile_databases:
        if _path_is_excluded(database, excluded_paths):
            continue
        if not database.is_file():
            continue
        try:
            records = json.loads(database.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict) or not record.get("file"):
                continue
            source = Path(str(record["file"]))
            directory = Path(str(record.get("directory", root)))
            if not source.is_absolute():
                source = directory / source
            try:
                relative = str(source.resolve().relative_to(root))
            except ValueError:
                continue
            command = str(record.get("command", ""))
            output = str(record.get("output", ""))
            if not output:
                output_match = re.search(r"(?:^|\s)-o\s+([^\s]+)", command)
                output = output_match.group(1) if output_match else "compile-database"
            targets.setdefault(relative, []).append(Path(output).name)

    return {source: unique_strings(names) for source, names in targets.items()}


def _discover_header_declarations(
    root: Path, excluded_paths: Iterable[Path] = ()
) -> dict[str, list[tuple[str, str]]]:
    declarations: dict[str, list[tuple[str, str]]] = {}
    pattern = re.compile(
        r"(?m)^[ \t]*(?P<declaration>"
        r"(?:extern[ \t]+)?(?:[A-Za-z_~][\w:<>,*&\[\] \t]*?[ \t]+)"
        r"(?P<name>[A-Za-z_~][\w]*(?:::[A-Za-z_~][\w]*)*)[ \t]*"
        r"\([^;{}]*\)[ \t]*(?:const[ \t]*)?;)"
    )
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".h", ".hh", ".hpp", ".hxx"}:
            continue
        if _path_is_excluded(path, excluded_paths):
            continue
        if _has_skipped_directory(path, root):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
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


def _matching_brace(text: str, start: int) -> int | None:
    depth = 0
    state = "code"
    index = start
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                state = "line_comment"
                index += 1
            elif char == "/" and nxt == "*":
                state = "block_comment"
                index += 1
            elif char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        elif state == "line_comment" and char == "\n":
            state = "code"
        elif state == "block_comment" and char == "*" and nxt == "/":
            state = "code"
            index += 1
        elif state in {"string", "char"}:
            if char == "\\":
                index += 1
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        index += 1
    return None


def _path_is_excluded(path: Path, excluded_paths: Iterable[Path]) -> bool:
    resolved = path.resolve()
    return any(resolved == root or root in resolved.parents for root in excluded_paths)


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
