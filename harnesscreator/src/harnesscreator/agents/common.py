from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, TypeVar

from ..analysis.graph import GraphStore, _code_only
from ..models import FunctionMetadata, UsageArtifact


T = TypeVar("T")


def resolve_source_linked_function(
    requested: str,
    opened: list[str],
    choices: list[dict[str, object]],
    graph: Any,
) -> str:
    """Open one explicitly requested indexed function for inspection.

    The frontier suggests useful next reads; it cannot establish that every
    relevant caller or consumer has already been found.  Navigation is not
    evidence of a call path, input flow, or runtime reachability.
    """
    if not requested:
        return ""
    if requested in graph.bundle.functions:
        return requested if requested not in opened else ""
    matches = [function for function in graph.bundle.functions.values()
               if function.name == requested or function.qualified_name == requested]
    return matches[0].function_id if len(matches) == 1 and matches[0].function_id not in opened else ""


def _source_linked_declaration_artifact(
    source_root: Path,
    symbol: str,
    opened_functions: list[FunctionMetadata],
    graph: GraphStore,
) -> tuple[UsageArtifact, int] | None:
    """Locate one initializer used by opened code in its file/local headers.

    This is a source navigation lead when AST declaration metadata is absent.
    It does not resolve preprocessing conditions, namespaces, or runtime use.
    Ambiguous and nonlocal definitions remain unresolved.
    """
    if re.fullmatch(r"[A-Za-z_]\w*", symbol) is None:
        return None
    root = source_root.resolve()
    token = re.compile(rf"\b{re.escape(symbol)}\b")
    candidate_files: set[Path] = set()
    for function in opened_functions:
        if token.search(_code_only(function.source)) is None:
            continue
        source_file = (root / function.file).resolve()
        if not source_file.is_relative_to(root) or not source_file.is_file():
            continue
        candidate_files.add(source_file)
        try:
            raw = source_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for source_line, code_line in zip(raw.splitlines(), _code_only(raw).splitlines()):
            if re.match(r"\s*#\s*include\b", code_line) is None:
                continue
            include = re.match(r'\s*#\s*include\s+"([^"\r\n]+)"', source_line)
            if include is None:
                continue
            header = (source_file.parent / include.group(1)).resolve()
            if (header.is_relative_to(root) and header.is_file()
                and header.suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}):
                candidate_files.add(header)

    located: dict[str, tuple[UsageArtifact, int]] = {}
    for path in candidate_files:
        try:
            data = path.read_bytes()
            source = data.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        code = _code_only(source)
        relative = path.relative_to(root).as_posix()
        ranges = sorted(
            (function.start_line, function.end_line)
            for function in graph.bundle.functions.values()
            if function.file == relative
        )
        merged_ranges: list[tuple[int, int]] = []
        for start, end in ranges:
            if merged_ranges and start <= merged_ranges[-1][1] + 1:
                merged_ranges[-1] = (
                    merged_ranges[-1][0], max(merged_ranges[-1][1], end),
                )
            else:
                merged_ranges.append((start, end))
        code_lines = code.splitlines(keepends=True)
        position = 0
        range_index = 0
        definitions_in_file = 0
        for line_number, code_line in enumerate(code_lines, 1):
            while (range_index < len(merged_ranges)
                   and merged_ranges[range_index][1] < line_number):
                range_index += 1
            inside_function = (
                range_index < len(merged_ranges)
                and merged_ranges[range_index][0] <= line_number
            )
            match = token.search(code_line)
            if match is None or inside_function:
                position += len(code_line)
                continue
            macro = re.match(
                rf"\s*#\s*define\s+{re.escape(symbol)}\b", code_line,
            ) is not None
            initialized = re.search(
                r"(?<![=!<>])=(?!=)", code_line[match.end():],
            ) is not None
            if macro or initialized:
                definitions_in_file += 1
                if definitions_in_file > 1:
                    # Distinct conditional variants in one file must not be
                    # collapsed into the first lexical definition.
                    return None
                excerpt_start = max(0, position - 512)
                excerpt_start = source.rfind("\n", 0, excerpt_start) + 1
                located[relative] = (
                    UsageArtifact(
                        path=relative, kind="source_linked_declaration",
                        sha256=hashlib.sha256(data).hexdigest(),
                        rationale=f"{symbol} is named in opened source; initializer is an inspection lead",
                    ),
                    excerpt_start,
                )
            position += len(code_line)
    return next(iter(located.values())) if len(located) == 1 else None


def source_linked_numeric_definitions(
    source_root: Path,
    function: FunctionMetadata,
) -> list[dict[str, object]]:
    """Show numeric definitions used by a function in its local include chain.

    This is source context for request construction, not a claim that a
    particular preprocessing branch or runtime path is active.  A definition
    is returned only when its symbol occurs in the opened function body.
    """
    root = source_root.resolve()
    source_file = (root / function.file).resolve()
    if not source_file.is_relative_to(root) or not source_file.is_file():
        return []
    symbols = set(re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", _code_only(function.source)))
    if not symbols:
        return []
    include_pattern = re.compile(r'^\s*#\s*include\s+"([^"\r\n]+)"')
    define_pattern = re.compile(
        r'^\s*#\s*define\s+([A-Za-z_]\w*)\s+([+-]?(?:0[xX][0-9A-Fa-f]+|\d+))\b'
    )
    enum_pattern = re.compile(
        r'\b([A-Za-z_]\w*)\s*=\s*([+-]?(?:0[xX][0-9A-Fa-f]+|\d+))\b'
    )
    queue = [source_file]
    visited: set[Path] = set()
    found: dict[str, list[dict[str, object]]] = {}
    while queue:
        path = queue.pop(0)
        if path in visited:
            continue
        visited.add(path)
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        code_lines = _code_only(source).splitlines()
        source_lines = source.splitlines()
        for line_number, (source_line, code_line) in enumerate(
            zip(source_lines, code_lines), 1
        ):
            include = include_pattern.match(source_line)
            if include:
                for candidate in (path.parent / include.group(1),
                                  root / include.group(1)):
                    candidate = candidate.resolve()
                    if (candidate.is_relative_to(root) and candidate.is_file()
                        and candidate.suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}):
                        if candidate not in visited and candidate not in queue:
                            queue.append(candidate)
                        break
            macro = define_pattern.match(code_line)
            matches = [macro] if macro else list(enum_pattern.finditer(code_line))
            for match in matches:
                if match is None or match.group(1) not in symbols:
                    continue
                name, value = match.group(1), match.group(2)
                found.setdefault(name, []).append({
                    "name": name,
                    "value": value,
                    "file": path.relative_to(root).as_posix(),
                    "line": line_number,
                    "source": source_line.strip(),
                })
    return [
        {**definition, "ambiguous": len(definitions) > 1}
        for name in sorted(found)
        for definitions in (found[name],)
        for definition in definitions
    ]


def chunks(values: list[T], size: int) -> Iterable[list[T]]:
    for offset in range(0, len(values), size):
        yield values[offset: offset + size]


async def concurrent_map(
    values: list[T],
    function: Callable[[T], Awaitable[Any]],
    limit: int,
) -> list[Any]:
    if limit <= 1:
        return [await function(value) for value in values]
    semaphore = asyncio.Semaphore(limit)

    async def bounded(value: T) -> Any:
        async with semaphore:
            return await function(value)

    tasks = [asyncio.create_task(bounded(value)) for value in values]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        # asyncio.gather propagates the first exception but leaves siblings
        # running. Cancel them so one deterministic infrastructure error cannot
        # consume every queued LLM job after the workflow has already failed.
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def function_payload(
    function: FunctionMetadata,
    source_limit: int | None = None,
    *,
    focus_line: int | None = None,
) -> dict[str, Any]:
    source = function.source
    # A caller that omits a limit must receive the whole source body.
    # Silent clipping can otherwise turn an unread condition or cleanup
    # into a false context-complete decision. Large bodies need an explicit
    # page-by-page reader, not an implicit proof-affecting cutoff.
    if source_limit is None:
        source_limit = len(source) + 1
    if source_limit < 1:
        raise ValueError("source_limit must be positive")
    truncated = len(source) > source_limit
    excerpt_start_line = function.start_line
    excerpt_end_line = function.end_line
    if truncated:
        start_offset = 0
        if focus_line is not None and function.start_line <= focus_line <= function.end_line:
            relative_line = focus_line - function.start_line
            lines = source.splitlines(keepends=True)
            focus_offset = sum(len(line) for line in lines[:relative_line])
            start_offset = max(0, focus_offset - source_limit // 2)
            if start_offset:
                start_offset = source.find("\n", start_offset)
                start_offset = start_offset + 1 if start_offset >= 0 else 0
        end_offset = min(len(source), start_offset + source_limit)
        if end_offset < len(source):
            boundary = source.rfind("\n", start_offset, end_offset)
            if boundary > start_offset:
                end_offset = boundary + 1
        excerpt_start_line = function.start_line + source.count("\n", 0, start_offset)
        excerpt_end_line = excerpt_start_line + source.count("\n", start_offset, end_offset)
        prefix = "/* HARNESSCREATOR_SOURCE_PREFIX_TRUNCATED */\n" if start_offset else ""
        suffix = "\n/* HARNESSCREATOR_SOURCE_SUFFIX_TRUNCATED */" if end_offset < len(source) else ""
        source = prefix + source[start_offset:end_offset] + suffix
    return {
        "function_id": function.function_id,
        "name": function.name,
        "qualified_name": function.qualified_name,
        "signature": function.signature,
        "file": function.file,
        "start_line": function.start_line,
        "end_line": function.end_line,
        "source": source,
        "external_call_sites": list(function.external_call_sites),
        "referenced_global_declarations": list(
            function.referenced_global_declarations
        ),
        "indirect_table_call_sites": list(function.indirect_table_call_sites),
        "referenced_macro_definitions": list(
            function.referenced_macro_definitions
        ),
        "source_truncated": truncated,
        "source_excerpt_start_line": excerpt_start_line,
        "source_excerpt_end_line": excerpt_end_line,
        "declaration": function.declaration,
        "headers": sorted(function.headers),
        "callers": sorted(function.callers),
        "callees": sorted(function.callees),
        "external_calls": sorted(function.external_calls),
        "build_targets": sorted(function.build_targets),
    }


def function_payload_excerpts(
    function: FunctionMetadata,
    source_limit: int = 16_000,
) -> list[dict[str, Any]]:
    """Cover a complete function with bounded, line-aware source excerpts."""

    if len(function.source) <= source_limit:
        return [function_payload(function, source_limit)]
    source = function.source
    result: list[dict[str, Any]] = []
    base_payload = function_payload(function, max(len(source), 1))
    offset = 0
    line_offset = 0
    while offset < len(source):
        end = min(len(source), offset + source_limit)
        if end < len(source):
            boundary = source.rfind("\n", offset, end)
            if boundary > offset:
                end = boundary + 1
        if end <= offset:
            end = min(len(source), offset + source_limit)
        excerpt_start = function.start_line + line_offset
        excerpt_line_count = source.count("\n", offset, end)
        excerpt_end = excerpt_start + excerpt_line_count
        payload = dict(base_payload)
        payload.update({
            "source": (
                ("/* HARNESSCREATOR_SOURCE_PREFIX_TRUNCATED */\n" if offset else "")
                + source[offset:end]
                + ("\n/* HARNESSCREATOR_SOURCE_SUFFIX_TRUNCATED */" if end < len(source) else "")
            ),
            "source_truncated": True,
            "source_excerpt_start_line": excerpt_start,
            "source_excerpt_end_line": excerpt_end,
            "source_excerpt_index": len(result),
        })
        result.append(payload)
        offset = end
        line_offset += excerpt_line_count
    for payload in result:
        payload["source_excerpt_count"] = len(result)
    return result


def function_ref(function: FunctionMetadata) -> dict[str, Any]:
    """Source-free function identity for traces and diagnostics."""
    return {
        "function_id": function.function_id,
        "name": function.name,
        "qualified_name": function.qualified_name,
        "file": function.file,
        "start_line": function.start_line,
        "end_line": function.end_line,
    }


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


def object_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def is_non_product_build_target(value: str) -> bool:
    normalized = value.strip().casefold()
    if not normalized:
        return False
    tokens = [token for token in re.split(r"[^a-z0-9]+", normalized) if token]
    return normalized.startswith(("test", "fuzz", "bench")) or any(
        token in {"test", "tests", "testing", "fuzz", "fuzzer", "fuzzers", "bench", "benchmark"}
        for token in tokens
    )


def prefer_product_build_targets(values: Iterable[str]) -> list[str]:
    unique = list(dict.fromkeys(value for value in values if value))
    product = [value for value in unique if not is_non_product_build_target(value)]
    non_product = [value for value in unique if is_non_product_build_target(value)]
    return [*product, *non_product]
