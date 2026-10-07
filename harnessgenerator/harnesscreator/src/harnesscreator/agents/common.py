from __future__ import annotations

import asyncio
import re
from typing import Any, Awaitable, Callable, Iterable, TypeVar

from ..models import FunctionMetadata


T = TypeVar("T")


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

    return await asyncio.gather(*(bounded(value) for value in values))


def function_payload(
    function: FunctionMetadata,
    source_limit: int = 16_000,
    *,
    focus_line: int | None = None,
) -> dict[str, Any]:
    source = function.source
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
