"""Opt-in, tool-free Direction source windows with 800 source chars/function.

This is a development comparison arm. It leaves the historical Direction
input builder, product prompts, product scheduler and frozen runner unchanged.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

PREP = Path(__file__).resolve().parents[1]
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path[:0] = [str(PREP / 'review_tools'), str(PRODUCT / 'src')]

from development_direction_study import build_context_from_artifact  # noqa: E402
from vulnerabilityanalysis.adapter import HarnessAdapter  # noqa: E402
from vulnerabilityanalysis.source import SourceRepository  # noqa: E402


SOURCE_CHARS = 800
HEAD_CHARS = 200
CALL_CHARS = 400
TAIL_CHARS = 200
MAX_CALLS = 4
CONTEXT_CHARS = 300_000


def _line(source: str, start_line: int, offset: int) -> int:
    return start_line + source[:offset].count('\n')


def _range(length: int, center: int, width: int) -> tuple[int, int]:
    begin = max(0, min(length - width, center - width // 2))
    return begin, begin + width


def _selected_indices(total: int, count: int) -> list[int]:
    if total <= count:
        return list(range(total))
    if count == 1:
        return [total // 2]
    return sorted({round(i * (total - 1) / (count - 1)) for i in range(count)})


def window_excerpt(source: str, start_line: int,
                   callsite_lines: list[int]) -> dict:
    """Return explicit disjoint source windows, never silently join code."""
    if (not isinstance(source, str) or not source or
            type(start_line) is not int or start_line < 1 or
            not isinstance(callsite_lines, list) or
            any(type(line) is not int or line < 1 for line in callsite_lines)):
        raise ValueError('invalid Direction source or callsite line')
    length = len(source)
    callsites = sorted(set(callsite_lines))
    source_lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in source_lines:
        offsets.append(offsets[-1] + len(line))
    valid = [line for line in callsites
             if start_line <= line < start_line + len(source_lines)]
    if length <= SOURCE_CHARS:
        ranges = [(0, length)]
        selected = set(valid)
    else:
        ranges = [(0, HEAD_CHARS), (length - TAIL_CHARS, length)]
        selected_lines = [valid[index] for index in
                          _selected_indices(len(valid), MAX_CALLS)]
        selected = set(selected_lines)
        if selected_lines:
            width = CALL_CHARS // len(selected_lines)
            for line in selected_lines:
                index = line - start_line
                center = offsets[index] + len(source_lines[index]) // 2
                ranges.append(_range(length, center, width))
        else:
            ranges.append(_range(length, length // 2, CALL_CHARS))
        ranges.sort()
        merged: list[tuple[int, int]] = []
        for begin, end in ranges:
            if merged and begin <= merged[-1][1]:
                merged[-1] = merged[-1][0], max(merged[-1][1], end)
            else:
                merged.append((begin, end))
        ranges = merged
    # Column names are supplied once at Context level. Repeated JSON keys for
    # every window would consume a material share of the bounded model input.
    windows = [[begin, end, _line(source, start_line, begin), source[begin:end]]
               for begin, end in ranges]
    if sum(len(row[3]) for row in windows) > SOURCE_CHARS:
        raise ValueError('Direction source window exceeded 800 characters')
    omitted = []
    cursor = 0
    for begin, end in ranges:
        if cursor < begin:
            omitted.append([cursor, begin])
        cursor = end
    if cursor < length:
        omitted.append([cursor, length])
    return {
        'source_windows': windows,
        'source_truncated': bool(omitted),
        'omitted_ranges': omitted,
        'callsite_line_omitted': [line for line in callsites if line not in selected],
        'source_context_incomplete': bool(omitted or set(callsites) - selected),
    }


def build_windowed_context_from_artifact(
        artifact: Path, target_repository: Path, *,
        oss_fuzz_checkout: Path, upstream_checkout: Path) -> tuple[dict, dict]:
    """Use the existing qualified V2 input; change only source excerpt layout."""
    context, pins = build_context_from_artifact(
        artifact, target_repository, oss_fuzz_checkout=oss_fuzz_checkout,
        upstream_checkout=upstream_checkout, source_mode='all_catalog_prefix')
    harness = HarnessAdapter().load(artifact, target_repository=target_repository)
    root = harness.metadata.get('run_root')
    if not isinstance(root, str):
        raise ValueError('Direction Catalog root unavailable')
    analysis = Path(root) / 'analysis'
    calls: dict[str, list[int]] = {}
    for name, pin in (('edges.jsonl', 'edges_sha256'),
                      ('indirect_edges.jsonl', 'indirect_edges_sha256')):
        path = analysis / name
        if (path.is_symlink() or not path.is_file() or
                hashlib.sha256(path.read_bytes()).hexdigest() != pins[pin]):
            raise ValueError('Direction graph changed during window preparation')
        for raw in path.read_text(encoding='utf-8').splitlines():
            if not raw.strip():
                continue
            row = json.loads(raw)
            line = row.get('line')
            if type(line) is int and line > 0:
                calls.setdefault(row['caller_id'], []).append(line)
    repository = SourceRepository(Path(harness.target_repository),
                                  harness.function_catalog)
    excerpts = context['source_excerpts_by_graph_rule']
    if len(excerpts) != len(context['functions']):
        raise ValueError('window mode requires every Catalog function')
    for excerpt in excerpts:
        fid = excerpt['id']
        span = repository.open_function_span(fid)
        path = repository.source_path(fid)
        relative = path.relative_to(repository.root).as_posix()
        if (pins['source_files_sha256'].get(relative) != span.source_file_sha256 or
                excerpt.get('source_sha256') != span.source_sha256 or
                excerpt.get('source_prefix') != span.source[:SOURCE_CHARS]):
            raise ValueError('Direction source changed during window preparation')
        excerpt.pop('source_prefix')
        excerpt.update(window_excerpt(span.source, span.start_line,
                                      calls.get(fid, [])))
    context['source_excerpt_rule'] = (
        'all Catalog functions; <=800 source characters as head, recorded '
        'callsite windows, tail; omitted ranges explicit')
    context['source_window_columns'] = ['start_char', 'end_char', 'start_line', 'text']
    context['omitted_range_columns'] = ['start_char', 'end_char']
    context['source_window_policy'] = {
        'source_chars_per_function_max': SOURCE_CHARS,
        'head_chars': HEAD_CHARS, 'callsite_chars_total': CALL_CHARS,
        'tail_chars': TAIL_CHARS, 'recorded_calls_max': MAX_CALLS,
        'callsite_evidence': 'Catalog direct and unverified indirect edge source lines',
        'indirect_runtime_reachability': 'UNVERIFIED',
    }
    if len(json.dumps(context, sort_keys=True, ensure_ascii=False)) > CONTEXT_CHARS:
        raise ValueError('windowed Direction context exceeds 300000 characters')
    return context, pins
