"""Limit Entry search to the code a diff can be reached through (delta scans).

A delta scan only cares about inputs whose data can reach changed code.  An Input Entry sits at the
top of a call chain and the changed function somewhere below it, so the functions worth inspecting
for Entries are the changed functions plus every transitive caller of them in the call graph.

Indirect calls the graph does not know about can hide a caller; such an Entry is missed.  That is
the price of not inspecting the whole program, and the reason a diff that matches no function falls
back to the full inventory instead of searching nothing.
"""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path
from typing import Any

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def changed_lines(diff_text: str) -> dict[str, set[int]]:
    """{path in the new tree: line numbers touched}.  A pure deletion marks the line it sat at."""
    changed: dict[str, set[int]] = {}
    path: str | None = None
    new_line = 0
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            name = line[4:].split("\t")[0].strip()
            path = None if name == "/dev/null" else (name[2:] if name.startswith("b/") else name)
            continue
        if line.startswith("--- ") or path is None:
            continue
        match = _HUNK.match(line)
        if match:
            new_line = int(match.group(3))
            continue
        if line.startswith("+"):
            changed.setdefault(path, set()).add(new_line)
            new_line += 1
        elif line.startswith("-"):
            changed.setdefault(path, set()).add(max(1, new_line))
        elif line.startswith(" ") or line == "":
            new_line += 1
    return changed


def _same_file(function_file: str, diff_path: str) -> bool:
    a, b = Path(function_file).parts, Path(diff_path).parts
    n = min(len(a), len(b))
    return n > 0 and a[-n:] == b[-n:]


def _params(signature: str) -> list[str]:
    inner = signature[signature.find("(") + 1: signature.rfind(")")] if "(" in signature else ""
    parts = [p.strip() for p in _split_top(inner)]
    return [] if parts in ([], [""], ["void"]) else parts


def _split_top(text: str) -> list[str]:
    parts, depth, current = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += ch
    return parts + [current]


def _base_type(param: str) -> str:
    """'const client *c' -> 'client'"""
    words = [w for w in re.findall(r"[A-Za-z_]\w*", param) if w not in ("const", "struct", "unsigned", "signed",
                                                                            "volatile", "enum", "union")]
    return words[0] if len(words) >= 2 else (words[0] if words else "")


def _declared_type(source: str, variable: str) -> str:
    """Type `variable` is declared with in `source` ('client *c' -> 'client'), or ''."""
    skip = {"const", "struct", "unsigned", "signed", "volatile", "enum", "union", "static", "register", "return"}
    for match in re.finditer(r"([A-Za-z_]\w*)\s*[*&\s]\s*\**\s*" + re.escape(variable) + r"\s*[,;=)\[]", source):
        if match.group(1) not in skip:
            return match.group(1)
    return ""


def _indirect_sites(function: Any) -> list[tuple[int, str]]:
    """(argument count, declared type of the first argument) of each call through a pointer."""
    names = {n for n in (getattr(function, "external_calls", None) or []) if re.fullmatch(r"[A-Za-z_]\w*", n)}
    source = getattr(function, "source", "") or ""
    sites = []
    for match in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*\(|\(\s*\*\s*([A-Za-z_][\w.>-]*)\s*\)\s*\(", source):
        if match.group(1) and match.group(1) not in names:
            continue
        depth, i, args = 1, match.end(), ""
        while i < len(source) and depth:
            depth += {"(": 1, ")": -1}.get(source[i], 0)
            if depth:
                args += source[i]
            i += 1
        parts = [] if not args.strip() else _split_top(args)
        first = re.fullmatch(r"\s*&?\s*([A-Za-z_]\w*)\s*", parts[0]) if parts else None
        sites.append((len(parts), _declared_type(source, first.group(1)) if first else ""))
    return sites


def _indirect_callers(functions: dict[str, Any]) -> dict[tuple[int, str], set[str]]:
    """(argument count, first argument type) -> functions that make such a pointer call."""
    table: dict[tuple[int, str], set[str]] = {}
    for function_id, function in functions.items():
        for count, first_type in _indirect_sites(function):
            if count and first_type:
                table.setdefault((count, first_type), set()).add(function_id)
    return table


def diff_scope(functions: dict[str, Any], edges: list[Any], diff_text: str, max_depth: int = 0) -> dict[str, Any]:
    """Changed functions and their transitive callers.  `scope` is None when nothing matched."""
    changed = changed_lines(diff_text)
    seeds: list[str] = []
    for function_id, function in functions.items():
        for path, lines in changed.items():
            if _same_file(function.file, path) and any(
                    function.start_line <= line <= function.end_line for line in lines):
                seeds.append(function_id)
                break
    callers: dict[str, set[str]] = {}
    for edge in edges:
        callers.setdefault(edge.callee_id, set()).add(edge.caller_id)
    # A function nobody calls directly is usually called through a pointer (command tables,
    # callbacks).  Its callers are then the functions that make a pointer call with the same number of
    # arguments while handling the type of its first parameter.  An over-approximation, never proof.
    pointer_callers: dict[tuple[int, str], set[str]] | None = None
    indirect: dict[str, list[str]] = {}
    # Hub functions (a command dispatcher, an event loop) fan out upward until the whole server is in
    # scope, so the walk stops `max_depth` callers above the change (0 = no limit).
    depth = {seed: 0 for seed in seeds}
    scope, queue = set(seeds), deque(seeds)
    while queue:
        current = queue.popleft()
        if max_depth and depth[current] >= max_depth:
            continue
        found = callers.get(current, set())
        if not found:
            params = _params(getattr(functions[current], "signature", "") or "")
            if pointer_callers is None:
                pointer_callers = _indirect_callers(functions)
            found = pointer_callers.get((len(params), _base_type(params[0]) if params else ""), set()) - {current}
            if not params:
                found = set()        # f(void) through a pointer matches far too much to mean anything
            if found:
                indirect[functions[current].name] = sorted(functions[f].name for f in found)[:20]
        for caller in found:
            if caller not in scope:
                scope.add(caller)
                depth[caller] = depth[current] + 1
                queue.append(caller)
    # The acquisition site itself is usually not a caller of the change but a callee of one:
    # readQueryFromClient -> connRead -> (pointer) connSocketRead -> read().  Walking callers upward
    # never reaches it, so every function that calls a known input API is always inspected.
    from .input_apis import SOURCE_APIS
    acquisition = {fid for fid, function in functions.items()
                   if set(getattr(function, "external_calls", None) or ()) & SOURCE_APIS.keys()}
    if seeds:
        scope |= acquisition
    return {
        "acquisition_functions": len(acquisition),
        "changed_files": sorted(changed),
        "changed_functions": sorted(seeds),
        "changed_function_names": sorted({functions[f].name for f in seeds}),
        "max_depth": max_depth,
        "indirect_callers": indirect,
        "scope": scope if seeds else None,
        "scope_size": len(scope) if seeds else len(functions),
        "policy": "Entries are searched only among changed functions and their callers up to max_depth calls above; "
                  "no matched function means the whole inventory is searched",
    }
