from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import replace
from typing import Iterable

from ..models import FunctionMetadata, OperationSeed, ProofStatus, stable_id
from .graph import GraphStore


_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CASE_RE = re.compile(r"^\s*case\s+(.+?)\s*:\s*(.*)$")
_DEFAULT_RE = re.compile(r"^\s*default\s*:\s*(.*)$")
_IF_START_RE = re.compile(r"\b(?:if|else\s+if)\s*\(")
_CONTROL_NAMES = {
    "if", "for", "while", "switch", "sizeof", "return", "assert",
}


def extract_operation_seeds(
    functions: Iterable[FunctionMetadata],
    graph: GraphStore,
    *,
    input_symbols: Iterable[str] | None = None,
) -> list[OperationSeed]:
    """Extract generic dispatcher work items from opened C/C++ source.

    The extractor records syntax and resolved project handlers only.  It does
    not decide that a branch is reachable or harnessable; those decisions stay
    with the source-walking input-action agent and runtime gates.
    """

    by_name: dict[str, list[str]] = defaultdict(list)
    for function in graph.bundle.functions.values():
        by_name[function.name].append(function.function_id)
        if function.qualified_name and function.qualified_name != function.name:
            by_name[function.qualified_name].append(function.function_id)

    # None is a syntax-only inspection. An explicit set means this inventory
    # is being scheduled from an Entry: conditional branches need a witnessed
    # input identifier even when their body calls another function.
    source_input_symbols = None if input_symbols is None else set(input_symbols)
    result: list[OperationSeed] = []
    seen: set[str] = set()
    for function in functions:
        lines = function.source.splitlines()
        case_indexes = [
            index for index, line in enumerate(lines)
            if _CASE_RE.match(line) or _DEFAULT_RE.match(line)
        ]
        for position, start in enumerate(case_indexes):
            line_text = lines[start]
            match = _CASE_RE.match(line_text)
            discriminator = (
                match.group(1).strip() if match else "default"
            )
            switch_end = _enclosing_block_end(lines, start)
            end = (
                min(case_indexes[position + 1], switch_end)
                if position + 1 < len(case_indexes) else switch_end
            )
            block = "\n".join(lines[start:end])
            handlers = _resolved_calls(block, by_name, function.function_id)
            unresolved_calls = _unresolved_or_indirect_calls(
                block, by_name, function
            )
            if unresolved_calls:
                handlers = _merge_function_ids(
                    handlers,
                    _possible_indirect_targets(
                        graph,
                        function.function_id,
                        start_line=function.start_line + start,
                        end_line=function.start_line + end,
                    ),
                )
            seed = _make_seed(
                function,
                discriminator,
                function.start_line + start,
                handlers,
                "switch_case",
                unresolved_calls,
                status=(
                    ProofStatus.POSSIBLE
                    if handlers
                    or unresolved_calls
                    or _branch_has_semantic_effect(block)
                    else ProofStatus.REFUTED
                ),
            )
            if seed.operation_seed_id not in seen:
                seen.add(seed.operation_seed_id)
                result.append(seed)

        # A conditional can implement an operation inline without calling a
        # handler. Keep it only when a source-flow walk supplies an identifier
        # carrying Entry bytes into the condition. Without that relation,
        # lifecycle/error branches would become unrelated operation work.
        for index, line in enumerate(lines):
            for condition, condition_end in _if_conditions_in_line(line):
                block, body_end = _conditional_body_with_end(
                    lines, index, condition_end
                )
                handlers = _resolved_calls(block, by_name, function.function_id)
                unresolved_calls = _unresolved_or_indirect_calls(
                    block, by_name, function
                )
                if unresolved_calls:
                    handlers = _merge_function_ids(
                        handlers,
                        _possible_indirect_targets(
                            graph,
                            function.function_id,
                            start_line=function.start_line + index,
                            end_line=function.start_line + body_end,
                        ),
                    )
                input_linked = (
                    source_input_symbols is not None
                    and _condition_uses_input(condition, source_input_symbols)
                )
                if source_input_symbols is not None and not input_linked:
                    continue
                if (
                    not handlers
                    and not unresolved_calls
                    and not (
                        _branch_has_semantic_effect(block)
                        and input_linked
                    )
                ):
                    continue
                discriminator = " ".join(condition.split())[:240]
                seed = _make_seed(
                    function,
                    discriminator,
                    function.start_line + index,
                    handlers,
                    "conditional_branch",
                    unresolved_calls,
                )
                if seed.operation_seed_id not in seen:
                    seen.add(seed.operation_seed_id)
                    result.append(seed)
    return result


def _if_conditions_in_line(line: str) -> list[tuple[str, int]]:
    """Read each balanced condition on a line without joining sibling ifs."""

    result: list[tuple[str, int]] = []
    for match in _IF_START_RE.finditer(line):
        depth = 1
        quote = ""
        escaped = False
        for position in range(match.end(), len(line)):
            char = line[position]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                continue
            if char in {'"', "'"}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    result.append((line[match.end():position], position + 1))
                    break
    return result


def _condition_uses_input(condition: str, input_symbols: set[str]) -> bool:
    if not input_symbols:
        return False
    identifiers = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", condition))
    return bool(identifiers & input_symbols)


def merge_operation_seed_records(
    seeds: Iterable[OperationSeed],
) -> list[OperationSeed]:
    """Merge repeated observations without allowing uncertainty to erase proof.

    The same source branch can be observed by the Entry-wide walk, a focused
    handler session, and a later structural replan.  Conflicting affirmative
    outcomes remain POSSIBLE for audit instead of selecting whichever result
    happened to finish last.
    """

    grouped: dict[str, list[OperationSeed]] = {}
    for operation_seed in seeds:
        grouped.setdefault(operation_seed.operation_seed_id, []).append(
            operation_seed
        )
    result: list[OperationSeed] = []
    # Dict insertion order preserves the source/graph discovery order.  Stable
    # IDs are used for deduplication, not scheduling: sorting hashes would make
    # the live branch order unrelated to the source and unreadable in traces.
    for operation_seed_id in grouped:
        records = grouped[operation_seed_id]
        statuses = {item.status for item in records}
        if (
            ProofStatus.PROVEN_STATIC in statuses
            and ProofStatus.REFUTED in statuses
        ):
            status = ProofStatus.POSSIBLE
        elif ProofStatus.PROVEN_RUNTIME in statuses:
            status = ProofStatus.PROVEN_RUNTIME
        elif ProofStatus.PROVEN_STATIC in statuses:
            status = ProofStatus.PROVEN_STATIC
        elif ProofStatus.REFUTED in statuses:
            status = ProofStatus.REFUTED
        else:
            status = ProofStatus.POSSIBLE
        result.append(replace(records[0], status=status))
    return result


def _enclosing_block_end(lines: list[str], start: int) -> int:
    """Stop a case at the switch's closing brace, not function tail.

    This is a conservative lexical boundary used only to build POSSIBLE work
    items.  It prevents calls after a switch from being attributed to its last
    case while leaving nested case bodies intact.
    """

    case_indent = len(lines[start]) - len(lines[start].lstrip())
    for index in range(start + 1, len(lines)):
        stripped = lines[index].lstrip()
        indent = len(lines[index]) - len(stripped)
        if stripped.startswith("}") and indent < case_indent:
            return index
    return len(lines)


def _conditional_body(
    lines: list[str],
    start: int,
    condition_end: int,
) -> str:
    return _conditional_body_with_end(lines, start, condition_end)[0]


def _conditional_body_with_end(
    lines: list[str],
    start: int,
    condition_end: int,
) -> tuple[str, int]:
    """Return only an if/else-if body.

    The previous fixed twelve-line window accidentally classified calls after
    an ordinary guard as handlers.  For example, ``if (read_failed) return;``
    followed by ``parse(input)`` became a fake parser operation.  A small
    brace-aware slice is sufficient for worklist extraction; later agents
    still validate every resulting seed against real source.
    """

    first = lines[start]
    suffix = first[condition_end:]
    opening = suffix.find("{")
    if opening < 0:
        inline = suffix.strip()
        if inline:
            return inline, start + 1
        for index, line in enumerate(lines[start + 1:], start + 1):
            if line.strip():
                return line, index + 1
        return "", start + 1

    body_parts: list[str] = []
    balance = 0
    started = False
    for index in range(start, len(lines)):
        fragment = lines[index]
        if index == start:
            fragment = suffix[opening:]
        if not started:
            position = fragment.find("{")
            if position >= 0:
                balance = 1
                started = True
                fragment = fragment[position + 1:]
        if not started:
            continue
        for offset, char in enumerate(fragment):
            if char == "{":
                balance += 1
            elif char == "}":
                balance -= 1
                if balance == 0:
                    body_parts.append(fragment[:offset])
                    return "\n".join(body_parts), index + 1
        body_parts.append(fragment)
    return "\n".join(body_parts), len(lines)


def _resolved_calls(
    source: str,
    by_name: dict[str, list[str]],
    dispatcher_id: str,
) -> list[str]:
    result: list[str] = []
    for name in _CALL_RE.findall(source):
        if name in _CONTROL_NAMES:
            continue
        matches = list(dict.fromkeys(by_name.get(name, [])))
        if len(matches) != 1 or matches[0] == dispatcher_id:
            continue
        if matches[0] not in result:
            result.append(matches[0])
    return result


def _unresolved_or_indirect_calls(
    source: str,
    by_name: dict[str, list[str]],
    function: FunctionMetadata,
) -> list[str]:
    """Whether a branch contains a call not uniquely resolved by its spelling.

    This is only a recall signal.  The possible targets still come from the
    locked call-graph providers and remain semantic-validation work items;
    this function never promotes a callback target to runtime proof.
    """

    result: list[str] = []
    for name in _CALL_RE.findall(source):
        if name in _CONTROL_NAMES:
            continue
        if len(list(dict.fromkeys(by_name.get(name, [])))) == 1:
            continue
        escaped = re.escape(name)
        member_call = re.search(
            rf"(?:->|\.)\s*{escaped}\s*\(", source
        )
        parameter_call = re.search(
            rf"\b{escaped}\b", function.signature
        )
        local_callable = re.search(
            rf"(?:\(\s*\*\s*{escaped}\s*\)|"
            rf"\b[A-Za-z_][A-Za-z0-9_]*(?:\s+[*A-Za-z_][A-Za-z0-9_]*)*"
            rf"\s+\**{escaped}\s*(?:=|;))",
            function.source,
        )
        if (member_call or parameter_call or local_callable) and name not in result:
            result.append(name)
    # Covers common table/dereference forms whose callee has no plain call
    # token, for example ``(*callback)(p)`` and ``table[index](p)``.
    if re.search(r"(?:\(\s*\*[^)]*\)|\[[^]]+\])\s*\(", source):
        result.append("<indirect-expression>")
    return result


def _possible_indirect_targets(
    graph: GraphStore,
    dispatcher_id: str,
    *,
    start_line: int,
    end_line: int,
) -> list[str]:
    """Resolve only targets attached to this exact branch callsite.

    SVF can conservatively report dozens of possible callees for a function.
    Assigning that whole set to every case/if branch creates a Cartesian
    product of unrelated handlers.  Function references are registration
    evidence rather than invocations, and line-less points-to edges cannot be
    attributed to one branch, so neither is promoted here.
    """

    result: list[str] = []
    for edge in graph.bundle.edges:
        if edge.caller_id != dispatcher_id:
            continue
        if edge.kind != "indirect_possible":
            continue
        if edge.line is None or not (start_line <= edge.line < end_line):
            continue
        if edge.callee_id not in graph.bundle.functions:
            continue
        if edge.callee_id not in result:
            result.append(edge.callee_id)
    return result


def _merge_function_ids(*groups: list[str]) -> list[str]:
    result: list[str] = []
    for group in groups:
        for function_id in group:
            if function_id not in result:
                result.append(function_id)
    return result


def _branch_has_semantic_effect(source: str) -> bool:
    """Conservatively distinguish inline work from a no-op/error branch."""

    lines = source.splitlines()
    if lines:
        case_match = _CASE_RE.match(lines[0])
        default_match = _DEFAULT_RE.match(lines[0])
        if case_match or default_match:
            inline = (
                case_match.group(2)
                if case_match is not None
                else default_match.group(1)
            )
            lines = [inline, *lines[1:]]
    body = " ".join(lines)
    body = re.sub(r"/\*.*?\*/|//[^\n]*", " ", body, flags=re.DOTALL)
    body = body.replace("{", " ").replace("}", " ")
    statements = [item.strip() for item in body.split(";") if item.strip()]
    for statement in statements:
        if statement in {"break", "continue"}:
            continue
        if re.fullmatch(
            r"return\s+(?:0|1|-1|NULL|nullptr|true|false|[A-Z_][A-Z0-9_]*)",
            statement,
        ):
            continue
        return True
    return False


def _make_seed(
    function: FunctionMetadata,
    discriminator: str,
    line: int,
    handlers: list[str],
    evidence_kind: str,
    unresolved_call_names: list[str],
    status: ProofStatus = ProofStatus.POSSIBLE,
) -> OperationSeed:
    return OperationSeed(
        operation_seed_id=stable_id(
            "opseed", function.function_id, line, discriminator,
            *handlers, *unresolved_call_names,
        ),
        dispatcher_function_id=function.function_id,
        discriminator=discriminator,
        line=line,
        handler_function_ids=handlers,
        evidence_kind=evidence_kind,
        status=status,
        unresolved_call_names=unresolved_call_names,
    )
