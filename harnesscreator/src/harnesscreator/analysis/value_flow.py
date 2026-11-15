"""Conservative source navigation for direct buffer handoffs.

The Clang AST provides declaration identity for direct call arguments.  That
lets us distinguish ``read(buf); handle(buf)`` from a same-spelled but shadowed
variable.  A handoff is only a *candidate*: branches, intervening writes,
indirect aliases, call success and request identity require other evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from .graph import GraphStore
from .input_apis import DIRECT_BUFFER_OUTPUT_ARGUMENTS


@dataclass(frozen=True, slots=True)
class SourceBufferHandoff:
    caller_function_id: str
    entry_function_id: str
    target_function_id: str
    acquisition_api: str
    acquisition_line: int
    entry_call_line: int
    target_call_line: int
    buffer_name: str


def direct_sibling_buffer_handoffs(
    graph: GraphStore, entry_function_id: str, target_function_id: str,
) -> tuple[SourceBufferHandoff, ...]:
    """Locate an AST-backed buffer shared by an Entry and a sibling target.

    Only direct arguments and a direct acquisition output parameter are
    considered.  The result is a source-reading lead, never proof that the
    acquisition succeeded or that the handler consumed those bytes.
    """
    functions = graph.bundle.functions
    if entry_function_id not in functions or target_function_id not in functions:
        return ()
    entry = functions[entry_function_id]
    parameter_ids = [
        str(item.get("declaration_id") or "")
        for item in entry.ast_parameter_declarations
    ]
    outputs: list[tuple[str, int, int]] = []
    for site in entry.external_call_sites:
        api = str(site.get("api") or "")
        line = site.get("line")
        arguments = site.get("direct_argument_declaration_ids")
        if not isinstance(line, int) or not isinstance(arguments, list):
            continue
        for buffer_index in DIRECT_BUFFER_OUTPUT_ARGUMENTS.get(api, ()):
            if buffer_index >= len(arguments):
                continue
            declaration = str(arguments[buffer_index] or "")
            if declaration and declaration in parameter_ids:
                outputs.append((api, line, parameter_ids.index(declaration)))
    if not outputs:
        return ()

    found: set[SourceBufferHandoff] = set()
    for caller in graph.callers(entry_function_id):
        entry_calls = [
            site for site in caller.direct_call_sites
            if site.get("callee_function_id") == entry_function_id
            and isinstance(site.get("line"), int)
        ]
        target_calls = [
            site for site in caller.direct_call_sites
            if site.get("callee_function_id") == target_function_id
            and isinstance(site.get("line"), int)
        ]
        for api, acquisition_line, parameter_index in outputs:
            for entry_call in entry_calls:
                entry_arguments = entry_call.get("direct_argument_declaration_ids")
                entry_names = entry_call.get("direct_argument_identifiers")
                if (not isinstance(entry_arguments, list)
                    or not isinstance(entry_names, list)
                    or parameter_index >= len(entry_arguments)
                    or parameter_index >= len(entry_names)):
                    continue
                buffer_id = str(entry_arguments[parameter_index] or "")
                buffer_name = str(entry_names[parameter_index] or "")
                if not buffer_id or not buffer_name:
                    continue
                for target_call in target_calls:
                    if target_call["line"] <= entry_call["line"]:
                        continue
                    target_arguments = target_call.get("direct_argument_declaration_ids")
                    if not isinstance(target_arguments, list) or buffer_id not in target_arguments:
                        continue
                    found.add(SourceBufferHandoff(
                        caller_function_id=caller.function_id,
                        entry_function_id=entry_function_id,
                        target_function_id=target_function_id,
                        acquisition_api=api,
                        acquisition_line=acquisition_line,
                        entry_call_line=entry_call["line"],
                        target_call_line=target_call["line"],
                        buffer_name=buffer_name,
                    ))
    return tuple(sorted(
        found,
        key=lambda item: (
            item.caller_function_id, item.entry_call_line,
            item.target_call_line, item.acquisition_api,
        ),
    ))
