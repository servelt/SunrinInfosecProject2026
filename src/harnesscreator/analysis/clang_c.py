"""Clang AST evidence supplement for C translation units.

The regex source bootstrap cannot see macro-expanded calls and definitions. This
module uses Clang's parsed AST to supplement (not overwrite) the existing graph.
Only direct CallExpr -> FunctionDecl edges are executable call evidence; taking
an address of a function remains a *reference*, never proof of execution.

This pass is best-effort: it does not infer compile flags or prove indirect
calls. Failed and unrecorded translation units stay in the source graph and
are counted separately.
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
from .indexer import _populate_adjacency, _path_is_excluded, _has_skipped_directory, _iter_project_files  # noqa: E402


@dataclass(frozen=True)
class AstResult:
    functions: int = 0
    added_functions: int = 0
    added_calls: int = 0
    added_references: int = 0
    parsed_files: int = 0
    failed_files: int = 0
    unrecorded_files: int = 0
    budget_exhausted: bool = False
    failure_diagnostics: tuple[dict[str, str], ...] = ()


def _compiler_diagnostic(stderr: str) -> str:
    """Keep the first actionable compiler error, without hiding its TU."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    return next((line for line in lines if 'error:' in line),
                lines[0] if lines else 'compiler failed without a diagnostic')[:500]


def _project_literal_includes(path: Path, root: Path) -> dict[Path, list[Path]]:
    """Read only source-root, quoted include edges for AST source locations.

    The compiler AST supplies the declaration identity and includer. This
    map only finds the physical text file; it never adds an AST declaration.
    """
    edges: dict[Path, list[Path]] = {}
    pending = [path.resolve()]
    while pending:
        parent = pending.pop()
        if parent in edges:
            continue
        try:
            source = parent.read_text(encoding='utf-8', errors='replace')
        except OSError:
            edges[parent] = []
            continue
        children: list[Path] = []
        for name in re.findall(r'^\s*#\s*include\s+"([^"\n]+)"', source, re.MULTILINE):
            for candidate in (parent.parent / name, root / name):
                candidate = candidate.resolve()
                if candidate.is_relative_to(root) and candidate.is_file():
                    children.append(candidate)
                    break
        edges[parent] = children
        pending.extend(child for child in children if child not in edges)
    return edges


def _loc(position: dict[str, Any]) -> dict[str, Any]:
    return position.get('expansionLoc') or position


def _line(position: dict[str, Any], source: str) -> int:
    pos = _loc(position)
    if pos.get('line'):
        return int(pos['line'])
    offset = pos.get('offset')
    if isinstance(offset, int) and 0 <= offset <= len(source):
        return source.count('\n', 0, offset) + 1
    return 0


def _main_file_definition(node: dict[str, Any], path: Path) -> bool:
    if node.get('kind') != 'FunctionDecl' or not any(
        x.get('kind') == 'CompoundStmt' for x in node.get('inner', ())
    ):
        return False
    loc = node.get('loc') or {}
    expansion = _loc(loc)
    # Included headers may define inline functions. They are not definitions
    # belonging to this translation unit and must not be imported as local.
    if expansion.get('includedFrom'):
        return False
    name = expansion.get('file')
    return not name or Path(str(name)).resolve() == path


def _callee_decl(node: dict[str, Any]) -> dict[str, Any] | None:
    if node.get('kind') == 'DeclRefExpr':
        ref = node.get('referencedDecl') or {}
        if ref.get('kind') == 'FunctionDecl':
            return ref
        return None
    # A function named inside an array index, argument, receiver, or
    # conditional expression is not the callee of the outer call.
    transparent = {
        'ImplicitCastExpr', 'ParenExpr', 'CStyleCastExpr',
        'CXXStaticCastExpr', 'CXXReinterpretCastExpr',
    }
    if node.get('kind') in transparent or (
        node.get('kind') == 'UnaryOperator' and node.get('opcode') == '*'
    ):
        children = list(_children(node))
        if len(children) == 1:
            return _callee_decl(children[0])
    return None


def _indirect_array_declaration(node: dict[str, Any]) -> dict[str, Any] | None:
    """Find the exact global array referenced as an indirect call's callee.

    Only transparent expression wrappers are stripped. An array mentioned in
    an argument or index expression is not the dispatch table.
    """

    while node.get('kind') in {
        'ImplicitCastExpr', 'ParenExpr', 'CStyleCastExpr',
        'CXXStaticCastExpr', 'CXXReinterpretCastExpr',
    }:
        children = list(_children(node))
        if len(children) != 1:
            return None
        node = children[0]
    if node.get('kind') != 'ArraySubscriptExpr':
        return None
    children = list(_children(node))
    if len(children) != 2:
        return None
    base = children[0]
    while base.get('kind') in {'ImplicitCastExpr', 'ParenExpr'}:
        operands = list(_children(base))
        if len(operands) != 1:
            return None
        base = operands[0]
    if base.get('kind') != 'DeclRefExpr':
        return None
    declaration = base.get('referencedDecl') or {}
    return declaration if declaration.get('kind') == 'VarDecl' else None


def _children(node: dict[str, Any]):
    for child in node.get('inner') or ():
        if isinstance(child, dict):
            yield child


def _walk(node: dict[str, Any]):
    yield node
    for child in _children(node):
        yield from _walk(child)


def _direct_call_argument_identifiers(
    call: dict[str, Any], local_declaration_ids: set[str],
) -> list[str]:
    """Name only direct variable arguments; reject fields and expressions.

    The first CallExpr child is the callee expression. A macro expansion can
    hide the written buffer from source-text call parsing, but Clang still
    resolves an argument such as ``data`` to its VarDecl/ParmVarDecl. This
    deliberately does not infer aliases, offsets, fields, or pointer-return
    helpers; those need separate evidence.
    """

    def direct_identifier(node: dict[str, Any]) -> str:
        kind = node.get('kind')
        if kind == 'DeclRefExpr':
            reference = node.get('referencedDecl') or {}
            if (reference.get('kind') in {'VarDecl', 'ParmVarDecl'}
                and str(reference.get('id')) in local_declaration_ids):
                return str(reference.get('name') or '')
            return ''
        children = list(_children(node))
        if len(children) != 1:
            return ''
        if kind in {
            'ImplicitCastExpr', 'CStyleCastExpr', 'CXXStaticCastExpr',
            'CXXReinterpretCastExpr', 'CXXConstCastExpr', 'ParenExpr',
            'ExprWithCleanups', 'MaterializeTemporaryExpr',
        }:
            return direct_identifier(children[0])
        if kind == 'UnaryOperator' and node.get('opcode') == '&':
            return direct_identifier(children[0])
        return ''

    return [direct_identifier(argument) for argument in list(_children(call))[1:]]


def _direct_call_argument_declarations(call: dict[str, Any]) -> list[str]:
    """Preserve declaration identity so shadowed names cannot be conflated."""
    def declaration(node: dict[str, Any]) -> str:
        if node.get('kind') == 'DeclRefExpr':
            ref = node.get('referencedDecl') or {}
            return (str(ref.get('id')) if ref.get('kind') in
                    {'VarDecl', 'ParmVarDecl'} else '')
        children = list(_children(node))
        if len(children) == 1 and node.get('kind') in {
            'ImplicitCastExpr', 'CStyleCastExpr', 'CXXStaticCastExpr',
            'CXXReinterpretCastExpr', 'CXXConstCastExpr', 'ParenExpr',
            'ExprWithCleanups', 'MaterializeTemporaryExpr',
        }:
            return declaration(children[0])
        if len(children) == 1 and node.get('kind') == 'UnaryOperator' and node.get('opcode') == '&':
            return declaration(children[0])
        return ''
    return [declaration(argument) for argument in list(_children(call))[1:]]


def _direct_call_argument_field_bindings(
    call: dict[str, Any],
) -> list[dict[str, str] | None]:
    """Locate an argument's direct struct/class field storage base.

    ``&this->buffer[index]`` and ``&ctx->buffer[index]`` identify the
    written field at the callsite. Index expressions are deliberately ignored.
    This is a source navigation fact, not a memory alias or runtime write
    proof. An expression with a nested/unknown receiver remains unresolved.
    """
    def unwrap(node: dict[str, Any]) -> dict[str, Any]:
        while node.get('kind') in {
            'ImplicitCastExpr', 'CStyleCastExpr', 'CXXStaticCastExpr',
            'CXXReinterpretCastExpr', 'CXXConstCastExpr', 'ParenExpr',
            'ExprWithCleanups', 'MaterializeTemporaryExpr',
        }:
            children = list(_children(node))
            if len(children) != 1:
                break
            node = children[0]
        return node

    def binding(argument: dict[str, Any]) -> dict[str, str] | None:
        node = unwrap(argument)
        if node.get('kind') == 'UnaryOperator' and node.get('opcode') == '&':
            children = list(_children(node))
            if len(children) != 1:
                return None
            node = unwrap(children[0])
        if node.get('kind') == 'ArraySubscriptExpr':
            children = list(_children(node))
            if len(children) != 2:
                return None
            node = unwrap(children[0])
        if node.get('kind') != 'MemberExpr':
            return None
        field_id = str(node.get('referencedMemberDecl') or '')
        field_name = str(node.get('name') or '')
        children = list(_children(node))
        if not field_id or not field_name or len(children) != 1:
            return None
        owner = unwrap(children[0])
        if owner.get('kind') == 'CXXThisExpr':
            return {'field_name': field_name, 'field_declaration_id': field_id,
                    'receiver_kind': 'this', 'receiver_declaration_id': ''}
        if owner.get('kind') == 'DeclRefExpr':
            declaration = owner.get('referencedDecl') or {}
            if declaration.get('kind') in {'VarDecl', 'ParmVarDecl'} and declaration.get('id'):
                return {
                    'field_name': field_name, 'field_declaration_id': field_id,
                    'receiver_kind': 'declaration',
                    'receiver_declaration_id': str(declaration['id']),
                }
        return None

    return [binding(argument) for argument in list(_children(call))[1:]]


def _direct_call_addressed_scalar_declarations(
    call: dict[str, Any], declarations: dict[str, dict[str, Any]],
) -> list[str]:
    """Identify local scalar objects passed by address to an input call."""
    result: list[str] = []
    for argument in list(_children(call))[1:]:
        addressed = next((part for part in _walk(argument)
                          if part.get('kind') == 'UnaryOperator'
                          and part.get('opcode') == '&'), None)
        if addressed is None:
            result.append('')
            continue
        refs = [part for part in _walk(addressed)
                if part.get('kind') == 'DeclRefExpr']
        if len(refs) != 1:
            result.append('')
            continue
        identifier = str((refs[0].get('referencedDecl') or {}).get('id') or '')
        declaration = declarations.get(identifier, {})
        kind = declaration.get('kind')
        spelling = str((declaration.get('type') or {}).get('qualType') or '')
        result.append(identifier if (
            kind in {'VarDecl', 'ParmVarDecl'} and spelling
            and '[' not in spelling and not spelling.startswith(
                ('struct ', 'class ', 'union ')
            )
        ) else '')
    return result


def _top_level_constant_scalar_overwrites(
    function: dict[str, Any],
) -> list[dict[str, Any]]:
    """Find narrow, definite source-navigation kills, not general taint facts.

    Only an entire local numeric scalar assigned a literal in a direct body
    statement qualifies. A conditional write, array element write, pointer
    write, computed RHS, or a function with source-level goto/label remains
    unresolved. This never proves that other effects are input-independent.
    """
    if any(item.get('kind') in {'GotoStmt', 'IndirectGotoStmt', 'LabelStmt'}
           for item in _walk(function)):
        return []
    body = next((item for item in _children(function)
                 if item.get('kind') == 'CompoundStmt'), None)
    if body is None:
        return []
    scalar_types = {
        'char', 'signed char', 'unsigned char', 'short', 'short int',
        'unsigned short', 'unsigned short int', 'int', 'unsigned int',
        'long', 'long int', 'unsigned long', 'unsigned long int',
        'long long', 'long long int', 'unsigned long long',
        'unsigned long long int', 'bool', '_Bool', 'float', 'double',
    }
    scalar_declarations = {
        str(item.get('id'))
        for item in _walk(function)
        if item.get('kind') in {'VarDecl', 'ParmVarDecl'}
        and str((item.get('type') or {}).get('qualType', '')) in scalar_types
    }

    def declaration(node: dict[str, Any]) -> str:
        if node.get('kind') == 'DeclRefExpr':
            ref = node.get('referencedDecl') or {}
            return str(ref.get('id') or '')
        if node.get('kind') in {'ParenExpr', 'ImplicitCastExpr'}:
            children = list(_children(node))
            if len(children) == 1:
                return declaration(children[0])
        return ''

    def literal(node: dict[str, Any]) -> bool:
        if node.get('kind') in {
            'IntegerLiteral', 'CharacterLiteral', 'FloatingLiteral',
            'CXXBoolLiteralExpr', 'CXXNullPtrLiteralExpr',
        }:
            return True
        if node.get('kind') in {
            'ParenExpr', 'ImplicitCastExpr', 'ConstantExpr',
        } or (node.get('kind') == 'UnaryOperator'
              and node.get('opcode') in {'+', '-', '!', '~'}):
            children = list(_children(node))
            return len(children) == 1 and literal(children[0])
        return False

    overwrites: list[dict[str, Any]] = []
    for statement in _children(body):
        if statement.get('kind') != 'BinaryOperator' or statement.get('opcode') != '=':
            continue
        operands = list(_children(statement))
        if len(operands) != 2 or not literal(operands[1]):
            continue
        declaration_id = declaration(operands[0])
        offset = _loc((statement.get('range') or {}).get('begin') or {}).get('offset')
        if declaration_id in scalar_declarations and isinstance(offset, int):
            overwrites.append({'declaration_id': declaration_id, 'offset': offset})
    return overwrites


def _guarded_call_sites(node: dict[str, Any], source: str) -> list[dict[str, Any]]:
    """Record declaration-resolved control dependencies for call navigation.

    This is a source-navigation index, not a full PDG or runtime proof. A
    condition must refer to a particular declaration, and the target call
    must occur within the selected statement subtree.
    """
    result: list[dict[str, Any]] = []
    literal_overwrites = _top_level_constant_scalar_overwrites(node)
    # A parser often reduces acquired bytes to a local command variable:
    # `int cmd = decode(input); if (cmd == X) handle();`. Preserve Clang's
    # declaration identities for that initializer chain as navigation only.
    # This is not a CFG/SSA proof: calls may ignore arguments, branches may
    # overwrite locals, and the initializer may not run for the request.
    local_initializers: dict[str, tuple[set[str], int]] = {}
    for declaration in _walk(node):
        if declaration.get('kind') != 'VarDecl' or not declaration.get('init'):
            continue
        children = list(_children(declaration))
        offset = _loc(declaration.get('loc') or {}).get('offset')
        if len(children) != 1 or not isinstance(offset, int):
            continue
        referenced = {
            str((ref.get('referencedDecl') or {}).get('id'))
            for ref in _walk(children[0])
            if ref.get('kind') == 'DeclRefExpr'
            and (ref.get('referencedDecl') or {}).get('kind')
                in {'VarDecl', 'ParmVarDecl'}
            and (ref.get('referencedDecl') or {}).get('id')
        }
        if referenced:
            local_initializers[str(declaration.get('id'))] = (referenced, offset)

    def initializer_origins(
        declaration_id: str, seen: set[str], latest_offset: int,
    ) -> list[tuple[str, int]]:
        if declaration_id in seen:
            return []
        initializer = local_initializers.get(declaration_id)
        if initializer is None:
            return [(declaration_id, latest_offset)]
        referenced, offset = initializer
        earliest = min(latest_offset, offset)
        return [
            origin
            for dependency in referenced
            for origin in initializer_origins(
                dependency, {*seen, declaration_id}, earliest,
            )
        ]

    def content_reads(expression: dict[str, Any]) -> set[str]:
        """Find declarations whose pointed-to/array contents a guard reads.

        Merely mentioning ``buf`` in ``if (buf)`` observes the pointer, not
        bytes written by a preceding read. Unknown call side effects are left
        for source inspection; this small AST fact is only a navigation lead.
        """
        found: set[str] = set()

        def visit(part: dict[str, Any]) -> None:
            kind = part.get('kind')
            # Taking an address or computing a sizeof operand need not read
            # the object. Neither establishes dependence on acquired bytes.
            if (kind == 'UnaryOperator' and part.get('opcode') == '&') or (
                kind == 'UnaryExprOrTypeTraitExpr'
                and part.get('name') in {'sizeof', 'alignof'}
            ):
                return
            if kind == 'ArraySubscriptExpr' or (
                kind == 'UnaryOperator' and part.get('opcode') == '*'
            ):
                operands = list(_children(part))
                if operands:
                    for ref in _walk(operands[0]):
                        if ref.get('kind') != 'DeclRefExpr':
                            continue
                        declaration = ref.get('referencedDecl') or {}
                        if declaration.get('kind') in {'VarDecl', 'ParmVarDecl'}:
                            found.add(str(declaration.get('id')))
            for child in _children(part):
                visit(child)

        visit(expression)
        return found

    for guard in _walk(node):
        kind = guard.get('kind')
        children = list(_children(guard))
        if not children:
            continue
        # These are Clang AST control-expression relationships, not Action
        # categories.  Keep declaration identity and exact call targets; a
        # call in the selected subtree is only a source-navigation question.
        if kind in {'IfStmt', 'SwitchStmt'}:
            body_index = len(children) - (
                2 if kind == 'IfStmt' and guard.get('hasElse') else 1
            )
            condition_index = body_index - 1
            bodies = children[body_index:]
        elif kind == 'WhileStmt':
            condition_index = len(children) - 2
            bodies = children[-1:]
        elif kind == 'ForStmt':
            # Clang keeps empty init/condition/increment slots in the JSON
            # AST.  The condition is the third child from the end.
            condition_index = len(children) - 3
            bodies = children[-1:]
        elif kind == 'ConditionalOperator':
            condition_index = 0
            bodies = children[1:]
        elif kind == 'BinaryOperator' and guard.get('opcode') in {'&&', '||'}:
            condition_index = 0
            bodies = children[1:2]
        else:
            continue
        if condition_index < 0 or condition_index >= len(children):
            continue
        condition = children[condition_index]
        declarations = {
            str((ref.get('referencedDecl') or {}).get('id'))
            for ref in _walk(condition)
            if ref.get('kind') == 'DeclRefExpr'
            and (ref.get('referencedDecl') or {}).get('kind') in {'VarDecl', 'ParmVarDecl'}
        }
        if not declarations:
            continue
        guard_offset = _loc((guard.get('range') or {}).get('begin') or {}).get('offset')
        initializer_sources = [
            {'source_declaration_id': source_id,
             'condition_declaration_id': declaration_id,
             'initializer_offset': earliest}
            for declaration_id in declarations
            if declaration_id in local_initializers
            for source_id, earliest in initializer_origins(
                declaration_id, set(), guard_offset
                if isinstance(guard_offset, int) else 0,
            )
            if source_id != declaration_id
        ]
        content_declarations = content_reads(condition)
        for body in bodies:
            for call in _walk(body):
                if call.get('kind') not in {'CallExpr', 'CXXMemberCallExpr'}:
                    continue
                operands = list(_children(call))
                ref = _callee_decl(operands[0]) if operands else None
                if ref is None and operands:
                    # C++ member calls reference a method declaration through
                    # MemberExpr rather than DeclRefExpr. This remains a
                    # navigation lead; virtual dispatch is not resolved here.
                    member = next((item for item in _walk(operands[0])
                                   if item.get('kind') == 'MemberExpr'
                                   and item.get('referencedMemberDecl')), None)
                    if member is not None:
                        ref = {
                            'id': member.get('referencedMemberDecl'),
                            'name': member.get('name'),
                        }
                if ref is None:
                    continue
                line = _line((call.get('range') or {}).get('begin') or {}, source)
                site = {
                    'guard_line': _line((guard.get('range') or {}).get('begin') or {}, source),
                    'guard_offset': _loc((guard.get('range') or {}).get('begin') or {}).get('offset'),
                    'call_line': line,
                    'callee_name': str(ref.get('name') or ''),
                    'callee_declaration_id': str(ref.get('id') or ''),
                    'condition_declaration_ids': sorted(declarations),
                    'condition_initializer_sources': initializer_sources,
                    'condition_content_declaration_ids': sorted(content_declarations),
                    'preceding_constant_scalar_overwrites': [
                        item for item in literal_overwrites
                        if item['declaration_id'] in declarations
                        and isinstance(_loc((guard.get('range') or {}).get('begin') or {}).get('offset'), int)
                        and item['offset'] < _loc((guard.get('range') or {}).get('begin') or {})['offset']
                    ],
                    'provider': 'clang-ast',
                }
                if site not in result:
                    result.append(site)
    return result


def _parameter_output_positions(node: dict[str, Any]) -> list[int]:
    """Locate direct writes through formal pointer, array or reference args.

    This syntactic fact is for navigation from a producer call to a later
    guard. It does not establish which branch executes or whether a write is
    reached on a particular request.
    """
    parameters = [item for item in _children(node)
                  if item.get('kind') == 'ParmVarDecl']
    by_id = {str(item.get('id')): index for index, item in enumerate(parameters)
             if item.get('id')}
    result: set[int] = set()
    for operation in _walk(node):
        if operation.get('kind') not in {'BinaryOperator', 'CompoundAssignOperator'}:
            continue
        if (operation.get('kind') == 'BinaryOperator'
            and operation.get('opcode') != '='):
            continue
        operands = list(_children(operation))
        if len(operands) < 2:
            continue
        lhs = operands[0]
        lhs_kind = lhs.get('kind')
        dereference = lhs_kind in {'ArraySubscriptExpr', 'MemberExpr'} or (
            lhs_kind == 'UnaryOperator' and lhs.get('opcode') == '*'
        )
        # In `array[index] = value`, the index expression is not an output
        # argument. Inspect only the base of the written object.
        target = (next(iter(_children(lhs)), lhs) if dereference else lhs)
        for ref in _walk(target):
            if ref.get('kind') != 'DeclRefExpr':
                continue
            declaration_id = str((ref.get('referencedDecl') or {}).get('id') or '')
            index = by_id.get(declaration_id)
            if index is None:
                continue
            parameter_type = str((parameters[index].get('type') or {}).get('qualType') or '')
            if ((dereference and any(mark in parameter_type
                                     for mark in ('*', '[', '&')))
                or (not dereference and '&' in parameter_type)):
                result.add(index)
    return sorted(result)


def _linkage_declarations(ast: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index compiler-reported external symbols within one parsed TU.

    AST pointer IDs cannot be compared across Clang invocations. Only the
    compiler's external symbol and reported function type may be compared;
    internal-linkage declarations are deliberately excluded.
    """
    declarations: dict[str, dict[str, Any]] = {}

    pending: list[tuple[dict[str, Any], bool]] = [(ast, False)]
    while pending:
        node, anonymous_namespace = pending.pop()
        if node.get('kind') == 'NamespaceDecl' and not node.get('name'):
            anonymous_namespace = True
        kind = node.get('kind')
        if kind in {
            'FunctionDecl', 'CXXMethodDecl', 'CXXConstructorDecl',
            'CXXDestructorDecl',
        }:
            identifier = str(node.get('id') or '')
            symbol = str(node.get('mangledName') or '')
            signature = str((node.get('type') or {}).get('qualType') or '')
            internal = (
                anonymous_namespace
                or (kind == 'FunctionDecl'
                    and node.get('storageClass') == 'static')
            )
            if identifier and symbol and signature:
                declarations[identifier] = {
                    'symbol': symbol,
                    'type': signature,
                    'external': not internal,
                }
        pending.extend(
            (child, anonymous_namespace) for child in _children(node)
        )
    return declarations


def _compile_context(
    root: Path, compile_database: Path | None = None,
) -> tuple[dict[Path, tuple[str, ...]], set[Path], bool]:
    # Compile database is pre-existing build evidence, never executed. Reuse
    # the native build's allowlisted -I/-D/-std arguments, not compiler plugins.
    from ..runtime.native_build import _find_compile_database, _flags_from_compile_record
    db = compile_database or _find_compile_database(root)
    if db is None:
        return {}, set(), False
    try:
        records = json.loads(db.read_text(encoding='utf-8'))
    except (ValueError, OSError) as exc:
        if compile_database is not None:
            raise ValueError(f"cannot read analysis compile database {db}: {exc}") from exc
        return {}, set(), False
    if not isinstance(records, list):
        if compile_database is not None:
            raise ValueError(f"analysis compile database is not an array: {db}")
        return {}, set(), False
    flags: dict[Path, tuple[str, ...]] = {}
    ambiguous: set[Path] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        directory = Path(str(record.get('directory') or db.parent)).resolve()
        value = record.get('file')
        if not isinstance(value, str) or not value:
            continue
        src = Path(value)
        src = (src if src.is_absolute() else directory / src).resolve()
        if src.suffix.lower() != '.c' or not src.is_file():
            continue
        parsed = _flags_from_compile_record(record, directory)
        if src in flags and flags[src] != parsed:
            ambiguous.add(src)
        flags[src] = parsed
    for src in ambiguous:
        # Target-dependent macros may change a translation unit's semantics.
        # Do not pick arbitrary flags from multiple build targets.
        del flags[src]
    return flags, ambiguous, True


def _compile_flags(root: Path) -> dict[Path, tuple[str, ...]]:
    return _compile_context(root)[0]


def augment_c_ast(
    bundle: AnalysisBundle, source_root: Path, *, excluded_paths: tuple[Path, ...] = (),
    compile_database: Path | None = None,
    target_binary: Path | None = None,
) -> AstResult:
    clang = shutil.which('clang')
    if not clang:
        return AstResult()
    root = source_root.resolve()
    # A hidden 45-second total allowance previously skipped most of a real
    # Dropbear checkout. With no operator-selected total budget, visit every
    # translation unit. The per-file timeout still records pathological units
    # as failures rather than declaring the analysis complete.
    selected_budget = os.environ.get('HC_C_AST_BUDGET_SECONDS')
    if selected_budget is not None:
        budget = float(selected_budget)
        if not math.isfinite(budget) or budget < 0:
            raise ValueError('HC_C_AST_BUDGET_SECONDS must be finite and nonnegative')
        if budget == 0:
            return AstResult()
        deadline = time.monotonic() + budget
    else:
        deadline = float('inf')
    flags, ambiguous, has_compile_db = _compile_context(root, compile_database)
    paths = [
        p for p in _iter_project_files(root, excluded_paths)
        if p.suffix.lower() == '.c' and p.is_file()
    ]
    # A compilation database describes the commands that actually ran. A
    # source missing from it may simply belong to another target or to an
    # incomplete incremental capture. Keep it in the bootstrap graph, but
    # do not parse it under guessed flags and label the resulting AST as
    # build-backed evidence.
    unrecorded = 0
    if has_compile_db:
        unrecorded = sum(path not in flags and path not in ambiguous for path in paths)
        paths = [path for path in paths if path in flags or path in ambiguous]
    from .compile_priority import order_translation_units
    paths = order_translation_units(paths, root, compile_database, target_binary)
    by_file: dict[str, list[FunctionMetadata]] = {}
    for f in bundle.functions.values():
        by_file.setdefault(f.file, []).append(f)
    edge_keys = {(e.caller_id, e.callee_id, e.line, e.kind): e for e in bundle.edges}
    parsed = failed = added_functions = added_calls = added_refs = seen_functions = 0
    pending_function_references: list[tuple[str, str, str, int]] = []
    exhausted = False
    diagnostics: list[dict[str, str]] = []
    for path in paths:
        if path in ambiguous:
            # Multiple compiler flag sets can generate different programs.
            # Neither is preferred over the other without an explicit target.
            failed += 1
            diagnostics.append({"file": str(path.relative_to(root)),
                                "reason": "ambiguous compile commands for this source"})
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            exhausted = True
            break
        try:
            src_text = path.read_text(encoding='utf-8', errors='replace')
            cmd = [clang, '-x', 'c', '-fsyntax-only', '-Xclang', '-ast-dump=json',
                   '-I', str(root), '-I', str(path.parent), *flags.get(path, ()), str(path)]
            # Clang's AST JSON can exceed 45 MB for ordinary daemon source
            # (memcached.c is about 55 MB). Spool the compiler output to a
            # temporary file instead of rejecting the translation unit or
            # keeping both the subprocess output and parsed tree in memory.
            with tempfile.TemporaryFile(mode='w+b') as output:
                result = subprocess.run(
                    cmd, cwd=root, stdout=output, stderr=subprocess.PIPE,
                    timeout=min(8.0, max(0.1, remaining)),
                )
                if result.returncode:
                    failed += 1
                    diagnostics.append({
                        "file": str(path.relative_to(root)),
                        "reason": _compiler_diagnostic(
                            result.stderr.decode('utf-8', errors='replace')
                        ),
                    })
                    continue
                output.seek(0)
                ast = json.load(output)
        except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError) as exc:
            failed += 1
            diagnostics.append({"file": str(path.relative_to(root)),
                                "reason": f"{type(exc).__name__}: {exc}"[:500]})
            continue
        parsed += 1
        relative = str(path.relative_to(root))
        linkage_declarations = _linkage_declarations(ast)
        nodes = [node for node in ast.get('inner', ()) if isinstance(node, dict)
                 and _main_file_definition(node, path)]
        # A DeclRefExpr's declaration identity, not its spelling, links a
        # function use to a file-scope declaration. Header offsets are read only when
        # the AST names their direct includer and exactly one local quoted
        # include has the declaration's identifier at that offset.
        global_declarations: dict[str, dict[str, Any]] = {}
        global_initializers: dict[str, dict[str, Any]] = {}
        global_initializer_nodes: dict[str, dict[str, Any]] = {}
        local_includes: dict[Path, list[Path]] | None = None
        declaration_source_cache: dict[Path, str | None] = {path: src_text}
        declaration_path_cache: dict[str, Path] = {str(path): path}

        def declaration_path_for(candidate: Path) -> Path:
            key = str(candidate)
            if key not in declaration_path_cache:
                declaration_path_cache[key] = candidate.resolve()
            return declaration_path_cache[key]

        def declaration_source_for(source_path: Path) -> str | None:
            if source_path not in declaration_source_cache:
                try:
                    declaration_source_cache[source_path] = source_path.read_text(
                        encoding='utf-8', errors='replace',
                    )
                except OSError:
                    declaration_source_cache[source_path] = None
            return declaration_source_cache[source_path]

        # Only declarations present in this preprocessed translation unit
        # can describe a build-visible prototype.  A raw header scan also
        # sees inactive #ifdef branches and can select the wrong ABI.
        active_prototypes: dict[str, tuple[str, str, str]] = {}
        for declaration in ast.get('inner', ()):
            if (not isinstance(declaration, dict)
                or declaration.get('kind') != 'FunctionDecl'
                or any(child.get('kind') == 'CompoundStmt'
                       for child in _children(declaration))):
                continue
            name = str(declaration.get('name') or '')
            location = declaration.get('loc') or {}
            offset = _loc(location).get('offset')
            if not name or not isinstance(offset, int):
                continue
            source_file = location.get('file')
            included_from = (location.get('includedFrom') or {}).get('file')
            if source_file:
                source_path = declaration_path_for(Path(str(source_file)))
                if not source_path.is_relative_to(root):
                    continue
                declaration_source = declaration_source_for(source_path)
                if declaration_source is None:
                    continue
            elif included_from:
                if local_includes is None:
                    local_includes = _project_literal_includes(path, root)
                includer = Path(str(included_from))
                if not includer.is_absolute():
                    includer = root / includer
                matches = []
                for candidate in local_includes.get(declaration_path_for(includer), []):
                    text = declaration_source_for(candidate)
                    if text is None:
                        continue
                    if text[offset:offset + len(name)] == name:
                        matches.append((candidate, text))
                if len(matches) != 1:
                    continue
                source_path, declaration_source = matches[0]
            else:
                source_path, declaration_source = path, src_text
            if declaration_source[offset:offset + len(name)] != name:
                continue
            line = _line(location, declaration_source)
            lines = declaration_source.splitlines()
            if not 1 <= line <= len(lines):
                continue
            prototype = ' '.join(lines[line - 1].split())
            # Multi-line declarations require a separate source-span reader;
            # never guess a signature from one fragment.
            if not prototype.endswith(';') or name not in prototype:
                continue
            active_prototypes[str(declaration.get('id'))] = (
                source_path.relative_to(root).as_posix(), prototype,
                str((declaration.get('type') or {}).get('qualType') or ''),
            )
        for declaration in ast.get('inner', ()):
            if not isinstance(declaration, dict) or declaration.get('kind') != 'VarDecl':
                continue
            location = declaration.get('loc') or {}
            begin = (declaration.get('range') or {}).get('begin') or {}
            end = (declaration.get('range') or {}).get('end') or {}
            start_offset = _loc(begin).get('offset')
            end_offset = _loc(end).get('offset')
            token_length = _loc(end).get('tokLen', 0)
            if (not isinstance(start_offset, int)
                or not isinstance(end_offset, int)
                or not isinstance(token_length, int)):
                continue
            name = str(declaration.get('name') or '')
            if not name:
                continue
            source_file = location.get('file')
            included_from = (location.get('includedFrom') or {}).get('file')
            if source_file:
                source_path = declaration_path_for(Path(str(source_file)))
                if not source_path.is_relative_to(root):
                    continue
                declaration_source = declaration_source_for(source_path)
                if declaration_source is None:
                    continue
            elif included_from:
                if local_includes is None:
                    local_includes = _project_literal_includes(path, root)
                includer = Path(str(included_from))
                if not includer.is_absolute():
                    includer = root / includer
                candidates: list[tuple[Path, str]] = []
                for candidate in local_includes.get(declaration_path_for(includer), []):
                    candidate_source = declaration_source_for(candidate)
                    if candidate_source is None:
                        continue
                    name_offset = _loc(location).get('offset')
                    if (isinstance(name_offset, int)
                        and candidate_source[name_offset:name_offset + len(name)]
                        == name):
                        candidates.append((candidate, candidate_source))
                if len(candidates) != 1:
                    continue
                source_path, declaration_source = candidates[0]
            else:
                source_path, declaration_source = path, src_text
            if not 0 <= start_offset < end_offset + token_length <= len(declaration_source):
                continue
            record = {
                'name': name,
                'file': source_path.relative_to(root).as_posix(),
                'start_line': _line(begin, declaration_source),
                'end_line': _line(end, declaration_source),
                'source': declaration_source[start_offset:end_offset + token_length],
                'provider': 'clang-ast-c',
                'analysis_unit': str(path),
            }
            global_declarations[str(declaration.get('id'))] = record
            # Only initialized declarations can provide indirect table
            # members. Uninitialized globals still supply their ownership
            # and type to the later state analysis, never an initial value.
            if not declaration.get('init') or not any(
                True for _ in _children(declaration)
            ):
                continue
            global_initializers[str(declaration.get('id'))] = record
            global_initializer_nodes[str(declaration.get('id'))] = declaration
        seen_functions += len(nodes)
        # A function-like macro followed by a later opening brace is not a C
        # function definition. The regex fallback may accidentally turn that
        # invocation into a phantom function. Discard it only in translation
        # units successfully parsed by Clang, and only when its identifier is
        # an actual function-like macro with no corresponding FunctionDecl.
        ast_names = {str(n.get('name')) for n in nodes}
        macro_names = set(re.findall(
            r'(?m)^\s*#\s*define\s+([A-Za-z_]\w*)\s*\(', src_text
        ))
        for existing in list(by_file.get(relative, ())):
            if existing.name in macro_names and existing.name not in ast_names:
                bundle.functions.pop(existing.function_id, None)
                bundle.edges = [
                    edge for edge in bundle.edges
                    if existing.function_id not in (edge.caller_id, edge.callee_id)
                ]
                by_file[relative].remove(existing)
        edge_keys = {(e.caller_id, e.callee_id, e.line, e.kind): e for e in bundle.edges}
        local_id: dict[str, FunctionMetadata] = {}
        local_functions = by_file.setdefault(relative, [])
        # AST sees functions produced by macros even though regex sees only
        # invocation text. Keep original source locations and preserve macro
        # directives as context; these are not fabricated expanded C bodies.
        for node in nodes:
            name = str(node.get('name') or '')
            if not name:
                continue
            start = _line((node.get('range') or {}).get('begin') or {}, src_text)
            end = _line((node.get('range') or {}).get('end') or {}, src_text)
            if not start:
                start = _line(node.get('loc') or {}, src_text)
            if not start:
                continue
            end = max(start, end)
            same_name = [f for f in local_functions if f.name == name]
            exact = next((f for f in same_name if f.start_line <= start <= f.end_line), None)
            if exact is None and len(same_name) == 1 and same_name[0].start_line == start:
                exact = same_name[0]
            if exact is None:
                lines = src_text.splitlines(keepends=True)
                snippet = ''.join(lines[start - 1:end])
                macro_defs = ''.join(line for line in lines if line.lstrip().startswith('#define'))
                if node.get('loc', {}).get('expansionLoc'):
                    # The source is *not* the expanded body. Marking this avoids
                    # misleading downstream agents about source completeness.
                    snippet = (f'/* Clang AST confirms macro-expanded definition of {name}; '
                               f'original source below, expansion body not captured */\n'
                               + macro_defs[:8192] + snippet)
                exact = FunctionMetadata.create(
                    name=name, file=relative, start_line=start, end_line=end,
                    signature=f"{name}: {(node.get('type') or {}).get('qualType', '')}",
                    source=snippet, provider='clang-ast-c', language='c_cpp',
                )
                bundle.functions[exact.function_id] = exact
                local_functions.append(exact)
                added_functions += 1
            else:
                exact.providers = unique_strings([*exact.providers, 'clang-ast-c'])
            previous = str(node.get('previousDecl') or '')
            active = active_prototypes.get(previous)
            if (active is not None
                and active[2] == str((node.get('type') or {}).get('qualType') or '')):
                exact.declaration = active[1]
                exact.headers = unique_strings([*exact.headers, active[0]])
            exact.ast_parameter_declarations = [
                {
                    'name': str(item.get('name') or ''),
                    'declaration_id': str(item.get('id') or ''),
                    'type': str((item.get('type') or {}).get('qualType') or ''),
                    'analysis_unit': str(path),
                }
                for item in _children(node)
                if item.get('kind') == 'ParmVarDecl' and item.get('id')
            ]
            exact.parameter_output_positions = _parameter_output_positions(node)
            linkage = linkage_declarations.get(str(node.get('id')), {})
            if linkage.get('external'):
                exact.linkage_symbol = str(linkage['symbol'])
                exact.linkage_type = str(linkage['type'])
                exact.linkage_external = True
            local_id[str(node.get('id'))] = exact
        for node in nodes:
            caller = local_id.get(str(node.get('id')))
            if caller is None:
                continue
            for site in _guarded_call_sites(node, src_text):
                site['analysis_unit'] = str(path)
                target = local_id.get(site['callee_declaration_id'])
                site['callee_function_id'] = target.function_id if target else ''
                linkage = linkage_declarations.get(site['callee_declaration_id'], {})
                if linkage.get('external'):
                    site['callee_linkage_symbol'] = linkage['symbol']
                    site['callee_linkage_type'] = linkage['type']
                if site not in caller.guarded_call_sites:
                    caller.guarded_call_sites.append(site)
        by_name: dict[str, list[FunctionMetadata]] = {}
        for f in bundle.functions.values():
            by_name.setdefault(f.name, []).append(f)

        def unique_typed_target(ref: dict[str, Any]) -> FunctionMetadata | None:
            name = str(ref.get('name') or '')
            candidates = by_name.get(name, ())
            if len(candidates) == 1:
                return candidates[0]
            # An included prototype can refer to a definition in another
            # translation unit.  If a checkout also contains an unrelated
            # same-named function, match the compiler-reported external
            # symbol and function type.  This remains navigation evidence;
            # the selected executable link is a separate question.
            qual_type = str((ref.get('type') or {}).get('qualType') or '')
            typed = [
                function for function in candidates
                if function.linkage_external
                and function.linkage_symbol == name
                and function.linkage_type == qual_type
            ]
            return typed[0] if len(typed) == 1 else None
        macro_source_cache: dict[Path, str] = {}
        # Clang repeats the same spelling/expansion file path on many AST
        # nodes. Resolving each occurrence performs filesystem lookups even
        # when the location has already been checked in this translation unit.
        location_path_cache: dict[str, Path] = {str(path): path}
        for node in nodes:
            caller = local_id.get(str(node.get('id')))
            if not caller:
                continue
            seen_macro_locations: set[tuple[str, int, str]] = set()
            for item in _walk(node):
                begin = (item.get('range') or {}).get('begin') or {}
                spelling = begin.get('spellingLoc') or {}
                expansion = begin.get('expansionLoc') or {}
                spelling_file = str(spelling.get('file') or '')
                expansion_file = str(expansion.get('file') or '')
                if not spelling_file or not expansion_file:
                    continue
                if expansion_file not in location_path_cache:
                    location_path_cache[expansion_file] = Path(expansion_file).resolve()
                if location_path_cache[expansion_file] != path:
                    continue
                if spelling_file not in location_path_cache:
                    location_path_cache[spelling_file] = Path(spelling_file).resolve()
                spelling_path = location_path_cache[spelling_file]
                if not spelling_path.is_relative_to(root):
                    continue
                offset = expansion.get('offset')
                token_length = expansion.get('tokLen')
                if (not isinstance(offset, int)
                    or not isinstance(token_length, int)
                    or not 0 <= offset < offset + token_length <= len(src_text)):
                    continue
                name = src_text[offset:offset + token_length]
                if not re.fullmatch(r'[A-Za-z_]\w*', name):
                    continue
                if spelling_path not in macro_source_cache:
                    try:
                        macro_source_cache[spelling_path] = spelling_path.read_text(
                            encoding='utf-8', errors='replace',
                        )
                    except OSError:
                        continue
                macro_source = macro_source_cache[spelling_path]
                macro_line = _line(spelling, macro_source)
                source_lines = macro_source.splitlines()
                if not 1 <= macro_line <= len(source_lines):
                    continue
                definition = source_lines[macro_line - 1]
                # A single-line object macro has an unambiguous source body.
                # Function-like or continued macros remain unresolved here.
                if (not re.match(
                    rf'^\s*#\s*define\s+{re.escape(name)}(?:\s+|$)',
                    definition,
                ) or definition.rstrip().endswith('\\')):
                    continue
                relative_macro = spelling_path.relative_to(root).as_posix()
                key = (relative_macro, macro_line, name)
                if key in seen_macro_locations:
                    continue
                seen_macro_locations.add(key)
                caller.referenced_macro_definitions.append({
                    'name': name,
                    'file': relative_macro,
                    'start_line': macro_line,
                    'end_line': macro_line,
                    'source': definition,
                    'expanded_at_line': _line(expansion, src_text),
                    'provider': 'clang-ast-c',
                    'analysis_unit': str(path),
                })
            seen_global_ids: set[str] = set()
            for item in _walk(node):
                if item.get('kind') != 'DeclRefExpr':
                    continue
                declaration_id = str(
                    (item.get('referencedDecl') or {}).get('id') or ''
                )
                declaration = global_declarations.get(declaration_id)
                if declaration is None or declaration_id in seen_global_ids:
                    continue
                seen_global_ids.add(declaration_id)
                if declaration not in caller.referenced_global_declarations:
                    caller.referenced_global_declarations.append(declaration)
            local_declaration_ids = {
                str(item.get('id')) for item in _walk(node)
                if item.get('kind') in {'VarDecl', 'ParmVarDecl'}
            }
            local_declarations = {
                str(item.get('id')): item for item in _walk(node)
                if item.get('kind') in {'VarDecl', 'ParmVarDecl'}
            }
            # Exclude call operands when counting address-taken references; a
            # direct call must not simultaneously become a weak reference.
            direct_refs: set[str] = set()
            for item in _walk(node):
                if item.get('kind') != 'CallExpr':
                    continue
                subnodes = list(_children(item))
                if not subnodes:
                    continue
                ref = _callee_decl(subnodes[0])
                if ref is None:
                    table = _indirect_array_declaration(subnodes[0])
                    table_id = str((table or {}).get('id') or '')
                    declaration = global_initializers.get(table_id)
                    initializer = global_initializer_nodes.get(table_id)
                    if declaration is not None and initializer is not None:
                        targets: list[str] = []
                        for member in _walk(initializer):
                            if member.get('kind') != 'DeclRefExpr':
                                continue
                            candidate = member.get('referencedDecl') or {}
                            if candidate.get('kind') != 'FunctionDecl':
                                continue
                            resolved = local_id.get(str(candidate.get('id'))) or unique_typed_target(candidate)
                            if resolved and resolved.function_id not in targets:
                                targets.append(resolved.function_id)
                        site = {
                            'table_name': declaration['name'],
                            'table_declaration_id': table_id,
                            'table_file': declaration['file'],
                            'table_start_line': declaration['start_line'],
                            'call_line': _line((item.get('range') or {}).get('begin') or {}, src_text),
                            'candidate_function_ids': targets,
                            'provider': 'clang-ast-c',
                            'analysis_unit': str(path),
                        }
                        if site not in caller.indirect_table_call_sites:
                            caller.indirect_table_call_sites.append(site)
                    continue  # genuine indirect call remains unresolved
                short = str(ref.get('name') or '')
                if not short:
                    continue
                direct_refs.add(str(ref.get('id')))
                line = _line((item.get('range') or {}).get('begin') or {}, src_text) or caller.start_line
                target = local_id.get(str(ref.get('id')))
                if not target:
                    target = unique_typed_target(ref)
                if target and target.function_id != caller.function_id:
                    direct_site = {
                        'callee_function_id': target.function_id,
                        'line': line,
                        'offset': _loc((item.get('range') or {}).get('begin') or {}).get('offset'),
                        'provider': 'clang-ast-c',
                        'analysis_unit': str(path),
                        'direct_argument_identifiers': _direct_call_argument_identifiers(
                            item, local_declaration_ids,
                        ),
                        'direct_argument_declaration_ids': _direct_call_argument_declarations(item),
                        'direct_argument_field_bindings': _direct_call_argument_field_bindings(item),
                    }
                    if direct_site not in caller.direct_call_sites:
                        caller.direct_call_sites.append(direct_site)
                    # A source-only Clang AST with guessed flags is navigation
                    # evidence, not a build-configuration-grounded direct call.
                    kind = 'direct' if (has_compile_db and path in flags) else 'source_candidate'
                    key = (caller.function_id, target.function_id, line, kind)
                    if key not in edge_keys:
                        edge = CallEdge(
                            edge_id=stable_id('clang-ast-call', *key),
                            caller_id=caller.function_id, callee_id=target.function_id,
                            line=line, kind=kind, confidence=0.98 if kind == 'direct' else 0.65,
                            providers=['clang-ast-c'],
                        )
                        bundle.edges.append(edge)
                        edge_keys[key] = edge
                        added_calls += 1
                    else:
                        edge_keys[key].providers = unique_strings([*edge_keys[key].providers, 'clang-ast-c'])
                elif not target:
                    caller.external_calls = unique_strings([*caller.external_calls, short])
                    begin = (item.get('range') or {}).get('begin') or {}
                    spelling = begin.get('spellingLoc') or begin
                    expansion = begin.get('expansionLoc') or begin
                    macro_expansion = bool(
                        begin.get('spellingLoc') and begin.get('expansionLoc')
                        and spelling.get('offset') != expansion.get('offset')
                    )
                    spelling_file = str(spelling.get('file') or path)
                    spelling_line = int(spelling.get('line') or 0)
                    spelling_path = Path(spelling_file)
                    if not spelling_path.is_absolute():
                        spelling_path = (root / spelling_path).resolve()
                    lines = src_text.splitlines()
                    spelling_text = (
                        lines[spelling_line - 1]
                        if spelling_path == path and 1 <= spelling_line <= len(lines)
                        else ''
                    )
                    site = {
                        'api': short,
                        'line': line,
                        'offset': _loc(begin).get('offset'),
                        'provider': 'clang-ast-c',
                        'analysis_unit': str(path),
                        'compile_command_available': path in flags,
                        'macro_expansion': macro_expansion,
                        'direct_argument_identifiers': _direct_call_argument_identifiers(
                            item, local_declaration_ids,
                        ),
                        'direct_argument_declaration_ids': _direct_call_argument_declarations(item),
                        'direct_argument_field_bindings': _direct_call_argument_field_bindings(item),
                        'direct_argument_addressed_scalar_declaration_ids': (
                            _direct_call_addressed_scalar_declarations(
                                item, local_declarations,
                            )
                        ),
                        'spelling_file': spelling_file,
                        'spelling_line': spelling_line,
                        'spelling_source': spelling_text,
                    }
                    if site not in caller.external_call_sites:
                        caller.external_call_sites.append(site)
            for item in _walk(node):
                if item.get('kind') != 'DeclRefExpr':
                    continue
                ref = item.get('referencedDecl') or {}
                if ref.get('kind') != 'FunctionDecl' or str(ref.get('id')) in direct_refs:
                    continue
                target = local_id.get(str(ref.get('id')))
                if not target:
                    target = unique_typed_target(ref)
                line = _line((item.get('range') or {}).get('begin') or {}, src_text) or caller.start_line
                if not target:
                    pending_function_references.append((
                        caller.function_id,
                        str(ref.get('name') or ''),
                        str((ref.get('type') or {}).get('qualType') or ''),
                        line,
                    ))
                    continue
                if target.function_id == caller.function_id:
                    continue
                key = (caller.function_id, target.function_id, line, 'function_reference')
                if key in edge_keys:
                    continue
                edge = CallEdge(
                    edge_id=stable_id('clang-ast-reference', *key),
                    caller_id=caller.function_id, callee_id=target.function_id,
                    line=line, kind='function_reference', confidence=0.4,
                    providers=['clang-ast-c'],
                )
                bundle.edges.append(edge)
                edge_keys[key] = edge
                added_refs += 1
    # A translation unit can be visited before the referenced function's
    # definition is AST-enriched. Revisit only compiler-located unresolved
    # references after every TU, and keep ambiguous symbols unresolved.
    final_edge_keys = {
        (e.caller_id, e.callee_id, e.line, e.kind)
        for e in bundle.edges
    }
    for caller_id, name, qual_type, line in pending_function_references:
        if not name or not qual_type:
            continue
        matches = [
            function for function in bundle.functions.values()
            if function.function_id != caller_id
            and function.linkage_external
            and function.linkage_symbol == name
            and function.linkage_type == qual_type
        ]
        if len(matches) != 1:
            continue
        target = matches[0]
        key = (caller_id, target.function_id, line, 'function_reference')
        if key in final_edge_keys:
            continue
        bundle.edges.append(CallEdge(
            edge_id=stable_id('clang-ast-reference', *key),
            caller_id=caller_id, callee_id=target.function_id,
            line=line, kind='function_reference', confidence=0.4,
            providers=['clang-ast-c'],
        ))
        final_edge_keys.add(key)
        added_refs += 1
    if added_functions or added_calls or added_refs:
        _populate_adjacency(bundle)
    return AstResult(
        functions=seen_functions, added_functions=added_functions,
        added_calls=added_calls, added_references=added_refs,
        parsed_files=parsed, failed_files=failed,
        unrecorded_files=unrecorded, budget_exhausted=exhausted,
        failure_diagnostics=tuple(diagnostics),
    )
