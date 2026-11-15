"""Partition no-alias cJSON source definitions by object/DWARF evidence."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import sys


PREP = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027')
ROOT = PREP / 'review/CJSON_V2_NO_ALIAS_REBUILD_20261102'
sys.path[:0] = [str(PREP / 'review_tools'), str(PREP)]
from supplement_compiled_catalog import _top_level_definitions, _row_from_definition
from catalog_dwarf import DwarfInlineIndex

SYMBOL = re.compile(r'[0-9a-fA-F]+\s+[TtWw]\s+([A-Za-z_]\w*)')


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def symbols(path: Path) -> set[str]:
    return {match.group(1) for line in path.read_text().splitlines()
            if (match := SYMBOL.fullmatch(line))}


def main() -> None:
    capture = json.loads((ROOT / 'ast-nm-capture.json').read_text())
    for role in ('asan', 'coverage'):
        root = ROOT / role / 'src/cjson'
        source = root / 'cJSON.c'
        binary = ROOT / role / 'out/cjson_read_fuzzer'
        role_capture = capture['roles'][role]
        names = role_capture['captures']
        ast_path = Path(names['source_ast']['stdout_path'])
        object_nm = Path(names['object_defined-only']['stdout_path'])
        binary_nm = Path(names['binary_defined-only']['stdout_path'])
        if (digest(binary) != role_capture['binary_sha256'] or
                digest(ast_path) != names['source_ast']['stdout_sha256'] or
                digest(object_nm) != names['object_defined-only']['stdout_sha256'] or
                digest(binary_nm) != names['binary_defined-only']['stdout_sha256']):
            raise ValueError(f'{role}: compiled evidence changed')
        object_symbols = symbols(object_nm)
        binary_symbols = symbols(binary_nm)
        if not object_symbols <= binary_symbols:
            raise ValueError(f'{role}: object code absent from binary')
        ast = json.loads(ast_path.read_text())
        rows = []
        for node, hint in _top_level_definitions(ast, source):
            try:
                row = _row_from_definition(node, hint, root)
            except (OSError, ValueError):
                continue
            if row['file'] == 'cJSON.c':
                rows.append(row)
        if len(rows) != 112 or len({row['function_id'] for row in rows}) != 112:
            raise ValueError(f'{role}: source definition count changed')
        dwarf = DwarfInlineIndex(binary)
        linked, inlined, not_found = [], [], []
        for row in rows:
            if row['name'] in object_symbols:
                linked.append(row['name'])
            else:
                evidence = dwarf.find(source, row['name'], row['start_line'])
                (inlined if evidence else not_found).append(
                    [row['name'], row['function_id'], evidence])
        result = {'status': 'CANDIDATE_UNAPPROVED',
                  'binary_sha256': digest(binary),
                  'source_sha256': digest(source),
                  'ast_sha256': digest(ast_path),
                  'object_nm_sha256': digest(object_nm),
                  'binary_nm_sha256': digest(binary_nm),
                  'ast_definitions': len(rows), 'object_code': len(linked),
                  'inlined': inlined, 'not_found': not_found}
        path = ROOT / f'{role}-inline-probe.json'
        with path.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write('\n')
        print(role, {'definitions': len(rows), 'object': len(linked),
                     'inlined': len(inlined), 'not_found': len(not_found),
                     'probe_sha256': digest(path)})


if __name__ == '__main__':
    main()
