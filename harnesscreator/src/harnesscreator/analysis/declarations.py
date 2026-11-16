"""Source-located C/C++ declaration inventory for direct name lookup.

These are lexical source candidates. A definition in a conditional branch is
not evidence that the compiler selected that branch for a particular target.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_DEFINE = re.compile(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)", re.MULTILINE)
_RECORD = re.compile(r"\b(?:struct|union|enum|class)\s+([A-Za-z_]\w*)?\s*\{", re.MULTILINE)
_ALIAS = re.compile(r"\s*([A-Za-z_]\w*)\s*;")
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")


@dataclass(frozen=True, slots=True)
class SourceDeclaration:
    name: str
    kind: str
    file: str
    start_line: int
    end_line: int
    source: str
    provenance: str = "source_lexical"

    def summary(self) -> dict[str, object]:
        return {"name": self.name, "kind": self.kind, "file": self.file,
                "start_line": self.start_line, "end_line": self.end_line,
                "provenance": self.provenance}


class DeclarationIndex:
    def __init__(self, declarations: Iterable[SourceDeclaration] = ()):
        self._by_name: dict[str, list[SourceDeclaration]] = {}
        self._count = 0
        for declaration in declarations:
            self._by_name.setdefault(declaration.name, []).append(declaration)
            self._count += 1
        for name in self._by_name:
            self._by_name[name].sort(key=lambda item: (item.file, item.start_line, item.kind))

    def __len__(self) -> int:
        return self._count

    def names(self, query: str = "") -> list[dict[str, object]]:
        """List all indexed names, optionally filtered by a literal substring."""
        needle = query.casefold().strip()
        return [{"name": name, "kinds": sorted({item.kind for item in records}),
                 "definitions": len(records), "files": sorted({item.file for item in records})}
                for name, records in sorted(self._by_name.items())
                if needle in name.casefold()]

    def lookup(self, name: str) -> list[SourceDeclaration]:
        """Resolve NAME, file:NAME, or file:line:NAME without guessing variants."""
        query = name.strip()
        if query in self._by_name:
            return list(self._by_name[query])
        if ":" not in query:
            return []
        file, symbol = query.rsplit(":", 1)
        line = None
        if ":" in file and file.rsplit(":", 1)[-1].isdigit():
            file, line_text = file.rsplit(":", 1)
            line = int(line_text)
        return [item for item in self._by_name.get(symbol, ())
                if (item.file == file or item.file.endswith("/" + file))
                and (line is None or item.start_line == line)]

    def all(self) -> list[SourceDeclaration]:
        return [item for name in sorted(self._by_name) for item in self._by_name[name]]


def extract_declarations(root: Path, paths: Iterable[Path]) -> DeclarationIndex:
    # The source indexer already chooses project files and exclusions. Reuse
    # that exact set so this inventory cannot drift into generated run output.
    from .indexer import _mask_comments_and_strings, _mask_preprocessor_lines

    found: dict[tuple[str, str, str, int], SourceDeclaration] = {}
    for path in paths:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        relative = str(path.relative_to(root))
        masked = _mask_comments_and_strings(source)
        # splitlines() also splits on form feeds inside quoted C literals;
        # the masked text replaces those bytes and would then have fewer rows.
        lines = source.split("\n")
        masked_lines = masked.split("\n")
        line = 0
        while line < len(lines):
            match = _DEFINE.match(masked_lines[line])
            if match:
                end = line
                while end + 1 < len(lines) and lines[end].rstrip("\r\n").rstrip().endswith("\\"):
                    end += 1
                name = match.group(1)
                item = SourceDeclaration(name, "macro", relative, line + 1,
                                         end + 1, "\n".join(lines[line:end + 1]))
                found[(item.name, item.kind, item.file, item.start_line)] = item
                line = end + 1
            else:
                line += 1

        declarations_only = _mask_preprocessor_lines(masked)
        for match in _RECORD.finditer(declarations_only):
            opening = match.end() - 1
            depth = 0
            closing = None
            for offset in range(opening, len(declarations_only)):
                char = declarations_only[offset]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        closing = offset
                        break
            if closing is None:
                continue
            head = declarations_only[match.start():opening]
            kind = head.split(None, 1)[0]
            names = [match.group(1)] if match.group(1) else []
            # Anonymous typedefs use the declarator after the closing brace.
            before = declarations_only[max(0, match.start() - 80):match.start()]
            if re.search(r"\btypedef\s*$", before):
                alias = _ALIAS.match(declarations_only[closing + 1:])
                if alias and alias.group(1) not in names:
                    names.append(alias.group(1))
            start = match.start()
            end = closing + 1
            before = declarations_only[max(0, start - 80):start]
            if re.search(r"\btypedef\s*$", before):
                prefix = re.search(r"\btypedef\s*$", before)
                assert prefix is not None
                start = max(0, start - 80) + prefix.start()
                alias_tail = _ALIAS.match(declarations_only[end:])
                if alias_tail:
                    end += alias_tail.end()
            end_line = source.count("\n", 0, end) + 1
            start_line = source.count("\n", 0, start) + 1
            for name in names:
                if name and _IDENTIFIER.fullmatch(name):
                    item = SourceDeclaration(name, kind, relative, start_line,
                                             end_line, source[start:end])
                    found[(item.name, item.kind, item.file, item.start_line)] = item
            if kind == "enum":
                # Enumerators are often the exact names the request model
                # needs for an opcode. Preserve their own source lines too.
                body_line = source.count("\n", 0, opening) + 1
                for offset, row in enumerate(declarations_only[opening + 1:closing].split("\n")):
                    member = re.fullmatch(
                        r"\s*([A-Za-z_]\w*)\s*(?:=\s*[^,{}]+)?\s*,?\s*", row)
                    if not member:
                        continue
                    member_line = body_line + offset
                    original = lines[member_line - 1]
                    entry = SourceDeclaration(member.group(1), "enum_constant", relative,
                                              member_line, member_line, original)
                    found[(entry.name, entry.kind, entry.file, entry.start_line)] = entry
    return DeclarationIndex(found.values())
