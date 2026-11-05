from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path


_BNF_BLOCK = re.compile(r"<BNF>\s*(.*?)\s*</BNF>", re.DOTALL)
_PRODUCTION = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:=\s*(.*?);(?:\s*$|\s*\n\s*assert)",
    re.MULTILINE | re.DOTALL,
)
_ASSERTION = re.compile(r"^\s*assert\((.*?)\)\s*$", re.MULTILINE)


@dataclass(slots=True)
class NetLifterGrammar:
    """Validated, lossless adapter for Popeye/NetLifter BNF output.

    HarnessCreator does not reproduce NetLifter's LLVM/Z3 analysis.  It only
    imports the grammar emitted by the original implementation and presents
    its rules as upstream evidence to the input-action agent.
    """

    source: str
    source_sha256: str
    productions: list[dict[str, str]] = field(default_factory=list)
    assertions: list[str] = field(default_factory=list)
    raw_bnf: str = ""

    def prompt_payload(self, *, limit: int | None = None) -> dict[str, object]:
        # No implicit prefix truncation: a production near the end of the
        # upstream grammar may be the only rule for the current input. A
        # caller may request an explicit preview limit for display, but the
        # Action agent receives the complete imported grammar by default.
        if limit is not None and limit < 0:
            raise ValueError("NetLifter grammar preview limit cannot be negative")
        productions = (
            self.productions if limit is None else self.productions[:limit]
        )
        assertions = self.assertions if limit is None else self.assertions[:limit]
        return {
            "provider": "NetLifter/Popeye",
            "source": self.source,
            "source_sha256": self.source_sha256,
            "productions": productions,
            "assertions": assertions,
            "omitted_productions": len(self.productions) - len(productions),
            "omitted_assertions": len(self.assertions) - len(assertions),
            "authority": (
                "upstream grammar evidence only; it constrains byte layout but "
                "does not prove dispatcher reachability or runtime success"
            ),
        }


def load_netlifter_grammars(paths: list[Path]) -> list[NetLifterGrammar]:
    result: list[NetLifterGrammar] = []
    for path in paths:
        data = path.read_bytes()
        text = data.decode("utf-8", errors="replace")
        match = _BNF_BLOCK.search(text)
        if match is None:
            raise ValueError(
                f"NetLifter evidence has no <BNF>...</BNF> block: {path}"
            )
        block = match.group(1).strip()
        productions = [
            {"nonterminal": item.group(1), "expression": " ".join(item.group(2).split())}
            for item in _PRODUCTION.finditer(block)
        ]
        if not productions and "S := epsilon" not in block:
            raise ValueError(f"NetLifter BNF contains no productions: {path}")
        result.append(NetLifterGrammar(
            source=str(path),
            source_sha256=hashlib.sha256(data).hexdigest(),
            productions=productions,
            assertions=[" ".join(item.split()) for item in _ASSERTION.findall(block)],
            raw_bnf=block,
        ))
    return result
