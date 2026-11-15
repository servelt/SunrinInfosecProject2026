"""Audit a persisted Function Catalog without guessing ambiguous call targets.

The producer's ID-valued ``callees`` are the only graph edges emitted here.
Call-like source text with multiple Catalog targets is separately recorded as
AMBIGUOUS_EDGE; it is never inserted into the traversal graph.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from pathlib import Path
import argparse
import json
import re


CALL_RE = re.compile(r"(?<![\w:])([A-Za-z_~][\w]*(?:::[A-Za-z_~][\w]*)*)\s*\(")
CONTROL = {"if", "for", "while", "switch", "catch", "return", "sizeof", "alignof"}
NONCODE = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _mask(text: str) -> str:
    return NONCODE.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), text)


def audit(rows: list[dict]) -> tuple[list[dict], list[dict], dict]:
    by_id = {str(row["function_id"]): row for row in rows}
    if len(by_id) != len(rows):
        raise ValueError("Function Catalog has duplicate IDs")
    by_name: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        for name in {row.get("name"), row.get("qualified_name")}:
            if isinstance(name, str) and name:
                by_name[name].add(str(row["function_id"]))

    resolved: list[dict] = []
    ambiguous: list[dict] = []
    unresolved_ids = 0
    seen_resolved: set[tuple[str, str]] = set()
    for row in rows:
        caller = str(row["function_id"])
        for raw_id in row.get("callees") or []:
            callee = str(raw_id)
            if callee not in by_id:
                unresolved_ids += 1
                continue
            key = (caller, callee)
            if key not in seen_resolved:
                resolved.append({"caller_id": caller, "callee_id": callee,
                                 "kind": "producer_catalog_id_edge"})
                seen_resolved.add(key)
        source = str(row.get("source") or "")
        brace = source.find("{")
        if brace < 0:
            continue
        body = _mask(source[brace + 1:])
        for call in CALL_RE.finditer(body):
            called = call.group(1)
            short = called.rsplit("::", 1)[-1]
            if short in CONTROL:
                continue
            candidates = by_name.get(called) or by_name.get(short) or set()
            if len(candidates) < 2:
                continue
            ambiguous.append({
                "status": "AMBIGUOUS_EDGE", "caller_id": caller,
                "source_file": row.get("file"),
                "source_line": int(row.get("start_line") or 1) +
                               source[brace + 1:brace + 1 + call.start()].count("\n"),
                "called_name": called, "candidate_ids": sorted(candidates),
                "note": "source-level callsite only; not a traversable edge",
            })
    summary = {"catalog_rows": len(rows), "resolved_id_edges": len(resolved),
               "ambiguous_source_callsites": len(ambiguous),
               "unresolved_producer_callee_ids": unresolved_ids,
               "scope": "producer ID edges plus source-level ambiguity audit; no rank"}
    return resolved, ambiguous, summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("catalog", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.catalog.read_text().splitlines()
            if line.strip()]
    resolved, ambiguous, summary = audit(rows)
    args.output.mkdir(parents=True, exist_ok=True)
    files = {"edges.jsonl": resolved, "ambiguous_edges.jsonl": ambiguous}
    for name, data in files.items():
        path = args.output / name
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in data))
        summary[name + "_sha256"] = sha256(path.read_bytes()).hexdigest()
    summary["catalog_sha256"] = sha256(args.catalog.read_bytes()).hexdigest()
    (args.output / "edge_audit_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
