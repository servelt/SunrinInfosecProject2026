"""Write a validated finding as a GitHub security advisory: a Markdown draft and an OSV record.

Field set, from GitHub's documentation (docs.github.com, "Creating a repository security
advisory" and "Privately reporting a security vulnerability"):
- title; CVE identifier (or "request one from GitHub"); description; affected products, each
  with ecosystem, package name, affected versions, patched versions and vulnerable functions;
  severity, optionally from a CVSS calculator; CWEs; credits (types include Finder and Tool).
- A private report's description requires, by default, a summary, details, a proof of concept
  and an impact statement, and the form asks whether AI assistance was used.
- Version ranges: operator, one space, version; a lower bound, ", ", an upper bound; avoid `>`
  because OSV cannot express it.
- The advisory database publishes OSV JSON and accepts CVSS v3.1; GitHub's severity levels are
  CVSS's, with Medium called Moderate.

Two deliberate limits.  C programs have no GitHub ecosystem (the list is Composer, Erlang, Go,
GitHub Actions, Maven, npm, NuGet, pip, Pub, RubyGems, Rust, Swift), so the ecosystem is left
for the maintainer to choose and the record says why.  Only the tested revision is known to be
affected, so the affected versions are `= <tested revision>`; a range needs the project's
history and is not guessed.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

_GITHUB_SEVERITY = {"Low": "Low", "Medium": "Moderate", "High": "High", "Critical": "Critical", "None": "None"}
NO_ECOSYSTEM = ("none of GitHub's supported ecosystems fits a C program (Composer, Erlang, Go, GitHub "
                "Actions, Maven, npm, NuGet, pip, Pub, RubyGems, Rust, Swift); choose it in the form")


def bytes_expression(data: bytes, min_run: int = 16) -> str:
    """A Python expression for `data` with long runs folded: b"USER " + b"A" * 600 + b"\\r\\n"."""
    parts, literal, i = [], bytearray(), 0
    while i < len(data):
        j = i
        while j < len(data) and data[j] == data[i]:
            j += 1
        if j - i >= min_run:
            if literal:
                parts.append(repr(bytes(literal)))
                literal.clear()
            parts.append(f"{bytes([data[i]])!r} * {j - i}")
        else:
            literal.extend(data[i:j])
        i = j
    if literal or not parts:
        parts.append(repr(bytes(literal)))
    return " + ".join(parts)


def _poc_bytes(crash: dict[str, Any]) -> str:
    path = Path(str(crash.get("input_path") or ""))
    if not path.is_file():
        return ""
    data = path.read_bytes()
    expression = bytes_expression(data)
    if len(expression) > 6000:
        return f"The input ({len(data)} bytes) is attached as `{path.name}`.\n"
    return f"Input that triggered it ({len(data)} bytes):\n\n```python\ndata = {expression}\n```\n"


def write_advisory(run_dir: Path, *, crash: dict[str, Any], validation: dict[str, Any], program: str,
                   version: str, title: str, summary: str, details: str, poc: str, impact: str,
                   vulnerable_functions: list[str], patched_versions: str, workarounds: str) -> dict[str, Path]:
    directory = Path(run_dir) / "advisories"
    directory.mkdir(parents=True, exist_ok=True)
    crash_id = crash["crash_id"]
    tested = version.strip() or "unknown (set --product-version)"
    affected = f"= {version.strip()}" if version.strip() else "the tested revision (unknown; set --product-version)"
    severity = _GITHUB_SEVERITY.get(validation["severity"], validation["severity"])
    checks = validation.get("checks") or {}
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    description = (f"### Summary\n\n{summary.strip()}\n\n### Details\n\n{details.strip()}\n\n"
                   f"### PoC\n\n{poc.strip()}\n\n{_poc_bytes(crash)}\n### Impact\n\n{impact.strip()}\n")
    if validation.get("preconditions"):
        description += f"\nPreconditions: {validation['preconditions'].strip()}\n"
    if (validation.get("conditional_impact") or "").strip():
        description += ("\nIn other environments (not scored above): "
                        f"{validation['conditional_impact'].strip()}\n")
    if workarounds.strip():
        description += f"\n### Workarounds\n\n{workarounds.strip()}\n"

    evidence = ["| Check | Result |", "|---|---|"]
    if "reproducibility" in checks:
        rep = checks["reproducibility"]
        evidence.append(f"| Replays on the harness build | {rep.get('same_fault_runs', rep['crashed'])}/{rep['runs']} "
                        f"reproduced the same fault ({rep['crashed']} faulted at all), "
                        f"signature `{rep.get('signature', '')}` |")
    if "daemon" in checks:
        dm = checks["daemon"]
        evidence.append(f"| Real program over its own socket (no harness) | {dm['summary']} |")
    if checks.get("plain_build", {}).get("configured"):
        evidence.append(f"| Program built without sanitizers | {checks['plain_build']['summary']} |")
    if "debug_allocator" in checks:
        evidence.append(f"| glibc debugging allocator | {checks['debug_allocator']['summary']} |")
    evidence.append(f"| Sanitizer finding | `{crash.get('crash_type')}` at `{crash.get('signature')}` |")
    if validation.get("impact_basis"):
        basis = validation["impact_basis"]
        evidence.append("| Basis of the impact score | " + ", ".join(f"{k}: {basis[k]}" for k in ("C", "I", "A")) + " |")
    for change in validation.get("score_adjustments") or []:
        evidence.append(f"| Not scored | `{change}` |")
    other = (crash.get("details") or {}).get("other_paths") or []
    if other:
        evidence.append(f"| Other paths to the same fault | {'; '.join(f'`{p}`' for p in other)} |")
    if checks.get("delta_relation"):
        evidence.append(f"| Relation to the analysed diff | {checks['delta_relation']} |")

    markdown = "\n".join([
        f"# {title.strip()}",
        "",
        "Draft of a GitHub repository security advisory. Fields are in the order of GitHub's form.",
        "",
        "| Field | Value |",
        "|---|---|",
        "| CVE identifier | none yet (request one from GitHub when publishing) |",
        f"| Ecosystem | — ({NO_ECOSYSTEM}) |",
        f"| Package name | {program} |",
        f"| Affected versions | {affected} |",
        f"| Patched versions | {patched_versions.strip() or '— (none known)'} |",
        f"| Vulnerable functions | {', '.join(f'`{f}`' for f in vulnerable_functions) or '—'} |",
        f"| Severity | {severity} ({validation['cvss_score']}) |",
        f"| CVSS v3.1 | `{validation['cvss_vector']}` |",
        f"| Weaknesses | {', '.join(validation.get('cwe_ids') or []) or '—'} |",
        "| Credits | fbaugur (Tool) |",
        "| AI assistance used to find or write up | yes — found and written by LLM agents; verify before publishing |",
        "",
        "## Description",
        "",
        description,
        "## Validation evidence (not part of the GitHub form)",
        "",
        *evidence,
        "",
        f"Verdict: **{validation['verdict']}** — {validation.get('reasons', '').strip()}",
        "",
        f"Attacker input: {validation.get('attacker_input', '').strip()}",
        "",
        f"Consequence: {validation.get('consequence', '').strip()}",
        "",
        f"Finding `{crash_id}`, input `{crash.get('input_path')}`, tested version {tested}.",
        "",
    ])
    md_path = directory / f"{crash_id}.md"
    md_path.write_text(markdown, encoding="utf-8")

    osv = {
        "schema_version": "1.6.0",
        "id": f"FBA-{crash_id}",
        "modified": now,
        "published": now,
        "summary": title.strip(),
        "details": description,
        "severity": [{"type": "CVSS_V3", "score": validation["cvss_vector"]}],
        "affected": [{
            "package": {"ecosystem": "", "name": program},
            **({"versions": [version.strip()]} if version.strip() else {}),
            "ecosystem_specific": {"affected_functions": vulnerable_functions},
            "database_specific": {"ecosystem_note": NO_ECOSYSTEM,
                                  "patched_versions": patched_versions.strip() or None},
        }],
        "credits": [{"name": "fbaugur", "type": "TOOL"}],
        "database_specific": {"cwe_ids": validation.get("cwe_ids") or [],
                              "severity": severity.upper(), "cvss_score": validation["cvss_score"],
                              "ai_assisted": True, "validation": {k: v for k, v in validation.items()
                                                                  if k != "agent_run"}},
    }
    osv_path = directory / f"{crash_id}.osv.json"
    osv_path.write_text(json.dumps(osv, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"markdown": md_path, "osv": osv_path}


def write_rejection(run_dir: Path, *, crash: dict[str, Any], validation: dict[str, Any]) -> Path:
    """Keep the reasoning for a finding judged not to be a vulnerability (or left for review)."""
    directory = Path(run_dir) / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    name = "not-a-vulnerability" if validation["verdict"] == "NOT_A_VULNERABILITY" else "needs-review"
    path = directory / f"{crash['crash_id']}-{name}.md"
    checks = validation.get("checks") or {}
    lines = [f"# {crash['crash_id']}: {validation['verdict']}", "",
             f"- finding: `{crash.get('crash_type')}` at `{crash.get('signature')}`",
             f"- input: `{crash.get('input_path')}`"]
    if "reproducibility" in checks:
        rep = checks["reproducibility"]
        lines.append(f"- harness replays: {rep.get('same_fault_runs', rep['crashed'])}/{rep['runs']} the same fault "
                     f"({rep['crashed']} faulted at all)")
    if "daemon" in checks:
        lines.append(f"- real program: {checks['daemon']['summary']}")
    if checks.get("plain_build", {}).get("configured"):
        lines.append(f"- {checks['plain_build']['summary']}")
    if "debug_allocator" in checks:
        lines.append(f"- {checks['debug_allocator']['summary']}")
    if validation.get("impact_basis"):
        lines.append("- basis of the impact score: " + ", ".join(f"{k}: {v}" for k, v in validation["impact_basis"].items()))
    for change in validation.get("score_adjustments") or []:
        lines.append(f"- not scored: `{change}`")
    if (validation.get("conditional_impact") or "").strip():
        lines += ["", "## Impact in other environments (not scored)", "", validation["conditional_impact"].strip()]
    lines += ["", "## Reasons", "", validation.get("reasons", "").strip(), "",
              "## Attacker input", "", validation.get("attacker_input", "").strip(), "",
              "## Preconditions", "", validation.get("preconditions", "").strip(), "",
              "## Consequence", "", validation.get("consequence", "").strip(), "",
              f"CVSS (if it were reported): `{validation.get('cvss_vector')}` = {validation.get('cvss_score')}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
