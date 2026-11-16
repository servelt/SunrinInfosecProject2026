"""Agent tools, served to Claude Code over MCP (fbaugur.mcp_server).

Names and arguments follow FuzzingBrain V2's MCP tools (tools/mcp_factory.py):
get_function_source, get_callers, get_callees, search_code, get_file_content,
get_fuzzer_info, get_call_graph, create_direction, create_suspicious_point,
update_suspicious_point, get_suspicious_point, create_pov, trace_pov, create_seed.
The Code Augur lane adds set_threat_model, get_threat_model, record_invariant,
repair_invariant, get_invariant, triage_verdict, refine_invariant; the report
agent uses submit_report.
"""

from __future__ import annotations

import ast
import collections
import difflib
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from .config import RunConfig
from .store import Store, new_id

# --------------------------------------------------------------------------------------
# Generator code execution (create_pov / create_seed / trace_pov)

_ALLOWED_IMPORTS = {"struct", "random", "string", "itertools", "math", "binascii", "zlib", "base64",
                    "hashlib", "json", "re", "collections", "functools"}
_FORBIDDEN_NAMES = {"open", "exec", "eval", "compile", "__import__", "input", "globals", "locals", "vars",
                    "getattr", "setattr", "delattr", "breakpoint", "exit", "quit"}

_RUNNER = r"""
import json, sys
src = open(sys.argv[1]).read()
ns = {}
exec(compile(src, "<generator>", "exec"), ns)
fn = ns["generate"]
out = []
for arg in json.loads(sys.argv[2]):
    value = fn(*arg)
    if isinstance(value, (bytes, bytearray)):
        out.append({"kind": "bytes", "data": bytes(value).hex()})
    elif isinstance(value, str):
        out.append({"kind": "bytes", "data": value.encode("latin-1").hex()})
    elif isinstance(value, (list, tuple)):
        msgs = []
        for m in value:
            if isinstance(m, str):
                m = m.encode("latin-1")
            msgs.append(bytes(m).hex())
        out.append({"kind": "messages", "data": msgs})
    else:
        raise TypeError("generate() must return bytes or a list of bytes, got %s" % type(value).__name__)
print(json.dumps(out))
"""


def check_generator(code: str) -> str | None:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"syntax error: {exc}"
    if not any(isinstance(n, ast.FunctionDef) and n.name == "generate" for n in tree.body):
        return "the code must define a top-level function `generate`"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in _ALLOWED_IMPORTS:
                    return f"import of `{alias.name}` is not allowed (allowed: {sorted(_ALLOWED_IMPORTS)})"
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in _ALLOWED_IMPORTS:
                return f"import from `{node.module}` is not allowed"
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            return f"use of `{node.id}` is not allowed"
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr != "__init__":
            return f"access to `{node.attr}` is not allowed"
    return None


def run_generator(code: str, calls: list[list[Any]], delivery: str, timeout: int = 30) -> list[bytes]:
    from .project import frame_messages

    problem = check_generator(code)
    if problem:
        raise ValueError(problem)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "gen.py"
        src.write_text(code, encoding="utf-8")
        runner = Path(tmp) / "runner.py"
        runner.write_text(_RUNNER, encoding="utf-8")
        argv = ["unshare", "-n" if os.geteuid() == 0 else "-rn", sys.executable, "-I", str(runner), str(src), json.dumps(calls)]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=tmp)
        if proc.returncode != 0:
            raise ValueError("generator failed: " + proc.stderr.strip()[-1500:])
        blobs = []
        for item in json.loads(proc.stdout.strip().splitlines()[-1]):
            if item["kind"] == "bytes":
                blobs.append(bytes.fromhex(item["data"]))
            else:
                blobs.append(frame_messages([bytes.fromhex(m) for m in item["data"]], delivery))
        for blob in blobs:
            if len(blob) > 1 << 20:
                raise ValueError("a generated input is larger than 1 MiB")
        return blobs


# --------------------------------------------------------------------------------------


# FBv2 core/sp_dedup.py, verbatim prompts.  FBv2 calls gpt-4o-mini; the utility tier is used here.
SP_DEDUP_MAX_COMPARE = 20
SP_DEDUP_SYSTEM = ("You are a vulnerability deduplication assistant. "
                   "Your task is to determine if a new SP describes the EXACT SAME "
                   "vulnerability as an existing SP. Be conservative: only mark as "
                   "duplicate if you are CERTAIN they are the same bug. "
                   "When uncertain, say NOT duplicate. "
                   "It's better to have extra SPs than to miss real vulnerabilities.")


def _sp_dedup_prompt(new_description: str, existing: list[dict[str, Any]]) -> str:
    existing_text = "\n".join(f"SP-{i} (ID: {sp['sp_id']}): {sp.get('description', '')}"
                              for i, sp in enumerate(existing, 1))
    return f"""Determine if the NEW suspicious point describes the EXACT SAME vulnerability as any EXISTING suspicious point.

NEW SP:
"{new_description}"

EXISTING SPs:
{existing_text}

Two SPs are duplicates ONLY if they describe the EXACT SAME bug:
1. Same vulnerability type AND
2. Same code location (same variable, same statement, same operation) AND
3. Same root cause

NOT duplicates if:
- Different variables or buffers involved
- Different operations (e.g., different memcpy calls, different array accesses)
- Different control flow paths
- Similar but not identical issues

IMPORTANT: When uncertain, answer "no duplicate".
It's better to have extra SPs than to miss real vulnerabilities.

Respond with JSON only:
- If CERTAIN it's a duplicate: {{"duplicate": true, "duplicate_of": "SP-N"}}
- If uncertain or not duplicate: {{"duplicate": false, "duplicate_of": null}}"""


def parse_sp_dedup(response: str, existing: list[dict[str, Any]]) -> str | None:
    """FBv2 _parse_sp_dedup_response: SP-N, a plain number or a direct id; anything else is no duplicate."""
    text = "\n".join(line for line in response.strip().splitlines() if not line.startswith("```"))
    match = re.search(r"\{.*\}", text, re.S)
    try:
        result = json.loads(match.group(0) if match else text)
    except ValueError:
        low = text.lower()
        if "no duplicate" in low or "not a duplicate" in low or "duplicate" not in low:
            return None
        found = re.search(r"SP-(\d+)", text, re.I)
        index = int(found.group(1)) - 1 if found else -1
        return existing[index]["sp_id"] if 0 <= index < len(existing) else None
    if not isinstance(result, dict) or not result.get("duplicate") or not result.get("duplicate_of"):
        return None
    ref = str(result["duplicate_of"])
    digits = ref[3:] if ref.upper().startswith("SP-") else ref
    if digits.isdigit() and 0 <= int(digits) - 1 < len(existing):
        return existing[int(digits) - 1]["sp_id"]
    return next((sp["sp_id"] for sp in existing if sp["sp_id"] == ref), None)


def sp_duplicate_of(new_description: str, existing: list[dict[str, Any]], cfg: RunConfig) -> str | None:
    """On any failure the SP is kept (FBv2: "assume not a duplicate")."""
    compare = existing[:SP_DEDUP_MAX_COMPARE]
    model, _ = cfg.model_for("sp_dedup")
    prompt = _sp_dedup_prompt(new_description, compare)
    try:
        if cfg.provider == "codex":
            with tempfile.TemporaryDirectory(prefix="fba-dedup-") as tmp:
                out = Path(tmp) / "answer.txt"
                subprocess.run([cfg.codex_executable, "exec", "--skip-git-repo-check", "-m", model, "-s", "read-only",
                                "-C", tmp, "-o", str(out), "-"], input=SP_DEDUP_SYSTEM + "\n\n" + prompt,
                               capture_output=True, text=True, timeout=300)
                text = out.read_text(encoding="utf-8") if out.is_file() else ""
        else:
            env = None
            if cfg.provider == "ollama":
                env = dict(os.environ, ANTHROPIC_BASE_URL=cfg.ollama_url.rstrip("/"), ANTHROPIC_AUTH_TOKEN="ollama",
                           ANTHROPIC_API_KEY="")
            proc = subprocess.run([cfg.claude_executable, "-p", "--model", model, "--output-format", "json",
                                   "--tools", "", "--disable-slash-commands", "--max-turns", "1",
                                   "--system-prompt", SP_DEDUP_SYSTEM],
                                  input=prompt, capture_output=True, text=True, timeout=180, env=env)
            text = json.loads(proc.stdout).get("result", "")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return parse_sp_dedup(text or "", compare)


class ToolError(Exception):
    pass


class Toolbox:
    def __init__(self, run_dir: Path, *, role: str, worker: str = "", harness: str = "", sp: str = "",
                 phi: int | None = None, violation: str = "", direction: str = "", function: str = "",
                 crash: str = "", agent_run: str = ""):
        self.run_dir = Path(run_dir)
        self.cfg = RunConfig.load(self.run_dir)
        self.store = Store(self.run_dir / "state.db")
        self.index = json.loads((self.run_dir / "index.json").read_text(encoding="utf-8"))
        self.source_root = Path(self.index["source_root"])
        self.role, self.worker, self.harness_id, self.sp_id = role, worker, harness, sp
        self.phi, self.violation_id, self.direction_id, self.function = phi, violation, direction, function
        self.crash_id, self.agent_run = crash, agent_run
        self.harness = self.index["harnesses"].get(harness, {})
        self.targets = set(self.index["targets"])
        self.calls = 0
        self.records = 0

    # ----------------------------------------------------------------------------- registry
    def tools(self) -> dict[str, tuple[str, dict[str, Any], Callable[..., Any]]]:
        code = {
            "get_function_source": ("Read the source code of a function (with original line numbers).",
                                    _schema({"function_name": "string"}), self.get_function_source),
            "get_callers": ("List functions that call the given function (static call graph).",
                            _schema({"function_name": "string"}), self.get_callers),
            "get_callees": ("List functions called by the given function (static call graph).",
                            _schema({"function_name": "string"}), self.get_callees),
            "search_code": ("Search the program source with a regular expression. file_pattern is a glob such "
                            "as '*.c' or 'proto_*.c,*.h'.",
                            _schema({"pattern": "string"}, {"file_pattern": "string", "max_results": "integer"}),
                            self.search_code),
            "get_file_content": ("Read lines of a source file (path relative to the source root).",
                                 _schema({"file_path": "string"}, {"start_line": "integer", "end_line": "integer"}),
                                 self.get_file_content),
            "get_fuzzer_info": ("Get the harness (fuzzer) source and how inputs are delivered to the program.",
                                _schema({}), self.get_fuzzer_info),
        }
        if (self.run_dir / "delta.diff").is_file():
            code["get_diff"] = ("Read the code change (unified diff) this delta scan analyses.", _schema({}),
                                self.get_diff)
        role_tools: dict[str, dict[str, tuple[str, dict[str, Any], Callable[..., Any]]]] = {
            "threat_model": {"set_threat_model": (
                "Store the audit's threat model (call once).",
                _schema({"attacker_control": "string", "in_scope": "string", "trust_boundary": "string",
                         "security_relevant_state": "array", "out_of_scope": "string"}, {"notes": "string"}),
                self.set_threat_model), "get_call_graph": self._call_graph_tool()},
            "direction": {"get_call_graph": self._call_graph_tool(), "create_direction": (
                "Create a direction (one business feature). Call once per direction, at most "
                f"{self.cfg.max_directions} per harness.",
                _schema({"name": "string", "risk_level": "string", "risk_reason": "string",
                         "core_functions": "array", "entry_functions": "array"}, {"code_summary": "string"}),
                self.create_direction), "get_threat_model": self._get_threat_tool()},
            "seed": {"create_seed": (
                "Run Python code defining generate(seed_num) -> bytes | list[bytes] for seed_num = 1..num_seeds and "
                "add the outputs to the fuzzer corpus.",
                _schema({"generator_code": "string"}, {"num_seeds": "integer"}), self.create_seed)},
            "sp_generator": {"create_suspicious_point": (
                "Report a potential vulnerability (suspicious point).",
                _schema({"function_name": "string", "vuln_type": "string", "description": "string"},
                        {"score": "number", "important_controlflow": "array"}), self.create_suspicious_point)},
            "delta_sp_generator": {"create_suspicious_point": (
                "Report a potential vulnerability (suspicious point).",
                _schema({"function_name": "string", "vuln_type": "string", "description": "string"},
                        {"score": "number", "important_controlflow": "array"}), self.create_suspicious_point),
                "get_threat_model": self._get_threat_tool()},
            "sp_verifier": {"update_suspicious_point": (
                "Submit the verification verdict for the suspicious point under review.",
                _schema({"suspicious_point_id": "string"},
                        {"score": "number", "is_checked": "boolean", "is_real": "boolean", "is_important": "boolean",
                         "verification_notes": "string", "pov_guidance": "string", "reachability_status": "string",
                         "reachability_multiplier": "number", "reachability_reason": "string",
                         "safety_reason": "string", "safety_location": "string", "description": "string",
                         "vuln_type": "string"}), self.update_suspicious_point),
                "get_suspicious_point": self._get_sp_tool(), "get_threat_model": self._get_threat_tool()},
            "pov": {"create_pov": (
                "Run Python code defining generate(variant) -> bytes | list[bytes] for variants 1..3, execute each "
                "input on the harness and report crashes.",
                _schema({"generator_code": "string"}), self.create_pov),
                "trace_pov": (
                "Run Python code defining generate() -> bytes | list[bytes] once and report which functions the "
                f"input executed (available after {self.cfg.trace_unlock_after} failed create_pov calls).",
                _schema({"generator_code": "string"}), self.trace_pov),
                "get_suspicious_point": self._get_sp_tool()},
            "vuln_validator": {"submit_validation": (
                "Submit the verdict on whether this confirmed finding is a security vulnerability.",
                _schema({"verdict": "string", "reasons": "string", "attacker_input": "string",
                         "preconditions": "string", "consequence": "string", "cvss_vector": "string",
                         "cwe_ids": "array", "impact_basis": "object"},
                        {"vulnerable_functions": "array", "conditional_impact": "string"}), self.submit_validation),
                "get_threat_model": self._get_threat_tool()},
            "report": {"submit_advisory": (
                "Submit the GitHub security advisory for the validated vulnerability.",
                _schema({"title": "string", "summary": "string", "details": "string", "poc": "string",
                         "impact": "string"}, {"vulnerable_functions": "array", "patched_versions": "string",
                                               "workarounds": "string"}), self.submit_advisory)},
            "invariant_recorder": {"record_invariant": (
                "Commit one invariant: a side-effect-free C expression that must hold immediately before the "
                "given source line.",
                _schema({"file": "string", "line": "integer", "expression": "string",
                         "security_property": "string", "rationale": "string"}), self.record_invariant),
                "get_threat_model": self._get_threat_tool(), "get_suspicious_point": self._get_sp_tool()},
            "invariant_repair": {"repair_invariant": (
                "Replace the line and/or expression of the invariant that failed to compile, or give up.",
                _schema({"explanation": "string"}, {"line": "integer", "expression": "string", "give_up": "boolean"}),
                self.repair_invariant), "get_invariant": self._get_inv_tool()},
            "triage": {"triage_verdict": (
                "Submit the triage verdict for the invariant violation: REAL_ISSUE, TOO_STRONG or UNDECIDED.",
                _schema({"verdict": "string", "explanation": "string"},
                        {"downstream_function": "string", "vuln_type": "string", "description": "string",
                         "pov_guidance": "string"}), self.triage_verdict),
                "get_invariant": self._get_inv_tool(), "get_threat_model": self._get_threat_tool()},
            "refine": {"refine_invariant": (
                "Replace the invariant with a refined one, or give up.",
                _schema({"rationale": "string"}, {"expression": "string", "line": "integer", "file": "string",
                                                  "give_up": "boolean"}), self.refine_invariant),
                "get_invariant": self._get_inv_tool(), "get_threat_model": self._get_threat_tool()},
        }
        out = dict(code)
        out.update(role_tools.get(self.role, {}))
        return out

    def _call_graph_tool(self):
        return ("Call graph reachable from the harness's input entry points (BFS over static edges).",
                _schema({}, {"depth": "integer"}), self.get_call_graph)

    def _get_threat_tool(self):
        return ("Read the audit's threat model.", _schema({}), self.get_threat_model)

    def _get_sp_tool(self):
        return ("Read a suspicious point.", _schema({"suspicious_point_id": "string"}), self.get_suspicious_point)

    def _get_inv_tool(self):
        return ("Read the invariant under work, its history and source context.", _schema({}), self.get_invariant)

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        tools = self.tools()
        if name not in tools:
            raise ToolError(f"unknown tool {name}")
        self.calls += 1
        limit = int(self.cfg.max_turns.get(self.role, 20)) * 3
        if self.calls > limit:
            raise ToolError("tool budget for this agent is exhausted; give your final answer now without tools")
        fn = tools[name][2]
        return fn(**arguments)

    # ----------------------------------------------------------------------------- code tools
    def _functions(self, name: str) -> list[dict[str, Any]]:
        found = self.index["functions"].get(name) or []
        return sorted(found, key=lambda f: (name not in self.targets, f["file"]))

    def get_function_source(self, function_name: str) -> str:
        found = self._functions(function_name)
        if not found:
            close = difflib.get_close_matches(function_name, list(self.index["functions"]), n=8, cutoff=0.6)
            return f"function `{function_name}` not found. Similar names: {close}"
        parts = []
        for fn in found[:3]:
            body = fn["source"].splitlines()
            numbered = "\n".join(f"{fn['start'] + i:6d}  {line}" for i, line in enumerate(body))
            parts.append(f"File: {fn['file']}  Lines: {fn['start']}-{fn['end']}"
                         f"{'  (reachable from the harness)' if function_name in self.targets else ''}\n{numbered}")
        if len(found) > 3:
            parts.append(f"... {len(found) - 3} more definitions with this name")
        return "\n\n".join(parts)

    def get_callers(self, function_name: str) -> str:
        names = sorted(self.index["callers"].get(function_name, []))
        if not names:
            return f"no static callers recorded for `{function_name}` (it may be called through a function pointer)"
        return "\n".join(f"{n}{'' if n in self.targets else '  (not reachable from this harness)'}" for n in names[:80])

    def get_callees(self, function_name: str) -> str:
        names = sorted(self.index["callees"].get(function_name, []))
        if not names:
            return f"no static callees recorded for `{function_name}`"
        return "\n".join(names[:120])

    def search_code(self, pattern: str, file_pattern: str = "*.c,*.h", max_results: int = 40) -> str:
        try:
            regex = re.compile(pattern)
        except re.error:
            regex = re.compile(re.escape(pattern))
        globs = [g.strip() for g in (file_pattern or "*.c,*.h").split(",") if g.strip()]
        include_vendor = any("vendor" in g for g in globs)
        hits: list[str] = []
        for path in sorted(self.source_root.rglob("*")):
            rel = path.relative_to(self.source_root).as_posix()
            if not path.is_file() or path.suffix not in (".c", ".h", ".cc", ".cpp", ".hpp"):
                continue
            if not include_vendor and rel.startswith(("vendor/", "t/", "testapp")):
                continue
            if not any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(path.name, g) for g in globs):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for number, line in enumerate(lines, 1):
                if regex.search(line):
                    hits.append(f"{rel}:{number}: {line.strip()[:200]}")
                    if len(hits) >= max(1, min(int(max_results or 40), 200)):
                        return "\n".join(hits) + "\n(result limit reached)"
        return "\n".join(hits) or "no matches"

    def get_file_content(self, file_path: str, start_line: int = 1, end_line: int | None = None) -> str:
        path = (self.source_root / file_path).resolve()
        if not str(path).startswith(str(self.source_root)) or not path.is_file():
            return f"file `{file_path}` not found under the source root"
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(start_line or 1))
        end = min(len(lines), int(end_line or start + 150), start + 300)
        return f"{file_path} lines {start}-{end} of {len(lines)}\n" + "\n".join(
            f"{i:6d}  {lines[i - 1]}" for i in range(start, end + 1))

    def get_fuzzer_info(self) -> str:
        if not self.harness:
            names = ", ".join(self.index["harnesses"])
            return f"no harness bound to this agent; harnesses: {names}"
        text = Path(self.harness["source_path"]).read_text(encoding="utf-8", errors="replace")
        return f"{self.harness['delivery_text']}\n\nHarness source ({Path(self.harness['source_path']).name}):\n{text}"

    def get_call_graph(self, depth: int = 4) -> str:
        roots = [n for n in self.index["interpreters"] if n in self.targets] or list(self.index["interpreters"])
        seen = set(roots)
        frontier = list(roots)
        lines = []
        for level in range(max(1, min(int(depth or 4), 8))):
            nxt = []
            for name in frontier:
                callees = sorted(c for c in self.index["callees"].get(name, []) if c in self.targets)
                if callees:
                    lines.append(f"{'  ' * level}{name} -> {', '.join(callees[:40])}")
                for c in callees:
                    if c not in seen:
                        seen.add(c)
                        nxt.append(c)
            frontier = nxt
            if len(lines) > 400:
                break
        return (f"Entry/interpreter functions: {roots}\n" + "\n".join(lines[:400])
                + f"\n({len(seen)} functions listed; {len(self.targets)} reachable functions in total)")

    # ----------------------------------------------------------------------------- threat model / directions
    def set_threat_model(self, attacker_control: str, in_scope: str, trust_boundary: str,
                         security_relevant_state: list, out_of_scope: str, notes: str = "") -> str:
        body = {"attacker_control": attacker_control, "in_scope": in_scope, "trust_boundary": trust_boundary,
                "security_relevant_state": security_relevant_state, "out_of_scope": out_of_scope, "notes": notes}
        self.store.conn.execute("INSERT OR REPLACE INTO threat_model VALUES (?,?,?)",
                                ("project", json.dumps(body, ensure_ascii=False), time.time()))
        return "threat model stored"

    def get_threat_model(self) -> str:
        row = self.store.row("SELECT body FROM threat_model WHERE harness_scope='project'")
        return json.dumps(row["body"], ensure_ascii=False, indent=2) if row else "no threat model was recorded"

    def create_direction(self, name: str, risk_level: str, risk_reason: str, core_functions: list,
                         entry_functions: list, code_summary: str = "") -> str:
        risk = (risk_level or "").lower()
        if risk not in ("high", "medium", "low"):
            raise ToolError("risk_level must be high, medium or low")
        count = self.store.scalar("SELECT COUNT(*) FROM directions WHERE harness_id=?", self.harness_id)
        if count >= self.cfg.max_directions:
            raise ToolError(f"this harness already has {count} directions (maximum {self.cfg.max_directions})")
        core = [f for f in core_functions if f in self.index["functions"]]
        entry = [f for f in entry_functions if f in self.index["functions"]]
        unknown = sorted(set(core_functions) | set(entry_functions) - set(core) - set(entry))
        if not core:
            raise ToolError(f"none of the core functions exist: {core_functions}")
        direction_id = new_id("dir")
        self.store.insert("directions", {"direction_id": direction_id, "harness_id": self.harness_id, "name": name,
                                         "risk_level": risk, "risk_reason": risk_reason, "core_functions": core,
                                         "entry_functions": entry, "code_summary": code_summary,
                                         "created_at": time.time()})
        note = f"; ignored unknown function names {unknown}" if unknown else ""
        outside = sorted(set(core + entry) - self.targets)
        if outside:
            note += f"; not statically reachable from this harness (kept): {outside}"
        return f"direction {direction_id} created ({len(core)} core, {len(entry)} entry){note}"

    # ----------------------------------------------------------------------------- seeds
    def _corpus_dir(self) -> Path:
        path = self.run_dir / "work" / self.harness_id / "corpus-extra"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _add_to_corpus(self, blob: bytes, label: str) -> Path:
        digest = hashlib.sha1(blob).hexdigest()
        path = self._corpus_dir() / f"{label}-{digest[:16]}"
        if not path.exists():
            path.write_bytes(blob)
        return path

    def create_seed(self, generator_code: str, num_seeds: int = 5) -> str:
        n = max(1, min(int(num_seeds or 5), 20))
        try:
            blobs = run_generator(generator_code, [[i] for i in range(1, n + 1)], self.harness["delivery"])
        except (ValueError, subprocess.TimeoutExpired) as exc:
            raise ToolError(str(exc))
        paths = [self._add_to_corpus(b, f"seed-{self.role}") for b in blobs]
        sizes = [len(b) for b in blobs]
        return f"{len(paths)} seeds added to the corpus (sizes {sizes})"

    def get_diff(self) -> str:
        """FBv2 get_diff: the whole diff, plus where each changed function sits in this program."""
        text = (self.run_dir / "delta.diff").read_text(encoding="utf-8", errors="replace")
        mapping = self.run_dir / "delta-changes.json"
        note = ""
        if mapping.is_file():
            data = json.loads(mapping.read_text(encoding="utf-8"))
            files = ", ".join(f"{f['diff_file']} -> {f['source_file']}" for f in data["report"].get("files", []))
            note = (f"Paths in the diff are relative to its repository; in this program: {files}. "
                    "Line numbers on the new side match the analysed source.\n\n")
        if len(text) > 60000:
            text = text[:60000] + "\n... (diff truncated; read individual functions with get_function_source)"
        return note + text

    # ----------------------------------------------------------------------------- suspicious points
    def create_suspicious_point(self, function_name: str, vuln_type: str, description: str, score: float = 0.5,
                                important_controlflow: list | None = None) -> str:
        if function_name not in self.index["functions"]:
            raise ToolError(f"unknown function `{function_name}`")
        score = max(0.0, min(1.0, float(score if score is not None else 0.5)))
        # FBv2 core/sp_dedup.py: a model compares the new description with the SPs already recorded for
        # the same function and merges only an exact same bug.  Scope is this worker's SPs: an SP here
        # belongs to one sanitizer worker's binary (FBv2 instead adds the harness/sanitizer as a source).
        existing = self.store.rows("SELECT sp_id, vuln_type, description, score FROM sps WHERE worker_id=? AND "
                                   "function_name=? AND merged_into IS NULL ORDER BY created_at",
                                   self.worker, function_name)
        duplicate = sp_duplicate_of(description, existing, self.cfg) if existing else None
        if duplicate:
            now = time.time()
            self.store.insert("sps", {"sp_id": new_id("sp"), "worker_id": self.worker, "harness_id": self.harness_id,
                                      "direction_id": self.direction_id, "function_name": function_name,
                                      "vuln_type": vuln_type, "description": description, "score": score,
                                      "important_controlflow": important_controlflow or [], "status": "duplicate",
                                      "merged_into": duplicate, "origin": "generator", "origin_ref": self.agent_run,
                                      "created_at": now, "updated_at": now})
            return json.dumps({"created": False, "merged": True, "suspicious_point_id": duplicate,
                               "message": f"Merged with existing SP in {function_name}"})
        sp_id = new_id("sp")
        now = time.time()
        self.store.insert("sps", {"sp_id": sp_id, "worker_id": self.worker, "harness_id": self.harness_id,
                                  "direction_id": self.direction_id, "function_name": function_name,
                                  "vuln_type": vuln_type, "description": description, "score": score,
                                  "important_controlflow": important_controlflow or [], "status": "pending_verify",
                                  "origin": "generator", "origin_ref": self.agent_run, "created_at": now,
                                  "updated_at": now})
        self.store.conn.execute("UPDATE pool SET sp_count=sp_count+1 WHERE worker_id=? AND direction_id=? AND "
                                "function_name=?", (self.worker, self.direction_id, self.function))
        return json.dumps({"created": True, "suspicious_point_id": sp_id})

    def get_suspicious_point(self, suspicious_point_id: str) -> str:
        row = self.store.row("SELECT * FROM sps WHERE sp_id=?", suspicious_point_id)
        if not row:
            return f"suspicious point {suspicious_point_id} not found"
        keep = ("sp_id", "function_name", "vuln_type", "description", "score", "important_controlflow", "status",
                "verification_notes", "pov_guidance", "reachability_status", "safety_reason", "safety_location",
                "origin", "pov_attempts")
        return json.dumps({k: row.get(k) for k in keep}, ensure_ascii=False, indent=2)

    def update_suspicious_point(self, suspicious_point_id: str, **fields: Any) -> str:
        if suspicious_point_id != self.sp_id:
            raise ToolError(f"you may only update the suspicious point under review ({self.sp_id})")
        allowed = {"score", "is_checked", "is_real", "is_important", "verification_notes", "pov_guidance",
                   "reachability_status", "reachability_multiplier", "reachability_reason", "safety_reason",
                   "safety_location", "description", "vuln_type"}
        values = {k: v for k, v in fields.items() if k in allowed and v is not None}
        if values.get("is_important") and not (values.get("pov_guidance") or
                                                self.store.scalar("SELECT pov_guidance FROM sps WHERE sp_id=?",
                                                                  self.sp_id)):
            raise ToolError("is_important=True requires pov_guidance (input direction, how to reach, constraints)")
        if "safety_location" in values and values["safety_location"]:
            from .project import parse_location
            loc = parse_location(values["safety_location"])
            if not loc or not (self.source_root / loc[0]).is_file():
                raise ToolError("safety_location must be `file:line` with a file path relative to the source root")
        for key in ("is_checked", "is_real", "is_important"):
            if key in values:
                values[key] = 1 if values[key] else 0
        values["updated_at"] = time.time()
        self.store.update("sps", "sp_id", self.sp_id, values)
        return "suspicious point updated"

    # ----------------------------------------------------------------------------- PoV
    def _sp(self) -> dict[str, Any]:
        row = self.store.row("SELECT * FROM sps WHERE sp_id=?", self.sp_id)
        if not row:
            raise ToolError("no suspicious point bound to this agent")
        return row

    def _on_target(self, sp: dict[str, Any], result) -> bool:
        """Did this finding happen in the function the suspicious point is about?

        Measured on LightFTP: the PoVs written for `ftpRMD`, `ftpDELE` and `ftpLIST` all crashed
        earlier, in the logging every command line goes through (writelogentry from
        ftp_client_thread), and each was recorded as proving its own suspicious point.  The
        handler-specific defects were never tested.  A crash counts for this point only when the
        point's function is on the stack -- or, for undefined behaviour, the reported site lies
        inside that function.
        """
        from .runner import new_ub_sites, program_frames
        target = str(sp.get("function_name") or "")
        if not target:
            return True
        if result.crashed:
            return any(str(f.get("function")) == target for f in program_frames(result.frames))
        spans = [(Path(fn["file"]).name, fn["start"], fn["end"]) for fn in self.index["functions"].get(target, [])]
        for site in new_ub_sites(result, self._ub_baseline()):
            name, _, line = site.rpartition(":")
            if line.isdigit() and any(name == f and s <= int(line) <= e for f, s, e in spans):
                return True
        return False

    def _ub_baseline(self) -> set[str]:
        if not hasattr(self, "_baseline"):
            from .runner import load_ub_baseline
            self._baseline = load_ub_baseline(self.run_dir)
        return self._baseline

    def create_pov(self, generator_code: str) -> str:
        from .runner import crash_signature, finding_type, is_finding, run_input

        sp = self._sp()
        attempt = (sp.get("pov_attempts") or 0) + 1
        if attempt > self.cfg.max_pov_attempts:
            raise ToolError(f"create_pov limit ({self.cfg.max_pov_attempts}) reached; stop and summarize")
        try:
            blobs = run_generator(generator_code, [[1], [2], [3]], self.harness["delivery"])
        except (ValueError, subprocess.TimeoutExpired) as exc:
            raise ToolError(str(exc))
        self.store.update("sps", "sp_id", self.sp_id, {"pov_attempts": attempt, "updated_at": time.time()})
        pov_dir = self.run_dir / "povs" / self.sp_id
        pov_dir.mkdir(parents=True, exist_ok=True)
        sp_corpus = self.run_dir / "work" / self.worker / "sp" / self.sp_id / "corpus"
        sp_corpus.mkdir(parents=True, exist_ok=True)
        lines = []
        crashed_any = False
        for variant, blob in enumerate(blobs, 1):
            path = pov_dir / f"a{attempt}-v{variant}.bin"
            path.write_bytes(blob)
            # This agent's own build first: the MSan worker proves its points on the MSan build.
            # The other build is a second look -- a read of uninitialized memory is invisible to
            # ASan, an overflow to MSan -- and a finding there is filed under that build's worker,
            # which is the one the confirmation lane replays it on.
            on_msan = self.worker.endswith("-msan")
            asan_worker = self.worker[:-len("-msan")] if on_msan else self.worker
            builds = [(Path(self.harness["binary"]), asan_worker)]
            if self.harness.get("msan_binary"):
                builds.append((Path(self.harness["msan_binary"]), f"{asan_worker}-msan"))
            if on_msan:
                builds.reverse()
            baseline = self._ub_baseline()
            result, worker = run_input(builds[0][0], blob, timeout=self.cfg.harness_timeout_seconds), builds[0][1]
            found = is_finding(result, baseline)
            for binary, other in builds[1:]:
                if found:
                    break
                second = run_input(binary, blob, timeout=self.cfg.harness_timeout_seconds)
                if is_finding(second, baseline):
                    result, found, worker = second, True, other
            # FBv2 isolates suspicious points per {fuzzer, sanitizer}: a point is proven only on its
            # own worker's build.  A fault the other build sees is still filed (under that worker),
            # but it is another sanitizer's bug, not proof of this point.  Measured on the LightFTP
            # delta run: the MSan worker filed a stack-buffer-overflow point, the ASan build crashed
            # on its PoV, and the point was recorded as proven by MemorySanitizer.
            own_build = worker == self.worker
            on_target = found and own_build and self._on_target(sp, result)
            if not found:
                # Only inputs that do not fault feed the fuzzers.  A faulting input in a libFuzzer
                # corpus stops every later fuzzer start at the seed-loading step.
                (sp_corpus / path.name).write_bytes(blob)       # FBv2: failed blobs feed the SP fuzzer
                self._add_to_corpus(blob, "pov")                  # and (here) the global corpus
            pov_id = new_id("pov")
            self.store.insert("povs", {"pov_id": pov_id, "sp_id": self.sp_id, "worker_id": self.worker,
                                       "attempt": attempt, "variant": variant, "blob_path": str(path),
                                       "crashed": int(on_target), "crash_type": finding_type(result, baseline),
                                       "summary": result.summary(), "created_at": time.time()})
            if found:
                # Every finding is filed, on target or not: an off-target fault is still a fault.
                self.store.insert("crashes", {"crash_id": new_id("crash"), "worker_id": worker, "source": "pov",
                                              "sp_id": self.sp_id if on_target else None, "input_path": str(path),
                                              "status": "pending", "crash_type": finding_type(result, baseline),
                                              "frames": result.frames,
                                              "created_at": time.time(), "updated_at": time.time()})
            if on_target:
                crashed_any = True
            hint = ""
            if found and not own_build:
                hint = (f" | OTHER SANITIZER: only the {worker} build detects this "
                        f"({finding_type(result, baseline)}); it is filed for that worker. This worker's "
                        f"sanitizer cannot detect this bug type, so it does not prove this suspicious point.")
            elif found and not on_target:
                hint = (f" | OFF TARGET: this fault is at `{crash_signature(result, baseline)}`, not in "
                        f"`{sp.get('function_name')}`. It is filed as its own finding but does not prove this "
                        f"suspicious point. Change the input so it avoids that earlier fault and reaches "
                        f"`{sp.get('function_name')}` (for example keep each line short enough not to trigger it).")
            if not found:
                ub = [u for u in result.ubsan if u["message"]][:2]
                hint = f" | UBSan: {ub}" if ub else ""
                tail = [l for l in result.stderr_tail.splitlines() if l.strip() and "INFO:" not in l
                        and "Running" not in l and "NOTE" not in l and "***" not in l][-3:]
                hint += f" | stderr: {tail}" if tail else ""
            mark = "CRASH " if on_target else ("OTHER SANITIZER " if found and not own_build else ("FAULT ELSEWHERE " if found else ""))
            summary = result.summary() if result.crashed or not found else finding_type(result, baseline)
            lines.append(f"variant {variant} ({len(blob)} bytes): {mark}{summary}{hint}")
        status = "crashed=True" if crashed_any else "crashed=False"
        remaining = self.cfg.max_pov_attempts - attempt
        unlock = (" trace_pov is now available." if attempt >= self.cfg.trace_unlock_after and not crashed_any else "")
        return f"attempt {attempt}: {status} ({remaining} attempts left).{unlock}\n" + "\n".join(lines)

    def trace_pov(self, generator_code: str) -> str:
        from .runner import covered_functions

        sp = self._sp()
        if (sp.get("pov_attempts") or 0) < self.cfg.trace_unlock_after:
            raise ToolError(f"trace_pov unlocks after {self.cfg.trace_unlock_after} failed create_pov attempts")
        try:
            blob = run_generator(generator_code, [[]], self.harness["delivery"])[0]
        except (ValueError, subprocess.TimeoutExpired) as exc:
            raise ToolError(str(exc))
        covered = covered_functions(Path(self.harness["binary"]), blob)
        target = sp["function_name"]
        callers = set(self.index["callers"].get(target, []))
        info = {
            "target_function": target,
            "target_reached": target in covered,
            "callers_reached": sorted(callers & set(covered)),
            "functions_executed": len(covered),
        }
        fn = (self._functions(target) or [{}])[0]
        same_file = sorted(n for n in covered if any(f.get("file") == fn.get("file")
                                                    for f in self.index["functions"].get(n, [])))
        info["executed_in_target_file"] = same_file[:80]
        return json.dumps(info, indent=2)

    # ----------------------------------------------------------------------------- report
    VERDICTS = ("VULNERABILITY", "NOT_A_VULNERABILITY", "NEEDS_REVIEW")

    IMPACT_BASES = ("measured", "code", "conditional", "none")

    def submit_validation(self, verdict: str, reasons: str, attacker_input: str, preconditions: str,
                          consequence: str, cvss_vector: str, cwe_ids: list, impact_basis: dict | None = None,
                          vulnerable_functions: list | None = None, conditional_impact: str = "") -> str:
        from . import cvss
        if not self.crash_id:
            raise ToolError("no confirmed finding is bound to this agent")
        verdict = verdict.strip().upper().replace(" ", "_")
        if verdict not in self.VERDICTS:
            raise ToolError(f"verdict must be one of {self.VERDICTS}")
        try:
            submitted = cvss.normalise(cvss_vector)
            cvss.base_score(submitted)
        except ValueError as exc:
            raise ToolError(f"invalid CVSS v3.1 vector: {exc}") from exc
        # Impact is scored only where it is shown: measured in the normal build, or proven from the
        # code for the default build and configuration.  An impact that needs another environment
        # (a hardened allocator, another libc, a non-default option) is recorded, not scored.  Three
        # validators gave the same one-byte overflow 0.0, 4.8 and 3.7 because nothing separated
        # the two.
        row = self.store.row("SELECT details FROM crashes WHERE crash_id=?", self.crash_id) or {}
        checks = (row.get("details") or {}).get("checks", {})
        plain = checks.get("plain_build") or {}
        basis = {str(k).strip().upper(): str(v).strip().lower() for k, v in (impact_basis or {}).items()}
        metrics = dict(part.split(":", 1) for part in submitted.split("/")[1:])
        adjusted = []
        for name in ("C", "I", "A"):
            value = metrics[name]
            kind = basis.get(name, "none" if value == "N" else "")
            if kind not in self.IMPACT_BASES:
                raise ToolError(f"impact_basis must give {name} one of {self.IMPACT_BASES} (for {name}:{value})")
            if value != "N" and kind == "none":
                raise ToolError(f"{name}:{value} is claimed with basis 'none'; give its basis or set {name}:N")
            if value != "N" and kind == "measured" and plain.get("started") and not plain.get("effect"):
                raise ToolError(f"impact_basis {name} is 'measured', but the normal-build replay shows no effect "
                                f"({plain.get('summary')}). Prove it from the code for the default build ('code', "
                                f"with file:line) or mark it 'conditional' and describe the condition")
            if value != "N" and kind == "conditional":
                metrics[name] = "N"
                adjusted.append(f"{name}:{value} -> {name}:N (needs another environment)")
            basis[name] = kind
        if adjusted and not str(conditional_impact).strip():
            raise ToolError("an impact is marked 'conditional'; describe the condition in conditional_impact")
        vector = "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in metrics.items())
        score = cvss.base_score(vector)
        cwes = []
        for cwe in cwe_ids or []:
            text = str(cwe).strip().upper()
            text = text if text.startswith("CWE-") else f"CWE-{text}"
            if not text[4:].isdigit():
                raise ToolError(f"CWE identifiers look like CWE-121, not {cwe!r}")
            cwes.append(text)
        details = dict(row.get("details") or {})
        details["validation"] = {
            "verdict": verdict, "reasons": reasons, "attacker_input": attacker_input,
            "preconditions": preconditions, "consequence": consequence, "cvss_vector": vector,
            "cvss_score": score, "severity": cvss.rating(score), "cwe_ids": cwes,
            "impact_basis": {k: basis[k] for k in ("C", "I", "A")}, "cvss_vector_submitted": submitted,
            "score_adjustments": adjusted, "conditional_impact": str(conditional_impact or "").strip(),
            "vulnerable_functions": [str(f) for f in (vulnerable_functions or [])],
            "checks": details.get("checks", {}), "agent_run": self.agent_run}
        self.store.update("crashes", "crash_id", self.crash_id, {"details": details, "updated_at": time.time()})
        note = (" -- adjusted: " + "; ".join(adjusted)) if adjusted else ""
        return f"recorded {verdict}; {vector} scores {score} ({cvss.rating(score)}){note}"

    def submit_advisory(self, title: str, summary: str, details: str, poc: str, impact: str,
                        vulnerable_functions: list | None = None, patched_versions: str = "",
                        workarounds: str = "") -> str:
        from .advisory import write_advisory
        if not self.crash_id:
            raise ToolError("no confirmed finding is bound to this agent")
        row = self.store.row("SELECT * FROM crashes WHERE crash_id=?", self.crash_id) or {}
        validation = (row.get("details") or {}).get("validation")
        if not validation or validation.get("verdict") != "VULNERABILITY":
            raise ToolError("this finding has not been validated as a vulnerability")
        for name, value in (("title", title), ("summary", summary), ("details", details), ("poc", poc),
                            ("impact", impact)):
            if not str(value or "").strip():
                raise ToolError(f"{name} is empty; GitHub requires it")
        paths = write_advisory(
            self.run_dir, crash=row, validation=validation, program=self.index["program"],
            version=self.cfg.product_version, title=title, summary=summary, details=details, poc=poc,
            impact=impact, vulnerable_functions=vulnerable_functions or validation.get("vulnerable_functions") or [],
            patched_versions=patched_versions, workarounds=workarounds)
        self.store.update("crashes", "crash_id", self.crash_id,
                          {"report_path": str(paths["markdown"]), "status": "reported", "updated_at": time.time()})
        return f"advisory written to {paths['markdown']} and {paths['osv']}"

    def submit_report(self, vuln_type: str, title: str, root_cause: str, report_markdown: str) -> str:
        if not self.crash_id:
            raise ToolError("no confirmed crash is bound to this agent")
        directory = self.run_dir / "reports"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.crash_id}.md"
        row = self.store.row("SELECT * FROM crashes WHERE crash_id=?", self.crash_id) or {}
        header = (f"# {title}\n\n- crash: `{self.crash_id}`\n- type: `{vuln_type}`\n"
                  f"- input: `{row.get('input_path')}`\n- harness: `{self.harness_id}`\n"
                  f"- suspicious point: `{row.get('sp_id') or '-'}`\n\n## Root cause\n\n{root_cause}\n\n")
        path.write_text(header + report_markdown.strip() + "\n", encoding="utf-8")
        self.store.update("crashes", "crash_id", self.crash_id,
                          {"crash_type": vuln_type, "report_path": str(path), "status": "reported",
                           "updated_at": time.time()})
        return f"report written to {path}"

    # ----------------------------------------------------------------------------- invariants
    def _builder(self):
        from .instrument import InvariantBuilder

        if not self.harness:
            raise ToolError("no harness bound to this agent")
        return InvariantBuilder(
            source_root=self.source_root, harness_source=Path(self.harness["source_path"]),
            build_plan=Path(self.harness["build_plan"]) if self.harness.get("build_plan") else None,
            work_dir=self.run_dir / "work" / self.harness_id / "invariants",
            harnesscreator_src=Path(self.index["harnesscreator_src"]),
            python=self.cfg.python or sys.executable, extra_cflags=self.cfg.native_extra_cflags,
            compile_database=Path(self.index["compile_database"]) if self.index.get("compile_database") else None)

    def _check_invariant(self, file: str, line: int, expression: str) -> bool:
        """Static + real-compiler validation; raises ToolError with the compiler's own words."""
        from .instrument import Invariant

        builder = self._builder()
        problems = builder.precheck(file, line, expression)
        if problems:
            raise ToolError("; ".join(problems))
        scratch = self.run_dir / "work" / self.harness_id / "syntax"
        probe = Invariant(num=900 + (self.records % 50), file=file, line=line, expression=expression)
        try:
            error, distance = builder.syntax_check(probe, scratch)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ToolError(f"could not compile the check: {exc}")
        if error:
            raise ToolError("the check does not compile at that line:\n" + error)
        return distance

    def _source_window(self, file: str, line: int, before: int = 18, after: int = 8) -> str:
        path = self.source_root / file
        if not path.is_file():
            return ""
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start, end = max(1, line - before), min(len(lines), line + after)
        return "\n".join(f"{i:6d} {'>' if i == line else ' '} {lines[i - 1]}" for i in range(start, end + 1))

    def record_invariant(self, file: str, line: int, expression: str, security_property: str,
                         rationale: str) -> str:
        line = int(line)
        expression = (expression or "").strip().rstrip(";")
        if self.records >= 3:
            raise ToolError("at most 3 invariants per safety judgment; stop here")
        distance = self._check_invariant(file, line, expression)
        # One program, one invariant: both harnesses build the same source, so an identical
        # assertion recorded for the other harness is already being tested.
        existing = self.store.row("SELECT phi_num, harness_id FROM invariants WHERE file=? AND line=? AND "
                                  "expression=? AND status NOT IN ('withdrawn','superseded')",
                                  file, line, expression)
        if existing:
            return (f"an identical invariant is already committed as phi {existing['phi_num']} "
                    f"(recorded for {existing['harness_id']}); every harness of this program tests it")
        now = time.time()
        with self.store.tx() as conn:
            cursor = conn.execute(
                "INSERT INTO invariants (harness_id, sp_id, file, line, expression, security_property, rationale,"
                " status, distance, history, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.harness_id, self.sp_id, file, line, expression, security_property, rationale,
                 "pending_build", int(distance),
                 json.dumps([{"event": "recorded", "by": self.agent_run, "at": now}]), now, now))
            phi = cursor.lastrowid
        self.records += 1
        note = ""
        if file in set(self.index.get("closed_files") or ()):
            note = (f"\nNOTE: no verified normal input of this program ever executed a function of "
                    f"`{file}`, so this harness may not reach the assertion at all. If the safety "
                    "argument also holds at a site the input path does reach, record it there instead.")
        elif self.function and self.function not in set(self.index.get("executed_by_seeds") or ()):
            note = (f"\nNOTE: no verified normal input executed `{self.function}`, so the assertion "
                    "may not be reached. The harness still gets it; reach is measured after the build.")
        return (f"invariant phi {phi} committed at {file}:{line} and it compiles"
                f"{' with a distance signal for the fuzzer' if distance else ''}; "
                "it will be built into the harness and the fuzzer will try to falsify it" + note)

    def get_invariant(self) -> str:
        if self.phi is None:
            raise ToolError("no invariant bound to this agent")
        row = self.store.row("SELECT * FROM invariants WHERE phi_num=?", self.phi)
        if not row:
            raise ToolError(f"invariant {self.phi} not found")
        info = {k: row.get(k) for k in ("phi_num", "file", "line", "expression", "security_property",
                                        "rationale", "status", "repairs", "refinements", "last_error", "history")}
        info["source_around_the_line"] = self._source_window(row["file"], row["line"])
        if row.get("sp_id"):
            info["from_suspicious_point"] = json.loads(self.get_suspicious_point(row["sp_id"]))
        return json.dumps(info, ensure_ascii=False, indent=2)

    def repair_invariant(self, explanation: str, line: int | None = None, expression: str | None = None,
                         give_up: bool = False) -> str:
        if self.phi is None:
            raise ToolError("no invariant bound to this agent")
        row = self.store.row("SELECT * FROM invariants WHERE phi_num=?", self.phi)
        history = list(row.get("history") or [])
        if give_up:
            history.append({"event": "repair_given_up", "explanation": explanation, "at": time.time()})
            self.store.update("invariants", "phi_num", self.phi,
                              {"status": "withdrawn", "history": history, "updated_at": time.time()})
            return "invariant withdrawn"
        new_line = int(line) if line else row["line"]
        new_expression = (expression or row["expression"]).strip().rstrip(";")
        if (new_line, new_expression) == (row["line"], row["expression"]):
            raise ToolError("the line and expression are unchanged; change one of them or give up")
        self._check_invariant(row["file"], new_line, new_expression)
        history.append({"event": "repaired", "from": [row["line"], row["expression"]],
                        "to": [new_line, new_expression], "explanation": explanation, "at": time.time()})
        self.store.update("invariants", "phi_num", self.phi,
                          {"line": new_line, "expression": new_expression, "status": "pending_build",
                           "repairs": (row.get("repairs") or 0) + 1, "last_error": None,
                           "history": history, "updated_at": time.time()})
        return f"invariant phi {self.phi} now compiles at {row['file']}:{new_line}"

    def refine_invariant(self, rationale: str, expression: str | None = None, line: int | None = None,
                         file: str | None = None, give_up: bool = False) -> str:
        from .instrument import split_comparison

        if self.phi is None:
            raise ToolError("no invariant bound to this agent")
        row = self.store.row("SELECT * FROM invariants WHERE phi_num=?", self.phi)
        history = list(row.get("history") or [])
        if give_up:
            history.append({"event": "refine_given_up", "rationale": rationale, "at": time.time()})
            self.store.update("invariants", "phi_num", self.phi,
                              {"status": "withdrawn", "history": history, "updated_at": time.time()})
            return "invariant withdrawn; no falsifiable security property remains"
        new_file = file or row["file"]
        new_line = int(line) if line else row["line"]
        new_expression = (expression or "").strip().rstrip(";")
        if not new_expression:
            raise ToolError("give the refined expression, or give_up=true")
        if (new_file, new_line, new_expression) == (row["file"], row["line"], row["expression"]):
            raise ToolError("the refined invariant is identical to the falsified one")
        if re.fullmatch(r"(1|true|!0)", new_expression):
            raise ToolError("that expression is always true and tests nothing")
        operands = split_comparison(new_expression)
        if operands and operands[0] == operands[2]:
            raise ToolError("both sides of the comparison are the same expression; it tests nothing")
        # The compiler rejects a comparison the operand types already decide (the usual way a
        # refinement gets widened into a check that can never fail).
        self._check_invariant(new_file, new_line, new_expression)
        history.append({"event": "refined", "from": [row["file"], row["line"], row["expression"]],
                        "to": [new_file, new_line, new_expression], "rationale": rationale,
                        "violation": self.violation_id, "at": time.time()})
        self.store.update("invariants", "phi_num", self.phi,
                          {"file": new_file, "line": new_line, "expression": new_expression,
                           "status": "pending_build", "refinements": (row.get("refinements") or 0) + 1,
                           "history": history, "updated_at": time.time()})
        return f"invariant phi {self.phi} refined; it will be rebuilt and fuzzed again"

    # ----------------------------------------------------------------------------- triage
    def triage_verdict(self, verdict: str, explanation: str, downstream_function: str = "",
                       vuln_type: str = "", description: str = "", pov_guidance: str = "") -> str:
        if not self.violation_id:
            raise ToolError("no invariant violation is bound to this agent")
        verdict = (verdict or "").strip().upper()
        if verdict not in ("REAL_ISSUE", "TOO_STRONG", "UNDECIDED"):
            raise ToolError("verdict must be REAL_ISSUE, TOO_STRONG or UNDECIDED")
        row = self.store.row("SELECT * FROM violations WHERE violation_id=?", self.violation_id)
        invariant = self.store.row("SELECT * FROM invariants WHERE phi_num=?", row["phi_num"])
        created = None
        if verdict == "REAL_ISSUE":
            function = downstream_function or invariant["file"]
            if downstream_function and downstream_function not in self.index["functions"]:
                raise ToolError(f"unknown function `{downstream_function}`")
            if not (description and vuln_type):
                raise ToolError("REAL_ISSUE needs vuln_type and description")
            if not downstream_function:
                raise ToolError("REAL_ISSUE needs downstream_function: where the insecure behaviour manifests")
            created = new_id("sp")
            now = time.time()
            # A violation is a lead, not a finding: it enters the ordinary FBv2 queue and must
            # still earn a reproducing crash. Verification is skipped (the invariant and the
            # triage already carry source evidence), PoV generation is not.
            self.store.insert("sps", {
                "sp_id": created, "worker_id": self.worker, "harness_id": self.harness_id,
                "function_name": downstream_function, "vuln_type": vuln_type,
                "description": description + f"\n\n[from invariant phi {row['phi_num']} "
                               f"({invariant['expression']} at {invariant['file']}:{invariant['line']}) "
                               f"falsified by a fuzzer input]\n{explanation}",
                "score": 0.6, "important_controlflow": [], "status": "pending_pov", "is_checked": 1,
                "is_important": 1, "verification_notes": explanation,
                "pov_guidance": pov_guidance or "Start from the recorded violating input and extend it so the "
                                "inconsistent state reaches the consumer.",
                "reachability_status": "direct", "reachability_reason": "an input already reached the invariant",
                "origin": "invariant_violation", "origin_ref": str(row["phi_num"]),
                "witness_path": row["input_path"], "created_at": now, "updated_at": now})
            self.store.update("invariants", "phi_num", row["phi_num"],
                              {"status": "lead", "updated_at": now})
        elif verdict == "TOO_STRONG":
            self.store.update("invariants", "phi_num", row["phi_num"],
                              {"status": "needs_refinement", "updated_at": time.time()})
        else:
            # Keep the invariant in place; it stays built and the fuzzer may hit it again.
            self.store.update("invariants", "phi_num", row["phi_num"],
                              {"status": "built", "updated_at": time.time()})
        self.store.update("violations", "violation_id", self.violation_id,
                          {"status": "triaged", "verdict": verdict, "notes": explanation,
                           "created_sp": created, "updated_at": time.time()})
        extra = f"; suspicious point {created} created for PoV generation" if created else ""
        return f"verdict {verdict} recorded{extra}"


def _schema(required: dict[str, str], optional: dict[str, str] | None = None) -> dict[str, Any]:
    """Minimal JSON Schema for an MCP tool's arguments."""
    properties = {name: {"type": kind} for name, kind in {**required, **(optional or {})}.items()}
    for spec in properties.values():
        if spec["type"] == "array":
            spec["items"] = {"type": "string"}
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False}