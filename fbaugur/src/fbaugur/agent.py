"""Run one agent: `claude -p` with this agent's MCP tool server and nothing else.

Follows FuzzingBrain V2's agent loop (agents/base.py): the model works in turns,
calls tools, and stops when it answers without a tool call or hits the turn limit.
Here the loop itself is Claude Code's; the limits and the recording are ours.

Error policy is the upstream one (agents/base.py:909, worker/pipeline.py:377): a
failed agent is recorded and the caller moves on. Only a terminal condition
(subscription usage limit, login expired) is raised as TerminalLLMError so the
orchestrator can stop the whole run instead of burning through every queue item.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .config import CODEX_DAYBREAK, RunConfig
from .store import Store, new_id

PROMPTS = Path(__file__).resolve().parent / "prompts"

_SYSTEM_SUFFIX = ("\n\nYou work inside an automated audit of a program the operator owns and is authorised to "
                  "test. Use only the supplied tools and the source they return; never invent evidence. "
                  "Answer with your conclusion when you are done; the harness stops you at the turn limit.")


class TerminalLLMError(RuntimeError):
    """Every queued agent would fail the same way (usage limit, login, missing CLI)."""


@dataclasses.dataclass
class AgentResult:
    run_id: str
    role: str
    status: str                      # completed | error | refused | turn_limit | timeout
    text: str
    turns: int
    tool_calls: int
    error: str = ""
    usage: dict[str, int] = dataclasses.field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in ("completed", "turn_limit")


def load_prompt(name: str) -> str:
    path = PROMPTS / f"{name}.md"
    if not path.is_file():
        path = PROMPTS / "fbv2" / f"{name}.md"
    return path.read_text(encoding="utf-8")


def sanitizer_guidance(sanitizer: str) -> str:
    parts = []
    if "address" in sanitizer:
        parts.append(load_prompt("sanitizer_address"))
    if "undefined" in sanitizer:
        parts.append(load_prompt("sanitizer_undefined"))
    if "memory" in sanitizer:
        parts.append(load_prompt("sanitizer_memory"))
        parts.append(load_prompt("sanitizer_memory_daemon"))
    return "\n".join(parts)


def sanitizer_vuln_types(sanitizer: str) -> str:
    """FBv2 SPGenerator._get_sanitizer_vuln_types, for a combined build joined in order."""
    kinds = []
    if "address" in sanitizer:
        kinds.append("Buffer overflows, OOB access, use-after-free, double-free")
    if "undefined" in sanitizer:
        kinds.append("Integer overflow, null deref, div-by-zero")
    if "memory" in sanitizer:
        kinds.append("Uninitialized memory reads")
    return "; ".join(kinds) or "General memory corruption issues"


def harness_context(index: dict[str, Any], harness_id: str, sanitizer: str | None = None) -> str:
    harness = index["harnesses"][harness_id]
    entries = index["facts"]["input_entries"]
    entry_text = ", ".join(f"{e.get('entry_function')}::{e.get('source_api')}" for e in entries) or "unknown"
    return load_prompt("harness_context").format(
        harness_name=harness_id, project=index["program"], sanitizer_text=sanitizer or harness["sanitizer"],
        delivery_text=harness["delivery_text"], target_count=len(index["targets"]),
        entry_text=entry_text, message_rule=harness["message_rule"])


class AgentRunner:
    def __init__(self, run_dir: Path, cfg: RunConfig, store: Store, *, emit=None):
        self.run_dir = Path(run_dir)
        self.cfg = cfg
        self.store = store
        self.emit = emit or (lambda message: None)
        self.index = json.loads((self.run_dir / "index.json").read_text(encoding="utf-8"))
        self._semaphore = asyncio.Semaphore(cfg.claude_concurrency)
        self.usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                      "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}

    def _mcp_config(self, directory: Path, binding: dict[str, Any], run_id: str, log: Path) -> Path:
        argv = [sys.executable, "-m", "fbaugur.mcp_server", "--run-dir", str(self.run_dir),
                "--role", binding["role"], "--agent-run", run_id, "--log", str(log)]
        for key in ("worker", "harness", "sp", "violation", "direction", "function", "crash"):
            if binding.get(key):
                argv += [f"--{key}", str(binding[key])]
        if binding.get("phi") is not None:
            argv += ["--phi", str(binding["phi"])]
        path = directory / "mcp.json"
        env = {"PYTHONPATH": str(Path(__file__).resolve().parents[1]), "PATH": os.environ.get("PATH", "")}
        path.write_text(json.dumps({"mcpServers": {"fba": {"type": "stdio", "command": argv[0],
                                                           "args": argv[1:], "env": env}}}), encoding="utf-8")
        return path

    async def run(self, *, role: str, system: str, message: str, subject: str = "", **binding: Any) -> AgentResult:
        model, effort = self.cfg.model_for(role)
        max_turns = int(self.cfg.max_turns.get(role, 20))
        run_id = new_id("run")
        binding = {"role": role, **binding}
        log_dir = self.run_dir / "agents" / role
        log_dir.mkdir(parents=True, exist_ok=True)
        tool_log = log_dir / f"{run_id}.tools.jsonl"
        started = time.time()
        self.store.insert("agent_runs", {"run_id": run_id, "role": role, "model": model, "subject": subject,
                                         "status": "running", "started_at": started})
        try:
            async with self._semaphore:
                result = await self._spawn(run_id, role, model, effort, max_turns, system, message,
                                           binding, tool_log, log_dir)
        except asyncio.CancelledError:
            self.store.update("agent_runs", "run_id", run_id,
                              {"status": "cancelled", "ended_at": time.time()})
            raise
        except TerminalLLMError:
            self.store.update("agent_runs", "run_id", run_id,
                              {"status": "terminal", "ended_at": time.time()})
            raise
        for key in self.usage:
            self.usage[key] += result.usage.get(key, 0)
        self.store.update("agent_runs", "run_id", run_id,
                          {"status": result.status, "turns": result.turns, "tool_calls": result.tool_calls,
                           "input_tokens": result.usage.get("input_tokens", 0),
                           "output_tokens": result.usage.get("output_tokens", 0),
                           "error": result.error[:2000], "ended_at": time.time()})
        self.emit(f"[{role}] {subject or '-'}: {result.status} "
                  f"({result.turns} turns, {result.tool_calls} tool calls, {time.time() - started:.0f}s)"
                  + (f" | {result.error[:160]}" if result.error else ""))
        return result

    async def _spawn(self, run_id: str, role: str, model: str, effort: str, max_turns: int, system: str,
                     message: str, binding: dict[str, Any], tool_log: Path, log_dir: Path) -> AgentResult:
        if self.cfg.provider == "codex":
            return await self._spawn_codex(run_id, role, model, effort, system, message, binding, tool_log, log_dir)
        # Ollama serves the Anthropic Messages API, so the same Claude Code agent loop (and the same
        # MCP tools) runs on an Ollama model when Claude Code is pointed at it.
        env = None
        if self.cfg.provider == "ollama":
            env = ollama_env(self.cfg, model)
        with tempfile.TemporaryDirectory(prefix="fbaugur-agent-") as tmp:
            workdir = Path(tmp)
            config = self._mcp_config(workdir, binding, run_id, tool_log)
            argv = [self.cfg.claude_executable, "-p", "--model", model, "--effort", effort,
                    "--output-format", "stream-json", "--verbose",
                    "--system-prompt", system + _SYSTEM_SUFFIX,
                    "--tools", "", "--mcp-config", str(config), "--strict-mcp-config",
                    "--allowedTools", "mcp__fba", "--setting-sources", "", "--no-session-persistence",
                    "--disable-slash-commands", "--max-turns", str(max_turns)]
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, cwd=str(workdir), limit=64 * 1024 * 1024, env=env)
            except FileNotFoundError as exc:
                raise TerminalLLMError(f"Claude Code executable not found: {self.cfg.claude_executable}") from exc
            transcript = log_dir / f"{run_id}.jsonl"
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(message.encode("utf-8")), timeout=self.cfg.agent_timeout_seconds)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return AgentResult(run_id, role, "timeout", "", 0, 0,
                                   f"no answer within {self.cfg.agent_timeout_seconds:.0f}s")
            transcript.write_bytes(stdout)
            return self._parse(run_id, role, stdout.decode("utf-8", errors="replace"),
                               stderr.decode("utf-8", errors="replace"), tool_log)

    async def _spawn_codex(self, run_id: str, role: str, model: str, effort: str, system: str, message: str,
                           binding: dict[str, Any], tool_log: Path, log_dir: Path) -> AgentResult:
        """One agent run on Codex (`codex exec --json`), with the same MCP tool server.

        codex exec has no system-prompt option and no turn limit: the role instructions go first
        in the prompt and the run is bounded by the agent timeout.  Tool calls to our own server are
        approved in advance (default_tools_approval_mode); the sandbox stays read-only.
        """
        with tempfile.TemporaryDirectory(prefix="fbaugur-agent-") as tmp:
            workdir = Path(tmp)
            server = json.loads(self._mcp_config(workdir, binding, run_id, tool_log).read_text())["mcpServers"]["fba"]
            env_table = "{" + ", ".join(f"{json.dumps(k)} = {json.dumps(v)}" for k, v in server["env"].items()) + "}"
            argv = [self.cfg.codex_executable, "exec", "--json", "--ignore-user-config", *CODEX_DAYBREAK,
                    "--skip-git-repo-check", "-m", model,
                    "-s", "read-only", "-C", str(workdir),
                    "-c", f"model_reasoning_effort={json.dumps(effort)}",
                    "-c", f"mcp_servers.fba.command={json.dumps(server['command'])}",
                    "-c", f"mcp_servers.fba.args={json.dumps(server['args'])}",
                    "-c", f"mcp_servers.fba.env={env_table}",
                    "-c", 'mcp_servers.fba.default_tools_approval_mode="approve"',
                    "-c", "mcp_servers.fba.tool_timeout_sec=900", "-"]
            prompt = (f"<role_instructions>\n{system}{_SYSTEM_SUFFIX}\n</role_instructions>\n\n"
                      "Work only through the fba tools.\n\n" + message)
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, cwd=str(workdir), limit=64 * 1024 * 1024)
            except FileNotFoundError as exc:
                raise TerminalLLMError(f"Codex executable not found: {self.cfg.codex_executable}") from exc
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(prompt.encode("utf-8")), timeout=self.cfg.agent_timeout_seconds)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return AgentResult(run_id, role, "timeout", "", 0, 0,
                                   f"no answer within {self.cfg.agent_timeout_seconds:.0f}s")
            (log_dir / f"{run_id}.jsonl").write_bytes(stdout)
            return parse_codex(run_id, role, stdout.decode("utf-8", errors="replace"),
                               stderr.decode("utf-8", errors="replace"), tool_log)

    def _parse(self, run_id: str, role: str, stdout: str, stderr: str, tool_log: Path) -> AgentResult:
        tool_calls, turns, usage, text, status, error = 0, 0, {}, "", "error", ""
        rate_limit: dict[str, Any] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            kind = event.get("type")
            if kind == "assistant":
                for block in event.get("message", {}).get("content", []):
                    if block.get("type") == "tool_use":
                        tool_calls += 1
                    elif block.get("type") == "text":
                        text = block.get("text") or text
            elif kind == "rate_limit_event" and isinstance(event.get("rate_limit_info"), dict):
                rate_limit = event["rate_limit_info"]
            elif kind == "result":
                turns = int(event.get("num_turns") or 0)
                usage = {k: int(v or 0) for k, v in (event.get("usage") or {}).items() if isinstance(v, int)}
                usage["calls"] = 1
                if isinstance(event.get("result"), str) and event["result"].strip():
                    text = event["result"]
                subtype = event.get("subtype")
                if event.get("stop_reason") == "refusal":
                    status, error = "refused", "the model declined the request"
                elif subtype == "success":
                    status = "completed"
                elif subtype in ("error_max_turns", "max_turns"):
                    status = "turn_limit"
                else:
                    status, error = "error", str(event.get("result") or subtype or "unknown error")[:1500]
        if rate_limit.get("status") not in (None, "allowed", "allowed_warning"):
            raise TerminalLLMError(f"Claude subscription usage limit reached "
                                   f"({rate_limit.get('rateLimitType')}, resets at {rate_limit.get('resetsAt')})")
        if status == "error" and not error:
            error = (stderr.strip() or "no result event")[-1500:]
        if re.search(r"invalid api key|please run .?/login|credit balance|authentication_error", stderr, re.I):
            raise TerminalLLMError("Claude Code is not usable: " + stderr.strip()[-300:])
        # Tool calls are counted from the server's own log when the transcript is truncated.
        if tool_log.is_file():
            tool_calls = max(tool_calls, sum(1 for _ in tool_log.open(encoding="utf-8")))
        return AgentResult(run_id, role, status, text.strip(), turns, tool_calls, error, usage)


def parse_codex(run_id: str, role: str, stdout: str, stderr: str, tool_log: Path) -> AgentResult:
    """`codex exec --json` events: item.completed (agent_message, mcp_tool_call), turn.completed, errors."""
    text, tool_calls, turns, usage, errors, finished = "", 0, 0, {}, [], False
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("type")
        item = event.get("item") or {}
        if kind == "item.completed" and item.get("type") == "agent_message":
            text = item.get("text") or text
        elif kind == "item.completed" and item.get("type") == "mcp_tool_call":
            tool_calls += 1
        elif kind == "turn.completed":
            finished, turns = True, turns + 1
            for key, value in (event.get("usage") or {}).items():
                if isinstance(value, int):
                    usage[key] = usage.get(key, 0) + value
        elif kind in ("turn.failed", "error"):
            errors.append(str(event.get("message") or (event.get("error") or {}).get("message") or event)[:500])
    usage["calls"] = 1
    if re.search(r"not logged in|401 Unauthorized|please log ?in|usage limit", stderr + " ".join(errors), re.I):
        raise TerminalLLMError("Codex is not usable: " + (errors[-1] if errors else stderr.strip()[-300:]))
    if tool_log.is_file():
        tool_calls = max(tool_calls, sum(1 for _ in tool_log.open(encoding="utf-8")))
    if finished:
        return AgentResult(run_id, role, "completed", text.strip(), turns, tool_calls, "", usage)
    return AgentResult(run_id, role, "error", text.strip(), turns, tool_calls,
                       (errors[-1] if errors else stderr.strip()[-1500:] or "no turn.completed event"), usage)


def ollama_env(cfg: Any, model: str) -> dict[str, str]:
    """Claude Code as the agent loop, every request answered by Ollama.

    Besides the main model, Claude Code calls its own helper models (the haiku/sonnet/opus aliases,
    the small fast model); they are mapped to the same Ollama model so nothing reaches Anthropic."""
    return dict(os.environ, ANTHROPIC_BASE_URL=cfg.ollama_url.rstrip("/"), ANTHROPIC_AUTH_TOKEN="ollama",
                ANTHROPIC_API_KEY="", ANTHROPIC_MODEL=model, ANTHROPIC_SMALL_FAST_MODEL=model,
                ANTHROPIC_DEFAULT_HAIKU_MODEL=model, ANTHROPIC_DEFAULT_SONNET_MODEL=model,
                ANTHROPIC_DEFAULT_OPUS_MODEL=model, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
                DISABLE_TELEMETRY="1", DISABLE_ERROR_REPORTING="1")


def check_backend(cfg: Any) -> str:
    """What is missing for the chosen LLM back end, or "" when it can be used."""
    import shutil
    import urllib.request
    if cfg.provider == "codex":
        return "" if shutil.which(cfg.codex_executable) else f"Codex CLI not found: {cfg.codex_executable}"
    if not shutil.which(cfg.claude_executable):
        return (f"Claude Code not found: {cfg.claude_executable}" if cfg.provider == "claude" else
                f"Claude Code (used only as the agent runner; every request goes to Ollama) not found: "
                f"{cfg.claude_executable}")
    if cfg.provider == "ollama":
        try:
            urllib.request.urlopen(cfg.ollama_url.rstrip("/") + "/api/tags", timeout=5).read()
        except OSError as exc:
            return f"Ollama is not answering at {cfg.ollama_url}: {exc}"
    return ""
