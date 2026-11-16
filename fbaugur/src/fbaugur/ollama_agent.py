"""An agent loop that talks to Ollama only.

With the Ollama back end nothing else is used: no Claude Code (which, without a login of its own,
stops at "Not logged in" on some versions even when pointed at Ollama), no other vendor.  The loop
is the usual one: send the conversation and the tool list to Ollama's /api/chat, run the tool calls
the model asks for, append their results, repeat until the model answers without a tool call.

Tools come from an MCP server (the same fbaugur tool server Claude Code and Codex use, over stdio)
and/or from local Python functions (the preparation agent's shell and file tools).
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


class OllamaError(RuntimeError):
    pass


# ------------------------------------------------------------------------------------------ MCP
class McpClient:
    """Minimal MCP client over stdio (initialize, tools/list, tools/call)."""

    def __init__(self, command: str, args: list[str], env: dict[str, str] | None = None, cwd: str | None = None):
        self.process = subprocess.Popen([command, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, cwd=cwd,
                                        env=dict(os.environ, **(env or {})))
        self._id = 0
        self._lock = threading.Lock()
        self._request("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                     "clientInfo": {"name": "occulta", "version": "1"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._id += 1
            wanted = self._id
            self._send({"jsonrpc": "2.0", "id": wanted, "method": method, "params": params})
            assert self.process.stdout is not None
            while True:
                line = self.process.stdout.readline()
                if not line:
                    raise OllamaError(f"MCP server ended during {method}")
                try:
                    message = json.loads(line)
                except ValueError:
                    continue
                if message.get("id") == wanted:
                    if "error" in message:
                        raise OllamaError(f"MCP {method}: {message['error']}")
                    return message.get("result") or {}

    def tools(self) -> list[dict[str, Any]]:
        return self._request("tools/list", {}).get("tools", [])

    def call(self, name: str, arguments: dict[str, Any]) -> str:
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        text = "\n".join(str(part.get("text", "")) for part in result.get("content", []) if isinstance(part, dict))
        return ("ERROR: " if result.get("isError") else "") + text

    def close(self) -> None:
        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except Exception:
            self.process.kill()


# ------------------------------------------------------------------------------------------ loop
@dataclass
class LoopResult:
    text: str = ""
    turns: int = 0
    tool_calls: int = 0
    usage: dict[str, int] = field(default_factory=dict)
    status: str = "completed"        # completed | turn_limit | timeout | error
    error: str = ""


def chat(url: str, model: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
         timeout: float = 600.0) -> dict[str, Any]:
    body: dict[str, Any] = {"model": model, "messages": messages, "stream": False}
    if tools:
        body["tools"] = tools
    request = urllib.request.Request(url.rstrip("/") + "/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise OllamaError(f"Ollama {exc.code}: {exc.read().decode(errors='replace')[:400]}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise OllamaError(f"Ollama is not answering at {url}: {exc}") from exc


def _as_ollama_tool(tool: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": {
        "name": tool["name"], "description": tool.get("description", ""),
        "parameters": tool.get("inputSchema") or tool.get("parameters") or {"type": "object", "properties": {}}}}


def run_loop(*, url: str, model: str, system: str, message: str, mcp: McpClient | None = None,
             local_tools: dict[str, tuple[dict[str, Any], Callable[..., str]]] | None = None,
             max_turns: int = 40, deadline_seconds: float = 1800.0,
             on_event: Callable[[str, Any], None] = lambda kind, data: None,
             history: list[dict[str, Any]] | None = None) -> tuple[LoopResult, list[dict[str, Any]]]:
    """Run until the model stops calling tools.  Returns the result and the conversation (to continue it)."""
    local_tools = local_tools or {}
    remote = mcp.tools() if mcp else []
    tools = [_as_ollama_tool(t) for t in remote] + [_as_ollama_tool(spec) for spec, _ in local_tools.values()]
    remote_names = {t["name"] for t in remote}
    messages = list(history) if history else [{"role": "system", "content": system}]
    messages.append({"role": "user", "content": message})
    result, started = LoopResult(), time.time()
    while True:
        if result.turns >= max_turns:
            result.status = "turn_limit"
            break
        if time.time() - started > deadline_seconds:
            result.status, result.error = "timeout", f"no answer within {deadline_seconds:.0f}s"
            break
        try:
            reply = chat(url, model, messages, tools, timeout=max(60.0, deadline_seconds - (time.time() - started)))
        except OllamaError as exc:
            result.status, result.error = "error", str(exc)
            break
        result.turns += 1
        for key in ("prompt_eval_count", "eval_count"):
            result.usage[key] = result.usage.get(key, 0) + int(reply.get(key) or 0)
        answer = reply.get("message") or {}
        calls = answer.get("tool_calls") or []
        messages.append({k: v for k, v in answer.items() if k in ("role", "content", "tool_calls")})
        if answer.get("content"):
            result.text = answer["content"]
        if not calls:
            break
        for call in calls:
            function = call.get("function") or {}
            name, arguments = function.get("name", ""), function.get("arguments") or {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except ValueError:
                    arguments = {}
            result.tool_calls += 1
            on_event("tool", {"name": name, "arguments": arguments})
            try:
                if name in remote_names and mcp is not None:
                    output = mcp.call(name, arguments)
                elif name in local_tools:
                    output = local_tools[name][1](**arguments)
                else:
                    output = f"ERROR: unknown tool {name}"
            except Exception as exc:          # a failing tool is reported to the model, not raised
                output = f"ERROR: {type(exc).__name__}: {exc}"
            messages.append({"role": "tool", "content": str(output)[:60000], "tool_name": name})
    result.usage["calls"] = 1
    return result, messages


# ------------------------------------------------------------------------------------------ local tools
def workspace_tools(root: Path, on_command: Callable[[str], None] = lambda c: None
                    ) -> dict[str, tuple[dict[str, Any], Callable[..., str]]]:
    """Shell and file tools for the preparation agent, working in `root`."""
    root = Path(root)

    def bash(command: str, timeout: int = 1200) -> str:
        on_command(command)
        try:
            done = subprocess.run(["bash", "-lc", command], cwd=str(root), capture_output=True, text=True,
                                  timeout=min(int(timeout), 3600))
        except subprocess.TimeoutExpired:
            return f"timed out after {timeout}s"
        out = (done.stdout + done.stderr)
        return f"exit {done.returncode}\n" + (out[-12000:] if len(out) > 12000 else out)

    def read_file(path: str) -> str:
        target = (root / path) if not Path(path).is_absolute() else Path(path)
        return target.read_text(encoding="utf-8", errors="replace")[:40000]

    def write_file(path: str, content: str) -> str:
        target = (root / path) if not Path(path).is_absolute() else Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"wrote {len(content)} bytes to {target}"

    string = {"type": "string"}
    return {
        "bash": ({"name": "bash", "description": "Run a bash command in the working directory; returns exit code and output.",
                  "parameters": {"type": "object", "properties": {"command": string, "timeout": {"type": "integer"}},
                                 "required": ["command"]}}, bash),
        "read_file": ({"name": "read_file", "description": "Read a text file (path relative to the working directory or absolute).",
                       "parameters": {"type": "object", "properties": {"path": string}, "required": ["path"]}}, read_file),
        "write_file": ({"name": "write_file", "description": "Write a text file, creating directories.",
                        "parameters": {"type": "object", "properties": {"path": string, "content": string},
                                       "required": ["path", "content"]}}, write_file),
    }
