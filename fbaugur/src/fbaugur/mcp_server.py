"""Expose one agent's Toolbox to `claude -p` over MCP (JSON-RPC 2.0 on stdin/stdout).

One server process per agent run: the orchestrator writes an --mcp-config pointing
at this module with the agent's binding (role, worker, harness, suspicious point,
invariant, ...) on the command line, so a tool call can only touch that agent's subject.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

from .tools import Toolbox, ToolError

PROTOCOL_VERSION = "2025-06-18"


def _text(value: object) -> dict:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    return {"content": [{"type": "text", "text": value}]}


def _error(value: str) -> dict:
    return {"content": [{"type": "text", "text": value}], "isError": True}


def serve(toolbox: Toolbox, stdin=None, stdout=None, log: Path | None = None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    tools = toolbox.tools()
    listing = [{"name": name, "description": description, "inputSchema": schema}
               for name, (description, schema, _) in sorted(tools.items())]

    def record(row: dict) -> None:
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        method, request_id = message.get("method"), message.get("id")
        if method == "initialize":
            result = {"protocolVersion": message.get("params", {}).get("protocolVersion", PROTOCOL_VERSION),
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": f"fbaugur-{toolbox.role}", "version": "0.1"}}
        elif method == "tools/list":
            result = {"tools": listing}
        elif method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name", "")
            arguments = params.get("arguments") or {}
            try:
                value = toolbox.call(name, arguments)
                result = _text(value)
                record({"tool": name, "arguments": arguments, "ok": True, "result": str(value)[:4000]})
            except ToolError as exc:
                result = _error(str(exc))
                record({"tool": name, "arguments": arguments, "ok": False, "error": str(exc)})
            except TypeError as exc:
                result = _error(f"wrong arguments for {name}: {exc}")
                record({"tool": name, "arguments": arguments, "ok": False, "error": str(exc)})
            except Exception as exc:                      # a broken tool must not kill the agent
                result = _error(f"{type(exc).__name__}: {exc}")
                record({"tool": name, "arguments": arguments, "ok": False,
                        "error": traceback.format_exc()[-3000:]})
        elif request_id is None:
            continue                                      # notification
        else:
            result = {}
        stdout.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result},
                                ensure_ascii=False) + "\n")
        stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="fbaugur MCP tool server (one agent per process)")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--role", required=True)
    parser.add_argument("--worker", default="")
    parser.add_argument("--harness", default="")
    parser.add_argument("--sp", default="")
    parser.add_argument("--phi", type=int, default=None)
    parser.add_argument("--violation", default="")
    parser.add_argument("--direction", default="")
    parser.add_argument("--function", default="")
    parser.add_argument("--function-id", default="")
    parser.add_argument("--crash", default="")
    parser.add_argument("--agent-run", default="")
    parser.add_argument("--log", type=Path)
    args = parser.parse_args(argv)
    toolbox = Toolbox(args.run_dir, role=args.role, worker=args.worker, harness=args.harness, sp=args.sp,
                      phi=args.phi, violation=args.violation, direction=args.direction,
                      function=args.function, function_id=args.function_id, crash=args.crash,
                      agent_run=args.agent_run)
    serve(toolbox, log=args.log)
    return 0


if __name__ == "__main__":
    sys.exit(main())
