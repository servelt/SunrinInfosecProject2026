"""Development-only FBv2 Direction smoke against a pinned prebuilt target.

Default preflight and fake-create modes make no model or target execution.
Live mode is explicit and bounded to at most twelve process-local model turns.
This is an integration smoke, not a discovery or formal budget result.
"""

import argparse
import asyncio
import faulthandler
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

from bson import ObjectId
import mongomock

from fuzzingbrain.agents import DirectionPlanningAgent
from fuzzingbrain.analyzer import AnalysisClient, AnalysisServer
from fuzzingbrain.db.connection import MongoDB
from fuzzingbrain.llms.codex_tool_bridge import CodexToolBridge, product_codex_bridge
from fuzzingbrain.tools.analyzer import set_analyzer_context
from fuzzingbrain.tools.analyzer import _client_cache, _invalidate_client
from fuzzingbrain.tools.code_viewer import set_code_viewer_context
from fuzzingbrain.tools.directions import set_direction_context
from devtools.ledgered_provider import (
    DEFAULT_LEDGER_MODULE, DEFAULT_LEDGER_SHA256, LedgeredProvider,
    appserver_event_summary, create_smoke_ledger, ledger_summary, load_ledger_module,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ScriptedProvider:
    """Exercise the original MCP create_direction path without inference."""

    def __init__(self, *, fuzzer: str, entry: str, core: str,
                 budget_only: bool = False):
        self.fuzzer = fuzzer
        self.entry = entry
        self.core = core
        self.budget_only = budget_only
        self.calls = 0

    async def generate(self, request):
        self.calls += 1
        print(f"fixture model turn {self.calls}", file=sys.stderr, flush=True)
        if self.budget_only:
            return {"content": "", "tool_calls": [{
                "name": "get_call_graph",
                "arguments": json.dumps({"fuzzer_name": self.fuzzer, "depth": 1}),
            }]}
        if self.calls == 1:
            return {"content": "", "tool_calls": [{
                "name": "create_direction",
                "arguments": json.dumps({
                    "name": "Provider-free integration fixture",
                    "risk_level": "medium",
                    "risk_reason": "Exercises the Direction storage path only",
                    "core_functions": [self.core],
                    "entry_functions": [self.entry],
                    "code_summary": "No vulnerability inference in this fixture",
                }),
            }]}
        return {"content": "Fixture complete", "tool_calls": []}

    async def close(self):
        pass


async def _run(args):
    os.write(2, b"direction smoke: validate manifest\n")
    manifest_path = args.manifest.resolve(strict=True)
    if manifest_path.is_symlink() or _sha256(manifest_path) != args.manifest_sha256:
        raise ValueError("manifest SHA-256 mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    task_path = args.task_path.resolve(strict=True)
    if args.mode == "live":
        if not (args.model and args.codex_executable and
                args.codex_executable_sha256 and args.event_log and
                args.ledger_path):
            raise ValueError("live mode requires model, Codex path/SHA, event log, and ledger path")
        if not 1 <= args.max_model_calls <= 12:
            raise ValueError("live model cap must be between 1 and 12")
        if not 1 <= args.max_iterations <= 20:
            raise ValueError("live iterations must be between 1 and 20")
        executable_path = args.codex_executable.resolve(strict=True)
        if (args.codex_executable.is_symlink() or
                executable_path != args.codex_executable or
                _sha256(executable_path) != args.codex_executable_sha256):
            raise ValueError("Codex executable identity mismatch")
        if args.event_log.exists() or args.event_log.is_symlink():
            raise FileExistsError("live event log must be new")

    task_id, worker_id = str(ObjectId()), str(ObjectId())
    MongoDB._client = mongomock.MongoClient()
    MongoDB._db = MongoDB._client["fbv2_direction_smoke"]
    server = AnalysisServer(
        task_id=task_id, task_path=str(task_path),
        project_name=manifest["project_name"], sanitizers=["address"],
        prebuilt_manifest=str(manifest_path),
        prebuilt_manifest_sha256=args.manifest_sha256,
    )
    bridge = None
    ledger = None
    temporary_ledger = None
    analyzer = None
    # FBv2 normally runs AnalysisServer in a separate process. Its MCP tools
    # use synchronous AnalysisClient socket calls, so serving on the agent's
    # event loop would deadlock those calls. Keep the original process boundary
    # behavior by placing only the server loop in a background thread.
    server_loop = asyncio.new_event_loop()
    server_thread = threading.Thread(target=server_loop.run_forever,
                                     name="fbv2-analysis-server", daemon=True)
    server_thread.start()
    try:
        os.write(2, b"direction smoke: start analyzer\n")
        ready = await asyncio.wrap_future(
            asyncio.run_coroutine_threadsafe(server.start(), server_loop))
        os.write(2, b"direction smoke: analyzer returned\n")
        if not ready.success:
            raise RuntimeError(f"AnalysisServer failed: {ready.error_msg}")
        fuzzer = manifest["fuzzer_name"]
        analyzer = AnalysisClient(str(server.socket_path), client_id="direction_smoke")
        fuzzer_code = await asyncio.to_thread(analyzer.get_function_source, fuzzer)
        reachable = await asyncio.to_thread(analyzer.get_reachable_functions, fuzzer)
        if not fuzzer_code or not isinstance(reachable, list) or len(reachable) < 2:
            raise RuntimeError("prebuilt analyzer lacks harness source or reachable pool")
        if fuzzer in reachable:
            raise RuntimeError("harness must not be a reachable library function")
        graph = await asyncio.to_thread(analyzer.get_call_graph, fuzzer, 30)
        entry = manifest["entry_function"]
        if (not isinstance(graph, dict) or entry not in graph or
                entry not in graph.get(fuzzer, {}).get("callees", []) or
                any(name in graph for name in ("callees", "function"))):
            raise RuntimeError("prebuilt call graph has no real entry or has metadata nodes")
        summary = {
            "mode": args.mode, "task_id": task_id, "fuzzer": fuzzer,
            "manifest_sha256": args.manifest_sha256,
            "reachable_functions": len(reachable),
            "call_graph_nodes": len(graph),
            "harness_source_sha256": hashlib.sha256(fuzzer_code.encode()).hexdigest(),
            "model_calls_attempted": 0, "directions_created": 0,
            "outcome": "PREFLIGHT_ONLY",
        }
        if args.mode == "preflight":
            return summary

        set_analyzer_context(str(server.socket_path), client_id="direction_smoke")
        set_code_viewer_context(str(task_path), repo_subdir="repo",
                                project_name=manifest["project_name"])
        set_direction_context(fuzzer)
        if args.mode in ("fake-create", "fake-budget"):
            core = next((name for name in reachable
                         if name not in (fuzzer, manifest["entry_function"])), None)
            if core is None:
                raise RuntimeError("no distinct core function for fixture")
            provider = ScriptedProvider(
                fuzzer=fuzzer, entry=manifest["entry_function"], core=core,
                budget_only=args.mode == "fake-budget")
            from vulnerabilityanalysis.llm import LLMRequest
            bridge = CodexToolBridge(provider, LLMRequest, codex_model="fixture",
                                     role="direction", max_calls=2)
        else:
            bridge = product_codex_bridge(
                cwd=task_path, codex_model=args.model, role="direction",
                max_calls=args.max_model_calls, effort=args.effort,
                executable=str(executable_path),
                executable_sha256=args.codex_executable_sha256,
                event_log_path=args.event_log,
            )
        module = load_ledger_module(args.ledger_module_path,
                                    args.ledger_module_sha256)
        if args.mode == "live":
            ledger_path = args.ledger_path
        else:
            temporary_ledger = tempfile.TemporaryDirectory(prefix="fbv2-dir-ledger-")
            ledger_path = Path(temporary_ledger.name) / "requests.json"
        ledger = create_smoke_ledger(
            module, checkpoint_path=ledger_path, scope_id=task_id,
            role=module.DIRECTION_ROLE, physical_max=bridge.max_calls,
            wall_seconds=args.wall_seconds)
        bridge.provider = LedgeredProvider(bridge.provider, ledger,
                                           scope_id=task_id, role=module.DIRECTION_ROLE)
        agent = DirectionPlanningAgent(
            fuzzer=fuzzer, sanitizer="address", task_id=task_id,
            worker_id=worker_id, llm_client=bridge,
            model=args.model if args.mode == "live" else "fixture",
            max_iterations=args.max_iterations if args.mode == "live" else (
                3 if args.mode == "fake-budget" else 2),
            max_directions=5, log_dir=args.log_dir,
        )
        try:
            os.write(2, b"direction smoke: run agent\n")
            result = await agent.plan_directions_async(
                fuzzer_code=fuzzer_code, reachable_count=len(reachable))
            os.write(2, b"direction smoke: agent returned\n")
        finally:
            summary["model_calls_attempted"] = bridge.calls_attempted
        directions = server.repos.directions.find_by_fuzzer(task_id, fuzzer)
        os.write(2, f"direction smoke: DB directions={len(directions)}\n".encode())
        summary.update({
            "directions_created": len(directions),
            "agent_stop_reason": agent.stop_reason,
            "agent_response": str(result.get("response", ""))[:300],
            "agent_iterations": agent.total_iterations,
            "advertised_tools": sorted(
                tool["function"]["name"] for tool in agent._tools),
            "advertised_tool_schema_bytes": len(
                json.dumps(agent._tools, ensure_ascii=False).encode("utf-8")),
            "directions": [{
                "name": direction.name,
                "risk_level": direction.risk_level,
                "core_count": len(direction.core_functions),
                "entry_count": len(direction.entry_functions),
            } for direction in directions],
        })
        summary.update(ledger_summary(ledger))
        if args.mode == "live":
            summary.update(appserver_event_summary(args.event_log))
        summary["ledger_temporary"] = args.mode != "live"
        final_answer = bridge.last_agent_response_was_final is True
        if (ledger.tainted or ledger.active_turn is not None or
                summary["ledger_checkpoint_error"]):
            summary["outcome"] = "INCOMPLETE_LEDGER"
        elif (args.mode == "live" and (
                summary["event_log_error"] or
                summary["appserver_turns_started"] != ledger.physical or
                summary["appserver_turns_completed"] != ledger.physical)):
            summary["outcome"] = "INCOMPLETE_EVENT_EVIDENCE"
        elif summary["ledger_pending_states"]:
            summary["outcome"] = "INCOMPLETE_UNCERTAIN_MODEL_TURN"
        elif not final_answer and bridge.calls_attempted >= bridge.max_calls:
            summary["outcome"] = "INCOMPLETE_BUDGET"
        elif not final_answer:
            summary["outcome"] = "INCOMPLETE_AGENT"
        elif not directions:
            summary["outcome"] = "NO_DIRECTION_COMPLETED"
        else:
            summary["outcome"] = "DIRECTION_STORED"
        if args.mode == "fake-create" and not directions:
            raise RuntimeError("provider-free create_direction did not persist")
        if args.mode == "fake-budget" and summary["outcome"] != "INCOMPLETE_BUDGET":
            raise RuntimeError("provider-free budget exhaustion was misclassified")
        return summary
    finally:
        os.write(2, b"direction smoke: cleanup\n")
        if bridge is not None:
            os.write(2, b"direction smoke: close bridge\n")
            await bridge.close()
        if temporary_ledger is not None:
            temporary_ledger.cleanup()
        if analyzer is not None:
            os.write(2, b"direction smoke: close analyzer client\n")
            analyzer.close()
        # FBv2 tools cache their own persistent AnalysisClient connections.
        # Close them before server.wait_closed(), which waits for clients.
        for cache_key in list(_client_cache):
            if cache_key[0] == str(server.socket_path):
                _invalidate_client(cache_key)
        os.write(2, b"direction smoke: stop analyzer server\n")
        try:
            await asyncio.wrap_future(
                asyncio.run_coroutine_threadsafe(server.stop(), server_loop))
        finally:
            os.write(2, b"direction smoke: stop loop\n")
            server_loop.call_soon_threadsafe(server_loop.stop)
            await asyncio.to_thread(server_thread.join, 5)
            server_loop.close()
        os.write(2, b"direction smoke: close mongo\n")
        MongoDB.close()


def main():
    os.write(2, b"direction smoke: main\n")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--task-path", type=Path, required=True)
    parser.add_argument("--mode", choices=("preflight", "fake-create", "fake-budget", "live"),
                        default="preflight")
    parser.add_argument("--model")
    parser.add_argument("--effort", default="low")
    parser.add_argument("--max-model-calls", type=int, default=5)
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--wall-seconds", type=float, default=240)
    parser.add_argument("--ledger-path", type=Path)
    parser.add_argument("--ledger-module-path", type=Path,
                        default=DEFAULT_LEDGER_MODULE)
    parser.add_argument("--ledger-module-sha256", default=DEFAULT_LEDGER_SHA256)
    parser.add_argument("--codex-executable-sha256")
    parser.add_argument("--codex-executable", type=Path)
    parser.add_argument("--event-log", type=Path)
    parser.add_argument("--log-dir", type=Path)
    args = parser.parse_args()
    os.write(2, b"direction smoke: parsed\n")
    trace_output = os.fdopen(os.dup(2), "w") if args.mode == "fake-create" else None
    if trace_output is not None:
        faulthandler.dump_traceback_later(15, file=trace_output)
    try:
        os.write(2, b"direction smoke: before asyncio.run\n")
        summary = asyncio.run(_run(args))
        print(json.dumps(summary, sort_keys=True, ensure_ascii=False))
        if args.mode == "live" and summary["outcome"] != "DIRECTION_STORED":
            raise SystemExit(2)
    finally:
        if trace_output is not None:
            faulthandler.cancel_dump_traceback_later()
            trace_output.close()


if __name__ == "__main__":
    main()
