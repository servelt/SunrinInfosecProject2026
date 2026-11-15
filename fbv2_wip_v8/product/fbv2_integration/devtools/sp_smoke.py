"""Bounded original FBv2 SP Generator smoke on a pinned prebuilt function.

The default target is the manifest's library entry. An explicit function name
is a manually selected control and is never an automatic discovery result.
Default preflight and fake-create modes use no model or target execution.
Live mode is explicit, capped, and is not a discovery or blind result.
"""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading

from bson import ObjectId
import mongomock

from fuzzingbrain.agents.sp_generators import FullSPGenerator
from fuzzingbrain.analyzer import AnalysisClient, AnalysisServer
from fuzzingbrain.db.connection import MongoDB
from fuzzingbrain.llms.codex_tool_bridge import CodexToolBridge, product_codex_bridge
from fuzzingbrain.tools.analyzer import set_analyzer_context, _client_cache, _invalidate_client
from fuzzingbrain.tools.suspicious_points import set_sp_context
from devtools.ledgered_provider import (
    DEFAULT_LEDGER_MODULE, DEFAULT_LEDGER_SHA256, LedgeredProvider,
    appserver_event_summary, create_smoke_ledger, ledger_summary, load_ledger_module,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ScriptedProvider:
    """Exercise candidate storage only; this is not vulnerability evidence."""

    def __init__(self, function_name: str, *, budget_only: bool = False):
        self.function_name = function_name
        self.budget_only = budget_only
        self.calls = 0

    async def generate(self, request):
        self.calls += 1
        if self.budget_only:
            return {"content": "", "tool_calls": [{
                "name": "get_callees",
                "arguments": json.dumps({"function_name": self.function_name}),
            }]}
        if self.calls == 1:
            return {"content": "", "tool_calls": [{
                "name": "create_suspicious_point",
                "arguments": json.dumps({
                    "function_name": self.function_name,
                    "vuln_type": "out-of-bounds-read",
                    "description": "Provider-free storage fixture; no vulnerability inference",
                    "score": 0.1,
                    "important_controlflow": [],
                }),
            }]}
        return {"content": "Fixture complete", "tool_calls": []}

    async def close(self):
        pass


async def run(args):
    manifest_path = args.manifest.resolve(strict=True)
    if args.manifest.is_symlink() or sha256(manifest_path) != args.manifest_sha256:
        raise ValueError("manifest SHA-256 mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    task_path = args.task_path.resolve(strict=True)
    executable_path = None
    if args.mode == "live":
        if not (args.model and args.codex_executable and
                args.codex_executable_sha256 and args.event_log and
                args.ledger_path):
            raise ValueError("live mode requires model, Codex path/SHA, event log, and ledger path")
        if not 1 <= args.max_model_calls <= 3:
            raise ValueError("live SP model cap must be between 1 and 3")
        if not 1 <= args.max_iterations <= 6:
            raise ValueError("live SP iterations must be between 1 and 6")
        executable_path = args.codex_executable.resolve(strict=True)
        if (args.codex_executable.is_symlink() or
                executable_path != args.codex_executable or
                sha256(executable_path) != args.codex_executable_sha256):
            raise ValueError("Codex executable identity mismatch")
        if args.event_log.exists() or args.event_log.is_symlink():
            raise FileExistsError("live event log must be new")

    task_id, worker_id = str(ObjectId()), str(ObjectId())
    MongoDB._client = mongomock.MongoClient()
    MongoDB._db = MongoDB._client["fbv2_sp_smoke"]
    server = AnalysisServer(
        task_id=task_id, task_path=str(task_path),
        project_name=manifest["project_name"], sanitizers=["address"],
        prebuilt_manifest=str(manifest_path),
        prebuilt_manifest_sha256=args.manifest_sha256,
    )
    server_loop = asyncio.new_event_loop()
    server_thread = threading.Thread(target=server_loop.run_forever,
                                     name="fbv2-sp-analyzer", daemon=True)
    server_thread.start()
    bridge = None
    ledger = None
    temporary_ledger = None
    analyzer = None
    try:
        ready = await asyncio.wrap_future(
            asyncio.run_coroutine_threadsafe(server.start(), server_loop))
        if not ready.success:
            raise RuntimeError(f"AnalysisServer failed: {ready.error_msg}")
        fuzzer = manifest["fuzzer_name"]
        # An explicit function is a labeled control, not repository-level
        # automatic selection. It must resolve from the pinned imported pool.
        selected_name = args.function_name or manifest["entry_function"]
        function = server.repos.functions.find_by_name(task_id, selected_name)
        if not function or not function.content:
            raise RuntimeError("selected function missing from pinned imported pool")
        analyzer = AnalysisClient(str(server.socket_path), client_id="sp_smoke")
        fuzzer_source = await asyncio.to_thread(analyzer.get_function_source, fuzzer)
        if not fuzzer_source:
            raise RuntimeError("pinned harness source unavailable")
        callers = server.repos.callgraph_nodes.find_callers(task_id, fuzzer, function.name) or []
        callees = server.repos.callgraph_nodes.find_callees(task_id, fuzzer, function.name) or []
        summary = {
            "mode": args.mode, "task_id": task_id, "fuzzer": fuzzer,
            "function": function.name,
            "selection_basis": ("MANUAL_FUNCTION_CONTROL" if args.function_name
                                else "MANIFEST_LIBRARY_ENTRY"),
            "function_source_sha256": hashlib.sha256(function.content.encode()).hexdigest(),
            "function_lines": [function.start_line, function.end_line],
            "callers": len(callers), "callees": len(callees),
            "model_calls_attempted": 0, "candidates_stored": 0,
            "target_executions": 0, "outcome": "PREFLIGHT_ONLY",
        }
        if args.mode == "preflight":
            return summary

        set_analyzer_context(str(server.socket_path), client_id="sp_smoke")
        set_sp_context(fuzzer, "address")
        if args.mode in ("fake-create", "fake-budget"):
            from vulnerabilityanalysis.llm import LLMRequest
            provider = ScriptedProvider(function.name,
                                        budget_only=args.mode == "fake-budget")
            bridge = CodexToolBridge(provider, LLMRequest, codex_model="fixture",
                                     role="sp", max_calls=2)
        else:
            bridge = product_codex_bridge(
                cwd=task_path, codex_model=args.model, role="sp",
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
            temporary_ledger = tempfile.TemporaryDirectory(prefix="fbv2-sp-ledger-")
            ledger_path = Path(temporary_ledger.name) / "requests.json"
        scope_id = task_id + ":" + function.name
        ledger = create_smoke_ledger(
            module, checkpoint_path=ledger_path, scope_id=scope_id,
            role="sp_generation", physical_max=bridge.max_calls,
            wall_seconds=args.wall_seconds)
        bridge.provider = LedgeredProvider(bridge.provider, ledger,
                                           scope_id=scope_id, role="sp_generation")
        agent = FullSPGenerator(
            function_name=function.name, function_source=function.content,
            function_file=function.file_path or "",
            function_lines=(function.start_line or 0, function.end_line or 0),
            callers=callers, callees=callees, fuzzer=fuzzer, sanitizer="address",
            task_id=task_id, worker_id=worker_id, llm_client=bridge,
            model=args.model if args.mode == "live" else "fixture",
            max_iterations=args.max_iterations if args.mode == "live" else (
                3 if args.mode == "fake-budget" else 2),
            log_dir=args.log_dir,
        )
        try:
            result = await agent.analyze_async()
        finally:
            summary["model_calls_attempted"] = bridge.calls_attempted
        candidates = server.repos.suspicious_points.find_by_task(task_id)
        summary.update({
            "candidates_stored": len(candidates),
            "candidate_ids": [point.suspicious_point_id for point in candidates],
            "agent_sp_created": bool(result.get("sp_created")),
            "agent_sp_details_id": (result.get("sp_details") or {}).get("sp_id"),
            "agent_stop_reason": agent.stop_reason,
            "agent_iterations": agent.total_iterations,
            "agent_response": str(result.get("response", ""))[:300],
            "advertised_tools": sorted(tool["function"]["name"]
                                       for tool in agent._tools),
            "advertised_tool_schema_bytes": len(
                json.dumps(agent._tools, ensure_ascii=False).encode("utf-8")),
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
        elif candidates:
            summary["outcome"] = "CANDIDATE_STORED"
        else:
            summary["outcome"] = "NO_CANDIDATE_COMPLETED"
        if args.mode == "fake-create" and len(candidates) != 1:
            raise RuntimeError("provider-free SP candidate did not persist")
        if args.mode == "fake-budget" and summary["outcome"] != "INCOMPLETE_BUDGET":
            raise RuntimeError("provider-free budget exhaustion was misclassified")
        return summary
    finally:
        if bridge is not None:
            await bridge.close()
        if temporary_ledger is not None:
            temporary_ledger.cleanup()
        if analyzer is not None:
            analyzer.close()
        for cache_key in list(_client_cache):
            if cache_key[0] == str(server.socket_path):
                _invalidate_client(cache_key)
        try:
            await asyncio.wrap_future(
                asyncio.run_coroutine_threadsafe(server.stop(), server_loop))
        finally:
            server_loop.call_soon_threadsafe(server_loop.stop)
            await asyncio.to_thread(server_thread.join, 5)
            server_loop.close()
            MongoDB.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--task-path", type=Path, required=True)
    parser.add_argument("--function-name",
                        help="manual control function from the pinned imported pool")
    parser.add_argument("--mode", choices=("preflight", "fake-create", "fake-budget", "live"),
                        default="preflight")
    parser.add_argument("--model")
    parser.add_argument("--effort", default="low")
    parser.add_argument("--max-model-calls", type=int, default=3)
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--wall-seconds", type=float, default=240)
    parser.add_argument("--ledger-path", type=Path)
    parser.add_argument("--ledger-module-path", type=Path,
                        default=DEFAULT_LEDGER_MODULE)
    parser.add_argument("--ledger-module-sha256", default=DEFAULT_LEDGER_SHA256)
    parser.add_argument("--codex-executable", type=Path)
    parser.add_argument("--codex-executable-sha256")
    parser.add_argument("--event-log", type=Path)
    parser.add_argument("--log-dir", type=Path)
    args = parser.parse_args()
    summary = asyncio.run(run(args))
    print(json.dumps(summary, sort_keys=True, ensure_ascii=False))
    if args.mode == "live" and summary["outcome"].startswith("INCOMPLETE_"):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
