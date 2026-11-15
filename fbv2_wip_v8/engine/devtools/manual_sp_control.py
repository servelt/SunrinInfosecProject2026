"""One explicitly selected public-development SP -> Verifier -> PoV control.

This is a bounded transport for the original agents, not a discovery run. It
never enters the original Seed/Global path and never grants Gate credit. The
fresh, signed CLI admission lives in ``original_public_live_entry``; this
module repeats its essential checks before the first model request.
"""

from __future__ import annotations

import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from devtools.original_public_live import (
    BoundOriginalPublicDev, _pinned_file, incomplete_model_activity,
    require_journaled_mongo,
)


_FUNCTION_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _manual_admission(bound: BoundOriginalPublicDev, function_name: str,
                      authorized: bool) -> None:
    if (authorized is not True or type(bound) is not BoundOriginalPublicDev or
            type(function_name) is not str or
            _FUNCTION_NAME.fullmatch(function_name) is None or
            sys.flags.isolated != 1):
        raise ValueError("signed isolated manual SP control is required")
    main = sys.modules.get("__main__")
    entry = Path(__file__).resolve().parent / "original_public_live_entry.py"
    marker = getattr(main, "_PINNED_PUBLIC_BOOTSTRAP", None)
    argv = sys.argv
    if (Path(getattr(main, "__file__", "")).resolve() != entry or
            Path(argv[0]).resolve() != entry or
            argv.count("--authorize-manual-sp-control") != 1 or
            argv.count("--function-name") != 1 or
            argv[argv.index("--function-name") + 1:
                 argv.index("--function-name") + 2] != [function_name] or
            type(marker) is not dict or
            marker.get("manual_sp_mode") is not True or
            marker.get("hp_mode") is not False or
            marker.get("pid") != os.getpid() or
            marker.get("used") is not False or
            bound.bootstrap_token is None or
            marker.get("token") is not bound.bootstrap_token or
            marker.get("engine_py_sha256") != bound.identity.engine_py_sha256 or
            marker.get("product_py_sha256") != bound.identity.product_py_sha256 or
            marker.get("evaluation_py_sha256") !=
                bound.identity.evaluation_py_sha256 or
            type(marker.get("spec_path")) is not str or
            type(marker.get("spec_sha256")) is not str):
        raise RuntimeError("fresh manual SP bootstrap identity is required")
    _pinned_file(Path(marker["spec_path"]), marker["spec_sha256"],
                 "manual public development launch spec")
    spec = json.loads(Path(marker["spec_path"]).read_text(encoding="utf-8"))
    control = spec.get("manual_sp_control")
    if (type(control) is not dict or control != {
            "enabled": True, "function_name": function_name,
            "max_model_calls_by_role": {"sp": 6, "verifier": 6, "pov": 6},
            "automatic_discovery": False} or
            bound.caps.calls_per_agent != 6 or
            bound.caps.physical_model_calls != 18 or
            spec.get("identity", {}).get("run_id") != bound.identity.run_id or
            spec.get("identity", {}).get("task_id") != bound.identity.task_id):
        raise ValueError("manual SP function or physical cap differs from signed spec")
    marker["used"] = True
    bound.recheck()
    require_journaled_mongo(bound.server, bound.identity.task_id)
    if (bound.executor.task_id != bound.identity.task_id or
            bound.executor.repos is not bound.server.repos or
            bound.executor.llm_client_factory is None or
            bound.executor.qualified_pov_runtime_binding is not
                bound.pov_adapter.binding or
            bound.pov_adapter.ledger is not bound.process_ledger or
            bound.global_campaign.final_result is not None or
            bound.model_gate.snapshot()["physical"] != 0 or
            bound.model_gate.snapshot()["records"] or
            bound.process_ledger.snapshot()["stop_status"] is not None or
            bound.process_ledger.snapshot()["active"] or
            bound.server.repos.suspicious_points.find_by_task(
                bound.identity.task_id)):
        raise ValueError("manual SP task, budget, or queue is not fresh")


def _pinned_function(bound: BoundOriginalPublicDev, function_name: str) -> Any:
    """Re-read the prebuilt source hashes before letting the model inspect it."""
    manifest_path = Path(bound.admission.summary["manifest_path"])
    _pinned_file(manifest_path, bound.admission.summary["manifest_sha256"],
                 "prebuilt manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source_files = manifest.get("source_files")
    repo = bound.identity.task_path / "repo"
    if (type(source_files) is not dict or not source_files or
            repo.is_symlink() or repo.resolve() != repo):
        raise ValueError("pinned prebuilt source map is unavailable")
    for relative, expected in source_files.items():
        if (type(relative) is not str or type(expected) is not str or
                Path(relative).is_absolute() or ".." in Path(relative).parts or
                re.fullmatch(r"[0-9a-f]{64}", expected) is None):
            raise ValueError("invalid prebuilt source pin")
        path = repo / relative
        if (not path.is_file() or path.is_symlink() or
                not path.resolve().is_relative_to(repo) or
                hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise ValueError("prebuilt source changed before manual SP control")
    functions = [function for function in
                 bound.server.repos.functions.find_by_task(bound.identity.task_id)
                 if function.name == function_name]
    if len(functions) != 1:
        raise ValueError("manual function is absent or ambiguous in imported pool")
    function = functions[0]
    relative = function.file_path
    if (type(relative) is not str or relative not in source_files or
            type(function.content) is not str or not function.content or
            (repo / relative).read_text(encoding="utf-8").count(
                function.content) != 1 or
            bound.admission.prepared["fuzzer_name"] not in
                function.reached_by_fuzzers or
            function_name == bound.admission.prepared["fuzzer_name"]):
        raise ValueError("manual function does not match pinned catalog source")
    return function


def _bounded_client_factory(bound: BoundOriginalPublicDev):
    """Enforce the signed physical role budgets across all clients."""
    original = bound.executor.llm_client_factory

    def create(role: str, owner_id: str):
        if role not in {"sp", "sp_large", "verifier", "pov"}:
            raise ValueError("manual SP control cannot start another model role")
        rows = bound.model_gate.snapshot()["records"]
        family = {"sp", "sp_large"} if role in {"sp", "sp_large"} else {role}
        used = sum(row.get("role") in family for row in rows)
        limit = 6
        remaining = limit - used
        if remaining < 1:
            from fuzzingbrain.worker.pipeline import IncompleteInjectedAgent
            raise IncompleteInjectedAgent(
                "manual role physical cap exhausted before transport",
                reason="budget_before_transport")
        client = original(role, owner_id)
        if (type(getattr(client, "max_calls", None)) is not int or
                client.max_calls < remaining):
            raise ValueError("bound manual model client has a smaller hidden cap")
        client.max_calls = remaining
        return client

    return create


async def _run_bound_agents(bound: BoundOriginalPublicDev, function: Any,
                            worker_id: str) -> dict[str, Any]:
    from fuzzingbrain.agents.sp_generators import (
        FullSPGenerator, LargeFullSPGenerator)
    from fuzzingbrain.llms.models import CLAUDE_OPUS_4_5, CLAUDE_SONNET_4_5
    from fuzzingbrain.tools.analyzer import set_analyzer_context
    from fuzzingbrain.tools.code_viewer import set_code_viewer_context
    from fuzzingbrain.tools.suspicious_points import set_sp_context
    from fuzzingbrain.worker.pipeline import (
        AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
        injected_agent_client, require_injected_agent_complete)

    task_id = bound.identity.task_id
    fuzzer = bound.admission.prepared["fuzzer_name"]
    root = bound.identity.run_dir
    model_factory = _bounded_client_factory(bound)
    socket_path = str(bound.server.socket_path)
    source = function.content
    callers = (bound.server.repos.callgraph_nodes.find_callers(
        task_id, fuzzer, function.name) or [])
    callees = (bound.server.repos.callgraph_nodes.find_callees(
        task_id, fuzzer, function.name) or [])
    manifest = json.loads(Path(bound.admission.summary["manifest_path"]).read_text(
        encoding="utf-8"))
    harness_relative = manifest.get("harness_source")
    if (type(harness_relative) is not str or
            harness_relative not in manifest["source_files"]):
        raise ValueError("pinned harness source missing from manifest")
    harness_path = bound.identity.task_path / "repo" / harness_relative
    harness_bytes = harness_path.read_bytes()
    if (hashlib.sha256(harness_bytes).hexdigest() !=
            manifest["source_files"][harness_relative]):
        raise ValueError("pinned harness source changed before SP generation")
    harness_source = harness_bytes.decode("utf-8")
    if not harness_source:
        raise ValueError("pinned harness source is empty")
    set_analyzer_context(socket_path, client_id="manual_sp_control")
    set_code_viewer_context(str(bound.identity.task_path), repo_subdir="repo",
                            project_name=bound.admission.summary["project_name"])
    set_sp_context(fuzzer, "address")

    log_dir = root / "manual-sp-agent-logs"
    pov_dir = root / "manual-sp-povs"
    for path in (log_dir, pov_dir):
        path.mkdir(mode=0o700)
    is_large = source.count("\n") + 1 > LargeFullSPGenerator.LARGE_FUNCTION_THRESHOLD
    role = "sp_large" if is_large else "sp"
    owner = f"manual:{getattr(function, 'function_id', function.name)}:0"
    outcome: dict[str, Any] = {"generation_completed": False,
                               "pipeline_completed": False,
                               "incomplete_reason": None,
                               "pipeline_stats": None}
    pipeline = None
    try:
        async with injected_agent_client(model_factory, role, owner) as client:
            agent_class = LargeFullSPGenerator if is_large else FullSPGenerator
            agent = agent_class(
                function_name=function.name, function_source=source,
                function_file=function.file_path or "",
                function_lines=(function.start_line or 0, function.end_line or 0),
                callers=callers, callees=callees, fuzzer=fuzzer,
                sanitizer="address", llm_client=client,
                model=CLAUDE_OPUS_4_5 if is_large else CLAUDE_SONNET_4_5,
                max_iterations=6 if is_large else 5,
                task_id=task_id, worker_id=worker_id,
                log_dir=log_dir, index=0)
            generation = await agent.analyze_async()
            require_injected_agent_complete(client, agent)
            if type(generation) is not dict or generation.get("success") is not True:
                raise IncompleteInjectedAgent(
                    "manual SP generation did not complete", reason="sp_incomplete")
        outcome["generation_completed"] = True
        if incomplete_model_activity(bound.model_gate.snapshot(), bound.model_gate):
            raise IncompleteInjectedAgent(
                "manual SP model evidence is incomplete", reason="model_evidence")
        candidates = bound.server.repos.suspicious_points.find_by_task(task_id)
        if not candidates:
            return outcome
        if any(point.function_name != function.name for point in candidates):
            raise ValueError("manual SP agent created an unrelated candidate")

        bound.recheck()
        if _pinned_function(bound, function.name).content != source:
            raise ValueError("manual function source changed after SP generation")
        config = PipelineConfig(
            num_verify_agents=1, num_pov_agents=1, pov_min_score=0.5,
            poll_interval=0.2, max_idle_cycles=10, max_iterations=6,
            max_pov_attempts=3, verifier_max_iterations=6,
            fuzzer_path=bound.pov_adapter.binding.pinned_binary()[0])
        pipeline = AgentPipeline(
            task_id=task_id, repos=bound.server.repos, fuzzer=fuzzer,
            sanitizer="address", scan_mode="full", config=config,
            output_dir=pov_dir, log_dir=log_dir,
            workspace_path=bound.executor.task_workspace_path,
            fuzzer_code=harness_source, mcp_socket_path=socket_path,
            worker_id=worker_id, llm_client_factory=model_factory,
            qualified_runtime_binding=bound.pov_adapter.binding)
        pipeline._sp_finding_done = True
        stats = await pipeline.run()
        outcome["pipeline_completed"] = True
        outcome["pipeline_stats"] = stats.to_dict()
    except IncompleteInjectedAgent as exc:
        outcome["incomplete_reason"] = exc.reason
        if pipeline is not None:
            outcome["pipeline_stats"] = pipeline.stats.to_dict()
    return outcome


def run_manual_sp_control(
    bound: BoundOriginalPublicDev, function_name: str, *,
    explicit_public_dev_authorization: bool,
) -> dict[str, Any]:
    """Run one manually selected original SP/Verifier/PoV trial, without credit."""
    _manual_admission(bound, function_name, explicit_public_dev_authorization)
    function = _pinned_function(bound, function_name)
    from fuzzingbrain.worker.context import WorkerContext

    with WorkerContext(
        task_id=bound.identity.task_id, fuzzer=bound.executor.fuzzer,
        sanitizer=bound.executor.sanitizer, scan_mode=bound.executor.scan_mode,
        project_name=bound.executor.project_name,
        task_type=bound.executor.task_type,
        workspace_path=str(bound.executor.workspace_path),
        celery_job_id=bound.executor.celery_job_id,
    ) as worker:
        bound.executor._worker_context = worker
        outcome = asyncio.run(_run_bound_agents(bound, function, worker.worker_id))

    candidates = bound.server.repos.suspicious_points.find_by_task(
        bound.identity.task_id)
    statuses = Counter(str(point.status.value if hasattr(point.status, "value")
                           else point.status) for point in candidates)
    model = bound.model_gate.snapshot()
    process, process_sha256 = bound.process_ledger.receipt_snapshot()
    model_incomplete = incomplete_model_activity(model, bound.model_gate)
    pending = any(not point.is_checked for point in candidates)
    if (outcome["incomplete_reason"] or model_incomplete or pending or
            model["physical"] < 1 or
            process["stop_status"] is not None or process["active"] or
            bound.global_campaign.final_result is not None):
        status = "INCOMPLETE"
    elif not candidates:
        status = "MANUAL_SP_CONTROL_NO_CANDIDATE"
    else:
        status = "MANUAL_SP_CONTROL_EXECUTED"
    if not model_incomplete and process["stop_status"] is None and not process["active"]:
        bound.recheck()
        if _pinned_function(bound, function_name).content != function.content:
            raise ValueError("manual function source changed after control run")
    incomplete_reason = outcome["incomplete_reason"]
    if incomplete_reason is None and pending:
        incomplete_reason = "UNVERIFIED_CANDIDATE"
    if incomplete_reason is None and model["physical"] < 1:
        incomplete_reason = "NO_PHYSICAL_MODEL_TURN"
    if incomplete_reason is None and (model_incomplete or
                                      process["stop_status"] is not None or
                                      process["active"]):
        incomplete_reason = "MODEL_OR_PROCESS_ACCOUNT"
    if incomplete_reason is None and bound.global_campaign.final_result is not None:
        incomplete_reason = "UNAUTHORIZED_GLOBAL_STAGE"
    return {
        "kind": "FBV2_PUBLIC_MANUAL_SP_CONTROL_V1",
        "status": status,
        "selection_basis": "MANUAL_FUNCTION_CONTROL",
        "automatic_discovery": False,
        "security_gate_credit": "NOT_CREDITED",
        "task_id": bound.identity.task_id,
        "run_id": bound.identity.run_id,
        "worker_id": worker.worker_id,
        "function_name": function_name,
        "function_source_sha256": hashlib.sha256(
            function.content.encode("utf-8")).hexdigest(),
        "prebuilt_manifest_sha256": bound.admission.summary["manifest_sha256"],
        "generation_completed": outcome["generation_completed"],
        "pipeline_completed": outcome["pipeline_completed"],
        "incomplete_reason": incomplete_reason,
        "candidate_count": len(candidates),
        "candidate_status_counts": dict(sorted(statuses.items())),
        "verifier_executed": (outcome["pipeline_stats"] or {}).get(
            "sp_verified", 0),
        "pov_generated": (outcome["pipeline_stats"] or {}).get(
            "pov_generated", 0),
        "pov_no_crash_inputs_executed": (outcome["pipeline_stats"] or {}).get(
            "pov_no_crash_inputs_executed", 0),
        "pov_pending_runtime": (outcome["pipeline_stats"] or {}).get(
            "pov_pending_runtime", 0),
        "pov_pending_validation": (outcome["pipeline_stats"] or {}).get(
            "pov_pending_validation", 0),
        "model_physical_calls": model["physical"],
        "model_record_status_counts": dict(sorted(Counter(
            row.get("status", "UNKNOWN") for row in model["records"]).items())),
        "process_wall_seconds": process["wall_spent_seconds"],
        "process_fuzz_seconds": process["fuzz_spent_seconds"],
        "process_stop_status": process["stop_status"],
        "process_receipt_sha256": process_sha256,
    }
