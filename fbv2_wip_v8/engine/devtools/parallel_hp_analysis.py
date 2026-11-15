"""Unsigned HP analysis and optional physical handoff alongside SP work.

The versioned parallel signed entry installs this runner after its own
approval and claim checks. HP-origin Independent Gate and public security
credit remain separate stages.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

from devtools.original_hp_preparation import (
    PreparedHPFunction, _prepared_pins_ok, prepare_hp_function,
    run_prepared_hp_analysis)
from devtools.parallel_hp_selection import (
    claim_parallel_hp_execution, freeze_parallel_hp_selection,
    verify_parallel_hp_execution_claim)


_PROFILE = "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1"
_COMPLETE_ANALYSIS = {
    "NO_SAFE_ASSUMPTION", "NO_ASSERTION_PROPOSAL",
    "ASSERTIONS_PROPOSED_UNVERIFIED",
}


def _read_parallel_result(run_dir: Path, name: str,
                          expected_sha256: str) -> dict[str, Any]:
    path = run_dir / name
    if (type(expected_sha256) is not str or len(expected_sha256) != 64 or
            any(char not in "0123456789abcdef" for char in expected_sha256) or
            path.is_symlink() or not path.is_file() or
            path.stat().st_uid != os.getuid() or
            stat.S_IMODE(path.stat().st_mode) != 0o600 or
            path.stat().st_size > 16_000_000):
        raise ValueError("parallel HP result file is invalid")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("parallel HP result hash changed")
    def unique_pairs(pairs):
        row = {}
        for key, value in pairs:
            if key in row:
                raise ValueError("parallel HP result has duplicate keys")
            row[key] = value
        return row
    row = json.loads(raw, object_pairs_hook=unique_pairs)
    if type(row) is not dict:
        raise ValueError("parallel HP result schema is invalid")
    return row


def reprove_parallel_hp_diagnostic(run_dir: Path, *, task_id: str,
                                   run_id: str, result: dict[str, Any],
                                   qualification: Any | None = None,
                                   process_ledger: Any | None = None,
                                   gate_policy: dict[str, Any] | None = None,
                                   gate_max_wall_seconds: float | None = None,
                                   gate_max_output_bytes: int | None = None,
                                   ) -> dict[str, Any]:
    """Re-read durable HP rows and separately re-prove HP Gate credit."""
    run_dir = Path(run_dir)
    if (not run_dir.is_absolute() or run_dir.is_symlink() or
            run_dir != run_dir.resolve(strict=True) or
            type(result) is not dict or
            result.get("kind") != "FBV2_PARALLEL_HP_ANALYSIS_RESULT_V1" or
            result.get("task_id") != task_id or
            result.get("run_id") != run_id or
            result.get("result_path") != str(
                run_dir / "HP_PARALLEL_ANALYSIS_RESULT.json")):
        raise ValueError("parallel HP identity is invalid")
    saved = _read_parallel_result(
        run_dir, "HP_PARALLEL_ANALYSIS_RESULT.json",
        result.get("result_sha256"))
    expected = {key: value for key, value in result.items()
                if key not in {"result_path", "result_sha256",
                               "physical_status", "physical_result_path",
                               "physical_result_sha256", "gate_status",
                               "gate_result_path", "gate_result_sha256",
                               "gate_error_type"}}
    if (saved != expected or saved.get("task_id") != task_id or
            saved.get("run_id") != run_id or
            saved.get("security_gate_credit") != "NOT_CREDITED" or
            saved.get("discovery_credit") != "NOT_CREDITED"):
        raise ValueError("parallel HP analysis receipt changed")
    diagnostic = {
        "analysis_status": saved.get("status"),
        "analysis_outcome": (saved.get("analysis", {}).get("status")
                             if type(saved.get("analysis")) is dict else None),
        "analysis_result_sha256": result["result_sha256"],
        "physical_status": "NOT_RUN",
        "assertion_observations": None,
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    physical_path = result.get("physical_result_path")
    if physical_path is not None:
        if physical_path != str(run_dir / "HP_PARALLEL_PHYSICAL_RESULT.json"):
            raise ValueError("parallel HP physical locator changed")
        physical = _read_parallel_result(
            run_dir, "HP_PARALLEL_PHYSICAL_RESULT.json",
            result.get("physical_result_sha256"))
        handoff = physical.get("physical_handoff")
        if (physical.get("kind") != "FBV2_PARALLEL_HP_PHYSICAL_RESULT_V1" or
                physical.get("task_id") != task_id or
                physical.get("run_id") != run_id or
                physical.get("analysis_result_sha256") !=
                    result["result_sha256"] or
                physical.get("security_gate_credit") != "NOT_CREDITED" or
                physical.get("discovery_credit") != "NOT_CREDITED" or
                type(handoff) is not dict or
                handoff.get("status") != result.get("physical_status") or
                handoff.get("security_gate_credit") != "NOT_CREDITED" or
                handoff.get("discovery_credit") != "NOT_CREDITED"):
            raise ValueError("parallel HP physical receipt changed")
        diagnostic["physical_status"] = handoff["status"]
        diagnostic["physical_result_sha256"] = (
            result["physical_result_sha256"])
        observations = handoff.get("physical_observations")
        if observations is not None:
            from devtools.hp_result_observations import (
                hp_physical_observations)
            computed = hp_physical_observations(
                handoff.get("assertion_status"),
                handoff.get("guided_report"))
            if observations != computed:
                raise ValueError("parallel HP Assertion observations changed")
            diagnostic["assertion_observations"] = computed
    elif any(key in result for key in (
            "physical_status", "physical_result_sha256")):
        raise ValueError("parallel HP physical receipt is missing")
    if "gate_result_path" in result:
        if (physical_path is None or
                handoff.get("status") !=
                    "HP_GUIDED_CRASH_OBSERVED_UNGATED" or
                type(diagnostic["assertion_observations"]) is not dict or
                diagnostic["assertion_observations"].get(
                    "guided_crash_observed_ungated") is not True or
                gate_policy is None or qualification is None or
                process_ledger is None or
                gate_max_wall_seconds is None or
                gate_max_output_bytes is None):
            raise ValueError("parallel HP Gate prerequisites are missing")
        from devtools.hp_guided_crash_freeze import (
            _regular_bytes, _unique_pairs)
        from devtools.hp_gate_handoff import reprove_hp_gate_handoff
        gate_dir = run_dir / "hp-gate"
        gate_path = gate_dir / "HP_PARALLEL_GATE_RESULT.json"
        if result["gate_result_path"] != str(gate_path):
            raise ValueError("parallel HP Gate locator changed")
        gate_raw = _regular_bytes(gate_path, gate_dir, 16_000_000)
        gate_row = json.loads(gate_raw, object_pairs_hook=_unique_pairs)
        proof = reprove_hp_gate_handoff(
            result={**gate_row, "result_path": str(gate_path),
                    "result_sha256": result["gate_result_sha256"]},
            physical_row=handoff,
            qualification=qualification,
            process_ledger=process_ledger,
            output_dir=gate_dir, policy=gate_policy,
            max_wall_seconds=gate_max_wall_seconds,
            max_output_bytes=gate_max_output_bytes,
            task_id=task_id, run_id=run_id)
        if proof["status"] != result.get("gate_status"):
            raise ValueError("parallel HP Gate status changed")
        diagnostic["gate_status"] = proof["status"]
        diagnostic["gate_result_sha256"] = result["gate_result_sha256"]
        diagnostic["security_gate_credit"] = proof["security_gate_credit"]
        diagnostic["processed_lead_count"] = proof["processed_lead_count"]
        diagnostic["unprocessed_lead_count"] = proof["unprocessed_lead_count"]
        diagnostic["rejected_lead_count"] = proof["rejected_lead_count"]
        diagnostic["pending_lead_count"] = proof["pending_lead_count"]
    elif result.get("gate_status") is not None:
        if (result["gate_status"] != "HP_GATE_INCOMPLETE" or
                type(result.get("gate_error_type")) is not str):
            raise ValueError("parallel HP Gate result is missing")
        diagnostic["gate_status"] = "HP_GATE_INCOMPLETE"
    elif any(key in result for key in (
            "gate_result_sha256", "gate_error_type")):
        raise ValueError("parallel HP Gate receipt is incomplete")
    return diagnostic


def _blocked(reason: str) -> dict[str, Any]:
    return {"kind": "FBV2_PARALLEL_HP_ANALYSIS_RESULT_V1",
            "status": "HP_PARALLEL_ANALYSIS_BLOCKED", "reason": reason,
            "security_gate_credit": "NOT_CREDITED",
            "discovery_credit": "NOT_CREDITED",
            "sp_global_effect": "UNCHANGED"}


async def _close_hp_role_pipelines(pipelines: tuple[Any, ...]) -> bool:
    """Join owned provider cleanup before propagating caller cancellation.

    Each provider is responsible for its bounded process shutdown. A cancelled
    close still requires attempting the other provider's shutdown.
    """
    async def close_all():
        failed = False
        inner_cancellation = None
        for pipeline in pipelines:
            if pipeline is not None:
                try:
                    await pipeline.provider.close()
                except asyncio.CancelledError as exc:
                    failed = True
                    if inner_cancellation is None:
                        inner_cancellation = exc
                except Exception:
                    failed = True
        return failed, inner_cancellation

    task = asyncio.create_task(close_all())
    cancellation = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if cancellation is None:
                cancellation = exc
    failed, inner_cancellation = task.result()
    if cancellation is not None:
        if inner_cancellation is not None:
            raise cancellation from inner_cancellation
        raise cancellation
    if inner_cancellation is not None:
        raise inner_cancellation
    return failed


async def _join_physical_handoff(handoff, work, row):
    """Keep the owned physical process joined even if the caller is cancelled."""
    task = asyncio.create_task(asyncio.to_thread(handoff, work, row))
    cancellation = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if cancellation is None:
                cancellation = exc
    if cancellation is not None:
        try:
            task.result()
        except BaseException as exc:
            cancellation.add_note("HP physical settlement: " +
                                  type(exc).__name__)
        raise cancellation
    return task.result()


async def _join_gate_handoff(handoff):
    """Join a Gate physical replay before propagating HP cancellation."""
    task = asyncio.create_task(asyncio.to_thread(handoff))
    cancellation = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if cancellation is None:
                cancellation = exc
    if cancellation is not None:
        try:
            task.result()
        except BaseException as exc:
            cancellation.add_note("HP Gate settlement: " +
                                  type(exc).__name__)
        raise cancellation
    return task.result()


async def run_parallel_hp_analysis(
        bound: Any, strategy: Any, directions: list[Any], *,
        hp: dict[str, Any], spec_path: Path, spec_sha256: str
        ) -> dict[str, Any]:
    """Run one pinned HP SAFE/Assertion attempt alongside SP model work.

    This does not grant physical or security success. The public entry must
    separately admit the new profile and install it as the SP async factory.
    """
    from devtools.original_hp_live_optin import (
        _check_signed_hp_spec, _physical_handoff_factory,
        _pipeline_factory, _write_once,
        validate_hp_spec)
    from devtools.original_hp_post_worker import _current_direction_ids

    try:
        bound.recheck()
        _check_signed_hp_spec(Path(spec_path), spec_sha256, hp)
        validate_hp_spec(hp, bound.identity.product_src, enabled=True)
        spec = json.loads(Path(spec_path).read_bytes())
        gate_policy = spec.get("hp_gate")
        if gate_policy is not None:
            from devtools.hp_gate_handoff import validate_hp_gate_policy
            validate_hp_gate_policy(
                gate_policy,
                max_wall_seconds=spec["caps"][
                    "gate_aux_reservation_seconds_per_observation"],
                max_output_bytes=hp["physical"]["output_limit_bytes"])
        scope = spec.get("development_seed_scope")
        if (type(scope) is not dict or scope.get("kind") != _PROFILE or
                scope.get("sp_queue_policy") !=
                    "PERSISTENT_CONCURRENT_QUEUE_V1" or
                scope.get("worker_pool") !=
                    {"discovery": 3, "verifier": 2, "pov": 2} or
                spec.get("identity", {}).get("task_id") !=
                    bound.identity.task_id or
                spec["identity"].get("run_id") != bound.identity.run_id or
                getattr(bound.caps, "sp_concurrent_queue", False) is not True or
                bound.strategy is not strategy or
                strategy.executor is not bound.executor or
                not directions):
            return _blocked("HP_PARALLEL_PROFILE_IDENTITY_INVALID")
        current_ids = _current_direction_ids(bound)
        if (current_ids is None or
                {item.direction_id for item in directions} != current_ids or
                len(directions) != len(current_ids)):
            return _blocked("HP_PARALLEL_DIRECTION_PLAN_UNPROVEN")
        _, plan_sha256 = strategy._development_direction_plan
        manifest = Path(bound.admission.summary["manifest_path"])
        manifest_sha256 = bound.admission.summary["manifest_sha256"]
        if (manifest.is_symlink() or not manifest.is_file() or
                manifest != manifest.resolve() or
                hashlib.sha256(manifest.read_bytes()).hexdigest() !=
                    manifest_sha256):
            return _blocked("HP_PARALLEL_CATALOG_CHANGED")
        task_id, run_id = bound.identity.task_id, bound.identity.run_id
        fuzzer = bound.executor.fuzzer
        run_dir = Path(bound.identity.run_dir)

        def current_functions():
            return bound.server.repos.functions.find_by_task(task_id)

        selected, selection_sha256 = freeze_parallel_hp_selection(
            run_dir=run_dir, task_id=task_id, run_id=run_id,
            fuzzer=fuzzer, spec_sha256=spec_sha256,
            direction_plan_sha256=plan_sha256,
            function_catalog_sha256=manifest_sha256,
            directions=directions, functions=current_functions())
        if selected is None:
            return _blocked("HP_NO_ELIGIBLE_FUNCTION")
        function, direction = selected
        claim_sha256 = claim_parallel_hp_execution(
            run_dir=run_dir, task_id=task_id, run_id=run_id,
            spec_sha256=spec_sha256,
            selection_receipt_sha256=selection_sha256)
        evidence = {
            "origin": "PARALLEL_HP_PRE_SP_SELECTION_V1",
            "task_id": task_id, "run_id": run_id,
            "function_id": function.function_id,
            "direction_id": direction.direction_id,
            "source_tree_sha256": bound.admission.qualification.source_tree_sha256,
            "contract_sha256": bound.admission.qualification.contract_sha256,
            "spec_sha256": spec_sha256,
            "direction_plan_sha256": plan_sha256,
            "function_catalog_sha256": manifest_sha256,
            "selection_receipt_sha256": selection_sha256,
            "execution_claim_sha256": claim_sha256,
            "run_dir": str(run_dir),
        }

        def check_selection() -> None:
            bound.recheck()
            if (_current_direction_ids(bound) != current_ids or
                    not verify_parallel_hp_execution_claim(
                        run_dir=run_dir, task_id=task_id, run_id=run_id,
                        spec_sha256=spec_sha256,
                        function_id=function.function_id,
                        direction_id=direction.direction_id,
                        direction_plan_sha256=plan_sha256,
                        function_catalog_sha256=manifest_sha256,
                        selection_receipt_sha256=selection_sha256,
                        execution_claim_sha256=claim_sha256)):
                raise ValueError("HP parallel claim changed")
            current, digest = freeze_parallel_hp_selection(
                run_dir=run_dir, task_id=task_id, run_id=run_id,
                fuzzer=fuzzer, spec_sha256=spec_sha256,
                direction_plan_sha256=plan_sha256,
                function_catalog_sha256=manifest_sha256,
                directions=directions, functions=current_functions())
            if (current is None or digest != selection_sha256 or
                    (current[0].function_id, current[1].direction_id) !=
                        (function.function_id, direction.direction_id)):
                raise ValueError("HP parallel selection changed")

        check_selection()
        work = prepare_hp_function(
            function=function, direction=direction,
            qualification=bound.admission.qualification,
            fuzzer=fuzzer, sanitizer="address",
            parallel_hp_selection_evidence=evidence)
        if type(work) is not PreparedHPFunction:
            return _blocked(work.get("reason", "HP_PARALLEL_PREPARATION_INVALID"))
        analysis = assertion = None
        close_failed = False
        try:
            analysis = _pipeline_factory(
                bound, hp, "function_analysis", Path(spec_path), spec_sha256,
                extra_check=check_selection)(work)
            assertion = _pipeline_factory(
                bound, hp, "assertion_generator", Path(spec_path), spec_sha256,
                extra_check=check_selection)(work)
            if (analysis.provider.gate is not bound.model_gate or
                    assertion.provider.gate is not bound.model_gate):
                return _blocked("HP_SHARED_MODEL_GATE_MISMATCH")
            row = await run_prepared_hp_analysis(
                work=work, qualification=bound.admission.qualification,
                analysis_pipeline=analysis, assertion_pipeline=assertion,
                worker_id=bound.executor._worker_context.worker_id,
                max_context_reanalyses=1,
                bounded_nohint_hp_context=True,
                catalog_manifest_path=manifest,
                catalog_manifest_sha256=manifest_sha256)
        finally:
            close_failed = await _close_hp_role_pipelines((assertion, analysis))
        check_selection()
        owners = {f"hp:{work.function_id}:{work.direction_id}:function_analysis",
                  f"hp:{work.function_id}:{work.direction_id}:assertion_generator"}
        model_rows = [item for item in bound.model_gate.snapshot()["records"]
                      if item.get("owner_id") in owners]
        required_roles = ({"function_analysis", "assertion_generator"}
                          if row.get("status") in {
                              "NO_ASSERTION_PROPOSAL",
                              "ASSERTIONS_PROPOSED_UNVERIFIED"}
                          else {"function_analysis"})
        model_settled = (not close_failed and 1 <= len(model_rows) <=
                         hp["max_model_calls"] and
                         required_roles.issubset({item.get("role")
                                                  for item in model_rows}) and
                         all(item.get("status") == "COMPLETED" and
                             bound.model_gate.verify_response_evidence(
                                 item["request_id"]).get("status") == "VERIFIED"
                             for item in model_rows))
        status = ("HP_PARALLEL_ANALYSIS_COMPLETE" if
                  model_settled and row.get("status") in _COMPLETE_ANALYSIS else
                  "HP_PARALLEL_ANALYSIS_INCOMPLETE")
        result = {
            "kind": "FBV2_PARALLEL_HP_ANALYSIS_RESULT_V1",
            "status": status, "task_id": task_id, "run_id": run_id,
            "selected_pair": [work.function_id, work.direction_id],
            "selection_receipt_sha256": selection_sha256,
            "execution_claim_sha256": claim_sha256,
            "model_request_ids": [item["request_id"] for item in model_rows],
            "analysis": row,
            "security_gate_credit": "NOT_CREDITED",
            "discovery_credit": "NOT_CREDITED",
            "sp_global_effect": "UNCHANGED",
        }
        result_sha256 = _write_once(
            run_dir / "HP_PARALLEL_ANALYSIS_RESULT.json", result)
        returned = {**result,
                "result_path": str(run_dir / "HP_PARALLEL_ANALYSIS_RESULT.json"),
                "result_sha256": result_sha256}
        if (status == "HP_PARALLEL_ANALYSIS_COMPLETE" and
                row.get("status") == "ASSERTIONS_PROPOSED_UNVERIFIED" and
                hp.get("physical") is not None):
            try:
                handoff = _physical_handoff_factory(
                    bound, hp, None, Path(spec_path), spec_sha256,
                    actor_id=bound.executor._worker_context.worker_id,
                    extra_check=check_selection,
                    parallel_hp_execution=True)
                physical_row = await _join_physical_handoff(
                    handoff, work, row)
                if (type(physical_row) is not dict or
                        physical_row.get("security_gate_credit") !=
                            "NOT_CREDITED" or
                        physical_row.get("discovery_credit") !=
                            "NOT_CREDITED"):
                    raise ValueError("HP physical result has invalid credit")
            except Exception as exc:
                physical_row = {
                    "status": "HP_PARALLEL_PHYSICAL_INCOMPLETE",
                    "error_type": type(exc).__name__,
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED",
                }
            physical_result = {
                "kind": "FBV2_PARALLEL_HP_PHYSICAL_RESULT_V1",
                "task_id": task_id, "run_id": run_id,
                "analysis_result_sha256": result_sha256,
                "physical_handoff": physical_row,
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED",
            }
            physical_sha256 = _write_once(
                run_dir / "HP_PARALLEL_PHYSICAL_RESULT.json",
                physical_result)
            returned["physical_status"] = physical_row["status"]
            returned["physical_result_path"] = str(
                run_dir / "HP_PARALLEL_PHYSICAL_RESULT.json")
            returned["physical_result_sha256"] = physical_sha256
            if (physical_row["status"] ==
                    "HP_GUIDED_CRASH_OBSERVED_UNGATED" and
                    gate_policy is not None):
                from devtools.hp_gate_handoff import run_hp_gate_handoff

                def gate_handoff():
                    check_selection()
                    return run_hp_gate_handoff(
                        physical_row=physical_row,
                        qualification=bound.admission.qualification,
                        process_ledger=bound.process_ledger,
                        output_dir=run_dir / "hp-gate",
                        policy=gate_policy,
                        max_wall_seconds=spec["caps"][
                            "gate_aux_reservation_seconds_per_observation"],
                        max_output_bytes=hp["physical"][
                            "output_limit_bytes"])

                try:
                    gate_result = await _join_gate_handoff(gate_handoff)
                    if (gate_result.get("task_id") != task_id or
                            gate_result.get("run_id") != run_id or
                            gate_result.get("assertion_id") !=
                                physical_row.get("assertion_id") or
                            gate_result.get("discovery_credit") !=
                                "NOT_CREDITED"):
                        raise ValueError("HP Gate result identity changed")
                    returned["gate_status"] = gate_result["status"]
                    returned["gate_result_path"] = gate_result["result_path"]
                    returned["gate_result_sha256"] = (
                        gate_result["result_sha256"])
                except Exception as exc:
                    returned["gate_status"] = "HP_GATE_INCOMPLETE"
                    returned["gate_error_type"] = type(exc).__name__
        return returned
    except Exception as exc:
        return {**_blocked("HP_PARALLEL_ANALYSIS_ERROR"),
                "error_type": type(exc).__name__}
