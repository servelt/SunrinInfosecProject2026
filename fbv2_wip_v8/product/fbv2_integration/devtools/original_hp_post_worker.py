"""Opt-in HP handoff after one completed original FBv2 public-dev Worker.

This is an injection seam, not a live Worker hook. It does not change the
original SP/Global result or grant discovery/Gate credit. The caller supplies
the completed run receipt and two role-bound product pipeline factories.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat
from typing import Any, Callable

from fuzzingbrain.core.models.worker import WorkerStatus

from devtools.original_hp_preparation import (
    PreparedHPFunction, prepare_hp_function, run_prepared_hp_analysis,
)


def _blocked(reason: str, task_id: str | None = None,
             run_id: str | None = None) -> dict[str, Any]:
    return {"status": "HP_POST_WORKER_BLOCKED", "reason": reason,
            "task_id": task_id, "run_id": run_id,
            "sp_global_effect": "UNCHANGED", "security_gate_credit": "NOT_CREDITED"}


def _partial_blocked(reason: str, task_id: str, run_id: str,
                     receipt: dict[str, Any], rows: list[dict[str, Any]]
                     ) -> dict[str, Any]:
    return {"status": "HP_POST_WORKER_PARTIAL_BLOCKED", "reason": reason,
            "task_id": task_id, "run_id": run_id,
            "original_result": receipt["original_result"],
            "original_execution_status": receipt.get("execution_status"),
            "original_global_status": receipt.get("global_status"),
            "rows": rows, "sp_global_effect": "UNCHANGED",
            "security_gate_credit": "NOT_CREDITED"}


def _settled_model(gate: Any, snapshot: dict[str, Any]) -> bool:
    rows = snapshot.get("records")
    if type(rows) is not list:
        return False
    for row in rows:
        if type(row) is not dict or row.get("status") != "COMPLETED":
            return False
        request_id = row.get("request_id")
        if (type(request_id) is not str or not request_id or
                gate.verify_response_evidence(request_id).get("status") !=
                    "VERIFIED"):
            return False
        events = row.get("tool_events", [])
        if type(events) is not list:
            return False
        for event in events:
            if (type(event) is not dict or
                    event.get("status") != "COMPLETED" or
                    type(event.get("call_id")) is not str or
                    gate.verify_tool_event(request_id, event["call_id"]).get(
                        "status") != "VERIFIED"):
                return False
    return True


def _current_direction_ids(bound: Any) -> set[str] | None:
    """Re-read this Worker's pinned Direction planning tool result."""
    try:
        path, expected_sha = bound.strategy._development_direction_plan
        path = Path(path)
        if (not path.is_absolute() or path.is_symlink() or
                not path.is_file() or path != path.resolve() or
                type(expected_sha) is not str):
            return None
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            return None
        plan = json.loads(raw)
        ids = plan.get("direction_ids")
        if (plan.get("kind") != "FBV2_DEV_DIRECTION_PLAN_V1" or
                plan.get("status") != "COMPLETED" or
                plan.get("task_id") != bound.identity.task_id or
                plan.get("fuzzer") != bound.executor.fuzzer or
                type(ids) is not list or not ids or
                any(type(value) is not str or not value for value in ids) or
                len(set(ids)) != len(ids) or
                plan.get("direction_count") != len(ids)):
            return None
        return set(ids)
    except (AttributeError, TypeError, ValueError, OSError, UnicodeError,
            json.JSONDecodeError):
        return None


def _private_directory(path: Path) -> bool:
    """Require a same-owner run directory with no writable outside users."""
    try:
        return (path.is_absolute() and path == path.resolve(strict=True) and
                not any(parent.is_symlink() for parent in (path, *path.parents)) and
                path.is_dir() and path.stat().st_uid == os.getuid() and
                stat.S_IMODE(path.stat().st_mode) == 0o700)
    except (OSError, RuntimeError, ValueError):
        return False


def _claim_live_hp_pair(bound: Any, worker_id: str,
                        prepared: PreparedHPFunction) -> str | None:
    """Durably consume one HP opportunity before constructing role clients.

    Claims are intentionally never released. A crash after this write may
    forfeit the pair, but cannot silently resend a possibly started model turn.
    """
    identity = bound.identity
    run_dir = getattr(identity, "run_dir", None)
    if run_dir is None:
        return "LIVE_HP_IDEMPOTENCE_CLAIM_MISSING"
    run_dir = Path(run_dir)
    if not _private_directory(run_dir):
        return "LIVE_HP_CLAIM_DIRECTORY_UNSAFE"
    claim_dir = run_dir / "hp-claims"
    try:
        try:
            claim_dir.mkdir(mode=0o700)
            parent_fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except FileExistsError:
            pass
        if not _private_directory(claim_dir):
            return "LIVE_HP_CLAIM_DIRECTORY_UNSAFE"
        pair = {"task_id": identity.task_id, "run_id": identity.run_id,
                "function_id": prepared.function_id,
                "direction_id": prepared.direction_id}
        pair_bytes = (json.dumps(pair, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode()
        name = "hp-" + hashlib.sha256(pair_bytes).hexdigest() + ".claim.json"
        payload = {"kind": "FBV2_HP_PAIR_CLAIM_V1", **pair,
                   "worker_id": worker_id,
                   "source_sha256": prepared.source_sha256,
                   "source_file_sha256": prepared.source_file_sha256,
                   "source_tree_sha256": prepared.source_tree_sha256,
                   "harness_sha256": prepared.harness_sha256,
                   "binary_sha256": prepared.binary_sha256,
                   "contract_sha256": prepared.contract_sha256,
                   "direction_plan_sha256":
                       bound.strategy._development_direction_plan[1]}
        data = (json.dumps(payload, sort_keys=True,
                           separators=(",", ":")) + "\n").encode()
        directory_fd = os.open(claim_dir, os.O_RDONLY | os.O_DIRECTORY |
                               os.O_NOFOLLOW)
        try:
            directory_stat = os.fstat(directory_fd)
            if ((directory_stat.st_dev, directory_stat.st_ino) !=
                    (claim_dir.stat().st_dev, claim_dir.stat().st_ino)):
                return "LIVE_HP_CLAIM_DIRECTORY_UNSAFE"
            try:
                claim_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                   os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            except FileExistsError:
                return "LIVE_HP_PAIR_ALREADY_CLAIMED"
            try:
                with os.fdopen(claim_fd, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(claim_fd)
            os.fsync(directory_fd)
            if ((directory_stat.st_dev, directory_stat.st_ino) !=
                    (claim_dir.stat().st_dev, claim_dir.stat().st_ino)):
                return "LIVE_HP_CLAIM_DIRECTORY_UNSAFE"
        finally:
            os.close(directory_fd)
    except (AttributeError, TypeError, ValueError, OSError):
        return "LIVE_HP_CLAIM_PERSISTENCE_FAILED"
    return None


def _live_pipelines_bound(bound: Any, analysis: Any,
                          assertion: Any) -> bool:
    """Both HP roles must debit the exact original campaign model gate."""
    from devtools.campaign_model_gate import CampaignLedgeredProvider
    from vulnerabilityanalysis.agents import AgentPipeline

    return (type(analysis) is AgentPipeline and
            type(assertion) is AgentPipeline and analysis is not assertion and
            type(analysis.provider) is CampaignLedgeredProvider and
            type(assertion.provider) is CampaignLedgeredProvider and
            analysis.provider.role == "function_analysis" and
            assertion.provider.role == "assertion_generator" and
            analysis.provider.gate is bound.model_gate and
            assertion.provider.gate is bound.model_gate and
            callable(getattr(analysis.provider, "close", None)) and
            callable(getattr(assertion.provider, "close", None)))


def _preflight(bound: Any, receipt: dict[str, Any]) -> str | None:
    """Validate the returned Worker, DB row, and shared physical owners."""
    try:
        identity = bound.identity
        task_id, run_id = identity.task_id, identity.run_id
        original = receipt["original_result"]
        if (receipt.get("kind") != "FBV2_PUBLIC_DEV_ORIGINAL_RESULT_V1" or
                receipt.get("task_id") != task_id or
                receipt.get("run_id") != run_id or
                receipt.get("execution_status") != "EXECUTED" or
                type(original) is not dict or
                original.get("task_type") != "pov" or
                original.get("fuzzer") != bound.executor.fuzzer or
                original.get("sanitizer") != "address" or
                bound.executor.task_id != task_id or
                bound.executor.repos is not bound.server.repos or
                bound.strategy.executor is not bound.executor or
                bound.admission.prepared.get("fuzzer_name") !=
                    bound.executor.fuzzer):
            return "WORKER_RUN_IDENTITY_UNPROVEN"
        worker_id = original.get("worker_id")
        if type(worker_id) is not str or not worker_id:
            return "WORKER_ID_MISSING"
        context = bound.executor._worker_context
        if (context.worker_id != worker_id or
                context.status != "completed"):
            return "WORKER_CONTEXT_NOT_COMPLETED"
        worker = bound.server.repos.workers.find_by_id(worker_id)
        if (worker is None or worker.task_id != task_id or
                worker.worker_id != worker_id or
                worker.fuzzer != bound.executor.fuzzer or
                worker.sanitizer != "address" or worker.task_type != "pov" or
                worker.status != WorkerStatus.COMPLETED or
                worker.finished_at is None or
                worker.result_summary != original):
            return "COMPLETED_WORKER_DB_RESULT_UNPROVEN"
        bound.recheck()
        model = bound.model_gate.snapshot()
        process, process_sha = bound.process_ledger.receipt_snapshot()
        if (bound.model_gate.campaign_id != run_id or
                model.get("campaign_id") != run_id or
                receipt.get("model_physical_calls") != model.get("physical") or
                receipt.get("process_receipt_sha256") != process_sha or
                receipt.get("process_stop_status") is not None or
                process.get("stop_status") is not None or
                "active" not in process or bool(process["active"]) or
                not _settled_model(bound.model_gate, model)):
            return "MODEL_OR_PROCESS_ACTIVITY_UNSETTLED"
        campaign = bound.global_campaign
        if (campaign.ledger is not bound.process_ledger or
                campaign.campaign.process_envelope.ledger is not
                    bound.process_ledger or
                campaign.reservation_key != f"GLOBAL_FUZZ:{task_id}:{run_id}"):
            return "GLOBAL_RUN_IDENTITY_UNPROVEN"
        global_result = campaign.final_result
        global_status = receipt.get("global_status")
        settled_run = (global_status == "RAN" and
                       type(global_result) is dict and
                       global_result.get("status") == "RAN" and
                       global_result.get("cleanup_complete") is True)
        settled_skip = (global_status == "SKIPPED_NO_SEED" and
                        type(global_result) is dict and
                        global_result.get("status") == "SKIPPED_NO_SEED" and
                        global_result.get("cleanup_complete") is True and
                        global_result.get("seed_count") == 0 and
                        global_result.get("physical_seconds") == 0.0 and
                        global_result.get("global_charge_relation") ==
                            "NO_PHYSICAL_GLOBAL_RUN" and
                        global_result.get("direction_plan_sha256") ==
                            bound.strategy._development_direction_plan[1])
        if not (settled_run or settled_skip):
            return "GLOBAL_SETTLEMENT_UNPROVEN"
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        return "WORKER_OR_ACCOUNT_EVIDENCE_UNAVAILABLE"
    return None


async def run_post_worker_hp(
    *, bound: Any, worker_receipt: dict[str, Any],
    analysis_pipeline_factory: Callable[[PreparedHPFunction], Any],
    assertion_pipeline_factory: Callable[[PreparedHPFunction], Any],
    max_items: int | None = None, provider_free_fixture: bool = False,
    physical_handoff_factory: Callable[[PreparedHPFunction, dict[str, Any]],
                                       dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Analyze completed SP-marked Function/Direction pairs after Worker exit.

    ``max_items`` is an explicit caller budget, not an inferred K policy.
    The optional physical handoff joins existing execution controls after
    both HP model providers close. Public live admission remains a separate
    signed boundary in the entrypoint and physical factory.
    """
    task_id = getattr(getattr(bound, "identity", None), "task_id", None)
    run_id = getattr(getattr(bound, "identity", None), "run_id", None)
    if (type(worker_receipt) is not dict or
            not callable(analysis_pipeline_factory) or
            not callable(assertion_pipeline_factory) or
            (max_items is not None and
             (type(max_items) is not int or max_items < 1)) or
            type(provider_free_fixture) is not bool or
            (physical_handoff_factory is not None and
             not callable(physical_handoff_factory))):
        return _blocked("HP_HANDOFF_ARGUMENT_INVALID", task_id, run_id)
    reason = _preflight(bound, worker_receipt)
    if reason is not None:
        return _blocked(reason, task_id, run_id)
    current_ids = _current_direction_ids(bound)
    if current_ids is None:
        return _blocked("CURRENT_DIRECTION_PLAN_UNPROVEN", task_id, run_id)
    repos = bound.server.repos
    fuzzer = bound.executor.fuzzer
    directions = {row.direction_id: row for row in
                  repos.directions.find_by_fuzzer(task_id, fuzzer)
                  if row.task_id == task_id and row.fuzzer == fuzzer and
                  row.direction_id in current_ids}
    if set(directions) != current_ids:
        return _blocked("CURRENT_DIRECTION_ROWS_MISSING", task_id, run_id)
    selected = sorted(
        ((function, directions[direction_id])
         for function in repos.functions.find_by_task(task_id)
         if function.task_id == task_id
         for direction_id in set(function.analyzed_by_directions)
         if direction_id in directions),
        key=lambda pair: (pair[1].direction_id, pair[0].function_id),
    )
    if max_items is not None:
        selected = selected[:max_items]
    rows: list[dict[str, Any]] = []
    for function, direction in selected:
        # A failed HP turn may taint the shared model gate. Stop before another
        # HP role; never let an HP-local failure rewrite the Worker result.
        try:
            bound.recheck()
            process = bound.process_ledger.snapshot()
            settled = (process.get("stop_status") is None and
                       "active" in process and not process["active"] and
                       _settled_model(bound.model_gate,
                                      bound.model_gate.snapshot()))
        except Exception:
            settled = False
        if not settled:
            return _partial_blocked("HP_SHARED_ACCOUNT_UNSETTLED", task_id,
                                    run_id, worker_receipt, rows)
        analysis = assertion = prepared = None
        close_error = False
        try:
            prepared = prepare_hp_function(
                function=function, direction=direction,
                qualification=bound.admission.qualification,
                fuzzer=fuzzer, sanitizer="address")
            if type(prepared) is dict:
                rows.append({"function_id": function.function_id,
                             "direction_id": direction.direction_id,
                             **prepared})
                continue
            if not provider_free_fixture:
                claim_error = _claim_live_hp_pair(
                    bound, worker_receipt["original_result"]["worker_id"],
                    prepared)
                if claim_error is not None:
                    return _partial_blocked(claim_error, task_id, run_id,
                                            worker_receipt, rows)
            analysis = analysis_pipeline_factory(prepared)
            assertion = assertion_pipeline_factory(prepared)
            if not provider_free_fixture and not _live_pipelines_bound(
                    bound, analysis, assertion):
                row = {"function_id": function.function_id,
                       "direction_id": direction.direction_id,
                       "status": "INCOMPLETE_HP_MODEL_GATE_MISMATCH",
                       "sp_global_effect": "UNCHANGED",
                       "security_gate_credit": "NOT_CREDITED"}
            else:
                row = await run_prepared_hp_analysis(
                    work=prepared, qualification=bound.admission.qualification,
                    analysis_pipeline=analysis, assertion_pipeline=assertion,
                    worker_id=worker_receipt["original_result"]["worker_id"],
                    provider_free_fixture=provider_free_fixture)
            rows.append(row)
        except Exception as exc:
            rows.append({"function_id": function.function_id,
                         "direction_id": direction.direction_id,
                         "status": "INCOMPLETE_HP_ERROR",
                         "error_type": type(exc).__name__,
                         "sp_global_effect": "UNCHANGED",
                         "security_gate_credit": "NOT_CREDITED"})
        finally:
            for pipeline in (assertion, analysis):
                provider = getattr(pipeline, "provider", None)
                close = getattr(provider, "close", None)
                if callable(close):
                    try:
                        await close()
                    except Exception:
                        close_error = True
                elif provider is not None and not provider_free_fixture:
                    close_error = True
        if close_error:
            return _partial_blocked("HP_PROVIDER_CLOSE_UNPROVEN", task_id,
                                    run_id, worker_receipt, rows)
        if (physical_handoff_factory is not None and
                type(prepared) is PreparedHPFunction and rows and
                rows[-1].get("status") == "ASSERTIONS_PROPOSED_UNVERIFIED"):
            before_keys = None

            def record_physical_account(state: Any, digest: Any) -> None:
                rows[-1]["physical_process_receipt_sha256"] = digest
                if type(state) is not dict:
                    rows[-1]["physical_account_status"] = "UNAVAILABLE"
                    return
                finished = state.get("finished")
                if type(finished) is list and before_keys is not None:
                    rows[-1]["physical_process_delta"] = [
                        {key: entry.get(key) for key in
                         ("key", "kind", "physical_seconds",
                          "cleanup_complete", "overrun")}
                        for entry in finished if type(entry) is dict and
                        entry.get("key") not in before_keys]
                rows[-1]["physical_process_stop_status"] = state.get("stop_status")
                active = state.get("active")
                rows[-1]["physical_process_active_count"] = (
                    len(active) if type(active) is dict else None)

            try:
                bound.recheck()
                process = bound.process_ledger.snapshot()
                if (process.get("stop_status") is not None or
                        process.get("active") or
                        not _settled_model(bound.model_gate,
                                           bound.model_gate.snapshot())):
                    return _partial_blocked("HP_SHARED_ACCOUNT_UNSETTLED",
                                            task_id, run_id, worker_receipt, rows)
                before_process, before_sha = bound.process_ledger.receipt_snapshot()
                before_finished = before_process.get("finished")
                if type(before_finished) is not list:
                    return _partial_blocked("HP_PHYSICAL_LEDGER_UNAVAILABLE",
                                            task_id, run_id, worker_receipt, rows)
                before_keys = {entry.get("key") for entry in before_finished
                               if type(entry) is dict}
                physical = physical_handoff_factory(prepared, rows[-1])
                after_process, after_sha = bound.process_ledger.receipt_snapshot()
                record_physical_account(after_process, after_sha)
            except Exception as exc:
                rows[-1]["physical_handoff"] = {
                    "status": "INCOMPLETE_HP_ASSERTION_HANDOFF",
                    "error_type": type(exc).__name__}
                if before_keys is not None:
                    try:
                        state, digest = bound.process_ledger.receipt_snapshot()
                        record_physical_account(state, digest)
                    except Exception as receipt_exc:
                        rows[-1]["physical_account_error_type"] = type(receipt_exc).__name__
                return _partial_blocked("HP_PHYSICAL_HANDOFF_INCOMPLETE",
                                        task_id, run_id, worker_receipt, rows)
            proposals = rows[-1].get("assertion_proposals")
            proposal_ids = {item.get("assertion_id") for item in
                            (proposals if type(proposals) is list else [])
                            if type(item) is dict and
                            item.get("status") == "PROPOSED"}
            guided = physical.get("guided_report") if type(physical) is dict else None
            assertion_id = physical.get("assertion_id") if type(physical) is dict else None
            selection = physical.get("assertion_selection") if type(physical) is dict else None
            selection_ok = provider_free_fixture
            if not provider_free_fixture and type(selection) is dict:
                not_run = selection.get("not_run")
                selection_ok = (
                    selection.get("policy") ==
                        "SOURCE_LINE_THEN_ASSERTION_ID_V1" and
                    selection.get("proposed_count") == len(proposal_ids) and
                    selection.get("selected_assertion_id") == assertion_id and
                    type(not_run) is list and
                    len(not_run) == len(proposal_ids) - 1 and
                    all(type(item) is dict and
                        set(item) == {"assertion_id", "status", "reason"} and
                        item.get("status") == "NOT_RUN" and
                        item.get("reason") == "BUDGET_NOT_SELECTED"
                        for item in not_run) and
                    {item["assertion_id"] for item in not_run} ==
                        proposal_ids - {assertion_id})
            prefix = f"{task_id}:{assertion_id}:{run_id}:"
            after_finished = (after_process.get("finished")
                              if type(after_process) is dict else None)
            new_finished = ([entry for entry in after_finished
                             if type(entry) is dict and
                             entry.get("key") not in before_keys]
                            if type(after_finished) is list else [])
            attributed_processes = bool(new_finished) and all(
                type(entry) is dict and
                type(entry.get("key")) is str and
                entry["key"].startswith(prefix) and
                entry.get("kind") in {"AUX_PROCESS", "HP_FUZZ"} and
                entry.get("cleanup_complete") is True and
                entry.get("overrun") is False
                for entry in new_finished)
            if attributed_processes and not provider_free_fixture:
                numeric = lambda value: type(value) in (int, float) and (
                    math.isfinite(value) and value >= 0)
                before_wall = before_process.get("wall_spent_seconds")
                before_fuzz = before_process.get("fuzz_spent_seconds")
                after_wall = after_process.get("wall_spent_seconds")
                after_fuzz = after_process.get("fuzz_spent_seconds")
                attributed_processes = (all(numeric(value) for value in (
                    before_wall, before_fuzz, after_wall, after_fuzz)) and
                    all(numeric(entry.get("physical_seconds"))
                        for entry in new_finished))
                if attributed_processes:
                    attributed_processes = (
                        math.isclose(after_wall - before_wall, math.fsum(
                            entry["physical_seconds"] for entry in new_finished),
                            abs_tol=1e-9, rel_tol=0) and
                        math.isclose(after_fuzz - before_fuzz, math.fsum(
                            entry["physical_seconds"] for entry in new_finished
                            if entry["kind"] == "HP_FUZZ"),
                            abs_tol=1e-9, rel_tol=0))
            guided_process = any(
                type(entry.get("key")) is str and
                entry["key"].startswith(prefix) and
                entry["key"].endswith(":guided.initial_campaign") and
                entry.get("kind") == "HP_FUZZ" and
                entry.get("cleanup_complete") is True and
                entry.get("overrun") is False
                for entry in new_finished)
            if (type(physical) is not dict or
                    physical.get("status") != "HP_ASSERTION_HANDOFF_COMPLETE" or
                    physical.get("function_id") != prepared.function_id or
                    physical.get("direction_id") != prepared.direction_id or
                    assertion_id not in proposal_ids or not selection_ok or
                    physical.get("source_sha256") != prepared.source_sha256 or
                    physical.get("seed_sha256") !=
                        bound.admission.qualification.normal_seed_sha256 or
                    physical.get("guided_status") not in
                        {"RAN", "ASSERTION_WITNESS_OBSERVED"} or
                    type(guided) is not dict or
                    guided.get("status") != physical.get("guided_status") or
                    guided.get("assertion_id") != assertion_id or
                    type(guided.get("fuzzer_run_count")) is not int or
                    guided["fuzzer_run_count"] < 1 or
                    not guided_process or not attributed_processes or
                    before_sha == after_sha or
                    type(after_process) is not dict or
                    after_process.get("stop_status") is not None or
                    after_process.get("active") or
                    physical.get("sp_global_effect") != "UNCHANGED" or
                    physical.get("security_gate_credit") != "NOT_CREDITED" or
                    physical.get("discovery_credit") != "NOT_CREDITED"):
                rows[-1]["physical_handoff"] = physical
                return _partial_blocked("HP_PHYSICAL_HANDOFF_INCOMPLETE",
                                        task_id, run_id, worker_receipt, rows)
            rows[-1]["physical_handoff"] = physical
        if (not provider_free_fixture and rows and
                rows[-1].get("status") ==
                    "INCOMPLETE_HP_MODEL_GATE_MISMATCH"):
            return _partial_blocked("HP_MODEL_GATE_MISMATCH", task_id,
                                    run_id, worker_receipt, rows)
    # The last HP item may itself leave an uncertain model turn. There is no
    # following iteration to detect that, so settle-check once more here.
    try:
        process = bound.process_ledger.snapshot()
        account_settled = (process.get("stop_status") is None and
                           "active" in process and not process["active"] and
                           _settled_model(bound.model_gate,
                                          bound.model_gate.snapshot()))
    except Exception:
        account_settled = False
    if not account_settled:
        return _partial_blocked("HP_SHARED_ACCOUNT_UNSETTLED", task_id,
                                run_id, worker_receipt, rows)
    proposed_rows = [row for row in rows if
                     row.get("status") == "ASSERTIONS_PROPOSED_UNVERIFIED"]
    if physical_handoff_factory is None:
        physical_status = "NOT_REQUESTED"
    elif not proposed_rows:
        physical_status = "NOT_RUN_NO_PROPOSAL"
    elif all(type(row.get("physical_handoff")) is dict and
             row["physical_handoff"].get("status") ==
                 "HP_ASSERTION_HANDOFF_COMPLETE" for row in proposed_rows):
        physical_status = "COMPLETE"
    else:
        physical_status = "INCOMPLETE"
    return {"status": "HP_POST_WORKER_COMPLETE", "task_id": task_id,
            "run_id": run_id, "selection_basis":
                "PINNED_CURRENT_DIRECTION_PLAN_AND_ANALYZED_MARKER",
            "analysis_status": "COMPLETE",
            "physical_execution_status": physical_status,
            "selected_count": len(selected), "rows": rows,
            "original_result": worker_receipt["original_result"],
            "original_execution_status": worker_receipt.get("execution_status"),
            "original_global_status": worker_receipt.get("global_status"),
            "sp_global_effect": "UNCHANGED",
            "security_gate_credit": "NOT_CREDITED"}
