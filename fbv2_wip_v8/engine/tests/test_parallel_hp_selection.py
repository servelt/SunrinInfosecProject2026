"""HP selection must remain stable while SP marks its own progress."""

import asyncio
import hashlib
import json
import threading
from types import SimpleNamespace

import pytest

from devtools.parallel_hp_selection import (
    claim_parallel_hp_execution, freeze_parallel_hp_selection,
    verify_parallel_hp_execution_claim)
from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


def _fixture(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    task_id = "a" * 24
    direction = Direction(direction_id="b" * 24, task_id=task_id,
                          fuzzer="target_fuzzer", core_functions=["parse"],
                          entry_functions=["entry"])
    functions = [
        Function(function_id="parse-id", task_id=task_id, name="parse",
                 file_path="src/parse.c", start_line=10, end_line=20),
        Function(function_id="entry-id", task_id=task_id, name="entry",
                 file_path="src/entry.c", start_line=1, end_line=9),
    ]
    args = dict(run_dir=run_dir, task_id=task_id, run_id="c" * 24,
                fuzzer="target_fuzzer", spec_sha256="1" * 64,
                direction_plan_sha256="2" * 64,
                function_catalog_sha256="3" * 64,
                directions=[direction], functions=functions)
    return args, direction, functions


def test_selection_survives_sp_progress_but_rejects_catalog_drift(tmp_path):
    args, direction, functions = _fixture(tmp_path)
    selected, digest = freeze_parallel_hp_selection(**args)
    assert selected == (functions[0], direction)
    receipt_path = args["run_dir"] / "HP_PARALLEL_SELECTION.json"
    receipt = json.loads(receipt_path.read_bytes())
    assert receipt["selected_pair"] == ["parse-id", direction.direction_id]
    assert receipt["selection_status"] == "SELECTED"
    assert receipt["model_calls"] == receipt["target_calls"] == 0
    assert hashlib.sha256(receipt_path.read_bytes()).hexdigest() == digest

    # The SP track updates this marker while HP is active. It is not part of
    # the immutable selection identity.
    functions[0].analyzed_by_directions.append(direction.direction_id)
    assert freeze_parallel_hp_selection(**args)[1] == digest

    functions[0].start_line += 1
    with pytest.raises(ValueError, match="PARALLEL_HP_SELECTION_CHANGED"):
        freeze_parallel_hp_selection(**args)


def test_selection_has_no_sp_marker_or_missing_function_dependency(tmp_path):
    args, direction, functions = _fixture(tmp_path)
    direction.core_functions = ["missing"]
    direction.entry_functions = []
    selected, _ = freeze_parallel_hp_selection(**args)
    assert selected is None
    receipt = json.loads((args["run_dir"] / "HP_PARALLEL_SELECTION.json").read_text())
    assert receipt["selected_pair"] is None
    assert receipt["selection_status"] == "HP_NO_ELIGIBLE_FUNCTION"
    # A later SP update cannot turn this already frozen no-opportunity result
    # into a new HP opportunity within the same run.
    direction.core_functions = [functions[0].name]
    with pytest.raises(ValueError, match="PARALLEL_HP_SELECTION_CHANGED"):
        freeze_parallel_hp_selection(**args)


def test_selection_rejects_duplicate_or_cross_task_catalog(tmp_path):
    args, _, functions = _fixture(tmp_path)
    args["functions"] = [functions[0], functions[0]]
    with pytest.raises(ValueError, match="PARALLEL_HP_CATALOG_INVALID"):
        freeze_parallel_hp_selection(**args)
    args["functions"] = functions
    functions[0].task_id = "d" * 24
    with pytest.raises(ValueError, match="PARALLEL_HP_CATALOG_INVALID"):
        freeze_parallel_hp_selection(**args)


def test_selection_rejects_non_direction_before_reading_members(tmp_path):
    args, _, _ = _fixture(tmp_path)
    args["directions"] = [None]
    with pytest.raises(ValueError, match="PARALLEL_HP_CATALOG_INVALID"):
        freeze_parallel_hp_selection(**args)


def test_unselected_fuzzer_catalog_sentinel_does_not_block_hp(tmp_path):
    args, direction, functions = _fixture(tmp_path)
    sentinel = Function(function_id="fuzzer-id", task_id=args["task_id"],
                        name=args["fuzzer"], file_path="test/fuzzers/target.c",
                        start_line=0, end_line=0)
    args["functions"] = [*functions, sentinel]
    selected, digest = freeze_parallel_hp_selection(**args)
    assert selected == (functions[0], direction)
    receipt = json.loads((args["run_dir"] / "HP_PARALLEL_SELECTION.json").read_text())
    assert receipt["selected_pair"] == [functions[0].function_id,
                                        direction.direction_id]
    assert receipt["catalog_metadata_sha256"]
    assert digest

    direction.core_functions = [sentinel.name]
    with pytest.raises(ValueError, match="PARALLEL_HP_CATALOG_INVALID"):
        freeze_parallel_hp_selection(**args)


def test_non_fuzzer_zero_line_catalog_row_remains_invalid(tmp_path):
    args, _, functions = _fixture(tmp_path)
    functions[1].start_line = functions[1].end_line = 0
    with pytest.raises(ValueError, match="PARALLEL_HP_CATALOG_INVALID"):
        freeze_parallel_hp_selection(**args)


def test_selection_rejects_weakened_receipt_permissions(tmp_path):
    args, _, _ = _fixture(tmp_path)
    freeze_parallel_hp_selection(**args)
    (args["run_dir"] / "HP_PARALLEL_SELECTION.json").chmod(0o644)
    with pytest.raises(ValueError, match="PARALLEL_HP_SELECTION_CHANGED"):
        freeze_parallel_hp_selection(**args)


def test_parallel_hp_execution_claim_is_once_only_and_binds_selection(tmp_path):
    args, _, _ = _fixture(tmp_path)
    _, selection_sha = freeze_parallel_hp_selection(**args)
    claim_args = dict(run_dir=args["run_dir"], task_id=args["task_id"],
                      run_id=args["run_id"], spec_sha256=args["spec_sha256"],
                      selection_receipt_sha256=selection_sha)
    with pytest.raises(ValueError, match="PARALLEL_HP_SELECTION_CHANGED"):
        claim_parallel_hp_execution(**{
            **claim_args, "selection_receipt_sha256": "0" * 64})
    claim_sha = claim_parallel_hp_execution(**claim_args)
    claim_path = args["run_dir"] / "HP_PARALLEL_RUN_CLAIM.json"
    claim = json.loads(claim_path.read_bytes())
    assert claim["selection_receipt_sha256"] == selection_sha
    assert claim["selected_pair"] == ["parse-id", "b" * 24]
    assert hashlib.sha256(claim_path.read_bytes()).hexdigest() == claim_sha
    verify_args = dict(**claim_args, execution_claim_sha256=claim_sha,
                       function_id="parse-id", direction_id="b" * 24,
                       direction_plan_sha256=args["direction_plan_sha256"],
                       function_catalog_sha256=args["function_catalog_sha256"])
    assert verify_parallel_hp_execution_claim(**verify_args)
    assert not verify_parallel_hp_execution_claim(
        **{**verify_args, "function_id": "other"})
    with pytest.raises(ValueError, match="PARALLEL_HP_ALREADY_CLAIMED"):
        claim_parallel_hp_execution(**claim_args)

    claim_path.write_bytes(claim_path.read_bytes() + b" ")
    assert not verify_parallel_hp_execution_claim(**verify_args)


def test_parallel_hp_no_opportunity_cannot_claim(tmp_path):
    args, direction, _ = _fixture(tmp_path)
    direction.core_functions = []
    direction.entry_functions = []
    _, selection_sha = freeze_parallel_hp_selection(**args)
    with pytest.raises(ValueError, match="PARALLEL_HP_SELECTION_INVALID"):
        claim_parallel_hp_execution(
            run_dir=args["run_dir"], task_id=args["task_id"],
            run_id=args["run_id"], spec_sha256=args["spec_sha256"],
            selection_receipt_sha256=selection_sha)


def _strategy_with_parallel_factory(factory, sp_pipeline):
    strategy = object.__new__(POVFullscanStrategy)
    strategy.executor = SimpleNamespace(
        require_original_global_bridge=False,
        parallel_hp_async_factory=factory)
    strategy.llm_client_factory = object()
    strategy.log_info = lambda _message: None

    async def planning():
        return [SimpleNamespace(direction_id="planned-direction")]

    strategy._run_direction_planning_async = planning
    strategy._run_v2_pipeline_with_fuzzer_init = sp_pipeline
    return strategy


def test_actual_sp_pipeline_seam_overlaps_hp_on_main_loop():
    sp_entered = asyncio.Event()
    hp_entered = asyncio.Event()
    threads = []

    async def sp_pipeline(directions):
        assert directions[0].direction_id == "planned-direction"
        threads.append(threading.current_thread())
        sp_entered.set()
        await asyncio.wait_for(hp_entered.wait(), timeout=2)
        return "sp-finished"

    async def hp_factory(strategy, directions):
        assert directions[0].direction_id == "planned-direction"
        threads.append(threading.current_thread())
        hp_entered.set()
        await asyncio.wait_for(sp_entered.wait(), timeout=2)
        return {"status": "HP_ANALYSIS_FINISHED_UNVERIFIED"}

    strategy = _strategy_with_parallel_factory(hp_factory, sp_pipeline)
    assert asyncio.run(strategy._run_full_pipeline()) == "sp-finished"
    assert strategy._parallel_hp_result == {
        "status": "HP_ANALYSIS_FINISHED_UNVERIFIED"}
    assert threads == [threading.main_thread(), threading.main_thread()]


def test_sp_failure_waits_for_inflight_hp_settlement():
    hp_entered = asyncio.Event()
    hp_settled = []

    async def sp_pipeline(_directions):
        await asyncio.wait_for(hp_entered.wait(), timeout=2)
        raise RuntimeError("sp failed")

    async def hp_factory(_strategy, _directions):
        hp_entered.set()
        await asyncio.sleep(0)
        hp_settled.append(True)
        return {"status": "HP_ANALYSIS_FINISHED_UNVERIFIED"}

    strategy = _strategy_with_parallel_factory(hp_factory, sp_pipeline)
    with pytest.raises(RuntimeError, match="sp failed"):
        asyncio.run(strategy._run_full_pipeline())
    assert hp_settled == [True]
    assert strategy._parallel_hp_result == {
        "status": "HP_ANALYSIS_FINISHED_UNVERIFIED"}


def test_hp_analysis_error_preserves_completed_sp_stats():
    async def sp_pipeline(_directions):
        return "sp-finished"

    async def hp_factory(_strategy, _directions):
        raise ValueError("hp analysis failed")

    strategy = _strategy_with_parallel_factory(hp_factory, sp_pipeline)
    with pytest.raises(ValueError, match="hp analysis failed"):
        asyncio.run(strategy._run_full_pipeline())
    assert strategy._parallel_sp_stats == "sp-finished"
    assert strategy._parallel_hp_result["status"] == (
        "HP_PARALLEL_ANALYSIS_INCOMPLETE")
    assert strategy._parallel_hp_result["security_gate_credit"] == "NOT_CREDITED"


def test_worker_result_carries_hp_analysis_without_security_credit():
    strategy = object.__new__(POVFullscanStrategy)
    strategy.executor = SimpleNamespace(parallel_hp_async_factory=object())
    strategy.fuzzer = "target_fuzzer"
    strategy.task_id = "a" * 24
    strategy.repos = SimpleNamespace(suspicious_points=SimpleNamespace(
        find_by_task=lambda _task_id: []))
    strategy.log_info = lambda _message: None
    strategy.log_error = lambda _message: None
    strategy._gate_verified_stop_requested = lambda: False
    strategy._sort_by_priority = lambda points: points
    strategy._save_results = lambda _points: None
    strategy._direction_seed_phase = None
    strategy._development_sp_scope = None

    async def completed_sp():
        return SimpleNamespace(sp_verified=0, pov_generated=0,
                               pov_pending_validation=0)

    strategy._run_full_pipeline = completed_sp
    strategy._parallel_hp_result = {
        "kind": "FBV2_PARALLEL_HP_ANALYSIS_RESULT_V1",
        "status": "HP_PARALLEL_ANALYSIS_COMPLETE",
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    result = strategy.execute()
    assert result["parallel_hp_analysis"] == {
        "status": "HP_PARALLEL_ANALYSIS_COMPLETE",
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    assert result["gate_verified"] == 0

    strategy._parallel_hp_result["security_gate_credit"] = "VERIFIED"
    with pytest.raises(RuntimeError, match="parallel HP analysis result is invalid"):
        strategy.execute()

    strategy._parallel_hp_result["security_gate_credit"] = "NOT_CREDITED"
    strategy._parallel_hp_result["status"] = ["HP_PARALLEL_ANALYSIS_COMPLETE"]
    with pytest.raises(RuntimeError, match="parallel HP analysis result is invalid"):
        strategy.execute()
