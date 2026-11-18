"""An SP generator turn counts only with an outcome on record.

Seen on a run: the model wrote that a function had a stack overflow and that it was "reporting it",
then ended the turn without calling create_suspicious_point; the function was settled as analysed
with no SP.  No model or target is run here: a fake agent stands in for the model.
"""

from __future__ import annotations

import asyncio
import time
import types
from pathlib import Path

from fbaugur.agent import AgentResult
from fbaugur.config import RunConfig
from fbaugur.orchestrator import NO_SP_MARKER, Run, Worker
from fbaugur.store import Store


def _run(tmp_path: Path, replies: list) -> tuple[Run, list[str]]:
    run = object.__new__(Run)
    run.store = Store(tmp_path / "state.db")
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    run.emit = lambda message: None
    messages: list[str] = []

    async def agent(role, harness_id, message, **binding):
        messages.append(message)
        run_id = f"run-{len(messages)}"
        text, creates = replies.pop(0)
        for _ in range(creates):
            run.store.insert("sps", {"sp_id": f"sp-{run_id}", "worker_id": "w", "status": "pending_verify",
                                     "origin": "generator", "origin_ref": run_id, "created_at": time.time()})
        return AgentResult(run_id, role, "completed", text, 1, creates)

    run._agent = agent
    return run, messages


def _turn(run: Run):
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id, worker.sanitizer = "w", "h", "address"
    return asyncio.run(run._sp_generation_turn(worker, {"direction_id": "d", "function_id": "fn-1"}, "f", "analyse f"))


def test_a_described_issue_without_the_call_gets_one_follow_up_that_records_it(tmp_path: Path):
    run, messages = _run(tmp_path, [("f has a stack overflow; I'm reporting this as a suspicious point.", 0),
                                    ("recorded", 1)])
    assert _turn(run) == ("analysed", None)
    assert len(messages) == 2 and "stack overflow" in messages[1]          # the follow-up carries the reply
    assert run.store.scalar("SELECT COUNT(*) FROM sps") == 1


def test_a_declared_safe_function_costs_no_follow_up(tmp_path: Path):
    run, messages = _run(tmp_path, [(f"bounded copy.\n{NO_SP_MARKER}", 0)])
    assert _turn(run) == ("analysed", None) and len(messages) == 1


def test_a_recorded_sp_costs_no_follow_up(tmp_path: Path):
    run, messages = _run(tmp_path, [("one issue", 1)])
    assert _turn(run) == ("analysed", None) and len(messages) == 1


def test_two_replies_without_an_outcome_fail_the_attempt(tmp_path: Path):
    run, messages = _run(tmp_path, [("looks risky", 0), ("still risky", 0)])
    status, error = _turn(run)
    assert status == "failed" and "without recording" in error and len(messages) == 2


def test_a_model_error_is_a_failed_attempt_without_follow_up(tmp_path: Path):
    run, messages = _run(tmp_path, [])

    async def broken(*a, **k):
        messages.append("x")
        return AgentResult("run-1", "sp_generator", "error", "", 0, 0, "stream disconnected")

    run._agent = broken
    assert _turn(run)[0] == "failed" and len(messages) == 1
