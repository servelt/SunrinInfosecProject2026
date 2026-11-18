"""A model error is not a result: PoV, invariant recording and repair are retried, not settled."""

from __future__ import annotations

import asyncio
import time
import types
from pathlib import Path

from fbaugur.config import RunConfig
from fbaugur.orchestrator import Run, Worker
from fbaugur.store import Store


def _run(tmp_path: Path) -> Run:
    run = object.__new__(Run)
    run.store = Store(tmp_path / "state.db")
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    run.cfg.sp_fuzz_seconds = 0
    run.emit = lambda message: None
    run.stop = asyncio.Event()
    run.out_of_time = run.stop.is_set
    run.run_dir = tmp_path
    run._window = lambda location: ""
    return run


def _worker() -> Worker:
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id, worker.sanitizer = "w", "h", "address"
    return worker


def _failing_agent(run: Run, calls: list):
    async def agent(role, *a, **k):
        calls.append(role)
        return types.SimpleNamespace(ok=False, error="model_error: stream disconnected")
    return agent


def test_a_pov_turn_that_ran_no_input_is_retried_then_reported_as_not_attempted(tmp_path: Path):
    run, calls = _run(tmp_path), []
    run._agent = _failing_agent(run, calls)
    run.store.insert("sps", {"sp_id": "sp1", "worker_id": "w", "status": "generating_pov", "created_at": time.time()})
    sp = run.store.row("SELECT * FROM sps WHERE sp_id='sp1'")
    asyncio.run(run._pov_one(_worker(), sp))
    assert run.store.scalar("SELECT status FROM sps WHERE sp_id='sp1'") == "pending_pov"
    asyncio.run(run._pov_one(_worker(), run.store.row("SELECT * FROM sps WHERE sp_id='sp1'")))
    assert run.store.scalar("SELECT status FROM sps WHERE sp_id='sp1'") == "pov_not_attempted"


def test_a_pov_that_ran_inputs_and_did_not_crash_is_a_failed_pov(tmp_path: Path):
    run = _run(tmp_path)

    async def agent(role, *a, **k):
        run.store.insert("povs", {"pov_id": "p1", "sp_id": "sp1", "worker_id": "w", "crashed": 0})
        return types.SimpleNamespace(ok=True, error=None)

    run._agent = agent
    run.store.insert("sps", {"sp_id": "sp1", "worker_id": "w", "status": "generating_pov", "created_at": time.time()})
    asyncio.run(run._pov_one(_worker(), run.store.row("SELECT * FROM sps WHERE sp_id='sp1'")))
    assert run.store.scalar("SELECT status FROM sps WHERE sp_id='sp1'") == "pov_failed"


def test_a_failed_recorder_turn_does_not_use_up_the_candidate(tmp_path: Path):
    run, calls = _run(tmp_path), []
    run._agent = _failing_agent(run, calls)
    run.sp_done = asyncio.Event()
    run.sp_done.set()
    run.store.insert("sps", {"sp_id": "sp1", "worker_id": "w", "status": "rejected", "safety_reason": "n <= cap",
                             "safety_location": "a.c:3", "created_at": time.time()})
    asyncio.run(asyncio.wait_for(run.invariant_recorder(_worker()), timeout=10))
    assert calls == ["invariant_recorder"] * run.cfg.recorder_attempts      # asked again, then given up
    assert run.store.scalar("SELECT COUNT(*) FROM events WHERE kind='recorder_failed'") == 1


def test_a_failed_repair_turn_returns_the_invariant_to_its_queue(tmp_path: Path):
    run, calls = _run(tmp_path), []
    run._agent = _failing_agent(run, calls)
    run.store.insert("invariants", {"harness_id": "h", "file": "a.c", "line": 3, "expression": "x",
                                    "status": "repairing", "repairs": 0, "updated_at": time.time()})
    target = run.store.row("SELECT * FROM invariants WHERE phi_num=1")
    asyncio.run(run._refine_one(_worker(), target))
    row = run.store.row("SELECT status, repairs FROM invariants WHERE phi_num=1")
    assert row == {"status": "needs_repair", "repairs": 1}


def _triage_setup(tmp_path: Path, agent):
    run = _run(tmp_path)
    run.cfg.triage_attempts = 2
    run.store.insert("invariants", {"harness_id": "h", "file": "src/a.c", "line": 3, "expression": "n <= cap",
                                    "status": "triaging", "updated_at": time.time()})
    (tmp_path / "in").write_bytes(b"x")
    run.store.insert("violations", {"violation_id": "v1", "phi_num": 1, "harness_id": "h", "worker_id": "w",
                                    "input_path": str(tmp_path / "in"), "status": "triaging", "created_at": time.time()})
    run.harness = lambda worker: types.SimpleNamespace(binary=tmp_path / "plain")
    run._agent = agent
    import fbaugur.orchestrator as orchestrator
    return run, orchestrator


def test_a_triage_turn_without_a_verdict_is_retried_then_kept_apart(tmp_path: Path, monkeypatch):
    # Follow-up review item 4: a model error must not settle the violation as UNDECIDED.
    run, orchestrator = _triage_setup(tmp_path, None)
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: types.SimpleNamespace(summary=lambda: "no fault"))
    run._agent = _failing_agent(run, [])
    asyncio.run(run._triage_one(_worker(), run.store.row("SELECT * FROM violations WHERE violation_id='v1'")))
    row = run.store.row("SELECT * FROM violations WHERE violation_id='v1'")
    assert row["status"] == "pending" and row["verdict"] is None and row["triage_attempts"] == 1
    asyncio.run(run._triage_one(_worker(), row))
    row = run.store.row("SELECT * FROM violations WHERE violation_id='v1'")
    assert row["status"] == "triage_failed" and row["verdict"] is None
    assert "stream disconnected" in row["notes"] and "no fault" in row["notes"]


def test_an_explicit_undecided_verdict_is_a_decision(tmp_path: Path, monkeypatch):
    async def undecided(role, *a, **k):
        run.store.update("violations", "violation_id", "v1", {"status": "undecided", "verdict": "UNDECIDED"})
        return types.SimpleNamespace(ok=True, error=None)

    run, orchestrator = _triage_setup(tmp_path, None)
    run._agent = undecided
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: types.SimpleNamespace(summary=lambda: ""))
    asyncio.run(run._triage_one(_worker(), run.store.row("SELECT * FROM violations WHERE violation_id='v1'")))
    row = run.store.row("SELECT * FROM violations WHERE violation_id='v1'")
    assert row["verdict"] == "UNDECIDED" and not row["triage_attempts"]
