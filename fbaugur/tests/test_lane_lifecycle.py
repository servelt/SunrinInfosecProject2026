"""A consumer lane ends only after every lane that can still fill its queue has ended.

Each test runs a real consumer lane next to a producer lane that puts one item into the queue
late, after the consumer has already seen it empty with SP generation finished (sp_done set).
Deterministic: the producer is a coroutine with a fixed delay, the consumer's work is a stub,
and asyncio.wait_for bounds every test.  No model, target or fuzzer is run.
"""

from __future__ import annotations

import asyncio
import time
import types
from pathlib import Path

import pytest

import fbaugur.orchestrator as orchestrator
from fbaugur.config import RunConfig
from fbaugur.orchestrator import Run, Worker
from fbaugur.store import Store


@pytest.fixture(autouse=True)
def fast_idle(monkeypatch):
    monkeypatch.setattr(orchestrator, "IDLE", 0.005)


def _run(tmp_path: Path, *, stopped: bool = False) -> Run:
    run = object.__new__(Run)
    run.store = Store(tmp_path / "state.db")
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    run.cfg.rebuild_min_interval_seconds = 0
    run.run_dir = tmp_path
    (tmp_path / "logs").mkdir(exist_ok=True)
    run.sp_done = asyncio.Event()
    run.sp_done.set()
    run.stop = asyncio.Event()
    if stopped:
        run.stop.set()
    run.out_of_time = run.stop.is_set
    run.draining = False
    run.emit = lambda message: None
    run._build_lock = asyncio.Lock()
    run._last_build = 0.0
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id, worker.sanitizer = "w", "h", "address"
    run.workers = [worker]
    run.worker = worker
    return run


async def _late(delay: float, action) -> None:
    await asyncio.sleep(delay)
    action()


async def _late_in_hand(run: Run, kind: str, delay: float, action) -> None:
    """A lane of the invariant/PoV cycle produces while it holds an item (an agent call)."""
    with run._working(run.worker, kind):
        await asyncio.sleep(delay)
        action()


async def _together(run: Run, consumer, producer_name: str, producer) -> None:
    """Start the producer lane first (it is running), then the consumer; both must end."""
    p = asyncio.create_task(run.lane(producer_name, producer))
    await asyncio.sleep(0)
    c = asyncio.create_task(run.lane("consumer:w", consumer))
    await asyncio.wait_for(asyncio.gather(p, c), timeout=3)


def test_build_lane_waits_for_the_recorder(tmp_path: Path):
    run = _run(tmp_path)
    built: list[int] = []

    async def rebuild(worker):                     # like _rebuild: the build is recorded with its phis
        phis = [row["phi_num"] for row in run.store.rows("SELECT phi_num FROM invariants WHERE status='pending_build'")]
        built.extend(phis)
        run.store.conn.execute("UPDATE invariants SET status='built' WHERE status='pending_build'")
        run.store.insert("builds", {"harness_id": worker.harness_id, "version": len(built), "status": "ok",
                                    "phis": phis})

    run._rebuild = rebuild
    record = lambda: run.store.insert("invariants", {"harness_id": "h", "status": "pending_build",
                                                     "updated_at": time.time()})
    asyncio.run(_together(run, run.build_coordinator(run.worker), "phi-record:w",
                          _late_in_hand(run, "phi-record", 0.05, record)))
    assert built == [1]


def test_triage_lane_waits_for_the_fuzzer(tmp_path: Path):
    run = _run(tmp_path)
    triaged: list[str] = []

    async def triage_one(worker, violation):
        triaged.append(violation["violation_id"])
        run.store.update("violations", "violation_id", violation["violation_id"], {"status": "triaged"})

    run._triage_one = triage_one
    found = lambda: run.store.insert("violations", {"violation_id": "v1", "phi_num": 1, "harness_id": "h",
                                                    "status": "pending", "created_at": time.time()})
    asyncio.run(_together(run, run.triage_agent(run.worker), "fuzz:w", _late(0.05, found)))
    assert triaged == ["v1"]


def test_pov_lane_waits_for_triage(tmp_path: Path):
    run = _run(tmp_path)
    tried: list[str] = []

    async def pov_one(worker, sp):
        tried.append(sp["sp_id"])
        run.store.update("sps", "sp_id", sp["sp_id"], {"status": "pov_failed"})

    run._pov_one = pov_one
    lead = lambda: run.store.insert("sps", {"sp_id": "sp-lead", "worker_id": "w", "status": "pending_pov",
                                            "is_important": 1, "score": 0.6, "created_at": time.time()})
    asyncio.run(_together(run, run.pov_agent(run.worker, 0), "phi-triage:w",
                          _late_in_hand(run, "phi-triage", 0.05, lead)))
    assert tried == ["sp-lead"]


def test_refine_lane_waits_for_builds(tmp_path: Path):
    run = _run(tmp_path)
    repaired: list[int] = []

    async def refine_one(worker, target):
        repaired.append(target["phi_num"])
        run.store.update("invariants", "phi_num", target["phi_num"], {"status": "withdrawn"})

    run._refine_one = refine_one
    broken = lambda: run.store.insert("invariants", {"harness_id": "h", "status": "needs_repair",
                                                     "updated_at": time.time()})
    asyncio.run(_together(run, run.refine_agent(run.worker), "phi-build:w",
                          _late_in_hand(run, "phi-build", 0.05, broken)))
    assert repaired == [1]


def test_consumers_still_end_when_no_producer_runs(tmp_path: Path):
    run = _run(tmp_path)

    async def all_consumers():
        await asyncio.wait_for(asyncio.gather(
            run.lane("phi-build:w", run.build_coordinator(run.worker)),
            run.lane("phi-triage:w", run.triage_agent(run.worker)),
            run.lane("phi-refine:w", run.refine_agent(run.worker)),
            run.lane("pov0:w", run.pov_agent(run.worker, 0))), timeout=3)

    asyncio.run(all_consumers())


def test_final_drain_settles_violations_new_points_builds_and_crashes(tmp_path: Path):
    run = _run(tmp_path, stopped=True)
    run.cfg.final_drain_minutes = 1
    done: list[str] = []
    now = time.time()
    run.store.insert("violations", {"violation_id": "v1", "phi_num": 1, "harness_id": "h", "status": "pending",
                                    "created_at": now})
    run.store.insert("invariants", {"harness_id": "h", "status": "pending_build", "updated_at": now})
    run.store.insert("crashes", {"crash_id": "c1", "worker_id": "w", "status": "pending", "created_at": now})

    async def triage_one(worker, violation):        # REAL_ISSUE: a new point to try, during the drain
        done.append("triage")
        run.store.update("violations", "violation_id", violation["violation_id"], {"status": "triaged"})
        run.store.insert("sps", {"sp_id": "sp-lead", "worker_id": "w", "status": "pending_pov",
                                 "is_important": 1, "score": 0.6, "created_at": time.time()})

    async def rebuild(worker):
        done.append("build")
        run.store.conn.execute("UPDATE invariants SET status='built' WHERE status='pending_build'")
        run.store.insert("builds", {"harness_id": worker.harness_id, "version": 1, "status": "ok", "phis": [1]})

    async def pov_one(worker, sp):
        done.append("pov")
        run.store.update("sps", "sp_id", sp["sp_id"], {"status": "pov_failed"})

    async def confirm(crash):
        done.append("confirm")
        run.store.update("crashes", "crash_id", crash["crash_id"], {"status": "confirmed"})

    run._triage_one, run._rebuild, run._pov_one, run._confirm = triage_one, rebuild, pov_one, confirm
    asyncio.run(asyncio.wait_for(run.final_drain(), timeout=3))
    assert done == ["triage", "build", "pov", "confirm"]
    assert run.store.scalar("SELECT status FROM sps WHERE sp_id='sp-lead'") == "pov_failed"


def test_failed_sp_analysis_is_retried_and_then_reported_as_not_analysed(tmp_path: Path):
    from fbaugur.project import FunctionInfo
    run = _run(tmp_path)
    run.sp_done = asyncio.Event()
    run.cfg.sp_generation_attempts = 3
    now = time.time()
    for name in ("flaky", "refused"):
        run.store.insert("pool", {"worker_id": "w", "direction_id": "d", "function_name": name,
                                  "function_id": f"fn-{name}", "pool": "core", "phase": 1, "status": "pending",
                                  "updated_at": now})
    run.project = types.SimpleNamespace(
        function=lambda name, fid="": FunctionInfo(fid, name, "src/x.c", 1, 2, "int f(void){return 0;}", ""),
        callers={}, callees={})
    calls: list[str] = []

    async def agent(role, harness_id, message, *, subject="", **_):
        calls.append(subject)
        ok = subject == "flaky" and calls.count("flaky") == 2
        # A completed turn declares the function safe, so it has an outcome on record.
        return types.SimpleNamespace(ok=ok, error=None if ok else "This content was flagged",
                                     status="completed" if ok else "refused", run_id="run-x",
                                     text="safe\nNO_SUSPICIOUS_POINT" if ok else "")

    run._agent = agent
    asyncio.run(asyncio.wait_for(run.sp_generator_agent(run.worker, 0), timeout=3))
    status = {r["function_name"]: (r["status"], r["attempts"]) for r in run.store.rows("SELECT * FROM pool")}
    assert status == {"flaky": ("analysed", 2), "refused": ("failed", 3)}
    run.project.target_ids = ["fn-flaky", "fn-refused", "fn-unqueued"]     # one active target no Direction named
    run.project.functions = {}
    report = run._not_analysed()
    assert (report["active_targets"], report["queued"], report["analysed"], report["failed"],
            report["never_queued"]) == (3, 2, 1, 1, 1)
    assert report["failed_functions"][0]["name"] == "refused"
    assert report["never_queued_functions"] == [{"name": "fn-unqueued", "function_id": "fn-unqueued"}]
    assert run.sp_done.is_set()
