"""SP Verifier -> PoV admission follows the verifier's verdict, not a score cut.

The FBv2 verifier prompt asks for is_important=True on every candidate it cannot prove
safe ("0.4-0.5: uncertain but possible -> PASS TO POV") and reserves is_important=False
for a certain false positive.  The orchestrator must not drop such a candidate before
PoV, and the PoV lane must be able to take every candidate it admitted.
"""

from __future__ import annotations

import asyncio
import time
import types
from pathlib import Path

from fbaugur.config import RunConfig
from fbaugur.orchestrator import Run, Worker
from fbaugur.store import Store
from fbaugur.tools import Toolbox

NO_CALL = object()      # the turn ended normally without calling update_suspicious_point


def _run(tmp_path: Path, verdicts: dict[str, dict | None]) -> tuple[Run, Store]:
    store = Store(tmp_path / "state.db")
    run = object.__new__(Run)
    run.store = store
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    run.sp_done = asyncio.Event()
    run.sp_done.set()
    run.out_of_time = lambda: False
    run.emit = lambda message: None
    seeded: list[str] = []

    async def fp_seed(worker, sp):
        seeded.append(sp["sp_id"])

    async def agent(role, harness_id, message, *, subject="", **_):
        verdict = verdicts[subject]
        if verdict is None:                     # the model turn failed: no verdict recorded
            return types.SimpleNamespace(ok=False, error="model error")
        if verdict is not NO_CALL:              # the model called the real tool with these fields
            tools = object.__new__(Toolbox)
            tools.store, tools.sp_id, tools.source_root = store, subject, tmp_path
            time.sleep(0.002)
            tools.update_suspicious_point(subject, **verdict)
        return types.SimpleNamespace(ok=True, error=None)

    run._agent = agent
    run._fp_seed = fp_seed
    run.seeded = seeded
    now = time.time()
    for sp_id in verdicts:
        store.insert("sps", {"sp_id": sp_id, "worker_id": "w", "harness_id": "h", "function_name": "f",
                             "vuln_type": "overflow", "description": sp_id, "score": 0.45,
                             "status": "pending_verify", "created_at": now, "updated_at": now})
    return run, store


def _worker() -> Worker:
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id = "w", "h"
    return worker


def test_uncertain_candidate_the_verifier_passes_reaches_pov(tmp_path: Path):
    run, store = _run(tmp_path, {
        "uncertain": {"score": 0.45, "is_important": 1, "pov_guidance": "send a long header"},
        "clear": {"score": 0.8, "is_important": 1, "pov_guidance": "send a long header"},
        "false_positive": {"score": 0.2, "is_important": 0},
        "unverified": None,
    })
    asyncio.run(run.verifier_agent(_worker(), 0))
    status = {row["sp_id"]: row["status"] for row in store.rows("SELECT sp_id, status FROM sps")}
    assert status["uncertain"] == "pending_pov"
    assert status["clear"] == "pending_pov"
    assert status["false_positive"] == "rejected"
    assert status["unverified"] == "pending_pov"      # no verdict is not a proof of safety
    assert run.seeded == ["false_positive"]           # a rejected SP still seeds the fuzzer


def test_pov_lane_claims_every_admitted_candidate(tmp_path: Path):
    run, store = _run(tmp_path, {"uncertain": {"score": 0.45, "is_important": 1, "pov_guidance": "x"}})
    asyncio.run(run.verifier_agent(_worker(), 0))
    claimed = store.claim_sp(from_status="pending_pov", to_status="generating_pov", worker_id="w",
                             agent="pov-0", **run.pov_claim_filter())
    assert claimed is not None and claimed["sp_id"] == "uncertain"


def test_verifier_turn_that_ends_without_a_verdict_keeps_the_candidate(tmp_path: Path):
    # The model finished its turn normally (result.ok) but never called update_suspicious_point.
    run, store = _run(tmp_path, {"silent": NO_CALL})
    store.update("sps", "sp_id", "silent", {"score": 0.6})
    asyncio.run(run.verifier_agent(_worker(), 0))
    row = store.row("SELECT status, is_important FROM sps WHERE sp_id='silent'")
    assert row["status"] == "pending_pov"
    assert run.seeded == []


def test_invariant_recorder_waits_for_candidates_still_in_pov(tmp_path: Path, monkeypatch):
    # A candidate admitted to PoV can still end as pov_failed with a recorded safety reason;
    # the recorder must still be running then, or that invariant is never committed.
    import fbaugur.orchestrator as orchestrator
    monkeypatch.setattr(orchestrator, "IDLE", 0.01)
    run, store = _run(tmp_path, {"in_pov": {}})
    store.update("sps", "sp_id", "in_pov", {"status": "generating_pov", "safety_reason": "n <= cap",
                                           "safety_location": "src/a.c:10"})
    recorded: list[str] = []

    async def agent(role, harness_id, message, *, subject="", **_):
        recorded.append(subject)
        # Recorded and (no build lane here) already compiled into this harness's binary.
        store.insert("invariants", {"sp_id": subject, "harness_id": "h", "status": "built"})
        store.insert("builds", {"harness_id": "h", "version": 1, "status": "ok", "phis": [1]})
        return types.SimpleNamespace(ok=True, error=None)

    run._agent = agent
    run._window = lambda location: ""

    async def scenario():
        task = asyncio.create_task(run.invariant_recorder(_worker()))
        await asyncio.sleep(0.1)
        store.update("sps", "sp_id", "in_pov", {"status": "pov_failed"})
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())
    assert recorded == ["in_pov"]


def test_tool_call_without_a_verdict_field_is_not_a_rejection(tmp_path: Path):
    run, store = _run(tmp_path, {
        "empty_call": {},                                            # update_suspicious_point(id) only
        "partial_call": {"score": 0.3, "verification_notes": "looked at the caller"},
        "explicit_reject": {"score": 0.2, "is_important": False},
        "uncertain_pass": {"score": 0.45, "is_important": True, "pov_guidance": "long header"},
    })
    asyncio.run(run.verifier_agent(_worker(), 0))
    status = {row["sp_id"]: row["status"] for row in store.rows("SELECT sp_id, status FROM sps")}
    assert status == {"empty_call": "pending_pov", "partial_call": "pending_pov",
                      "explicit_reject": "rejected", "uncertain_pass": "pending_pov"}
    assert run.seeded == ["explicit_reject"]
    claimed = []
    while (sp := store.claim_sp(from_status="pending_pov", to_status="generating_pov", worker_id="w",
                                agent="pov-0", **run.pov_claim_filter())):
        claimed.append(sp["sp_id"])
    assert claimed[0] == "uncertain_pass"                 # a verified pass is tried first
    assert sorted(claimed) == ["empty_call", "partial_call", "uncertain_pass"]


def test_database_from_before_verdict_at_is_migrated(tmp_path: Path):
    import sqlite3
    old = sqlite3.connect(tmp_path / "state.db")
    old.execute("CREATE TABLE sps (sp_id TEXT PRIMARY KEY, status TEXT, is_important INTEGER DEFAULT 0, "
                "updated_at REAL)")
    old.execute("INSERT INTO sps VALUES ('old', 'pending_verify', 0, 1.0)")
    old.commit()
    old.close()
    store = Store(tmp_path / "state.db")
    row = store.row("SELECT sp_id, verdict_at FROM sps WHERE sp_id='old'")
    assert row["sp_id"] == "old" and row["verdict_at"] is None
