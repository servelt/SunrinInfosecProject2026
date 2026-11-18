"""A PoV's first crashing replay is not a confirmed finding until the crash lane reproduces it."""

from __future__ import annotations

import asyncio
import time
import types
from pathlib import Path

from fbaugur.orchestrator import Run
from fbaugur.store import Store, settled_pov_status


def _sp(store: Store, sp_id: str, status: str) -> None:
    store.insert("sps", {"sp_id": sp_id, "worker_id": "w", "status": status, "is_real": 1 if status == "pov_generated" else 0,
                         "created_at": time.time()})


def _crash(store: Store, crash_id: str, sp_id: str, status: str) -> None:
    store.insert("crashes", {"crash_id": crash_id, "worker_id": "w", "sp_id": sp_id, "source": "pov",
                             "status": status, "created_at": time.time()})


def test_the_rule():
    assert settled_pov_status("pov_unconfirmed", ["pending"]) == "pov_unconfirmed"
    assert settled_pov_status("pov_unconfirmed", ["not_reproduced", "confirmed"]) == "pov_confirmed"
    assert settled_pov_status("pov_unconfirmed", ["harness_fault"]) == "pov_harness_fault"
    assert settled_pov_status("pov_unconfirmed", ["unattributed"]) == "pov_unattributed"
    assert settled_pov_status("pov_failed", ["confirmed"]) == "pov_failed"     # not a PoV success state


def test_stored_runs_are_settled_too(tmp_path: Path):
    store = Store(tmp_path / "state.db")
    _sp(store, "old", "pov_generated")                  # written by older code after the first replay
    _crash(store, "c1", "old", "not_reproduced")
    _sp(store, "good", "pov_generated")
    _crash(store, "c2", "good", "validated")
    store.settle_pov()
    rows = {r["sp_id"]: (r["status"], r["is_real"]) for r in store.rows("SELECT * FROM sps")}
    assert rows == {"old": ("pov_not_reproduced", 0), "good": ("pov_confirmed", 1)}


def test_confirmation_settles_the_point(tmp_path: Path):
    run = object.__new__(Run)
    run.store = Store(tmp_path / "state.db")
    _sp(run.store, "sp1", "pov_unconfirmed")
    _crash(run.store, "c1", "sp1", "confirming")

    async def check(crash):
        run.store.update("crashes", "crash_id", crash["crash_id"], {"status": "harness_fault"})

    run._confirm_crash = check
    asyncio.run(run._confirm(run.store.row("SELECT * FROM crashes WHERE crash_id='c1'")))
    assert run.store.row("SELECT status, is_real FROM sps WHERE sp_id='sp1'") == {"status": "pov_harness_fault",
                                                                                  "is_real": 0}
