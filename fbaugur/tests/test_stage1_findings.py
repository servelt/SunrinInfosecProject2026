"""What stage 1 and the verified inputs already show is checked in stage 2, not dropped."""

from __future__ import annotations

import asyncio
import json
import types
from pathlib import Path

import fbaugur.orchestrator as orchestrator
from fbaugur.config import RunConfig
from fbaugur.orchestrator import Run, Worker
from fbaugur.runner import RunResult
from fbaugur.store import Store


def _run(tmp_path: Path, seeds, findings=None) -> Run:
    attempt = tmp_path / "attempt-1"
    attempt.mkdir()
    if findings is not None:
        (attempt / "program-findings.json").write_text(json.dumps({"findings": findings}))
    run = object.__new__(Run)
    run.store, run.emit, run.run_dir = Store(tmp_path / "state.db"), (lambda m: None), tmp_path
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id, worker.sanitizer = "w", "h", "address"
    run.workers = [worker]
    run.harness = lambda w: types.SimpleNamespace(harness_id="h", binary=tmp_path / "fuzzer", seeds=seeds,
                                                  attempt_dir=attempt)
    return run


CLEAN = RunResult(0, False, False, None, None, [], [], [], [], "")
UB = RunResult(0, False, False, None, None, [], [{"file": "/s/src/a.c", "line": 7, "message": "shift"}], [], [], "")
CRASH = RunResult(1, False, True, "AddressSanitizer", "stack-buffer-overflow",
                  [{"index": 0, "function": "f", "file": "/s/src/a.c", "line": 9}], [], [], [], "")


def test_a_faulting_seed_is_a_candidate_and_the_others_go_on(tmp_path: Path, monkeypatch):
    run = _run(tmp_path, [("bad", b"A" * 600), ("good", b"USER a\r\n")])
    monkeypatch.setattr(orchestrator, "run_input", lambda b, data, **k: CRASH if data.startswith(b"A") else CLEAN)
    assert asyncio.run(run._replay_verified_inputs()) == set()
    row = run.store.row("SELECT source, status, crash_type FROM crashes")
    assert row == {"source": "seed_replay", "status": "pending", "crash_type": "stack-buffer-overflow"}


def test_no_clean_seed_stops_the_run(tmp_path: Path, monkeypatch):
    run = _run(tmp_path, [("bad", b"A" * 600)])
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: CRASH)
    assert asyncio.run(run._replay_verified_inputs()) is None


def test_a_seed_ub_site_is_baseline_and_also_checked_once(tmp_path: Path, monkeypatch):
    run = _run(tmp_path, [("s1", b"x"), ("s2", b"y")])
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: UB)
    baseline = asyncio.run(run._replay_verified_inputs())
    assert baseline == {"/s/src/a.c:7"}
    rows = run.store.rows("SELECT source, details FROM crashes")
    assert [(r["source"], r["details"]["ub_site"]) for r in rows] == [("seed_ub", "/s/src/a.c:7")]
    asyncio.run(run._replay_verified_inputs())                 # a resumed run does not queue it again
    assert run.store.scalar("SELECT COUNT(*) FROM crashes") == 1


def test_stage1_program_findings_reach_the_confirmation_queue(tmp_path: Path, monkeypatch):
    findings = [{"sanitizer": "AddressSanitizer", "file": "src/a.c", "line": 9, "message": "stack-buffer-overflow",
                 "seed_ids": ["s1"]}]
    run = _run(tmp_path, [("s1", b"x")], findings)
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: CLEAN)
    asyncio.run(run._replay_verified_inputs())
    row = run.store.row("SELECT source, details FROM crashes")
    assert row["source"] == "stage1_report" and row["details"]["stage1"]["line"] == 9
