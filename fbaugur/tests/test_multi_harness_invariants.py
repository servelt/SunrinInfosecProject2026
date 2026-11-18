"""Every harness builds every invariant, and each watcher checks every assertion in its binary.

Repository-independent: a fake builder stands in for the compiler, a fake replay for the
binary.  No model, target or fuzzer is run.
"""

from __future__ import annotations

import asyncio
import time
import types
from pathlib import Path

import pytest

import fbaugur.fuzzing as fuzzing
import fbaugur.orchestrator as orchestrator
from fbaugur.config import RunConfig
from fbaugur.fuzzing import CrashWatcher
from fbaugur.orchestrator import Run, Worker
from fbaugur.store import Store


@pytest.fixture(autouse=True)
def fast_idle(monkeypatch):
    monkeypatch.setattr(orchestrator, "IDLE", 0.005)


def _worker(wid: str, hid: str) -> Worker:
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id, worker.sanitizer = wid, hid, "address"
    return worker


def _run(tmp_path: Path) -> Run:
    run = object.__new__(Run)
    run.store = Store(tmp_path / "state.db")
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    run.cfg.rebuild_min_interval_seconds = 0
    run.run_dir = tmp_path
    (tmp_path / "logs").mkdir(exist_ok=True)
    run.sp_done = asyncio.Event()
    run.sp_done.set()
    run.stop = asyncio.Event()
    run.out_of_time = run.stop.is_set
    run.emit = lambda message: None
    run._build_lock = asyncio.Lock()
    run._last_build = 0.0
    run.builds, run.fuzzers = {}, {}
    run.workers = [_worker("w1", "h1"), _worker("w2", "h2")]

    class Builder:
        def __init__(self, harness_id):
            self.harness_id = harness_id

        def build(self, version, invariants, emit):
            return types.SimpleNamespace(ok=True, binary=tmp_path / f"{self.harness_id}-v{version}",
                                         line_map={}, error="", failing=[])

    run._builder = lambda harness_id: Builder(harness_id)

    async def no_reach(*args, **kwargs):
        return None

    run._measure_reach = no_reach
    return run


def _record(run: Run, harness_id: str) -> None:
    run.store.insert("invariants", {"harness_id": harness_id, "file": "src/a.c", "line": 10,
                                    "expression": "n <= cap", "status": "pending_build", "updated_at": time.time()})


async def _coordinators(run: Run) -> None:
    run._build_lock = asyncio.Lock()              # one per event loop
    await asyncio.wait_for(asyncio.gather(*(run.lane(f"phi-build:{w.worker_id}", run.build_coordinator(w))
                                            for w in run.workers)), timeout=3)


def _built(run: Run) -> dict[str, list[list[int]]]:
    out: dict[str, list[list[int]]] = {}
    for row in run.store.rows("SELECT harness_id, phis FROM builds WHERE status='ok' ORDER BY version"):
        out.setdefault(row["harness_id"], []).append(sorted(row["phis"]))
    return out


def test_an_invariant_recorded_for_one_harness_is_built_into_both(tmp_path: Path):
    run = _run(tmp_path)
    _record(run, "h1")                                       # phi 1, owned by h1
    asyncio.run(_coordinators(run))
    assert _built(run) == {"h1": [[1]], "h2": [[1]]}
    _record(run, "h2")                                       # phi 2, owned by h2, later
    asyncio.run(_coordinators(run))
    assert _built(run) == {"h1": [[1], [1, 2]], "h2": [[1], [1, 2]]}
    # h2's watcher checks phi 1 too: it is in h2's binary although h1 recorded it.
    assert run.phis_in_binary("h2") == {1: 1, 2: 2}


def test_a_failed_build_is_not_repeated_but_the_survivors_are_rebuilt(tmp_path: Path):
    run = _run(tmp_path)
    _record(run, "h1")
    _record(run, "h1")
    calls: list[list[int]] = []

    class Breaks:
        def build(self, version, invariants, emit):
            calls.append([i.num for i in invariants])
            if 2 in [i.num for i in invariants]:
                return types.SimpleNamespace(ok=False, binary=None, line_map={}, error="phi 2 does not compile",
                                             failing=[2])
            return types.SimpleNamespace(ok=True, binary=tmp_path / "b", line_map={}, error="", failing=[])

    run._builder = lambda harness_id: Breaks()
    run.workers = run.workers[:1]
    run.cfg.max_repairs = 0                                  # the broken one is withdrawn, not repaired
    asyncio.run(_coordinators(run))
    assert calls == [[1, 2], [1]]                            # phi 1 still reaches the binary
    assert run.phis_in_binary("h1") == {1: 1}


def test_an_input_is_classified_again_on_a_new_build(tmp_path: Path, monkeypatch):
    store = Store(tmp_path / "state.db")
    artifacts = tmp_path / "artifacts"
    watcher = CrashWatcher(store, run_dir=tmp_path, worker="w2", harness="h2")
    watcher.add(artifacts, "global")
    (artifacts / "crash-1").write_bytes(b"GET / HTTP/1.0\r\n\r\n")
    runs: list[str] = []

    def replay(binary, data, timeout=15, env_extra=None, **_):
        if env_extra:                        # the run past the violated assertion: nothing follows
            return types.SimpleNamespace(violations=[1], crashed=False, frames=[], summary=lambda: "")
        runs.append(Path(binary).name)
        violated = [1] if Path(binary).name == "h2-v2" else []
        return types.SimpleNamespace(violations=violated, crashed=False, frames=[], summary=lambda: "")

    monkeypatch.setattr(fuzzing, "run_input", replay)
    monkeypatch.setattr(fuzzing, "is_finding", lambda result, baseline: False)
    monkeypatch.setattr(fuzzing, "load_ub_baseline", lambda run_dir: set())
    asyncio.run(watcher.sweep(tmp_path / "h2-v1", phis={}))
    asyncio.run(watcher.sweep(tmp_path / "h2-v2", phis={1: 1}))
    asyncio.run(watcher.sweep(tmp_path / "h2-v2", phis={1: 1}))     # same build: not classified again
    assert runs == ["h2-v1", "h2-v2"]
    assert [r["phi_num"] for r in store.rows("SELECT phi_num FROM violations")] == [1]


def test_an_msan_worker_does_not_keep_an_unreached_invariant_built(tmp_path: Path, monkeypatch):
    run = _run(tmp_path)
    asan, msan = _worker("w-asan", "h1"), _worker("w-msan", "h1")
    msan.sanitizer = "memory"
    run.workers = [asan, msan]                                # two workers, one probing harness
    run.harness = lambda worker: types.SimpleNamespace(seeds=[("s1", b"GET /")])
    run.project = types.SimpleNamespace(closed_files={"src/closed.c"})
    run.store.insert("invariants", {"harness_id": "h1", "file": "src/closed.c", "line": 3, "expression": "a",
                                    "status": "built", "updated_at": time.time()})
    from fbaugur.instrument import Invariant
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: types.SimpleNamespace(
        reached=[], violations=[], crashed=False, timed_out=False, frames=[], ubsan=[], reach_order=[]))

    async def unsafe(*a, **k):
        return None

    run._drop_unsafe = unsafe
    run._measure_reach = Run._measure_reach.__get__(run)
    asyncio.run(run._measure_reach(asan, tmp_path / "pprime", [Invariant(num=1, file="src/closed.c", line=3,
                                                                          expression="a", distance=False)]))
    assert run.store.scalar("SELECT status FROM invariants WHERE phi_num=1") == "built_unreached"


def _result(*, crashed=False, kind=None, frames=(), ubsan=()):
    from fbaugur.runner import RunResult
    return RunResult(1 if crashed else 0, False, crashed, "AddressSanitizer" if crashed else None, kind,
                     list(frames), list(ubsan), [], [], "")


def test_one_input_on_two_builds_keeps_both_defects(tmp_path: Path, monkeypatch):
    store = Store(tmp_path / "state.db")
    artifacts = tmp_path / "artifacts"
    watcher = CrashWatcher(store, run_dir=tmp_path, worker="w", harness="h")
    watcher.add(artifacts, "global")
    (artifacts / "crash-1").write_bytes(b"input")
    by_build = {"v1": _result(crashed=True, kind="heap-buffer-overflow",
                              frames=[{"function": "f", "file": "/s/x.c", "line": 1}]),
                "v2": _result(crashed=True, kind="heap-use-after-free",
                              frames=[{"function": "g", "file": "/s/x.c", "line": 2}])}
    monkeypatch.setattr(fuzzing, "run_input", lambda binary, data, **k: by_build[Path(binary).name])
    monkeypatch.setattr(fuzzing, "load_ub_baseline", lambda run_dir: set())
    asyncio.run(watcher.sweep(tmp_path / "v1"))
    asyncio.run(watcher.sweep(tmp_path / "v2"))
    asyncio.run(watcher.sweep(tmp_path / "v2"))
    kinds = sorted(r["crash_type"] for r in store.rows("SELECT crash_type FROM crashes"))
    assert kinds == ["heap-buffer-overflow", "heap-use-after-free"]


def test_each_new_ub_site_of_one_input_is_a_candidate(tmp_path: Path, monkeypatch):
    store = Store(tmp_path / "state.db")
    artifacts = tmp_path / "artifacts"
    watcher = CrashWatcher(store, run_dir=tmp_path, worker="w", harness="h")
    watcher.add(artifacts, "global")
    (artifacts / "slow-1").write_bytes(b"input")
    two = _result(ubsan=[{"file": "/s/a.c", "line": 10, "message": "shift"},
                         {"file": "/s/b.c", "line": 20, "message": "overflow"}])
    monkeypatch.setattr(fuzzing, "run_input", lambda *a, **k: two)
    monkeypatch.setattr(fuzzing, "load_ub_baseline", lambda run_dir: set())
    asyncio.run(watcher.sweep(tmp_path / "v1"))
    sites = sorted(r["details"]["ub_site"] for r in store.rows("SELECT details FROM crashes"))
    assert sites == ["/s/a.c:10", "/s/b.c:20"]


def test_a_replay_cut_off_is_done_again(tmp_path: Path, monkeypatch):
    store = Store(tmp_path / "state.db")
    artifacts = tmp_path / "artifacts"
    watcher = CrashWatcher(store, run_dir=tmp_path, worker="w", harness="h")
    watcher.add(artifacts, "global")
    (artifacts / "crash-1").write_bytes(b"input")
    calls = []

    def replay(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise asyncio.CancelledError()                  # the deadline or a build swap
        return _result(crashed=True, kind="stack-buffer-overflow",
                       frames=[{"function": "f", "file": "/s/x.c", "line": 1}])

    monkeypatch.setattr(fuzzing, "run_input", replay)
    monkeypatch.setattr(fuzzing, "load_ub_baseline", lambda run_dir: set())
    try:
        asyncio.run(watcher.sweep(tmp_path / "v1"))
    except asyncio.CancelledError:
        pass
    asyncio.run(watcher.sweep(tmp_path / "v1"))
    assert len(calls) == 2 and store.scalar("SELECT COUNT(*) FROM crashes") == 1


def test_a_fault_after_a_violated_assertion_is_kept(tmp_path: Path, monkeypatch):
    # Follow-up review item 2: the fuzzer ran past phi 1 (continue mode) into a heap overflow.
    # The plain replay aborts at phi 1; the replay past it must still yield the crash candidate.
    store = Store(tmp_path / "state.db")
    artifacts = tmp_path / "artifacts"
    watcher = CrashWatcher(store, run_dir=tmp_path, worker="w", harness="h")
    watcher.add(artifacts, "global")
    (artifacts / "crash-1").write_bytes(b"input")
    overflow = _result(crashed=True, kind="heap-buffer-overflow", frames=[{"function": "f", "file": "/s/x.c", "line": 7}])
    overflow.violations = [1]
    aborted = _result(crashed=True, kind="abort")
    aborted.violations = [1]
    envs = []

    def replay(binary, data, env_extra=None, **k):
        envs.append((env_extra or {}).get("FBA_PHI_CONTINUE"))
        return overflow if env_extra else aborted

    monkeypatch.setattr(fuzzing, "run_input", replay)
    monkeypatch.setattr(fuzzing, "load_ub_baseline", lambda run_dir: set())
    asyncio.run(watcher.sweep(tmp_path / "v1", phis={1: 1}))
    assert envs == [None, "1"]
    assert store.scalar("SELECT COUNT(*) FROM violations") == 1                 # the violation, in abort mode
    assert [r["crash_type"] for r in store.rows("SELECT crash_type FROM crashes")] == ["heap-buffer-overflow"]
