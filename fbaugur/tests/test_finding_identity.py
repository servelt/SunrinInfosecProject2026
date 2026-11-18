"""Finding identity: UB sites keep their path, signatures keep class and path, and a finding is
validated only by a reproduction of the same defect.  Repository-independent counterexamples."""

from __future__ import annotations

import asyncio
import json
import time
import types
from pathlib import Path

import pytest

import fbaugur.orchestrator as orchestrator
import fbaugur.runner as runner
from fbaugur.config import RunConfig
from fbaugur.orchestrator import Run, Worker
from fbaugur.runner import (DaemonReplay, RunResult, crash_signature, fault_key, find_duplicate, is_finding,
                            load_ub_baseline, new_ub_sites, same_fault, set_source_root, write_ub_baseline)
from fbaugur.store import Store


@pytest.fixture()
def tree(tmp_path: Path):
    for rel in ("src/old/parser.c", "plugins/new/parser.c", "src/a/parse.c", "plugins/b/parse.c"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("int x;\n")
    set_source_root(tmp_path)
    yield tmp_path
    set_source_root(None)


def _ub(path: str, line: int) -> RunResult:
    return RunResult(0, False, False, None, None, [], [{"file": path, "line": line, "message": "shift"}],
                     [], [], "")


def _crash(kind: str, function: str, path: str | None, line: int | None) -> RunResult:
    return RunResult(1, False, True, "AddressSanitizer", kind,
                     [{"index": 0, "function": function, "file": path, "line": line}], [], [], [], "")


def test_ub_in_a_same_named_file_elsewhere_is_new(tree: Path):
    baseline = set(_ub("/build/src/old/parser.c", 42).ub_sites())
    assert baseline == {"src/old/parser.c:42"}
    assert new_ub_sites(_ub("/build/plugins/new/parser.c", 42), baseline) == ["plugins/new/parser.c:42"]
    assert is_finding(_ub("/build/plugins/new/parser.c", 42), baseline)
    # The same file compiled from another copy of the tree (an invariant build) is the same site.
    assert new_ub_sites(_ub("/work/h1/invariants/v3/src/old/parser.c", 42), baseline) == []


def test_baseline_is_versioned_and_an_old_one_still_loads(tree: Path, tmp_path: Path):
    write_ub_baseline(tmp_path, {"src/old/parser.c:42"})
    assert load_ub_baseline(tmp_path) == {"src/old/parser.c:42"}
    (tmp_path / "ub-baseline.json").write_text(json.dumps(["parser.c:42"]))     # written before paths were kept
    legacy = load_ub_baseline(tmp_path)
    assert new_ub_sites(_ub("/build/src/old/parser.c", 42), legacy) == []      # still matches by file name


def test_signatures_keep_the_file_and_the_bug_class(tree: Path):
    a = _crash("heap-buffer-overflow", "parse", "/build/src/a/parse.c", 42)
    b = _crash("heap-buffer-overflow", "parse", "/build/plugins/b/parse.c", 42)
    uaf = _crash("heap-use-after-free", "parse", "/build/src/a/parse.c", 42)
    assert crash_signature(a) != crash_signature(b)
    assert crash_signature(a) != crash_signature(uaf) and fault_key(a) != fault_key(uaf)
    earlier = [{"signature": crash_signature(a), "details": {"fault_key": fault_key(a)}}]
    assert find_duplicate(crash_signature(b), fault_key(b), earlier) == (None, "")
    assert find_duplicate(crash_signature(uaf), fault_key(uaf), earlier) == (None, "")
    assert find_duplicate(crash_signature(a), fault_key(a), earlier)[1] == "same stack"


def test_an_unlocated_crash_is_never_merged(tree: Path):
    unlocated = _crash("heap-buffer-overflow", "parse", None, None)
    earlier = [{"signature": crash_signature(unlocated), "details": {"fault_key": fault_key(unlocated)}}]
    assert find_duplicate(crash_signature(unlocated), fault_key(unlocated), earlier) == (None, "")
    assert same_fault(unlocated, unlocated) is None


# ---------------------------------------------------------------- validation of a confirmed finding

BUG_A = ("heap-buffer-overflow", "parse", "/build/src/a/parse.c", 42)
BUG_B = ("heap-use-after-free", "parse", "/build/plugins/b/parse.c", 20)


def _validation_run(tmp_path: Path, monkeypatch, *, harness: list, daemon: list) -> tuple[Run, Store]:
    store = Store(tmp_path / "state.db")
    run = object.__new__(Run)
    run.store, run.emit = store, (lambda message: None)
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    run.cfg.validation_replays = len(harness)
    run.run_dir = tmp_path
    run.cfg.daemon_command = "server --config c"
    run.index = {"program": "demo"}
    run.validation_closed = lambda: False
    run.harness = lambda worker: types.SimpleNamespace(port=1, trigger=b"")
    run.binary_for = lambda worker: tmp_path / "fuzzer"

    async def plain(worker, data):
        return {}

    async def validator(role, harness_id, message, *, subject="", **_):
        row = store.row("SELECT details FROM crashes WHERE crash_id=?", subject)
        details = dict(row["details"] or {})
        details["validation"] = {"verdict": "VULNERABILITY", "reasons": "model says so", "cvss_score": 7.5}
        store.update("crashes", "crash_id", subject, {"details": details})
        return types.SimpleNamespace(ok=True)

    run._measure_plain_build, run._agent = plain, validator
    replays = iter(harness)
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: next(replays))
    daemons = iter(daemon)
    monkeypatch.setattr(orchestrator, "daemon_replay", lambda *a, **k: next(daemons))
    store.insert("crashes", {"crash_id": "c1", "worker_id": "w", "status": "confirmed", "input_path": "/in",
                             "details": {}, "created_at": time.time()})
    return run, store


def _worker() -> Worker:
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id, worker.sanitizer, worker.delivery = "w", "h", "address", "stream"
    return worker


def test_a_different_fault_on_the_real_program_does_not_validate(tree: Path, tmp_path: Path, monkeypatch):
    found = _crash(*BUG_A)
    run, store = _validation_run(tmp_path, monkeypatch, harness=[_crash(*BUG_A), _crash(*BUG_A)],
                                 daemon=[DaemonReplay(True, _crash(*BUG_B), 18, "crashed")] * 3)
    asyncio.run(run._validate_and_report("c1", _worker(), b"GET /\r\n\r\n", found, crash_signature(found), set()))
    row = store.row("SELECT status, details FROM crashes WHERE crash_id='c1'")
    daemon = row["details"]["checks"]["daemon"]
    assert daemon["same_fault"] is False and daemon["other_fault_runs"] == 3 and not daemon["reproduced"]
    assert row["status"] == "needs_review"
    kept = store.row("SELECT * FROM crashes WHERE source='real_program'")
    assert kept["status"] == "needs_review" and kept["crash_type"] == "heap-use-after-free"


def test_harness_replays_count_only_the_same_fault(tree: Path, tmp_path: Path, monkeypatch):
    found = _crash(*BUG_A)
    run, store = _validation_run(tmp_path, monkeypatch, harness=[_crash(*BUG_B), _crash(*BUG_B)],
                                 daemon=[DaemonReplay(True, None, 18, "kept running")] * 3)
    asyncio.run(run._validate_and_report("c1", _worker(), b"x", found, crash_signature(found), set()))
    row = store.row("SELECT status, details FROM crashes WHERE crash_id='c1'")
    rep = row["details"]["checks"]["reproducibility"]
    assert rep["crashed"] == 2 and rep["same_fault_runs"] == 0
    assert row["status"] == "needs_review"


def test_a_fault_before_any_input_byte_is_not_a_reproduction(tree: Path, tmp_path: Path, monkeypatch):
    found = _crash(*BUG_A)
    run, store = _validation_run(tmp_path, monkeypatch, harness=[_crash(*BUG_B)],
                                 daemon=[DaemonReplay(True, _crash(*BUG_A), 0, "crashed")] * 3)
    asyncio.run(run._validate_and_report("c1", _worker(), b"x", found, crash_signature(found), set()))
    row = store.row("SELECT status, details FROM crashes WHERE crash_id='c1'")
    daemon = row["details"]["checks"]["daemon"]
    assert daemon["faults_without_input"] == 3 and not daemon["reproduced"]
    assert row["status"] == "needs_review"


def test_the_same_fault_on_the_real_program_validates_and_records_a_mid_input_close(tree: Path, tmp_path: Path,
                                                                                     monkeypatch):
    found = _crash(*BUG_A)
    closed = "the program closed the connection after 9 of 40 input bytes: reset"
    run, store = _validation_run(tmp_path, monkeypatch, harness=[_crash(*BUG_A)],
                                 daemon=[DaemonReplay(True, _crash(*BUG_A), 9, "crashed", closed)] * 3)
    asyncio.run(run._validate_and_report("c1", _worker(), b"x" * 40, found, crash_signature(found), set()))
    row = store.row("SELECT status, details FROM crashes WHERE crash_id='c1'")
    daemon = row["details"]["checks"]["daemon"]
    assert daemon["reproduced"] and daemon["closed_mid_input"] == [closed] * 3
    assert row["status"] == "validated"


def test_an_identical_unlocated_crash_is_kept_but_not_validated_again(tmp_path: Path, monkeypatch):
    set_source_root(None)
    lib = RunResult(1, False, True, "MemorySanitizer", "use-of-uninitialized-value",
                    [{"index": 1, "function": "lib_get_type", "file": None, "line": None},
                     {"index": 2, "function": "lib_config", "file": None, "line": None}], [], [], [], "")
    store = Store(tmp_path / "state.db")
    run = object.__new__(Run)
    run.store, run.emit, run.run_dir, run.prior, run.delta = store, (lambda m: None), tmp_path, [], False
    run.ub_baseline = set()
    run.stop, run.draining = asyncio.Event(), False
    run._fixed_deadline, run.started_at = time.time() + 600, time.time()
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    worker = _worker()
    run.workers = [worker]
    run.harness = lambda w: types.SimpleNamespace(source_path=tmp_path / "fuzz_target.c")
    run.binary_for = lambda w: tmp_path / "fuzzer"
    validated: list[str] = []

    async def validate(crash_id, *a, **k):
        validated.append(crash_id)
        store.update("crashes", "crash_id", crash_id, {"status": "not_vulnerability"})

    run._validate_and_report = validate
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: lib)
    (tmp_path / "in").write_bytes(b"x")
    for cid in ("c1", "c2"):
        store.insert("crashes", {"crash_id": cid, "worker_id": "w", "status": "confirming",
                                 "input_path": str(tmp_path / "in"), "details": {}, "created_at": time.time()})
        asyncio.run(run._confirm_crash(store.row("SELECT * FROM crashes WHERE crash_id=?", cid)))
    assert validated == ["c1"]
    second = store.row("SELECT status, duplicate_of FROM crashes WHERE crash_id='c2'")
    assert second == {"status": "possible_duplicate", "duplicate_of": "c1"}


def test_an_msan_build_that_faults_with_no_input_is_not_a_worker(tmp_path: Path, monkeypatch):
    import fbaugur.instrument as instrument
    store = Store(tmp_path / "state.db")
    run = object.__new__(Run)
    run.store, run.emit, run.run_dir = store, (lambda m: None), tmp_path
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    worker = _worker()
    run.workers = [worker]
    run.index = {"harnesscreator_src": str(tmp_path), "harnesses": {}}
    run.project = types.SimpleNamespace(source_root=tmp_path, compile_database=None)
    run.harness = lambda w: types.SimpleNamespace(source_path=tmp_path / "f.c", build_plan=None,
                                                  seeds=[("s1", b"GET /\r\n\r\n")])

    class Builder:
        def __init__(self, **kwargs):
            pass

        def build(self, version, invariants, emit):
            return types.SimpleNamespace(ok=True, binary=tmp_path / "msan", error="")

    monkeypatch.setattr(instrument, "InvariantBuilder", Builder)
    startup = RunResult(1, False, True, "MemorySanitizer", "use-of-uninitialized-value",
                        [{"index": 1, "function": "lib_get_type", "file": None, "line": None}], [], [], [], "")
    monkeypatch.setattr(orchestrator, "run_input", lambda *a, **k: startup)
    asyncio.run(run._add_msan_workers())
    assert [w.sanitizer for w in run.workers] == ["address"]
    assert "no input" in store.get_meta("msan_skipped_h", "")


def test_an_msan_fault_of_one_verified_input_is_a_candidate_not_a_reason_to_drop_msan(tmp_path: Path, monkeypatch):
    import fbaugur.instrument as instrument
    store = Store(tmp_path / "state.db")
    run = object.__new__(Run)
    run.store, run.emit, run.run_dir = store, (lambda m: None), tmp_path
    run.cfg = RunConfig(run_dir=tmp_path, hc_run=tmp_path, context_id="ctx", deliveries=["stream"])
    worker = _worker()
    worker.binary = tmp_path / "asan"
    run.workers = [worker]
    run.index = {"harnesscreator_src": str(tmp_path), "harnesses": {}}
    run.project = types.SimpleNamespace(source_root=tmp_path, compile_database=None)
    run.harness = lambda w: types.SimpleNamespace(source_path=tmp_path / "f.c", build_plan=None,
                                                  seeds=[("good", b"USER a\r\n"), ("bad", b"PASS b\r\n")])

    class Builder:
        def __init__(self, **kwargs):
            pass

        def build(self, version, invariants, emit):
            return types.SimpleNamespace(ok=True, binary=tmp_path / "msan", error="")

    monkeypatch.setattr(instrument, "InvariantBuilder", Builder)
    clean = RunResult(0, False, False, None, None, [], [], [], [], "")
    fault = RunResult(1, False, True, "MemorySanitizer", "use-of-uninitialized-value",
                      [{"index": 0, "function": "check_pass", "file": "/s/src/auth.c", "line": 9}], [], [], [], "")
    monkeypatch.setattr(orchestrator, "run_input", lambda binary, data, **k: fault if data.startswith(b"PASS") else clean)
    asyncio.run(run._add_msan_workers())
    assert [w.sanitizer for w in run.workers] == ["address", "memory"]
    row = store.row("SELECT source, status, crash_type FROM crashes")
    assert row == {"source": "msan_seed", "status": "pending", "crash_type": "use-of-uninitialized-value"}
    assert run._msan_quarantine["h"] == {"bad"}


def test_a_candidate_for_the_second_ub_site_needs_that_site_again():
    # Follow-up review item 3: first run reports :10 and :20 (two candidates); a later run reports
    # only :10.  It reproduces the :10 candidate, not the :20 one.
    from fbaugur.runner import RunResult, same_fault

    def run(*lines):
        return RunResult(0, False, False, None, None, [], [{"file": "src/p.c", "line": n, "message": "m"}
                                                           for n in lines], [], [], "")

    first, again = run(10, 20), run(10)
    assert same_fault(again, first, set(), site="src/p.c:20") is False
    assert same_fault(again, first, set(), site="src/p.c:10") is True
    assert same_fault(run(20), first, set(), site="src/p.c:20") is True


def test_validation_of_a_second_ub_site_counts_only_runs_that_report_it(tree: Path, tmp_path: Path, monkeypatch):
    # Harness replays and the real program report only :10; the candidate is for :20.
    from fbaugur.runner import RunResult

    def ub(*lines):
        return RunResult(0, False, False, None, None, [], [{"file": "src/p.c", "line": n, "message": "m"}
                                                           for n in lines], [], [], "")

    found = ub(10, 20)
    run, store = _validation_run(tmp_path, monkeypatch, harness=[ub(10), ub(10)],
                                 daemon=[DaemonReplay(True, ub(10), 18, "kept running")] * 3)
    asyncio.run(run._validate_and_report("c1", _worker(), b"x", found, "UB src/p.c:20", set(),
                                         ub_site="src/p.c:20"))
    row = store.row("SELECT status, details FROM crashes WHERE crash_id='c1'")
    assert row["details"]["checks"]["reproducibility"]["same_fault_runs"] == 0
    assert not row["details"]["checks"]["daemon"]["reproduced"]
    assert row["status"] == "needs_review"
