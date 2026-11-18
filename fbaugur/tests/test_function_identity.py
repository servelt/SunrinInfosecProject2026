"""Stage 2 keeps a function's definition (id, file, lines), not just its name.

One name can stand for several definitions: opposite #ifdef branches in one file (only one is
compiled), file-static helpers in different files (both compiled), other programs of the same
build.  Repository-independent counterexamples; no model, target or fuzzer is run.
"""

from __future__ import annotations

import time
import types
from pathlib import Path

from fbaugur.orchestrator import Run, Worker
from fbaugur.project import FunctionInfo, parse_nm_sites, resolve_active_targets
from fbaugur.store import Store
from fbaugur.tools import Toolbox


def _fn(fid: str, name: str, file: str, start: int, end: int) -> FunctionInfo:
    return FunctionInfo(fid, name, file, start, end, f"int {name}(void) {{ return 0; }}", f"int {name}(void)")


FUNCTIONS = {
    "fn-win": _fn("fn-win", "recv_wrapper", "src/common.c", 380, 385),     # #ifdef _WIN32 branch
    "fn-posix": _fn("fn-posix", "recv_wrapper", "src/common.c", 440, 447),  # #else branch
    "fn-a": _fn("fn-a", "parse", "src/a/parser.c", 30, 60),                  # static in one file
    "fn-b": _fn("fn-b", "parse", "plugins/b/parser.c", 10, 50),              # static in another
    "fn-u": _fn("fn-u", "unique", "src/u.c", 1, 9),
}


def test_nm_locations_are_parsed_per_definition():
    sites = parse_nm_sites("0000000000001130 T recv_wrapper\t/build/src/common.c:441\n"
                           "0000000000001200 t parse\t/build/src/a/parser.c:31\n"
                           "0000000000001300 t parse\t/build/plugins/b/parser.c:11\n"
                           "0000000000001400 T unique\n")
    assert sites["recv_wrapper"] == [("/build/src/common.c", 441)]
    assert len(sites["parse"]) == 2 and "unique" not in sites


def test_only_the_compiled_ifdef_branch_is_a_target():
    sites = {"recv_wrapper": [("/build/src/common.c", 441)]}
    active, ambiguous = resolve_active_targets(FUNCTIONS, ["fn-posix"], {"recv_wrapper"}, sites)
    assert active == ["fn-posix"] and not ambiguous
    # The context names the uncompiled branch: the binary's location rules it out.
    active, _ = resolve_active_targets(FUNCTIONS, ["fn-win"], {"recv_wrapper"}, sites)
    assert active == []


def test_file_static_twins_are_two_targets():
    sites = {"parse": [("/build/src/a/parser.c", 31), ("/build/plugins/b/parser.c", 11)]}
    active, ambiguous = resolve_active_targets(FUNCTIONS, ["fn-a", "fn-b"], {"parse"}, sites)
    assert sorted(active) == ["fn-a", "fn-b"] and not ambiguous


def test_without_debug_locations_a_shared_name_stays_ambiguous():
    active, ambiguous = resolve_active_targets(FUNCTIONS, ["fn-a", "fn-u"], {"parse", "unique"}, {})
    assert sorted(active) == ["fn-a", "fn-u"]
    assert set(ambiguous) == {"fn-a"}          # one name, two definitions, no location: not resolved


def _toolbox(tmp_path: Path, *, function: str = "", function_id: str = "") -> Toolbox:
    tools = object.__new__(Toolbox)
    tools.store = Store(tmp_path / "state.db")
    tools.worker, tools.harness_id, tools.direction_id = "w", "h", "d"
    tools.function, tools.function_id, tools.agent_run = function, function_id, "run"
    tools.cfg = types.SimpleNamespace()
    tools.targets = {"parse", "recv_wrapper"}
    tools.index = {"functions": {
        "parse": [{"file": "src/a/parser.c", "start": 30, "end": 60, "function_id": "fn-a", "active": True},
                  {"file": "plugins/b/parser.c", "start": 10, "end": 50, "function_id": "fn-b", "active": True}],
        "recv_wrapper": [{"file": "src/common.c", "start": 380, "end": 385, "function_id": "fn-win", "active": False},
                         {"file": "src/common.c", "start": 440, "end": 447, "function_id": "fn-posix",
                          "active": True}],
        "unique": [{"file": "src/u.c", "start": 1, "end": 9, "function_id": "fn-u", "active": True}]}}
    tools._baseline = set()
    return tools


def _crash(*frames: dict) -> types.SimpleNamespace:
    return types.SimpleNamespace(crashed=True, frames=list(frames))


def test_pov_crash_in_a_same_named_other_definition_is_not_on_target(tmp_path: Path):
    tools = _toolbox(tmp_path)
    sp = {"function_name": "parse", "function_id": "fn-a"}
    other = _crash({"function": "parse", "file": "/build/plugins/b/parser.c", "line": 20})
    mine = _crash({"function": "parse", "file": "/build/src/a/parser.c", "line": 42})
    unlocated = _crash({"function": "parse", "file": None, "line": None})
    assert tools._on_target(sp, other) is False
    assert tools._on_target(sp, mine) is True
    assert tools._on_target(sp, unlocated) is False      # undetermined: not credited
    assert tools._on_target({"function_name": "unique"}, _crash({"function": "unique"})) is True


def test_sp_keeps_the_definition_the_generator_analysed(tmp_path: Path):
    tools = _toolbox(tmp_path, function="recv_wrapper", function_id="fn-posix")
    tools.store.insert("pool", {"worker_id": "w", "direction_id": "d", "function_name": "recv_wrapper",
                                "function_id": "fn-posix", "status": "analysing", "updated_at": time.time()})
    tools.create_suspicious_point("recv_wrapper", "overflow", "len unchecked")
    tools.create_suspicious_point("parse", "overflow", "a callee with two compiled definitions")
    tools.create_suspicious_point("unique", "overflow", "a callee with one definition")
    ids = {row["function_name"]: row["function_id"] for row in tools.store.rows("SELECT * FROM sps")}
    assert ids == {"recv_wrapper": "fn-posix", "parse": None, "unique": "fn-u"}
    # sp_count counts what analysing this pool item produced (three SPs, under three names).
    assert tools.store.scalar("SELECT sp_count FROM pool WHERE function_id='fn-posix'") == 3


def test_pool_holds_one_item_per_compiled_definition(tmp_path: Path):
    store = Store(tmp_path / "state.db")
    store.insert("directions", {"direction_id": "d1", "harness_id": "h", "entry_functions": [],
                                "core_functions": ["parse", "recv_wrapper"]})
    run = object.__new__(Run)
    run.store, run.emit = store, (lambda message: None)
    run.cfg = types.SimpleNamespace(max_function_analyses=0)
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id = "w", "h"
    run.workers = [worker]
    active = {"parse": ["fn-a", "fn-b"], "recv_wrapper": ["fn-posix"]}
    run.project = types.SimpleNamespace(
        by_name={"parse": [1], "recv_wrapper": [1]}, blocked_names=set(), executed_names={"parse"},
        reachable_from=lambda core: list(core), active_ids=lambda name: active.get(name, []))
    run._fill_pools()
    rows = sorted((r["function_name"], r["function_id"]) for r in store.rows("SELECT * FROM pool"))
    assert rows == [("parse", "fn-a"), ("parse", "fn-b"), ("recv_wrapper", "fn-posix")]


def test_a_frontier_opinion_queues_a_function_last_but_keeps_it(tmp_path: Path):
    store = Store(tmp_path / "state.db")
    store.insert("directions", {"direction_id": "d1", "harness_id": "h", "entry_functions": [],
                                "core_functions": ["parsehost", "parse"]})
    run = object.__new__(Run)
    run.store, run.emit = store, (lambda message: None)
    run.cfg = types.SimpleNamespace(max_function_analyses=0)
    worker = object.__new__(Worker)
    worker.worker_id, worker.harness_id = "w", "h"
    run.workers = [worker]
    run.project = types.SimpleNamespace(
        by_name={"parsehost": [1], "parse": [1]}, blocked_names={"parsehost"}, executed_names=set(),
        reachable_from=lambda core: list(core), active_ids=lambda name: [f"fn-{name}"])
    run._fill_pools()
    phases = {r["function_name"]: r["phase"] for r in store.rows("SELECT * FROM pool")}
    assert set(phases) == {"parsehost", "parse"} and phases["parsehost"] > phases["parse"]
