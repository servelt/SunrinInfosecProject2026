"""Provider-free checks for original Direction Seed Docker accounting."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from fuzzingbrain.fuzzer.seed_sandbox import (
    SeedSandboxCleanupError, SeedSandboxError, SeedSandboxOutputLimitError,
)
from fuzzingbrain.fuzzer.seed_tools import (
    clear_seed_context, create_seed_impl, set_seed_context,
)
from fuzzingbrain.tools.qualified_runtime import QualifiedRuntimeBinding


EVAL_TOOLS = Path(__file__).resolve().parents[2] / "evaluation_tools"
if str(EVAL_TOOLS) not in sys.path:
    sys.path.insert(0, str(EVAL_TOOLS))

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from devtools.product_qualified_runtime import ProductQualifiedPoVAdapter
from devtools.original_public_live import _bound_seed_pin_hook
from devtools.original_global_bridge import OriginalGlobalBridge


def _adapter(tmp_path, *, wall_seconds=400, pin_hook=None):
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "physical.json", wall_total_seconds=wall_seconds,
        fuzz_total_seconds=0)
    direction = SimpleNamespace(task_id="task-1", fuzzer="fuzz")
    adapter = object.__new__(ProductQualifiedPoVAdapter)
    adapter.task_id = "task-1"
    adapter.run_id = "run-1"
    adapter.fuzzer = "fuzz"
    adapter.repos = SimpleNamespace(directions=SimpleNamespace(
        find_by_id=lambda value: direction if value == "dir-1" else None))
    adapter.ledger = ledger
    adapter.binding = QualifiedRuntimeBinding(object(), Mock(), adapter.generate)
    adapter._seed_pin_hook = pin_hook or (lambda _phase, _command: None)
    return adapter, ledger


def _generate(adapter, *, worker_id="agent-1", attempt=1,
              direction_id="dir-1", task_id="task-1",
              code="def generate(n): return b'x'"):
    return adapter.generate_seed(
        task_id=task_id, direction_id=direction_id,
        worker_id=worker_id, attempt=attempt,
        code=code, num_seeds=1)


def test_seed_docker_is_reserved_before_launch_and_settled(tmp_path):
    adapter, ledger = _adapter(tmp_path)

    def generator(_code, _count):
        active = ledger.snapshot()["active"]
        assert len(active) == 1
        assert next(iter(active.values()))["kind"] == "AUX_PROCESS"
        return [b"x"]

    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator",
               side_effect=generator):
        assert _generate(adapter) == [b"x"]
        assert _generate(adapter, attempt=2) == [b"x"]
        with pytest.raises(ValueError, match="reservation not eligible"):
            _generate(adapter, attempt=2, code="def generate(n): return b'y'")

    state = ledger.snapshot()
    assert state["active"] == {}
    assert state["stop_status"] is None
    assert len(state["finished"]) == 2
    assert all(row["kind"] == "AUX_PROCESS" and
               row["cleanup_complete"] is True and
               row["output_limited"] is False
               for row in state["finished"])
    assert any("task-1:dir-1:seed_generator:agent-1:1" == row["key"]
               for row in state["finished"])


def test_five_concurrent_seed_agents_use_distinct_reservations(tmp_path):
    adapter, ledger = _adapter(tmp_path)

    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator",
               return_value=[b"x"]):
        with ThreadPoolExecutor(max_workers=5) as pool:
            rows = list(pool.map(
                lambda n: _generate(adapter, worker_id=f"agent-{n}"),
                range(5)))
    assert rows == [[b"x"]] * 5
    state = ledger.snapshot()
    assert state["active"] == {}
    assert len(state["finished"]) == 5
    assert len({row["key"] for row in state["finished"]}) == 5


@pytest.mark.parametrize("error,stop_status,cleanup_complete", [
    (SeedSandboxCleanupError("cleanup uncertain"),
     "STOPPED_CLEANUP_INCOMPLETE", False),
    (SeedSandboxOutputLimitError("output exceeded"),
     "STOPPED_OUTPUT_LIMIT", True),
])
def test_seed_cleanup_and_output_failure_stop_shared_ledger(
        tmp_path, error, stop_status, cleanup_complete):
    adapter, ledger = _adapter(tmp_path)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator",
               side_effect=error):
        expected_error = (SeedSandboxCleanupError if not cleanup_complete
                          else SeedSandboxError)
        with pytest.raises(expected_error):
            _generate(adapter)
    state = ledger.snapshot()
    assert state["active"] == {}
    assert state["stop_status"] == stop_status
    assert state["finished"][0]["cleanup_complete"] is cleanup_complete


def test_seed_pin_drift_after_execution_blocks_seed_return(tmp_path):
    phases = []

    def pin_hook(phase, _command):
        phases.append(phase)
        if phase == "after_seed_process":
            raise ValueError("changed")

    adapter, ledger = _adapter(tmp_path, pin_hook=pin_hook)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator",
               return_value=[b"x"]):
        with pytest.raises(SeedSandboxError, match="source pin changed"):
            _generate(adapter)
    assert phases == ["before_seed_reserve", "after_seed_process"]
    assert ledger.snapshot()["stop_status"] == "STOPPED_PIN_DRIFT"


def test_bound_seed_docker_pins_reject_image_and_cli_drift(
        tmp_path, monkeypatch):
    docker = tmp_path / "docker"
    docker.write_bytes(b"pinned-cli")
    image_id = "sha256:" + "1" * 64
    cli_sha = hashlib.sha256(docker.read_bytes()).hexdigest()
    monkeypatch.setenv("FBV2_SEED_DOCKER_IMAGE_ID", image_id)
    monkeypatch.setenv("FBV2_SEED_DOCKER_CLI_SHA256", cli_sha)
    with patch("devtools.original_public_live.shutil.which",
               return_value=str(docker)):
        hook = _bound_seed_pin_hook(lambda _phase, _command: None)
        hook("before_seed_reserve", [])
        monkeypatch.setenv("FBV2_SEED_DOCKER_IMAGE_ID", "sha256:" + "2" * 64)
        with pytest.raises(ValueError, match="Docker identity changed"):
            hook("after_seed_process", [])
        monkeypatch.setenv("FBV2_SEED_DOCKER_IMAGE_ID", image_id)
        docker.write_bytes(b"replaced-cli")
        with pytest.raises(ValueError, match="Docker CLI identity changed"):
            hook("after_seed_process", [])


def test_seed_rejects_unqualified_direction_before_docker(tmp_path):
    adapter, ledger = _adapter(tmp_path)
    with patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator") as run:
        with pytest.raises(SeedSandboxError, match="identity changed"):
            _generate(adapter, direction_id="other")
        with pytest.raises(SeedSandboxError, match="identity changed"):
            _generate(adapter, task_id="other")
    run.assert_not_called()
    assert ledger.snapshot()["finished"] == []


def test_seed_tool_attempt_is_unique_and_no_corpus_before_settlement(tmp_path):
    manager = Mock()
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    manager.global_corpus_dir = corpus

    def save(data, direction_id):
        path = corpus / f"direction_{direction_id[:8]}_{hashlib.sha1(data).hexdigest()[:16]}"
        path.write_bytes(data)
        return path

    manager.add_direction_seed.side_effect = save
    account = Mock(side_effect=[[b"a"], [b"b"]])
    set_seed_context("task-1", "agent-1", direction_id="dir-1",
                     fuzzer_manager=manager, qualified_seed_generator=account,
                     qualified_seed_required=True)
    try:
        assert create_seed_impl("def generate(n): return b'a'",
                                worker_id="agent-1")["success"] is True
        assert create_seed_impl("def generate(n): return b'b'",
                                worker_id="agent-1")["success"] is True
    finally:
        clear_seed_context("agent-1")
    assert [call.kwargs["attempt"] for call in account.call_args_list] == [1, 2]
    assert manager.add_direction_seed.call_count == 2

    manager.reset_mock()
    set_seed_context("task-1", "agent-1", direction_id="dir-1",
                     fuzzer_manager=manager, qualified_seed_required=True)
    try:
        result = create_seed_impl("def generate(n): return b'x'",
                                  worker_id="agent-1")
    finally:
        clear_seed_context("agent-1")
    assert result["success"] is False
    assert "process account unavailable" in result["error"]
    manager.add_direction_seed.assert_not_called()


@pytest.mark.parametrize("failure,expected_saved", [
    ("all", 0), ("partial", 1), ("wrong_bytes", 0),
])
def test_seed_tool_counts_only_matching_persisted_corpus_entries(
        tmp_path, failure, expected_saved):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    manager = Mock()
    manager.global_corpus_dir = corpus

    def save(data, direction_id):
        if failure == "all" or failure == "partial" and data == b"a":
            raise OSError("write failed")
        path = corpus / f"direction_{direction_id[:8]}_{hashlib.sha1(data).hexdigest()[:16]}"
        path.write_bytes(b"wrong" if failure == "wrong_bytes" else data)
        return path

    manager.add_direction_seed.side_effect = save
    account = Mock(return_value=[b"a", b"b"] if failure != "wrong_bytes"
                   else [b"a"])
    set_seed_context("task-1", "agent-1", direction_id="dir-1",
                     fuzzer_manager=manager, qualified_seed_generator=account,
                     qualified_seed_required=True)
    try:
        result = create_seed_impl("def generate(n): return b'x'",
                                  num_seeds=2, worker_id="agent-1")
    finally:
        clear_seed_context("agent-1")
    assert result["success"] is (expected_saved > 0)
    assert result["seeds_generated"] == expected_saved
    assert len(result.get("seed_paths", [])) == expected_saved
    assert result["seed_save_failures"] == (
        2 - expected_saved if failure != "wrong_bytes" else 1)


@pytest.mark.parametrize("seed_type,context_id,expected_prefix,manager_method", [
    ("fp", "sp-123456", "fp_sp-12345_", "add_fp_seed"),
    ("delta", "delta-123456", "direction_delta_de_", "add_direction_seed"),
])
def test_fp_and_delta_seeds_verify_their_global_corpus_source(
        tmp_path, seed_type, context_id, expected_prefix, manager_method):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    manager = Mock()
    manager.global_corpus_dir = corpus

    def save(data, source_id):
        prefix = (f"fp_{source_id[:8]}_" if seed_type == "fp"
                  else f"direction_{source_id[:8]}_")
        path = corpus / (prefix + hashlib.sha1(data).hexdigest()[:16])
        path.write_bytes(data)
        return path

    getattr(manager, manager_method).side_effect = save
    context = ({"sp_id": context_id} if seed_type == "fp"
               else {"delta_id": context_id})
    set_seed_context("task-1", "agent-1", fuzzer_manager=manager, **context)
    try:
        # The public qualified account intentionally supports only Direction
        # Seeds. Exercise the original non-qualified FP/delta persistence path.
        with patch("fuzzingbrain.fuzzer.seed_tools.execute_seed_generator",
                   return_value=[b"x"]):
            result = create_seed_impl("def generate(n): return b'x'",
                                      num_seeds=1, seed_type=seed_type,
                                      worker_id="agent-1")
    finally:
        clear_seed_context("agent-1")
    assert result["success"] is True
    assert result["seeds_generated"] == 1
    assert Path(result["seed_paths"][0]).name.startswith(expected_prefix)


def test_public_global_bridge_actual_spool_is_counted_once(tmp_path):
    plan = tmp_path / "DIRECTION_PLAN.json"
    plan.write_text(json.dumps({"status": "COMPLETED",
                                "direction_ids": ["dir-1"]}))
    qualification = SimpleNamespace(
        product_issued=True,
        contract_kind="OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
        binary_sha256="b" * 64)
    campaign = SimpleNamespace(
        q=qualification, _authority_ok=lambda: True,
        stage_direction_seeds=lambda *_args: None,
        start=lambda: None, finish=lambda: None, abort=lambda: None,
        require_accounted_consumer=True, global_seconds=1,
        global_wall_reservation_seconds=2)
    bridge = OriginalGlobalBridge(
        campaign=campaign, direction_plan_path=plan,
        direction_plan_sha256=hashlib.sha256(plan.read_bytes()).hexdigest(),
        seed_spool=tmp_path / "spool", expected_binary_sha256="b" * 64)
    account = Mock(return_value=[b"bridge-seed"])
    set_seed_context("task-1", "agent-1", direction_id="dir-1",
                     fuzzer_manager=bridge, qualified_seed_generator=account,
                     qualified_seed_required=True)
    try:
        saved = create_seed_impl("def generate(n): return b'bridge-seed'",
                                 num_seeds=1, worker_id="agent-1")
        assert saved["success"] is True
        assert saved["seeds_generated"] == 1
        path = Path(saved["seed_paths"][0])
        assert path.parent == bridge.spool
        assert path.name == ("direction_dir-1_" +
                             hashlib.sha256(b"bridge-seed").hexdigest())
        assert path.read_bytes() == b"bridge-seed"
        bridge._start_attempted = True
        failed = create_seed_impl("def generate(n): return b'new-seed'",
                                  num_seeds=1, worker_id="agent-1")
        assert failed["success"] is False
        assert failed["seeds_generated"] == 0
        assert failed["seed_save_failures"] == 1
    finally:
        clear_seed_context("agent-1")
