"""A completed PoV search with no crash is a terminal negative result."""

import base64
from datetime import datetime
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId
import pytest

from fuzzingbrain.agents.pov_agent import POVResult
from fuzzingbrain.tools.qualified_runtime import QualifiedRuntimeBinding
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, require_injected_agent_complete,
)
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2


def _case(tmp_path):
    task_id, sp_id, agent_id = (str(ObjectId()) for _ in range(3))
    run_id = str(ObjectId())
    binary = tmp_path / "target"
    binary.write_bytes(b"target")
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "process-ledger.json", wall_total_seconds=100,
        fuzz_total_seconds=50)
    rows = []
    for variant in (1, 2, 3):
        pov_id = str(ObjectId())
        data = bytes([variant])
        root = tmp_path / pov_id
        root.mkdir()
        input_path = root / "input.bin"
        input_path.write_bytes(data)
        runtime = root / "runtime.json"
        physical = root / "physical.json"
        input_sha = hashlib.sha256(data).hexdigest()
        key = f"{task_id}:{sp_id}:{pov_id}:000000:pov.qualified_direct"
        ledger.reserve(key, "AUX_PROCESS", 19.5)
        lease = ledger.finish(key, physical_seconds=0.05,
                              cleanup_complete=True)
        identity = {"task_id": task_id, "run_id": run_id,
                    "work_item_id": task_id, "sp_id": sp_id,
                    "pov_id": pov_id, "input_sha256": input_sha,
                    "binary_sha256": binary_sha}
        physical.write_text(json.dumps({
            **identity, "kind": "FBV2_DEV_QUALIFIED_POV_PHYSICAL_V1",
            "input_path": str(input_path), "ledger_path": str(ledger.path),
            "lease": lease,
        }))
        runtime.write_text(json.dumps({
            **identity, "kind": "FBV2_DEV_QUALIFIED_POV_RUNTIME_V1",
            "status": "NO_CRASH", "source": "FBV2_POV",
            "command": [str(binary), str(input_path)],
            "input_path": str(input_path),
            "physical_receipt_sha256": hashlib.sha256(
                physical.read_bytes()).hexdigest(),
            "runtime": {"exit_code": 0, "timed_out": False,
                        "sanitizer": None},
        }))
        rows.append({
            "_id": ObjectId(pov_id), "pov_id": pov_id,
            "task_id": ObjectId(task_id),
            "suspicious_point_id": ObjectId(sp_id),
            "agent_id": ObjectId(agent_id), "attempt": 1,
            "variant": variant, "harness_name": "fuzz-mdhtml",
            "sanitizer": "address", "is_successful": False,
            "is_active": True,
            "blob": base64.b64encode(data).decode(),
            "qualified_runtime": {
                "status": "NO_CRASH",
                "input_sha256": input_sha,
                "binary_sha256": binary_sha,
                "runtime_receipt_path": str(runtime),
                "runtime_receipt_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                "physical_receipt_path": str(physical),
                "physical_receipt_sha256": hashlib.sha256(physical.read_bytes()).hexdigest(),
                "sanitizer": None,
            },
        })

    class Collection:
        def find(self, query):
            return [row for row in rows if all(row.get(k) == v
                                                for k, v in query.items())]

    pipeline = AgentPipeline.__new__(AgentPipeline)
    pipeline.task_id = task_id
    pipeline.fuzzer = "fuzz-mdhtml"
    pipeline.sanitizer = "address"
    pipeline.llm_client_factory = object()
    pipeline.repos = SimpleNamespace(povs=SimpleNamespace(collection=Collection()))
    class Adapter:
        def execute(self, _):
            raise AssertionError("no physical execution in this test")

    adapter = Adapter()
    adapter.task_id = task_id
    adapter.run_id = run_id
    adapter.work_item_id = task_id
    adapter.fuzzer = pipeline.fuzzer
    adapter.sanitizer = pipeline.sanitizer
    adapter.repos = pipeline.repos
    adapter.root = tmp_path
    adapter.ledger = ledger
    adapter.binding = QualifiedRuntimeBinding(object(), adapter.execute)
    pipeline.qualified_runtime_binding = adapter.binding
    sp = SimpleNamespace(suspicious_point_id=sp_id)
    result = POVResult(suspicious_point_id=sp_id, task_id=task_id,
                       pov_attempts=1, total_variants=3, completed_at=datetime.now())
    agent = SimpleNamespace(stop_reason=None, max_pov_attempts=1,
                            total_tool_calls=1,
                            mcp_context_id=agent_id)
    return pipeline, sp, result, agent, rows, binary, binary_sha


def test_receipt_backed_exhaustion_is_a_clean_no_crash_terminal(tmp_path):
    pipeline, sp, result, agent, rows, binary, binary_sha = _case(tmp_path)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(binary, binary_sha)):
        count = pipeline._qualified_no_crash_input_count(sp, result, agent)
        assert count == 3
        require_injected_agent_complete(
            SimpleNamespace(last_agent_response_was_final=False), agent,
            tool_success=bool(count))


def test_failed_generation_leaves_a_valid_attempt_number_gap(tmp_path):
    pipeline, sp, result, agent, rows, binary, binary_sha = _case(tmp_path)
    agent.total_tool_calls = 2
    for row in rows:
        row["attempt"] = 2  # create_pov call 1 failed before any input was saved
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(binary, binary_sha)):
        assert pipeline._qualified_no_crash_input_count(sp, result, agent) == 3
        agent.total_tool_calls = 3
        rows[0]["attempt"] = 3  # a partial second batch is not a clean terminal
        assert pipeline._qualified_no_crash_input_count(sp, result, agent) == 0


def test_own_global_reservation_does_not_hide_finished_pov_inputs(tmp_path):
    pipeline, sp, result, agent, rows, binary, binary_sha = _case(tmp_path)
    adapter = pipeline.qualified_runtime_binding.execute.__self__
    key = f"GLOBAL_FUZZ:{pipeline.task_id}:{adapter.run_id}"
    adapter.ledger.reserve(key, "GLOBAL_FUZZ", 45.0)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(binary, binary_sha)):
        assert pipeline._qualified_no_crash_input_count(sp, result, agent) == 3
        require_injected_agent_complete(
            SimpleNamespace(last_agent_response_was_final=False), agent,
            tool_success=True)
    adapter.ledger.finish(key, physical_seconds=1.0,
                          cleanup_complete=True)


def test_parallel_foreign_reservation_does_not_hide_own_finished_receipts(tmp_path):
    pipeline, sp, result, agent, rows, binary, binary_sha = _case(tmp_path)
    adapter = pipeline.qualified_runtime_binding.execute.__self__
    adapter.ledger.reserve("GLOBAL_FUZZ:another-task:another-run",
                           "GLOBAL_FUZZ", 1.0)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(binary, binary_sha)):
        assert pipeline._qualified_no_crash_input_count(sp, result, agent) == 3


def test_parallel_pov_process_does_not_hide_own_finished_receipts(tmp_path):
    pipeline, sp, result, agent, rows, binary, binary_sha = _case(tmp_path)
    adapter = pipeline.qualified_runtime_binding.execute.__self__
    adapter.ledger.reserve("another-pov", "AUX_PROCESS", 1.0)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(binary, binary_sha)):
        assert pipeline._qualified_no_crash_input_count(sp, result, agent) == 3


def test_active_lease_for_same_pov_blocks_terminal_receipt(tmp_path):
    pipeline, sp, result, agent, rows, binary, binary_sha = _case(tmp_path)
    adapter = pipeline.qualified_runtime_binding.execute.__self__
    adapter.ledger.reserve(
        f"{pipeline.task_id}:{sp.suspicious_point_id}:"
        f"{rows[0]['pov_id']}:999999:pov.qualified_direct",
        "AUX_PROCESS", 1.0)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(binary, binary_sha)):
        assert pipeline._qualified_no_crash_input_count(sp, result, agent) == 0


@pytest.mark.parametrize("change", [
    "missing_input", "tampered_receipt", "pending_runtime", "model_error",
    "fake_receipt", "wrong_command", "unowned_lease",
])
def test_incomplete_or_changed_no_crash_evidence_stays_incomplete(tmp_path, change):
    pipeline, sp, result, agent, rows, binary, binary_sha = _case(tmp_path)
    if change == "missing_input":
        rows.pop()
    elif change == "tampered_receipt":
        rows[0]["qualified_runtime"]["physical_receipt_sha256"] = "0" * 64
    elif change == "pending_runtime":
        rows[0]["qualified_runtime"]["status"] = "PENDING_QUALIFIED_RUNTIME"
    elif change == "model_error":
        agent.stop_reason = "llm_error"
    elif change == "fake_receipt":
        path = tmp_path / rows[0]["pov_id"] / "runtime.json"
        path.write_bytes(b"runtime")
        rows[0]["qualified_runtime"]["runtime_receipt_sha256"] = \
            hashlib.sha256(path.read_bytes()).hexdigest()
    elif change == "wrong_command":
        path = tmp_path / rows[0]["pov_id"] / "runtime.json"
        value = json.loads(path.read_bytes())
        value["command"] = ["/tmp/other", value["input_path"]]
        path.write_text(json.dumps(value))
        rows[0]["qualified_runtime"]["runtime_receipt_sha256"] = \
            hashlib.sha256(path.read_bytes()).hexdigest()
    elif change == "unowned_lease":
        path = tmp_path / rows[0]["pov_id"] / "physical.json"
        value = json.loads(path.read_bytes())
        value["lease"]["key"] = value["lease"]["key"].replace(
            ":000000:", ":999999:")
        path.write_text(json.dumps(value))
        rows[0]["qualified_runtime"]["physical_receipt_sha256"] = \
            hashlib.sha256(path.read_bytes()).hexdigest()
        runtime_path = tmp_path / rows[0]["pov_id"] / "runtime.json"
        runtime = json.loads(runtime_path.read_bytes())
        runtime["physical_receipt_sha256"] = \
            rows[0]["qualified_runtime"]["physical_receipt_sha256"]
        runtime_path.write_text(json.dumps(runtime))
        rows[0]["qualified_runtime"]["runtime_receipt_sha256"] = \
            hashlib.sha256(runtime_path.read_bytes()).hexdigest()
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(binary, binary_sha)):
        count = pipeline._qualified_no_crash_input_count(sp, result, agent)
    assert count == 0
    with pytest.raises(IncompleteInjectedAgent):
        require_injected_agent_complete(
            SimpleNamespace(last_agent_response_was_final=False), agent,
            tool_success=bool(count))
