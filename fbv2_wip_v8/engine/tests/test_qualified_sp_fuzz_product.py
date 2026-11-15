"""Provider-free V2 process accounting for the qualified SP Fuzzer handoff."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId
import mongomock
import pytest

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from devtools.product_qualified_runtime import (
    ProductQualifiedPoVAdapter, run_qualified_sp_fuzz)


def _sp_fuzz_envelope_type():
    # The frozen Global fixture imports an older same-named module first when
    # pytest collects the whole suite. Load this test's current SP contract
    # directly without changing the shared module cache used by that fixture.
    source = (Path(__file__).resolve().parents[2] /
              "evaluation_tools/dev_process_envelope_v2.py")
    spec = importlib.util.spec_from_file_location(
        "_fbv2_sp_fuzz_process_envelope_v2", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module.DevelopmentProcessEnvelopeV2


@pytest.mark.parametrize("mode", ["ran", "timeout_crash"])
def test_product_sp_fuzz_uses_shared_v2_aux_and_sp_debits(tmp_path, mode):
    from vulnerabilityanalysis import official_harness, runtime
    from devtools import product_qualified_runtime as handoff

    task_id, sp_id, pov_id = (str(ObjectId()) for _ in range(3))
    binary = tmp_path / "fuzzer"
    binary.write_bytes(b"provider-free fuzzer fixture")
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    source = tmp_path / "source"
    source.mkdir()
    harness = source / "harness.c"
    harness.write_text("/* controlled */")
    q = SimpleNamespace(source_tree_sha256="1" * 64,
                        harness_sha256="2" * 64,
                        contract_sha256="3" * 64,
                        source_root=source, harness=harness)
    root = tmp_path / "attempts"
    root.mkdir()
    attempt = root / pov_id
    attempt.mkdir()
    raw = b"ordinary corpus input"
    inp = attempt / "input.bin"
    inp.write_bytes(raw)
    inp.chmod(0o600)
    input_sha = hashlib.sha256(raw).hexdigest()
    database = mongomock.MongoClient().sp_fuzz_v2
    database.povs.insert_one({
        "_id": ObjectId(pov_id), "task_id": ObjectId(task_id),
        "suspicious_point_id": ObjectId(sp_id), "source": "agent",
        "qualified_runtime": {"status": "NO_CRASH",
                              "input_sha256": input_sha,
                              "binary_sha256": binary_sha}})
    adapter = object.__new__(ProductQualifiedPoVAdapter)
    adapter.binding = SimpleNamespace(qualification=q,
                                      pinned_binary=lambda: (binary, binary_sha))
    adapter.repos = SimpleNamespace(povs=SimpleNamespace(collection=database.povs))
    adapter.task_id, adapter.run_id = task_id, "run_fixture"
    adapter.root = root
    adapter.ledger = PersistentProcessLedgerV2.create(
        tmp_path / "physical.json", wall_total_seconds=120,
        fuzz_total_seconds=60)
    adapter._envelope_type = _sp_fuzz_envelope_type()
    adapter.output_limit_bytes = 4096
    lineage = {
        "status": "VERIFIED", "runtime_status": "NO_CRASH",
        "task_id": task_id, "run_id": adapter.run_id, "sp_id": sp_id,
        "direction_id": "direction_fixture", "pov_id": pov_id,
        "input_sha256": input_sha, "binary_sha256": binary_sha,
        "source_tree_sha256": q.source_tree_sha256,
        "harness_sha256": q.harness_sha256,
        "contract_sha256": q.contract_sha256,
    }
    launches = []

    def wire(command, **kwargs):
        launches.append(command)
        if "-help=1" in command:
            return subprocess.CompletedProcess(command, 0, "max_total_time", "")
        if mode == "timeout_crash":
            (Path(kwargs["cwd"]) / "crash-controlled").write_bytes(
                b"controlled timeout witness")
            raise subprocess.TimeoutExpired(
                command, kwargs["timeout"], stderr=b"#2 NEW cov: 3 ft: 3\n")
        return subprocess.CompletedProcess(command, 0, "", "#2 NEW cov: 3 ft: 3\n")

    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(official_harness, "_qualification_pins_ok",
                      return_value=True), \
         patch.object(handoff, "verify_qualified_pov_runtime_lineage",
                      return_value=lineage), \
         patch.object(runtime, "_guarded_run_once", side_effect=wire):
        result = run_qualified_sp_fuzz(
            adapter, pov_id, SimpleNamespace(snapshot=lambda: {}),
            recheck=lambda: None, seconds=1, fuzz_wall_seconds=40,
            replay_limit=0)
    state = adapter.ledger.snapshot()
    assert result["status"] == (
        "INCOMPLETE_FUZZ_WITH_OBSERVED_CRASH" if mode == "timeout_crash"
        else "EXECUTED")
    assert result["automatic_discovery"] is False
    assert len(launches) == len(state["finished"]) == 2
    assert [row["kind"] for row in state["finished"]] == [
        "AUX_PROCESS", "SP_FUZZ"]
    assert state["active"] == {}
    assert state["fuzz_spent_seconds"] > 0
    assert json.loads((tmp_path / "sp-fuzz-claims" / sp_id /
                       "outcome.json").read_text())["status"] == result["status"]
    if mode == "timeout_crash":
        assert result["fuzzer_status"] == "TIMED_OUT"
        assert len(result["crash_ids"]) == 1
        assert result["consumer_rows"] == [{
            "status": "PENDING_REPLAY_LIMIT",
            "input_sha256": hashlib.sha256(
                b"controlled timeout witness").hexdigest()}]
