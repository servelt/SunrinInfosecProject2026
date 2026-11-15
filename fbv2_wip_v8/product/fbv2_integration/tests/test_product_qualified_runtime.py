"""Provider-free contract tests for the development-only product PoV adapter."""

import base64
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import mongomock
import pytest
from bson import ObjectId
from pymongo import MongoClient
from pymongo.monitoring import CommandListener

from fuzzingbrain.core.models import POV, SPStatus, SuspiciousPoint
from fuzzingbrain.core.utils import generate_id
from fuzzingbrain.db.repository import RepositoryManager
from fuzzingbrain.tools.qualified_runtime import (
    QualifiedRuntimeBinding, QualifiedRuntimeRequest, validate_outcome,
)


PRODUCT_SRC = Path("/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src")
EVAL_TOOLS = Path("/home/dawne/work/SunrinInfosecProject2026/"
                  "fbv2_eval_dev/evaluation_tools")
for source in (PRODUCT_SRC, EVAL_TOOLS):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from devtools.product_qualified_runtime import (
    ProductQualifiedPoVAdapter, _gate_trace_summary,
    consume_qualified_pov_observation, verify_qualified_pov_runtime_lineage,
    run_qualified_sp_fuzz,
)


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _ready(tmp_path, *, ledger_wall=60, database=None):
    repos = RepositoryManager(
        database if database is not None else
        mongomock.MongoClient().qualified_product_runtime)
    task_id, sp_id = generate_id(), generate_id()
    point = SuspiciousPoint(
        suspicious_point_id=sp_id, task_id=task_id, function_name="target",
        sources=[{"harness_name": "fuzz_fixture", "sanitizer": "address"}],
        status=SPStatus.PENDING_POV.value, score=0.9)
    assert repos.suspicious_points.save(point)
    assert repos.suspicious_points.claim_for_pov(
        task_id, "pov_agent", harness_name="fuzz_fixture", sanitizer="address")
    binary = tmp_path / "fuzzer"
    binary.write_bytes(b"synthetic pinned binary")
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "physical.json", wall_total_seconds=ledger_wall,
        fuzz_total_seconds=0)
    adapter = ProductQualifiedPoVAdapter(
        qualification=object(), repos=repos, task_id=task_id,
        work_item_id="work_1", run_id="run_1", fuzzer="fuzz_fixture",
        sanitizer="address", ledger=ledger, output_dir=tmp_path / "attempts",
        timeout_seconds=2, wall_seconds=15, output_limit_bytes=4096)
    request = QualifiedRuntimeRequest(
        task_id=task_id, suspicious_point_id=sp_id, pov_id=generate_id(),
        harness_name="fuzz_fixture", sanitizer="address",
        input_bytes=b"valid corpus input", input_sha256=hashlib.sha256(
            b"valid corpus input").hexdigest(), binary_path=binary,
        binary_sha256=_sha(binary))
    assert repos.povs.save(POV(
        pov_id=request.pov_id, task_id=task_id, suspicious_point_id=sp_id,
        harness_name="fuzz_fixture", sanitizer="address",
        blob=base64.b64encode(request.input_bytes).decode("ascii")))
    assert repos.povs.collection.update_one(
        {"_id": ObjectId(request.pov_id)},
        {"$set": {"qualified_runtime": {
            "status": "STARTED", "input_sha256": request.input_sha256,
            "binary_sha256": request.binary_sha256}}}).modified_count == 1
    return adapter, request, ledger, binary


def test_gate_call_boundary_is_not_reported_as_completed_invocation():
    trace = {
        "crash_id": "crash-one", "security_property_attempted": True,
        "security_property_evaluated": True,
        "security_property_state": "COMPLETED",
        "promotion_attempted": True, "promotion_state": "STARTED",
        "promotion_result": None, "promotion_error_type": None,
    }
    gate = {"independent_verification_status": "PENDING",
            "independent_gate_trace": trace}
    started = _gate_trace_summary(gate, "crash-one", canonical_exists=True)
    assert started["security_gate_invoked"] is None
    assert started["security_gate_completed"] is False
    assert started["security_gate_result"] is None
    trace["promotion_state"] = "INCOMPLETE"
    trace["promotion_error_type"] = "RuntimeError"
    interrupted = _gate_trace_summary(gate, "crash-one", canonical_exists=True)
    assert interrupted["security_gate_invoked"] is True
    assert interrupted["security_gate_completed"] is False
    trace["promotion_result"] = True
    with pytest.raises(ValueError, match="Gate trace changed"):
        _gate_trace_summary(gate, "crash-one", canonical_exists=True)
    trace["promotion_state"] = "COMPLETED"
    trace["promotion_error_type"] = None
    gate["independent_verification_status"] = "VERIFIED"
    completed = _gate_trace_summary(gate, "crash-one", canonical_exists=True)
    assert completed["security_gate_invoked"] is True
    assert completed["security_gate_completed"] is True
    assert completed["security_gate_result"] is True


@pytest.fixture
def pinned_binary(monkeypatch, tmp_path):
    # Product qualification issuance itself is tested by the product suite.
    # This fixture substitutes only the immutable issued token check; the
    # product Runtime and durable physical ledger execute their real code.
    binary = tmp_path / "fuzzer"
    monkeypatch.setattr(
        QualifiedRuntimeBinding, "pinned_binary",
        lambda self: (binary, _sha(binary)))


def test_product_runtime_observation_has_one_durable_physical_debit(
        tmp_path, pinned_binary):
    adapter, request, ledger, binary = _ready(tmp_path)
    launches = []

    def wire(command, **_kwargs):
        launches.append(command)
        assert command == [str(binary), str((adapter.root / request.pov_id /
                                              "input.bin").resolve())]
        assert len(ledger.snapshot()["active"]) == 1
        assert ledger.path.is_file()
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch("vulnerabilityanalysis.runtime._guarded_run_once", side_effect=wire):
        outcome = adapter.execute(request)
    validate_outcome(outcome, request)
    assert outcome.status == "NO_CRASH"
    assert len(launches) == 1
    state = ledger.snapshot()
    assert state["active"] == {}
    assert len(state["finished"]) == 1
    assert state["finished"][0]["cleanup_complete"] is True
    physical = json.loads(outcome.physical_receipt_path.read_text())
    runtime = json.loads(outcome.runtime_receipt_path.read_text())
    assert physical["input_sha256"] == runtime["input_sha256"] == request.input_sha256
    assert physical["ledger_sha256"] == _sha(ledger.path)
    assert runtime["physical_receipt_sha256"] == outcome.physical_receipt_sha256
    with pytest.raises(RuntimeError, match="no resend"):
        adapter.execute(request)
    assert len(launches) == 1
    assert len(ledger.snapshot()["finished"]) == 1


def test_postrun_lineage_requires_same_input_and_runtime_receipts(
        tmp_path, pinned_binary):
    from vulnerabilityanalysis import official_harness
    adapter, request, ledger, binary = _ready(tmp_path)
    fake_q = SimpleNamespace(
        source_tree_sha256="1" * 64, harness_sha256="2" * 64,
        contract_sha256="3" * 64)
    adapter.binding = QualifiedRuntimeBinding(fake_q, adapter.execute)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess([], 0, "", "")):
        outcome = adapter.execute(request)
    adapter.repos.povs.collection.update_one(
        {"_id": ObjectId(request.pov_id)},
        {"$set": {"qualified_runtime": {
            "status": outcome.status,
            "input_sha256": outcome.input_sha256,
            "binary_sha256": outcome.binary_sha256,
            "runtime_receipt_path": str(outcome.runtime_receipt_path),
            "runtime_receipt_sha256": outcome.runtime_receipt_sha256,
            "physical_receipt_path": str(outcome.physical_receipt_path),
            "physical_receipt_sha256": outcome.physical_receipt_sha256}}})
    candidate = {
        "status": "VERIFIED", "campaign_id": adapter.run_id,
        "task_id": adapter.task_id, "sp_id": request.suspicious_point_id,
        "direction_id": generate_id(),
        "model_tool_turns": [{"role": role} for role in
                             ("sp", "verifier", "pov")],
        "pov_inputs": [{"pov_id": request.pov_id,
                        "input_sha256": request.input_sha256}]}
    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(official_harness, "_qualification_pins_ok",
                      return_value=True), \
         patch("devtools.model_candidate_lineage.find_candidate_lineage",
               return_value=candidate) as lineage_lookup:
        verified = verify_qualified_pov_runtime_lineage(
            adapter, request.pov_id, SimpleNamespace(snapshot=lambda: {}),
            recheck=lambda: None)
        assert verified["status"] == "VERIFIED"
        assert verified["runtime_status"] == "NO_CRASH"
        assert verified["discovery_credit"] == "NOT_CREDITED_BY_LINEAGE_ONLY"
        changed = dict(candidate, pov_inputs=[{
            "pov_id": request.pov_id, "input_sha256": "0" * 64}])
        lineage_lookup.return_value = changed
        assert verify_qualified_pov_runtime_lineage(
            adapter, request.pov_id, SimpleNamespace(snapshot=lambda: {}),
            recheck=lambda: None)["status"] == "UNPROVEN"
        lineage_lookup.return_value = candidate
        adapter.repos.povs.collection.update_one(
            {"_id": ObjectId(request.pov_id)},
            {"$set": {"harness_name": "different_harness"}})
        assert verify_qualified_pov_runtime_lineage(
            adapter, request.pov_id, SimpleNamespace(snapshot=lambda: {}),
            recheck=lambda: None)["status"] == "UNPROVEN"
        adapter.repos.povs.collection.update_one(
            {"_id": ObjectId(request.pov_id)},
            {"$set": {"harness_name": adapter.fuzzer}})
        runtime = json.loads(outcome.runtime_receipt_path.read_text())
        runtime["work_item_id"] = "different_work_item"
        outcome.runtime_receipt_path.write_text(json.dumps(runtime))
        adapter.repos.povs.collection.update_one(
            {"_id": ObjectId(request.pov_id)},
            {"$set": {"qualified_runtime.runtime_receipt_sha256":
                      _sha(outcome.runtime_receipt_path)}})
        assert verify_qualified_pov_runtime_lineage(
            adapter, request.pov_id, SimpleNamespace(snapshot=lambda: {}),
            recheck=lambda: None)["status"] == "UNPROVEN"
        runtime["work_item_id"] = adapter.work_item_id
        physical = json.loads(outcome.physical_receipt_path.read_text())
        physical["lease"]["key"] = "other:work:item:000000:pov.qualified_direct"
        outcome.physical_receipt_path.write_text(json.dumps(physical))
        runtime["physical_receipt_sha256"] = _sha(outcome.physical_receipt_path)
        outcome.runtime_receipt_path.write_text(json.dumps(runtime))
        adapter.repos.povs.collection.update_one(
            {"_id": ObjectId(request.pov_id)},
            {"$set": {
                "qualified_runtime.physical_receipt_sha256":
                    _sha(outcome.physical_receipt_path),
                "qualified_runtime.runtime_receipt_sha256":
                    _sha(outcome.runtime_receipt_path)}})
        with patch.object(ledger, "snapshot",
                          return_value={"finished": [physical["lease"]]}):
            assert verify_qualified_pov_runtime_lineage(
                adapter, request.pov_id, SimpleNamespace(snapshot=lambda: {}),
                recheck=lambda: None)["status"] == "UNPROVEN"
    assert len(ledger.snapshot()["finished"]) == 1


@pytest.mark.parametrize("new_work_item", ["work_1", "work_2"])
def test_new_run_id_cannot_resend_same_pov_on_shared_ledger(
        tmp_path, pinned_binary, new_work_item):
    adapter, request, ledger, _ = _ready(tmp_path)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess([], 0, "", "")) as wire:
        first = adapter.execute(request)
    assert first.status == "NO_CRASH"
    assert wire.call_count == 1
    fresh = ProductQualifiedPoVAdapter(
        qualification=object(), repos=adapter.repos, task_id=adapter.task_id,
        work_item_id=new_work_item, run_id="run_2",
        fuzzer=adapter.fuzzer, sanitizer=adapter.sanitizer, ledger=ledger,
        output_dir=tmp_path / "fresh-run-attempts", timeout_seconds=2,
        wall_seconds=15, output_limit_bytes=4096)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once") as wire:
        with pytest.raises(RuntimeError, match="no resend"):
            fresh.execute(request)
        wire.assert_not_called()
    assert list(fresh.root.iterdir()) == []
    assert len(ledger.snapshot()["finished"]) == 1


@pytest.mark.parametrize("settled_status", ["STARTED", "NO_CRASH", "INCOMPLETE"])
def test_fresh_ledger_cannot_resend_saved_pov_after_db_claim(
        tmp_path, pinned_binary, settled_status):
    adapter, request, original_ledger, _ = _ready(tmp_path)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess([], 0, "", "")) as wire:
        assert adapter.execute(request).status == "NO_CRASH"
    assert wire.call_count == 1
    if settled_status != "STARTED":
        # The original pov.py replaces the STARTED subdocument after a
        # completed outcome, or changes status in-place after failure.
        adapter.repos.povs.collection.update_one(
            {"_id": ObjectId(request.pov_id)},
            {"$set": {"qualified_runtime": {
                "status": settled_status,
                "input_sha256": request.input_sha256,
                "binary_sha256": request.binary_sha256}}})
    fresh_ledger = PersistentProcessLedgerV2.create(
        tmp_path / "fresh-physical.json", wall_total_seconds=60,
        fuzz_total_seconds=0)
    fresh = ProductQualifiedPoVAdapter(
        qualification=object(), repos=adapter.repos, task_id=adapter.task_id,
        work_item_id="another_work", run_id="another_run",
        fuzzer=adapter.fuzzer, sanitizer=adapter.sanitizer,
        ledger=fresh_ledger, output_dir=tmp_path / "fresh-attempts",
        timeout_seconds=2, wall_seconds=15, output_limit_bytes=4096)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once") as wire:
        with pytest.raises(RuntimeError, match="no resend"):
            fresh.execute(request)
        wire.assert_not_called()
    assert fresh_ledger.snapshot()["finished"] == []
    assert list(fresh.root.iterdir()) == []
    assert len(original_ledger.snapshot()["finished"]) == 1


class _ClaimWriteListener(CommandListener):
    def __init__(self):
        self.updates = []

    def started(self, event):
        if event.command_name == "update" and event.command.get("update") == "povs":
            self.updates.append(dict(event.command))

    def succeeded(self, event):
        pass

    def failed(self, event):
        pass


def test_real_mongo_journaled_claim_survives_new_client_and_ledger(
        tmp_path, pinned_binary):
    """Optional localhost Mongo integration; never launches a real Target."""
    listener = _ClaimWriteListener()
    first_client = MongoClient(
        "mongodb://127.0.0.1:27027/?directConnection=true",
        serverSelectionTimeoutMS=500, event_listeners=[listener])
    try:
        first_client.admin.command("ping")
    except Exception as exc:
        first_client.close()
        pytest.skip(f"local development MongoDB unavailable: {type(exc).__name__}")
    db_name = "fbv2_qualified_cas_" + uuid4().hex
    second_client = None
    try:
        adapter, request, old_ledger, _ = _ready(
            tmp_path, database=first_client[db_name])
        with patch("vulnerabilityanalysis.runtime._guarded_run_once",
                   return_value=subprocess.CompletedProcess([], 0, "", "")) as wire:
            assert adapter.execute(request).status == "NO_CRASH"
            assert wire.call_count == 1
        assert len(old_ledger.snapshot()["finished"]) == 1
        claims = [command for command in listener.updates if any(
            "qualified_runtime.adapter_claim" in update.get("u", {}).get("$set", {})
            for update in command.get("updates", []))]
        assert len(claims) == 1
        assert claims[0].get("writeConcern") == {"w": 1, "j": True}
        first_client.close()  # Simulate a new adapter process/client.
        second_client = MongoClient(
            "mongodb://127.0.0.1:27027/?directConnection=true",
            serverSelectionTimeoutMS=500)
        saved = second_client[db_name].povs.find_one(
            {"_id": ObjectId(request.pov_id)})["qualified_runtime"]
        assert saved["adapter_claim"]["pov_id"] == request.pov_id
        fresh_ledger = PersistentProcessLedgerV2.create(
            tmp_path / "brand-new-physical.json", wall_total_seconds=60,
            fuzz_total_seconds=0)
        fresh = ProductQualifiedPoVAdapter(
            qualification=object(),
            repos=RepositoryManager(second_client[db_name]),
            task_id=adapter.task_id, work_item_id="different_work",
            run_id="different_run", fuzzer=adapter.fuzzer,
            sanitizer=adapter.sanitizer, ledger=fresh_ledger,
            output_dir=tmp_path / "brand-new-attempts", timeout_seconds=2,
            wall_seconds=15, output_limit_bytes=4096)
        with patch("vulnerabilityanalysis.runtime._guarded_run_once") as wire:
            with pytest.raises(RuntimeError, match="no resend"):
                fresh.execute(request)
            wire.assert_not_called()
        assert fresh_ledger.snapshot()["finished"] == []
        assert list(fresh.root.iterdir()) == []
    finally:
        # This test owns only the unique database name it created.
        cleaner = second_client if second_client is not None else MongoClient(
            "mongodb://127.0.0.1:27027/?directConnection=true",
            serverSelectionTimeoutMS=500)
        try:
            cleaner.drop_database(db_name)
        finally:
            cleaner.close()
            first_client.close()


def test_unqualified_or_wrong_sp_rejected_before_target(
        tmp_path, pinned_binary):
    adapter, request, ledger, _ = _ready(tmp_path)
    from dataclasses import replace
    with pytest.raises(ValueError, match="SP is not an eligible"):
        adapter.execute(replace(request, suspicious_point_id=generate_id()))
    with pytest.raises(ValueError, match="identity or input"):
        adapter.execute(replace(request, input_bytes=b"changed"))
    assert ledger.snapshot()["finished"] == []
    assert list(adapter.root.iterdir()) == []


def test_budget_refusal_makes_no_target_start_or_success_receipt(
        tmp_path, pinned_binary):
    adapter, request, ledger, _ = _ready(tmp_path, ledger_wall=1)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once") as wire:
        with pytest.raises(Exception, match="prelaunch reservation"):
            adapter.execute(request)
        wire.assert_not_called()
    assert ledger.snapshot()["finished"] == []
    assert not (adapter.root / request.pov_id / "runtime.json").exists()


def test_product_runtime_crash_is_observation_not_gate_verdict(
        tmp_path, pinned_binary):
    adapter, request, ledger, _ = _ready(tmp_path)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess(
                   [], 1, "", "ERROR: AddressSanitizer: heap-buffer-overflow\n"
                   "#0 0x1 in target /tmp/target.c:1:1\n")):
        outcome = adapter.execute(request)
    validate_outcome(outcome, request)
    assert outcome.status == "CRASH_OBSERVED"
    assert outcome.sanitizer is not None
    assert len(ledger.snapshot()["finished"]) == 1
    runtime = json.loads(outcome.runtime_receipt_path.read_text())
    assert runtime["status"] == "CRASH_OBSERVED"
    assert "VERIFIED" not in runtime


@pytest.mark.parametrize("lineage_case", [
    "absent", "verified", "wrong_input", "tampered_receipt"])
def test_observed_pov_uses_same_ledger_for_product_gate_and_cannot_resend(
        tmp_path, pinned_binary, lineage_case):
    """The FBv2 PoV crash crosses into the existing product verdict path."""
    from vulnerabilityanalysis.models import RuntimeResult
    from vulnerabilityanalysis.final_verification import crash_fingerprint
    from vulnerabilityanalysis import official_harness
    from vulnerabilityanalysis import scan

    adapter, request, ledger, binary = _ready(tmp_path)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess(
                   [], 1, "", "ERROR: AddressSanitizer: heap-buffer-overflow\n"
                   "#0 0x1 in target /tmp/target.c:1:1\n")):
        first = adapter.execute(request)
    assert first.status == "CRASH_OBSERVED"
    adapter.repos.povs.collection.update_one(
        {"_id": ObjectId(request.pov_id)},
        {"$set": {"qualified_runtime": {
            "status": first.status,
            "input_sha256": first.input_sha256,
            "binary_sha256": first.binary_sha256,
            "runtime_receipt_path": str(first.runtime_receipt_path),
            "runtime_receipt_sha256": first.runtime_receipt_sha256,
            "physical_receipt_path": str(first.physical_receipt_path),
            "physical_receipt_sha256": first.physical_receipt_sha256,
        }}})
    harness = tmp_path / "harness.c"
    harness.write_text("// provider-free fixture\n")
    fake_q = SimpleNamespace(
        source_root=tmp_path, harness=harness,
        source_tree_sha256="1" * 64, harness_sha256="2" * 64,
        contract_sha256="3" * 64)
    adapter.binding = QualifiedRuntimeBinding(fake_q, adapter.execute)
    calls = []
    model_gate = None if lineage_case == "absent" else object()
    lineage = {
        "status": "VERIFIED", "task_id": adapter.task_id,
        "run_id": adapter.run_id,
        "sp_id": request.suspicious_point_id, "pov_id": request.pov_id,
        "direction_id": generate_id(),
        "model_tool_turns": [{"role": role} for role in
                             ("sp", "verifier", "pov")],
        "input_sha256": ("0" * 64 if lineage_case == "wrong_input"
                         else request.input_sha256),
        "binary_sha256": first.binary_sha256,
        "source_tree_sha256": fake_q.source_tree_sha256,
        "harness_sha256": fake_q.harness_sha256,
        "contract_sha256": fake_q.contract_sha256,
    }

    def fake_product_gate(poc, point, command, run_dir, **kwargs):
        calls.append((poc, point, command, run_dir, kwargs))
        assert kwargs["process_envelope"].ledger is ledger
        assert Path(poc.generated_input).read_bytes() == request.input_bytes
        assert command == [str(binary), "{input}"]
        assert kwargs["official_qualification"] is fake_q
        result = RuntimeResult(**json.loads(first.runtime_receipt_path.read_text())[
            "runtime"])
        runtime_dir = run_dir / "runtime"
        (runtime_dir / "crashes").mkdir(parents=True)
        (runtime_dir / f"{poc.poc_id}.json").write_text(json.dumps(asdict(result)))
        crash_id = crash_fingerprint(result)
        (runtime_dir / "crashes" / f"{crash_id}.json").write_text(json.dumps({
            "independent_verification_status":
                "BLOCKED_VERIFIED_GATE",
            "independent_gate_trace": {
                "crash_id": crash_id,
                "security_property_attempted": True,
                "security_property_evaluated": True,
                "security_property_state": "COMPLETED",
                "promotion_attempted": True,
                "promotion_state": "COMPLETED",
                "promotion_result": False,
                "promotion_error_type": None,
            }}))
        if lineage_case == "tampered_receipt":
            (run_dir.parent / "origin-lineage.json").write_text("tampered\n")
        return []

    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(scan, "execute_poc", side_effect=fake_product_gate), \
         patch("devtools.product_qualified_runtime."
               "verify_qualified_pov_runtime_lineage",
               return_value=lineage) as verify_lineage:
        if lineage_case == "tampered_receipt":
            with pytest.raises(ValueError,
                               match="origin lineage changed during product replay"):
                consume_qualified_pov_observation(
                    adapter, request.pov_id, recheck=lambda: None,
                    timeout_seconds=2, model_gate=model_gate)
            claim = adapter.root.parent / "pov-validation" / request.pov_id
            assert (claim / "incomplete.json").is_file()
            assert not (claim / "outcome.json").exists()
            return
        row = consume_qualified_pov_observation(
            adapter, request.pov_id, recheck=lambda: None,
            timeout_seconds=2, model_gate=model_gate)
        assert row["product_gate_status"] == "BLOCKED_VERIFIED_GATE"
        assert row["security_property_evaluated"] is True
        assert row["security_gate_invoked"] is True
        assert row["security_gate_completed"] is True
        assert row["security_gate_state"] == "COMPLETED"
        assert row["security_gate_result"] is False
        assert row["automatic_discovery"] is False
        assert row["claimed_input_origin"] == "agent"
        assert row["origin_verification_status"] == (
            "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE"
            if lineage_case == "verified" else "UNVERIFIED_LINEAGE")
        origin_path = Path(row["origin_lineage_receipt_path"])
        assert _sha(origin_path) == row["origin_lineage_receipt_sha256"]
        origin = json.loads(origin_path.read_text())
        assert origin["origin_verification_status"] == row[
            "origin_verification_status"]
        assert origin["discovery_credit"] == "NOT_CREDITED"
        if lineage_case == "absent":
            verify_lineage.assert_not_called()
        elif lineage_case == "verified":
            assert verify_lineage.call_count >= 2  # claim and final recheck
        else:
            verify_lineage.assert_called_once()
        if lineage_case == "wrong_input":
            assert origin["lineage"]["reason"] == "ORIGIN_IDENTITY_MISMATCH"
        assert row["discovery_credit"] == "NOT_CREDITED"
        with pytest.raises(FileExistsError):
            consume_qualified_pov_observation(
                adapter, request.pov_id, recheck=lambda: None, timeout_seconds=2)
    assert len(calls) == 1
    assert len(ledger.snapshot()["finished"]) == 1  # fake Gate launched no process
    assert Path(row["product_runtime_artifact"]).is_file()


def test_observed_pov_tamper_blocks_before_new_gate_claim(tmp_path, pinned_binary):
    from vulnerabilityanalysis import official_harness

    adapter, request, ledger, _ = _ready(tmp_path)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess(
                   [], 1, "", "ERROR: AddressSanitizer: heap-buffer-overflow\n")):
        first = adapter.execute(request)
    adapter.repos.povs.collection.update_one(
        {"_id": ObjectId(request.pov_id)},
        {"$set": {"qualified_runtime": {
            "status": first.status, "input_sha256": first.input_sha256,
            "binary_sha256": first.binary_sha256,
            "runtime_receipt_path": str(first.runtime_receipt_path),
            "runtime_receipt_sha256": first.runtime_receipt_sha256,
            "physical_receipt_path": str(first.physical_receipt_path),
            "physical_receipt_sha256": first.physical_receipt_sha256,
        }}})
    first.runtime_receipt_path.write_text("{}")
    harness = tmp_path / "harness.c"
    harness.write_text("// provider-free fixture\n")
    adapter.binding = QualifiedRuntimeBinding(
        SimpleNamespace(source_root=tmp_path, harness=harness), adapter.execute)
    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch("vulnerabilityanalysis.scan.execute_poc") as gate:
        with pytest.raises(ValueError, match="identity changed|receipt changed"):
            consume_qualified_pov_observation(
                adapter, request.pov_id, recheck=lambda: None)
        gate.assert_not_called()
    assert not (tmp_path / "pov-validation").exists()
    assert len(ledger.snapshot()["finished"]) == 1


def test_observed_pov_gate_stop_is_durable_and_cannot_relaunch(
        tmp_path, pinned_binary):
    from vulnerabilityanalysis import official_harness, scan
    from vulnerabilityanalysis.runtime import ProcessEnvelopeStop

    adapter, request, ledger, _ = _ready(tmp_path)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess(
                   [], 1, "", "ERROR: AddressSanitizer: heap-buffer-overflow\n")):
        first = adapter.execute(request)
    adapter.repos.povs.collection.update_one(
        {"_id": ObjectId(request.pov_id)},
        {"$set": {"qualified_runtime": {
            "status": first.status, "input_sha256": first.input_sha256,
            "binary_sha256": first.binary_sha256,
            "runtime_receipt_path": str(first.runtime_receipt_path),
            "runtime_receipt_sha256": first.runtime_receipt_sha256,
            "physical_receipt_path": str(first.physical_receipt_path),
            "physical_receipt_sha256": first.physical_receipt_sha256,
        }}})
    harness = tmp_path / "harness.c"
    harness.write_text("// provider-free fixture\n")
    adapter.binding = QualifiedRuntimeBinding(
        SimpleNamespace(source_root=tmp_path, harness=harness), adapter.execute)
    gate_calls = []

    def stopped_gate(*_args, **_kwargs):
        gate_calls.append(1)
        ledger.mark_stop("STOPPED_WALL_LIMIT", "fixture reservation exhausted")
        raise ProcessEnvelopeStop("STOPPED_WALL_LIMIT", "fixture stopped")

    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(scan, "execute_poc", side_effect=stopped_gate):
        with pytest.raises(ProcessEnvelopeStop):
            consume_qualified_pov_observation(
                adapter, request.pov_id, recheck=lambda: None,
                timeout_seconds=2)
        with pytest.raises(FileExistsError):
            consume_qualified_pov_observation(
                adapter, request.pov_id, recheck=lambda: None,
                timeout_seconds=2)
    assert gate_calls == [1]
    incomplete = json.loads((tmp_path / "pov-validation" / request.pov_id /
                             "incomplete.json").read_text())
    assert incomplete["stop_status"] == "STOPPED_WALL_LIMIT"
    assert incomplete["physical_finished"] == 1
    assert not (tmp_path / "pov-validation" / request.pov_id /
                "outcome.json").exists()


def test_claimed_pov_setup_failure_gets_receipt_without_target_relaunch(
        tmp_path, pinned_binary):
    from vulnerabilityanalysis import official_harness, scan

    adapter, request, ledger, _ = _ready(tmp_path)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess(
                   [], 1, "", "ERROR: AddressSanitizer: heap-buffer-overflow\n")):
        first = adapter.execute(request)
    adapter.repos.povs.collection.update_one(
        {"_id": ObjectId(request.pov_id)},
        {"$set": {"qualified_runtime": {
            "status": first.status, "input_sha256": first.input_sha256,
            "binary_sha256": first.binary_sha256,
            "runtime_receipt_path": str(first.runtime_receipt_path),
            "runtime_receipt_sha256": first.runtime_receipt_sha256,
            "physical_receipt_path": str(first.physical_receipt_path),
            "physical_receipt_sha256": first.physical_receipt_sha256,
        }}})
    harness = tmp_path / "harness.c"
    harness.write_text("// provider-free fixture\n")
    adapter.binding = QualifiedRuntimeBinding(
        SimpleNamespace(source_root=tmp_path, harness=harness), adapter.execute)
    adapter._envelope_type = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("fixture envelope setup failure"))
    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(scan, "execute_poc") as gate:
        with pytest.raises(RuntimeError, match="fixture envelope setup failure"):
            consume_qualified_pov_observation(
                adapter, request.pov_id, recheck=lambda: None)
        gate.assert_not_called()
        with pytest.raises(FileExistsError):
            consume_qualified_pov_observation(
                adapter, request.pov_id, recheck=lambda: None)
    incomplete = json.loads((tmp_path / "pov-validation" / request.pov_id /
                             "incomplete.json").read_text())
    assert incomplete["stage"] == "PRE_EXECUTE_SETUP"
    assert incomplete["physical_finished"] == 1
    assert len(ledger.snapshot()["finished"]) == 1


def test_binary_change_during_process_settles_physical_but_no_success(
        tmp_path, pinned_binary):
    adapter, request, ledger, binary = _ready(tmp_path)

    def wire(command, **_kwargs):
        binary.write_bytes(binary.read_bytes() + b"changed")
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch("vulnerabilityanalysis.runtime._guarded_run_once", side_effect=wire):
        with pytest.raises(Exception, match="process identity changed"):
            adapter.execute(request)
    state = ledger.snapshot()
    assert len(state["finished"]) == 1
    assert state["stop_status"] == "STOPPED_PIN_DRIFT"
    assert not (adapter.root / request.pov_id / "runtime.json").exists()


def test_unissued_product_qualification_refused_before_adapter_artifacts(tmp_path):
    with pytest.raises(ValueError, match="product-issued"):
        _ready(tmp_path)
    assert not (tmp_path / "attempts").exists()


def test_local_prestart_file_failure_records_reason_without_physical_start(
        tmp_path, pinned_binary):
    adapter, request, ledger, _ = _ready(tmp_path)
    (adapter.root / request.pov_id).mkdir()
    with patch("vulnerabilityanalysis.runtime._guarded_run_once") as wire:
        with pytest.raises(FileExistsError):
            adapter.execute(request)
        wire.assert_not_called()
    saved = adapter.repos.povs.collection.find_one(
        {"_id": ObjectId(request.pov_id)})["qualified_runtime"]
    assert saved["status"] == "INCOMPLETE"
    assert saved["error"] == "LOCAL_PRESTART_FileExistsError"
    assert saved["adapter_claim"]["input_sha256"] == request.input_sha256
    assert ledger.snapshot()["finished"] == []
    assert ledger.snapshot()["active"] == {}
    with patch("vulnerabilityanalysis.runtime._guarded_run_once") as wire:
        with pytest.raises(RuntimeError, match="no resend"):
            adapter.execute(request)
        wire.assert_not_called()


def test_nonfinite_wall_budget_refused_before_artifacts(tmp_path, pinned_binary):
    repos = RepositoryManager(mongomock.MongoClient().nonfinite_pov)
    binary = tmp_path / "fuzzer"
    binary.write_bytes(b"synthetic pinned binary")
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "physical.json", wall_total_seconds=60,
        fuzz_total_seconds=0)
    with pytest.raises(ValueError, match="development account"):
        ProductQualifiedPoVAdapter(
            qualification=object(), repos=repos, task_id="task_1",
            work_item_id="work_1", run_id="run_1", fuzzer="fuzz_fixture",
            sanitizer="address", ledger=ledger, output_dir=tmp_path / "attempts",
            timeout_seconds=float("nan"), wall_seconds=15,
            output_limit_bytes=4096)
    assert not (tmp_path / "attempts").exists()


def _qualified_sp_fuzz_setup(tmp_path):
    adapter, request, ledger, binary = _ready(tmp_path)
    adapter.ledger = PersistentProcessLedgerV2.create(
        tmp_path / "physical-fuzz.json", wall_total_seconds=120,
        fuzz_total_seconds=60)
    q = SimpleNamespace(source_tree_sha256="1" * 64,
                        harness_sha256="2" * 64,
                        contract_sha256="3" * 64,
                        source_root=tmp_path, harness=tmp_path / "harness.c")
    q.harness.write_text("/* provider-free fixture */")
    adapter.binding = QualifiedRuntimeBinding(q, adapter.execute)
    attempt = adapter.root / request.pov_id
    attempt.mkdir()
    (attempt / "input.bin").write_bytes(request.input_bytes)
    (attempt / "input.bin").chmod(0o600)
    adapter.repos.povs.collection.update_one(
        {"_id": ObjectId(request.pov_id)},
        {"$set": {"qualified_runtime.status": "NO_CRASH"}})
    lineage = {
        "status": "VERIFIED", "runtime_status": "NO_CRASH",
        "task_id": adapter.task_id, "run_id": adapter.run_id,
        "sp_id": request.suspicious_point_id,
        "direction_id": "direction_fixture", "pov_id": request.pov_id,
        "input_sha256": request.input_sha256,
        "binary_sha256": request.binary_sha256,
        "source_tree_sha256": q.source_tree_sha256,
        "harness_sha256": q.harness_sha256,
        "contract_sha256": q.contract_sha256,
    }
    return adapter, request, q, lineage


def _fake_sp_fuzz_receipts(run_dir, request, status, *, runtime_status=None,
                           crash_bytes=None):
    from vulnerabilityanalysis.models import RuntimeResult
    sp_id = request.suspicious_point_id
    attempt = (run_dir / "runtime" / "targeted_fuzz_attempts" /
               sp_id / "attempt-fixture")
    attempt.mkdir(parents=True)
    runtime = attempt / "runtime.json"
    actual_status = runtime_status or status
    stderr = ("#1 INITED cov: 1 ft: 1\n" if
              actual_status == "INCOMPLETE_NO_FUZZ_EVIDENCE" else
              "#2 NEW cov: 3 ft: 3\n")
    measured = RuntimeResult(
        None if actual_status == "TIMED_OUT" else 0, "", stderr, None,
        actual_status == "TIMED_OUT", None, None,
        "ENVIRONMENT_ERROR" if actual_status == "TIMED_OUT" else "NO_CRASH")
    runtime.write_text(json.dumps(asdict(measured)))
    crash_inputs = []
    if crash_bytes is not None:
        digest = hashlib.sha256(crash_bytes).hexdigest()
        witness = (run_dir / "corpus" / "targeted_witnesses" / sp_id /
                   "attempt-fixture" / f"witness-{digest}.bin")
        witness.parent.mkdir(parents=True)
        witness.write_bytes(crash_bytes)
        witness.chmod(0o600)
        crash_inputs.append({
            "candidate_path": str(witness),
            "attempt_witness_artifact": str(witness),
            "attempt_id": "attempt-fixture", "sha256": digest,
            "size": len(crash_bytes), "observed_crash_id": "crash_fixture"})
    seeds = attempt / "seeds.json"
    report = {
        "status": status, "sp_id": sp_id,
        "binary_sha256": request.binary_sha256,
        "initial_seed_hashes": [request.input_sha256],
        "crash_inputs": crash_inputs, "pending_crash_inputs": [],
        "observed_crash_id": "crash_fixture" if crash_inputs else None,
        "mutation_proven": actual_status != "INCOMPLETE_NO_FUZZ_EVIDENCE",
        "exit_code": measured.exit_code, "coverage_feedback": None,
        "observed_executions_max": (1 if actual_status ==
                                    "INCOMPLETE_NO_FUZZ_EVIDENCE" else 2),
        "requested_seconds": 1,
        "attempt_id": "attempt-fixture",
        "attempt_seed_artifact": str(seeds),
        "attempt_runtime_artifact": str(runtime),
        "attempt_runtime_sha256": _sha(runtime),
    }
    seeds.write_text(json.dumps(report))
    (run_dir / "runtime" / f"{sp_id}.targeted_fuzz.seeds.json").write_text(
        json.dumps(report))


def _fake_sp_fuzz_lease(adapter, request, ordinal, kind, segment, *, wrong=False):
    attempt_id = "different_attempt" if wrong else request.pov_id + "_sp_fuzz"
    key = (f"{adapter.task_id}:{request.suspicious_point_id}:"
           f"{attempt_id}:{ordinal:06d}:{segment}")
    adapter.ledger.reserve(key, kind, 1.0)
    adapter.ledger.finish(key, physical_seconds=0.01,
                          cleanup_complete=True, output_limited=False)


@pytest.mark.parametrize("mode", ["ran", "timeout", "no_mutation",
                                  "blocked_probe", "seed_drift", "extra_seed",
                                  "receipt_tamper", "zero_leases",
                                  "one_lease", "wrong_attempt",
                                  "runtime_timeout_forged", "runtime_empty"])
def test_qualified_sp_fuzz_claim_is_one_time_and_pins_seed(
        tmp_path, pinned_binary, mode):
    from vulnerabilityanalysis import official_harness, scan
    from devtools import product_qualified_runtime as handoff
    adapter, request, q, lineage = _qualified_sp_fuzz_setup(tmp_path)
    launches = []

    def fake_fuzzer(point, binary, run_dir, retry, evidences, *, seconds,
                    process_envelope):
        launches.append("probe")
        claim = run_dir / "sp-fuzz-claims" / "run-wide-one-item.json"
        assert claim.is_file()
        seed = run_dir / "corpus" / "candidate" / point.sp_id / (
            request.pov_id + ".bin")
        assert seed.read_bytes() == request.input_bytes
        process_envelope.pin_hook("before_reserve", [str(binary), "-help=1"])
        if mode not in {"zero_leases"}:
            _fake_sp_fuzz_lease(adapter, request, 0, "AUX_PROCESS",
                                "sp.libfuzzer_help", wrong=mode == "wrong_attempt")
        if mode == "blocked_probe":
            return None
        if mode == "seed_drift":
            seed.write_bytes(b"changed")
        elif mode == "extra_seed":
            (seed.parent / "untrusted.bin").write_bytes(b"extra")
        if mode in {"seed_drift", "extra_seed"}:
            with pytest.raises(ValueError):
                process_envelope.pin_hook(
                    "before_reserve", [str(binary), str(seed.parent),
                                       "-max_total_time=1"])
            raise RuntimeError("fuzz launch rejected by pin")
        launches.append("fuzz")
        process_envelope.pin_hook(
            "before_reserve", [str(binary), str(seed.parent),
                               "-max_total_time=1"])
        if mode not in {"zero_leases", "one_lease"}:
            _fake_sp_fuzz_lease(adapter, request, 1, "SP_FUZZ",
                                "sp.campaign", wrong=mode == "wrong_attempt")
        _fake_sp_fuzz_receipts(
            run_dir, request,
            "TIMED_OUT" if mode == "timeout" else
            "INCOMPLETE_NO_FUZZ_EVIDENCE" if mode == "no_mutation" else "RAN",
            runtime_status="TIMED_OUT" if mode == "runtime_timeout_forged"
            else None)
        if mode == "runtime_empty":
            runtime_path = (run_dir / "runtime" / "targeted_fuzz_attempts" /
                            point.sp_id / "attempt-fixture" / "runtime.json")
            runtime_path.write_text("{}")
            report_path = runtime_path.parent / "seeds.json"
            report = json.loads(report_path.read_text())
            report["attempt_runtime_sha256"] = _sha(runtime_path)
            report_path.write_text(json.dumps(report))
            (run_dir / "runtime" /
             f"{point.sp_id}.targeted_fuzz.seeds.json").write_text(
                json.dumps(report))
        if mode == "receipt_tamper":
            (run_dir / "runtime" /
             f"{point.sp_id}.targeted_fuzz.seeds.json").write_text("{}")
        return {"status": "TIMED_OUT" if mode == "timeout" else "RAN"}

    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(official_harness, "_qualification_pins_ok",
                      return_value=True), \
         patch.object(handoff, "verify_qualified_pov_runtime_lineage",
                      return_value=lineage), \
         patch.object(scan, "run_targeted_fuzz", side_effect=fake_fuzzer):
        if mode == "ran":
            result = run_qualified_sp_fuzz(
                adapter, request.pov_id, SimpleNamespace(snapshot=lambda: {}),
                recheck=lambda: None, seconds=1, fuzz_wall_seconds=40,
                replay_limit=0)
            assert result["status"] == "EXECUTED"
            assert result["automatic_discovery"] is False
            assert result["discovery_credit"] == "NOT_CREDITED"
        else:
            with pytest.raises((RuntimeError, ValueError)):
                run_qualified_sp_fuzz(
                    adapter, request.pov_id,
                    SimpleNamespace(snapshot=lambda: {}),
                    recheck=lambda: None, seconds=1, fuzz_wall_seconds=40,
                    replay_limit=0)
            assert (tmp_path / "sp-fuzz-claims" /
                    request.suspicious_point_id / "incomplete.json").is_file()
        before = len(launches)
        with pytest.raises(RuntimeError, match="already claimed"):
            run_qualified_sp_fuzz(
                adapter, request.pov_id, SimpleNamespace(snapshot=lambda: {}),
                recheck=lambda: None, seconds=1, fuzz_wall_seconds=40,
                replay_limit=0)
        assert len(launches) == before


def test_qualified_sp_fuzz_run_wide_claim_rejects_second_pov(
        tmp_path, pinned_binary):
    from vulnerabilityanalysis import official_harness, scan
    from devtools import product_qualified_runtime as handoff
    adapter, request, q, lineage = _qualified_sp_fuzz_setup(tmp_path)
    launched = []

    def fake_fuzzer(point, binary, run_dir, retry, evidences, *, seconds,
                    process_envelope):
        launched.append(point.sp_id)
        _fake_sp_fuzz_lease(adapter, request, 0, "AUX_PROCESS",
                            "sp.libfuzzer_help")
        _fake_sp_fuzz_lease(adapter, request, 1, "SP_FUZZ", "sp.campaign")
        _fake_sp_fuzz_receipts(run_dir, request, "RAN")
        return {"status": "RAN"}

    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(official_harness, "_qualification_pins_ok",
                      return_value=True), \
         patch.object(handoff, "verify_qualified_pov_runtime_lineage",
                      return_value=lineage) as verified, \
         patch.object(scan, "run_targeted_fuzz", side_effect=fake_fuzzer):
        run_qualified_sp_fuzz(
            adapter, request.pov_id, SimpleNamespace(snapshot=lambda: {}),
            recheck=lambda: None, seconds=1, fuzz_wall_seconds=40,
            replay_limit=0)
        second_id = generate_id()
        assert adapter.repos.povs.save(POV(
            pov_id=second_id, task_id=adapter.task_id,
            suspicious_point_id=request.suspicious_point_id,
            harness_name=adapter.fuzzer, sanitizer=adapter.sanitizer,
            blob=base64.b64encode(request.input_bytes).decode()))
        adapter.repos.povs.collection.update_one(
            {"_id": ObjectId(second_id)},
            {"$set": {"qualified_runtime": {
                "status": "NO_CRASH", "input_sha256": request.input_sha256,
                "binary_sha256": request.binary_sha256}}})
        second_attempt = adapter.root / second_id
        second_attempt.mkdir()
        (second_attempt / "input.bin").write_bytes(request.input_bytes)
        (second_attempt / "input.bin").chmod(0o600)
        verified.return_value = {**lineage, "pov_id": second_id}
        with pytest.raises(RuntimeError, match="already claimed"):
            run_qualified_sp_fuzz(
                adapter, second_id, SimpleNamespace(snapshot=lambda: {}),
                recheck=lambda: None, seconds=1, fuzz_wall_seconds=40,
                replay_limit=0)
        assert launched == [request.suspicious_point_id]


@pytest.mark.parametrize("consumer_lease", ["valid", "none", "foreign"])
def test_qualified_sp_fuzz_timeout_witness_is_consumed_without_success_credit(
        tmp_path, pinned_binary, consumer_lease):
    from vulnerabilityanalysis import fuzzer_crash_consumer, official_harness, scan
    from devtools import product_qualified_runtime as handoff
    adapter, request, q, lineage = _qualified_sp_fuzz_setup(tmp_path)
    consumed = []

    def fake_fuzzer(point, binary, run_dir, retry, evidences, *, seconds,
                    process_envelope):
        _fake_sp_fuzz_lease(adapter, request, 0, "AUX_PROCESS",
                            "sp.libfuzzer_help")
        _fake_sp_fuzz_lease(adapter, request, 1, "SP_FUZZ", "sp.campaign")
        _fake_sp_fuzz_receipts(run_dir, request, "TIMED_OUT",
                               crash_bytes=b"controlled retained crash input")
        return {"status": "TIMED_OUT"}

    def fake_consumer(run_dir, observation_id, input_sha256, **kwargs):
        consumed.append(input_sha256)
        assert observation_id == "crash_fixture"
        assert kwargs["process_envelope"].ledger is adapter.ledger
        if consumer_lease != "none":
            key = (f"{adapter.task_id}:{request.suspicious_point_id}:"
                   f"{request.pov_id}_sp_consumer:000000:pov.primary_execution"
                   if consumer_lease == "valid" else
                   f"{adapter.task_id}:{request.suspicious_point_id}:"
                   "another_attempt:000000:pov.primary_execution")
            adapter.ledger.reserve(key, "AUX_PROCESS", 1.0)
            adapter.ledger.finish(key, physical_seconds=0.01,
                                  cleanup_complete=True, output_limited=False)
        return {"status": "PENDING_CAUSAL_EVIDENCE",
                "input_sha256": input_sha256}

    with patch.object(official_harness, "OfficialPinnedQualification",
                      SimpleNamespace), \
         patch.object(official_harness, "_qualification_pins_ok",
                      return_value=True), \
         patch.object(handoff, "verify_qualified_pov_runtime_lineage",
                      return_value=lineage), \
         patch.object(scan, "run_targeted_fuzz", side_effect=fake_fuzzer), \
         patch.object(fuzzer_crash_consumer,
                      "consume_fuzzer_crash_observation",
                      side_effect=fake_consumer):
        if consumer_lease == "foreign":
            with pytest.raises(RuntimeError, match="Consumer physical AUX"):
                run_qualified_sp_fuzz(
                    adapter, request.pov_id,
                    SimpleNamespace(snapshot=lambda: {}),
                    recheck=lambda: None, seconds=1, fuzz_wall_seconds=40,
                    replay_limit=1)
            assert (tmp_path / "sp-fuzz-claims" /
                    request.suspicious_point_id / "incomplete.json").is_file()
        else:
            result = run_qualified_sp_fuzz(
                adapter, request.pov_id,
                SimpleNamespace(snapshot=lambda: {}),
                recheck=lambda: None, seconds=1, fuzz_wall_seconds=40,
                replay_limit=1)
            assert result["status"] == "INCOMPLETE_FUZZ_WITH_OBSERVED_CRASH"
            assert result["fuzzer_status"] == "TIMED_OUT"
            assert result["automatic_discovery"] is False
            assert result["discovery_credit"] == "NOT_CREDITED"
            assert len(result["crash_ids"]) == 1
            assert len(result["consumer_physical_lease_keys"]) == (
                1 if consumer_lease == "valid" else 0)
        assert len(consumed) == 1
