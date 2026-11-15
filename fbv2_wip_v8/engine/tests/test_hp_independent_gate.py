"""HP Gate keeps physical defect verification separate from discovery credit."""

from dataclasses import asdict
from hashlib import sha256
import json

import pytest

from devtools import hp_independent_gate as gate
from vulnerabilityanalysis.final_verification import crash_fingerprint
from vulnerabilityanalysis.models import RuntimeResult


def _case(tmp_path, monkeypatch, *, oracle="heap-use-after-free",
          delivery=True, origin="PINNED_RUNTIME_EXECUTOR"):
    from vulnerabilityanalysis import official_harness

    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    primary = RuntimeResult(
        1, "",
        f"ERROR: AddressSanitizer: {oracle}\n"
        "READ of size 1 at 0x123 thread T0\n"
        "    #0 0x123 in parse_input /tmp/parser.c:2:5\n",
        None, False, f"AddressSanitizer: {oracle}", None,
        "SANITIZER_CRASH")
    runtime_path = replay_dir / "original_observation-runtime.json"
    runtime_path.write_text(json.dumps(asdict(primary)))
    replay_path = replay_dir / "HP_REPLAY_RESULT.json"
    replay_path.write_text("{}\n")
    replay_result = {
        "result_path": str(replay_path),
        "result_sha256": sha256(replay_path.read_bytes()).hexdigest(),
        "execution_origin": origin,
        "observations": [{}, {
            "runtime_path": str(runtime_path),
            "runtime_sha256": sha256(runtime_path.read_bytes()).hexdigest()}],
    }
    source_result = {"result_sha256": "c" * 64}
    fingerprint = crash_fingerprint(primary)
    replay_proof = {
        "status": "HP_REPLAY_EVIDENCE_REPROVED_PENDING_SECURITY",
        "task_id": "task", "run_id": "run", "assertion_id": "assertion",
        "input_sha256": "a" * 64,
        "original_binary_sha256": "b" * 64,
        "crash_fingerprint": fingerprint,
    }
    source_proof = {
        "status": "HP_SOURCE_EVIDENCE_REPROVED_PENDING_SECURITY",
        "crash_fingerprint": fingerprint,
        "source_sha256": "d" * 64,
        "input_delivery_measured": delivery,
    }
    monkeypatch.setattr(gate, "reprove_hp_original_replay",
                        lambda **kwargs: dict(replay_proof))
    monkeypatch.setattr(gate, "reprove_hp_source_attribution",
                        lambda **kwargs: dict(source_proof))

    class QualifiedFixture:
        pass

    qualification = QualifiedFixture()
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda value: value is qualification)
    return {
        "replay_result": replay_result,
        "source_result": source_result,
        "lead": {}, "physical_claim_path": tmp_path / "HP_PHYSICAL_CLAIM.json",
        "physical_claim_sha256": "e" * 64,
        "qualification": qualification, "process_ledger": object(),
        "output_dir": tmp_path / "gate-result",
    }


@pytest.mark.parametrize("oracle", [
    "heap-use-after-free", "heap-buffer-overflow",
    "attempting double-free"])
def test_hp_gate_verifies_physical_memory_defect_without_discovery_credit(
        tmp_path, monkeypatch, oracle):
    args = _case(tmp_path, monkeypatch, oracle=oracle)
    row = gate.issue_hp_independent_gate(**args)
    assert row["status"] == "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN"
    assert row["security_gate_credit"] == "HP_GATE_VERIFIED"
    assert row["discovery_credit"] == "NOT_CREDITED"
    assert row["hp_assertion_causal_relation_status"] == "UNPROVEN"
    proof_args = {key: value for key, value in args.items()
                  if key != "output_dir"}
    proven = gate.reprove_hp_independent_gate(
        gate_result=row, **proof_args)
    assert proven["security_gate_credit"] == "HP_GATE_VERIFIED"
    with pytest.raises(FileExistsError):
        gate.issue_hp_independent_gate(**args)


@pytest.mark.parametrize("oracle,delivery", [
    ("heap-use-after-free", False), ("SEGV", True),
    ("SEGV (heap-use-after-free)", True)])
def test_hp_gate_keeps_missing_input_or_unsupported_oracle_pending(
        tmp_path, monkeypatch, oracle, delivery):
    args = _case(tmp_path, monkeypatch, oracle=oracle, delivery=delivery)
    row = gate.issue_hp_independent_gate(**args)
    assert row["status"].startswith("HP_GATE_PENDING_")
    assert row["security_gate_credit"] == "NOT_CREDITED"
    proof_args = {key: value for key, value in args.items()
                  if key != "output_dir"}
    assert gate.reprove_hp_independent_gate(
        gate_result=row, **proof_args)["security_gate_credit"] == "NOT_CREDITED"


def test_hp_gate_rejects_fixture_origin_and_forged_verdict(tmp_path, monkeypatch):
    fixture = _case(tmp_path, monkeypatch, origin="PROVIDER_FREE_FIXTURE")
    with pytest.raises(ValueError, match="physical evidence"):
        gate.issue_hp_independent_gate(**fixture)
    assert not fixture["output_dir"].exists()

    separate = tmp_path / "separate"
    separate.mkdir()
    args = _case(separate, monkeypatch)
    row = gate.issue_hp_independent_gate(**args)
    forged = {**row, "discovery_credit": "CREDITED"}
    proof_args = {key: value for key, value in args.items()
                  if key != "output_dir"}
    with pytest.raises(ValueError, match="not re-proven"):
        gate.reprove_hp_independent_gate(
            gate_result=forged, **proof_args)
