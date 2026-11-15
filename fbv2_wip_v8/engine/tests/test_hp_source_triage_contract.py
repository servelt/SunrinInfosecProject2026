"""HP source attribution can use Product triage without inventing an SP."""

from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path

import pytest

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from devtools.hp_source_attribution import (
    attribute_hp_replayed_crash_source, reprove_hp_source_attribution)
from vulnerabilityanalysis import runtime as product_runtime
from vulnerabilityanalysis.models import RuntimeResult
from vulnerabilityanalysis.runtime import CLEAN_RUNTIME_ENVIRONMENT


def _asan(frame: Path) -> RuntimeResult:
    stderr = (
        "ERROR: AddressSanitizer: heap-use-after-free\n"
        "READ of size 1 at 0x1234 thread T0\n"
        f"    #0 0x1234 in parse_input {frame}:2:5\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free\n"
    )
    return RuntimeResult(1, "", stderr, None, False,
                         "AddressSanitizer: heap-use-after-free",
                         None, "SANITIZER_CRASH")


def test_hp_target_source_triage_needs_no_sp_identity(tmp_path, monkeypatch):
    root = tmp_path / "target"
    root.mkdir()
    source = root / "parser.c"
    source.write_text("int parse_input(void) {\nreturn 0;\n}\n")
    harness = root / "harness.cc"
    harness.write_text("int main() { return 0; }\n")
    binary = tmp_path / "qualified-binary"
    binary.write_bytes(b"fixture binary")
    environments = []

    def inventory(candidate, **kwargs):
        environments.append(kwargs.get("env"))
        return {source.resolve()}

    monkeypatch.setattr(product_runtime, "_dwarf_sources", inventory)

    triage = product_runtime.triage_crash(
        _asan(source), str(root), str(harness), target_binary=binary,
        source_inventory_env=dict(CLEAN_RUNTIME_ENVIRONMENT))

    assert triage["category"] == "TARGET_CRASH"
    assert triage["source_provenance"] == {
        "observed_source": str(source.resolve()),
        "checkout_source": str(source.resolve()),
        "sha256": product_runtime.hashlib.sha256(source.read_bytes()).hexdigest(),
        "binary": str(binary.resolve()),
        "method": "DWARF_PATH_RELATIVE_PATH_SHA256",
    }
    assert triage["sp_linked"] is False
    assert triage["verification_eligible"] is False
    assert environments and all(
        env == CLEAN_RUNTIME_ENVIRONMENT for env in environments)


def test_hp_source_triage_rejects_harness_and_missing_dwarf(
        tmp_path, monkeypatch):
    root = tmp_path / "target"
    root.mkdir()
    source = root / "parser.c"
    source.write_text("int parse_input(void) {\nreturn 0;\n}\n")
    harness = root / "harness.cc"
    harness.write_text("int main() { return 0; }\n")
    binary = tmp_path / "qualified-binary"
    binary.write_bytes(b"fixture binary")
    monkeypatch.setattr(product_runtime, "_dwarf_sources",
                        lambda candidate, **kwargs: {source.resolve()})

    harness_triage = product_runtime.triage_crash(
        _asan(harness), str(root), str(harness), target_binary=binary)
    assert harness_triage["category"] == "HARNESS_CRASH"
    assert harness_triage["source_provenance"] is None

    monkeypatch.setattr(product_runtime, "_dwarf_sources",
                        lambda candidate, **kwargs: set())
    missing_dwarf = product_runtime.triage_crash(
        _asan(source), str(root), str(harness), target_binary=binary)
    assert missing_dwarf["category"] == "UNKNOWN"
    assert missing_dwarf["source_provenance"] is None


def _source_stage_fixture(tmp_path, monkeypatch, *, fixture_origin=False,
                          valid_source=True, ledger_process=True,
                          wrong_process_segment=False,
                          callback_measured=True, callback_ledger_process=True):
    from devtools import hp_source_attribution as hp_source
    from vulnerabilityanalysis import direct_input, official_harness

    root = tmp_path / "target"
    root.mkdir()
    source = root / "parser.c"
    source.write_text("int parse_input(void) {\nreturn 0;\n}\n")
    harness = root / "harness.cc"
    harness.write_text("int main() { return 0; }\n")
    binary = tmp_path / "original-binary"
    binary.write_bytes(b"qualified original fixture")
    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    primary_path = replay_dir / "original_observation-runtime.json"
    primary_path.write_text(json.dumps(asdict(_asan(source))))
    replay_path = replay_dir / "HP_REPLAY_RESULT.json"
    replay_path.write_text("{}\n")
    frozen_input = tmp_path / "frozen-input"
    frozen_input.write_bytes(b"candidate input")
    input_sha = sha256(frozen_input.read_bytes()).hexdigest()
    replay_result = {
        "result_path": str(replay_path),
        "result_sha256": sha256(replay_path.read_bytes()).hexdigest(),
        "observations": [{}, {
            "runtime_path": str(primary_path),
            "runtime_sha256": sha256(primary_path.read_bytes()).hexdigest()}],
    }
    proof = {
        "status": ("HP_REPLAY_FIXTURE_REPROVED_UNCREDITED" if fixture_origin
                   else "HP_REPLAY_EVIDENCE_REPROVED_PENDING_SECURITY"),
        "task_id": "task", "run_id": "run", "assertion_id": "assertion",
        "input_sha256": input_sha, "original_binary_sha256": "b" * 64,
        "crash_fingerprint": "crash-id",
    }
    monkeypatch.setattr(hp_source, "reprove_hp_original_replay",
                        lambda **kwargs: dict(proof))

    class QualifiedFixture:
        def __init__(self):
            self.source_root = root
            self.harness = harness
            self.binary = binary
            self.source_tree_sha256 = "c" * 64
            self.harness_sha256 = "d" * 64

    qualification = QualifiedFixture()
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda value: value is qualification)

    def scripted_triage(primary, target_root, harness_path, *, target_binary,
                        process_envelope, source_inventory_env):
        assert Path(target_root) == root
        assert Path(harness_path) == harness
        assert target_binary == binary
        assert source_inventory_env == CLEAN_RUNTIME_ENVIRONMENT
        if ledger_process:
            lease = process_envelope.before_process(
                ["gdb", str(binary)], cwd=None,
                env=source_inventory_env, timeout=1,
                kind="AUX_PROCESS",
                segment=("other.process" if wrong_process_segment else
                         "assertion.gdb_source_inventory"))
            process_envelope.after_process(
                lease, elapsed_seconds=0.1, cleanup_complete=True,
                output_limited=False, error=None)
        return {
            "category": "TARGET_CRASH",
            "sp_linked": False, "verification_eligible": False,
            "source_provenance": {
                "observed_source": str(source),
                "checkout_source": str(source if valid_source else harness),
                "sha256": sha256(source.read_bytes()).hexdigest(),
                "binary": str(binary.resolve()),
                "method": "DWARF_PATH_RELATIVE_PATH_SHA256",
            },
        }

    monkeypatch.setattr(product_runtime, "triage_crash", scripted_triage)

    def scripted_callback(candidate_binary, input_path, *, process_envelope, env):
        assert candidate_binary == binary
        assert input_path == frozen_input
        assert env == CLEAN_RUNTIME_ENVIRONMENT
        if callback_ledger_process:
            lease = process_envelope.before_process(
                ["gdb", str(binary), str(input_path)], cwd=None,
                env=env, timeout=1, kind="AUX_PROCESS",
                segment="harness.callback_probe")
            process_envelope.after_process(
                lease, elapsed_seconds=0.1, cleanup_complete=True,
                output_limited=False, error=None)
        return direct_input.CallbackProbe(
            callback_measured,
            len(frozen_input.read_bytes()) if callback_measured else None,
            input_sha if callback_measured else None,
            "scripted callback")

    monkeypatch.setattr(direct_input, "probe_libfuzzer_callback",
                        scripted_callback)
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "process.json", wall_total_seconds=120,
        fuzz_total_seconds=20)
    return {
        "replay_result": replay_result,
        "lead": {"frozen_input_path": str(frozen_input)},
        "physical_claim_path": tmp_path / "HP_PHYSICAL_CLAIM.json",
        "physical_claim_sha256": "e" * 64,
        "qualification": qualification, "process_ledger": ledger,
        "output_dir": tmp_path / "source-result",
        "wall_seconds": 30, "output_limit_bytes": 1_000_000,
    }


@pytest.mark.parametrize("valid_source,ledger_process", [
    (True, True), (False, True), (True, False)])
def test_hp_source_stage_keeps_unproven_cases_pending(
        tmp_path, monkeypatch, valid_source, ledger_process):
    args = _source_stage_fixture(
        tmp_path, monkeypatch, valid_source=valid_source,
        ledger_process=ledger_process)
    row = attribute_hp_replayed_crash_source(**args)
    assert row["status"] == (
        "HP_TARGET_SOURCE_ATTRIBUTED_PENDING_SECURITY" if
        valid_source and ledger_process else
        "HP_SOURCE_UNPROVEN_PENDING_SECURITY")
    assert row["security_gate_credit"] == "NOT_CREDITED"
    assert row["discovery_credit"] == "NOT_CREDITED"
    assert row["input_delivery_measured"] is True
    assert args["process_ledger"].snapshot()["stop_status"] is None
    with pytest.raises(FileExistsError):
        attribute_hp_replayed_crash_source(**args)


def test_hp_source_stage_rejects_fixture_replay_before_claim(tmp_path, monkeypatch):
    args = _source_stage_fixture(tmp_path, monkeypatch, fixture_origin=True)
    with pytest.raises(ValueError, match="requires physical replay"):
        attribute_hp_replayed_crash_source(**args)
    assert not args["output_dir"].exists()


def test_hp_source_stage_rejects_unrelated_process_receipt(tmp_path, monkeypatch):
    args = _source_stage_fixture(
        tmp_path, monkeypatch, wrong_process_segment=True)
    with pytest.raises(ValueError, match="process is unsettled"):
        attribute_hp_replayed_crash_source(**args)
    failure = json.loads((args["output_dir"] / "HP_SOURCE_RESULT.json").read_text())
    assert failure["status"] == "INCOMPLETE_HP_SOURCE_ATTRIBUTION"
    assert failure["security_gate_credit"] == "NOT_CREDITED"


def test_hp_source_reproof_binds_saved_bytes_and_owner_ledger(tmp_path, monkeypatch):
    args = _source_stage_fixture(tmp_path, monkeypatch)
    row = attribute_hp_replayed_crash_source(**args)
    proof_args = {key: value for key, value in args.items()
                  if key not in {"output_dir", "wall_seconds",
                                 "output_limit_bytes"}}
    ledger = args["process_ledger"]
    ledger.reserve("other:sp:run:000000:sp.campaign", "SP_FUZZ", 3)
    proven = reprove_hp_source_attribution(source_result=row, **proof_args)
    assert proven["status"] == "HP_SOURCE_EVIDENCE_REPROVED_PENDING_SECURITY"
    assert proven["input_delivery_measured"] is True
    assert proven["security_gate_credit"] == "NOT_CREDITED"
    forged = {**row, "status": "HP_GATE_VERIFIED"}
    with pytest.raises(ValueError, match="not an attributed"):
        reprove_hp_source_attribution(source_result=forged, **proof_args)
    source = args["qualification"].source_root / "parser.c"
    source.write_text(source.read_text() + "// changed\n")
    with pytest.raises(ValueError, match="source bytes"):
        reprove_hp_source_attribution(source_result=row, **proof_args)


@pytest.mark.parametrize("callback_measured,callback_ledger_process", [
    (False, True), (True, False)])
def test_hp_source_stage_keeps_unmeasured_input_pending(
        tmp_path, monkeypatch, callback_measured, callback_ledger_process):
    args = _source_stage_fixture(
        tmp_path, monkeypatch, callback_measured=callback_measured,
        callback_ledger_process=callback_ledger_process)
    row = attribute_hp_replayed_crash_source(**args)
    assert row["status"] == "HP_TARGET_SOURCE_ATTRIBUTED_PENDING_SECURITY"
    assert row["input_delivery_measured"] is False
    assert row["security_gate_credit"] == "NOT_CREDITED"
    proof_args = {key: value for key, value in args.items()
                  if key not in {"output_dir", "wall_seconds",
                                 "output_limit_bytes"}}
    proven = reprove_hp_source_attribution(source_result=row, **proof_args)
    assert proven["input_delivery_measured"] is False
