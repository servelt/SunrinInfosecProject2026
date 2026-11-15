"""The HP evidence freezer preserves a lead without claiming a vulnerability."""

import hashlib
import json
from pathlib import Path

import pytest

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from devtools.hp_original_replay import (
    replay_hp_original_crash, reprove_hp_original_replay)
from vulnerabilityanalysis.final_verification import REPLAY_ASAN_OPTIONS
from vulnerabilityanalysis.models import RuntimeResult
from vulnerabilityanalysis.runtime import CLEAN_RUNTIME_ENVIRONMENT
from vulnerabilityanalysis.runtime import ProcessEnvelopeStop
from devtools.hp_guided_crash_freeze import (
    admit_hp_original_replay, freeze_hp_guided_crash_lead,
    freeze_reported_hp_guided_crash_leads)


IDS = {"task_id": "task", "run_id": "run", "worker_id": "worker",
       "function_id": "function", "direction_id": "direction",
       "assertion_id": "assertion"}


def _fixture(tmp_path, *, segment="initial"):
    guided = tmp_path / "guided"
    guided.mkdir()
    selected_dir = guided if segment == "initial" else guided / "continuation"
    selected_dir.mkdir(exist_ok=True)
    crash = selected_dir / "crash-example"
    crash.write_bytes(b"candidate input")
    binary = selected_dir / "guided-target"
    binary.write_bytes(b"instrumented binary")
    runtime = selected_dir / "fuzzer-runtime.json"
    runtime.write_text(json.dumps({
        "sanitizer": "AddressSanitizer: heap-buffer-overflow",
        "stderr": "ERROR: AddressSanitizer: heap-buffer-overflow\n",
        "exit_code": 1, "timed_out": False,
        "failure_classification": "TARGET_CRASH"}))
    report = {
        "assertion_id": "assertion",
        "status": ("CRASH_OBSERVED_INCOMPLETE" if segment == "initial" else
                   "INCOMPLETE_CONTINUATION"),
        "binary": str(guided / "guided-target"),
        "other_crash_artifacts": [str(crash)] if segment == "initial" else [],
        "other_crash_artifact_pins": ([{
            "path": str(crash), "sha256": hashlib.sha256(crash.read_bytes()).hexdigest()
        }] if segment == "initial" else []),
        "fuzzer_runtime": str(guided / "fuzzer-runtime.json"),
        "fuzzer_exit_code": 1, "fuzzer_timed_out": False,
    }
    if segment == "continuation":
        report["continuation"] = {
            "status": "CRASH_OBSERVED_INCOMPLETE",
            "binary": str(binary), "runtime_artifact": str(runtime),
            "exit_code": 1, "timed_out": False,
            "crash_artifacts": [str(crash)],
            "crash_artifact_pins": [{
                "path": str(crash),
                "sha256": hashlib.sha256(crash.read_bytes()).hexdigest()}],
        }
        (guided / "guided-target").write_bytes(b"initial binary")
    if segment == "continuation":
        (guided / "fuzzer-runtime.json").write_text('{"initial":true}')
    (guided / "guided_fuzz.json").write_text(json.dumps(report))
    handoff = {
        "status": "HP_GUIDED_CRASH_OBSERVED_UNGATED",
        "function_id": "function", "direction_id": "direction",
        "assertion_id": "assertion", "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED", "sp_global_effect": "UNCHANGED",
        "physical_observations": {"guided_crash_observed_ungated": True},
        "guided_report": report,
    }
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "process.json", wall_total_seconds=120,
        fuzz_total_seconds=20)
    key = "task:assertion:run:000000:guided." + (
        "initial_campaign" if segment == "initial" else "continuation_campaign")
    ledger.reserve(key, "HP_FUZZ", 5)
    ledger.finish(key, physical_seconds=1, cleanup_complete=True)
    return {"handoff": handoff, **IDS, "guided_dir": guided,
            "crash_path": crash, "claim_root": tmp_path / "claims",
            "process_ledger": ledger}


@pytest.mark.parametrize("segment", ["initial", "continuation"])
def test_freeze_binds_guided_input_and_ledger_without_gate_credit(tmp_path, segment):
    args = _fixture(tmp_path, segment=segment)
    row = freeze_hp_guided_crash_lead(**args)
    assert row["status"] == "HP_CRASH_INPUT_FROZEN_UNVERIFIED"
    assert row["segment"] == segment
    assert row["input_sha256"] == hashlib.sha256(b"candidate input").hexdigest()
    assert row["security_gate_credit"] == "NOT_CREDITED"
    assert row["discovery_credit"] == "NOT_CREDITED"
    with open(row["frozen_input_path"], "rb") as stream:
        assert stream.read() == b"candidate input"
    with open(row["claim_path"], "rb") as stream:
        assert hashlib.sha256(stream.read()).hexdigest() == row["claim_sha256"]
    with pytest.raises(FileExistsError):
        freeze_hp_guided_crash_lead(**args)


def test_freeze_rejects_changed_input_and_report(tmp_path):
    args = _fixture(tmp_path)
    args["crash_path"].write_bytes(b"changed input")
    with pytest.raises(ValueError, match="producer pin"):
        freeze_hp_guided_crash_lead(**args)
    args["crash_path"].write_bytes(b"candidate input")
    report_path = args["guided_dir"] / "guided_fuzz.json"
    report = json.loads(report_path.read_text())
    report["assertion_id"] = "other"
    report_path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="not bound"):
        freeze_hp_guided_crash_lead(**args)


def test_freeze_rejects_unsettled_process_and_outside_file(tmp_path):
    args = _fixture(tmp_path)
    outside = tmp_path / "crash-outside"
    outside.write_bytes(b"candidate input")
    args["crash_path"] = outside
    with pytest.raises(ValueError, match="unique crash lead"):
        freeze_hp_guided_crash_lead(**args)
    args["crash_path"] = args["guided_dir"] / "crash-example"
    args["process_ledger"].reserve("task:assertion:run:000001:guided.next", "HP_FUZZ", 2)
    with pytest.raises(ValueError, match="not settled"):
        freeze_hp_guided_crash_lead(**args)


def test_freeze_rejects_forged_verified_label(tmp_path):
    args = _fixture(tmp_path)
    args["handoff"]["security_gate_credit"] = "VERIFIED"
    with pytest.raises(ValueError, match="identity is invalid"):
        freeze_hp_guided_crash_lead(**args)


def test_one_shot_claim_does_not_reopen_after_input_and_report_rewrite(tmp_path):
    args = _fixture(tmp_path)
    freeze_hp_guided_crash_lead(**args)
    args["crash_path"].write_bytes(b"new candidate input")
    report_path = args["guided_dir"] / "guided_fuzz.json"
    report = json.loads(report_path.read_text())
    report["other_crash_artifact_pins"][0]["sha256"] = hashlib.sha256(
        b"new candidate input").hexdigest()
    report_path.write_text(json.dumps(report))
    args["handoff"]["guided_report"] = report
    with pytest.raises(FileExistsError):
        freeze_hp_guided_crash_lead(**args)


def test_freeze_rejects_runtime_without_sanitizer_and_changed_binary(tmp_path):
    args = _fixture(tmp_path)
    runtime_path = args["guided_dir"] / "fuzzer-runtime.json"
    runtime = json.loads(runtime_path.read_text())
    runtime["sanitizer"] = None
    runtime_path.write_text(json.dumps(runtime))
    with pytest.raises(ValueError, match="completed sanitizer crash"):
        freeze_hp_guided_crash_lead(**args)
    runtime["sanitizer"] = "AddressSanitizer: heap-buffer-overflow"
    runtime_path.write_text(json.dumps(runtime))
    binary = args["guided_dir"] / "guided-target"
    binary.unlink()
    binary.symlink_to(tmp_path / "outside-binary")
    (tmp_path / "outside-binary").write_bytes(b"other")
    with pytest.raises(ValueError, match="canonical and local"):
        freeze_hp_guided_crash_lead(**args)


def test_freeze_rejects_reported_runtime_result_mismatch(tmp_path):
    args = _fixture(tmp_path)
    report_path = args["guided_dir"] / "guided_fuzz.json"
    report = json.loads(report_path.read_text())
    report["fuzzer_exit_code"] = 0
    report_path.write_text(json.dumps(report))
    args["handoff"]["guided_report"] = report
    with pytest.raises(ValueError, match="segment result differs"):
        freeze_hp_guided_crash_lead(**args)


def test_batch_freeze_preserves_partial_leads_and_never_grants_credit(tmp_path):
    args = _fixture(tmp_path)
    missing = args["guided_dir"] / "crash-missing"
    report_path = args["guided_dir"] / "guided_fuzz.json"
    report = json.loads(report_path.read_text())
    report["other_crash_artifacts"].append(str(missing))
    report["other_crash_artifact_pins"].append({"path": str(missing),
                                                "sha256": None})
    report_path.write_text(json.dumps(report))
    args["handoff"]["guided_report"] = report
    args.pop("crash_path")
    row = freeze_reported_hp_guided_crash_leads(**args)
    assert row["status"] == "INCOMPLETE_HP_CRASH_LEAD_FREEZE"
    assert row["reported_lead_count"] == 2
    assert len(row["frozen_leads"]) == 1
    assert row["rejected_leads"] == [{"path": str(missing),
                                      "error_type": "ValueError"}]
    assert row["security_gate_credit"] == "NOT_CREDITED"
    assert row["discovery_credit"] == "NOT_CREDITED"


def test_batch_freeze_with_no_artifact_is_incomplete(tmp_path):
    args = _fixture(tmp_path)
    report_path = args["guided_dir"] / "guided_fuzz.json"
    report = json.loads(report_path.read_text())
    report["other_crash_artifacts"] = []
    report["other_crash_artifact_pins"] = []
    report_path.write_text(json.dumps(report))
    args["handoff"]["guided_report"] = report
    args.pop("crash_path")
    row = freeze_reported_hp_guided_crash_leads(**args)
    assert row["status"] == "INCOMPLETE_HP_CRASH_LEAD_FREEZE"
    assert row["reported_lead_count"] == 0
    assert row["frozen_leads"] == []


def _admission_case(tmp_path, monkeypatch):
    from vulnerabilityanalysis import official_harness

    args = _fixture(tmp_path)
    lead = freeze_hp_guided_crash_lead(**args)
    original = tmp_path / "original-binary"
    original.write_bytes(b"original qualified binary")
    normal = tmp_path / "normal-seed"
    normal.write_bytes(b"normal input")

    class QualifiedFixture:
        product_issued = True
        binary = original
        binary_sha256 = hashlib.sha256(original.read_bytes()).hexdigest()
        normal_seed = normal
        normal_seed_sha256 = hashlib.sha256(normal.read_bytes()).hexdigest()
        harness_sha256 = "a" * 64
        source_tree_sha256 = "b" * 64

    qualification = QualifiedFixture()
    monkeypatch.setattr(official_harness, "OfficialPinnedQualification",
                        QualifiedFixture)
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda q: q is qualification)
    physical_claim = tmp_path / "HP_PHYSICAL_CLAIM.json"
    physical_claim.write_text(json.dumps({
        "kind": "FBV2_HP_PHYSICAL_CLAIM_V1",
        **IDS,
        "assertion_selection": {"selected_assertion_id": "assertion"},
        "binary_sha256": qualification.binary_sha256,
        "harness_sha256": qualification.harness_sha256,
        "source_tree_sha256": qualification.source_tree_sha256,
    }))
    return {
        "lead": lead,
        "physical_claim_path": physical_claim,
        "physical_claim_sha256": hashlib.sha256(
            physical_claim.read_bytes()).hexdigest(),
        "qualification": qualification,
        "process_ledger": args["process_ledger"],
    }


def test_original_replay_admission_rechecks_both_hp_claims_and_target(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    row = admit_hp_original_replay(**args)
    assert row["status"] == "HP_ORIGINAL_REPLAY_ADMITTED_UNVERIFIED"
    assert row["assertion_id"] == "assertion"
    assert row["input_sha256"] == hashlib.sha256(
        b"candidate input").hexdigest()
    assert row["security_gate_credit"] == "NOT_CREDITED"
    assert row["discovery_credit"] == "NOT_CREDITED"


def test_original_replay_admission_rejects_parent_or_frozen_input_drift(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    Path(args["lead"]["frozen_input_path"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="frozen input changed"):
        admit_hp_original_replay(**args)
    Path(args["lead"]["frozen_input_path"]).write_bytes(b"candidate input")
    parent = args["physical_claim_path"]
    payload = json.loads(parent.read_text())
    payload["binary_sha256"] = "c" * 64
    parent.write_text(json.dumps(payload))
    args["physical_claim_sha256"] = hashlib.sha256(parent.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="physical claim or target"):
        admit_hp_original_replay(**args)


def test_original_replay_admission_rejects_report_drift_but_allows_append_only_ledger(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    report = Path(args["lead"]["guided_report_path"])
    report.write_text(report.read_text() + " ")
    with pytest.raises(ValueError, match="Guided report changed"):
        admit_hp_original_replay(**args)
    report.write_text(report.read_text().rstrip())
    args["process_ledger"].reserve("other:work:run:000001:extra", "AUX_PROCESS", 1)
    args["process_ledger"].finish(
        "other:work:run:000001:extra", physical_seconds=0.1,
        cleanup_complete=True)
    admitted = admit_hp_original_replay(**args)
    assert admitted["process_ledger_sha256"] != (
        admitted["process_ledger_sha256_at_freeze"])


_ASAN = ("ERROR: AddressSanitizer: heap-use-after-free\n"
         "READ of size 1 at 0x123\n"
         "    #0 0x123 in parse_input /tmp/parser.c:2:5\n")


def _scripted_replay_factory(results):
    sequence = iter(results)

    class ScriptedRuntime:
        def __init__(self, timeout):
            assert timeout == 1.0
            self.last_asan_options = REPLAY_ASAN_OPTIONS
            self.last_environment = {
                **CLEAN_RUNTIME_ENVIRONMENT,
                "ASAN_OPTIONS": REPLAY_ASAN_OPTIONS}

        def run(self, command, input_path, *, extra_env,
                inherit_environment, process_envelope, process_segment):
            assert extra_env == {"ASAN_OPTIONS": REPLAY_ASAN_OPTIONS}
            assert inherit_environment is False
            argv = [command[0], str(input_path)]
            lease = process_envelope.before_process(
                argv, cwd=None, env=self.last_environment,
                timeout=1, kind="AUX_PROCESS", segment=process_segment)
            process_envelope.after_process(
                lease, elapsed_seconds=0.1, cleanup_complete=True,
                output_limited=False, error=None)
            return next(sequence)

    return ScriptedRuntime


def _control():
    return RuntimeResult(0, "", "", None, False, None, None, "UNKNOWN")


def _asan(stderr=_ASAN):
    return RuntimeResult(1, "", stderr, None, False,
                         "AddressSanitizer: heap-use-after-free",
                         None, "SANITIZER_CRASH")


def test_original_replay_matches_only_same_fingerprint_and_stays_uncredited(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    row = replay_hp_original_crash(
        **args, output_dir=tmp_path / "replay", timeout_seconds=1,
        wall_seconds=60, output_limit_bytes=1_000_000,
        provider_free_fixture=True,
        runtime_factory=_scripted_replay_factory([
            _control(), _asan(), _asan()]))
    assert row["status"] == "HP_REPLAY_MATCHED_PENDING_SECURITY"
    assert len(row["observations"]) == 3
    assert row["security_gate_credit"] == "NOT_CREDITED"
    assert row["discovery_credit"] == "NOT_CREDITED"
    assert row["execution_origin"] == "PROVIDER_FREE_FIXTURE"
    assert Path(row["result_path"]).is_file()
    reproved = reprove_hp_original_replay(replay_result=row, **args)
    assert reproved["status"] == "HP_REPLAY_FIXTURE_REPROVED_UNCREDITED"
    assert reproved["crash_fingerprint"]
    assert reproved["security_gate_credit"] == "NOT_CREDITED"
    with pytest.raises(FileExistsError):
        replay_hp_original_crash(
            **args, output_dir=tmp_path / "replay", timeout_seconds=1,
            wall_seconds=60, output_limit_bytes=1_000_000,
            provider_free_fixture=True,
            runtime_factory=_scripted_replay_factory([
                _control(), _asan(), _asan()]))


def test_original_replay_different_crash_stays_pending(tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    different = _ASAN.replace("parse_input /tmp/parser.c:2:5",
                              "parse_other /tmp/parser.c:3:5")
    row = replay_hp_original_crash(
        **args, output_dir=tmp_path / "replay", timeout_seconds=1,
        wall_seconds=60, output_limit_bytes=1_000_000,
        provider_free_fixture=True,
        runtime_factory=_scripted_replay_factory([
            _control(), _asan(), _asan(different)]))
    assert row["status"] == "HP_REPLAY_MISMATCH_PENDING"
    assert row["security_gate_credit"] == "NOT_CREDITED"


def test_instrumented_only_crash_never_reaches_independent_replay(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    row = replay_hp_original_crash(
        **args, output_dir=tmp_path / "replay", timeout_seconds=1,
        wall_seconds=60, output_limit_bytes=1_000_000,
        provider_free_fixture=True,
        runtime_factory=_scripted_replay_factory([_control(), _control()]))
    assert row["status"] == "HP_INSTRUMENTED_ONLY_CRASH_PENDING"
    assert len(row["observations"]) == 2
    assert row["security_gate_credit"] == "NOT_CREDITED"


def test_parallel_sp_reservation_does_not_block_hp_evidence_or_replay(
        tmp_path, monkeypatch):
    args = _fixture(tmp_path)
    ledger = args["process_ledger"]
    ledger.reserve("other:sp:run:000000:sp.campaign", "SP_FUZZ", 3)
    lead = freeze_hp_guided_crash_lead(**args)
    assert lead["status"] == "HP_CRASH_INPUT_FROZEN_UNVERIFIED"
    # Construct a fresh parent claim with the same identity, while the SP
    # lease remains active in the shared physical ledger.
    from vulnerabilityanalysis import official_harness

    original = tmp_path / "original-binary"
    original.write_bytes(b"original qualified binary")
    normal = tmp_path / "normal-seed"
    normal.write_bytes(b"normal input")

    class QualifiedFixture:
        product_issued = True
        binary = original
        binary_sha256 = hashlib.sha256(original.read_bytes()).hexdigest()
        normal_seed = normal
        normal_seed_sha256 = hashlib.sha256(normal.read_bytes()).hexdigest()
        harness_sha256 = "a" * 64
        source_tree_sha256 = "b" * 64

    q = QualifiedFixture()
    monkeypatch.setattr(official_harness, "OfficialPinnedQualification",
                        QualifiedFixture)
    monkeypatch.setattr(official_harness, "_qualification_pins_ok",
                        lambda value: value is q)
    physical_claim = tmp_path / "HP_PHYSICAL_CLAIM.json"
    physical_claim.write_text(json.dumps({
        "kind": "FBV2_HP_PHYSICAL_CLAIM_V1", **IDS,
        "assertion_selection": {"selected_assertion_id": "assertion"},
        "binary_sha256": q.binary_sha256,
        "harness_sha256": q.harness_sha256,
        "source_tree_sha256": q.source_tree_sha256,
    }))
    replay_args = {"lead": lead, "physical_claim_path": physical_claim,
                   "physical_claim_sha256": hashlib.sha256(
                       physical_claim.read_bytes()).hexdigest(),
                   "qualification": q, "process_ledger": ledger}
    assert admit_hp_original_replay(**replay_args)["status"] == (
        "HP_ORIGINAL_REPLAY_ADMITTED_UNVERIFIED")
    row = replay_hp_original_crash(
        **replay_args, output_dir=tmp_path / "replay", timeout_seconds=1,
        wall_seconds=60, output_limit_bytes=1_000_000,
        provider_free_fixture=True,
        runtime_factory=_scripted_replay_factory([
            _control(), _asan(), _asan()]))
    assert row["status"] == "HP_REPLAY_MATCHED_PENDING_SECURITY"
    assert "other:sp:run:000000:sp.campaign" in ledger.snapshot()["active"]


def test_unrelated_sp_reservation_after_receipt_snapshot_keeps_hp_freeze(
        tmp_path, monkeypatch):
    args = _fixture(tmp_path)
    ledger = args["process_ledger"]
    original_receipt = ledger.receipt_snapshot

    def racing_receipt():
        state, digest = original_receipt()
        ledger.reserve("other:sp:run:000000:sp.campaign", "SP_FUZZ", 3)
        return state, digest

    monkeypatch.setattr(ledger, "receipt_snapshot", racing_receipt)
    lead = freeze_hp_guided_crash_lead(**args)
    assert lead["status"] == "HP_CRASH_INPUT_FROZEN_UNVERIFIED"
    assert "other:sp:run:000000:sp.campaign" in ledger.snapshot()["active"]


def test_original_replay_abnormal_normal_control_blocks_crash_credit(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    row = replay_hp_original_crash(
        **args, output_dir=tmp_path / "replay", timeout_seconds=1,
        wall_seconds=60, output_limit_bytes=1_000_000,
        provider_free_fixture=True,
        runtime_factory=_scripted_replay_factory([_asan()]))
    assert row["status"] == "INCOMPLETE_HP_NORMAL_CONTROL"
    assert len(row["observations"]) == 1
    assert row["security_gate_credit"] == "NOT_CREDITED"


def test_hp_replay_local_wall_limit_preserves_unrelated_sp_work(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    ledger = args["process_ledger"]
    with pytest.raises(ProcessEnvelopeStop) as stopped:
        replay_hp_original_crash(
            **args, output_dir=tmp_path / "replay", timeout_seconds=1,
            wall_seconds=0.01, output_limit_bytes=1_000_000,
            provider_free_fixture=True,
            runtime_factory=_scripted_replay_factory([_control()]))
    assert stopped.value.status == "STOPPED_LOCAL_WALL_LIMIT"
    assert ledger.snapshot()["stop_status"] is None
    ledger.reserve("other:sp:run:000000:sp.campaign", "SP_FUZZ", 3)
    assert "other:sp:run:000000:sp.campaign" in ledger.snapshot()["active"]
    failure = json.loads((tmp_path / "replay" / "HP_REPLAY_RESULT.json").read_text())
    assert failure["status"] == "INCOMPLETE_HP_ORIGINAL_REPLAY_EXCEPTION"
    assert failure["security_gate_credit"] == "NOT_CREDITED"


def test_original_replay_rejects_unpinned_runtime_environment(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    base = _scripted_replay_factory([_control()])

    class BadEnvironment(base):
        def __init__(self, timeout):
            super().__init__(timeout)
            self.last_asan_options = "handle_abort=1"
            self.last_environment["ASAN_OPTIONS"] = "handle_abort=1"

    with pytest.raises(ValueError, match="environment differs"):
        replay_hp_original_crash(
            **args, output_dir=tmp_path / "replay", timeout_seconds=1,
            wall_seconds=60, output_limit_bytes=1_000_000,
            provider_free_fixture=True, runtime_factory=BadEnvironment)
    failure = json.loads((tmp_path / "replay" / "HP_REPLAY_RESULT.json").read_text())
    assert failure["status"] == "INCOMPLETE_HP_ORIGINAL_REPLAY_EXCEPTION"
    assert failure["security_gate_credit"] == "NOT_CREDITED"


def test_reproof_rejects_forged_status_and_changed_runtime_artifact(
        tmp_path, monkeypatch):
    args = _admission_case(tmp_path, monkeypatch)
    row = replay_hp_original_crash(
        **args, output_dir=tmp_path / "replay", timeout_seconds=1,
        wall_seconds=60, output_limit_bytes=1_000_000,
        provider_free_fixture=True,
        runtime_factory=_scripted_replay_factory([
            _control(), _asan(), _asan()]))
    forged = {**row, "execution_origin": "PINNED_RUNTIME_EXECUTOR"}
    with pytest.raises(ValueError, match="persisted bytes"):
        reprove_hp_original_replay(replay_result=forged, **args)
    replay_runtime = tmp_path / "replay" / "independent_replay-runtime.json"
    replay_runtime.write_text(replay_runtime.read_text() + " ")
    with pytest.raises(ValueError, match="runtime bytes changed"):
        reprove_hp_original_replay(replay_result=row, **args)
