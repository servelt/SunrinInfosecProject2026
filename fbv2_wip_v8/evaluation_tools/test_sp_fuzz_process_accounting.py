"""Provider-free SP fuzz accounting through the existing V2 process ledger."""

from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_persistent_physical_fuzz_ledger import PhysicalBudgetExhausted
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from vulnerabilityanalysis.analysis import RetryLedger
from vulnerabilityanalysis.models import SuspiciousPoint
from vulnerabilityanalysis.runtime import ProcessEnvelopeStop, fuzz_locally
from vulnerabilityanalysis.scan import run_targeted_fuzz


def _point() -> SuspiciousPoint:
    return SuspiciousPoint("sp", "worker", "direction", "parse", "target.c",
                           "target.c:1", "read", "bounds", [], "bytes",
                           [], [], [], [])


def _prepared(tmp_path: Path, *, fuzz_budget: float):
    binary = tmp_path / "binary"
    binary.write_bytes(b"provider-free binary placeholder")
    corpus = tmp_path / "corpus" / "candidate" / "sp"
    corpus.mkdir(parents=True)
    (corpus / "seed").write_bytes(b"normal")
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "physical.json", wall_total_seconds=120,
        fuzz_total_seconds=fuzz_budget)
    envelope = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id="work", assertion_id="sp", attempt_id="one",
        output_limit_bytes=4096, total_wall_seconds=120,
        pin_hook=lambda _phase, _command: None)
    return binary, ledger, envelope


def _fake_process(command, **_kwargs):
    if command[-1] == "-help=1":
        return subprocess.CompletedProcess(command, 0, "max_total_time", "")
    return subprocess.CompletedProcess(command, 0, "", "#2 NEW cov: 2 ft: 2\n")


def test_sp_probe_and_fuzz_share_one_v2_wall_and_fuzz_account(tmp_path):
    binary, ledger, envelope = _prepared(tmp_path, fuzz_budget=60)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               side_effect=_fake_process) as launched:
        result = run_targeted_fuzz(_point(), binary, tmp_path, RetryLedger(2),
                                   [], seconds=1, process_envelope=envelope)
    assert result.type == "FUZZING"
    assert launched.call_count == 2
    snapshot = ledger.snapshot()
    assert [row["kind"] for row in snapshot["finished"]] == [
        "AUX_PROCESS", "SP_FUZZ"]
    assert snapshot["active"] == {}
    assert snapshot["stop_status"] is None
    assert snapshot["fuzz_spent_seconds"] == snapshot["finished"][1]["physical_seconds"]
    assert snapshot["wall_spent_seconds"] == sum(
        row["physical_seconds"] for row in snapshot["finished"])


def test_sp_fuzz_budget_refusal_happens_before_fuzz_launch(tmp_path):
    binary, ledger, envelope = _prepared(tmp_path, fuzz_budget=1)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               side_effect=_fake_process) as launched:
        with pytest.raises(ProcessEnvelopeStop) as stopped:
            run_targeted_fuzz(_point(), binary, tmp_path, RetryLedger(2),
                              [], seconds=1, process_envelope=envelope)
    assert stopped.value.status == "PENDING_PHYSICAL_BUDGET"
    assert launched.call_count == 1  # only the accounted interface probe
    snapshot = ledger.snapshot()
    assert [row["kind"] for row in snapshot["finished"]] == ["AUX_PROCESS"]
    assert snapshot["fuzz_spent_seconds"] == 0
    assert snapshot["active"] == {}
    assert not (tmp_path / "runtime" / "sp.targeted_fuzz.json").exists()


def test_global_charge_reduces_sp_fuzz_reservation(tmp_path):
    binary, ledger, envelope = _prepared(tmp_path, fuzz_budget=30)
    ledger.reserve("earlier-global", "GLOBAL_FUZZ", 10)
    ledger.finish("earlier-global", physical_seconds=10,
                  cleanup_complete=True)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               side_effect=_fake_process) as launched:
        with pytest.raises(ProcessEnvelopeStop) as stopped:
            run_targeted_fuzz(_point(), binary, tmp_path, RetryLedger(2),
                              [], seconds=1, process_envelope=envelope)
    assert stopped.value.status == "PENDING_PHYSICAL_BUDGET"
    assert launched.call_count == 1
    snapshot = ledger.snapshot()
    assert [row["kind"] for row in snapshot["finished"]] == [
        "GLOBAL_FUZZ", "AUX_PROCESS"]
    assert snapshot["fuzz_spent_seconds"] == 10


def test_sp_fuzz_kind_cannot_run_without_envelope(tmp_path):
    binary, _, _ = _prepared(tmp_path, fuzz_budget=60)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once") as launched:
        with pytest.raises(ValueError, match="requires a V2 process envelope"):
            fuzz_locally(binary, tmp_path / "seed-corpus", seconds=1,
                         process_kind="SP_FUZZ")
    launched.assert_not_called()


def test_overlapping_physical_reservations_sum_without_parallel_discount(
        tmp_path):
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "parallel.json", wall_total_seconds=102,
        fuzz_total_seconds=102)
    ledger.reserve("global", "GLOBAL_FUZZ", 67.5)
    ledger.reserve("sp-probe", "AUX_PROCESS", 14.5)
    ledger.reserve("sp-campaign", "SP_FUZZ", 20)
    active = ledger.snapshot()
    assert active["wall_reserved_seconds"] == 102
    assert active["fuzz_reserved_seconds"] == 87.5
    with pytest.raises(PhysicalBudgetExhausted):
        ledger.reserve("parallel-extra", "AUX_PROCESS", 0.001)
    ledger.finish("sp-probe", physical_seconds=2, cleanup_complete=True)
    ledger.finish("sp-campaign", physical_seconds=3, cleanup_complete=True)
    ledger.finish("global", physical_seconds=4, cleanup_complete=True)
    settled = ledger.snapshot()
    assert settled["wall_spent_seconds"] == 9
    assert settled["fuzz_spent_seconds"] == 7
    assert settled["active"] == {}


def test_sp_local_deadline_accepts_exact_envelope_and_rejects_epsilon_below(
        tmp_path):
    exact_ledger = PersistentProcessLedgerV2.create(
        tmp_path / "exact.json", wall_total_seconds=40,
        fuzz_total_seconds=40)
    with patch("dev_process_envelope_v2.time.monotonic", return_value=100):
        exact = DevelopmentProcessEnvelopeV2(
            exact_ledger, work_item_id="work", assertion_id="sp",
            attempt_id="exact", output_limit_bytes=4096,
            total_wall_seconds=40, pin_hook=lambda *_args: None)
        lease = exact.before_process(
            ["fuzzer"], cwd=None, env=None, timeout=30.5,
            kind="SP_FUZZ", segment="sp.campaign")
        with patch("dev_process_envelope_v2.time.monotonic", return_value=101):
            exact.after_process(
                lease, elapsed_seconds=1, cleanup_complete=True,
                output_limited=False, error=None)

    short_ledger = PersistentProcessLedgerV2.create(
        tmp_path / "short.json", wall_total_seconds=40,
        fuzz_total_seconds=40)
    with patch("dev_process_envelope_v2.time.monotonic", return_value=100):
        short = DevelopmentProcessEnvelopeV2(
            short_ledger, work_item_id="work", assertion_id="sp",
            attempt_id="short", output_limit_bytes=4096,
            total_wall_seconds=39.999, pin_hook=lambda *_args: None)
        with pytest.raises(ProcessEnvelopeStop) as stopped:
            short.before_process(
                ["fuzzer"], cwd=None, env=None, timeout=30.5,
                kind="SP_FUZZ", segment="sp.campaign")
    assert stopped.value.status == "STOPPED_WALL_LIMIT"
    assert short_ledger.snapshot()["active"] == {}
