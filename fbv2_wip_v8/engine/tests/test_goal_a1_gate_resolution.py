"""Goal A.1 (G-1): structured, authenticated PoV Gate terminality.

These tests drive the real adapter (``consume_qualified_pov_observation``),
the real product ``execute_poc`` / ``_verify_observed_target_crash`` /
``independent_replay`` code, the real V2 process envelope and durable process
ledger, and the real run-result consumer (``run_original_public_dev``). Only
the process launch itself, sanitizer triage, and root-cause/hypothesis
analysis are substituted, so no Target, Fuzzer, model, MongoDB or network is
touched.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId
import pytest

from devtools import original_public_live as live
from devtools.product_qualified_runtime import (
    QualifiedRuntimeBinding, consume_qualified_pov_observation,
    verify_terminal_pov_gate)
from tests.test_goal_a_v3r6_contracts import _public_dev
from tests.test_product_qualified_runtime import _ready, pinned_binary  # noqa: F401

UAF = ("==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602 "
       "at pc 0x1 bp 0x2 sp 0x3\nREAD of size 1 at 0x602 thread T0\n"
       "    #0 0x4f in victim /src/target.c:15:3\n"
       "    #1 0x5f in LLVMFuzzerTestOneInput /src/fuzz.c:4:1\n")
SEGV = ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000 "
        "(pc 0x1 bp 0x2 sp 0x3 T0)\n"
        "    #0 0x4f in other_function /src/other.c:40:2\n")
UNSYMBOLIZED = ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000 "
                "(pc 0x1 bp 0x2 sp 0x3 T0)\n    #0 0x4f  (/target/binary+0x1234)\n")
TERMINAL = "TERMINAL_REJECTED"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _triage(result, *_a, **_k):
    completed = (bool(result.sanitizer) and not result.timed_out and
                 result.exit_code is not None)
    return {"category": "TARGET_CRASH" if completed else "ENVIRONMENT_ERROR",
            "top_source_frame": None, "source_provenance": None,
            "resource_exhaustion_kind": None, "sp_linked": False,
            "verification_eligible": False, "crash_relation": "UNRELATED",
            "relevant_stack_frames": [], "allocation_stack": [], "free_stack": []}


def _gate(tmp_path, *, primary: str, replay=None, confirmed=False,
          freeze_error: Exception | None = None, original: str | None = None,
          extra_patches=(), primary_code: int = 1):
    """Run one real adapter consumption; return (adapter, request, ledger, row)."""
    from vulnerabilityanalysis import official_harness, scan
    from vulnerabilityanalysis.final_verification import crash_fingerprint
    from vulnerabilityanalysis.models import RootCauseResult, SuspiciousPoint

    adapter, request, ledger, _binary = _ready(tmp_path)
    with patch("vulnerabilityanalysis.runtime._guarded_run_once",
               return_value=subprocess.CompletedProcess(
                   [], 1, "", original if original is not None else primary)):
        first = adapter.execute(request)
    assert first.status == "CRASH_OBSERVED"
    adapter.repos.povs.collection.update_one(
        {"_id": ObjectId(request.pov_id)},
        {"$set": {"qualified_runtime": {
            "status": first.status, "input_sha256": first.input_sha256,
            "binary_sha256": first.binary_sha256,
            "runtime_receipt_path": str(first.runtime_receipt_path),
            "runtime_receipt_sha256": first.runtime_receipt_sha256,
            "physical_receipt_path": str(first.physical_receipt_path),
            "physical_receipt_sha256": first.physical_receipt_sha256}}})
    harness = tmp_path / "harness.c"
    harness.write_text("// provider-free fixture\n")
    adapter.binding = QualifiedRuntimeBinding(SimpleNamespace(
        source_root=tmp_path, harness=harness, source_tree_sha256="1" * 64,
        harness_sha256="2" * 64, contract_sha256="3" * 64), adapter.execute)
    launches = []

    def launch(command, **kwargs):
        launches.append(list(command))
        if len(launches) == 1:
            return subprocess.CompletedProcess(command, primary_code, "", primary)
        if replay == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        code, stderr = replay
        return subprocess.CompletedProcess(command, code, "", stderr)

    def hypothesis(result, *_a, **_k):
        crash_id = crash_fingerprint(result)
        return SuspiciousPoint(crash_id, "w", "d", "victim", "src/target.c",
                               "src/target.c:15", "use", "UAF", [], "UNKNOWN",
                               [], [], [], []), {"crash_id": crash_id}

    def root(point, result, *_a, **_k):
        verdict = ("CONFIRMED" if confirmed and point.sp_id == crash_fingerprint(result)
                   else "INCONCLUSIVE")
        return RootCauseResult(point.sp_id, crash_fingerprint(result), "EXACT", "victim",
                               "target.c:15", result.sanitizer, [], [], [], "", "",
                               [], [], [], verdict)

    def broken_freeze(*_a, **_k):
        raise freeze_error

    patches = [patch("vulnerabilityanalysis.runtime._guarded_run_once", side_effect=launch),
               patch.object(official_harness, "OfficialPinnedQualification", SimpleNamespace),
               patch.object(scan, "triage_crash", _triage),
               patch.object(scan, "verify_root_cause", root)]
    if confirmed:
        patches.append(patch.object(scan, "observed_crash_hypothesis", hypothesis))
    if freeze_error is not None:
        patches.append(patch.object(scan, "freeze_poc", broken_freeze))
    patches.extend(extra_patches)
    for item in patches:
        item.start()
    try:
        row = consume_qualified_pov_observation(
            adapter, request.pov_id, recheck=lambda: None, timeout_seconds=2,
            model_gate=None, gate_wall_seconds=60)
    finally:
        for item in reversed(patches):
            item.stop()
    return adapter, request, ledger, row


def _identity(adapter):
    return SimpleNamespace(task_id=adapter.task_id, run_id=adapter.run_id,
                           run_dir=adapter.root.parent)


def _terminal_ids(adapter, ledger, rows, observed):
    return live._authenticated_terminal_gate_pov_ids(
        _identity(adapter), rows, observed, set(), ledger.snapshot()["finished"])


def _run_result(tmp_path, monkeypatch, adapter, ledger, row):
    return _public_dev(tmp_path / "result", monkeypatch, {row["pov_id"]: row},
                       task_id=adapter.task_id, run_id=adapter.run_id,
                       run_dir=adapter.root.parent, pov_root=adapter.root,
                       finished=ledger.snapshot()["finished"])


@pytest.fixture
def result_dir(tmp_path):
    (tmp_path / "result").mkdir()
    return tmp_path


# ---- terminal cases (proven) ----------------------------------------------

def test_unsupported_crash_type_is_pending_and_exposed(
        result_dir, monkeypatch, pinned_binary):
    # Goal A.1.1 (R9): no signed out-of-scope policy yet, so an unsupported
    # target crash is never settled; it is surfaced for human review.
    adapter, request, ledger, row = _gate(result_dir, primary=SEGV)
    assert row["product_gate_status"] == "BLOCKED_UNSUPPORTED_CRASH_TYPE"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", "UNSUPPORTED_CRASH_TYPE_HUMAN_REVIEW_PENDING")
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["status"] == "INCOMPLETE"
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["pov_crashes_gate_terminal_not_verified_count"] == 0
    assert result["pov_crashes_unsupported_type_pending_count"] == 1
    assert result["pov_crashes_unsupported_type_pending"] == [{
        "pov_id": request.pov_id, "observed_sanitizer": row["observed_sanitizer"],
        "reason": "UNSUPPORTED_CRASH_TYPE_HUMAN_REVIEW_PENDING"}]
    assert result["automatic_discovery_verified_count"] == 0


def test_single_clean_exit_replay_stays_pending(
        result_dir, monkeypatch, pinned_binary):
    adapter, request, ledger, row = _gate(
        result_dir, primary=UAF, replay=(0, ""), confirmed=True)
    assert row["product_gate_status"] == "BLOCKED_INDEPENDENT_REPLAY"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", "REPLAY_NOT_REPRODUCED_REPEAT_POLICY_UNDEFINED")
    assert row["independent_replay_status"] == "NOT_REPRODUCED"
    assert row["physical_step_completed"] is False
    segments = sorted(item["key"].rsplit(":", 1)[1] for item in row["gate_process_receipts"])
    assert segments == ["pov.observed_independent_replay", "pov.primary_execution"]
    assert {item["role"] for item in row["gate_resolution_evidence"]} == {
        "product_runtime", "canonical_crash", "fixed_poc", "fixed_input",
        "replay_validation", "replay_runtime"}
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["pov_crashes_gate_terminal_not_verified_ids"] == []
    assert result["status"] == "INCOMPLETE"
    assert result["pov_crashes_gate_verified_count"] == 0
    assert result["model_lineage_gate_verified_pov_count"] == 0
    assert result["automatic_discovery_verified_count"] == 0


# ---- pending cases ----------------------------------------------------------

@pytest.mark.parametrize("replay, reason", [
    ("timeout", "REPLAY_PROCESS_INCOMPLETE"),          # G-1 counterexample
    ((-9, ""), "REPLAY_KILLED_BY_SIGNAL"),             # SIGKILL / OOM killer
    ((127, ""), "REPLAY_NONZERO_EXIT_WITHOUT_ORACLE"),  # loader failure
    ((1, UNSYMBOLIZED), "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED"),
    # Goal A.1.1 (F8): one different, fully symbolized crash is not conclusive.
    ((1, SEGV), "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED"),
])
def test_uncertain_replay_stays_pending_and_run_incomplete(
        result_dir, monkeypatch, pinned_binary, replay, reason):
    adapter, request, ledger, row = _gate(
        result_dir, primary=UAF, replay=replay, confirmed=True)
    # Same legacy label as a conclusive rejection; only the resolution differs.
    assert row["product_gate_status"] == "BLOCKED_INDEPENDENT_REPLAY"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", reason)
    assert row["physical_step_completed"] is False
    if replay == "timeout":
        assert row["independent_replay_status"] == "ENVIRONMENT_ERROR"
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["pov_crashes_gate_terminal_not_verified_count"] == 0
    assert result["status"] == "INCOMPLETE"
    assert result["verification_status"] == "PENDING_INDEPENDENT_VALIDATION"


def test_fixed_poc_block_is_pending(result_dir, monkeypatch, pinned_binary):
    adapter, _request, ledger, row = _gate(
        result_dir, primary=UAF, confirmed=True, freeze_error=OSError("disk full"))
    assert row["product_gate_status"] == "BLOCKED_FIXED_POC"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", "FIXED_POC_UNAVAILABLE")
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["status"] == "INCOMPLETE"


def test_source_provenance_block_is_pending(result_dir, monkeypatch, pinned_binary):
    adapter, _request, ledger, row = _gate(result_dir, primary=UAF)
    assert row["product_gate_status"] == "BLOCKED_SOURCE_PROVENANCE"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", "SOURCE_PROVENANCE_UNVERIFIED")
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["pov_crashes_pending_independent_validation"] == 1


# ---- forged / missing evidence ---------------------------------------------

def _rewrite_outcome(adapter, row, **changes):
    forged = {**row, **changes}
    path = adapter.root.parent / "pov-validation" / row["pov_id"] / "outcome.json"
    path.write_text(json.dumps(forged, sort_keys=True))
    return forged


@pytest.fixture
def terminal_replay(result_dir, pinned_binary):
    adapter, request, ledger, row = _gate(
        result_dir, primary=UAF, replay=(0, ""), confirmed=True)
    # A forged legacy terminal receipt must remain unprovable after R1.
    row = {**row, "gate_resolution": TERMINAL,
           "gate_resolution_reason": "REPLAY_NOT_REPRODUCED_CLEAN_EXIT"}
    claim = adapter.root.parent / "pov-validation" / row["pov_id"]
    assert _terminal_ids(adapter, ledger, [row], [row["pov_id"]]) == set()
    return adapter, ledger, row, claim


def test_tampered_artifact_is_pending(terminal_replay):
    adapter, ledger, row, _claim = terminal_replay
    runtime = Path(next(item["path"] for item in row["gate_resolution_evidence"]
                        if item["role"] == "replay_runtime"))
    runtime.write_text(runtime.read_text().replace('"exit_code": 0', '"exit_code": 0 '))
    assert verify_terminal_pov_gate(row, claim_dir=_claim, finished_rows=ledger.snapshot()[
        "finished"]) == "NOT_A_PROVABLE_OUTCOME"
    assert _terminal_ids(adapter, ledger, [row], [row["pov_id"]]) == set()


def test_rehashed_forged_validation_is_still_pending(terminal_replay):
    # Consistent SHA-256 alone is not enough: the verdict is recomputed from the
    # saved RuntimeResult. Forge a timed-out runtime with a "clean" validation.
    adapter, ledger, row, claim = terminal_replay
    evidence = {item["role"]: item for item in row["gate_resolution_evidence"]}
    runtime_path = Path(evidence["replay_runtime"]["path"])
    runtime = json.loads(runtime_path.read_text())
    runtime.update(timed_out=True, exit_code=None)
    runtime_path.write_text(json.dumps(runtime))
    evidence["replay_runtime"]["sha256"] = _sha(runtime_path)
    partial = _rewrite_outcome(adapter, row,
                               gate_resolution_evidence=list(evidence.values()))
    # The producer's own recorded runtime hash no longer matches.
    assert verify_terminal_pov_gate(partial, claim_dir=claim, finished_rows=ledger.snapshot()[
        "finished"]) == "NOT_A_PROVABLE_OUTCOME"
    # Forge the canonical record and every hash consistently: the verdict is
    # still recomputed from the saved RuntimeResult and is not conclusive.
    canonical_path = Path(evidence["canonical_crash"]["path"])
    canonical = json.loads(canonical_path.read_text())
    canonical["independent_gate_resolution"]["replay"]["runtime_sha256"] = _sha(runtime_path)
    canonical_path.write_text(json.dumps(canonical))
    evidence["canonical_crash"]["sha256"] = _sha(canonical_path)
    forged = _rewrite_outcome(adapter, row, gate_resolution_evidence=list(evidence.values()),
                              canonical_crash_sha256=_sha(canonical_path))
    assert verify_terminal_pov_gate(forged, claim_dir=claim, finished_rows=ledger.snapshot()[
        "finished"]) == "NOT_A_PROVABLE_OUTCOME"
    assert _terminal_ids(adapter, ledger, [forged], [row["pov_id"]]) == set()


@pytest.mark.parametrize("change", [
    {"run_id": "another_run"},
    {"task_id": str(ObjectId())},
    {"pov_id": str(ObjectId())},
    {"input_sha256": "0" * 64},
])
def test_identity_mismatch_is_pending(terminal_replay, change):
    adapter, ledger, row, _claim = terminal_replay
    forged = _rewrite_outcome(adapter, row, **change)
    assert _terminal_ids(adapter, ledger, [forged], [row["pov_id"], forged["pov_id"]]) == set()


def test_row_differing_from_durable_outcome_is_pending(terminal_replay):
    adapter, ledger, row, _claim = terminal_replay
    assert _terminal_ids(adapter, ledger, [{**row, "observed_sanitizer": "x"}],
                         [row["pov_id"]]) == set()


def test_missing_process_receipt_is_pending(terminal_replay):
    adapter, ledger, row, claim = terminal_replay
    finished = [item for item in ledger.snapshot()["finished"]
                if not item["key"].endswith(":pov.observed_independent_replay")]
    assert verify_terminal_pov_gate(row, claim_dir=claim, finished_rows=finished) == (
        "NOT_A_PROVABLE_OUTCOME")
    unclean = [{**item, "cleanup_complete": False} for item in ledger.snapshot()["finished"]]
    assert verify_terminal_pov_gate(row, claim_dir=claim, finished_rows=unclean) == (
        "NOT_A_PROVABLE_OUTCOME")


@pytest.mark.parametrize("change", [
    {"gate_resolution_reason": "ROOT_CAUSE_NOT_CONFIRMED"},
    {"gate_resolution_reason": "FIXED_POC_UNAVAILABLE"},
    {"product_gate_status": "BLOCKED_SOMETHING_NEW"},
    {"product_gate_status": "BLOCKED_SOURCE_PROVENANCE"},
    {"gate_resolution": "VERIFIED"},
    {"gate_resolution_evidence": []},
    {"kind": "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1"},
])
def test_unknown_or_forged_resolution_is_pending(terminal_replay, change):
    adapter, ledger, row, _claim = terminal_replay
    forged = _rewrite_outcome(adapter, row, **change)
    assert _terminal_ids(adapter, ledger, [forged], [row["pov_id"]]) == set()


def test_duplicate_or_unobserved_rows_are_pending(terminal_replay):
    adapter, ledger, row, _claim = terminal_replay
    assert _terminal_ids(adapter, ledger, [row, dict(row)], [row["pov_id"]]) == set()
    assert _terminal_ids(adapter, ledger, [row], []) == set()


def test_bare_blocked_rows_are_never_terminal(result_dir, monkeypatch):
    rows = {}
    for status in ("BLOCKED_INDEPENDENT_REPLAY", "BLOCKED_UNSUPPORTED_CRASH_TYPE",
                   "BLOCKED_ROOT_CAUSE", "BLOCKED_SECURITY_PROPERTY",
                   "BLOCKED_VERIFIED_GATE", "BLOCKED_FIXED_POC",
                   "BLOCKED_SOURCE_PROVENANCE", "BLOCKED_UNKNOWN_FUTURE"):
        pov = str(ObjectId())
        rows[pov] = {"kind": "FBV2_POV_PRODUCT_GATE_OUTCOME_V1", "pov_id": pov,
                     "product_gate_status": status,
                     "gate_resolution": TERMINAL,
                     "gate_resolution_reason": "UNSUPPORTED_CRASH_TYPE"}
    result = _public_dev(result_dir / "result", monkeypatch, rows)
    assert result["pov_crashes_pending_independent_validation"] == len(rows)
    assert result["pov_crashes_gate_terminal_not_verified_count"] == 0
    assert result["status"] == "INCOMPLETE"


def test_prefix_rule_is_gone():
    source = Path(live.__file__).read_text()
    assert 'startswith("BLOCKED_")' not in source
    assert "startswith('BLOCKED_')" not in source


# ---- internal red-team regressions (R2, R4) --------------------------------

def test_product_primary_must_reobserve_the_original_crash(result_dir, monkeypatch,
                                                           pinned_binary):
    # R2: the original PoV observed one UAF site; the product's own re-run
    # crashes elsewhere. Even a clean-exit replay of that cannot settle it.
    other = UAF.replace("victim /src/target.c:15:3", "elsewhere /src/target.c:99:1")
    adapter, _request, ledger, row = _gate(result_dir, primary=UAF, original=other,
                                           replay=(0, ""), confirmed=True)
    assert row["product_gate_status"] == "BLOCKED_INDEPENDENT_REPLAY"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", "REPLAY_NOT_REPRODUCED_REPEAT_POLICY_UNDEFINED")
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["status"] == "INCOMPLETE"


def test_real_consume_verified_is_unchanged(result_dir, monkeypatch, pinned_binary):
    from vulnerabilityanalysis import scan
    from vulnerabilityanalysis.models import SecurityPropertyResult

    def confirmed_security(point, *_a, **_k):
        return SecurityPropertyResult(point.sp_id, "CONFIRMED", ["e"], ["h"], ["i"], [])
    # The REAL seven-condition promote_verified runs (only the security
    # property evidence is supplied); Goal A.1.2 adds the fingerprint proof.
    adapter, request, ledger, row = _gate(
        result_dir, primary=UAF, replay=(1, UAF), confirmed=True,
        extra_patches=[patch.object(scan, "check_security_property", confirmed_security)])
    assert row["product_gate_status"] == "VERIFIED"
    assert row["gate_resolution_detail"] is None
    assert {item["role"] for item in row["gate_resolution_evidence"]} == {
        "product_runtime", "canonical_crash", "fixed_poc", "fixed_input",
        "replay_validation", "replay_runtime", "candidate", "root_cause",
        "security_property"}
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "VERIFIED", "GATE_VERIFIED")
    assert row["security_gate_completed"] is True and row["security_gate_result"] is True
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["pov_crashes_gate_verified_count"] == 1
    assert result["pov_crashes_gate_terminal_not_verified_count"] == 0
    assert result["pov_crashes_pending_independent_validation"] == 0
    assert result["verification_status"] == "PRODUCT_GATE_VERIFIED_MODEL_ORIGIN_UNPROVEN"
    assert result["automatic_discovery_verified_count"] == 0


def test_missing_producer_resolution_is_pending(result_dir, monkeypatch, pinned_binary):
    from vulnerabilityanalysis import scan
    adapter, _request, ledger, row = _gate(
        result_dir, primary=SEGV,
        extra_patches=[patch.object(scan, "_set_gate_resolution",
                                    lambda *_a, **_k: None)])
    assert row["product_gate_status"] == "BLOCKED_UNSUPPORTED_CRASH_TYPE"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", "PRODUCER_RESOLUTION_MISSING")
    assert _run_result(result_dir, monkeypatch, adapter, ledger, row)["status"] == (
        "INCOMPLETE")


@pytest.mark.parametrize("damage", ["overrun", "output_limited", "duplicate", "active"])
def test_replay_row_receipt_defects_are_pending(terminal_replay, damage):
    _adapter, ledger, row, claim = terminal_replay
    finished = ledger.snapshot()["finished"]
    replay = [item for item in finished
              if item["key"].endswith(":pov.observed_independent_replay")]
    assert len(replay) == 1
    if damage == "duplicate":
        key = replay[0]["key"].replace(":000001:", ":000009:")
        finished = finished + [{**replay[0], "key": key}]
    elif damage == "active":
        finished = [item for item in finished if item is not replay[0]] + [
            {**replay[0], "kind": "SP_FUZZ"}]
    else:
        finished = [({**item, damage: True} if item is replay[0] else item)
                    for item in finished]
    assert verify_terminal_pov_gate(row, claim_dir=claim, finished_rows=finished) == (
        "NOT_A_PROVABLE_OUTCOME")


@pytest.mark.parametrize("change", [
    {"run_id": "another_run"}, {"task_id": str(ObjectId())},
    {"sp_id": str(ObjectId())}, {"binary_sha256": "0" * 64},
])
def test_claim_identity_binding_inside_verifier(terminal_replay, change):
    _adapter, ledger, row, claim = terminal_replay
    assert verify_terminal_pov_gate({**row, **change}, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) == (
        "NOT_A_PROVABLE_OUTCOME")


# ---- internal red-team round 2 regressions (F2, F5, F6) -------------------

def test_signal_killed_primary_is_not_unsupported_terminal(result_dir, monkeypatch,
                                                           pinned_binary):
    # F2: a sanitizer line followed by an OOM/cgroup kill is not a completed crash.
    adapter, _request, ledger, row = _gate(result_dir, primary=SEGV, primary_code=-9)
    assert row["product_gate_status"] == "BLOCKED_UNSUPPORTED_CRASH_TYPE"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", "UNSUPPORTED_CRASH_TYPE_PRIMARY_INCOMPLETE")
    assert _run_result(result_dir, monkeypatch, adapter, ledger, row)["status"] == (
        "INCOMPLETE")


def test_malformed_hash_consistent_evidence_is_pending_not_an_exception(terminal_replay):
    # F5: run assembly must not crash on malformed evidence.
    adapter, ledger, row, claim = terminal_replay
    evidence = {item["role"]: item for item in row["gate_resolution_evidence"]}
    runtime_path = Path(evidence["product_runtime"]["path"])
    runtime = json.loads(runtime_path.read_text())
    runtime["stderr"] = None
    runtime_path.write_text(json.dumps(runtime))
    evidence["product_runtime"]["sha256"] = _sha(runtime_path)
    forged = _rewrite_outcome(adapter, row, gate_resolution_evidence=list(evidence.values()),
                              product_runtime_sha256=_sha(runtime_path))
    assert verify_terminal_pov_gate(forged, claim_dir=claim, finished_rows=ledger.snapshot()[
        "finished"]) == "NOT_A_PROVABLE_OUTCOME"
    assert _terminal_ids(adapter, ledger, [forged], [row["pov_id"]]) == set()


def test_original_observation_receipt_is_rederived(terminal_replay):
    # F6: the claim's original_crash_id is not self-asserted.
    adapter, ledger, row, claim = terminal_replay
    original = Path(json.loads((claim / "claim.json").read_text())[
        "original_runtime_receipt_path"])
    assert original.is_file() and original.parent.name == row["pov_id"]
    original.write_text(original.read_text() + " ")
    assert verify_terminal_pov_gate(row, claim_dir=claim, finished_rows=ledger.snapshot()[
        "finished"]) == "NOT_A_PROVABLE_OUTCOME"


# ---- Goal A.1.1 (independent cold review: F9) ------------------------------

def test_signed_supervisor_rejects_inherited_sanitizer_options(monkeypatch):
    # F9: the signed runtime closure accepts only its exact environment, so an
    # externally injected ASAN_OPTIONS (e.g. allocator_may_return_null=1) is
    # refused before any product replay starts.
    from devtools import sp_runtime_closure_supervisor as supervisor
    assert not any(key.endswith("SAN_OPTIONS") or key.startswith(("ASAN", "UBSAN",
                                                                  "MSAN", "LSAN"))
                   for key in supervisor._EXPECTED_ENVIRONMENT)
    for key in list(__import__("os").environ):
        monkeypatch.delenv(key)
    for key, value in supervisor._EXPECTED_ENVIRONMENT.items():
        monkeypatch.setenv(key, value)
    assert supervisor._clean_environment() == supervisor._EXPECTED_ENVIRONMENT
    monkeypatch.setenv("ASAN_OPTIONS", "allocator_may_return_null=1")
    with pytest.raises(ValueError, match="environment is not exact"):
        supervisor._clean_environment()


# ---- Goal A.1.2 (independent cold review: same first line, other crash) -----

SHARED_ALPHA = (
    "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602 at pc 0x1\n"
    "READ of size 8 at 0x602 thread T0\n"
    "    #0 0x1 in shared_access /src/parser.c:101:5\n"
    "    #1 0x2 in caller_alpha /src/parser.c:300:3\n"
    "\nfreed by thread T0 here:\n"
    "    #0 0x3 in free /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:52:3\n"
    "    #1 0x4 in release_alpha /src/lifetime.c:70:3\n"
    "\npreviously allocated by thread T0 here:\n"
    "    #0 0x5 in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:68:3\n"
    "    #1 0x6 in make_node /src/lifetime.c:20:12\n")
SHARED_BETA = SHARED_ALPHA.replace(
    "caller_alpha /src/parser.c:300:3", "caller_beta /src/parser.c:400:3").replace(
    "release_alpha /src/lifetime.c:70:3", "release_beta /src/lifetime.c:80:3")


def _confirmed_security():
    from vulnerabilityanalysis import scan
    from vulnerabilityanalysis.models import SecurityPropertyResult
    return patch.object(
        scan, "check_security_property",
        lambda point, *_a, **_k: SecurityPropertyResult(
            point.sp_id, "CONFIRMED", ["e"], ["h"], ["i"], []))


def test_same_first_line_other_lifetime_crash_is_never_verified(
        result_dir, monkeypatch, pinned_binary):
    # Codex counterexample through producer -> adapter -> consumer: the replay
    # shares the first application line but is a different lifetime crash.
    adapter, request, ledger, row = _gate(
        result_dir, primary=SHARED_ALPHA, replay=(1, SHARED_BETA), confirmed=True,
        extra_patches=[_confirmed_security()])
    assert row["product_gate_status"] == "BLOCKED_INDEPENDENT_REPLAY"
    assert row["independent_replay_status"] == "INCONSISTENT"
    assert (row["gate_resolution"], row["gate_resolution_reason"]) == (
        "INCOMPLETE", "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["pov_crashes_gate_verified_count"] == 0
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["status"] == "INCOMPLETE"


@pytest.fixture
def verified_replay(result_dir, pinned_binary):
    adapter, request, ledger, row = _gate(
        result_dir, primary=SHARED_ALPHA, replay=(1, SHARED_ALPHA), confirmed=True,
        extra_patches=[_confirmed_security()])
    assert (row["product_gate_status"], row["gate_resolution"]) == ("VERIFIED", "VERIFIED")
    claim = adapter.root.parent / "pov-validation" / row["pov_id"]
    return adapter, ledger, row, claim


def _verified_ids(adapter, ledger, rows, observed):
    return live._authenticated_verified_gate_pov_ids(
        _identity(adapter), rows, observed, ledger.snapshot()["finished"])


def test_fuzzer_consumer_reproves_real_verified_artifacts(verified_replay):
    from devtools.product_qualified_runtime import verified_fuzzer_consumer_evidence
    adapter, _ledger, row, _claim = verified_replay
    fixed_path = next(Path(item["path"]) for item in row["gate_resolution_evidence"]
                      if item["role"] == "fixed_poc")
    fixed = json.loads(fixed_path.read_text())
    outcome = {
        "status": "VERIFIED", "gate_status": "VERIFIED",
        "poc_id": row["evaluation_pov_id"],
        "input_sha256": row["input_sha256"],
        "binary_sha256": row["binary_sha256"],
        "runtime_artifact": row["product_runtime_artifact"],
        "runtime_sha256": row["product_runtime_sha256"],
        "canonical_crash_id": row["gate_crash_id"],
        "canonical_crash_artifact": row["canonical_crash_artifact"],
        "canonical_crash_artifact_sha256": row["canonical_crash_sha256"],
        "qualification_identity": {
            "kind": "OFFICIAL_PINNED", "binary": fixed["target_binary"],
            "binary_sha256": fixed["binary_sha256"]},
    }
    assert verified_fuzzer_consumer_evidence(adapter.root.parent, outcome)
    assert not verified_fuzzer_consumer_evidence(
        adapter.root.parent, {**outcome, "input_sha256": "0" * 64})
    security_path = Path(json.loads(Path(row["canonical_crash_artifact"]).read_text())[
        "independent_security_artifact"])
    security = json.loads(security_path.read_text())
    security["status"] = "UNKNOWN"
    security_path.write_text(json.dumps(security))
    assert not verified_fuzzer_consumer_evidence(adapter.root.parent, outcome)


def test_identical_crash_is_verified_and_reproven_by_the_consumer(
        verified_replay, result_dir, monkeypatch):
    from devtools.product_qualified_runtime import verify_verified_pov_gate
    adapter, ledger, row, claim = verified_replay
    fixed = json.loads(next(Path(item["path"]) for item in row["gate_resolution_evidence"]
                            if item["role"] == "fixed_poc").read_text())
    assert fixed["expected_crash_fingerprint"] == row["gate_crash_id"]
    assert verify_verified_pov_gate(row, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) is None
    assert _verified_ids(adapter, ledger, [row], [row["pov_id"]]) == {row["pov_id"]}
    result = _run_result(result_dir, monkeypatch, adapter, ledger, row)
    assert result["pov_crashes_gate_verified_count"] == 1
    assert result["pov_crashes_pending_independent_validation"] == 0
    assert result["automatic_discovery_verified_count"] == 0


def test_mutated_security_result_cannot_retain_verified_credit(verified_replay):
    from devtools.product_qualified_runtime import verify_verified_pov_gate
    adapter, ledger, row, claim = verified_replay
    record = json.loads(Path(row["canonical_crash_artifact"]).read_text())
    security_path = Path(record["independent_security_artifact"])
    security = json.loads(security_path.read_text())
    assert security["status"] == "CONFIRMED"
    security.update(status="UNKNOWN", external_input_evidence=[],
                    harness_validity_evidence=[], impact_evidence=[])
    security_path.write_text(json.dumps(security))
    assert verify_verified_pov_gate(row, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) is not None
    assert _verified_ids(adapter, ledger, [row], [row["pov_id"]]) == set()


@pytest.mark.parametrize("role, change", [
    ("security_property", {"status": "UNKNOWN", "external_input_evidence": [],
                           "harness_validity_evidence": [], "impact_evidence": []}),
    ("root_cause", {"verdict": "INCONCLUSIVE"}),
    ("candidate", {"original_sp_id": "another-candidate"}),
])
def test_rehashed_promotion_inputs_cannot_retain_verified_credit(
        verified_replay, role, change):
    from devtools.product_qualified_runtime import verify_verified_pov_gate
    adapter, ledger, row, claim = verified_replay
    forged = _reforge(adapter, row, role, lambda data: data.update(change))
    assert verify_verified_pov_gate(forged, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) is not None
    assert _verified_ids(adapter, ledger, [forged], [row["pov_id"]]) == set()


def test_blocked_security_cannot_be_relabelled_verified(result_dir, pinned_binary):
    from devtools.product_qualified_runtime import verify_verified_pov_gate
    adapter, _request, ledger, row = _gate(
        result_dir, primary=SHARED_ALPHA, replay=(1, SHARED_ALPHA), confirmed=True)
    assert row["product_gate_status"] == "BLOCKED_SECURITY_PROPERTY"
    record_path = Path(row["canonical_crash_artifact"])
    record = json.loads(record_path.read_text())
    security = json.loads(Path(record["independent_security_artifact"]).read_text())
    assert security["status"] == "UNKNOWN"
    record["independent_verification_status"] = "VERIFIED"
    record["independent_gate_resolution"].update(
        status="VERIFIED", resolution="VERIFIED", reason="GATE_VERIFIED")
    record["independent_gate_trace"]["promotion_result"] = True
    record_path.write_text(json.dumps(record))
    canonical_sha = _sha(record_path)
    evidence = [({**item, "sha256": canonical_sha}
                if item["role"] == "canonical_crash" else item)
                for item in row["gate_resolution_evidence"]]
    forged = _rewrite_outcome(
        adapter, row, product_gate_status="VERIFIED", gate_resolution="VERIFIED",
        gate_resolution_reason="GATE_VERIFIED", security_gate_result=True,
        producer_gate_resolution="VERIFIED",
        producer_gate_resolution_reason="GATE_VERIFIED",
        canonical_crash_sha256=canonical_sha, gate_resolution_evidence=evidence)
    claim = adapter.root.parent / "pov-validation" / row["pov_id"]
    assert verify_verified_pov_gate(forged, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) is not None
    assert _verified_ids(adapter, ledger, [forged], [row["pov_id"]]) == set()


def test_replay_binary_path_substitution_cannot_retain_credit(verified_replay):
    from devtools.product_qualified_runtime import verify_verified_pov_gate
    adapter, ledger, row, claim = verified_replay
    forged = _reforge(
        adapter, row, "fixed_poc",
        lambda data: data.update(target_binary="/bin/true",
                                 run_command=["/bin/true", "{input}"]),
        also_canonical_key="fixed_poc_sha256")
    assert verify_verified_pov_gate(forged, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) is not None
    assert _verified_ids(adapter, ledger, [forged], [row["pov_id"]]) == set()


def test_identical_binary_at_other_path_cannot_substitute_replay_target(
        verified_replay, tmp_path):
    from devtools.product_qualified_runtime import verify_verified_pov_gate
    adapter, ledger, row, claim = verified_replay
    fixed_item = next(item for item in row["gate_resolution_evidence"]
                      if item["role"] == "fixed_poc")
    fixed = json.loads(Path(fixed_item["path"]).read_text())
    other_binary = tmp_path / "same-binary"
    other_binary.write_bytes(Path(fixed["target_binary"]).read_bytes())
    forged = _reforge(
        adapter, row, "fixed_poc",
        lambda data: data.update(target_binary=str(other_binary),
                                 run_command=[str(other_binary), "{input}"]),
        also_canonical_key="fixed_poc_sha256")
    assert verify_verified_pov_gate(forged, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) is not None
    assert _verified_ids(adapter, ledger, [forged], [row["pov_id"]]) == set()


def _reforge(adapter, row, role, mutate, *, also_canonical_key=None):
    """Rewrite one evidence file and every hash that binds it, consistently."""
    evidence = {item["role"]: dict(item) for item in row["gate_resolution_evidence"]}
    path = Path(evidence[role]["path"])
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data))
    evidence[role]["sha256"] = _sha(path)
    changes = {}
    if also_canonical_key:
        canonical_path = Path(evidence["canonical_crash"]["path"])
        canonical = json.loads(canonical_path.read_text())
        canonical["independent_gate_resolution"]["replay"][also_canonical_key] = _sha(path)
        canonical_path.write_text(json.dumps(canonical))
        evidence["canonical_crash"]["sha256"] = _sha(canonical_path)
        changes["canonical_crash_sha256"] = _sha(canonical_path)
    return _rewrite_outcome(adapter, row,
                            gate_resolution_evidence=list(evidence.values()), **changes)


@pytest.mark.parametrize("case, expected", [
    ("replay_other_stack", "REPLAY_IDENTITY_UNPROVEN"),
    ("fingerprint_not_frozen", "REPLAY_IDENTITY_UNPROVEN"),
    ("receipt_fingerprint_forged", "REPLAY_IDENTITY_UNPROVEN"),
    ("replay_environment_unpinned", "REPLAY_IDENTITY_UNPROVEN"),
])
def test_forged_verified_evidence_is_pending(verified_replay, result_dir, monkeypatch,
                                             case, expected):
    from devtools.product_qualified_runtime import verify_verified_pov_gate
    adapter, ledger, row, claim = verified_replay
    if case == "replay_other_stack":
        forged = _reforge(adapter, row, "replay_runtime",
                          lambda data: data.update(stderr=SHARED_BETA),
                          also_canonical_key="runtime_sha256")
    elif case == "fingerprint_not_frozen":
        forged = _reforge(adapter, row, "fixed_poc",
                          lambda data: data.pop("expected_crash_fingerprint"),
                          also_canonical_key="fixed_poc_sha256")
    elif case == "receipt_fingerprint_forged":
        forged = _reforge(adapter, row, "replay_validation",
                          lambda data: data.update(actual_crash_fingerprint="crash-forged"),
                          also_canonical_key="validation_sha256")
    else:
        forged = _reforge(adapter, row, "replay_runtime",
                          lambda data: data.update(runtime_profile=None),
                          also_canonical_key="runtime_sha256")
    assert verify_verified_pov_gate(forged, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) == expected
    assert _verified_ids(adapter, ledger, [forged], [row["pov_id"]]) == set()
    result = _run_result(result_dir, monkeypatch, adapter, ledger, forged)
    assert result["pov_crashes_gate_verified_count"] == 0
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["status"] == "INCOMPLETE"


def test_verified_needs_clean_process_receipts_and_durable_identity(verified_replay):
    from devtools.product_qualified_runtime import verify_verified_pov_gate
    adapter, ledger, row, claim = verified_replay
    finished = [item for item in ledger.snapshot()["finished"]
                if not item["key"].endswith(":pov.observed_independent_replay")]
    assert verify_verified_pov_gate(row, claim_dir=claim, finished_rows=finished) == (
        "PROCESS_RECEIPT_UNPROVEN")
    assert verify_verified_pov_gate({**row, "run_id": "another_run"}, claim_dir=claim,
                                    finished_rows=ledger.snapshot()["finished"]) == (
        "IDENTITY_MISMATCH")
    # A row that differs from the durable outcome is not counted.
    assert _verified_ids(adapter, ledger, [{**row, "observed_sanitizer": "x"}],
                         [row["pov_id"]]) == set()
    assert _verified_ids(adapter, ledger, [row, dict(row)], [row["pov_id"]]) == set()
