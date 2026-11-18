"""Which built harness attempt stage 2 analyses.

HarnessCreator never reports QUALIFIED (no fuzzing run, no crash attribution yet), so stage 2
must not require it.  It must not take an attempt whose verified seeds did not replay either:
such a harness changes or loses the input before the program sees it.
"""

from __future__ import annotations

import json
from pathlib import Path

from fbaugur.pipeline import built_harnesses
from fbaugur.project import pick_attempt


def _attempt(unit: Path, number: int, status: str, *, missing: list[str] | None = None) -> None:
    attempt = unit / f"attempt-{number}"
    (attempt / "build").mkdir(parents=True)
    (attempt / "build" / "hc-native-fuzzer").write_bytes(b"\x7fELF")
    if missing is not None:
        (attempt / "seed-equivalence.json").write_text(json.dumps({"missing_in_harness": missing}))


def _unit(run: Path, attempts: list[tuple[int, str, list[str] | None]]) -> Path:
    unit = run / "context-harnesses" / "ctx-a-stream"
    for number, status, missing in attempts:
        _attempt(unit, number, status, missing=missing)
    (unit / "status.json").write_text(json.dumps({
        "status": attempts[-1][1],
        "attempts": [{"attempt": n, "status": s, "built": True,
                      "seeds_replayed": 3, "seeds_replay_ok": 0 if s == "BUILT_REPLAY_FAILED" else 3}
                     for n, s, _ in attempts]}))
    return unit


def test_attempt_whose_seeds_did_not_replay_is_not_analysed(tmp_path: Path):
    _unit(tmp_path, [(1, "BUILT_SEED_EQUIVALENT_REVIEW_FAILED", []), (2, "BUILT_REPLAY_FAILED", None)])
    assert pick_attempt(tmp_path, "ctx-a", "stream").name == "attempt-1"


def test_context_with_only_replay_failed_attempts_is_not_built(tmp_path: Path):
    _unit(tmp_path, [(1, "BUILT_REPLAY_FAILED", None)])
    assert built_harnesses(tmp_path) == []


def test_review_failed_attempt_still_enters_stage2(tmp_path: Path):
    # Not QUALIFIED is the normal state; a review FAIL is reported, not a reason to analyse nothing.
    _unit(tmp_path, [(1, "BUILT_SEED_EQUIVALENT_REVIEW_FAILED", [])])
    assert built_harnesses(tmp_path) == [("ctx-a", "stream")]
    assert pick_attempt(tmp_path, "ctx-a", "stream").name == "attempt-1"


def test_best_status_wins_over_a_later_weaker_attempt(tmp_path: Path):
    _unit(tmp_path, [(1, "BUILT_SEED_EQUIVALENT_NOT_QUALIFIED", []),
                     (2, "BUILT_SEED_EQUIVALENT_REVIEW_FAILED", [])])
    assert pick_attempt(tmp_path, "ctx-a", "stream").name == "attempt-1"


def test_an_attempt_without_a_status_in_its_receipt_is_not_analysed(tmp_path: Path):
    unit = tmp_path / "context-harnesses" / "ctx-a-stream"
    _attempt(unit, 1, "", missing=[])
    (unit / "status.json").write_text(json.dumps({"attempts": [{"attempt": 1, "built": True}]}))
    assert built_harnesses(tmp_path) == []


def test_an_attempt_whose_replay_is_not_on_record_is_not_analysed(tmp_path: Path):
    unit = tmp_path / "context-harnesses" / "ctx-a-stream"
    _attempt(unit, 1, "", missing=[])
    (unit / "status.json").write_text(json.dumps({"attempts": [
        {"attempt": 1, "status": "BUILT_SEED_EQUIVALENT_NOT_QUALIFIED", "built": True}]}))
    assert built_harnesses(tmp_path) == []


def test_a_run_without_status_json_is_analysed_as_unverified(tmp_path: Path):
    from fbaugur.project import attempt_status
    unit = tmp_path / "context-harnesses" / "ctx-a-stream"
    _attempt(unit, 1, "", missing=[])
    assert built_harnesses(tmp_path) == [("ctx-a", "stream")]
    assert attempt_status(pick_attempt(tmp_path, "ctx-a", "stream")).startswith("UNVERIFIED")
