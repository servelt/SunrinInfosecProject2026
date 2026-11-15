"""Provider-free contract checks for the HP crash-to-Gate join."""

from hashlib import sha256
import json
from pathlib import Path

import pytest

from devtools import hp_gate_handoff
from devtools.hp_guided_crash_freeze import _write_new


_POLICY = {
    "enabled": True, "max_leads": 1,
    "replay_timeout_seconds": 10,
    "replay_wall_seconds": 90,
    "source_wall_seconds": 90,
    "output_limit_bytes": 4_000_000,
}


def _stage(path: Path, row: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = _write_new(path, raw)
    return {**row, "result_path": str(path), "result_sha256": digest}


def _physical(tmp_path: Path):
    claim = tmp_path / "HP_PHYSICAL_CLAIM.json"
    claim.write_text(json.dumps({
        "kind": "FBV2_HP_PHYSICAL_CLAIM_V1",
        "task_id": "task", "run_id": "run", "assertion_id": "assertion"}))
    leads = [{"claim_sha256": label * 64,
              "task_id": "task", "run_id": "run",
              "assertion_id": "assertion"} for label in ("a", "b")]
    return {
        "status": "HP_GUIDED_CRASH_OBSERVED_UNGATED",
        "assertion_id": "assertion",
        "physical_claim_path": str(claim),
        "physical_claim_sha256": sha256(claim.read_bytes()).hexdigest(),
        "hp_crash_freeze": {
            "status": "HP_CRASH_LEADS_FROZEN_UNVERIFIED",
            "reported_lead_count": 2,
            "frozen_leads": leads, "rejected_leads": [],
        },
    }


def test_parallel_hp_gate_credits_only_reproved_lead_and_reports_limit(
        tmp_path, monkeypatch):
    from devtools import hp_original_replay, hp_source_attribution
    from devtools import hp_independent_gate

    calls = []

    def replay(**kwargs):
        calls.append("replay")
        return _stage(kwargs["output_dir"] / "HP_REPLAY_RESULT.json", {
            "status": "HP_REPLAY_MATCHED_PENDING_SECURITY"})

    def source(**kwargs):
        calls.append("source")
        return _stage(kwargs["output_dir"] / "HP_SOURCE_RESULT.json", {
            "status": "HP_TARGET_SOURCE_ATTRIBUTED_PENDING_SECURITY"})

    def issue(**kwargs):
        calls.append("issue")
        return _stage(kwargs["output_dir"] / "HP_GATE_RESULT.json", {
            "status": "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN",
            "security_gate_credit": "HP_GATE_VERIFIED",
            "discovery_credit": "NOT_CREDITED"})

    def reprove(**kwargs):
        calls.append("reprove")
        assert kwargs["lead"]["claim_sha256"] == "a" * 64
        return {"status": "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN",
                "security_gate_credit": "HP_GATE_VERIFIED"}

    monkeypatch.setattr(hp_original_replay, "replay_hp_original_crash",
                        replay)
    monkeypatch.setattr(hp_source_attribution,
                        "attribute_hp_replayed_crash_source", source)
    monkeypatch.setattr(hp_independent_gate, "issue_hp_independent_gate",
                        issue)
    monkeypatch.setattr(hp_independent_gate, "reprove_hp_independent_gate",
                        reprove)
    physical = _physical(tmp_path)
    args = {
        "physical_row": physical, "qualification": object(),
        "process_ledger": object(), "output_dir": tmp_path / "hp-gate",
        "policy": dict(_POLICY), "max_wall_seconds": 600,
        "max_output_bytes": 4_000_000,
    }
    result = hp_gate_handoff.run_hp_gate_handoff(**args)
    assert result["security_gate_credit"] == "HP_GATE_VERIFIED"
    assert result["processed_lead_count"] == 1
    assert result["unprocessed_lead_count"] == 1
    assert calls == ["replay", "source", "issue", "reprove"]
    proof = hp_gate_handoff.reprove_hp_gate_handoff(
        result=result, **args, task_id="task", run_id="run")
    assert proof["security_gate_credit"] == "HP_GATE_VERIFIED"
    gate_file = tmp_path / "hp-gate" / ("a" * 64) / "gate" / "HP_GATE_RESULT.json"
    gate_file.write_text('{"status":"FORGED_VERIFIED"}\n')
    with pytest.raises(ValueError, match="stage bytes changed"):
        hp_gate_handoff.reprove_hp_gate_handoff(
            result=result, **args, task_id="task", run_id="run")


def test_parallel_hp_gate_pending_replay_cannot_claim_credit(
        tmp_path, monkeypatch):
    from devtools import hp_original_replay

    def replay(**kwargs):
        return _stage(kwargs["output_dir"] / "HP_REPLAY_RESULT.json", {
            "status": "HP_INSTRUMENTED_ONLY_CRASH_PENDING"})

    monkeypatch.setattr(hp_original_replay, "replay_hp_original_crash",
                        replay)
    physical = _physical(tmp_path)
    args = {
        "physical_row": physical, "qualification": object(),
        "process_ledger": object(), "output_dir": tmp_path / "hp-gate",
        "policy": dict(_POLICY), "max_wall_seconds": 600,
        "max_output_bytes": 4_000_000,
    }
    result = hp_gate_handoff.run_hp_gate_handoff(**args)
    assert result["security_gate_credit"] == "NOT_CREDITED"
    assert result["lead_results"][0]["status"] == "HP_GATE_PENDING_REPLAY"
    assert hp_gate_handoff.reprove_hp_gate_handoff(
        result=result, **args, task_id="task", run_id="run")[
            "security_gate_credit"] == "NOT_CREDITED"
    with pytest.raises(ValueError, match="handoff receipt differs"):
        hp_gate_handoff.reprove_hp_gate_handoff(
            result={**result, "security_gate_credit": "HP_GATE_VERIFIED"},
            **args, task_id="task", run_id="run")


def test_public_parallel_join_reproves_gate_before_exposing_credit(
        tmp_path, monkeypatch):
    from devtools.hp_result_observations import hp_physical_observations
    from devtools.parallel_hp_analysis import reprove_parallel_hp_diagnostic

    def saved(path, row):
        path.write_text(json.dumps(row, sort_keys=True) + "\n")
        path.chmod(0o600)
        return sha256(path.read_bytes()).hexdigest()

    analysis = {
        "kind": "FBV2_PARALLEL_HP_ANALYSIS_RESULT_V1",
        "task_id": "task", "run_id": "run",
        "status": "HP_PARALLEL_ANALYSIS_COMPLETE",
        "analysis": {"status": "ASSERTIONS_PROPOSED_UNVERIFIED"},
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    analysis_path = tmp_path / "HP_PARALLEL_ANALYSIS_RESULT.json"
    analysis_sha = saved(analysis_path, analysis)
    physical = {
        "kind": "FBV2_PARALLEL_HP_PHYSICAL_RESULT_V1",
        "task_id": "task", "run_id": "run",
        "analysis_result_sha256": analysis_sha,
        "physical_handoff": {
            "status": "HP_GUIDED_CRASH_OBSERVED_UNGATED",
            "assertion_status": "NOT_REACHED",
            "guided_report": {
                "status": "CRASH_OBSERVED_INCOMPLETE",
                "initial_segment_status": "CRASH_OBSERVED_INCOMPLETE"},
            "physical_observations": hp_physical_observations(
                "NOT_REACHED", {
                    "status": "CRASH_OBSERVED_INCOMPLETE",
                    "initial_segment_status": "CRASH_OBSERVED_INCOMPLETE"}),
            "security_gate_credit": "NOT_CREDITED",
            "discovery_credit": "NOT_CREDITED"},
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
    physical_path = tmp_path / "HP_PARALLEL_PHYSICAL_RESULT.json"
    physical_sha = saved(physical_path, physical)
    gate_dir = tmp_path / "hp-gate"
    gate_dir.mkdir()
    gate_path = gate_dir / "HP_PARALLEL_GATE_RESULT.json"
    gate_sha = saved(gate_path, {"kind": "fixture-gate"})
    result = {
        **analysis, "result_path": str(analysis_path),
        "result_sha256": analysis_sha,
        "physical_status": "HP_GUIDED_CRASH_OBSERVED_UNGATED",
        "physical_result_path": str(physical_path),
        "physical_result_sha256": physical_sha,
        "gate_status": "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN",
        "gate_result_path": str(gate_path),
        "gate_result_sha256": gate_sha,
    }
    calls = []

    def reprove(**kwargs):
        calls.append(kwargs)
        return {"status": "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN",
                "security_gate_credit": "HP_GATE_VERIFIED",
                "processed_lead_count": 1,
                "unprocessed_lead_count": 0,
                "rejected_lead_count": 0,
                "pending_lead_count": 0}

    monkeypatch.setattr(hp_gate_handoff, "reprove_hp_gate_handoff",
                        reprove)
    kwargs = {
        "qualification": object(), "process_ledger": object(),
        "gate_policy": dict(_POLICY),
        "gate_max_wall_seconds": 600,
        "gate_max_output_bytes": 4_000_000,
    }
    diagnostic = reprove_parallel_hp_diagnostic(
        tmp_path, task_id="task", run_id="run", result=result, **kwargs)
    assert diagnostic["security_gate_credit"] == "HP_GATE_VERIFIED"
    assert diagnostic["discovery_credit"] == "NOT_CREDITED"
    assert len(calls) == 1
    with pytest.raises(ValueError, match="prerequisites"):
        reprove_parallel_hp_diagnostic(
            tmp_path, task_id="task", run_id="run", result=result)
    forged = {**result, "gate_status": "HP_GATE_PENDING_OR_INCOMPLETE"}
    with pytest.raises(ValueError, match="status changed"):
        reprove_parallel_hp_diagnostic(
            tmp_path, task_id="task", run_id="run", result=forged,
            **kwargs)


@pytest.mark.parametrize("changed", [
    {"max_leads": 4},
    {"max_leads": 3, "replay_wall_seconds": 180,
     "source_wall_seconds": 180},
    {"output_limit_bytes": 5_000_000},
])
def test_parallel_hp_gate_policy_rejects_unbounded_execution(changed):
    with pytest.raises(ValueError, match="budget policy"):
        hp_gate_handoff.validate_hp_gate_policy(
            {**_POLICY, **changed}, max_wall_seconds=600,
            max_output_bytes=4_000_000)
