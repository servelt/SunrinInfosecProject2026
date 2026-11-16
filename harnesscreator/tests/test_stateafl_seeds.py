from __future__ import annotations

from dataclasses import replace

from harnesscreator.models import (
    RuntimeStepObservation, ScenarioStatus, ScenarioStep, ScenarioWitness,
)
from harnesscreator.runtime.stateafl_seeds import export_stateafl_seeds
from harnesscreator.storage import ArtifactStore


def _witness(status: ScenarioStatus, *, channel: str = "tcp") -> ScenarioWitness:
    messages = [b"SET a 1\r\n", b"GET a\r\n"]
    steps = [
        ScenarioStep(i, f"action-{i}", "entry", message.hex(), {}, [])
        for i, message in enumerate(messages)
    ]
    observations = [
        RuntimeStepObservation(
            i, step.action_id, step.request_hex, b"OK\r\n".hex(),
            True, "original response", 0.01,
            response_success=True,
            target_reached=status is ScenarioStatus.PROVEN_RUNTIME,
        )
        for i, step in enumerate(steps)
    ]
    return ScenarioWitness(
        "witness-1", "scenario-1", "action-1", steps, observations,
        ["daemon"], channel, None, status, "original run",
    )


def test_proven_sequence_uses_stateafl_replay_format(tmp_path):
    store = ArtifactStore(tmp_path)
    observed = _witness(ScenarioStatus.PROVEN_RUNTIME)
    observed.tcp_connect_after_launch_seconds = 0.12
    observed.connection_prelude_hex = b"220 Ready\r\n".hex()
    manifest = export_stateafl_seeds(
        store, [observed],
    )
    row = manifest["rows"][0]
    assert row["seed_path"].startswith("research/stateafl/proven/")
    content = (tmp_path / row["seed_path"]).read_bytes()
    assert content == (
        b"\x09\x00\x00\x00SET a 1\r\n"
        b"\x07\x00\x00\x00GET a\r\n"
    )
    assert manifest["qualified_harness_claim"] is False
    assert manifest["automatic_fuzzing_started"] is False
    assert row["tcp_connect_after_launch_seconds"] == 0.12
    assert row["connection_prelude_hex"] == b"220 Ready\r\n".hex()
    assert "not a safe StateAFL -D value" in row["startup_measurement_policy"]


def test_observed_seed_is_separate_and_never_claimed_proven(tmp_path):
    store = ArtifactStore(tmp_path)
    manifest = export_stateafl_seeds(
        store, [_witness(ScenarioStatus.REPLAYED_RUNTIME)],
    )
    row = manifest["rows"][0]
    assert row["seed_path"].startswith("research/stateafl/exploratory/")
    assert "unproven" in row["reason"]


def test_unproven_reply_is_preserved_only_as_diagnostic_seed(tmp_path):
    unproven = _witness(ScenarioStatus.UNPROVEN)
    unproven.observations = [
        replace(item, success=False, response_success=False,
                response_hex=b"ERR\r\n".hex(), detail="no success marker")
        for item in unproven.observations
    ]
    manifest = export_stateafl_seeds(ArtifactStore(tmp_path), [unproven])
    row = manifest["rows"][0]
    assert row["seed_path"].startswith("research/stateafl/diagnostic/")
    assert "acceptance and handler reach are unproven" in row["reason"]
    assert manifest["qualified_harness_claim"] is False
    assert manifest["automatic_fuzzing_started"] is False
    content = (tmp_path / row["seed_path"]).read_bytes()
    assert content == (
        b"\x09\x00\x00\x00SET a 1\r\n"
        b"\x07\x00\x00\x00GET a\r\n"
    )


def test_unproven_trial_without_reply_is_not_a_replay_seed(tmp_path):
    unproven = _witness(ScenarioStatus.UNPROVEN)
    unproven.observations = [
        replace(item, success=False, response_success=False,
                response_hex="", detail="transport/response failure: TimeoutError")
        for item in unproven.observations
    ]
    row = export_stateafl_seeds(ArtifactStore(tmp_path), [unproven])["rows"][0]
    assert row["seed_path"] is None


def test_completed_local_write_without_reply_is_diagnostic_only(tmp_path):
    """Server-first protocols may wait for another message before replying."""
    unproven = _witness(ScenarioStatus.UNPROVEN)
    unproven.steps = unproven.steps[:1]
    unproven.observations = [replace(
        unproven.observations[0],
        request_hex=b"SSH-2.0-dbfuzz\r\n".hex(),
        response_hex="",
        success=False,
        response_success=False,
        request_write_completed=True,
        detail="transport/response failure: TimeoutError: no next packet yet",
    )]
    row = export_stateafl_seeds(ArtifactStore(tmp_path), [unproven])["rows"][0]
    assert row["seed_path"].startswith("research/stateafl/diagnostic/")
    assert "peer receipt" in row["reason"]
    assert row["local_write_completed_steps"] == [0]
    assert (tmp_path / row["seed_path"]).read_bytes() == (
        b"\x10\x00\x00\x00SSH-2.0-dbfuzz\r\n"
    )


def test_unaccepted_or_non_network_scenarios_are_not_exported(tmp_path):
    proven = _witness(ScenarioStatus.PROVEN_RUNTIME)
    failed = replace(proven, witness_id="failed", observations=[
        proven.observations[0],
        replace(proven.observations[1], success=False),
    ])
    manifest = export_stateafl_seeds(ArtifactStore(tmp_path), [
        failed,
        replace(proven, witness_id="stdin", channel="stdin"),
        replace(proven, witness_id="crash", original_program_crashed=True),
    ])
    assert all(row["seed_path"] is None for row in manifest["rows"])
    assert not (tmp_path / "research/stateafl/proven").exists()


def test_export_uses_materialized_original_bytes_not_candidate_template(tmp_path):
    proven = _witness(ScenarioStatus.PROVEN_RUNTIME)
    proven.steps[1] = replace(proven.steps[1], request_hex=b"GET $KEY\r\n".hex())
    manifest = export_stateafl_seeds(ArtifactStore(tmp_path), [proven])
    content = (tmp_path / manifest["rows"][0]["seed_path"]).read_bytes()
    assert b"GET a\r\n" in content
    assert b"$KEY" not in content
