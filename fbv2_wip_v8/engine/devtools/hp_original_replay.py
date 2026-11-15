"""Independent original-binary replay of one frozen HP Guided crash lead.

This establishes physical reproduction only. Source, impact and security
property checks are separate, so no result from this module is Gate VERIFIED.
"""

from __future__ import annotations

from dataclasses import asdict, fields
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Callable

from devtools.hp_guided_crash_freeze import (
    _regular_bytes, _regular_sha, _sync_dir, _write_new,
    _unique_pairs, admit_hp_original_replay)


def replay_hp_original_crash(
    *, lead: dict[str, Any], physical_claim_path: Path,
    physical_claim_sha256: str, qualification: Any,
    process_ledger: Any, output_dir: Path,
    timeout_seconds: float, wall_seconds: float,
    output_limit_bytes: int,
    provider_free_fixture: bool = False,
    runtime_factory: Callable[[float], Any] | None = None,
) -> dict[str, Any]:
    """Run normal control, original observation, then a fresh exact replay."""
    from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
    from vulnerabilityanalysis.final_verification import (
        REPLAY_ASAN_OPTIONS, _replay_environment_pinned, _signature,
        completed_asan_crash, crash_fingerprint)
    from vulnerabilityanalysis.official_harness import _qualification_pins_ok
    from vulnerabilityanalysis.runtime import RuntimeExecutor

    if (type(timeout_seconds) not in (int, float) or
            not math.isfinite(timeout_seconds) or
            not 0 < timeout_seconds <= 60 or
            type(wall_seconds) not in (int, float) or
            not math.isfinite(wall_seconds) or
            wall_seconds <= 0 or
            type(output_limit_bytes) is not int or
            not 0 < output_limit_bytes <= 16_000_000 or
            (runtime_factory is not None and
             (not provider_free_fixture or not callable(runtime_factory)))):
        raise ValueError("HP original replay budget or runner is invalid")
    admission = admit_hp_original_replay(
        lead=lead, physical_claim_path=physical_claim_path,
        physical_claim_sha256=physical_claim_sha256,
        qualification=qualification, process_ledger=process_ledger)
    output_dir = Path(output_dir)
    if (not output_dir.is_absolute() or output_dir.is_symlink() or
            output_dir != output_dir.resolve(strict=False) or
            any(parent.is_symlink() for parent in output_dir.parents)):
        raise ValueError("HP replay output path is invalid")
    binary = Path(admission["original_binary_path"])
    frozen = Path(admission["input_path"])
    normal = Path(admission["normal_seed_path"])
    expected_commands = {
        (str(binary), str(normal)), (str(binary), str(frozen))}

    def pin(_phase: str, command: list[str]) -> None:
        if (tuple(command) not in expected_commands or
                not _qualification_pins_ok(qualification) or
                _regular_sha(binary, binary.parent, 512_000_000) !=
                    admission["original_binary_sha256"] or
                hashlib.sha256(_regular_bytes(
                    frozen, frozen.parent, 2_097_152)).hexdigest() !=
                    admission["input_sha256"] or
                hashlib.sha256(_regular_bytes(
                    normal, normal.parent, 2_097_152)).hexdigest() !=
                    admission["normal_seed_sha256"] or
                hashlib.sha256(_regular_bytes(
                    Path(admission["lead_claim_path"]),
                    Path(admission["lead_claim_path"]).parent,
                    16_000_000)).hexdigest() != admission["lead_claim_sha256"] or
                hashlib.sha256(_regular_bytes(
                    Path(admission["physical_claim_path"]),
                    Path(admission["physical_claim_path"]).parent,
                    16_000_000)).hexdigest() !=
                    admission["physical_claim_sha256"]):
            raise ValueError("HP original replay pin changed")

    # Claim before any Target launch. A failed or interrupted replay remains
    # terminal under this path and cannot be silently retried.
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    _sync_dir(output_dir.parent)
    claim = {"kind": "FBV2_HP_ORIGINAL_REPLAY_CLAIM_V1",
             "status": "STARTED", "lead_claim_path": admission["lead_claim_path"],
             "lead_claim_sha256": admission["lead_claim_sha256"],
             "physical_claim_sha256": physical_claim_sha256,
             "task_id": admission["task_id"], "run_id": admission["run_id"],
             "assertion_id": admission["assertion_id"],
             "input_sha256": admission["input_sha256"],
             "binary_sha256": admission["original_binary_sha256"],
             "normal_seed_sha256": admission["normal_seed_sha256"],
             "process_ledger_sha256_before": admission["process_ledger_sha256"],
             "timeout_seconds": float(timeout_seconds),
             "wall_seconds": float(wall_seconds),
             "output_limit_bytes": output_limit_bytes,
             "execution_origin": ("PROVIDER_FREE_FIXTURE" if
                                  provider_free_fixture else
                                  "PINNED_RUNTIME_EXECUTOR"),
             "security_gate_credit": "NOT_CREDITED",
             "discovery_credit": "NOT_CREDITED"}
    claim_sha = _write_new(output_dir / "HP_REPLAY_CLAIM.json", (
        json.dumps(claim, sort_keys=True, separators=(",", ":"),
                   allow_nan=False) + "\n").encode())
    _sync_dir(output_dir)
    observations = []
    result_status = "INCOMPLETE_HP_ORIGINAL_REPLAY"
    try:
        envelope = DevelopmentProcessEnvelopeV2(
            process_ledger, work_item_id=admission["task_id"],
            assertion_id="hp_gate_" + hashlib.sha256(
                admission["lead_claim_path"].encode()).hexdigest()[:24],
            attempt_id=admission["run_id"],
            output_limit_bytes=output_limit_bytes,
            total_wall_seconds=wall_seconds, pin_hook=pin,
            wall_limit_scope="LOCAL")
        runner_type = (runtime_factory if runtime_factory is not None
                       else RuntimeExecutor)
        pinned_env = {"ASAN_OPTIONS": REPLAY_ASAN_OPTIONS}
        for segment, input_path in (
                ("normal_control", normal),
                ("original_observation", frozen),
                ("independent_replay", frozen)):
            executor = runner_type(float(timeout_seconds))
            runtime = executor.run(
                [str(binary), "{input}"], input_path,
                extra_env=pinned_env, inherit_environment=False,
                process_envelope=envelope,
                process_segment="hp_gate." + segment)
            runtime.runtime_profile = {
                "pinned_asan_options": REPLAY_ASAN_OPTIONS,
                "replay_asan_options": executor.last_asan_options,
                "environment_policy": "CLEAN_REPLAY_ENV_V1",
                "execution_environment": executor.last_environment}
            if not _replay_environment_pinned(runtime.runtime_profile):
                raise ValueError("HP original replay environment differs")
            state, ledger_sha = process_ledger.receipt_snapshot()
            rows = [row for row in state["finished"] if
                    type(row) is dict and
                    type(row.get("key")) is str and
                    row["key"].endswith(":hp_gate." + segment) and
                    row["key"].startswith(
                        f"{admission['task_id']}:{envelope.assertion_id}:"
                        f"{admission['run_id']}:")]
            active = state.get("active")
            prefix = (f"{admission['task_id']}:{envelope.assertion_id}:"
                      f"{admission['run_id']}:")
            if (state.get("stop_status") is not None or
                    type(active) is not dict or
                    any(key.startswith(prefix) for key in active) or
                    len(rows) != 1 or rows[0].get("kind") != "AUX_PROCESS" or
                    rows[0].get("cleanup_complete") is not True or
                    rows[0].get("output_limited") is not False or
                    rows[0].get("overrun") is not False):
                raise ValueError("HP original replay process is unsettled")
            runtime_raw = (json.dumps(asdict(runtime), sort_keys=True,
                                      separators=(",", ":"),
                                      allow_nan=False) + "\n").encode()
            runtime_path = output_dir / (segment + "-runtime.json")
            runtime_sha = _write_new(runtime_path, runtime_raw)
            observations.append({
                "segment": segment, "runtime": runtime,
                "runtime_path": str(runtime_path),
                "runtime_sha256": runtime_sha,
                "ledger_sha256": ledger_sha, "process_key": rows[0]["key"],
                "lease": rows[0]})
            if segment == "normal_control" and (
                    runtime.exit_code != 0 or runtime.signal is not None or
                    runtime.sanitizer or runtime.timed_out or
                    runtime.failure_classification not in {
                        "UNKNOWN", "NO_CRASH_BUT_FUNCTION_REACHED",
                        "NO_CRASH_BUT_SP_LOCATION_REACHED",
                        "NO_CRASH_BUT_SP_CONDITION_REACHED"}):
                result_status = "INCOMPLETE_HP_NORMAL_CONTROL"
                break
            if segment == "original_observation" and (
                    not completed_asan_crash(runtime) or
                    _signature(runtime) is None):
                result_status = "HP_INSTRUMENTED_ONLY_CRASH_PENDING"
                break
        if len(observations) == 3:
            primary = observations[1]["runtime"]
            replay = observations[2]["runtime"]
            result_status = (
                "HP_REPLAY_MATCHED_PENDING_SECURITY" if
                completed_asan_crash(replay) and
                _signature(replay) == _signature(primary) and
                crash_fingerprint(replay) == crash_fingerprint(primary) else
                "HP_REPLAY_MISMATCH_PENDING")
    except BaseException as original:
        failure = {"status": "INCOMPLETE_HP_ORIGINAL_REPLAY_EXCEPTION",
                   "error_type": type(original).__name__,
                   "security_gate_credit": "NOT_CREDITED",
                   "discovery_credit": "NOT_CREDITED"}
        try:
            _write_new(output_dir / "HP_REPLAY_RESULT.json", (
                json.dumps(failure, sort_keys=True, separators=(",", ":")) +
                "\n").encode())
            _sync_dir(output_dir)
        except BaseException as receipt_error:
            original.add_note("HP replay failure receipt: " +
                              type(receipt_error).__name__)
        raise
    result = {"kind": "FBV2_HP_ORIGINAL_REPLAY_RESULT_V1",
              "status": result_status,
              "task_id": admission["task_id"], "run_id": admission["run_id"],
              "worker_id": admission["worker_id"],
              "function_id": admission["function_id"],
              "direction_id": admission["direction_id"],
              "assertion_id": admission["assertion_id"],
              "input_sha256": admission["input_sha256"],
              "original_binary_sha256": admission["original_binary_sha256"],
              "normal_seed_sha256": admission["normal_seed_sha256"],
              "lead_claim_sha256": admission["lead_claim_sha256"],
              "physical_claim_sha256": physical_claim_sha256,
              "replay_claim_sha256": claim_sha,
              "execution_origin": claim["execution_origin"],
              "observations": [{key: value for key, value in row.items()
                                if key != "runtime"} for row in observations],
              "security_gate_credit": "NOT_CREDITED",
              "discovery_credit": "NOT_CREDITED"}
    result_raw = (json.dumps(result, sort_keys=True, separators=(",", ":"),
                             allow_nan=False) + "\n").encode()
    result_sha = _write_new(output_dir / "HP_REPLAY_RESULT.json", result_raw)
    _sync_dir(output_dir)
    return {**result, "result_path": str(output_dir / "HP_REPLAY_RESULT.json"),
            "result_sha256": result_sha}


def reprove_hp_original_replay(
    *, replay_result: dict[str, Any], lead: dict[str, Any],
    physical_claim_path: Path, physical_claim_sha256: str,
    qualification: Any, process_ledger: Any,
) -> dict[str, Any]:
    """Recompute replay identity from saved bytes and physical ledger rows.

    This is the Gate's read-only evidence boundary. A matching replay is still
    pending source/impact and security-property checks, not VERIFIED.
    """
    from vulnerabilityanalysis.final_verification import (
        _replay_environment_pinned, _signature,
        completed_asan_crash, crash_fingerprint)
    from vulnerabilityanalysis.models import RuntimeResult
    from vulnerabilityanalysis.runtime import classify_runtime, parse_sanitizer

    admission = admit_hp_original_replay(
        lead=lead, physical_claim_path=physical_claim_path,
        physical_claim_sha256=physical_claim_sha256,
        qualification=qualification, process_ledger=process_ledger)
    if (type(replay_result) is not dict or
            replay_result.get("status") !=
                "HP_REPLAY_MATCHED_PENDING_SECURITY" or
            replay_result.get("security_gate_credit") != "NOT_CREDITED" or
            replay_result.get("discovery_credit") != "NOT_CREDITED"):
        raise ValueError("HP replay result is not a matching uncredited lead")
    result_path = Path(replay_result.get("result_path", ""))
    if result_path.name != "HP_REPLAY_RESULT.json":
        raise ValueError("HP replay result locator is invalid")
    result_raw = _regular_bytes(result_path, result_path.parent, 16_000_000)
    saved = json.loads(result_raw, object_pairs_hook=_unique_pairs)
    expected = {key: value for key, value in replay_result.items()
                if key not in {"result_path", "result_sha256"}}
    if (type(saved) is not dict or saved != expected or
            hashlib.sha256(result_raw).hexdigest() !=
                replay_result.get("result_sha256") or
            saved.get("kind") != "FBV2_HP_ORIGINAL_REPLAY_RESULT_V1"):
        raise ValueError("HP replay result differs from persisted bytes")
    claim_path = result_path.parent / "HP_REPLAY_CLAIM.json"
    claim_raw = _regular_bytes(claim_path, result_path.parent, 16_000_000)
    replay_claim = json.loads(claim_raw, object_pairs_hook=_unique_pairs)
    if (type(replay_claim) is not dict or
            hashlib.sha256(claim_raw).hexdigest() !=
                saved.get("replay_claim_sha256") or
            replay_claim.get("kind") != "FBV2_HP_ORIGINAL_REPLAY_CLAIM_V1" or
            replay_claim.get("status") != "STARTED" or
            replay_claim.get("execution_origin") not in {
                "PINNED_RUNTIME_EXECUTOR", "PROVIDER_FREE_FIXTURE"} or
            replay_claim.get("lead_claim_sha256") !=
                admission["lead_claim_sha256"] or
            replay_claim.get("physical_claim_sha256") !=
                admission["physical_claim_sha256"] or
            replay_claim.get("input_sha256") != admission["input_sha256"] or
            replay_claim.get("binary_sha256") !=
                admission["original_binary_sha256"] or
            saved.get("execution_origin") !=
                replay_claim.get("execution_origin") or
            any(saved.get(key) != admission.get(key) for key in (
                "task_id", "run_id", "worker_id", "function_id",
                "direction_id", "assertion_id", "input_sha256"))):
        raise ValueError("HP replay claim or identity differs")
    rows = saved.get("observations")
    segments = ("normal_control", "original_observation",
                "independent_replay")
    if (type(rows) is not list or len(rows) != 3 or
            [row.get("segment") if type(row) is dict else None
             for row in rows] != list(segments)):
        raise ValueError("HP replay segment sequence is incomplete")
    state, _ = process_ledger.receipt_snapshot()
    if state.get("stop_status") is not None:
        raise ValueError("HP replay Process Ledger stopped")
    physical = {row["key"]: row for row in state["finished"]}
    runtimes = []
    seen_processes = set()
    for segment, row in zip(segments, rows):
        path = result_path.parent / (segment + "-runtime.json")
        if row.get("runtime_path") != str(path):
            raise ValueError("HP replay runtime locator differs")
        raw = _regular_bytes(path, result_path.parent, 16_000_000)
        if hashlib.sha256(raw).hexdigest() != row.get("runtime_sha256"):
            raise ValueError("HP replay runtime bytes changed")
        payload = json.loads(raw, object_pairs_hook=_unique_pairs)
        if type(payload) is not dict or set(payload) != {
                item.name for item in fields(RuntimeResult)}:
            raise ValueError("HP replay runtime schema differs")
        runtime = RuntimeResult(**payload)
        if (not _replay_environment_pinned(runtime.runtime_profile) or
                type(runtime.stderr) is not str or
                parse_sanitizer(runtime.stderr) != runtime.sanitizer):
            raise ValueError("HP replay runtime environment or oracle differs")
        key = row.get("process_key")
        lease = physical.get(key)
        if (type(key) is not str or key in seen_processes or
                not key.startswith(
                    f"{admission['task_id']}:hp_gate_") or
                not key.endswith(":hp_gate." + segment) or
                type(lease) is not dict or lease != row.get("lease") or
                lease.get("kind") != "AUX_PROCESS" or
                lease.get("cleanup_complete") is not True or
                lease.get("output_limited") is not False or
                lease.get("overrun") is not False):
            raise ValueError("HP replay physical process differs")
        seen_processes.add(key)
        runtimes.append(runtime)
    control, primary, replay = runtimes
    if (control.exit_code != 0 or control.signal is not None or
            control.timed_out or control.sanitizer or
            classify_runtime(control.exit_code, control.stderr,
                             target_reached=None, sp_reached=None) !=
                "UNKNOWN" or
            not completed_asan_crash(primary) or
            not completed_asan_crash(replay) or
            _signature(primary) is None or
            _signature(primary) != _signature(replay) or
            crash_fingerprint(primary) != crash_fingerprint(replay)):
        raise ValueError("HP original/replay crash identity is not re-proven")
    return {
        "status": ("HP_REPLAY_EVIDENCE_REPROVED_PENDING_SECURITY" if
                   saved.get("execution_origin") == "PINNED_RUNTIME_EXECUTOR"
                   else "HP_REPLAY_FIXTURE_REPROVED_UNCREDITED"),
        "task_id": admission["task_id"], "run_id": admission["run_id"],
        "assertion_id": admission["assertion_id"],
        "input_sha256": admission["input_sha256"],
        "original_binary_sha256": admission["original_binary_sha256"],
        "crash_fingerprint": crash_fingerprint(primary),
        "application_signature": _signature(primary),
        "execution_origin": saved["execution_origin"],
        "security_gate_credit": "NOT_CREDITED",
        "discovery_credit": "NOT_CREDITED",
    }
