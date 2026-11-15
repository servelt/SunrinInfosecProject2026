"""Provider-free admission boundaries for the original public dev binding."""

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from bson import ObjectId
import mongomock
import pytest

from fuzzingbrain.db.repository import RepositoryManager

PRODUCT_SRC = Path("/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src")
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))

from devtools import original_public_live as live


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _caps() -> live.PublicDevCaps:
    return live.PublicDevCaps(
        physical_model_calls=3, model_wall_seconds=30,
        calls_per_agent=2, total_wall_seconds=1000,
        total_fuzz_seconds=30, global_fuzz_seconds=5,
        global_reservation_seconds=20, global_replay_limit=1,
        pov_timeout_seconds=2, pov_wall_seconds=12,
        process_output_limit_bytes=1000)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def test_model_pov_gate_count_requires_matching_independent_receipts(tmp_path):
    """A model-origin Gate result is reported without discovery credit."""
    run_dir = tmp_path / "run"
    pov_id, sp_id = str(ObjectId()), str(ObjectId())
    input_sha, binary_sha = "a" * 64, "b" * 64
    turns = [{"role": role, "request_id": str(ObjectId())}
             for role in ("sp", "verifier", "pov")]
    candidate = {
        "status": "VERIFIED", "task_id": "task", "campaign_id": "run-id",
        "sp_id": sp_id, "pov_inputs": [{"pov_id": pov_id,
                                      "input_sha256": input_sha}],
        "model_tool_turns": turns}
    runtime = {
        "status": "VERIFIED", "task_id": "task", "run_id": "run-id",
        "sp_id": sp_id, "pov_id": pov_id, "input_sha256": input_sha,
        "binary_sha256": binary_sha, "model_tool_turns": turns,
        "source_tree_sha256": "c" * 64, "harness_sha256": "d" * 64,
        "contract_sha256": "e" * 64}
    claim = run_dir / "pov-validation" / pov_id
    origin_path = claim / "origin-lineage.json"
    _write_json(origin_path, {
        "kind": "FBV2_POV_PRODUCT_ORIGIN_LINEAGE_V1",
        "task_id": "task", "run_id": "run-id", "pov_id": pov_id,
        "input_sha256": input_sha,
        "origin_verification_status": "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE",
        "lineage": runtime, "automatic_discovery": False,
        "discovery_credit": "NOT_CREDITED"})
    canonical_path = claim / "product" / "runtime" / "crashes" / "crash.json"
    product_runtime_path = claim / "product" / "runtime" / "poc.json"
    _write_json(product_runtime_path, {"sanitizer": "AddressSanitizer"})
    _write_json(canonical_path, {
        "independent_verification_status": "VERIFIED",
        "crash_id": "crash-1",
        "independent_verification_source": {
            "input_sha256": input_sha,
            "runtime_artifact": str(product_runtime_path)},
        "independent_gate_trace": {
            "crash_id": "crash-1",
            "promotion_state": "COMPLETED", "promotion_result": True,
            "security_property_state": "COMPLETED"}})
    lineage_rows = [{"pov_id": pov_id, "candidate_lineage": candidate,
                     "runtime_lineage": runtime, "automatic_discovery": False}]
    gate_rows = [{
        "task_id": "task", "run_id": "run-id", "sp_id": sp_id,
        "pov_id": pov_id, "input_sha256": input_sha,
        "binary_sha256": binary_sha, "product_gate_status": "VERIFIED",
        "origin_verification_status": "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE",
        "security_gate_state": "COMPLETED", "security_gate_result": True,
        "automatic_discovery": False, "discovery_credit": "NOT_CREDITED",
        "origin_lineage_receipt_path": str(origin_path),
        "origin_lineage_receipt_sha256": _sha(origin_path),
        "product_runtime_artifact": str(product_runtime_path),
        "product_runtime_sha256": _sha(product_runtime_path),
        "canonical_crash_artifact": str(canonical_path),
        "canonical_crash_sha256": _sha(canonical_path)}]
    count = live._model_lineage_gate_verified_pov_ids
    assert count(run_dir, lineage_rows, gate_rows) == [pov_id]
    for key, bad in (("input_sha256", "f" * 64),
                     ("security_gate_state", "STARTED"),
                     ("origin_verification_status", "UNVERIFIED_LINEAGE")):
        row = {**gate_rows[0], key: bad}
        assert count(run_dir, lineage_rows, [row]) == []
    assert count(run_dir, lineage_rows, gate_rows * 2) == []
    assert count(run_dir, lineage_rows * 2, gate_rows) == []
    canonical = json.loads(canonical_path.read_text(encoding="utf-8"))
    canonical["independent_verification_source"]["input_sha256"] = "f" * 64
    _write_json(canonical_path, canonical)
    changed_gate = {**gate_rows[0],
                    "canonical_crash_sha256": _sha(canonical_path)}
    assert count(run_dir, lineage_rows, [changed_gate]) == []
    canonical["independent_verification_source"]["input_sha256"] = input_sha
    _write_json(canonical_path, canonical)
    product_runtime_path.write_text("{}", encoding="utf-8")
    assert count(run_dir, lineage_rows, gate_rows) == []
    _write_json(product_runtime_path, {"sanitizer": "AddressSanitizer"})
    origin_path.write_text("{}", encoding="utf-8")
    assert count(run_dir, lineage_rows, gate_rows) == []


def _global_consumer_fixture(run_dir: Path, status: str) -> dict:
    """A product-shaped retained input, runtime and consumer Gate chain."""
    run_dir.mkdir(parents=True, exist_ok=True)
    crash_id, poc_id, canonical_id = "observed-1", "poc-1", "crash-1"
    content = b"retained input"
    input_sha = hashlib.sha256(content).hexdigest()
    binary_sha = "b" * 64
    candidate = run_dir / "corpus" / "global" / "crash-example"
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(content)
    observation = {"observed_crash_id": crash_id, "sha256": input_sha,
                   "candidate_path": str(candidate), "size": len(content)}
    global_runtime = run_dir / "runtime" / "global-fuzz.runtime.json"
    _write_json(global_runtime, {"status": "CRASH_OBSERVED_INCOMPLETE"})
    report = {"status": "CRASH_OBSERVED_INCOMPLETE",
              "binary_sha256": binary_sha,
              "runtime_artifact": str(global_runtime),
              "observed_crashes": [observation]}
    report_path = run_dir / "runtime" / "global_fuzz.json"
    _write_json(report_path, report)
    snapshot = (run_dir / "runtime" / "fuzzer_validation" / crash_id /
                f"{input_sha}.input.bin")
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_bytes(content)
    runtime_path = run_dir / "runtime" / f"{poc_id}.json"
    target_crash = status in {"VERIFIED", "GATE_CHECKED_NOT_VERIFIED"}
    sanitizer = (None if status == "ORIGINAL_REPLAY_NOT_REPRODUCED" else
                 "AddressSanitizer: heap-use-after-free")
    runtime = {"timed_out": False, "exit_code": 1 if sanitizer else 0,
               "sanitizer": sanitizer,
               "crash_triage": {"category": ("TARGET_CRASH" if target_crash
                                             else "HARNESS_CRASH")}}
    _write_json(runtime_path, runtime)
    outcome = {"status": status, "input_sha256": input_sha,
               "binary_sha256": binary_sha, "poc_id": poc_id,
               "runtime_artifact": str(runtime_path),
               "runtime_sha256": _sha(runtime_path),
               "snapshot_path": str(snapshot),
               "qualification_identity": {"kind": "OFFICIAL_PINNED",
                                          "binary_sha256": binary_sha}}
    if target_crash:
        canonical_path = (run_dir / "runtime" / "crashes" /
                          f"{canonical_id}.json")
        source = {"poc_id": poc_id, "input_sha256": input_sha,
                  "runtime_artifact": str(runtime_path)}
        gate_status = ("VERIFIED" if status == "VERIFIED" else
                       "BLOCKED_ROOT_CAUSE")
        canonical = {"crash_id": canonical_id,
                     "observations": [source],
                     "independent_verification_source": source,
                     "independent_verification_status": gate_status,
                     "independent_gate_trace": {
                         "crash_id": canonical_id,
                         "security_property_evaluated": status == "VERIFIED",
                         "security_property_state": ("COMPLETED" if status == "VERIFIED"
                                                     else "NOT_STARTED"),
                         "promotion_state": ("COMPLETED" if status == "VERIFIED"
                                             else "NOT_STARTED"),
                         "promotion_result": status == "VERIFIED"}}
        if status == "VERIFIED":
            for field, relative, contents in (
                ("independent_candidate_artifact",
                 f"runtime/crash_candidates/{canonical_id}.json", {}),
                ("independent_root_cause_artifact",
                 f"root_cause/{canonical_id}/observed.json",
                 {"verdict": "CONFIRMED"}),
                ("independent_fixed_poc_artifact",
                 f"fixed_poc/{canonical_id}/fixed.json", {}),
                ("independent_replay_artifact",
                 f"independent/{canonical_id}/validation.json",
                 {"status": "REPRODUCED"}),
                ("independent_security_artifact",
                 f"security/{canonical_id}.json", {"status": "CONFIRMED"}),
            ):
                artifact = run_dir / relative
                _write_json(artifact, contents)
                canonical[field] = str(artifact)
        _write_json(canonical_path, canonical)
        outcome.update(canonical_crash_id=canonical_id,
                       canonical_crash_artifact=str(canonical_path),
                       gate_status=gate_status)
    consumer_row = {"crash_id": crash_id, "input_sha256": input_sha,
                    "status": status, "consumer_result": outcome}
    record = {"crash_id": crash_id, "status": status,
              "observations": [{"source": "GLOBAL_FUZZER", "sp_id": None,
                                "runtime_artifact": str(global_runtime),
                                "crash_input": observation}],
              "consumer_results": {input_sha: outcome},
              "consumer_attempts": {input_sha: [outcome]}}
    _write_json(run_dir / "runtime" / "fuzzer_crashes" /
                f"{crash_id}.json", record)
    _write_json(run_dir / "runtime" / "global_fuzzer_consumption.json",
                [consumer_row])
    receipt = {"status": "CRASH_OBSERVED_INCOMPLETE",
               "cleanup_complete": True,
               "consumer_process_account_installed": True,
               "observed_crash_count": 1,
               "observed_crash_rows": [{"crash_id": crash_id,
                                        "input_sha256": input_sha}],
               "global_report_sha256": _sha(report_path),
               "consumer_rows": [consumer_row]}
    _write_json(run_dir / "DEV_GLOBAL_RESULT.json", receipt)
    return receipt


def _append_pending_global_observation(run_dir: Path, receipt: dict) -> None:
    crash_id, content = "observed-2", b"other pending input"
    input_sha = hashlib.sha256(content).hexdigest()
    candidate = run_dir / "corpus" / "global" / "crash-pending"
    candidate.write_bytes(content)
    observation = {"observed_crash_id": crash_id, "sha256": input_sha,
                   "candidate_path": str(candidate), "size": len(content)}
    report_path = run_dir / "runtime" / "global_fuzz.json"
    report = json.loads(report_path.read_text())
    report["observed_crashes"].append(observation)
    _write_json(report_path, report)
    receipt["observed_crash_count"] = 2
    receipt["observed_crash_rows"].append(
        {"crash_id": crash_id, "input_sha256": input_sha})
    receipt["consumer_rows"].append(
        {"crash_id": crash_id, "input_sha256": input_sha,
         "status": "PENDING_CAUSAL_EVIDENCE"})
    receipt["global_report_sha256"] = _sha(report_path)
    _write_json(run_dir / "runtime" / "global_fuzzer_consumption.json",
                receipt["consumer_rows"])
    _write_json(run_dir / "DEV_GLOBAL_RESULT.json", receipt)


def test_preliminary_caps_reject_unmetered_or_overbooked_work():
    _caps().validate()
    from dataclasses import replace
    with pytest.raises(ValueError, match="physical caps"):
        replace(_caps(), physical_model_calls=0).validate()
    with pytest.raises(ValueError, match="physical caps"):
        replace(_caps(), global_reservation_seconds=5).validate()
    with pytest.raises(ValueError, match="physical caps"):
        replace(_caps(), total_wall_seconds=40).validate()


def test_sp_fuzz_optin_reserves_probe_wall_and_shared_fuzz_time():
    from dataclasses import replace

    replace(_caps(), sp_fuzz_seconds=10, sp_fuzz_max_items=1,
            total_fuzz_seconds=90, total_wall_seconds=1500).validate()
    for changed in (
        {"sp_fuzz_seconds": 11, "sp_fuzz_max_items": 1,
         "total_fuzz_seconds": 90},
        {"sp_fuzz_seconds": 10, "sp_fuzz_max_items": 2,
         "total_fuzz_seconds": 90},
        {"sp_fuzz_seconds": 10, "sp_fuzz_max_items": 1,
         "total_fuzz_seconds": 50},
        {"sp_fuzz_seconds": 10, "sp_fuzz_max_items": 1,
         "total_fuzz_seconds": 90, "total_wall_seconds": 1300},
    ):
        with pytest.raises(ValueError, match="physical caps"):
            replace(_caps(), **changed).validate()


def test_sp_fuzz_post_worker_selects_only_verified_noncrashing_model_pov(monkeypatch):
    from dataclasses import replace
    from devtools import product_qualified_runtime

    calls = []
    monkeypatch.setattr(product_qualified_runtime, "run_qualified_sp_fuzz",
                        lambda *args, **kwargs: calls.append((args, kwargs)) or
                        {"status": "EXECUTED", "automatic_discovery": False})
    caps = replace(_caps(), sp_fuzz_seconds=10, sp_fuzz_max_items=1,
                   total_fuzz_seconds=90, total_wall_seconds=1500)
    bound = SimpleNamespace(caps=caps,
                            identity=SimpleNamespace(task_id="task", run_id="run"),
                            pov_adapter=object(), model_gate=object(),
                            recheck=lambda: None)
    handoff = live._run_qualified_sp_fuzz_after_worker
    assert handoff(bound, []) == {
        "status": "SKIPPED_NO_ELIGIBLE_MODEL_POV",
        "automatic_discovery": False}
    assert calls == []
    rows = [
        {"pov_id": "pov-a", "candidate_lineage": {
            "status": "VERIFIED", "task_id": "task", "campaign_id": "run",
            "sp_id": "sp"}, "runtime_lineage": {
                "status": "VERIFIED", "task_id": "task", "run_id": "run",
                "sp_id": "sp", "pov_id": "pov-a", "runtime_status": "CRASH_OBSERVED"}},
        {"pov_id": "pov-b", "candidate_lineage": {
            "status": "VERIFIED", "task_id": "task", "campaign_id": "run",
            "sp_id": "sp"}, "runtime_lineage": {
                "status": "VERIFIED", "task_id": "task", "run_id": "run",
                "sp_id": "sp", "pov_id": "pov-b", "runtime_status": "NO_CRASH"}},
    ]
    assert handoff(bound, rows)["status"] == "EXECUTED"
    assert len(calls) == 1 and calls[0][0][1] == "pov-b"
    assert calls[0][1]["seconds"] == 10
    assert calls[0][1]["fuzz_wall_seconds"] == 49.0
    assert calls[0][1]["replay_limit"] == 1
    assert handoff(bound, [rows[1] | {"candidate_lineage": {
        **rows[1]["candidate_lineage"], "campaign_id": "other"}}])[
            "status"] == "SKIPPED_NO_ELIGIBLE_MODEL_POV"
    assert len(calls) == 1


@pytest.mark.parametrize("status", [
    "ORIGINAL_REPLAY_NOT_REPRODUCED", "BLOCKED_NON_TARGET_CRASH",
    "GATE_CHECKED_NOT_VERIFIED", "VERIFIED",
])
def test_product_terminal_consumer_rows_are_settled(tmp_path, status):
    receipt = _global_consumer_fixture(tmp_path / "global", status)
    assert live.pending_global_crash_count(
        receipt, run_dir=tmp_path / "global",
        expected_binary_sha256="b" * 64) == 0


def test_verified_global_mutation_requires_raw_log_and_gate(tmp_path):
    run_dir = tmp_path / "global"
    receipt = _global_consumer_fixture(run_dir, "VERIFIED")
    seed = run_dir / "corpus" / "global" / "seed"
    seed.write_bytes(b"Y")
    seed_sha = _sha(seed)
    report_path = run_dir / "runtime" / "global_fuzz.json"
    report = json.loads(report_path.read_text())
    observed = report["observed_crashes"][0]
    runtime_path = Path(report["runtime_artifact"])
    runtime = json.loads(runtime_path.read_text())
    runtime["stderr"] = (
        "MS: 1 ChangeByte-; base unit: " +
        hashlib.sha1(seed.read_bytes()).hexdigest() + "\n" +
        "artifact_prefix='./'; Test unit written to ./crash-example\n")
    _write_json(runtime_path, runtime)
    report["runtime_artifact_sha256"] = _sha(runtime_path)
    report["crash_mutation_observed"] = True
    report["crash_mutation_observations"] = [{
        "observed_crash_id": observed["observed_crash_id"],
        "input_sha256": observed["sha256"], "base_sha256": seed_sha}]
    _write_json(report_path, report)
    receipt["global_report_sha256"] = _sha(report_path)
    receipt["global_crash_mutation_observed"] = True
    receipt["staged_seed_sha256s"] = [seed_sha]
    receipt["observed_mutated_crash_rows"] = [{
        "crash_id": observed["observed_crash_id"],
        "input_sha256": observed["sha256"], "base_sha256": seed_sha}]
    _write_json(run_dir / "DEV_GLOBAL_RESULT.json", receipt)
    expected = receipt["observed_mutated_crash_rows"]
    assert live.verified_global_mutation_rows(
        receipt, run_dir=run_dir, expected_binary_sha256="b" * 64) == expected
    _append_pending_global_observation(run_dir, receipt)
    assert live.pending_global_crash_count(
        receipt, run_dir=run_dir, expected_binary_sha256="b" * 64) == 1
    assert live.verified_global_mutation_rows(
        receipt, run_dir=run_dir, expected_binary_sha256="b" * 64) == expected
    disk_rows = run_dir / "runtime" / "global_fuzzer_consumption.json"
    disk_rows.write_text("[]")
    assert live.verified_global_mutation_rows(
        receipt, run_dir=run_dir, expected_binary_sha256="b" * 64) == []
    _write_json(disk_rows, receipt["consumer_rows"])
    receipt["consumer_rows"][0].pop("status")
    _write_json(disk_rows, receipt["consumer_rows"])
    _write_json(run_dir / "DEV_GLOBAL_RESULT.json", receipt)
    assert live.pending_global_crash_count(
        receipt, run_dir=run_dir, expected_binary_sha256="b" * 64) == 2
    assert live.verified_global_mutation_rows(
        receipt, run_dir=run_dir, expected_binary_sha256="b" * 64) == []
    receipt["consumer_rows"][0]["status"] = "VERIFIED"
    _write_json(disk_rows, receipt["consumer_rows"])
    _write_json(run_dir / "DEV_GLOBAL_RESULT.json", receipt)
    runtime["stderr"] = runtime["stderr"].replace("base unit:", "other unit:")
    _write_json(runtime_path, runtime)
    assert live.verified_global_mutation_rows(
        receipt, run_dir=run_dir, expected_binary_sha256="b" * 64) == []


@pytest.mark.parametrize("damage", [
    "missing_run_dir", "report_sha", "report_observation", "runtime_sha",
    "runtime_file", "snapshot", "record_result", "record_observation",
    "consumer_file", "canonical_gate", "canonical_source",
    "root_receipt", "process_account", "wrong_binary",
])
def test_global_terminal_requires_product_artifacts(tmp_path, damage):
    run_dir = tmp_path / "global"
    receipt = _global_consumer_fixture(run_dir, "VERIFIED")
    row = receipt["consumer_rows"][0]
    outcome = row["consumer_result"]
    record_path = run_dir / "runtime" / "fuzzer_crashes" / "observed-1.json"
    if damage == "missing_run_dir":
        assert live.pending_global_crash_count(receipt) == 1
        return
    if damage == "report_sha":
        (run_dir / "runtime" / "global_fuzz.json").write_text("{}")
    elif damage == "report_observation":
        report_path = run_dir / "runtime" / "global_fuzz.json"
        report = json.loads(report_path.read_text())
        report["observed_crashes"][0]["observed_crash_id"] = "other"
        _write_json(report_path, report)
        receipt["global_report_sha256"] = _sha(report_path)
        _write_json(run_dir / "DEV_GLOBAL_RESULT.json", receipt)
    elif damage == "runtime_sha":
        outcome["runtime_sha256"] = "f" * 64
        _write_json(run_dir / "DEV_GLOBAL_RESULT.json", receipt)
        _write_json(run_dir / "runtime" / "global_fuzzer_consumption.json",
                    receipt["consumer_rows"])
        record = json.loads(record_path.read_text())
        record["consumer_results"][row["input_sha256"]] = outcome
        record["consumer_attempts"][row["input_sha256"]] = [outcome]
        _write_json(record_path, record)
    elif damage == "runtime_file":
        Path(outcome["runtime_artifact"]).unlink()
    elif damage == "snapshot":
        Path(outcome["snapshot_path"]).write_bytes(b"changed")
    elif damage == "record_result":
        record = json.loads(record_path.read_text())
        record["consumer_results"][row["input_sha256"]]["status"] = "OPEN"
        _write_json(record_path, record)
    elif damage == "record_observation":
        record = json.loads(record_path.read_text())
        record["observations"][0]["source"] = "SP_FUZZER"
        _write_json(record_path, record)
    elif damage == "consumer_file":
        (run_dir / "runtime" / "global_fuzzer_consumption.json").unlink()
    elif damage == "canonical_gate":
        canonical = Path(outcome["canonical_crash_artifact"])
        data = json.loads(canonical.read_text())
        data["independent_gate_trace"]["promotion_result"] = False
        _write_json(canonical, data)
    elif damage == "canonical_source":
        canonical = Path(outcome["canonical_crash_artifact"])
        data = json.loads(canonical.read_text())
        data["independent_verification_source"]["poc_id"] = "unrelated"
        _write_json(canonical, data)
    elif damage == "root_receipt":
        canonical = json.loads(Path(outcome["canonical_crash_artifact"]).read_text())
        Path(canonical["independent_root_cause_artifact"]).unlink()
    elif damage == "process_account":
        receipt["consumer_process_account_installed"] = False
        _write_json(run_dir / "DEV_GLOBAL_RESULT.json", receipt)
    assert live.pending_global_crash_count(
        receipt, run_dir=run_dir,
        expected_binary_sha256=("c" * 64 if damage == "wrong_binary"
                                else "b" * 64)) == 1


@pytest.mark.parametrize("status", [
    "PENDING_RUNTIME_ATTEMPT_LIMIT", "PENDING_SCAN_DEADLINE",
    "PENDING_REPLAY_ERROR", "PENDING_ORIGINAL_REPLAY_INCOMPLETE",
    "PENDING_CAUSAL_EVIDENCE",
    "DUPLICATE_CANONICAL_CRASH_INPUT_UNVALIDATED",
])
def test_unresolved_consumer_rows_remain_pending(status):
    assert live.pending_global_crash_count({
        "observed_crash_count": 1,
        "observed_crash_rows": [{"crash_id": "observed-1",
                                 "input_sha256": "f" * 64}],
        "consumer_rows": [{"crash_id": "observed-1",
                           "input_sha256": "f" * 64,
                           "status": status}]}) == 1


def test_malformed_or_duplicate_global_rows_remain_pending():
    valid = {"crash_id": "observed-1", "input_sha256": "f" * 64,
             "status": "VERIFIED", "consumer_result": {
                 "input_sha256": "f" * 64, "status": "VERIFIED",
                 "gate_status": "VERIFIED"}}
    for rows, count in (([valid, valid], 1), ([{"status": "VERIFIED"}], 1),
                        ([valid], 0), ([{**valid, "consumer_result": {
                            "status": "VERIFIED", "input_sha256": "e" * 64,
                            "gate_status": "VERIFIED"}}], 1),
                        ([{**valid, "crash_id": "unrelated"}], 1)):
        assert live.pending_global_crash_count({
            "observed_crash_count": count,
            "observed_crash_rows": ([{"crash_id": "observed-1",
                                      "input_sha256": "f" * 64}]
                                    if count else []),
            "consumer_rows": rows}) > 0


def test_completed_model_turn_with_incomplete_tool_is_incomplete_execution():
    assert live.incomplete_model_activity({"records": [{
        "status": "COMPLETED",
        "response_evidence": {"status": "VERIFIED"},
        "tool_events": [{"status": "STARTED"}]}]}) is True
    assert live.incomplete_model_activity({"records": [{
        "status": "COMPLETED",
        "response_evidence": {"status": "VERIFIED"},
        "tool_events": [{"status": "INCOMPLETE"}]}]}) is True
    assert live.incomplete_model_activity({"records": [{
        "status": "COMPLETED",
        "response_evidence": {"status": "VERIFIED"},
        "tool_events": [{"status": "COMPLETED"}]}]}) is False
    assert live.incomplete_model_activity({"records": [{
        "status": "COMPLETED",
        "response_evidence": {"status": "UNPROVEN"},
        "tool_events": []}]}) is True


def test_final_execution_rereads_model_and_tool_artifacts():
    receipt = {"records": [{
        "request_id": "turn", "status": "COMPLETED",
        "response_evidence": {"status": "VERIFIED"},
        "tool_events": [{"call_id": "tool", "status": "COMPLETED"}]}]}
    response = {"status": "VERIFIED"}
    tool = {"status": "VERIFIED"}
    gate = SimpleNamespace(
        verify_response_evidence=lambda _id: response,
        verify_tool_event=lambda _id, _call: tool)
    assert live.incomplete_model_activity(receipt, gate) is False
    response["status"] = "UNPROVEN"
    assert live.incomplete_model_activity(receipt, gate) is True
    response["status"] = "VERIFIED"
    tool["status"] = "UNPROVEN"
    assert live.incomplete_model_activity(receipt, gate) is True


def test_source_and_executable_pins_are_required(tmp_path):
    roots = [tmp_path / name for name in ("engine", "product", "evaluation")]
    for root in roots:
        root.mkdir()
        (root / "module.py").write_text("x = 1\n")
    executable = tmp_path / "codex"
    executable.write_bytes(b"fixture executable")
    executable.chmod(0o700)
    task = tmp_path / "task"
    (task / "repo").mkdir(parents=True)
    identity = live.PublicDevIdentity(
        task_id=str(ObjectId()), run_id="public-dev-1",
        engine_root=roots[0], engine_py_sha256=live.python_tree_sha256(roots[0]),
        product_src=roots[1], product_py_sha256=live.python_tree_sha256(roots[1]),
        evaluation_dir=roots[2],
        evaluation_py_sha256=live.python_tree_sha256(roots[2]),
        codex_executable=executable, codex_executable_sha256=_sha(executable),
        codex_model="fixture", codex_effort="medium",
        mongo_url="mongodb://127.0.0.1:27027", mongo_database="fbv2_public_test",
        task_path=task, run_dir=tmp_path / "new-run")
    identity.validate()
    (roots[2] / "module.py").write_text("x = 2\n")
    with pytest.raises(ValueError, match="Python source identity changed"):
        identity.validate()


def test_original_prompt_change_fails_before_model_construction(tmp_path):
    engine = tmp_path / "engine"
    prompts = engine / "fuzzingbrain" / "agents" / "prompts"
    prompts.mkdir(parents=True)
    (engine / "fuzzingbrain" / "tools").mkdir()
    (engine / "fuzzingbrain" / "llm_config.yaml").write_text("model: fixture\n")
    (engine / "fuzzingbrain" / "tools" / "tools.yaml").write_text("tools: []\n")
    prompt = prompts / "direction_planning_prompt.md"
    prompt.write_text("original prompt\n")
    (engine / "fuzzingbrain" / "agent.py").write_text("pass\n")
    product = tmp_path / "product"
    evaluation = tmp_path / "evaluation"
    for root in (product, evaluation):
        root.mkdir()
        (root / "module.py").write_text("pass\n")
    executable = tmp_path / "codex"
    executable.write_bytes(b"fixture executable")
    executable.chmod(0o700)
    task = tmp_path / "task"
    (task / "repo").mkdir(parents=True)
    identity = live.PublicDevIdentity(
        task_id=str(ObjectId()), run_id="prompt-pin-test",
        engine_root=engine, engine_py_sha256=live.python_tree_sha256(engine),
        product_src=product, product_py_sha256=live.python_tree_sha256(product),
        evaluation_dir=evaluation,
        evaluation_py_sha256=live.python_tree_sha256(evaluation),
        codex_executable=executable, codex_executable_sha256=_sha(executable),
        codex_model="fixture", codex_effort="medium",
        mongo_url="mongodb://127.0.0.1:27027", mongo_database="fbv2_public_test",
        task_path=task, run_dir=tmp_path / "new-run")
    identity.validate()
    calls = []
    prompt.write_text("changed prompt\n")
    with pytest.raises(ValueError, match="Python source identity changed"):
        identity.validate()
        calls.append("model")
    assert calls == []


def test_live_admission_rejects_mongomock_before_any_budget_or_provider(monkeypatch):
    from fuzzingbrain.db.connection import MongoDB
    fake = mongomock.MongoClient()["fixture"]
    monkeypatch.setattr(MongoDB, "get_db", classmethod(lambda cls: fake))
    server = SimpleNamespace(repos=SimpleNamespace(db=fake), ready=True,
                             task_id=str(ObjectId()))
    with pytest.raises(ValueError, match="real MongoDB"):
        live.require_journaled_mongo(server, server.task_id)


def test_live_admission_rejects_nonjournaled_mongo(monkeypatch):
    from fuzzingbrain.db.connection import MongoDB

    class FakeAdmin:
        def command(self, name):
            if name == "hello":
                return {"isWritablePrimary": True}
            return {"parsed": {"storage": {"journal": {"enabled": False}}}}

    class FakeDatabase:
        client = SimpleNamespace(admin=FakeAdmin())

        def get_collection(self, *_args, **_kwargs):
            raise AssertionError("journal-disabled DB must never get a probe write")

    db = FakeDatabase()
    monkeypatch.setattr(live, "Database", FakeDatabase)
    monkeypatch.setattr(MongoDB, "get_db", classmethod(lambda cls: db))
    server = SimpleNamespace(repos=SimpleNamespace(db=db), ready=True,
                             task_id=str(ObjectId()))
    with pytest.raises(ValueError, match="journaled writable"):
        live.require_journaled_mongo(server, server.task_id)


def test_original_worker_execution_remains_closed_even_with_explicit_flag(monkeypatch):
    called = []
    worker = SimpleNamespace(task_id="t", repos=object())
    worker._get_strategy = lambda: SimpleNamespace(executor=worker)
    worker.run = lambda: called.append("executed")
    bound = SimpleNamespace(
        recheck=lambda: None, executor=worker,
        identity=SimpleNamespace(task_id="t"),
        server=SimpleNamespace(repos=worker.repos))
    monkeypatch.setattr(live, "require_journaled_mongo", lambda *_args: None)
    with pytest.raises(ValueError, match="explicit public"):
        live.run_original_public_dev(bound, explicit_public_dev_authorization=False)
    with pytest.raises(RuntimeError, match="fresh-interpreter"):
        live.run_original_public_dev(bound, explicit_public_dev_authorization=True)
    assert called == []


def test_fresh_cli_token_is_single_use_and_final_stopped_ledger_wins(
        tmp_path, monkeypatch):
    entry = Path(live.__file__).resolve().parent / "original_public_live_entry.py"
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    token = object()
    marker = {"pid": __import__("os").getpid(), "spec_path": str(spec),
              "spec_sha256": _sha(spec), "token": token, "used": False,
              "engine_py_sha256": "a" * 64,
              "product_py_sha256": "b" * 64,
              "evaluation_py_sha256": "c" * 64}
    monkeypatch.setitem(sys.modules, "__main__",
                        SimpleNamespace(__file__=str(entry),
                                        _PINNED_PUBLIC_BOOTSTRAP=marker))
    monkeypatch.setattr(sys, "argv", [str(entry), "--authorize-public-dev"])
    monkeypatch.setattr(live, "_isolated_runtime", lambda: True)
    monkeypatch.setattr(live, "require_journaled_mongo", lambda *_args: None)
    task = tmp_path / "task"
    (task / "repo").mkdir(parents=True)
    pov_root = tmp_path / "pov"
    pov_root.mkdir()
    calls = []
    task_id = str(ObjectId())
    repos = RepositoryManager(mongomock.MongoClient().pending_worker)
    worker = SimpleNamespace(task_id=task_id, repos=repos)
    worker._get_strategy = lambda: SimpleNamespace(executor=worker)
    worker.run = lambda: calls.append("original_worker") or {"pov_generated": 0}
    server = SimpleNamespace(repos=repos, socket_path=tmp_path / "unused.sock")
    identity = SimpleNamespace(task_id=task_id, run_id="run", task_path=task,
                                   run_dir=tmp_path,
                               engine_py_sha256="a" * 64,
                               product_py_sha256="b" * 64,
                               evaluation_py_sha256="c" * 64)
    stopped = {
        "stop_status": "STOPPED_OUTPUT_LIMIT", "active": {},
        "wall_spent_seconds": 1.0, "fuzz_spent_seconds": 0.0,
        "revision": 1}
    ledger = SimpleNamespace(receipt_snapshot=lambda: (stopped, "d" * 64))
    bound = SimpleNamespace(
        recheck=lambda: None, bootstrap_token=token, identity=identity,
            caps=_caps(),
        executor=worker, server=server,
        admission=SimpleNamespace(summary={"project_name": "fixture"},
                                  qualification=SimpleNamespace(
                                      binary_sha256="b" * 64)),
        process_ledger=ledger,
        model_gate=SimpleNamespace(snapshot=lambda: {"physical": 0, "records": []}),
        global_campaign=SimpleNamespace(
            final_result={"status": "RAN"},
            campaign=SimpleNamespace(run_dir=tmp_path / "global_campaign")),
        pov_adapter=SimpleNamespace(root=pov_root))
    result = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert result["status"] == "INCOMPLETE"
    assert result["process_stop_status"] == "STOPPED_OUTPUT_LIMIT"
    assert result["execution_status"] == "INCOMPLETE"
    assert result["pov_lineage_rows"] == []
    assert result["model_lineage_gate_verified_pov_count"] == 0
    assert result["automatic_discovery_verified_count"] == 0
    assert _sha(tmp_path / "pov-lineage.json") == result["pov_lineage_receipt_sha256"]
    assert calls == ["original_worker"]
    with pytest.raises(RuntimeError, match="fresh-interpreter"):
        live.run_original_public_dev(bound, explicit_public_dev_authorization=True)
    assert calls == ["original_worker"]
    # Synthetic inconsistent Global receipt: status RAN cannot hide an
    # unconsumed crash even when the durable process ledger itself is clean.
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    clean = {
        "stop_status": None, "active": {},
        "wall_spent_seconds": 1.0, "fuzz_spent_seconds": 1.0,
        "revision": 2}
    bound.process_ledger = SimpleNamespace(
        receipt_snapshot=lambda: (clean, "e" * 64))
    bound.global_campaign.final_result = {
        "status": "RAN", "observed_crash_count": 1,
        "consumer_rows": [{"status": "PENDING_RUNTIME_ATTEMPT_LIMIT"}]}
    # A real fresh run gets a new directory; this fixture re-enters the
    # function only to test final receipt precedence.
    identity.run_dir = tmp_path / "second-run"
    identity.run_dir.mkdir()
    result = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert result["status"] == "INCOMPLETE"
    assert result["pending_global_crashes"] == 1
    # Only the authenticated campaign's explicit clean skip can represent a
    # Global phase with no physical execution. Unknown statuses stay blocked.
    for status, expected in (("SKIPPED_NO_SEED", "EXECUTED_UNVERIFIED"),
                             ("UNRECOGNIZED", "INCOMPLETE")):
        marker["token"] = object()
        marker["used"] = False
        bound.bootstrap_token = marker["token"]
        bound.global_campaign.final_result = {"status": status,
                                               "cleanup_complete": True}
        identity.run_dir = tmp_path / f"global-{status.lower()}"
        identity.run_dir.mkdir()
        checked = live.run_original_public_dev(
            bound, explicit_public_dev_authorization=True)
        assert checked["status"] == expected
        assert checked["execution_status"] == (
            "EXECUTED" if status == "SKIPPED_NO_SEED" else "INCOMPLETE")
    # A cleanly reclaimed Global crash is a terminal process observation.
    # Its consumer verdict is preserved, while unproven mutation origin earns
    # no automatic-discovery credit.
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    identity.run_dir = tmp_path / "global-verified-observation"
    bound.global_campaign.campaign.run_dir = identity.run_dir / "global_campaign"
    bound.global_campaign.final_result = _global_consumer_fixture(
        bound.global_campaign.campaign.run_dir, "VERIFIED")
    observed = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert observed["execution_status"] == "EXECUTED"
    assert observed["status"] == "EXECUTED_UNVERIFIED"
    assert observed["verification_status"] == (
        "PRODUCT_CONSUMER_VERIFIED_ORIGIN_UNPROVEN")
    assert observed["global_consumer_verified_count"] == 1
    assert observed["global_consumer_rows"][0]["input_sha256"] == (
        bound.global_campaign.final_result["observed_crash_rows"][0]["input_sha256"])
    assert observed["global_discovery_credit"] == "NOT_CREDITED_ORIGIN_UNPROVEN"
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    identity.run_dir = tmp_path / "global-mixed-observations"
    bound.global_campaign.campaign.run_dir = identity.run_dir / "global_campaign"
    bound.global_campaign.final_result = _global_consumer_fixture(
        bound.global_campaign.campaign.run_dir, "VERIFIED")
    _append_pending_global_observation(
        bound.global_campaign.campaign.run_dir,
        bound.global_campaign.final_result)
    mixed = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert mixed["pending_global_crashes"] == 1
    assert mixed["global_consumer_verified_count"] == 1
    assert mixed["verification_status"] == "PENDING_INDEPENDENT_VALIDATION"
    assert mixed["automatic_discovery_verified_count"] == 0
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    identity.run_dir = tmp_path / "global-missing-consumer-status"
    bound.global_campaign.campaign.run_dir = identity.run_dir / "global_campaign"
    bound.global_campaign.final_result = _global_consumer_fixture(
        bound.global_campaign.campaign.run_dir, "VERIFIED")
    bound.global_campaign.final_result["consumer_rows"][0].pop("status")
    _write_json(
        bound.global_campaign.campaign.run_dir / "runtime" /
        "global_fuzzer_consumption.json",
        bound.global_campaign.final_result["consumer_rows"])
    _write_json(
        bound.global_campaign.campaign.run_dir / "DEV_GLOBAL_RESULT.json",
        bound.global_campaign.final_result)
    missing_status = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert missing_status["pending_global_crashes"] == 1
    assert missing_status["global_consumer_verified_count"] == 0
    assert missing_status["automatic_discovery_verified_count"] == 0
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    bound.global_campaign.campaign.run_dir = tmp_path / "global-pending-receipt"
    bound.global_campaign.final_result = _global_consumer_fixture(
        bound.global_campaign.campaign.run_dir, "VERIFIED")
    bound.global_campaign.final_result["consumer_rows"][0]["status"] = (
        "PENDING_RUNTIME_ATTEMPT_LIMIT")
    identity.run_dir = tmp_path / "global-pending-observation"
    bound.global_campaign.campaign.run_dir = identity.run_dir / "global_campaign"
    identity.run_dir.mkdir()
    pending = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert pending["execution_status"] == "EXECUTED"
    assert pending["verification_status"] == "PENDING_INDEPENDENT_VALIDATION"
    assert pending["status"] == "INCOMPLETE"
    assert pending["pending_global_crashes"] == 1
    # A saved original PoV crash is handed to the product consumer after the
    # Worker returns; a pending Gate verdict remains pending in the summary.
    from devtools import product_qualified_runtime as qualified_runtime
    pov_id = str(ObjectId())
    (pov_root / pov_id).mkdir()
    (pov_root / pov_id / "runtime.json").write_text(
        '{"status":"CRASH_OBSERVED"}')
    gate_calls = []
    monkeypatch.setattr(
        qualified_runtime, "consume_qualified_pov_observation",
        lambda adapter, claimed_id, **_kwargs:
        gate_calls.append((adapter, claimed_id)) or {
            "pov_id": claimed_id,
            "product_gate_status": "TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE"})
    bound.caps = _caps()
    bound.global_campaign.final_result = {"status": "RAN"}
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    identity.run_dir = tmp_path / "third-run"
    identity.run_dir.mkdir()
    result = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert gate_calls == [(bound.pov_adapter, pov_id)]
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["pov_product_gate_rows"][0]["product_gate_status"] == (
        "TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE")
    assert result["pov_lineage_rows"][0]["automatic_discovery"] is False
    assert result["pov_lineage_rows"][0]["candidate_lineage"]["status"] == "UNPROVEN"
    assert result["status"] == "INCOMPLETE"
    assert result["execution_status"] == "EXECUTED"
    assert result["verification_status"] == "PENDING_INDEPENDENT_VALIDATION"
    # The real original Pipeline raises after a qualified PoV crash. That
    # exact pending reason must still reach the independent product consumer.
    from fuzzingbrain.worker.pipeline import IncompleteInjectedAgent
    pending_pov_root = tmp_path / "pending-pov"
    pending_pov_id = str(ObjectId())
    (pending_pov_root / pending_pov_id).mkdir(parents=True)
    (pending_pov_root / pending_pov_id / "runtime.json").write_text(
        '{"status":"CRASH_OBSERVED"}')
    bound.pov_adapter.root = pending_pov_root
    pending_sp_id = ObjectId()
    repos.suspicious_points.collection.insert_one({
        "_id": pending_sp_id, "task_id": ObjectId(task_id),
        "status": "pending_independent_validation",
        "pending_pov_ids": [pending_pov_id]})
    worker._worker_context = SimpleNamespace(worker_id=str(ObjectId()))

    def validation_pending():
        raise IncompleteInjectedAgent("qualified PoV retained",
                                      reason="validation_pending")

    worker.run = validation_pending
    gate_calls.clear()
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    identity.run_dir = tmp_path / "pending-run"
    identity.run_dir.mkdir()
    pending_result = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert gate_calls == [(bound.pov_adapter, pending_pov_id)]
    assert pending_result["original_worker_status"] == (
        "PENDING_INDEPENDENT_VALIDATION")
    assert pending_result["original_result"]["worker_id"] == (
        worker._worker_context.worker_id)
    assert pending_result["execution_status"] == "EXECUTED"
    assert pending_result["verification_status"] == (
        "PENDING_INDEPENDENT_VALIDATION")
    assert pending_result["status"] == "INCOMPLETE"

    # A second pending PoV with no runtime must not be hidden by the first
    # observed crash.
    second_pov_id = str(ObjectId())
    (pending_pov_root / second_pov_id).mkdir()
    (pending_pov_root / second_pov_id / "runtime.json").write_text(
        '{"status":"NO_CRASH"}')
    repos.suspicious_points.collection.update_one(
        {"_id": pending_sp_id},
        {"$set": {"pending_pov_ids": [pending_pov_id, second_pov_id]}})
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    identity.run_dir = tmp_path / "partial-pending-run"
    identity.run_dir.mkdir()
    partial = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert partial["execution_status"] == "INCOMPLETE"
    assert partial["status"] == "INCOMPLETE"
    repos.suspicious_points.collection.update_one(
        {"_id": pending_sp_id},
        {"$set": {"pending_pov_ids": [pending_pov_id]}})

    # Other Worker exceptions, especially uncertain model turns, never get
    # recast as a pending validation opportunity.
    def uncertain_remote():
        raise IncompleteInjectedAgent("remote state unknown",
                                      reason="uncertain_remote")

    worker.run = uncertain_remote
    gate_calls.clear()
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    identity.run_dir = tmp_path / "uncertain-run"
    identity.run_dir.mkdir()
    with pytest.raises(IncompleteInjectedAgent, match="remote state unknown"):
        live.run_original_public_dev(
            bound, explicit_public_dev_authorization=True)
    assert gate_calls == []

    # A pending Worker with no retained crash cannot be called executed.
    worker.run = validation_pending
    bound.pov_adapter.root = tmp_path / "missing-pov"
    bound.pov_adapter.root.mkdir()
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    identity.run_dir = tmp_path / "missing-pov-run"
    identity.run_dir.mkdir()
    missing = live.run_original_public_dev(
        bound, explicit_public_dev_authorization=True)
    assert missing["execution_status"] == "INCOMPLETE"
    assert missing["pov_product_gate_rows"] == []
    assert missing["status"] == "INCOMPLETE"

    worker.run = lambda: {"pov_generated": 0}
    marker["token"] = object()
    marker["used"] = False
    bound.bootstrap_token = marker["token"]
    bound.process_ledger = SimpleNamespace(
        receipt_snapshot=lambda: (_ for _ in ()).throw(
            RuntimeError("V2 process receipt differs from owner state")))
    identity.run_dir = tmp_path / "fourth-run"
    identity.run_dir.mkdir()
    with pytest.raises(RuntimeError, match="receipt differs"):
        live.run_original_public_dev(bound, explicit_public_dev_authorization=True)
