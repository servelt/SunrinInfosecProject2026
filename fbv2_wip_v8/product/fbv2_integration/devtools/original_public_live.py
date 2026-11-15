"""Bounded public-development binding for the original FBv2 fullscan.

Construction is provider-free. The explicit ``run_original_public_dev`` call
is the only point that enters the original WorkerExecutor. There is no Blind 3
or Oracle path. Callers must supply an externally pinned Python source tree,
product-issued V2 qualification, one MongoDB-backed AnalysisServer, and
physical model/process budgets. This module does not contain a scanner loop.
The callable live entry requires an explicit fresh-interpreter CLI and bounded
replay/Gate process reservation. Disk hashes alone do not attest modules
already loaded in a long-lived Python process. Product HP prompts/config are
outside this SP/Global runtime source pin and require separate admission.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import sys
import threading
from typing import Any

from bson import ObjectId
from pymongo.database import Database
from pymongo.write_concern import WriteConcern

from devtools.campaign_model_gate import (
    CampaignModelGate, product_campaign_client_factory)
from devtools.original_global_bridge import (
    OriginalGlobalBridge, _settled_crash_observation)
from devtools.original_public_dev import PinnedAdmission, build_provider_free_executor


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_-]+\Z")


def _isolated_runtime() -> bool:
    return sys.flags.isolated == 1


_TERMINAL_CONSUMER_STATUSES = frozenset({
    "VERIFIED", "ORIGINAL_REPLAY_NOT_REPRODUCED",
    "BLOCKED_NON_TARGET_CRASH", "GATE_CHECKED_NOT_VERIFIED",
})


def _plain_run_bytes(run_dir: Path, path: Path) -> bytes | None:
    """Read only a plain, canonical file below this run's private directory."""
    try:
        if (not run_dir.is_absolute() or run_dir != run_dir.resolve() or
                run_dir.is_symlink() or not run_dir.is_dir() or
                not path.is_absolute() or path != path.resolve() or
                not path.is_relative_to(run_dir) or not path.is_file()):
            return None
        return path.read_bytes()
    except (OSError, RuntimeError, ValueError):
        return None


def _plain_run_json(run_dir: Path, path: Path) -> Any:
    data = _plain_run_bytes(run_dir, path)
    if data is None:
        return None
    try:
        return json.loads(data)
    except (UnicodeError, ValueError, RecursionError):
        return None


def _model_lineage_gate_verified_pov_ids(
        run_dir: Path, lineage_rows: list[dict[str, Any]],
        gate_rows: list[dict[str, Any]]) -> list[str]:
    """Count product-verified model PoVs without claiming automatic discovery.

    A model/tool lineage and a product Gate result must refer to the same
    retained input. A manual function hint or copied PoC is not excluded by
    these receipts, so this is deliberately a PoV count, not discovery credit.
    """
    if (type(lineage_rows) is not list or type(gate_rows) is not list or
            any(type(row) is not dict for row in lineage_rows + gate_rows)):
        return []
    lineage_ids = [row.get("pov_id") for row in lineage_rows]
    gate_ids = [row.get("pov_id") for row in gate_rows]
    if (any(type(value) is not str for value in lineage_ids + gate_ids) or
            len(lineage_ids) != len(set(lineage_ids)) or
            len(gate_ids) != len(set(gate_ids))):
        return []
    by_id = {row["pov_id"]: row for row in lineage_rows}
    verified = []
    for gate in gate_rows:
        pov_id = gate.get("pov_id")
        row = by_id.get(pov_id)
        if (type(pov_id) is not str or not ObjectId.is_valid(pov_id) or
                row is None or gate.get("product_gate_status") != "VERIFIED" or
                gate.get("origin_verification_status") !=
                    "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE" or
                gate.get("security_gate_state") != "COMPLETED" or
                gate.get("security_gate_result") is not True or
                gate.get("automatic_discovery") is not False or
                gate.get("discovery_credit") != "NOT_CREDITED"):
            continue
        candidate = row.get("candidate_lineage")
        runtime = row.get("runtime_lineage")
        if (type(candidate) is not dict or type(runtime) is not dict or
                candidate.get("status") != "VERIFIED" or
                runtime.get("status") != "VERIFIED" or
                row.get("automatic_discovery") is not False):
            continue
        shared = ("task_id", "run_id", "sp_id", "pov_id",
                  "input_sha256", "binary_sha256")
        pov_inputs = candidate.get("pov_inputs")
        if (type(pov_inputs) is not list or
                any(runtime.get(key) != gate.get(key) for key in shared) or
                any(candidate.get(key) != runtime.get(key)
                    for key in ("task_id", "sp_id")) or
                candidate.get("campaign_id") != runtime.get("run_id") or
                not any(item.get("pov_id") == pov_id and
                            item.get("input_sha256") == runtime.get("input_sha256")
                            for item in pov_inputs
                            if type(item) is dict) or
                candidate.get("model_tool_turns") != runtime.get("model_tool_turns")):
            continue
        claim = run_dir / "pov-validation" / pov_id
        origin_path = claim / "origin-lineage.json"
        canonical_name = gate.get("canonical_crash_artifact")
        canonical_path = Path(canonical_name) if type(canonical_name) is str else None
        product_runtime_name = gate.get("product_runtime_artifact")
        product_runtime_path = (Path(product_runtime_name)
                                if type(product_runtime_name) is str else None)
        origin_bytes = _plain_run_bytes(run_dir, origin_path)
        canonical_bytes = (_plain_run_bytes(run_dir, canonical_path)
                           if canonical_path is not None else None)
        product_runtime_bytes = (_plain_run_bytes(run_dir, product_runtime_path)
                                 if product_runtime_path is not None else None)
        if (gate.get("origin_lineage_receipt_path") != str(origin_path) or
                type(gate.get("origin_lineage_receipt_sha256")) is not str or
                origin_bytes is None or
                hashlib.sha256(origin_bytes).hexdigest() !=
                    gate["origin_lineage_receipt_sha256"] or
                canonical_path is None or
                canonical_path.parent != claim / "product" / "runtime" / "crashes" or
                type(gate.get("canonical_crash_sha256")) is not str or
                canonical_bytes is None or
                hashlib.sha256(canonical_bytes).hexdigest() !=
                    gate["canonical_crash_sha256"] or
                product_runtime_path is None or
                product_runtime_path.parent != claim / "product" / "runtime" or
                type(gate.get("product_runtime_sha256")) is not str or
                product_runtime_bytes is None or
                hashlib.sha256(product_runtime_bytes).hexdigest() !=
                    gate["product_runtime_sha256"]):
            continue
        try:
            origin = json.loads(origin_bytes)
            canonical = json.loads(canonical_bytes)
        except (UnicodeError, ValueError, RecursionError):
            continue
        trace = canonical.get("independent_gate_trace") if type(canonical) is dict else None
        if (type(origin) is not dict or
                origin.get("kind") != "FBV2_POV_PRODUCT_ORIGIN_LINEAGE_V1" or
                origin.get("lineage") != runtime or
                origin.get("origin_verification_status") !=
                    "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE" or
                origin.get("automatic_discovery") is not False or
                origin.get("discovery_credit") != "NOT_CREDITED" or
                any(origin.get(key) != runtime.get(key)
                    for key in ("task_id", "run_id", "pov_id", "input_sha256")) or
                type(canonical) is not dict or
                canonical.get("independent_verification_status") != "VERIFIED" or
                type(canonical.get("independent_verification_source")) is not dict or
                canonical["independent_verification_source"].get("input_sha256") !=
                    runtime.get("input_sha256") or
                canonical["independent_verification_source"].get("runtime_artifact") !=
                    str(product_runtime_path) or
                type(trace) is not dict or
                trace.get("crash_id") != canonical.get("crash_id") or
                trace.get("promotion_state") != "COMPLETED" or
                trace.get("promotion_result") is not True or
                trace.get("security_property_state") != "COMPLETED"):
            continue
        verified.append(pov_id)
    return verified


def _global_report_observations(global_receipt: dict[str, Any],
                                run_dir: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]] | None:
    report_path = run_dir / "runtime" / "global_fuzz.json"
    data = _plain_run_bytes(run_dir, report_path)
    expected_sha = global_receipt.get("global_report_sha256")
    if (data is None or type(expected_sha) is not str or
            _SHA.fullmatch(expected_sha) is None or
            hashlib.sha256(data).hexdigest() != expected_sha):
        return None
    try:
        report = json.loads(data)
    except (UnicodeError, ValueError, RecursionError):
        return None
    if (type(report) is not dict or
            report.get("status") != "CRASH_OBSERVED_INCOMPLETE" or
            type(report.get("observed_crashes")) is not list):
        return None
    runtime_artifact = report.get("runtime_artifact")
    if (type(runtime_artifact) is not str or
            _plain_run_bytes(run_dir, Path(runtime_artifact)) is None):
        return None
    observed = {}
    for item in report["observed_crashes"]:
        if type(item) is not dict:
            return None
        crash_id, input_sha = item.get("observed_crash_id"), item.get("sha256")
        candidate_name, size = item.get("candidate_path"), item.get("size")
        if (type(crash_id) is not str or _ID.fullmatch(crash_id) is None or
                type(input_sha) is not str or _SHA.fullmatch(input_sha) is None or
                type(candidate_name) is not str or type(size) is not int or
                size < 0 or crash_id in observed):
            return None
        candidate = Path(candidate_name)
        content = _plain_run_bytes(run_dir, candidate)
        if (candidate.parent != run_dir / "corpus" / "global" or
                content is None or len(content) != size or
                hashlib.sha256(content).hexdigest() != input_sha):
            return None
        observed[crash_id] = item
    return report, observed


def _consumer_row_terminal(row: dict[str, Any], run_dir: Path,
                           report: dict[str, Any], observation: dict[str, Any]) -> bool:
    input_sha = row.get("input_sha256")
    outcome = row.get("consumer_result")
    crash_id = row.get("crash_id")
    if (row.get("status") not in _TERMINAL_CONSUMER_STATUSES or
            type(crash_id) is not str or _ID.fullmatch(crash_id) is None or
            type(input_sha) is not str or _SHA.fullmatch(input_sha) is None or
            type(outcome) is not dict or
            outcome.get("status") != row["status"] or
            outcome.get("input_sha256") != input_sha or
            outcome.get("binary_sha256") != report.get("binary_sha256") or
            type(outcome.get("qualification_identity")) is not dict or
            outcome["qualification_identity"].get("kind") != "OFFICIAL_PINNED" or
            outcome["qualification_identity"].get("binary_sha256") !=
                report.get("binary_sha256")):
        return False
    record = _plain_run_json(
        run_dir, run_dir / "runtime" / "fuzzer_crashes" / f"{crash_id}.json")
    if type(record) is not dict or record.get("crash_id") != crash_id:
        return False
    observations = record.get("observations")
    matches = ([item for item in observations if type(item) is dict and
                item.get("source") == "GLOBAL_FUZZER" and
                item.get("crash_input") == observation and
                item.get("runtime_artifact") == report.get("runtime_artifact")]
               if type(observations) is list else [])
    attempts = record.get("consumer_attempts")
    results = record.get("consumer_results")
    history = attempts.get(input_sha) if type(attempts) is dict else None
    if (len(matches) != 1 or type(results) is not dict or
            results.get(input_sha) != outcome or type(history) is not list or
            not history or history[-1] != outcome or
            record.get("status") != row["status"]):
        return False
    poc_id = outcome.get("poc_id")
    if type(poc_id) is not str or _ID.fullmatch(poc_id) is None:
        return False
    runtime_path = run_dir / "runtime" / f"{poc_id}.json"
    runtime_bytes = _plain_run_bytes(run_dir, runtime_path)
    snapshot = run_dir / "runtime" / "fuzzer_validation" / crash_id / f"{input_sha}.input.bin"
    snapshot_bytes = _plain_run_bytes(run_dir, snapshot)
    if (outcome.get("runtime_artifact") != str(runtime_path) or
            type(outcome.get("runtime_sha256")) is not str or
            _SHA.fullmatch(outcome["runtime_sha256"]) is None or
            runtime_bytes is None or
            hashlib.sha256(runtime_bytes).hexdigest() != outcome["runtime_sha256"] or
            outcome.get("snapshot_path") != str(snapshot) or
            snapshot_bytes is None or
            hashlib.sha256(snapshot_bytes).hexdigest() != input_sha):
        return False
    try:
        runtime = json.loads(runtime_bytes)
    except (UnicodeError, ValueError, RecursionError):
        return False
    if type(runtime) is not dict or runtime.get("timed_out") is not False or \
            type(runtime.get("exit_code")) is not int:
        return False
    target_crash = (bool(runtime.get("sanitizer")) and
                    type(runtime.get("crash_triage")) is dict and
                    runtime["crash_triage"].get("category") == "TARGET_CRASH")
    if row["status"] == "ORIGINAL_REPLAY_NOT_REPRODUCED":
        return not runtime.get("sanitizer")
    if row["status"] == "BLOCKED_NON_TARGET_CRASH":
        return bool(runtime.get("sanitizer")) and not target_crash
    if not target_crash:
        return False
    canonical_id = outcome.get("canonical_crash_id")
    if type(canonical_id) is not str or _ID.fullmatch(canonical_id) is None:
        return False
    canonical_path = run_dir / "runtime" / "crashes" / f"{canonical_id}.json"
    canonical = _plain_run_json(run_dir, canonical_path)
    source = {"poc_id": poc_id, "input_sha256": input_sha,
              "runtime_artifact": str(runtime_path)}
    if (outcome.get("canonical_crash_artifact") != str(canonical_path) or
            type(canonical) is not dict or canonical.get("crash_id") != canonical_id or
            canonical.get("independent_verification_source") != source or
            canonical.get("independent_verification_status") !=
                outcome.get("gate_status")):
        return False
    canonical_observations = canonical.get("observations")
    if (type(canonical_observations) is not list or
            len(canonical_observations) != 1 or
            type(canonical_observations[0]) is not dict or
            any(canonical_observations[0].get(key) != value
                for key, value in source.items())):
        return False
    if row["status"] == "GATE_CHECKED_NOT_VERIFIED":
        return bool(outcome.get("gate_status")) and outcome["gate_status"] != "VERIFIED"
    trace = canonical.get("independent_gate_trace")
    if (row["status"] != "VERIFIED" or outcome.get("gate_status") != "VERIFIED" or
            type(trace) is not dict or trace.get("crash_id") != canonical_id or
            trace.get("security_property_evaluated") is not True or
            trace.get("security_property_state") != "COMPLETED" or
            trace.get("promotion_state") != "COMPLETED" or
            trace.get("promotion_result") is not True):
        return False
    # A final Gate label is meaningful only with its saved causal, replay,
    # and security evidence. Never infer these receipts from the label alone.
    required = {
        "independent_candidate_artifact": None,
        "independent_root_cause_artifact": ("verdict", "CONFIRMED"),
        "independent_fixed_poc_artifact": None,
        "independent_replay_artifact": ("status", "REPRODUCED"),
        "independent_security_artifact": ("status", "CONFIRMED"),
    }
    for field, expected_field in required.items():
        artifact_name = canonical.get(field)
        if type(artifact_name) is not str:
            return False
        artifact = _plain_run_json(run_dir, Path(artifact_name))
        if type(artifact) is not dict or (expected_field is not None and
                artifact.get(expected_field[0]) != expected_field[1]):
            return False
    return True


def _bound_global_consumer_evidence(
        global_receipt: dict[str, Any], run_dir: Path | None,
        expected_binary_sha256: str | None
) -> tuple[dict[str, Any], dict[str, dict[str, Any]],
           list[dict[str, Any]], dict[str, Any]] | None:
    """Reopen the complete campaign identity before trusting any one Crash."""
    observed_count = global_receipt.get("observed_crash_count", 0)
    consumer_rows = global_receipt.get("consumer_rows", [])
    expected_rows = global_receipt.get("observed_crash_rows", [])
    if (type(observed_count) is not int or observed_count < 1 or
            type(consumer_rows) is not list or
            type(expected_rows) is not list or
            len(expected_rows) != observed_count):
        return None
    expected = {}
    for row in expected_rows:
        if (type(row) is not dict or
                type(row.get("crash_id")) is not str or not row["crash_id"] or
                type(row.get("input_sha256")) is not str or
                _SHA.fullmatch(row["input_sha256"]) is None or
                row["crash_id"] in expected):
            return None
        expected[row["crash_id"]] = row["input_sha256"]
    ids = [row.get("crash_id") for row in consumer_rows
           if type(row) is dict]
    if (len(consumer_rows) != observed_count or len(ids) != len(consumer_rows)
            or any(type(value) is not str or not value for value in ids)
            or len(set(ids)) != len(ids) or
            any(expected.get(row["crash_id"]) != row.get("input_sha256")
                for row in consumer_rows)):
        return None
    if (run_dir is None or type(expected_binary_sha256) is not str or
            _SHA.fullmatch(expected_binary_sha256) is None):
        return None
    run_dir = Path(run_dir)
    report_observations = _global_report_observations(global_receipt, run_dir)
    raw_result = _plain_run_json(run_dir, run_dir / "DEV_GLOBAL_RESULT.json")
    disk_rows = _plain_run_json(
        run_dir, run_dir / "runtime" / "global_fuzzer_consumption.json")
    if (report_observations is None or type(raw_result) is not dict or
            type(disk_rows) is not list or
            raw_result.get("observed_crash_rows") != expected_rows or
            raw_result.get("observed_crash_count") != observed_count or
            raw_result.get("consumer_rows") != consumer_rows or
            raw_result.get("global_report_sha256") !=
                global_receipt.get("global_report_sha256") or
            raw_result.get("consumer_process_account_installed") is not True or
            global_receipt.get("consumer_process_account_installed") is not True or
            disk_rows != consumer_rows):
        return None
    report, observed = report_observations
    if (report.get("binary_sha256") != expected_binary_sha256 or
            len(observed) != observed_count or
            expected != {key: value.get("sha256") for key, value in observed.items()}):
        return None
    return report, observed, consumer_rows, raw_result


def pending_global_crash_count(global_receipt: dict[str, Any], *,
                               run_dir: Path | None = None,
                               expected_binary_sha256: str | None = None) -> int:
    """Count unresolved observations using the product consumer's statuses."""
    observed_count = global_receipt.get("observed_crash_count", 0)
    consumer_rows = global_receipt.get("consumer_rows", [])
    if (type(observed_count) is not int or observed_count < 0 or
            type(consumer_rows) is not list):
        raise ValueError("Global crash consumer accounting changed")
    expected_rows = global_receipt.get("observed_crash_rows", [])
    if type(expected_rows) is not list:
        raise ValueError("Global observation identities changed")
    if observed_count == 0 and not expected_rows and not consumer_rows:
        return 0
    bound = _bound_global_consumer_evidence(
        global_receipt, run_dir, expected_binary_sha256)
    if bound is None:
        return max(1, observed_count, len(consumer_rows))
    report, observed, consumer_rows, _raw_result = bound
    return sum(not _consumer_row_terminal(row, run_dir, report,
                                          observed[row["crash_id"]])
               for row in consumer_rows)


def verified_global_mutation_rows(global_receipt: dict[str, Any], *,
                                  run_dir: Path | None,
                                  expected_binary_sha256: str | None) -> list[dict[str, str]]:
    """Identify Gate-verified mutated inputs, without awarding discovery credit.

    A verified crash may originate in a human-supplied seed or function hint.
    This only proves the retained input was mutated by this physical fuzzer
    run and then passed the existing independent product checks.
    """
    bound = _bound_global_consumer_evidence(
        global_receipt, run_dir, expected_binary_sha256)
    if bound is None:
        return []
    run_dir = Path(run_dir)
    report, observed, consumer_rows, raw_result = bound
    rows = global_receipt.get("observed_mutated_crash_rows")
    seeds = global_receipt.get("staged_seed_sha256s")
    if (type(rows) is not list or type(seeds) is not list or
            raw_result.get("observed_mutated_crash_rows") != rows or
            raw_result.get("staged_seed_sha256s") != seeds or
            global_receipt.get("global_crash_mutation_observed") is not True or
            report.get("crash_mutation_observed") is not True or
            any(type(item) is not dict for item in rows) or
            any(type(value) is not str or _SHA.fullmatch(value) is None
                for value in seeds) or len(set(seeds)) != len(seeds)):
        return []
    runtime_name = report.get("runtime_artifact")
    runtime_sha = report.get("runtime_artifact_sha256")
    if (type(runtime_name) is not str or type(runtime_sha) is not str or
            _SHA.fullmatch(runtime_sha) is None):
        return []
    runtime_bytes = _plain_run_bytes(run_dir, Path(runtime_name))
    if runtime_bytes is None or hashlib.sha256(runtime_bytes).hexdigest() != runtime_sha:
        return []
    try:
        runtime = json.loads(runtime_bytes)
    except (UnicodeError, ValueError, RecursionError):
        return []
    if type(runtime) is not dict or type(runtime.get("stderr")) is not str:
        return []
    from vulnerabilityanalysis.scan import (
        _corpus_inputs, _observed_libfuzzer_crash_mutations)
    try:
        recomputed = _observed_libfuzzer_crash_mutations(
            runtime["stderr"], report["observed_crashes"], set(seeds),
            _corpus_inputs(run_dir / "corpus" / "global"))
    except (OSError, ValueError, TypeError, KeyError):
        return []
    expected_rows = [{"crash_id": item["observed_crash_id"],
                      "input_sha256": item["input_sha256"],
                      "base_sha256": item["base_sha256"]}
                     for item in recomputed]
    if (rows != expected_rows or
            any(item.get("crash_id") not in observed or
                observed[item["crash_id"]].get("sha256") != item.get("input_sha256")
                for item in rows)):
        return []
    verified_ids = {
        row["crash_id"] for row in consumer_rows
        if row.get("status") == "VERIFIED" and
        _consumer_row_terminal(row, run_dir, report, observed[row["crash_id"]])
    }
    return [row for row in rows if row["crash_id"] in verified_ids]


def incomplete_model_activity(model_receipt: dict[str, Any],
                              gate: CampaignModelGate | None = None) -> bool:
    """Re-read every model and tool artifact before declaring execution done."""
    try:
        rows = model_receipt["records"]
        if type(rows) is not list:
            return True
        for row in rows:
            request_id = row.get("request_id")
            if (type(row) is not dict or row.get("status") != "COMPLETED" or
                    (gate is not None and
                     (type(request_id) is not str or not request_id)) or
                    (row.get("response_evidence") or {}).get("status") !=
                        "VERIFIED"):
                return True
            if (gate is not None and
                    gate.verify_response_evidence(request_id).get("status") !=
                        "VERIFIED"):
                return True
            events = row.get("tool_events", [])
            if type(events) is not list:
                return True
            for event in events:
                if (type(event) is not dict or
                        event.get("status") != "COMPLETED" or
                        (gate is not None and
                         type(event.get("call_id")) is not str) or
                        (gate is not None and
                         gate.verify_tool_event(
                             request_id, event["call_id"]).get("status") !=
                             "VERIFIED")):
                    return True
    except Exception:
        return True
    return False


def python_tree_sha256(root: Path) -> str:
    """Hash Python plus runtime prompt/config assets, rejecting linked files.

    A source-only pin would miss prompt or tool-schema changes that alter the
    original Direction/SP/PoV behavior without changing Python code.
    """
    if (not root.is_absolute() or root.is_symlink() or
            root != root.resolve() or not root.is_dir()):
        raise ValueError("Python source root must be a canonical directory")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise ValueError("Python source tree contains a linked entry")
    files = sorted(root.rglob("*.py"))
    if (root / "fuzzingbrain").is_dir():
        prompts = root / "fuzzingbrain" / "agents" / "prompts"
        assets = [root / "fuzzingbrain" / "llm_config.yaml",
                  root / "fuzzingbrain" / "tools" / "tools.yaml"]
        if not prompts.is_dir():
            raise ValueError("original FBv2 prompt directory is missing")
        assets.extend(sorted(prompts.glob("*.md")))
        if (len(assets) < 3 or any(not asset.is_file() or asset.is_symlink()
                                   for asset in assets)):
            raise ValueError("original FBv2 prompt/config assets are missing")
        files = sorted(set(files + assets))
    if not files:
        raise ValueError("Python source tree is empty")
    digest = hashlib.sha256()
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Python source tree contains a linked module")
        name = path.relative_to(root).as_posix().encode()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _pinned_file(path: Path, expected: str, label: str) -> None:
    if (not isinstance(expected, str) or not _SHA.fullmatch(expected) or
            not path.is_absolute() or path.is_symlink() or
            path != path.resolve() or not path.is_file() or
            not os.access(path, os.X_OK) and label == "Codex executable" or
            hashlib.sha256(path.read_bytes()).hexdigest() != expected):
        raise ValueError(f"{label} SHA-256 identity changed")


@dataclass(frozen=True)
class PublicDevCaps:
    """Preliminary caps for dependency construction, not a Gate budget.

    Global crash replay can involve several GDB, original, and negative
    control processes per observation. ``global_replay_limit`` is a count,
    not a complete physical wall reservation. The live entry remains closed.
    """
    physical_model_calls: int
    model_wall_seconds: float
    calls_per_agent: int
    total_wall_seconds: float
    total_fuzz_seconds: float
    global_fuzz_seconds: int
    global_reservation_seconds: float
    global_replay_limit: int
    pov_timeout_seconds: float
    pov_wall_seconds: float
    process_output_limit_bytes: int
    gate_aux_reservation_seconds_per_observation: float = 600.0
    sp_fuzz_seconds: int = 0
    sp_fuzz_max_items: int = 0

    def validate(self) -> None:
        number = (self.model_wall_seconds, self.total_wall_seconds,
                  self.total_fuzz_seconds, self.global_reservation_seconds,
                  self.pov_timeout_seconds, self.pov_wall_seconds,
                  self.gate_aux_reservation_seconds_per_observation)
        # One SP attempt includes an AUX interface probe (5s + 9.5s cleanup)
        # and a fuzz process (requested seconds + 15s runtime slack + 9.5s
        # cleanup). One SP Crash consumer may then need the existing Gate AUX
        # allowance. All three reserve wall; only the fuzz process reserves
        # fuzz time. This is an admission cap, not a launch instruction.
        sp_fuzz_wall_reservation = self.sp_fuzz_max_items * (
            self.sp_fuzz_seconds + 39.0 +
            self.gate_aux_reservation_seconds_per_observation)
        sp_fuzz_fuzz_reservation = self.sp_fuzz_max_items * (
            self.sp_fuzz_seconds + 24.5)
        if (any(type(value) not in (int, float) or not math.isfinite(value)
                or value <= 0 for value in number) or
                any(type(value) is not int or value < 1 for value in
                    (self.physical_model_calls, self.calls_per_agent,
                     self.global_fuzz_seconds, self.process_output_limit_bytes)) or
                type(self.global_replay_limit) is not int or
                self.global_replay_limit < 1 or
                type(self.sp_fuzz_seconds) is not int or
                type(self.sp_fuzz_max_items) is not int or
                not ((self.sp_fuzz_seconds == 0 and self.sp_fuzz_max_items == 0)
                     or (1 <= self.sp_fuzz_seconds <= 10 and
                         self.sp_fuzz_max_items == 1)) or
                self.gate_aux_reservation_seconds_per_observation < 600 or
                self.gate_aux_reservation_seconds_per_observation > 3600 or
                self.global_reservation_seconds < self.global_fuzz_seconds + 12.5 or
                self.pov_wall_seconds < self.pov_timeout_seconds + 9.5 or
                self.total_fuzz_seconds < self.global_reservation_seconds or
                self.total_fuzz_seconds < self.global_reservation_seconds +
                    sp_fuzz_fuzz_reservation or
                self.total_wall_seconds < (self.model_wall_seconds +
                    self.global_reservation_seconds +
                    self.pov_wall_seconds + self.global_replay_limit *
                    self.gate_aux_reservation_seconds_per_observation +
                    sp_fuzz_wall_reservation) or
                self.total_wall_seconds > 3600 or
                self.total_fuzz_seconds > 120 or
                self.global_fuzz_seconds > 60 or
                self.global_replay_limit > 2 or
                self.physical_model_calls > 32 or
                self.calls_per_agent > 12 or
                self.process_output_limit_bytes > 16_000_000 or
                self.pov_timeout_seconds > 120):
            raise ValueError("public development physical caps are incomplete")


@dataclass(frozen=True)
class PublicDevIdentity:
    task_id: str
    run_id: str
    engine_root: Path
    engine_py_sha256: str
    product_src: Path
    product_py_sha256: str
    evaluation_dir: Path
    evaluation_py_sha256: str
    codex_executable: Path
    codex_executable_sha256: str
    codex_model: str
    codex_effort: str
    mongo_url: str
    mongo_database: str
    task_path: Path
    run_dir: Path

    def validate(self) -> None:
        if (not ObjectId.is_valid(self.task_id) or
                not isinstance(self.run_id, str) or not _ID.fullmatch(self.run_id)
                or not isinstance(self.codex_model, str) or not self.codex_model
                or self.codex_effort not in {"low", "medium", "high", "xhigh"}
                or not isinstance(self.mongo_url, str) or not self.mongo_url
                or not isinstance(self.mongo_database, str) or
                not re.fullmatch(r"[A-Za-z0-9_-]+", self.mongo_database)
                or any(not _SHA.fullmatch(value) for value in
                       (self.engine_py_sha256, self.product_py_sha256,
                        self.evaluation_py_sha256))):
            raise ValueError("public development run identity is invalid")
        if (python_tree_sha256(self.engine_root) != self.engine_py_sha256 or
                python_tree_sha256(self.product_src) != self.product_py_sha256 or
                python_tree_sha256(self.evaluation_dir) != self.evaluation_py_sha256):
            raise ValueError("public development Python source identity changed")
        _pinned_file(self.codex_executable, self.codex_executable_sha256,
                     "Codex executable")
        if (not self.task_path.is_absolute() or self.task_path.is_symlink() or
                self.task_path != self.task_path.resolve() or
                not (self.task_path / "repo").is_dir() or
                not self.run_dir.is_absolute() or self.run_dir.is_symlink() or
                self.run_dir != self.run_dir.resolve() or
                self.run_dir.exists() or not self.run_dir.parent.is_dir()):
            raise ValueError("public development workspace is unavailable")


@dataclass
class BoundOriginalPublicDev:
    admission: PinnedAdmission
    identity: PublicDevIdentity
    caps: PublicDevCaps
    server: Any
    executor: Any
    strategy: Any
    model_gate: CampaignModelGate
    process_ledger: Any
    global_campaign: Any
    pov_adapter: Any
    bootstrap_token: object = None

    def recheck(self) -> None:
        """Recheck sources, contract, and binary before any external launch."""
        from vulnerabilityanalysis.official_harness import _qualification_pins_ok
        q = self.admission.qualification
        if (python_tree_sha256(self.identity.engine_root) !=
                    self.identity.engine_py_sha256 or
                python_tree_sha256(self.identity.product_src) !=
                    self.identity.product_py_sha256 or
                python_tree_sha256(self.identity.evaluation_dir) !=
                    self.identity.evaluation_py_sha256 or
                not _qualification_pins_ok(q) or
                self.pov_adapter.binding.pinned_binary()[1] != q.binary_sha256 or
                self.global_campaign.ledger is not self.process_ledger or
                self.global_campaign.campaign.process_envelope.ledger is not
                    self.process_ledger or
                self.model_gate.snapshot()["physical"] > self.caps.physical_model_calls or
                self.process_ledger.snapshot()["stop_status"] is not None):
            raise ValueError("public development authority or budget changed")


def require_journaled_mongo(server: Any, task_id: str) -> None:
    """Require one real writable MongoDB and acknowledge a journaled probe."""
    from fuzzingbrain.db.connection import MongoDB

    db = getattr(getattr(server, "repos", None), "db", None)
    if (not isinstance(db, Database) or db is not MongoDB.get_db() or
            getattr(server, "ready", None) is not True or
            str(getattr(server, "task_id", "")) != task_id):
        raise ValueError("original live path requires one real MongoDB task DB")
    _journaled_mongo_probe(db, task_id)


def _journaled_mongo_probe(db: Database, task_id: str) -> None:
    """Prove journaled writes before the AnalysisServer imports task data."""
    try:
        hello = db.client.admin.command("hello")
        options = db.client.admin.command("getCmdLineOpts")
        journal = options.get("parsed", {}).get("storage", {}).get("journal", {})
        if (hello.get("isWritablePrimary") is not True or
                journal.get("enabled") is False or
                hello.get("msg") == "isdbgrid"):
            raise ValueError("journaled writable MongoDB primary is unavailable")
        collection = db.get_collection("_fbv2_public_dev_admission",
                                       write_concern=WriteConcern(w=1, j=True))
        key = "fbv2-public-dev-" + task_id
        collection.insert_one({"_id": key, "kind": "JOURNALED_ADMISSION_PROBE"})
        deleted = collection.delete_one({"_id": key})
        if deleted.deleted_count != 1:
            raise ValueError("journaled MongoDB deletion was not acknowledged")
    except ValueError:
        raise
    except BaseException as exc:
        raise ValueError("journaled MongoDB admission probe failed") from exc


@contextmanager
def original_analysis_server_session(admission: PinnedAdmission,
                                     identity: PublicDevIdentity):
    """Start the original pinned AnalysisServer on one real MongoDB task DB.

    Its socket server runs in a separate event loop because original MCP code
    uses synchronous AnalysisClient calls. This context starts no model,
    target, or fuzzer.
    """
    from fuzzingbrain.analyzer import AnalysisServer
    from fuzzingbrain.db.connection import MongoDB
    from fuzzingbrain.tools.analyzer import _client_cache, _invalidate_client

    identity.validate()
    if MongoDB.get_db() is not None:
        raise ValueError("original AnalysisServer needs a fresh DB connection")
    db = MongoDB.connect(identity.mongo_url, identity.mongo_database)
    if not isinstance(db, Database):
        MongoDB.close()
        raise ValueError("original live AnalysisServer cannot use mongomock")
    try:
        _journaled_mongo_probe(db, identity.task_id)
    except BaseException:
        MongoDB.close()
        raise
    server = AnalysisServer(
        task_id=identity.task_id, task_path=str(identity.task_path),
        project_name=admission.summary["project_name"], sanitizers=["address"],
        prebuilt_manifest=admission.summary["manifest_path"],
        prebuilt_manifest_sha256=admission.summary["manifest_sha256"])
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever,
                              name="fbv2-public-analysis-server", daemon=True)
    thread.start()
    try:
        result = asyncio.run_coroutine_threadsafe(server.start(), loop).result(timeout=120)
        if not result.success:
            raise RuntimeError("original pinned AnalysisServer did not start")
        require_journaled_mongo(server, identity.task_id)
        yield server
    finally:
        for key in list(_client_cache):
            if key[0] == str(server.socket_path):
                _invalidate_client(key)
        try:
            if server.running:
                asyncio.run_coroutine_threadsafe(server.stop(), loop).result(timeout=20)
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=5)
            loop.close()
            MongoDB.close()


def bind_original_public_dev(admission: PinnedAdmission, identity: PublicDevIdentity,
                             caps: PublicDevCaps, *, server: Any,
                             bootstrap_token: object = None) -> BoundOriginalPublicDev:
    """Bind existing original Worker to one qualified live account, no calls.

    ``server`` must be the ready AnalysisServer for ``identity.task_id`` and
    use the same MongoDB that the original WorkerContext will read. This
    function creates fresh durable budgets but starts no model or target.
    """
    identity.validate()
    caps.validate()
    if (server is None or server.ready is not True or
            str(server.task_id) != identity.task_id or server.repos is None or
            not Path(server.socket_path).is_socket() or
            identity.engine_root != Path(__file__).resolve().parent.parent):
        raise ValueError("original AnalysisServer is not pinned")
    if (admission.summary.get("product_issued") is not True or
            admission.summary.get("binary_sha256") !=
                admission.qualification.binary_sha256 or
            admission.summary.get("manifest_sha256") !=
                hashlib.sha256(Path(server.prebuilt_manifest).read_bytes()).hexdigest() or
            server.task_path != identity.task_path):
        raise ValueError("original AnalysisServer differs from admitted prebuilt task")

    from vulnerabilityanalysis import official_harness
    if Path(official_harness.__file__).resolve().parent.parent != identity.product_src:
        raise ValueError("product qualification module is from another checkout")
    require_journaled_mongo(server, identity.task_id)

    if str(identity.evaluation_dir) not in sys.path:
        sys.path.insert(0, str(identity.evaluation_dir))
    # Pin loaded module locations as well as source trees. A cached shadow
    # module cannot silently replace the product/evaluation implementation.
    for name, expected in (
        ("dev_global_campaign", identity.evaluation_dir / "dev_global_campaign.py"),
        ("dev_accounted_global_campaign",
         identity.evaluation_dir / "dev_accounted_global_campaign.py"),
        ("dev_process_envelope_v2", identity.evaluation_dir / "dev_process_envelope_v2.py"),
        ("dev_persistent_process_ledger_v2",
         identity.evaluation_dir / "dev_persistent_process_ledger_v2.py"),
    ):
        module = importlib.import_module(name)
        if Path(getattr(module, "__file__", "")).resolve() != expected:
            raise ValueError(f"loaded evaluation module changed: {name}")
    from dev_global_campaign import DevGlobalCampaign
    from dev_accounted_global_campaign import AccountedGlobalCampaign
    from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
    from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
    from devtools.product_qualified_runtime import ProductQualifiedPoVAdapter
    from vulnerabilityanalysis.official_harness import _qualification_pins_ok
    if not _qualification_pins_ok(admission.qualification):
        raise ValueError("product-issued qualification changed")
    # The Global helper hard-pins its own product path. A different checkout
    # is not eligible for this public development launcher.
    global_module = sys.modules["dev_global_campaign"]
    if Path(global_module.PRODUCT_SRC) != identity.product_src:
        raise ValueError("Global campaign product checkout differs")
    if (python_tree_sha256(identity.engine_root) != identity.engine_py_sha256 or
            python_tree_sha256(identity.product_src) != identity.product_py_sha256 or
            python_tree_sha256(identity.evaluation_dir) != identity.evaluation_py_sha256):
        raise ValueError("Python source identity changed during import")

    root = identity.run_dir
    root.mkdir(mode=0o700)
    (root / "model_events").mkdir(mode=0o700)
    model_gate = CampaignModelGate(root / "model-ledger.json", identity.run_id,
                                   caps.physical_model_calls,
                                   caps.model_wall_seconds, create=True)
    process_ledger = PersistentProcessLedgerV2.create(
        root / "process-ledger.json",
        wall_total_seconds=caps.total_wall_seconds,
        fuzz_total_seconds=caps.total_fuzz_seconds)

    def pin_hook(_phase: str, _command: list[str]) -> None:
        if (python_tree_sha256(identity.engine_root) != identity.engine_py_sha256 or
                python_tree_sha256(identity.product_src) != identity.product_py_sha256 or
                python_tree_sha256(identity.evaluation_dir) != identity.evaluation_py_sha256 or
                not _qualification_pins_ok(admission.qualification)):
            raise ValueError("public development process pin changed")

    envelope = DevelopmentProcessEnvelopeV2(
        process_ledger, work_item_id=identity.task_id,
        assertion_id="GLOBAL", attempt_id=identity.run_id,
        output_limit_bytes=caps.process_output_limit_bytes,
        total_wall_seconds=caps.total_wall_seconds, pin_hook=pin_hook)
    base_campaign = DevGlobalCampaign(
        root, admission.qualification,
        total_fuzz_seconds=caps.total_fuzz_seconds,
        global_seconds=caps.global_fuzz_seconds,
        global_wall_reservation_seconds=caps.global_reservation_seconds,
        replay_limit=caps.global_replay_limit,
        process_envelope=envelope, require_accounted_consumer=True)
    campaign = AccountedGlobalCampaign(
        base_campaign, process_ledger,
        reservation_key=f"GLOBAL_FUZZ:{identity.task_id}:{identity.run_id}")
    adapter = ProductQualifiedPoVAdapter(
        qualification=admission.qualification, repos=server.repos,
        task_id=identity.task_id, work_item_id=identity.task_id,
        run_id=identity.run_id, fuzzer=admission.prepared["fuzzer_name"],
        sanitizer="address", ledger=process_ledger,
        output_dir=root / "pov-runtime",
        timeout_seconds=caps.pov_timeout_seconds,
        wall_seconds=caps.pov_wall_seconds,
        output_limit_bytes=caps.process_output_limit_bytes)
    client_factory = product_campaign_client_factory(
        model_gate, cwd=identity.task_path, codex_model=identity.codex_model,
        max_calls_per_agent=caps.calls_per_agent,
        executable=str(identity.codex_executable),
        executable_sha256=identity.codex_executable_sha256,
        event_log_dir=root / "model_events", effort=identity.codex_effort)

    def global_factory(plan_path: Path, plan_sha256: str) -> OriginalGlobalBridge:
        pin_hook("before_global_bridge", [])
        return OriginalGlobalBridge(
            campaign=campaign, direction_plan_path=plan_path,
            direction_plan_sha256=plan_sha256,
            seed_spool=root / "direction-seeds",
            expected_binary_sha256=admission.qualification.binary_sha256,
            model_gate=model_gate)

    executor, strategy = build_provider_free_executor(
        admission, workspace=root / "worker", task_path=identity.task_path,
        repos=server.repos, task_id=identity.task_id,
        llm_client_factory=client_factory,
        original_global_bridge_factory=global_factory,
        qualified_pov_runtime_binding=adapter.binding,
        analysis_socket_path=str(server.socket_path))
    bound = BoundOriginalPublicDev(admission, identity, caps, server, executor,
                                   strategy, model_gate, process_ledger,
                                   campaign, adapter, bootstrap_token)
    bound.recheck()
    return bound


def _run_qualified_sp_fuzz_after_worker(
        bound: BoundOriginalPublicDev,
        pov_lineage_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Offer one completed model PoV to the opt-in product SP Fuzzer.

    This post-Worker path is deliberately separate from FBv2's original
    concurrent Docker SP Fuzzer. No eligible input means no physical launch.
    """
    if bound.caps.sp_fuzz_max_items == 0:
        return {"status": "DISABLED", "automatic_discovery": False}
    if (bound.caps.sp_fuzz_max_items != 1 or
            not 1 <= bound.caps.sp_fuzz_seconds <= 10):
        raise ValueError("SP Fuzzer opt-in cap changed")
    eligible = []
    for row in pov_lineage_rows:
        candidate = row.get("candidate_lineage")
        runtime = row.get("runtime_lineage")
        if (type(candidate) is dict and type(runtime) is dict and
                candidate.get("status") == "VERIFIED" and
                runtime.get("status") == "VERIFIED" and
                runtime.get("runtime_status") == "NO_CRASH" and
                candidate.get("task_id") == runtime.get("task_id") ==
                    bound.identity.task_id and
                candidate.get("campaign_id") == runtime.get("run_id") ==
                    bound.identity.run_id and
                candidate.get("sp_id") == runtime.get("sp_id") and
                row.get("pov_id") == runtime.get("pov_id")):
            eligible.append(row["pov_id"])
    if not eligible:
        return {"status": "SKIPPED_NO_ELIGIBLE_MODEL_POV",
                "automatic_discovery": False}
    from devtools.product_qualified_runtime import run_qualified_sp_fuzz
    return run_qualified_sp_fuzz(
        bound.pov_adapter, sorted(eligible)[0], bound.model_gate,
        recheck=bound.recheck, seconds=bound.caps.sp_fuzz_seconds,
        fuzz_wall_seconds=bound.caps.sp_fuzz_seconds + 39.0,
        replay_wall_seconds=min(
            600.0, bound.caps.gate_aux_reservation_seconds_per_observation),
        replay_limit=1)


def run_original_public_dev(bound: BoundOriginalPublicDev, *,
                            explicit_public_dev_authorization: bool) -> dict:
    """Enter the original Worker only from a pinned fresh public-dev process.

    The return is execution accounting, never a vulnerability verdict. The
    existing product Gate alone can make that decision for consumed crashes.
    """
    if explicit_public_dev_authorization is not True:
        raise ValueError("explicit public development authorization required")
    main = sys.modules.get("__main__")
    entry = Path(__file__).resolve().parent / "original_public_live_entry.py"
    marker = getattr(main, "_PINNED_PUBLIC_BOOTSTRAP", None)
    if (not _isolated_runtime() or
            Path(getattr(main, "__file__", "")).resolve() != entry or
            Path(sys.argv[0]).resolve() != entry or
            ("--authorize-public-dev" not in sys.argv and
             "--authorize-public-dev-hp" not in sys.argv) or
            type(marker) is not dict or
            marker.get("hp_mode", False) is not
                ("--authorize-public-dev-hp" in sys.argv) or
            marker.get("pid") != os.getpid() or
            marker.get("used") is not False or
            bound.bootstrap_token is None or
            marker.get("token") is not bound.bootstrap_token or
            not isinstance(marker.get("spec_path"), str) or
            not isinstance(marker.get("spec_sha256"), str) or
            marker.get("engine_py_sha256") != bound.identity.engine_py_sha256 or
            marker.get("product_py_sha256") != bound.identity.product_py_sha256 or
            marker.get("evaluation_py_sha256") !=
                bound.identity.evaluation_py_sha256):
        raise RuntimeError("fresh-interpreter source admission is required")
    _pinned_file(Path(marker["spec_path"]), marker["spec_sha256"],
                 "public development launch spec")
    marker["used"] = True
    bound.recheck()
    require_journaled_mongo(bound.server, bound.identity.task_id)
    if (bound.executor.task_id != bound.identity.task_id or
            bound.executor.repos is not bound.server.repos or
            bound.executor._get_strategy().executor is not bound.executor):
        raise ValueError("original Worker task/DB identity changed")
    from fuzzingbrain.tools.analyzer import set_analyzer_context
    from fuzzingbrain.tools.code_viewer import set_code_viewer_context
    set_analyzer_context(str(bound.server.socket_path), client_id="public_dev_original")
    set_code_viewer_context(str(bound.identity.task_path), repo_subdir="repo",
                            project_name=bound.admission.summary["project_name"])
    from fuzzingbrain.worker.pipeline import IncompleteInjectedAgent
    worker_pending_reason = None
    try:
        result = bound.executor.run()
    except IncompleteInjectedAgent as exc:
        # The original Pipeline deliberately raises after a qualified PoV
        # crash until independent validation consumes the retained input.
        # Every other incomplete reason remains a hard stop.
        if exc.reason != "validation_pending":
            raise
        context = getattr(bound.executor, "_worker_context", None)
        worker_id = getattr(context, "worker_id", None)
        if not isinstance(worker_id, str) or not ObjectId.is_valid(worker_id):
            raise
        worker_pending_reason = exc.reason
        result = {"worker_id": worker_id,
                  "status": "PENDING_INDEPENDENT_VALIDATION",
                  "incomplete_reason": exc.reason}
    # The original create_pov tool executes the Target before its host-tool
    # result is audited. Reconcile model/tool/DB/Runtime lineage only after the
    # Worker returns. Provenance alone never grants discovery or Gate credit.
    from devtools.model_candidate_lineage import find_candidate_lineage
    from devtools.product_qualified_runtime import (
        _json_new, verify_qualified_pov_runtime_lineage)
    pov_lineage_rows = []
    for path in sorted(bound.pov_adapter.root.glob("*/runtime.json")):
        pov_id = path.parent.name
        candidate = find_candidate_lineage(
            bound.model_gate, bound.server.repos,
            task_id=bound.identity.task_id, pov_id=pov_id)
        runtime_lineage = verify_qualified_pov_runtime_lineage(
            bound.pov_adapter, pov_id, bound.model_gate, recheck=bound.recheck)
        pov_lineage_rows.append({
            "pov_id": pov_id, "candidate_lineage": candidate,
            "runtime_lineage": runtime_lineage,
            "automatic_discovery": False,
        })
    lineage_path = bound.identity.run_dir / "pov-lineage.json"
    lineage_sha256 = _json_new(lineage_path, {
        "kind": "FBV2_PUBLIC_DEV_POV_LINEAGE_V1",
        "task_id": bound.identity.task_id, "run_id": bound.identity.run_id,
        "rows": pov_lineage_rows,
    })
    sp_fuzz_result = _run_qualified_sp_fuzz_after_worker(bound, pov_lineage_rows)
    # An original PoV Runtime crash is only an observation. Consume its saved
    # input through the product's independent path with the same physical
    # ledger; this never changes the original FBv2 SP/PoV verdict.
    from devtools.product_qualified_runtime import consume_qualified_pov_observation
    observed_pov_ids = []
    for path in sorted(bound.pov_adapter.root.glob("*/runtime.json")):
        if json.loads(path.read_text(encoding="utf-8")).get("status") == "CRASH_OBSERVED":
            observed_pov_ids.append(path.parent.name)
    pov_gate_rows = []
    for pov_id in observed_pov_ids:
        try:
            pov_gate_rows.append(consume_qualified_pov_observation(
                bound.pov_adapter, pov_id, recheck=bound.recheck,
                timeout_seconds=min(10.0, bound.caps.pov_timeout_seconds),
                model_gate=bound.model_gate))
        except Exception as exc:
            pov_gate_rows.append({"pov_id": pov_id, "product_gate_status":
                                  "INCOMPLETE_CONSUMPTION", "error_type": type(exc).__name__})
            break  # An uncertain physical attempt cannot admit another replay.
    pending_claim_incomplete = False
    if worker_pending_reason is not None:
        # One observed crash cannot stand in for another SP's missing PoV.
        # The original Pipeline persists every pending input ID before it
        # raises validation_pending; compare that DB set to saved runtimes.
        pending_rows = list(bound.server.repos.suspicious_points.collection.find(
            {"task_id": ObjectId(bound.identity.task_id),
             "status": "pending_independent_validation"},
            {"pending_pov_ids": 1}))
        pending_ids = []
        for row in pending_rows:
            ids = row.get("pending_pov_ids")
            if (type(ids) is not list or not ids or
                    any(type(value) is not str or not ObjectId.is_valid(value)
                        for value in ids)):
                pending_claim_incomplete = True
                break
            pending_ids.extend(ids)
        if (not pending_rows or not pending_ids or
                len(pending_ids) != len(set(pending_ids)) or
                not set(pending_ids).issubset(set(observed_pov_ids))):
            pending_claim_incomplete = True
    # Re-read the one durable process account after all original roles and
    # Global settlement. An earlier Global "RAN" receipt cannot override a
    # concurrent PoV/consumer STOPPED status.
    process, process_receipt_sha256 = bound.process_ledger.receipt_snapshot()
    model = bound.model_gate.snapshot()
    if process["stop_status"] is None and not process["active"]:
        bound.recheck()
    global_status = (bound.global_campaign.final_result or {}).get("status")
    global_receipt = bound.global_campaign.final_result or {}
    global_consumer_rows = global_receipt.get("consumer_rows", [])
    if type(global_consumer_rows) is not list:
        raise ValueError("Global consumer rows changed")
    qualification = getattr(bound.admission, "qualification", None)
    global_run_dir = getattr(
        getattr(bound.global_campaign, "campaign", None), "run_dir", None)
    pending_global_crashes = pending_global_crash_count(
        global_receipt, run_dir=global_run_dir,
        expected_binary_sha256=getattr(qualification, "binary_sha256", None))
    incomplete_global = (global_status not in {"RAN", "SKIPPED_NO_SEED"}
                         and not _settled_crash_observation(global_receipt))
    # An unrelated pending Crash must not hide an independently checked
    # VERIFIED row. A malformed campaign identity still makes every row
    # untrusted, and a status label alone never grants this count.
    global_bound = _bound_global_consumer_evidence(
        global_receipt, global_run_dir,
        getattr(qualification, "binary_sha256", None))
    global_consumer_verified = 0
    if global_bound is not None:
        global_report, global_observed, bound_rows, _raw_result = global_bound
        global_consumer_verified = sum(
            row.get("status") == "VERIFIED" and
            _consumer_row_terminal(
                row, global_run_dir, global_report,
                global_observed[row["crash_id"]])
            for row in bound_rows)
    global_verified_mutation_rows = verified_global_mutation_rows(
        global_receipt, run_dir=global_run_dir,
        expected_binary_sha256=getattr(qualification, "binary_sha256", None))
    model_lineage_gate_verified_pov_ids = _model_lineage_gate_verified_pov_ids(
        bound.identity.run_dir, pov_lineage_rows, pov_gate_rows)
    verified_pov_ids = {row["pov_id"] for row in pov_gate_rows
                        if row.get("product_gate_status") == "VERIFIED"}
    pending_pov_crashes = sum(pov_id not in verified_pov_ids
                              for pov_id in observed_pov_ids)
    execution_incomplete = (
        process["stop_status"] is not None or bool(process["active"])
        or incomplete_model_activity(model, bound.model_gate)
        or incomplete_global or pending_claim_incomplete
        or sp_fuzz_result.get("status") in {
            "INCOMPLETE", "INCOMPLETE_FUZZ_WITH_OBSERVED_CRASH"})
    verification_pending = (pending_global_crashes > 0 or
                            pending_pov_crashes > 0 or any(
                      row.get("product_gate_status") == "INCOMPLETE_CONSUMPTION"
                      for row in pov_gate_rows) or
                            sp_fuzz_result.get("status") in {
                                "PENDING_INDEPENDENT_VALIDATION",
                                "INCOMPLETE_FUZZ_WITH_OBSERVED_CRASH"})
    incomplete = execution_incomplete or verification_pending
    return {
        "kind": "FBV2_PUBLIC_DEV_ORIGINAL_RESULT_V1",
        "status": "INCOMPLETE" if incomplete else "EXECUTED_UNVERIFIED",
        "execution_status": "INCOMPLETE" if execution_incomplete else "EXECUTED",
        "verification_status": ("PENDING_INDEPENDENT_VALIDATION"
                                if verification_pending else
                                "MODEL_POV_PRODUCT_GATE_VERIFIED_DISCOVERY_UNPROVEN"
                                if model_lineage_gate_verified_pov_ids else
                                "PRODUCT_CONSUMER_VERIFIED_ORIGIN_UNPROVEN"
                                if global_consumer_verified else
                                "NO_PENDING_OBSERVATION"),
        "pov_crashes_pending_independent_validation": pending_pov_crashes,
        "pov_product_gate_rows": pov_gate_rows,
        "pov_lineage_rows": pov_lineage_rows,
        "sp_fuzz_result": sp_fuzz_result,
        "model_lineage_gate_verified_pov_ids": model_lineage_gate_verified_pov_ids,
        "model_lineage_gate_verified_pov_count": len(
            model_lineage_gate_verified_pov_ids),
        "automatic_discovery_verified_count": 0,
        "pov_lineage_receipt_path": str(lineage_path),
        "pov_lineage_receipt_sha256": lineage_sha256,
        "pending_global_crashes": pending_global_crashes,
        "global_consumer_rows": global_consumer_rows,
        "global_consumer_verified_count": global_consumer_verified,
        "global_verified_mutation_rows": global_verified_mutation_rows,
        "global_discovery_credit": "NOT_CREDITED_ORIGIN_UNPROVEN",
        "task_id": bound.identity.task_id, "run_id": bound.identity.run_id,
        "model_physical_calls": model["physical"],
        "process_wall_seconds": process["wall_spent_seconds"],
        "process_fuzz_seconds": process["fuzz_spent_seconds"],
        "process_stop_status": process["stop_status"],
        "process_receipt_sha256": process_receipt_sha256,
        "process_ledger_revision": process["revision"],
        "global_status": global_status,
        "original_worker_status": ("PENDING_INDEPENDENT_VALIDATION"
                                   if worker_pending_reason else "COMPLETED"),
        "original_result": result,
    }
