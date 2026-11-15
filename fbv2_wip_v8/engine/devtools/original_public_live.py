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
import shutil
import signal
import stat
import sys
import threading
from typing import Any

from bson import ObjectId
from pymongo.database import Database
from pymongo.write_concern import WriteConcern
import yaml

from devtools.campaign_model_gate import (
    CampaignModelGate, product_campaign_client_factory)
from devtools.original_global_bridge import (
    MAX_STAGED_SEEDS, OriginalGlobalBridge, _settled_crash_observation)
from devtools.original_public_dev import PinnedAdmission, build_provider_free_executor


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_FBV2_PRODUCT_MODEL_ROLES = {
    "direction": "direction_generator",
    # The preserved role plan assigns both normal Seed and SP generation to
    # the lightweight generation tier.  Keep Seed on that tier even when the
    # Direction planner is promoted after a format failure.
    "seed": "sp_generation",
    "sp": "sp_generation",
    "sp_large": "sp_generation",
    "verifier": "sp_verifier",
    "pov": "poc_generator",
    "function_analysis": "function_analysis",
    "assertion_generator": "assertion_generator",
}
_MODEL_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})
FULL_NOHINT_SP_ITERATION_POLICY = {
    "kind": "LINE_SCALED_V1",
    "up_to_100": 8,
    "up_to_250": 12,
    "up_to_500": 24,
    "up_to_1000": 32,
    "up_to_2000": 40,
    "large_window_lines": 100,
    "large_window_overlap": 20,
    "large_base": 8,
    "large_turns_per_window": 2,
    "large_max": 64,
}


def validate_sp_iteration_policy(policy: dict[str, Any] | None) -> bool:
    """Validate a signed, line-scaled FullScan ceiling without launching work."""
    if (type(policy) is not dict or
            set(policy) != set(FULL_NOHINT_SP_ITERATION_POLICY) or
            policy.get("kind") != "LINE_SCALED_V1"):
        return False
    integer_keys = set(policy) - {"kind"}
    if any(type(policy[key]) is not int or not 1 <= policy[key] <= 128
           for key in integer_keys):
        return False
    limits = [policy[key] for key in (
        "up_to_100", "up_to_250", "up_to_500", "up_to_1000", "up_to_2000")]
    return (limits == sorted(limits) and
            policy["large_window_overlap"] < policy["large_window_lines"] and
            policy["large_max"] >= policy["up_to_2000"] and
            policy["large_base"] < policy["large_max"])


def product_fbv2_role_models(product_src: Path) -> tuple[dict[str, dict[str, str]], str]:
    """Read the product's existing Codex-equivalent role profile and pin it."""
    product_src = Path(product_src)
    config = product_src.parent / "config" / "default.yaml"
    if (not config.is_absolute() or config.is_symlink() or
            config != config.resolve() or not config.is_file()):
        raise ValueError("product role model configuration is unavailable")
    raw = config.read_bytes()
    try:
        parsed = yaml.safe_load(raw)
        models = parsed["models"]
        selected = {
            fbv2_role: dict(models[product_role])
            for fbv2_role, product_role in _FBV2_PRODUCT_MODEL_ROLES.items()
        }
    except (KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        raise ValueError("product role model configuration is invalid") from exc
    if (set(selected) != set(_FBV2_PRODUCT_MODEL_ROLES) or
            any(type(row) is not dict or set(row) != {"model", "reasoning"} or
                not isinstance(row["model"], str) or not row["model"] or
                row["reasoning"] not in _MODEL_EFFORTS
                for row in selected.values())):
        raise ValueError("product role model configuration is invalid")
    return selected, hashlib.sha256(raw).hexdigest()


def _isolated_runtime() -> bool:
    return sys.flags.isolated == 1 and sys.flags.no_site == 1


def _complete_runtime_tree_paths(root: Path) -> list[Path]:
    """Enumerate every runtime node without pathlib/glob error suppression."""
    def failed(error: OSError) -> None:
        raise error

    rows: list[Path] = []
    root_info = root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or
            stat.S_IMODE(root_info.st_mode) & (stat.S_IRUSR | stat.S_IXUSR) !=
            (stat.S_IRUSR | stat.S_IXUSR)):
        raise ValueError("Python source root is not owner-readable")
    for current, directories, files in os.walk(
            root, followlinks=False, onerror=failed):
        for name in sorted([*directories, *files]):
            path = Path(current) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("Python source tree contains a linked entry")
            if stat.S_ISDIR(info.st_mode):
                if (stat.S_IMODE(info.st_mode) &
                        (stat.S_IRUSR | stat.S_IXUSR) !=
                        (stat.S_IRUSR | stat.S_IXUSR)):
                    raise ValueError("Python source tree is not completely readable")
            elif stat.S_ISREG(info.st_mode):
                if stat.S_IMODE(info.st_mode) & stat.S_IRUSR != stat.S_IRUSR:
                    raise ValueError("Python source tree is not completely readable")
            else:
                raise ValueError("Python source tree contains a special entry")
            rows.append(path)
    return rows


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


def _authenticated_terminal_gate_pov_ids(
        identity: Any, gate_rows: list[dict[str, Any]], observed_pov_ids: list[str],
        verified_pov_ids: set[str], finished_rows: Any) -> set[str]:
    """PoV crashes whose product Gate rejection is proven conclusive."""
    from devtools.product_qualified_runtime import (
        POV_GATE_OUTCOME_KIND, verify_terminal_pov_gate)

    if type(gate_rows) is not list or any(type(row) is not dict for row in gate_rows):
        return set()
    ids = [row.get("pov_id") for row in gate_rows]
    run_dir = identity.run_dir
    terminal = set()
    for row in gate_rows:
        pov_id = row.get("pov_id")
        if (type(pov_id) is not str or not ObjectId.is_valid(pov_id) or
                ids.count(pov_id) != 1 or pov_id not in observed_pov_ids or
                pov_id in verified_pov_ids or
                row.get("kind") != POV_GATE_OUTCOME_KIND or
                row.get("gate_resolution") != "TERMINAL_REJECTED" or
                row.get("task_id") != identity.task_id or
                row.get("run_id") != identity.run_id):
            continue
        claim_dir = run_dir / "pov-validation" / pov_id
        if _plain_run_json(run_dir, claim_dir / "outcome.json") != row:
            continue
        if verify_terminal_pov_gate(row, claim_dir=claim_dir,
                                    finished_rows=finished_rows) is None:
            terminal.add(pov_id)
    return terminal


def _authenticated_verified_gate_pov_ids(
        identity: Any, gate_rows: list[dict[str, Any]], observed_pov_ids: list[str],
        finished_rows: Any) -> set[str]:
    """PoV crashes whose product Gate VERIFIED outcome is re-proven (Goal A.1.2).

    A ``VERIFIED`` label alone is not counted: the row must be the durable,
    identity-bound outcome and the replay identity (crash fingerprints,
    signature, pinned environment, clean process receipts) must be re-proven
    from hash-bound artifacts. Anything else stays pending.
    """
    from devtools.product_qualified_runtime import (
        POV_GATE_OUTCOME_KIND, verify_verified_pov_gate)

    if type(gate_rows) is not list or any(type(row) is not dict for row in gate_rows):
        return set()
    ids = [row.get("pov_id") for row in gate_rows]
    run_dir = identity.run_dir
    verified = set()
    for row in gate_rows:
        pov_id = row.get("pov_id")
        if (type(pov_id) is not str or not ObjectId.is_valid(pov_id) or
                ids.count(pov_id) != 1 or pov_id not in observed_pov_ids or
                row.get("kind") != POV_GATE_OUTCOME_KIND or
                row.get("product_gate_status") != "VERIFIED" or
                row.get("gate_resolution") != "VERIFIED" or
                row.get("task_id") != identity.task_id or
                row.get("run_id") != identity.run_id):
            continue
        claim_dir = run_dir / "pov-validation" / pov_id
        if _plain_run_json(run_dir, claim_dir / "outcome.json") != row:
            continue
        if verify_verified_pov_gate(row, claim_dir=claim_dir,
                                    finished_rows=finished_rows) is None:
            verified.add(pov_id)
    return verified


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


def _conclusive_global_non_target(status: str, runtime: dict[str, Any]) -> bool:
    """Goal A.1b: a Global consumer replay settles only when conclusive.

    Structured fields are recomputed from the saved stderr; nothing is
    inferred from a status label.
    """
    from vulnerabilityanalysis.final_verification import (
        _first_application_frame_symbolized, completed_asan_crash)
    from vulnerabilityanalysis.models import RuntimeResult
    from vulnerabilityanalysis.runtime import classify_runtime, parse_sanitizer

    try:
        result = RuntimeResult(**{
            "stdout": "", "failure_classification": "", **runtime})
        stderr = result.stderr
        if type(stderr) is not str:
            return False
        if status == "ORIGINAL_REPLAY_NOT_REPRODUCED":
            return (result.timed_out is False and result.exit_code == 0 and
                    result.signal is None and not result.sanitizer and
                    parse_sanitizer(stderr) is None and
                    classify_runtime(0, stderr, target_reached=None, sp_reached=None,
                                     timed_out=False) == "UNKNOWN")
        # BLOCKED_NON_TARGET_CRASH: only a fatal ASan report positively
        # attributed to the qualified harness, symbolized up to that frame.
        return (type(result.crash_triage) is dict and
                result.crash_triage.get("category") == "HARNESS_CRASH" and
                completed_asan_crash(result) and
                _first_application_frame_symbolized(stderr))
    except Exception:  # malformed saved runtime: stay pending
        return False


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
    # Goal A.1b: only a completed, conclusive replay settles a Global crash.
    # A signal kill (OOM/envelope), a non-zero exit without an oracle (loader
    # or ASan init failure), or an unattributed sanitizer report stays pending.
    if row["status"] in {"ORIGINAL_REPLAY_NOT_REPRODUCED", "BLOCKED_NON_TARGET_CRASH"}:
        return _conclusive_global_non_target(row["status"], runtime)
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
        # BLOCKED_SECURITY_PROPERTY / BLOCKED_VERIFIED_GATE: the security
        # property or promotion step has no per-step physical completion proof
        # (an official Harness validation can return None after a timeout), so
        # the crash stays pending, as on the PoV Gate path.
        return False
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
    from devtools.product_qualified_runtime import verified_fuzzer_consumer_evidence
    return verified_fuzzer_consumer_evidence(run_dir, outcome)


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
    all_paths = _complete_runtime_tree_paths(root)
    for path in all_paths:
        if not path.is_file():
            continue
        lower = path.name.lower()
        if (lower.endswith((".so", ".pyd", ".dll", ".dylib", ".pyo")) or
                (lower.endswith(".pyc") and path.parent.name != "__pycache__")):
            raise ValueError("Python source tree contains unsigned importable bytes")
    files = sorted(path for path in all_paths
                   if path.is_file() and path.suffix == ".py")
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


GLOBAL_INTERFACE_PROBE_WALL_SECONDS = 5.0
GLOBAL_FUZZ_SUBPROCESS_SLACK_SECONDS = 15.0
GLOBAL_REPORT_SETTLEMENT_WALL_SECONDS = 5.0
GLOBAL_GUARD_CLEANUP_ENVELOPE_SECONDS = 12.5
SP_FUZZ_FUZZ_OVERHEAD_SECONDS = 24.5
SP_FUZZ_WALL_OVERHEAD_SECONDS = 39.0


def required_global_worker_wall_reservation(global_fuzz_seconds: int) -> float:
    """Return the worker envelope before outer guard cleanup.

    The product performs one bounded interface probe, supervises libFuzzer for
    the signed campaign plus subprocess slack, and must still serialize the
    corpus/report before the worker exits.  The outer guard cleanup is not
    worker time and is added by :func:`required_global_wall_reservation`.
    """
    if type(global_fuzz_seconds) is not int or global_fuzz_seconds < 1:
        raise ValueError("Global fuzz seconds must be a positive integer")
    return (float(global_fuzz_seconds) +
            GLOBAL_INTERFACE_PROBE_WALL_SECONDS +
            GLOBAL_FUZZ_SUBPROCESS_SLACK_SECONDS +
            GLOBAL_REPORT_SETTLEMENT_WALL_SECONDS)


def required_global_wall_reservation(global_fuzz_seconds: int) -> float:
    """Return the complete physical envelope for one Global campaign.

    The worker probes the libFuzzer interface before starting the bounded
    campaign.  ``fuzz_locally`` then supervises that campaign for the signed
    fuzz duration plus its own subprocess slack, and the outer guard retains a
    separate cleanup envelope.  Reserving only fuzz time plus cleanup can kill
    a healthy worker before it publishes its terminal report.
    """
    return (required_global_worker_wall_reservation(global_fuzz_seconds) +
            GLOBAL_GUARD_CLEANUP_ENVELOPE_SECONDS)


def required_sp_fuzz_fuzz_reservation(sp_fuzz_seconds: int,
                                      sp_fuzz_max_items: int) -> float:
    """Return cumulative physical fuzz seconds for bounded SP fuzzing."""
    if (type(sp_fuzz_seconds) is not int or
            type(sp_fuzz_max_items) is not int or
            not ((sp_fuzz_seconds == 0 and sp_fuzz_max_items == 0) or
                 (1 <= sp_fuzz_seconds <= 10 and sp_fuzz_max_items == 1))):
        raise ValueError("invalid SP fuzz reservation")
    return float(sp_fuzz_max_items *
                 (sp_fuzz_seconds + SP_FUZZ_FUZZ_OVERHEAD_SECONDS))


def required_sp_fuzz_wall_reservation(
    sp_fuzz_seconds: int,
    sp_fuzz_max_items: int,
    gate_aux_reservation_seconds_per_observation: float,
) -> float:
    """Return the sequential wall envelope for bounded SP fuzz + consumer."""
    # Reuse the same shape guard as the physical fuzz reservation and keep the
    # independent Gate consumer explicit: it is wall time, not fuzz time.
    required_sp_fuzz_fuzz_reservation(
        sp_fuzz_seconds, sp_fuzz_max_items)
    if (type(gate_aux_reservation_seconds_per_observation) not in (int, float)
            or isinstance(gate_aux_reservation_seconds_per_observation, bool)
            or not math.isfinite(gate_aux_reservation_seconds_per_observation)
            or gate_aux_reservation_seconds_per_observation < 0):
        raise ValueError("invalid SP fuzz Gate wall reservation")
    return float(sp_fuzz_max_items * (
        sp_fuzz_seconds + SP_FUZZ_WALL_OVERHEAD_SECONDS +
        gate_aux_reservation_seconds_per_observation))


def required_total_wall_reservation(
    *,
    model_wall_seconds: float | None,
    global_reservation_seconds: float,
    pov_wall_seconds: float,
    global_replay_limit: int,
    gate_aux_reservation_seconds_per_observation: float,
    sp_fuzz_seconds: int,
    sp_fuzz_max_items: int,
) -> float:
    """Derive the serial public-live wall envelope from physical consumers."""
    if (model_wall_seconds is not None and
            (type(model_wall_seconds) not in (int, float) or
             isinstance(model_wall_seconds, bool) or
             not math.isfinite(model_wall_seconds) or
             model_wall_seconds < 0)):
        raise ValueError("invalid model wall reservation")
    if (type(global_reservation_seconds) not in (int, float) or
            isinstance(global_reservation_seconds, bool) or
            not math.isfinite(global_reservation_seconds) or
            global_reservation_seconds <= 0 or
            type(pov_wall_seconds) not in (int, float) or
            isinstance(pov_wall_seconds, bool) or
            not math.isfinite(pov_wall_seconds) or pov_wall_seconds <= 0 or
            type(global_replay_limit) is not int or global_replay_limit < 1 or
            type(gate_aux_reservation_seconds_per_observation) not in
                (int, float) or
            isinstance(gate_aux_reservation_seconds_per_observation, bool) or
            not math.isfinite(gate_aux_reservation_seconds_per_observation) or
            gate_aux_reservation_seconds_per_observation < 0):
        raise ValueError("invalid total wall reservation input")
    return float(
        (model_wall_seconds or 0) + global_reservation_seconds +
        pov_wall_seconds + global_replay_limit *
        gate_aux_reservation_seconds_per_observation +
        required_sp_fuzz_wall_reservation(
            sp_fuzz_seconds,
            sp_fuzz_max_items,
            gate_aux_reservation_seconds_per_observation,
        )
    )


def required_total_fuzz_reservation(global_fuzz_seconds: int,
                                    sp_fuzz_seconds: int,
                                    sp_fuzz_max_items: int) -> float:
    """Return summed process-seconds even when workers overlap in wall time."""
    return (required_global_wall_reservation(global_fuzz_seconds) +
            required_sp_fuzz_fuzz_reservation(
                sp_fuzz_seconds, sp_fuzz_max_items))


@dataclass(frozen=True)
class PublicDevCaps:
    """Preliminary caps for dependency construction, not a Gate budget.

    Global crash replay can involve several GDB, original, and negative
    control processes per observation. ``global_replay_limit`` is a count,
    not a complete physical wall reservation. The live entry remains closed.
    """
    physical_model_calls: int | None
    model_wall_seconds: float | None
    calls_per_agent: int | None
    total_wall_seconds: float
    total_fuzz_seconds: float
    global_fuzz_seconds: int
    global_reservation_seconds: float
    global_replay_limit: int
    pov_timeout_seconds: float
    pov_wall_seconds: float
    process_output_limit_bytes: int
    # A finite request deadline remains required even when FullScan has no
    # campaign-wide model wall cap.
    model_turn_seconds: float = 300.0
    gate_aux_reservation_seconds_per_observation: float = 600.0
    sp_fuzz_seconds: int = 0
    sp_fuzz_max_items: int = 0
    bounded_nohint_dev: bool = False
    seed_direction_limit: int = 5
    full_nohint_sp: bool = False
    sp_iteration_policy: dict[str, Any] | None = None
    security_invariant_focus: str | None = None
    pov_attempts_per_candidate: int = 20
    sp_start_min_remaining_calls: int | None = None
    sp_start_min_remaining_wall_seconds: float | None = None
    # A signed execution-policy switch, not a role budget. When enabled the
    # existing Mongo-backed Discovery, Verifier, and PoV pools run together;
    # the campaign keeps one shared model/process envelope.
    sp_concurrent_queue: bool = False
    sp_discovery_agents: int = 1
    sp_verify_agents: int = 1
    sp_pov_agents: int = 1
    seed_required_unique: int | None = None

    def validate(self) -> None:
        number = (self.total_wall_seconds,
                  self.total_fuzz_seconds, self.global_reservation_seconds,
                  self.pov_timeout_seconds, self.pov_wall_seconds,
                  self.model_turn_seconds,
                  self.gate_aux_reservation_seconds_per_observation)
        # One SP attempt includes an AUX interface probe (5s + 9.5s cleanup)
        # and a fuzz process (requested seconds + 15s runtime slack + 9.5s
        # cleanup). One SP Crash consumer may then need the existing Gate AUX
        # allowance. All three reserve wall; only the fuzz process reserves
        # fuzz time. This is an admission cap, not a launch instruction.
        try:
            required_wall = required_total_wall_reservation(
                model_wall_seconds=self.model_wall_seconds,
                global_reservation_seconds=self.global_reservation_seconds,
                pov_wall_seconds=self.pov_wall_seconds,
                global_replay_limit=self.global_replay_limit,
                gate_aux_reservation_seconds_per_observation=
                    self.gate_aux_reservation_seconds_per_observation,
                sp_fuzz_seconds=self.sp_fuzz_seconds,
                sp_fuzz_max_items=self.sp_fuzz_max_items,
            )
        except ValueError:
            required_wall = math.inf
        try:
            sp_fuzz_fuzz_reservation = required_sp_fuzz_fuzz_reservation(
                self.sp_fuzz_seconds, self.sp_fuzz_max_items)
        except ValueError:
            sp_fuzz_fuzz_reservation = math.inf
        model_caps = (self.physical_model_calls, self.calls_per_agent,
                      self.model_wall_seconds, self.total_wall_seconds)
        signed_sp_caps = {(80, 32, 1200, 2100),
                          (120, 64, 1500, 2400)}
        full_sp_profile = (
            self.full_nohint_sp is True and
            model_caps[:3] == (None, None, None) and
            type(self.total_wall_seconds) is int and
            self.seed_direction_limit == 5 and
            self.bounded_nohint_dev is False and
            ((self.sp_fuzz_seconds == 0 and self.sp_fuzz_max_items == 0) or
             (1 <= self.sp_fuzz_seconds <= 10 and
              self.sp_fuzz_max_items == 1)))
        sp_start_envelope = (
            self.sp_start_min_remaining_calls,
            self.sp_start_min_remaining_wall_seconds,
        )
        signed_start_envelope = (
            sp_start_envelope != (None, None) and
            type(self.sp_start_min_remaining_calls) is int and
            self.sp_start_min_remaining_calls > 0 and
            type(self.sp_start_min_remaining_wall_seconds) in (int, float) and
            math.isfinite(self.sp_start_min_remaining_wall_seconds) and
            self.sp_start_min_remaining_wall_seconds > 0 and
            self.physical_model_calls is not None and
            self.sp_start_min_remaining_calls <= self.physical_model_calls and
            self.model_wall_seconds is not None and
            self.sp_start_min_remaining_wall_seconds <= self.model_wall_seconds and
            self.seed_direction_limit == 1 and
            self.bounded_nohint_dev is False and
            self.full_nohint_sp is False)
        concurrent_workers = (
            self.sp_discovery_agents,
            self.sp_verify_agents,
            self.sp_pov_agents,
        )
        concurrent_profile = (
            self.sp_concurrent_queue is True and
            self.seed_direction_limit == 1 and
            self.bounded_nohint_dev is False and
            self.full_nohint_sp is False and
            sp_start_envelope == (None, None) and
            model_caps in {(120, 64, 1500, 2400),
                           (None, None, 1500, 2400)} and
            all(type(value) is int and 1 <= value <= 8
                for value in concurrent_workers))
        if ((self.model_wall_seconds is not None and
             (type(self.model_wall_seconds) not in (int, float) or
              not math.isfinite(self.model_wall_seconds) or
              self.model_wall_seconds <= 0)) or
                any(type(value) not in (int, float) or not math.isfinite(value)
                or value <= 0 for value in number) or
                any(type(value) is not int or value < 1 for value in
                    (self.global_fuzz_seconds, self.process_output_limit_bytes)) or
                (not full_sp_profile and not concurrent_profile and
                 any(type(value) is not int or value < 1 for value in
                     (self.physical_model_calls, self.calls_per_agent))) or
                type(self.full_nohint_sp) is not bool or
                type(self.sp_concurrent_queue) is not bool or
                (self.sp_concurrent_queue and
                 (type(self.seed_required_unique) is not int or
                  not 1 <= self.seed_required_unique <= MAX_STAGED_SEEDS)) or
                (not self.sp_concurrent_queue and
                 self.seed_required_unique is not None) or
                (self.sp_concurrent_queue and not concurrent_profile) or
                (not self.sp_concurrent_queue and
                 concurrent_workers != (1, 1, 1)) or
                (self.full_nohint_sp and not full_sp_profile) or
                (self.full_nohint_sp and
                 not validate_sp_iteration_policy(self.sp_iteration_policy)) or
                (not self.full_nohint_sp and self.sp_iteration_policy is not None) or
                type(self.global_replay_limit) is not int or
                self.global_replay_limit < 1 or
                type(self.sp_fuzz_seconds) is not int or
                type(self.sp_fuzz_max_items) is not int or
                not ((self.sp_fuzz_seconds == 0 and self.sp_fuzz_max_items == 0)
                     or (1 <= self.sp_fuzz_seconds <= 10 and
                         self.sp_fuzz_max_items == 1)) or
                self.gate_aux_reservation_seconds_per_observation < 600 or
                self.gate_aux_reservation_seconds_per_observation > 3600 or
                self.global_reservation_seconds <
                    required_global_wall_reservation(self.global_fuzz_seconds) or
                self.pov_wall_seconds < self.pov_timeout_seconds + 9.5 or
                self.total_fuzz_seconds < self.global_reservation_seconds or
                self.total_fuzz_seconds < self.global_reservation_seconds +
                    sp_fuzz_fuzz_reservation or
                self.total_wall_seconds < required_wall or
                (not full_sp_profile and self.total_wall_seconds > 3600) or
                self.total_fuzz_seconds > 120 or
                self.global_fuzz_seconds > 60 or
                self.global_replay_limit > 2 or
                type(self.bounded_nohint_dev) is not bool or
                type(self.seed_direction_limit) is not int or
                self.seed_direction_limit not in (1, 5) or
                self.security_invariant_focus not in {
                    None, "BOUNDS_EXTENT", "LIFETIME_OWNERSHIP",
                    "ARITHMETIC_RANGE", "INITIALIZATION", "NULLABILITY",
                    "STATE_CONSISTENCY"} or
                type(self.pov_attempts_per_candidate) is not int or
                not 1 <= self.pov_attempts_per_candidate <= 20 or
                ((sp_start_envelope != (None, None)) != signed_start_envelope) or
                ((self.security_invariant_focus is not None or
                  self.pov_attempts_per_candidate != 20) and
                 self.seed_direction_limit != 1) or
                (self.bounded_nohint_dev and self.seed_direction_limit != 5) or
                (not full_sp_profile and self.bounded_nohint_dev and
                 model_caps not in {
                    (48, 20, 900, 1800),
                    (80, 32, 1200, 2100)}) or
                (not full_sp_profile and not concurrent_profile and
                 not self.bounded_nohint_dev and
                 model_caps not in signed_sp_caps and (
                    self.physical_model_calls > 48 or
                    self.calls_per_agent > 20)) or
                (self.physical_model_calls in (80, 120) and not (
                    (self.bounded_nohint_dev and
                     model_caps == (80, 32, 1200, 2100)) or
                    (not self.bounded_nohint_dev and
                     self.seed_direction_limit == 1 and
                     model_caps in signed_sp_caps))) or
                not 4096 <= self.process_output_limit_bytes <= 16_000_000 or
                self.model_turn_seconds > 1200 or
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
    codex_role_models: dict[str, dict[str, str]] | None = None
    codex_role_models_sha256: str | None = None

    def validate(self) -> None:
        if (not ObjectId.is_valid(self.task_id) or
                not isinstance(self.run_id, str) or not _ID.fullmatch(self.run_id)
                or not isinstance(self.codex_model, str) or not self.codex_model
                or self.codex_effort not in _MODEL_EFFORTS
                or not isinstance(self.mongo_url, str) or not self.mongo_url
                or not isinstance(self.mongo_database, str) or
                not re.fullmatch(r"[A-Za-z0-9_-]+", self.mongo_database)
                or any(not _SHA.fullmatch(value) for value in
                       (self.engine_py_sha256, self.product_py_sha256,
                        self.evaluation_py_sha256))):
            raise ValueError("public development run identity is invalid")
        if ((self.codex_role_models is None) !=
                (self.codex_role_models_sha256 is None)):
            raise ValueError("public development role model identity is incomplete")
        if self.codex_role_models is not None:
            observed, digest = product_fbv2_role_models(self.product_src)
            if (self.codex_role_models != observed or
                    not _SHA.fullmatch(self.codex_role_models_sha256 or "") or
                    self.codex_role_models_sha256 != digest):
                raise ValueError("public development role model identity changed")
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
    qualified_gate_stop: Any = None

    def recheck(self) -> None:
        """Recheck sources, contract, and binary before any external launch."""
        from vulnerabilityanalysis.official_harness import _qualification_pins_ok
        q = self.admission.qualification
        if self.identity.codex_role_models is not None:
            role_models, role_models_sha256 = product_fbv2_role_models(
                self.identity.product_src)
            if (role_models != self.identity.codex_role_models or
                    role_models_sha256 != self.identity.codex_role_models_sha256):
                raise ValueError("public development role model identity changed")
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
                (self.caps.physical_model_calls is not None and
                 self.model_gate.snapshot()["physical"] >
                 self.caps.physical_model_calls) or
                self.process_ledger.snapshot()["stop_status"] is not None):
            raise ValueError("public development authority or budget changed")


@contextmanager
def graceful_public_stop_signals(bound: BoundOriginalPublicDev, *,
                                 grace_seconds: float):
    """Turn the first process stop signal into a cooperative queue drain.

    The handler performs no durable IO. It closes process-local model
    admission, asks the live strategy to stop queueing work, and lets owned
    remote turns finish normally. A second signal is an explicit forced stop.
    """
    if (threading.current_thread() is not threading.main_thread() or
            type(grace_seconds) not in (int, float) or
            not math.isfinite(grace_seconds) or grace_seconds <= 0):
        raise RuntimeError("public stop signals require the main thread")
    previous = {number: signal.getsignal(number)
                for number in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM)}
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    seen = {"count": 0}

    def handle(signum, _frame):
        if signum == signal.SIGALRM:
            raise KeyboardInterrupt("graceful stop drain deadline expired")
        seen["count"] += 1
        if seen["count"] > 1:
            raise KeyboardInterrupt(f"forced stop after signal {signum}")
        bound.model_gate.close_admission(signal.Signals(signum).name)
        bound.executor.graceful_stop_requested = True
        request_stop = getattr(bound.strategy, "request_graceful_stop", None)
        if callable(request_stop):
            request_stop()
        signal.setitimer(signal.ITIMER_REAL, float(grace_seconds))

    try:
        for number in previous:
            signal.signal(number, handle)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        for number, handler in previous.items():
            signal.signal(number, handler)


def _signed_pov_admission_mode(bound: Any) -> str | None:
    """Return the Verifier-to-PoV mode the executed Pipeline actually used.

    An unavailable or unknown mode is passed through as None so that model
    lineage fails closed as UNPROVEN instead of guessing a policy.
    """
    mode = getattr(getattr(bound, "executor", None),
                   "development_pov_admission_mode", None)
    return mode if mode in {"legacy_score", "explicit_disposition"} else None


class QualifiedGateStop:
    """Consume settled model PoV crashes once and signal a verified stop.

    The signal is only an execution decision. Product Gate evidence and model
    lineage remain separate from automatic-discovery credit.
    """

    def __init__(self, bound: BoundOriginalPublicDev) -> None:
        self.bound = bound
        self.verified = threading.Event()
        self._lock = threading.Lock()
        self._rows: dict[str, dict] = {}

    def _settled_local_failure(self, pov_id: str,
                               exc: Exception) -> dict | None:
        """Return a terminal Gate-local receipt, never a shared stop.

        The model PoV claim was already retained before Gate consumption.
        A product-Gate implementation or post-processing failure may therefore
        remain attached to that one crash while unrelated FBv2 work continues,
        but only after the Gate's own physical attempt has settled.  Shared
        budget, pin, cleanup, or ledger stops are deliberately not isolated.
        """
        from vulnerabilityanalysis.runtime import ProcessEnvelopeStop
        try:
            self.bound.recheck()
        except BaseException as pin_exc:
            try:
                self.bound.process_ledger.mark_stop(
                    "STOPPED_PIN_DRIFT",
                    "qualified Gate local-failure pin recheck failed")
            except BaseException as audit_exc:
                pin_exc.add_note(
                    "Gate pin-drift stop receipt failed: " +
                    type(audit_exc).__name__)
            raise ProcessEnvelopeStop(
                "STOPPED_PIN_DRIFT",
                "qualified Gate identity changed during local failure") from pin_exc
        process = self.bound.process_ledger.snapshot()
        if process.get("stop_status") is not None:
            return None
        active = process.get("active")
        if (type(active) is not dict or any(
                f":{pov_id}_gate:" in key for key in active)):
            return None
        path = (self.bound.pov_adapter.root.parent / "pov-validation" /
                pov_id / "incomplete.json")
        try:
            row = _plain_run_json(self.bound.identity.run_dir, path)
        except (OSError, TypeError, ValueError):
            return None
        if (row.get("kind") != "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1" or
                row.get("pov_id") != pov_id or
                row.get("error_type") != type(exc).__name__ or
                row.get("stop_status") is not None or
                row.get("stage") not in {
                    "PRE_EXECUTE_SETUP", "PRODUCT_EXECUTION",
                    "PRODUCT_POSTPROCESS"}):
            return None
        return row

    def _existing_outcome(self, pov_id: str) -> dict | None:
        """Load a product outcome for read-only lineage re-evaluation.

        A completed physical Gate claim is never resent.  If lineage checking
        was interrupted after the outcome file was written, a later call may
        re-read that immutable result and finish only the evidence comparison.
        """
        path = (self.bound.pov_adapter.root.parent / "pov-validation" /
                pov_id / "outcome.json")
        if not path.is_file():
            return None
        row = _plain_run_json(self.bound.identity.run_dir, path)
        if (row.get("kind") != "FBV2_POV_PRODUCT_GATE_OUTCOME_V1" or
                row.get("pov_id") != pov_id):
            raise ValueError("existing qualified Gate outcome identity changed")
        self.bound.recheck()
        return row

    def consume(self, pov_ids: list[str]) -> bool:
        if (type(pov_ids) is not list or not pov_ids or
                len(pov_ids) != len(set(pov_ids)) or
                any(type(value) is not str or not ObjectId.is_valid(value)
                    for value in pov_ids)):
            raise ValueError("qualified Gate input IDs are invalid")
        from devtools.product_qualified_runtime import consume_qualified_pov_observation
        from devtools.product_qualified_runtime import verify_qualified_pov_runtime_lineage
        from devtools.model_candidate_lineage import find_candidate_lineage
        from vulnerabilityanalysis.runtime import ProcessEnvelopeStop

        with self._lock:
            for pov_id in pov_ids:
                if pov_id in self._rows:
                    continue
                try:
                    row = self._existing_outcome(pov_id)
                    if row is None:
                        row = consume_qualified_pov_observation(
                            self.bound.pov_adapter, pov_id,
                            recheck=self.bound.recheck,
                            timeout_seconds=min(
                                10.0, self.bound.caps.pov_timeout_seconds),
                            model_gate=self.bound.model_gate,
                            gate_wall_seconds=self.bound.caps.
                                gate_aux_reservation_seconds_per_observation,
                            pov_admission_mode=_signed_pov_admission_mode(
                                self.bound))
                except ProcessEnvelopeStop as exc:
                    # A Gate's own bounded causal-analysis reservation is not
                    # a campaign-wide physical stop.  Its exclusive claim and
                    # incomplete receipt remain terminal, while unrelated
                    # SP/Verifier/PoV work may continue.  Real shared-ledger
                    # caps, pin drift, cleanup failures, and remote ambiguity
                    # still propagate through their original statuses.
                    if exc.status != "STOPPED_LOCAL_WALL_LIMIT":
                        raise
                    path = (self.bound.pov_adapter.root.parent /
                            "pov-validation" / pov_id / "incomplete.json")
                    row = _plain_run_json(self.bound.identity.run_dir, path)
                    if (row.get("kind") !=
                            "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1" or
                            row.get("pov_id") != pov_id or
                            row.get("stop_status") !=
                            "STOPPED_LOCAL_WALL_LIMIT"):
                        raise ValueError(
                            "qualified Gate local-stop receipt changed") from exc
                except Exception as exc:
                    row = self._settled_local_failure(pov_id, exc)
                    if row is None:
                        raise
                if (type(row) is not dict or row.get("pov_id") != pov_id):
                    raise ValueError("qualified Gate outcome identity changed")
                if (row.get("product_gate_status") == "VERIFIED" and
                        row.get("origin_verification_status") ==
                            "VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE"):
                    # Match the post-Worker proof before stopping a live
                    # FullScan. A status label alone cannot stop the queue.
                    mode = _signed_pov_admission_mode(self.bound)
                    candidate = find_candidate_lineage(
                        self.bound.model_gate, self.bound.server.repos,
                        task_id=self.bound.identity.task_id, pov_id=pov_id,
                        pov_admission_mode=mode)
                    runtime = verify_qualified_pov_runtime_lineage(
                        self.bound.pov_adapter, pov_id,
                        self.bound.model_gate, recheck=self.bound.recheck,
                        pov_admission_mode=mode)
                    if (_model_lineage_gate_verified_pov_ids(
                            self.bound.identity.run_dir,
                            [{"pov_id": pov_id, "candidate_lineage": candidate,
                              "runtime_lineage": runtime,
                              "automatic_discovery": False}], [row]) == [pov_id] and
                            # Goal A.1.2: only a re-proven VERIFIED outcome
                            # may stop the live queue.
                            pov_id in _authenticated_verified_gate_pov_ids(
                                self.bound.identity, [row], [pov_id],
                                self.bound.process_ledger.snapshot().get(
                                    "finished", []))):
                        self.verified.set()
                # Cache only after all validation required for this row has
                # completed. A failed lineage check can therefore be retried
                # read-only from outcome.json without replaying the target.
                self._rows[pov_id] = row
            return self.verified.is_set()

    def retained_row(self, pov_id: str) -> dict | None:
        with self._lock:
            row = self._rows.get(pov_id)
            if row is None:
                return None
            name = ("incomplete.json" if row.get("kind") ==
                    "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1" else "outcome.json")
            path = (self.bound.pov_adapter.root.parent / "pov-validation" /
                    pov_id / name)
            if _plain_run_json(self.bound.identity.run_dir, path) != row:
                raise ValueError("early qualified Gate outcome changed")
            self.bound.recheck()
            return json.loads(json.dumps(row))


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
        prebuilt_manifest_sha256=admission.summary["manifest_sha256"],
        allow_llm_sp_dedup=False)
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


def _bound_seed_pin_hook(source_pin_hook):
    """Freeze Docker identity alongside the existing source/qualification pin."""
    from fuzzingbrain.fuzzer.seed_sandbox import (
        DOCKER_CLI_SHA_ENV, IMAGE_ID_ENV,
    )
    seed_image_id = os.environ.get(IMAGE_ID_ENV, "")
    seed_cli_sha = os.environ.get(DOCKER_CLI_SHA_ENV, "")
    seed_cli_path = shutil.which("docker")
    seed_cli_realpath = os.path.realpath(seed_cli_path) if seed_cli_path else None

    def check(phase: str, command: list[str]) -> None:
        source_pin_hook(phase, command)
        current = shutil.which("docker")
        if (not seed_image_id or not seed_cli_sha or not seed_cli_realpath or
                os.environ.get(IMAGE_ID_ENV, "") != seed_image_id or
                os.environ.get(DOCKER_CLI_SHA_ENV, "") != seed_cli_sha or
                current is None or os.path.realpath(current) != seed_cli_realpath):
            raise ValueError("Direction Seed Docker identity changed")
        try:
            with open(seed_cli_realpath, "rb") as stream:
                actual_sha = hashlib.file_digest(stream, "sha256").hexdigest()
        except OSError as exc:
            raise ValueError("Direction Seed Docker CLI cannot be pinned") from exc
        if actual_sha != seed_cli_sha:
            raise ValueError("Direction Seed Docker CLI identity changed")

    return check


def bind_original_public_dev(admission: PinnedAdmission, identity: PublicDevIdentity,
                             caps: PublicDevCaps, *, server: Any,
                             bootstrap_token: object = None,
                             automatic_sp_function_limit: int | None = None
                             ) -> BoundOriginalPublicDev:
    """Bind existing original Worker to one qualified live account, no calls.

    ``server`` must be the ready AnalysisServer for ``identity.task_id`` and
    use the same MongoDB that the original WorkerContext will read. This
    function creates fresh durable budgets but starts no model or target.
    """
    identity.validate()
    caps.validate()
    if ((caps.bounded_nohint_dev and
         (type(automatic_sp_function_limit) is not int or
          automatic_sp_function_limit not in (1, 3))) or
            (not caps.bounded_nohint_dev and
             automatic_sp_function_limit is not None)):
        raise ValueError("bounded automatic SP function limit is invalid")
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

    # Docker inspect/run/cleanup are charged by the shared process ledger.
    # Freeze its image/CLI identity at binding to reject later drift.
    seed_pin_hook = _bound_seed_pin_hook(pin_hook)

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
        output_limit_bytes=caps.process_output_limit_bytes,
        seed_pin_hook=seed_pin_hook)
    client_factory = product_campaign_client_factory(
        model_gate, cwd=identity.task_path, codex_model=identity.codex_model,
        max_calls_per_agent=caps.calls_per_agent,
        executable=str(identity.codex_executable),
        executable_sha256=identity.codex_executable_sha256,
        event_log_dir=root / "model_events", effort=identity.codex_effort,
        turn_timeout_seconds=caps.model_turn_seconds,
        # Reuse the already signed physical-output byte ceiling for each model
        # JSONL line and the cumulative App Server response stream.  This keeps
        # the new bound inside the existing run contract instead of introducing
        # a target- or incident-specific magic number.
        response_stream_limit_bytes=caps.process_output_limit_bytes,
        parallel_agents=(caps.full_nohint_sp or caps.sp_concurrent_queue),
        role_models=identity.codex_role_models)

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
        qualified_seed_generator=adapter.generate_seed,
        analysis_socket_path=str(server.socket_path))
    if caps.bounded_nohint_dev:
        executor.development_auto_scope = {
            "seed_directions": 2,
            "sp_functions": automatic_sp_function_limit,
            "sp_max_iterations": 7,
        }
        executor.development_process_ledger = process_ledger
        executor.development_run_id = identity.run_id
        strategy._development_auto_scope = executor.development_auto_scope
        strategy.num_parallel_agents = 1
    elif caps.full_nohint_sp:
        # Preserve all five model Directions and full-pool membership. This
        # opt-in run interleaves Directions fairly within each original pool
        # phase. A read-only SP Agent may exhaust its local iteration limit;
        # record that missing opportunity without losing other functions.
        executor.full_nohint_sp = True
        executor.development_process_ledger = process_ledger
        executor.development_run_id = identity.run_id
        executor.development_sp_scope = {
            "kind": "FULL_NOHINT_SP_V1", "status": "FULL_FUNCTION_POOL",
            "function_outcomes": [],
            "sp_iteration_policy": dict(caps.sp_iteration_policy),
        }
        strategy._full_nohint_sp = True
        strategy._development_sp_scope = executor.development_sp_scope
    elif caps.seed_direction_limit == 1:
        # A signed SP diagnostic keeps the original full function pool while
        # draining its candidate queues before the next function takes a turn.
        executor.development_seed_limit = 1
        executor.development_process_ledger = process_ledger
        executor.development_run_id = identity.run_id
        if caps.sp_concurrent_queue:
            # The signed Seed minimum is independent of the prompt's batch
            # size. Count new digest-verified unique files for this Agent.
            executor.development_seed_required_unique = caps.seed_required_unique
        executor.development_sp_queue_drain = not caps.sp_concurrent_queue
        executor.development_sp_concurrent_queue = caps.sp_concurrent_queue
        executor.development_sp_discovery_agents = caps.sp_discovery_agents
        executor.development_sp_verify_agents = caps.sp_verify_agents
        executor.development_sp_pov_agents = caps.sp_pov_agents
        executor.development_security_invariant_focus = (
            caps.security_invariant_focus)
        executor.development_pov_attempts_per_candidate = (
            caps.pov_attempts_per_candidate)
        executor.development_sp_start_envelope = None
        strategy._development_seed_limit = 1
        strategy._development_sp_queue_drain = not caps.sp_concurrent_queue
        strategy._development_sp_concurrent_queue = caps.sp_concurrent_queue
        strategy._development_security_invariant_focus = (
            caps.security_invariant_focus)
        strategy._development_pov_attempts_per_candidate = (
            caps.pov_attempts_per_candidate)
        if caps.sp_start_min_remaining_calls is not None:
            executor.development_sp_start_envelope = {
                "minimum_calls": caps.sp_start_min_remaining_calls,
                "minimum_wall_seconds":
                    caps.sp_start_min_remaining_wall_seconds,
            }
            strategy._development_sp_start_envelope = dict(
                executor.development_sp_start_envelope)
        executor.development_sp_scope = {
            "kind": ("SP_PERSISTENT_CONCURRENT_QUEUE_DEV_V1" if
                     caps.sp_concurrent_queue else
                     "SP_PRIORITY_ONE_SEED_DEV_V2"),
            "status": "PARTIAL_SEED_SCOPE",
            "function_outcomes": [],
            "sp_queue_policy": (
                "PERSISTENT_CONCURRENT_QUEUE_V1" if
                caps.sp_concurrent_queue else
                "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"),
            "security_invariant_focus": caps.security_invariant_focus,
            "pov_attempts_per_candidate": caps.pov_attempts_per_candidate,
            "sp_start_envelope": (
                None if caps.sp_start_min_remaining_calls is None else {
                    "minimum_calls": caps.sp_start_min_remaining_calls,
                    "minimum_wall_seconds":
                        caps.sp_start_min_remaining_wall_seconds,
                }),
        }
        strategy._development_sp_scope = executor.development_sp_scope
        strategy.num_parallel_agents = caps.sp_discovery_agents
        strategy._development_verify_agents = caps.sp_verify_agents
        strategy._development_pov_agents = caps.sp_pov_agents
    bound = BoundOriginalPublicDev(admission, identity, caps, server, executor,
                                   strategy, model_gate, process_ledger,
                                   campaign, adapter, bootstrap_token)
    if caps.full_nohint_sp:
        bound.qualified_gate_stop = QualifiedGateStop(bound)
        executor.qualified_gate_stop = bound.qualified_gate_stop
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
    sp_fuzz_local_wall = required_sp_fuzz_wall_reservation(
        bound.caps.sp_fuzz_seconds,
        bound.caps.sp_fuzz_max_items,
        0,
    )
    return run_qualified_sp_fuzz(
        bound.pov_adapter, sorted(eligible)[0], bound.model_gate,
        recheck=bound.recheck, seconds=bound.caps.sp_fuzz_seconds,
        fuzz_wall_seconds=sp_fuzz_local_wall,
        replay_wall_seconds=min(
            600.0, bound.caps.gate_aux_reservation_seconds_per_observation),
        replay_limit=1)


def _run_worker_with_bound_strategy(bound: BoundOriginalPublicDev) -> dict:
    """Retain the exact Strategy instance executed by the original Worker."""
    executor = bound.executor
    factory = executor._get_strategy
    previous = vars(executor).get("_get_strategy")
    had_override = "_get_strategy" in vars(executor)

    def capture_strategy():
        strategy = factory()
        if strategy.executor is not executor:
            raise ValueError("original Worker strategy identity changed")
        bound.strategy = strategy
        if getattr(executor, "graceful_stop_requested", False):
            request_stop = getattr(strategy, "request_graceful_stop", None)
            if callable(request_stop):
                request_stop()
        return strategy

    executor._get_strategy = capture_strategy
    try:
        return executor.run()
    finally:
        if had_override:
            executor._get_strategy = previous
        else:
            del executor._get_strategy


def _record_claim_settlement(bound, *, process, process_receipt_sha256,
                             model, phase,
                             parallel_hp_diagnostic=None):
    from devtools.product_qualified_runtime import _json_new
    filenames = {"POST_WORKER_POST_GATE": "claim-settlement.json",
                 "FINAL_POST_HP": "final-claim-settlement.json"}
    filename = filenames[phase]
    from devtools.candidate_claim_settlement import candidate_claim_snapshot
    claim_snapshot = candidate_claim_snapshot(
        bound.server.repos, bound.identity.task_id)
    model_incomplete = incomplete_model_activity(model, bound.model_gate)
    claims_zero_proven = (
        claim_snapshot["status"] == "NO_ACTIVE_CLAIMS" and
        process.get("active") == {} and not model_incomplete)
    claim_receipt = {
        "kind": "FBV2_PUBLIC_DEV_CLAIM_SETTLEMENT_V1",
        "task_id": bound.identity.task_id, "run_id": bound.identity.run_id,
        "phase": phase,
        "status": "NO_ACTIVE_CLAIMS" if claims_zero_proven else "UNPROVEN",
        "repository_snapshot": claim_snapshot,
        "process_receipt_sha256": process_receipt_sha256,
        "process_ledger_revision": process.get("revision"),
        "processes_inactive": process.get("active") == {},
        "model_and_tools_settled": not model_incomplete,
        "model_snapshot_sha256": hashlib.sha256(json.dumps(
            model, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }
    if parallel_hp_diagnostic is not None:
        claim_receipt["parallel_hp_evidence"] = (
            _parallel_hp_settlement_evidence(parallel_hp_diagnostic))
    claim_receipt_path = bound.identity.run_dir / filename
    claim_receipt_sha256 = _json_new(claim_receipt_path, claim_receipt)
    return (claim_receipt, claim_receipt_path, claim_receipt_sha256,
            model_incomplete, claims_zero_proven)


def _parallel_hp_settlement_evidence(diagnostic):
    if (type(diagnostic) is not dict or
            diagnostic.get("discovery_credit") != "NOT_CREDITED" or
            diagnostic.get("security_gate_credit") not in {
                "NOT_CREDITED", "HP_GATE_VERIFIED"}):
        raise ValueError("parallel HP settlement evidence is invalid")
    return {key: diagnostic.get(key) for key in (
        "analysis_status", "analysis_result_sha256",
        "physical_status", "physical_result_sha256",
        "gate_status", "gate_result_sha256",
        "security_gate_credit", "discovery_credit")}


def finalize_public_claim_settlement(bound, result, *,
                                     parallel_hp_spec_path=None,
                                     parallel_hp_spec_sha256=None):
    """Re-read activity after optional HP while the analysis DB is open."""
    if (result.get("kind") != "FBV2_PUBLIC_DEV_ORIGINAL_RESULT_V1" or
            result.get("task_id") != bound.identity.task_id or
            result.get("run_id") != bound.identity.run_id):
        raise ValueError("final Claim settlement identity mismatch")
    worker_path = bound.identity.run_dir / "claim-settlement.json"
    worker_sha = result.get("claim_settlement_receipt_sha256")
    if (result.get("claim_settlement_receipt_path") !=
            str(worker_path) or worker_path.is_symlink() or
            not worker_path.is_file()):
        raise ValueError("worker Claim settlement receipt is missing")
    raw = worker_path.read_bytes()
    if (type(worker_sha) is not str or
            hashlib.sha256(raw).hexdigest() != worker_sha):
        raise ValueError("worker Claim settlement receipt changed")
    worker_receipt = json.loads(raw)
    diagnostic = result.get("parallel_hp_diagnostic")
    wanted_hp_evidence = (
        _parallel_hp_settlement_evidence(diagnostic)
        if diagnostic is not None else None)
    if (type(worker_receipt) is not dict or
            worker_receipt.get("kind") !=
                "FBV2_PUBLIC_DEV_CLAIM_SETTLEMENT_V1" or
            worker_receipt.get("task_id") != bound.identity.task_id or
            worker_receipt.get("run_id") != bound.identity.run_id or
            worker_receipt.get("phase") != "POST_WORKER_POST_GATE" or
            worker_receipt.get("parallel_hp_evidence") !=
                wanted_hp_evidence):
        raise ValueError("worker Claim settlement evidence changed")
    parallel_row = getattr(getattr(bound, "strategy", None),
                           "_parallel_hp_result", None)
    if type(parallel_row) is dict and parallel_row.get("result_path") is not None:
        if (parallel_hp_spec_path is None or
                parallel_hp_spec_sha256 is None):
            raise ValueError("parallel HP final spec pin is missing")
        from devtools.parallel_hp_analysis import reprove_parallel_hp_diagnostic
        spec_path = Path(parallel_hp_spec_path)
        _pinned_file(spec_path, parallel_hp_spec_sha256,
                     "parallel HP final spec")
        spec_raw = spec_path.read_bytes()
        if hashlib.sha256(spec_raw).hexdigest() != parallel_hp_spec_sha256:
            raise ValueError("parallel HP final spec bytes changed")
        pinned_spec = json.loads(spec_raw)
        gate_policy = (pinned_spec.get("hp_gate") if
                       parallel_row.get("gate_result_path") is not None else
                       None)
        current_hp_evidence = reprove_parallel_hp_diagnostic(
            bound.identity.run_dir, task_id=bound.identity.task_id,
            run_id=bound.identity.run_id, result=parallel_row,
            qualification=bound.admission.qualification,
            process_ledger=bound.process_ledger,
            gate_policy=gate_policy,
            gate_max_wall_seconds=bound.caps.
                gate_aux_reservation_seconds_per_observation,
            gate_max_output_bytes=pinned_spec.get("hp", {}).get(
                "physical", {}).get("output_limit_bytes"))
        if current_hp_evidence != diagnostic:
            raise ValueError("parallel HP final evidence changed")
    elif (type(diagnostic) is dict and diagnostic.get(
            "security_gate_credit") == "HP_GATE_VERIFIED"):
        raise ValueError("parallel HP Gate credit lacks final evidence")
    process, process_sha = bound.process_ledger.receipt_snapshot()
    model = bound.model_gate.snapshot()
    receipt, path, sha, _, zero = _record_claim_settlement(
        bound, process=process, process_receipt_sha256=process_sha,
        model=model, phase="FINAL_POST_HP",
        parallel_hp_diagnostic=result.get("parallel_hp_diagnostic"))
    final = {**result,
        "worker_claim_settlement_receipt_path": result.get("claim_settlement_receipt_path"),
        "worker_claim_settlement_receipt_sha256": result.get("claim_settlement_receipt_sha256"),
        "claim_settlement_status": receipt["status"],
        "claim_settlement_phase": receipt["phase"],
        "active_repository_claim_document_count": receipt["repository_snapshot"]["active_document_count"],
        "claim_settlement_receipt_path": str(path),
        "claim_settlement_receipt_sha256": sha,
    }
    if not zero:
        final.update(status="INCOMPLETE", execution_status="INCOMPLETE")
    return final


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
             "--authorize-public-dev-hp" not in sys.argv and
             "--authorize-public-dev-hp-parallel" not in sys.argv and
             "--authorize-bounded-nohint-hp" not in sys.argv) or
            type(marker) is not dict or
            marker.get("hp_mode", False) is not
                ("--authorize-public-dev-hp" in sys.argv or
                 "--authorize-public-dev-hp-parallel" in sys.argv or
                 "--authorize-bounded-nohint-hp" in sys.argv) or
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
        result = _run_worker_with_bound_strategy(bound)
    except IncompleteInjectedAgent as exc:
        # A qualified PoV crash and a model request denied before transport
        # both leave earlier Runtime artifacts to reconcile. Neither makes
        # the Worker complete. Uncertain remote state remains a hard stop.
        if exc.reason not in {"validation_pending", "budget_before_transport",
                              "verifier_no_verdict"}:
            raise
        context = getattr(bound.executor, "_worker_context", None)
        worker_id = getattr(context, "worker_id", None)
        if not isinstance(worker_id, str) or not ObjectId.is_valid(worker_id):
            raise
        worker_pending_reason = exc.reason
        result = {"worker_id": worker_id,
                  "status": ("PENDING_INDEPENDENT_VALIDATION"
                             if exc.reason == "validation_pending" else
                             "INCOMPLETE_VERIFIER"
                             if exc.reason == "verifier_no_verdict" else
                             "INCOMPLETE_BUDGET"),
                  "incomplete_reason": exc.reason}
    parallel_hp_diagnostic = None
    if getattr(bound.executor, "parallel_hp_async_factory", None) is not None:
        from devtools.parallel_hp_analysis import reprove_parallel_hp_diagnostic
        parallel_row = getattr(bound.strategy, "_parallel_hp_result", None)
        if (type(parallel_row) is dict and
                parallel_row.get("result_path") is not None):
            try:
                gate_policy = None
                gate_output_limit = None
                if parallel_row.get("gate_result_path") is not None:
                    live_spec_path = Path(marker["spec_path"])
                    _pinned_file(live_spec_path, marker["spec_sha256"],
                                 "parallel HP Gate public spec")
                    live_spec_raw = live_spec_path.read_bytes()
                    if (hashlib.sha256(live_spec_raw).hexdigest() !=
                            marker["spec_sha256"]):
                        raise ValueError("parallel HP public spec bytes changed")
                    live_spec = json.loads(live_spec_raw)
                    gate_policy = live_spec.get("hp_gate")
                    gate_output_limit = live_spec.get("hp", {}).get(
                        "physical", {}).get("output_limit_bytes")
                parallel_hp_diagnostic = reprove_parallel_hp_diagnostic(
                    bound.identity.run_dir, task_id=bound.identity.task_id,
                    run_id=bound.identity.run_id, result=parallel_row,
                    qualification=bound.admission.qualification,
                    process_ledger=bound.process_ledger,
                    gate_policy=gate_policy,
                    gate_max_wall_seconds=bound.caps.
                        gate_aux_reservation_seconds_per_observation,
                    gate_max_output_bytes=gate_output_limit)
            except (OSError, TypeError, ValueError, KeyError) as exc:
                parallel_hp_diagnostic = {
                    "analysis_status": "HP_PARALLEL_EVIDENCE_UNPROVEN",
                    "error_type": type(exc).__name__,
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED",
                }
        else:
            parallel_hp_diagnostic = {
                "analysis_status": "HP_PARALLEL_EVIDENCE_UNPROVEN",
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED",
            }
    if getattr(bound.model_gate, "admission_open", True) is False:
        raise IncompleteInjectedAgent(
            "user stop settled the Worker; post-Worker work was not admitted",
            reason="user_stop_settled")
    # The original create_pov tool executes the Target before its host-tool
    # result is audited. Reconcile model/tool/DB/Runtime lineage only after the
    # Worker returns. Provenance alone never grants discovery or Gate credit.
    from devtools.model_candidate_lineage import find_candidate_lineage
    from devtools.product_qualified_runtime import (
        _json_new, verify_qualified_pov_runtime_lineage)
    pov_lineage_rows = []
    for path in sorted(bound.pov_adapter.root.glob("*/runtime.json")):
        pov_id = path.parent.name
        admission_mode = _signed_pov_admission_mode(bound)
        candidate = find_candidate_lineage(
            bound.model_gate, bound.server.repos,
            task_id=bound.identity.task_id, pov_id=pov_id,
            pov_admission_mode=admission_mode)
        runtime_lineage = verify_qualified_pov_runtime_lineage(
            bound.pov_adapter, pov_id, bound.model_gate, recheck=bound.recheck,
            pov_admission_mode=admission_mode)
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
    before_sp_fuzz_process, _ = bound.process_ledger.receipt_snapshot()
    before_sp_fuzz_model = bound.model_gate.snapshot()
    sp_fuzz_worker_settled = (
        worker_pending_reason is None and
        before_sp_fuzz_process.get("stop_status") is None and
        before_sp_fuzz_process.get("active") == {} and
        not incomplete_model_activity(before_sp_fuzz_model, bound.model_gate))
    if not sp_fuzz_worker_settled:
        sp_fuzz_result = {
            "status": ("SKIPPED_WORKER_MODEL_BUDGET"
                       if worker_pending_reason == "budget_before_transport" else
                       "SKIPPED_WORKER_INCOMPLETE"),
            "automatic_discovery": False,
        }
    else:
        sp_fuzz_result = _run_qualified_sp_fuzz_after_worker(
            bound, pov_lineage_rows)
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
            gate_stop = getattr(bound, "qualified_gate_stop", None)
            retained = (gate_stop.retained_row(pov_id)
                        if gate_stop is not None else None)
            pov_gate_rows.append(retained if retained is not None else
                consume_qualified_pov_observation(
                    bound.pov_adapter, pov_id, recheck=bound.recheck,
                    timeout_seconds=min(10.0, bound.caps.pov_timeout_seconds),
                    model_gate=bound.model_gate,
                    gate_wall_seconds=bound.caps.gate_aux_reservation_seconds_per_observation,
                    pov_admission_mode=_signed_pov_admission_mode(bound)))
        except Exception as exc:
            pov_gate_rows.append({"pov_id": pov_id, "product_gate_status":
                                  "INCOMPLETE_CONSUMPTION", "error_type": type(exc).__name__})
            break  # An uncertain physical attempt cannot admit another replay.
    pending_claim_incomplete = False
    # Check every retained pending-validation candidate even when a different
    # incomplete reason won the Pipeline's primary-reason slot.
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
            continue
        pending_ids.extend(ids)
    missing_pending_observations = sorted(set(pending_ids) - set(observed_pov_ids))
    if (len(pending_ids) != len(set(pending_ids)) or missing_pending_observations or
            (worker_pending_reason == "validation_pending" and
             (not pending_rows or not pending_ids))):
        pending_claim_incomplete = True
    # Re-read the one durable process account after all original roles and
    # Global settlement. An earlier Global "RAN" receipt cannot override a
    # concurrent PoV/consumer STOPPED status.
    process, process_receipt_sha256 = bound.process_ledger.receipt_snapshot()
    model = bound.model_gate.snapshot()
    (claim_receipt, claim_receipt_path, claim_receipt_sha256,
     model_incomplete, claims_zero_proven) = _record_claim_settlement(
        bound, process=process, process_receipt_sha256=process_receipt_sha256,
        model=model, phase="POST_WORKER_POST_GATE",
        parallel_hp_diagnostic=parallel_hp_diagnostic)
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
    # Goal A.1.2: a VERIFIED label counts only when the durable outcome is
    # re-proven; an unproven label is neither success nor lineage credit.
    verified_pov_ids = _authenticated_verified_gate_pov_ids(
        bound.identity, pov_gate_rows, observed_pov_ids, process.get("finished", []))
    model_lineage_gate_verified_pov_ids = [
        pov_id for pov_id in _model_lineage_gate_verified_pov_ids(
            bound.identity.run_dir, pov_lineage_rows, pov_gate_rows)
        if pov_id in verified_pov_ids]
    sp_fuzz_consumer_rows = sp_fuzz_result.get("consumer_rows", [])
    if type(sp_fuzz_consumer_rows) is not list or any(
            type(row) is not dict for row in sp_fuzz_consumer_rows):
        raise ValueError("SP Fuzzer consumer rows changed")
    from devtools.product_qualified_runtime import verified_fuzzer_consumer_evidence
    sp_fuzz_consumer_verified_count = sum(
        row.get("status") == "VERIFIED" and
        verified_fuzzer_consumer_evidence(bound.pov_adapter.root.parent, row)
        for row in sp_fuzz_consumer_rows)
    gate_stop = getattr(bound, "qualified_gate_stop", None)
    gate_stop_requested = bool(
        gate_stop is not None and gate_stop.verified.is_set())
    gate_stop_verified = bool(
        gate_stop_requested and model_lineage_gate_verified_pov_ids and
        isinstance(result, dict) and
        result.get("gate_verified_early_stop") is True)
    # A conclusive product Gate rejection is terminal: not success, and not
    # pending either. A BLOCKED_* label alone never qualifies; only a durable,
    # identity-bound outcome whose structured TERMINAL_REJECTED resolution is
    # re-proven from hashed artifacts and the process ledger. Everything else
    # (timeouts, environment errors, unknown or forged rows) stays pending.
    terminal_gate_pov_ids = _authenticated_terminal_gate_pov_ids(
        bound.identity, pov_gate_rows, observed_pov_ids, verified_pov_ids,
        process.get("finished", []))
    # Goal A.1.1 (R9): unsupported target crash types are never settled and
    # are always surfaced for human review (not success, not Discovery).
    unsupported_gate_rows = [
        {"pov_id": row.get("pov_id"), "observed_sanitizer": row.get("observed_sanitizer"),
         "reason": row.get("producer_gate_resolution_reason")}
        for row in pov_gate_rows
        if row.get("product_gate_status") == "BLOCKED_UNSUPPORTED_CRASH_TYPE"]
    local_gate_failures = [row for row in pov_gate_rows if
                           row.get("kind") ==
                           "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1"]
    offline_gate_revalidation = [{
        "pov_id": row.get("pov_id"),
        "input_sha256": row.get("input_sha256"),
        "stage": row.get("stage"),
        "error_type": row.get("error_type"),
        "stop_status": row.get("stop_status"),
    } for row in local_gate_failures]
    pending_pov_crashes = sum(pov_id not in verified_pov_ids and
                              pov_id not in terminal_gate_pov_ids
                              for pov_id in observed_pov_ids)
    analysis_scope = (result.get("analysis_scope")
                      if isinstance(result, dict) else None)
    if isinstance(analysis_scope, dict):
        outcomes = analysis_scope.get("function_outcomes", [])
        if (type(outcomes) is not list or
                any(type(row) is not dict for row in outcomes)):
            raise ValueError("bounded SP function outcomes are malformed")
    else:
        outcomes = []
    local_sp_exhaustion = (
        isinstance(analysis_scope, dict) and
        any(row.get("opportunity_status") in {
                "NO_OPPORTUNITY_MAX_ITERATIONS", "SP_CREATED_MAX_ITERATIONS"}
            for row in outcomes))
    downstream_reserve_stop = bool(
        isinstance(analysis_scope, dict) and
        analysis_scope.get("status") == "DOWNSTREAM_RESERVE_STOP" and
        isinstance(analysis_scope.get("downstream_reserve_stop"), dict) and
        analysis_scope["downstream_reserve_stop"].get("admitted") is False)
    execution_incomplete = (
        worker_pending_reason in {"budget_before_transport", "verifier_no_verdict"}
        or (gate_stop_requested and not gate_stop_verified)
        or process["stop_status"] is not None or bool(process["active"])
        or model_incomplete or not claims_zero_proven
        or incomplete_global or pending_claim_incomplete
        or sp_fuzz_result.get("status") in {
            "INCOMPLETE", "INCOMPLETE_FUZZ_WITH_OBSERVED_CRASH"})
    verification_pending = (pending_global_crashes > 0 or
                            pending_pov_crashes > 0 or any(
                      row.get("product_gate_status") == "INCOMPLETE_CONSUMPTION"
                      for row in pov_gate_rows) or
                            bool(local_gate_failures) or
                            sp_fuzz_result.get("status") in {
                                "PENDING_INDEPENDENT_VALIDATION",
                                "INCOMPLETE_FUZZ_WITH_OBSERVED_CRASH"})
    # A prior function's settled local iteration limit is still recorded in
    # analysis_scope, but it cannot invalidate a later qualified Gate stop.
    incomplete = (execution_incomplete or verification_pending or
                  (local_sp_exhaustion and not gate_stop_verified))
    return {
        "kind": "FBV2_PUBLIC_DEV_ORIGINAL_RESULT_V1",
        **({"parallel_hp_diagnostic": parallel_hp_diagnostic}
           if parallel_hp_diagnostic is not None else {}),
        "status": ("INCOMPLETE" if incomplete else
                   "EXECUTED_VERIFIED_EARLY_STOP" if gate_stop_verified else
                   # Product Gate verified a model PoV; automatic discovery
                   # causality is still unproven and is never credited here.
                   "EXECUTED_GATE_VERIFIED_DISCOVERY_UNPROVEN"
                   if model_lineage_gate_verified_pov_ids else
                   "EXECUTED_UNVERIFIED"),
        "execution_status": ("INCOMPLETE" if execution_incomplete else
                             "STOPPED_GATE_VERIFIED" if gate_stop_verified else
                             "EXECUTED"),
        "sp_analysis_status": ("INCOMPLETE_VERIFIER"
                               if worker_pending_reason == "verifier_no_verdict" else
                               "STOPPED_GATE_VERIFIED" if gate_stop_verified else
                               "PARTIAL_DOWNSTREAM_RESERVE_STOP"
                               if downstream_reserve_stop else
                               "PARTIAL_LOCAL_OPPORTUNITY_EXHAUSTED"
                               if local_sp_exhaustion else
                               "COMPLETED"),
        "gate_verified_early_stop": gate_stop_verified,
        "verification_status": ("PENDING_INDEPENDENT_VALIDATION"
                                if verification_pending else
                                "MODEL_POV_PRODUCT_GATE_VERIFIED_DISCOVERY_UNPROVEN"
                                if model_lineage_gate_verified_pov_ids else
                                "PRODUCT_GATE_VERIFIED_MODEL_ORIGIN_UNPROVEN"
                                if verified_pov_ids else
                                "POV_CRASH_GATE_TERMINAL_NOT_VERIFIED"
                                if terminal_gate_pov_ids else
                                "PRODUCT_SP_FUZZ_GATE_VERIFIED_ORIGIN_UNPROVEN"
                                if sp_fuzz_consumer_verified_count else
                                "PRODUCT_CONSUMER_VERIFIED_ORIGIN_UNPROVEN"
                                if global_consumer_verified else
                                "NO_PENDING_OBSERVATION"),
        "pov_crashes_pending_independent_validation": pending_pov_crashes,
        "pending_validation_claims_incomplete": pending_claim_incomplete,
        "claim_settlement_status": claim_receipt["status"],
        "claim_settlement_phase": claim_receipt["phase"],
        "active_repository_claim_document_count": claim_receipt["repository_snapshot"][
            "active_document_count"],
        "claim_settlement_receipt_path": str(claim_receipt_path),
        "claim_settlement_receipt_sha256": claim_receipt_sha256,
        "pending_validation_candidate_count": len(pending_rows),
        "pending_validation_pov_ids": sorted(set(pending_ids)),
        "pending_validation_missing_observation_pov_ids": missing_pending_observations,
        "pov_crashes_gate_verified_count": len(verified_pov_ids),
        "pov_crashes_gate_terminal_not_verified_count": len(
            terminal_gate_pov_ids),
        "pov_crashes_gate_terminal_not_verified_ids": sorted(
            terminal_gate_pov_ids),
        "pov_crashes_unsupported_type_pending_count": len(unsupported_gate_rows),
        "pov_crashes_unsupported_type_pending": unsupported_gate_rows,
        "pov_product_gate_rows": pov_gate_rows,
        "pov_product_gate_local_failure_count": len(local_gate_failures),
        "pov_product_gate_local_failure_reasons": sorted({
            f"{row.get('stage')}:{row.get('error_type')}:"
            f"{row.get('stop_status')}" for row in local_gate_failures}),
        "pov_product_gate_offline_revalidation": offline_gate_revalidation,
        "pov_lineage_rows": pov_lineage_rows,
        "sp_fuzz_result": sp_fuzz_result,
        "sp_fuzz_consumer_verified_count": sp_fuzz_consumer_verified_count,
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
                                   if worker_pending_reason == "validation_pending" else
                                   "INCOMPLETE_VERIFIER"
                                   if worker_pending_reason == "verifier_no_verdict" else
                                   "INCOMPLETE_BUDGET"
                                   if worker_pending_reason == "budget_before_transport" else
                                   "STOPPED_GATE_VERIFIED"
                                   if gate_stop_verified else
                                   "PARTIAL_DOWNSTREAM_RESERVE_STOP"
                                   if downstream_reserve_stop else
                                   "PARTIAL_LOCAL_OPPORTUNITY_EXHAUSTED"
                                   if local_sp_exhaustion else "COMPLETED"),
        "worker_incomplete_reason": worker_pending_reason,
        "direction_seed_phase": (result.get("direction_seed_phase")
                                 if isinstance(result, dict) else None),
        "analysis_scope": analysis_scope,
        "original_result": result,
    }
