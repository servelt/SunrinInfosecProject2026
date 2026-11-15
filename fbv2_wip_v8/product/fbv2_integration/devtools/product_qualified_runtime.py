"""Development-only FBv2 PoV execution through the qualified product Runtime.

This adapter observes one original PoV input. A separate consumer below can
send an observed crash to the existing product replay/root-cause/Gate path.
Both use the same persistent V2 process ledger. Neither a Runtime crash nor
the original FBv2 PoV status is a product VERIFIED verdict.
"""

from __future__ import annotations

from dataclasses import asdict
import base64
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Callable

from bson import ObjectId
from pymongo.write_concern import WriteConcern

from fuzzingbrain.core.models.suspicious_point import SPStatus
from fuzzingbrain.tools.qualified_runtime import (
    QualifiedRuntimeBinding, QualifiedRuntimeOutcome, QualifiedRuntimeRequest,
)


_ID = re.compile(r"[A-Za-z0-9_-]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _write_new(path: Path, content: bytes) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(content).hexdigest()


def _json_new(path: Path, payload: dict[str, Any]) -> str:
    return _write_new(path, (json.dumps(payload, sort_keys=True,
                                        separators=(",", ":"),
                                        allow_nan=False) + "\n").encode())


class ProductQualifiedPoVAdapter:
    """One task's bounded direct PoV observation with a durable process debit."""

    def __init__(self, *, qualification: Any, repos: Any, task_id: str,
                 work_item_id: str, run_id: str, fuzzer: str, sanitizer: str,
                 ledger: Any, output_dir: Path, timeout_seconds: float,
                 wall_seconds: float, output_limit_bytes: int):
        # These imports are intentionally lazy: only a development launcher
        # that has pinned both product and evaluation modules may construct us.
        try:
            from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
            from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
            from vulnerabilityanalysis.runtime import RuntimeExecutor
        except ImportError as exc:
            raise ValueError("pinned development process/runtime modules unavailable") from exc
        if (type(ledger) is not PersistentProcessLedgerV2 or
                any(type(value) is not str or not _ID.fullmatch(value)
                    for value in (task_id, work_item_id, run_id, fuzzer)) or
                sanitizer != "address" or
                type(timeout_seconds) not in (int, float) or
                not math.isfinite(timeout_seconds) or
                timeout_seconds <= 0 or timeout_seconds > 120 or
                type(wall_seconds) not in (int, float) or
                not math.isfinite(wall_seconds) or
                wall_seconds < timeout_seconds + 9.5 or
                type(output_limit_bytes) is not int or
                output_limit_bytes < 1 or output_limit_bytes > 16_000_000 or
                not callable(getattr(repos.suspicious_points, "find_by_id", None))):
            raise ValueError("qualified PoV development account is invalid")
        root = Path(output_dir)
        if (not root.is_absolute() or root != root.resolve() or
                root.is_symlink() or any(parent.is_symlink() for parent in root.parents)
                or not root.parent.is_dir() or root.exists()):
            raise ValueError("qualified PoV output must be a new canonical directory")
        # Validate an actual product-issued V2 token before creating artifacts.
        binding = QualifiedRuntimeBinding(qualification, self.execute)
        binding.pinned_binary()
        root.mkdir(mode=0o700)
        self.binding = binding
        self.repos = repos
        self.task_id = task_id
        self.work_item_id = work_item_id
        self.run_id = run_id
        self.fuzzer = fuzzer
        self.sanitizer = sanitizer
        self.ledger = ledger
        self.root = root
        self.timeout_seconds = float(timeout_seconds)
        self.wall_seconds = float(wall_seconds)
        self.output_limit_bytes = output_limit_bytes
        self._envelope_type = DevelopmentProcessEnvelopeV2
        self._runtime_type = RuntimeExecutor

    def _check_request(self, request: QualifiedRuntimeRequest) -> tuple[Path, str]:
        if (type(request) is not QualifiedRuntimeRequest or
                request.task_id != self.task_id or
                request.harness_name != self.fuzzer or
                request.sanitizer != self.sanitizer or
                any(type(value) is not str or not _ID.fullmatch(value)
                    for value in (request.suspicious_point_id, request.pov_id)) or
                type(request.input_bytes) is not bytes or
                not request.input_bytes or len(request.input_bytes) > 2_097_152 or
                not _SHA.fullmatch(request.input_sha256) or
                hashlib.sha256(request.input_bytes).hexdigest() != request.input_sha256):
            raise ValueError("PoV request identity or input changed")
        point = self.repos.suspicious_points.find_by_id(request.suspicious_point_id)
        if (point is None or point.task_id != self.task_id or
                point.status != SPStatus.GENERATING_POV.value or
                not any(source.get("harness_name") == self.fuzzer and
                            source.get("sanitizer") == self.sanitizer
                            for source in point.sources)):
            raise ValueError("PoV SP is not an eligible claimed task candidate")
        binary, binary_sha = self.binding.pinned_binary()
        if (request.binary_path != binary or
                request.binary_sha256 != binary_sha):
            raise ValueError("PoV request binary differs from product qualification")
        return binary, binary_sha

    def _claim_pov_once(self, request: QualifiedRuntimeRequest,
                        binary_sha: str) -> None:
        """Claim this saved PoV across ledger/run/work-item replacement.

        The original PoV tool sets qualified_runtime.STARTED before invoking
        the callback. A separate adapter marker is needed because a newly
        created physical ledger cannot know that an older ledger ran this PoV.
        The original tool replaces the whole qualified_runtime subdocument on
        completion (thereby leaving STARTED); on failure it changes status to
        INCOMPLETE. Either terminal transition still rejects a second claim.
        """
        base_collection = self.repos.povs.collection
        if (not callable(getattr(base_collection, "update_one", None)) or
                not callable(getattr(base_collection, "with_options", None))):
            raise ValueError("durable PoV claim repository is unavailable")
        # Journal acknowledgment is part of admission: after this call
        # returns, a fresh process/ledger must see the previous attempt.
        collection = base_collection.with_options(
            write_concern=WriteConcern(w=1, j=True))
        claim = collection.update_one(
            {"_id": ObjectId(request.pov_id),
             "task_id": ObjectId(self.task_id),
             "suspicious_point_id": ObjectId(request.suspicious_point_id),
             "harness_name": self.fuzzer, "sanitizer": self.sanitizer,
             "is_successful": False, "is_active": True,
             "blob": base64.b64encode(request.input_bytes).decode("ascii"),
             "qualified_runtime.status": "STARTED",
             "qualified_runtime.input_sha256": request.input_sha256,
             "qualified_runtime.binary_sha256": binary_sha,
             "qualified_runtime.adapter_claim": {"$exists": False}},
            {"$set": {"qualified_runtime.adapter_claim": {
                "kind": "FBV2_DEV_QUALIFIED_POV_CLAIM_V1",
                "task_id": self.task_id,
                "sp_id": request.suspicious_point_id,
                "pov_id": request.pov_id,
                "input_sha256": request.input_sha256,
                "binary_sha256": binary_sha,
                "ledger_path": str(self.ledger.path),
                "run_id": self.run_id,
            }}},
        )
        if claim.acknowledged is not True or claim.modified_count != 1:
            raise RuntimeError("saved PoV already claimed or changed; no resend")

    def _record_local_prestart(self, request: QualifiedRuntimeRequest,
                               original: BaseException) -> None:
        """Keep a journaled reason after the DB claim but before a Target start."""
        try:
            collection = self.repos.povs.collection.with_options(
                write_concern=WriteConcern(w=1, j=True))
            changed = collection.update_one(
                {"_id": ObjectId(request.pov_id),
                 "qualified_runtime.status": "STARTED",
                 "qualified_runtime.adapter_claim.run_id": self.run_id,
                 "qualified_runtime.adapter_claim.ledger_path": str(self.ledger.path)},
                {"$set": {"qualified_runtime.status": "INCOMPLETE",
                          "qualified_runtime.error":
                          "LOCAL_PRESTART_" + type(original).__name__}},
            )
            if changed.acknowledged is not True or changed.modified_count != 1:
                raise RuntimeError("local-prestart reason was not journaled")
        except BaseException as cleanup:
            original.add_note("local-prestart reason persistence failed: " +
                              type(cleanup).__name__)

    def execute(self, request: QualifiedRuntimeRequest) -> QualifiedRuntimeOutcome:
        binary, binary_sha = self._check_request(request)
        self._claim_pov_once(request, binary_sha)
        attempt_dir = self.root / request.pov_id
        input_path = attempt_dir / "input.bin"
        expected_command = [str(binary), str(input_path)]

        def pin(phase: str, command: list[str]) -> None:
            same_binary, same_sha = self.binding.pinned_binary()
            if (same_binary != binary or same_sha != binary_sha or
                    command != expected_command or
                    _sha(input_path) != request.input_sha256 or
                    request.task_id != self.task_id):
                raise ValueError(f"qualified PoV pin changed at {phase}")

        try:
            envelope = self._envelope_type(
                self.ledger, work_item_id=self.task_id,
                # Physical identity is stable across a fresh run_id/output_dir.
                # A new campaign or work item may not resend the same task/SP/PoV.
                assertion_id=request.suspicious_point_id,
                attempt_id=request.pov_id,
                output_limit_bytes=self.output_limit_bytes,
                total_wall_seconds=self.wall_seconds, pin_hook=pin)
            attempt_dir.mkdir(mode=0o700, exist_ok=False)
            _write_new(input_path, request.input_bytes)
        except BaseException as original:
            self._record_local_prestart(request, original)
            raise
        # RuntimeExecutor owns the supervised process. The envelope fsyncs
        # its physical reservation before launch and settlement after cleanup.
        result = self._runtime_type(self.timeout_seconds).run(
            [str(binary), "{input}"], input_path,
            process_envelope=envelope,
            process_segment="pov.qualified_direct")
        pin("after_runtime", expected_command)
        snap = self.ledger.snapshot()
        prefix = (f"{self.task_id}:{request.suspicious_point_id}:"
                  f"{request.pov_id}:")
        rows = [row for row in snap["finished"] if row["key"].startswith(prefix)]
        if (len(rows) != 1 or rows[0]["kind"] != "AUX_PROCESS" or
                not rows[0]["cleanup_complete"] or rows[0]["output_limited"] or
                rows[0]["overrun"] or snap["stop_status"] is not None or
                any(key.startswith(prefix) for key in snap["active"])):
            raise RuntimeError("qualified PoV physical settlement is incomplete")
        if result.exit_code is None or result.timed_out:
            status = "INCOMPLETE"
        elif result.sanitizer and result.exit_code != 0:
            status = "CRASH_OBSERVED"
        elif result.exit_code == 0 and not result.sanitizer:
            status = "NO_CRASH"
        else:
            status = "INCOMPLETE"
        physical_path = attempt_dir / "physical.json"
        physical_sha = _json_new(physical_path, {
            "kind": "FBV2_DEV_QUALIFIED_POV_PHYSICAL_V1",
            "task_id": self.task_id, "work_item_id": self.work_item_id,
            "run_id": self.run_id, "sp_id": request.suspicious_point_id,
            "pov_id": request.pov_id, "input_sha256": request.input_sha256,
            "input_path": str(input_path),
            "binary_sha256": binary_sha, "ledger_path": str(self.ledger.path),
            "ledger_sha256": _sha(self.ledger.path), "lease": rows[0],
        })
        runtime_path = attempt_dir / "runtime.json"
        runtime_sha = _json_new(runtime_path, {
            "kind": "FBV2_DEV_QUALIFIED_POV_RUNTIME_V1",
            "task_id": self.task_id, "work_item_id": self.work_item_id,
            "run_id": self.run_id, "sp_id": request.suspicious_point_id,
            "pov_id": request.pov_id, "input_sha256": request.input_sha256,
            "input_path": str(input_path),
            "binary_sha256": binary_sha, "physical_receipt_sha256": physical_sha,
            "status": status, "command": expected_command,
            "source": "FBV2_POV", "runtime": asdict(result),
        })
        return QualifiedRuntimeOutcome(
            status=status, pov_id=request.pov_id,
            input_sha256=request.input_sha256, binary_sha256=binary_sha,
            runtime_receipt_path=runtime_path,
            runtime_receipt_sha256=runtime_sha,
            physical_receipt_path=physical_path,
            physical_receipt_sha256=physical_sha,
            output_summary=(result.stderr or result.stdout or "")[:8_000],
            sanitizer=result.sanitizer if status == "CRASH_OBSERVED" else None,
        )


def _record_claim_incomplete(adapter: ProductQualifiedPoVAdapter,
                             claim_dir: Path, pov_id: str, input_sha: str,
                             stage: str, exc: BaseException) -> None:
    """Record a claimed attempt's failure without masking the original error."""
    try:
        ledger_state, ledger_sha = adapter.ledger.receipt_snapshot()
        _json_new(claim_dir / "incomplete.json", {
            "kind": "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1",
            "task_id": adapter.task_id, "run_id": adapter.run_id,
            "pov_id": pov_id, "input_sha256": input_sha,
            "stage": stage, "error_type": type(exc).__name__,
            "stop_status": getattr(exc, "status", None),
            "physical_finished": len(ledger_state["finished"]),
            "physical_active": len(ledger_state["active"]),
            "physical_ledger_receipt_sha256": ledger_sha,
        })
    except BaseException as cleanup_exc:
        exc.add_note("PoV incomplete receipt failed: " +
                     type(cleanup_exc).__name__)


def _gate_trace_summary(gate: dict[str, Any], crash_id: str | None,
                        *, canonical_exists: bool) -> dict[str, Any]:
    """A pre-call marker is unresolved until the product records a return or error."""
    if not isinstance(gate, dict):
        raise ValueError("product independent Gate trace changed")
    trace = gate.get("independent_gate_trace", {})
    if not isinstance(trace, dict):
        raise ValueError("product independent Gate trace changed")
    security_state = trace.get("security_property_state", "NOT_STARTED")
    promotion_state = trace.get("promotion_state", "NOT_STARTED")
    states = {"NOT_STARTED", "STARTED", "INCOMPLETE", "COMPLETED"}
    if ((canonical_exists and trace.get("crash_id") != crash_id) or
            security_state not in states or promotion_state not in states or
            (trace.get("security_property_attempted") is True) !=
             (security_state != "NOT_STARTED") or
            (trace.get("security_property_evaluated") is True) !=
             (security_state == "COMPLETED") or
            (security_state == "INCOMPLETE") !=
             (type(trace.get("security_property_error_type")) is str) or
            (trace.get("promotion_attempted") is True) !=
             (promotion_state != "NOT_STARTED") or
            (promotion_state != "NOT_STARTED" and security_state != "COMPLETED") or
            (promotion_state == "COMPLETED") !=
             (type(trace.get("promotion_result")) is bool) or
            (promotion_state == "INCOMPLETE") !=
             (type(trace.get("promotion_error_type")) is str) or
            ((gate.get("independent_verification_status") == "VERIFIED") !=
             (promotion_state == "COMPLETED" and
              trace.get("promotion_result") is True))):
        raise ValueError("product independent Gate trace changed")
    return {
        "security_property_evaluated": security_state == "COMPLETED",
        "security_gate_state": promotion_state,
        "security_gate_invoked": (None if promotion_state == "STARTED" else
                                  promotion_state in {"INCOMPLETE", "COMPLETED"}),
        "security_gate_completed": promotion_state == "COMPLETED",
        "security_gate_result": trace.get("promotion_result"),
    }


def verify_qualified_pov_runtime_lineage(
    adapter: ProductQualifiedPoVAdapter, pov_id: str,
    model_gate: Any, *, recheck: Callable[[], None],
) -> dict[str, Any]:
    """Bind a proven model/PoV chain to this run's qualified Target receipt.

    This is post-execution provenance only.  It neither replays a process nor
    grants automatic-discovery or product Security Gate credit.
    """
    from devtools.campaign_model_gate import _private_bytes
    from devtools.model_candidate_lineage import find_candidate_lineage
    from vulnerabilityanalysis.models import RuntimeResult
    from vulnerabilityanalysis.official_harness import (
        OfficialPinnedQualification, _qualification_pins_ok)

    def unproven(reason: str) -> dict[str, Any]:
        return {"status": "UNPROVEN", "pov_id": pov_id, "reason": reason,
                "discovery_credit": "NOT_CREDITED"}

    if (type(adapter) is not ProductQualifiedPoVAdapter or
            type(pov_id) is not str or not ObjectId.is_valid(pov_id) or
            not callable(getattr(model_gate, "snapshot", None)) or
            not callable(recheck)):
        return unproven("CANDIDATE_OR_RUN_UNPROVEN")
    candidate_lineage = find_candidate_lineage(
        model_gate, adapter.repos, task_id=adapter.task_id, pov_id=pov_id)
    if (candidate_lineage.get("status") != "VERIFIED" or
            candidate_lineage.get("campaign_id") != adapter.run_id or
            candidate_lineage.get("task_id") != adapter.task_id):
        return unproven("CANDIDATE_OR_RUN_UNPROVEN")
    if type(candidate_lineage.get("pov_inputs")) is not list:
        return unproven("POV_INPUT_LINEAGE_MISSING")
    if (type(candidate_lineage.get("direction_id")) is not str or
            type(candidate_lineage.get("model_tool_turns")) is not list or
            len(candidate_lineage["model_tool_turns"]) != 3):
        return unproven("MODEL_TOOL_TURNS_MISSING")
    entries = [item for item in candidate_lineage["pov_inputs"]
               if type(item) is dict and item.get("pov_id") == pov_id]
    if len(entries) != 1 or not _SHA.fullmatch(
            str(entries[0].get("input_sha256", ""))):
        return unproven("POV_INPUT_LINEAGE_MISSING")
    try:
        recheck()
        q = adapter.binding.qualification
        if type(q) is not OfficialPinnedQualification or not _qualification_pins_ok(q):
            return unproven("OFFICIAL_QUALIFICATION_CHANGED")
        binary, binary_sha = adapter.binding.pinned_binary()
        attempt = adapter.root / pov_id
        input_path = attempt / "input.bin"
        runtime_path = attempt / "runtime.json"
        physical_path = attempt / "physical.json"
        raw_input = _private_bytes(input_path)
        raw_runtime = _private_bytes(runtime_path)
        raw_physical = _private_bytes(physical_path)
        if any(raw is None for raw in (raw_input, raw_runtime, raw_physical)):
            return unproven("QUALIFIED_RUNTIME_ARTIFACT_MISSING")
        assert raw_input is not None and raw_runtime is not None and raw_physical is not None
        input_sha = hashlib.sha256(raw_input).hexdigest()
        runtime_sha = hashlib.sha256(raw_runtime).hexdigest()
        physical_sha = hashlib.sha256(raw_physical).hexdigest()
        runtime = json.loads(raw_runtime)
        physical = json.loads(raw_physical)
        measured = RuntimeResult(**runtime["runtime"])
        saved = adapter.repos.povs.collection.find_one({"_id": ObjectId(pov_id)})
        receipt = saved.get("qualified_runtime") if isinstance(saved, dict) else None
        if (not isinstance(receipt, dict) or
                str(saved.get("task_id")) != adapter.task_id or
                str(saved.get("suspicious_point_id")) !=
                    candidate_lineage.get("sp_id") or
                saved.get("harness_name") != adapter.fuzzer or
                saved.get("sanitizer") != adapter.sanitizer or
                base64.b64decode(saved["blob"], validate=True) != raw_input or
                entries[0]["input_sha256"] != input_sha or
                runtime.get("kind") != "FBV2_DEV_QUALIFIED_POV_RUNTIME_V1" or
                physical.get("kind") != "FBV2_DEV_QUALIFIED_POV_PHYSICAL_V1" or
                runtime.get("status") not in {"CRASH_OBSERVED", "NO_CRASH"} or
                runtime.get("source") != "FBV2_POV" or
                runtime.get("command") != [str(binary), str(input_path)] or
                (runtime.get("status") == "CRASH_OBSERVED" and
                 (not measured.sanitizer or measured.exit_code in (None, 0)
                  or measured.timed_out)) or
                (runtime.get("status") == "NO_CRASH" and
                 (measured.sanitizer or measured.exit_code != 0
                  or measured.timed_out)) or
                receipt.get("status") != runtime["status"] or
                any(row.get(key) != value for row in (runtime, physical)
                    for key, value in (
                        ("task_id", adapter.task_id), ("run_id", adapter.run_id),
                        ("pov_id", pov_id),
                        ("sp_id", candidate_lineage["sp_id"]),
                        ("input_sha256", input_sha),
                        ("binary_sha256", binary_sha))) or
                runtime.get("physical_receipt_sha256") != physical_sha or
                runtime.get("input_path") != str(input_path) or
                runtime.get("work_item_id") != adapter.work_item_id or
                physical.get("input_path") != str(input_path) or
                physical.get("work_item_id") != adapter.work_item_id or
                physical.get("ledger_path") != str(adapter.ledger.path) or
                not isinstance(physical.get("lease"), dict) or
                physical["lease"].get("kind") != "AUX_PROCESS" or
                type(physical["lease"].get("key")) is not str or
                re.fullmatch(
                    re.escape(f"{adapter.task_id}:{candidate_lineage['sp_id']}:"
                              f"{pov_id}:") + r"[0-9]{6,}:pov\.qualified_direct",
                    physical["lease"]["key"]) is None or
                physical["lease"].get("cleanup_complete") is not True or
                physical["lease"].get("output_limited") is not False or
                physical["lease"].get("overrun") is not False or
                receipt.get("runtime_receipt_path") != str(runtime_path) or
                receipt.get("runtime_receipt_sha256") != runtime_sha or
                receipt.get("physical_receipt_path") != str(physical_path) or
                receipt.get("physical_receipt_sha256") != physical_sha or
                receipt.get("input_sha256") != input_sha or
                receipt.get("binary_sha256") != binary_sha or
                physical.get("lease") not in adapter.ledger.snapshot()["finished"]):
            return unproven("QUALIFIED_RUNTIME_RECEIPT_MISMATCH")
        recheck()
        if adapter.binding.pinned_binary() != (binary, binary_sha):
            return unproven("OFFICIAL_BINARY_CHANGED")
        return {
            "status": "VERIFIED", "task_id": adapter.task_id,
            "run_id": adapter.run_id, "sp_id": candidate_lineage["sp_id"],
            "direction_id": candidate_lineage["direction_id"],
            "model_tool_turns": candidate_lineage["model_tool_turns"],
            "pov_id": pov_id, "input_sha256": input_sha,
            "runtime_status": runtime["status"],
            "runtime_receipt_sha256": runtime_sha,
            "physical_receipt_sha256": physical_sha,
            "source_tree_sha256": q.source_tree_sha256,
            "harness_sha256": q.harness_sha256,
            "binary_sha256": binary_sha,
            "contract_sha256": q.contract_sha256,
            "discovery_credit": "NOT_CREDITED_BY_LINEAGE_ONLY",
        }
    except (ValueError, TypeError, KeyError, IndexError, AttributeError,
            OSError, binascii.Error, json.JSONDecodeError):
        return unproven("QUALIFIED_RUNTIME_EVIDENCE_UNPROVEN")


def consume_qualified_pov_observation(
    adapter: ProductQualifiedPoVAdapter, pov_id: str, *,
    recheck: Callable[[], None], timeout_seconds: float = 10.0,
    model_gate: Any = None,
) -> dict[str, Any]:
    """Replay one FBv2 PoV crash through the product's independent path.

    A private claim precedes every new physical launch. A failed or interrupted
    claim is never retried, and the original SP is never promoted from this
    consumer's neutral observed-crash lead.
    """
    if (type(adapter) is not ProductQualifiedPoVAdapter or
            type(pov_id) is not str or not _ID.fullmatch(pov_id) or
            not ObjectId.is_valid(pov_id) or not callable(recheck) or
            type(timeout_seconds) not in (int, float) or
            not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 10):
        raise ValueError("invalid qualified PoV observation claim")
    from vulnerabilityanalysis.models import PoC, SuspiciousPoint, RuntimeResult, stable_id
    from vulnerabilityanalysis.official_harness import OfficialPinnedQualification
    from vulnerabilityanalysis.scan import execute_poc
    from vulnerabilityanalysis.final_verification import crash_fingerprint

    recheck()
    binary, binary_sha = adapter.binding.pinned_binary()
    q = adapter.binding.qualification
    if type(q) is not OfficialPinnedQualification:
        raise ValueError("PoV observation lacks official product qualification")
    source_root, harness = q.source_root, q.harness
    attempt = adapter.root / pov_id
    input_path, runtime_path, physical_path = (
        attempt / "input.bin", attempt / "runtime.json", attempt / "physical.json")
    if (attempt.is_symlink() or not attempt.is_dir() or
            any(path.is_symlink() or not path.is_file() for path in
                (input_path, runtime_path, physical_path))):
        raise ValueError("qualified PoV observation artifacts are unavailable")
    observation = json.loads(runtime_path.read_text())
    physical = json.loads(physical_path.read_text())
    raw = adapter.repos.povs.collection.find_one({"_id": ObjectId(pov_id)})
    if (not isinstance(raw, dict) or str(raw.get("task_id")) != adapter.task_id or
            str(raw.get("suspicious_point_id")) != observation.get("sp_id")):
        raise ValueError("qualified PoV DB identity changed")
    saved = raw.get("qualified_runtime")
    if not isinstance(saved, dict):
        raise ValueError("qualified PoV DB receipt is absent")
    claimed_origin = raw.get("source")
    if (type(claimed_origin) is not str or claimed_origin not in
            {"agent", "global_fuzzer", "sp_fuzzer", "controlled_fixture"}):
        claimed_origin = "UNKNOWN"
    try:
        db_bytes = base64.b64decode(raw["blob"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("qualified PoV DB input is malformed") from exc
    input_sha = _sha(input_path)
    if (db_bytes != input_path.read_bytes() or
            observation.get("kind") != "FBV2_DEV_QUALIFIED_POV_RUNTIME_V1" or
            observation.get("task_id") != adapter.task_id or
            observation.get("run_id") != adapter.run_id or
            observation.get("pov_id") != pov_id or
            observation.get("sp_id") != str(raw["suspicious_point_id"]) or
            observation.get("status") != "CRASH_OBSERVED" or
            observation.get("input_sha256") != input_sha or
            observation.get("binary_sha256") != binary_sha or
            observation.get("input_path") != str(input_path) or
            observation.get("physical_receipt_sha256") != _sha(physical_path) or
            saved.get("status") != "CRASH_OBSERVED" or
            saved.get("input_sha256") != input_sha or
            saved.get("binary_sha256") != binary_sha or
            saved.get("runtime_receipt_path") != str(runtime_path) or
            saved.get("runtime_receipt_sha256") != _sha(runtime_path) or
            saved.get("physical_receipt_path") != str(physical_path) or
            saved.get("physical_receipt_sha256") != _sha(physical_path) or
            physical.get("kind") != "FBV2_DEV_QUALIFIED_POV_PHYSICAL_V1" or
            physical.get("task_id") != adapter.task_id or
            physical.get("run_id") != adapter.run_id or
            physical.get("pov_id") != pov_id or
            physical.get("input_sha256") != input_sha or
            physical.get("binary_sha256") != binary_sha or
            physical.get("ledger_path") != str(adapter.ledger.path)):
        raise ValueError("qualified PoV observation receipt changed")
    runtime = RuntimeResult(**observation["runtime"])
    if (not runtime.sanitizer or runtime.exit_code in (None, 0) or
            runtime.timed_out or physical.get("lease") not in
            adapter.ledger.snapshot()["finished"]):
        raise ValueError("qualified PoV crash or physical debit is unproven")

    # Derive origin from the same durable model/tool and qualified Runtime
    # evidence. A caller-supplied label or the PoV DB source is not proof.
    lineage = ({"status": "UNPROVEN", "reason": "MODEL_GATE_NOT_SUPPLIED"}
               if model_gate is None else
               verify_qualified_pov_runtime_lineage(
                   adapter, pov_id, model_gate, recheck=recheck))
    origin_verified = (
        lineage.get("status") == "VERIFIED" and
        claimed_origin == "agent" and
        all(lineage.get(key) == value for key, value in (
            ("task_id", adapter.task_id), ("run_id", adapter.run_id),
            ("sp_id", str(raw["suspicious_point_id"])), ("pov_id", pov_id),
            ("input_sha256", input_sha), ("binary_sha256", binary_sha),
            ("source_tree_sha256", q.source_tree_sha256),
            ("harness_sha256", q.harness_sha256),
            ("contract_sha256", q.contract_sha256))))
    if lineage.get("status") == "VERIFIED" and not origin_verified:
        lineage = {"status": "UNPROVEN", "reason": "ORIGIN_IDENTITY_MISMATCH"}
    origin_status = ("VERIFIED_MODEL_TOOL_RUNTIME_LINEAGE" if origin_verified
                     else "UNVERIFIED_LINEAGE")

    # The claim directory's exclusive creation makes even an interrupted
    # consumer terminal; a later invocation cannot re-execute the input.
    validation_root = adapter.root.parent / "pov-validation"
    if validation_root.is_symlink():
        raise ValueError("PoV validation root is linked")
    new_validation_root = not validation_root.exists()
    validation_root.mkdir(mode=0o700, exist_ok=True)
    if new_validation_root:
        parent_fd = os.open(validation_root.parent,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    claim_dir = validation_root / pov_id
    claim_dir.mkdir(mode=0o700, exist_ok=False)
    try:
        root_fd = os.open(validation_root,
                          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        _json_new(claim_dir / "claim.json", {
            "kind": "FBV2_POV_GATE_CLAIM_V1", "task_id": adapter.task_id,
            "run_id": adapter.run_id, "pov_id": pov_id,
            "sp_id": str(raw["suspicious_point_id"]),
            "input_sha256": input_sha, "binary_sha256": binary_sha,
            "original_runtime_receipt_sha256": _sha(runtime_path),
            "original_physical_receipt_sha256": _sha(physical_path),
        })
        origin_path = claim_dir / "origin-lineage.json"
        origin_sha256 = _json_new(origin_path, {
            "kind": "FBV2_POV_PRODUCT_ORIGIN_LINEAGE_V1",
            "task_id": adapter.task_id, "run_id": adapter.run_id,
            "pov_id": pov_id, "input_sha256": input_sha,
            "origin_verification_status": origin_status,
            "lineage": lineage,
            "automatic_discovery": False,
            "discovery_credit": "NOT_CREDITED",
        })
        retained = claim_dir / "input.bin"
        _write_new(retained, input_path.read_bytes())
        product_run = claim_dir / "product"
        product_run.mkdir(mode=0o700)
        _json_new(product_run / "run.json", {
            "run_id": adapter.run_id, "source": "FBV2_POV_OBSERVATION",
            "claimed_input_origin": claimed_origin,
            "origin_verification_status": origin_status,
            "origin_lineage_receipt_path": str(origin_path),
            "origin_lineage_receipt_sha256": origin_sha256,
            "automatic_discovery": False,
        })

        def pin(_phase: str, _command: list[str]) -> None:
            recheck()
            same_binary, same_sha = adapter.binding.pinned_binary()
            if (same_binary != binary or same_sha != binary_sha or
                    _sha(origin_path) != origin_sha256 or
                    (origin_verified and
                     verify_qualified_pov_runtime_lineage(
                         adapter, pov_id, model_gate,
                         recheck=recheck) != lineage) or
                    _sha(retained) != input_sha or _sha(input_path) != input_sha or
                    _sha(runtime_path) != saved["runtime_receipt_sha256"] or
                    _sha(physical_path) != saved["physical_receipt_sha256"]):
                raise ValueError("PoV observation changed before product replay")

        envelope = adapter._envelope_type(
            adapter.ledger, work_item_id=adapter.task_id,
            assertion_id=str(raw["suspicious_point_id"]),
            attempt_id=pov_id + "_gate", output_limit_bytes=adapter.output_limit_bytes,
            total_wall_seconds=adapter.wall_seconds, pin_hook=pin)
        lead_id = stable_id("fbv2-pov-lead", adapter.task_id, pov_id, input_sha)
        product_pov_id = stable_id("poc", "fbv2-pov-observation", pov_id, input_sha)
        lead = SuspiciousPoint(
            lead_id, "FBV2_POV_OBSERVATION", "FBV2_POV_OBSERVATION", "UNKNOWN", None,
            "UNKNOWN", "unclassified FBv2 PoV crash input",
            "unverified sanitizer observation", [], "UNKNOWN", [], [], [],
            ["original FBv2 SP relation is not presumed"])
        poc = PoC(product_pov_id, lead_id,
                  "from pathlib import Path\ndef build():\n"
                  "    return Path(__file__).with_name('input.bin').read_bytes()\n",
                  str(retained), [str(binary), "{input}"],
                  "replay qualified FBv2 PoV observation")
    except BaseException as exc:
        _record_claim_incomplete(adapter, claim_dir, pov_id, input_sha,
                                 "PRE_EXECUTE_SETUP", exc)
        raise
    try:
        execute_poc(
            poc, lead, [str(binary), "{input}"], product_run,
            target_repository=source_root, harness_path=harness,
            target_binary=binary, official_qualification=q,
            timeout_seconds=float(timeout_seconds), process_envelope=envelope)
    except BaseException as exc:
        # A process may already have been launched and debited. Keep the
        # original error and leave the exclusive claim terminal on failure.
        _record_claim_incomplete(adapter, claim_dir, pov_id, input_sha,
                                 "PRODUCT_EXECUTION", exc)
        raise
    try:
        if (_sha(origin_path) != origin_sha256 or
                (origin_verified and
                 verify_qualified_pov_runtime_lineage(
                     adapter, pov_id, model_gate,
                     recheck=recheck) != lineage)):
            raise ValueError("PoV origin lineage changed during product replay")
        product_runtime = product_run / "runtime" / f"{product_pov_id}.json"
        actual = RuntimeResult(**json.loads(product_runtime.read_text()))
        crash_id = crash_fingerprint(actual) if actual.sanitizer else None
        canonical = (product_run / "runtime" / "crashes" / f"{crash_id}.json"
                     if crash_id else None)
        gate = json.loads(canonical.read_text()) if canonical and canonical.is_file() else {}
        trace_summary = _gate_trace_summary(
            gate, crash_id, canonical_exists=bool(canonical and canonical.is_file()))
        outcome = {
            "kind": "FBV2_POV_PRODUCT_GATE_OUTCOME_V1",
            "task_id": adapter.task_id, "run_id": adapter.run_id,
            "sp_id": str(raw["suspicious_point_id"]), "pov_id": pov_id,
            "input_sha256": input_sha, "binary_sha256": binary_sha,
            "source": "FBV2_POV_OBSERVATION", "automatic_discovery": False,
            "claimed_input_origin": claimed_origin,
            "origin_verification_status": origin_status,
            "origin_lineage_receipt_path": str(origin_path),
            "origin_lineage_receipt_sha256": origin_sha256,
            "discovery_credit": "NOT_CREDITED",
            "product_runtime_artifact": str(product_runtime),
            "product_runtime_sha256": _sha(product_runtime),
            "canonical_crash_artifact": str(canonical) if canonical and canonical.is_file() else None,
            "canonical_crash_sha256": _sha(canonical) if canonical and canonical.is_file() else None,
            "product_gate_status": gate.get("independent_verification_status", "NOT_VERIFIED"),
            **trace_summary,
            "observed_sanitizer": actual.sanitizer,
        }
        _json_new(claim_dir / "outcome.json", outcome)
        return outcome
    except BaseException as exc:
        _record_claim_incomplete(adapter, claim_dir, pov_id, input_sha,
                                 "PRODUCT_POSTPROCESS", exc)
        raise


def run_qualified_sp_fuzz(
    adapter: ProductQualifiedPoVAdapter, pov_id: str, model_gate: Any, *,
    recheck: Callable[[], None], seconds: int, fuzz_wall_seconds: float,
    replay_wall_seconds: float = 600.0, replay_limit: int = 1,
) -> dict[str, Any]:
    """Fuzz a completed, noncrashing model PoV with the product V2 process account.

    This is a post-PoV development handoff, not the original concurrent
    Docker SP Fuzzer. It never awards automatic-discovery credit. A journaled
    PoV claim precedes the libFuzzer probe, and an interrupted claim cannot be
    replayed under a new process ledger.
    """
    from devtools.campaign_model_gate import _private_bytes
    from vulnerabilityanalysis.analysis import RetryLedger
    from vulnerabilityanalysis.fuzzer_crash_consumer import (
        consume_fuzzer_crash_observation)
    from vulnerabilityanalysis.models import RuntimeResult, SuspiciousPoint
    from vulnerabilityanalysis.official_harness import (
        OfficialPinnedQualification, _qualification_pins_ok)
    from vulnerabilityanalysis.scan import (
        _plain_targeted_replay_input, record_targeted_fuzzer_observations,
        run_targeted_fuzz)

    if (type(adapter) is not ProductQualifiedPoVAdapter or
            type(pov_id) is not str or not ObjectId.is_valid(pov_id) or
            not callable(recheck) or
            not callable(getattr(model_gate, "snapshot", None)) or
            type(seconds) is not int or not 1 <= seconds <= 60 or
            type(replay_limit) is not int or not 0 <= replay_limit <= 1 or
            type(fuzz_wall_seconds) not in (int, float) or
            not math.isfinite(fuzz_wall_seconds) or
            fuzz_wall_seconds < seconds + 39 or fuzz_wall_seconds > 180 or
            type(replay_wall_seconds) not in (int, float) or
            not math.isfinite(replay_wall_seconds) or
            replay_wall_seconds < 20 or replay_wall_seconds > 600):
        raise ValueError("SP Fuzzer physical cap or provenance is invalid")
    recheck()
    q = adapter.binding.qualification
    if type(q) is not OfficialPinnedQualification or not _qualification_pins_ok(q):
        raise ValueError("SP Fuzzer needs the pinned product V2 qualification")
    binary, binary_sha = adapter.binding.pinned_binary()
    lineage = verify_qualified_pov_runtime_lineage(
        adapter, pov_id, model_gate, recheck=recheck)
    if (lineage.get("status") != "VERIFIED" or
            lineage.get("runtime_status") != "NO_CRASH" or
            lineage.get("task_id") != adapter.task_id or
            lineage.get("run_id") != adapter.run_id or
            lineage.get("pov_id") != pov_id or
            lineage.get("binary_sha256") != binary_sha or
            lineage.get("source_tree_sha256") != q.source_tree_sha256 or
            lineage.get("harness_sha256") != q.harness_sha256 or
            lineage.get("contract_sha256") != q.contract_sha256 or
            type(lineage.get("direction_id")) is not str or
            type(lineage.get("sp_id")) is not str or
            not ObjectId.is_valid(lineage["sp_id"]) or
            type(lineage.get("input_sha256")) is not str or
            not _SHA.fullmatch(lineage["input_sha256"])):
        raise ValueError("completed model PoV input lineage is unproven")
    sp_id = lineage["sp_id"]
    input_sha = lineage["input_sha256"]
    original_input = adapter.root / pov_id / "input.bin"
    raw_input = _private_bytes(original_input)
    if raw_input is None or hashlib.sha256(raw_input).hexdigest() != input_sha:
        raise ValueError("qualified PoV bytes changed before SP fuzz")
    saved = adapter.repos.povs.collection.find_one({"_id": ObjectId(pov_id)})
    if (not isinstance(saved, dict) or saved.get("source") != "agent" or
            str(saved.get("task_id")) != adapter.task_id or
            str(saved.get("suspicious_point_id")) != sp_id or
            not isinstance(saved.get("qualified_runtime"), dict) or
            saved["qualified_runtime"].get("status") != "NO_CRASH"):
        raise ValueError("PoV is not an eligible model-generated SP seed")
    process, starting_ledger_sha = adapter.ledger.receipt_snapshot()
    if process.get("stop_status") is not None or process.get("active"):
        raise ValueError("SP fuzz requires a settled shared process account")
    run_dir = adapter.root.parent
    if (run_dir.is_symlink() or not run_dir.is_dir() or
            run_dir.resolve() != run_dir or
            (run_dir / "sp-fuzz-claims").is_symlink() or
            any(path.is_symlink() for path in
                (run_dir / "corpus", run_dir / "corpus" / "candidate",
                 run_dir / "runtime", run_dir / "runtime" / "fuzzer_crashes"))):
        raise ValueError("SP fuzz run directory is untrusted")
    claim_root = run_dir / "sp-fuzz-claims"
    run_claim = claim_root / "run-wide-one-item.json"
    corpus = run_dir / "corpus" / "candidate" / sp_id
    runtime_artifact = run_dir / "runtime" / f"{sp_id}.targeted_fuzz.json"
    seed_artifact = run_dir / "runtime" / f"{sp_id}.targeted_fuzz.seeds.json"
    blocked_artifact = run_dir / "runtime" / f"{sp_id}.targeted_fuzz.blocked.json"
    if (run_claim.exists() or run_claim.is_symlink() or
            (claim_root / sp_id).exists() or corpus.exists() or corpus.is_symlink() or
            any(path.exists() or path.is_symlink() for path in
                (runtime_artifact, seed_artifact, blocked_artifact))):
        raise RuntimeError("SP Fuzzer already claimed this candidate")

    # Mongo's journaled conditional update is the cross-run claim. The
    # directory and envelope each add a local exclusive boundary.
    collection = adapter.repos.povs.collection.with_options(
        write_concern=WriteConcern(w=1, j=True))
    claim_row = {"kind": "FBV2_QUALIFIED_SP_FUZZ_CLAIM_V1",
                 "status": "STARTED", "task_id": adapter.task_id,
                 "run_id": adapter.run_id, "sp_id": sp_id, "pov_id": pov_id,
                 "input_sha256": input_sha, "binary_sha256": binary_sha,
                 "ledger_path": str(adapter.ledger.path)}
    # This development path permits one SP item per run, even if a different
    # PoV is later offered with a settled ledger. O_EXCL is the durable claim.
    claim_root.mkdir(mode=0o700, exist_ok=True)
    run_claim_sha = _json_new(run_claim, claim_row)
    try:
        changed = collection.update_one(
            {"_id": ObjectId(pov_id), "task_id": ObjectId(adapter.task_id),
             "suspicious_point_id": ObjectId(sp_id), "source": "agent",
             "qualified_runtime.status": "NO_CRASH",
             "qualified_runtime.input_sha256": input_sha,
             "qualified_runtime.binary_sha256": binary_sha,
             "sp_fuzz_claim": {"$exists": False}},
            {"$set": {"sp_fuzz_claim": claim_row}})
        if changed.acknowledged is not True or changed.modified_count != 1:
            raise RuntimeError("qualified SP fuzz already claimed or changed")
    except BaseException as claim_error:
        failure_dir = claim_root / sp_id
        failure_dir.mkdir(mode=0o700, exist_ok=True)
        _json_new(failure_dir / "incomplete.json", {
            "kind": "FBV2_QUALIFIED_SP_FUZZ_INCOMPLETE_V1",
            "task_id": adapter.task_id, "run_id": adapter.run_id,
            "sp_id": sp_id, "pov_id": pov_id, "stage": "DB_CLAIM",
            "error_type": type(claim_error).__name__,
            "input_sha256": input_sha, "binary_sha256": binary_sha,
        })
        raise

    stage = "CLAIM"
    claim_dir = claim_root / sp_id
    try:
        claim_root.mkdir(mode=0o700, exist_ok=True)
        claim_dir.mkdir(mode=0o700, exist_ok=False)
        _json_new(claim_dir / "claim.json", claim_row)
        corpus.mkdir(parents=True, mode=0o700, exist_ok=False)
        seed = corpus / (pov_id + ".bin")
        _write_new(seed, raw_input)

        def pin(_phase: str, _command: list[str]) -> None:
            recheck()
            same_binary, same_sha = adapter.binding.pinned_binary()
            refreshed = verify_qualified_pov_runtime_lineage(
                adapter, pov_id, model_gate, recheck=recheck)
            db_row = adapter.repos.povs.collection.find_one({"_id": ObjectId(pov_id)})
            if (same_binary != binary or same_sha != binary_sha or
                    not _qualification_pins_ok(q) or
                    refreshed != lineage or
                    not isinstance(db_row, dict) or
                    db_row.get("sp_fuzz_claim") != claim_row or
                    _sha(seed) != input_sha or
                    _sha(original_input) != input_sha or
                    _sha(run_claim) != run_claim_sha or
                    _sha(claim_dir / "claim.json") !=
                    hashlib.sha256((json.dumps(claim_row, sort_keys=True,
                        separators=(",", ":"), allow_nan=False) + "\n").encode()).hexdigest()):
                raise ValueError("SP fuzz source, PoV, seed, or binary pin changed")
            if (_phase in {"before_reserve", "after_reserve_before_launch"} and
                    any(arg.startswith("-max_total_time=") for arg in _command)):
                if (corpus.is_symlink() or
                        {path.name for path in corpus.iterdir()} != {seed.name} or
                        not seed.is_file() or seed.is_symlink()):
                    raise ValueError("SP fuzz candidate corpus changed before launch")

        envelope = adapter._envelope_type(
            adapter.ledger, work_item_id=adapter.task_id,
            assertion_id=sp_id, attempt_id=pov_id + "_sp_fuzz",
            output_limit_bytes=adapter.output_limit_bytes,
            total_wall_seconds=fuzz_wall_seconds, pin_hook=pin)
        stage = "TARGETED_FUZZ"
        fuzz_result = run_targeted_fuzz(
            SuspiciousPoint(sp_id, "FBV2_SP_FUZZ", lineage["direction_id"],
                            "UNKNOWN", None, "UNKNOWN", "PoV seed",
                            "candidate-specific fuzz exploration", [], "UNKNOWN",
                            [], [], [], ["model hypothesis not independently verified"]),
            binary, run_dir, RetryLedger(1), [], seconds=seconds,
            process_envelope=envelope)
        if fuzz_result is None:
            raise RuntimeError("qualified SP Fuzzer returned no result")
        # A product helper can return RAN with a plausible JSON artifact while
        # having launched nothing. The shared V2 ledger is the physical proof.
        after_fuzzer, after_fuzzer_sha = adapter.ledger.receipt_snapshot()
        previous = process["finished"]
        finished = after_fuzzer["finished"]
        new_leases = finished[len(previous):]
        prefix = f"{adapter.task_id}:{sp_id}:{pov_id}_sp_fuzz:"
        expected = (
            (f"{prefix}000000:sp.libfuzzer_help", "AUX_PROCESS"),
            (f"{prefix}000001:sp.campaign", "SP_FUZZ"),
        )
        if (finished[:len(previous)] != previous or
                len(new_leases) != 2 or
                after_fuzzer.get("active") or
                after_fuzzer.get("stop_status") is not None or
                any(row.get("key") != key or row.get("kind") != kind or
                    row.get("cleanup_complete") is not True or
                    row.get("output_limited") is not False or
                    row.get("overrun") is not False or
                    type(row.get("physical_seconds")) not in (int, float) or
                    row["physical_seconds"] <= 0
                    for row, (key, kind) in zip(new_leases, expected)) or
                not math.isclose(
                    after_fuzzer["wall_spent_seconds"] - process["wall_spent_seconds"],
                    math.fsum(row["physical_seconds"] for row in new_leases),
                    abs_tol=1e-9, rel_tol=1e-9) or
                not math.isclose(
                    after_fuzzer["fuzz_spent_seconds"] - process["fuzz_spent_seconds"],
                    new_leases[1]["physical_seconds"],
                    abs_tol=1e-9, rel_tol=1e-9)):
            raise RuntimeError("SP Fuzzer two physical V2 leases are unproven")
        seed_report_path = run_dir / "runtime" / f"{sp_id}.targeted_fuzz.seeds.json"
        seed_report = json.loads(seed_report_path.read_text())
        if not isinstance(seed_report, dict):
            raise ValueError("SP Fuzzer seed report is invalid")
        attempt_id = seed_report.get("attempt_id")
        if (type(attempt_id) is not str or
                re.fullmatch(r"attempt-[A-Za-z0-9_-]+", attempt_id) is None):
            raise ValueError("SP Fuzzer immutable attempt ID is missing")
        attempt_dir = (run_dir / "runtime" / "targeted_fuzz_attempts" /
                       sp_id / attempt_id)
        immutable_seeds = attempt_dir / "seeds.json"
        immutable_runtime = attempt_dir / "runtime.json"
        if (any(path.is_symlink() for path in
                    (attempt_dir.parent.parent, attempt_dir.parent, attempt_dir,
                     immutable_seeds, immutable_runtime)) or
                seed_report.get("attempt_seed_artifact") != str(immutable_seeds) or
                seed_report.get("attempt_runtime_artifact") != str(immutable_runtime) or
                seed_report.get("attempt_runtime_sha256") != _sha(immutable_runtime) or
                json.loads(immutable_seeds.read_text()) != seed_report or
                seed_report.get("sp_id") != sp_id or
                seed_report.get("binary_sha256") != binary_sha or
                seed_report.get("initial_seed_hashes") != [input_sha]):
            raise ValueError("SP Fuzzer immutable attempt receipt changed")
        raw_runtime = json.loads(immutable_runtime.read_text())
        if not isinstance(raw_runtime, dict):
            raise ValueError("SP Fuzzer runtime receipt is invalid")
        try:
            measured = RuntimeResult(**raw_runtime)
        except TypeError as exc:
            raise ValueError("SP Fuzzer runtime receipt fields are missing") from exc
        if (type(measured.timed_out) is not bool or
                type(measured.stderr) is not str or
                type(measured.failure_classification) is not str or
                type(measured.exit_code) not in (int, type(None)) or
                type(measured.sanitizer) not in (str, type(None))):
            raise ValueError("SP Fuzzer runtime fields are invalid")
        progress = [(int(count), event) for count, event in re.findall(
            r"(?m)^#(\d+)\s+(INITED|NEW|REDUCE|pulse|DONE)\b",
            measured.stderr)]
        mutation_proven = any(count > 1 and event != "INITED"
                              for count, event in progress)
        observed_inputs = (seed_report.get("crash_inputs") or []) + (
            seed_report.get("pending_crash_inputs") or [])
        expected_status = (
            "TIMED_OUT" if measured.timed_out else
            "ERROR" if measured.failure_classification == "ENVIRONMENT_ERROR" else
            "CRASH_OBSERVED_INCOMPLETE" if observed_inputs or measured.sanitizer else
            "ERROR" if measured.exit_code != 0 else
            "RAN" if mutation_proven else "INCOMPLETE_NO_FUZZ_EVIDENCE")
        if (seed_report.get("status") != expected_status or
                seed_report.get("mutation_proven") is not mutation_proven or
                seed_report.get("exit_code") != measured.exit_code or
                seed_report.get("coverage_feedback") != measured.coverage or
                seed_report.get("observed_executions_max") !=
                    max((count for count, _ in progress), default=None) or
                seed_report.get("requested_seconds") != seconds):
            raise ValueError("SP Fuzzer status conflicts with physical runtime receipt")
        if (any(not isinstance(row, dict) or
                row.get("attempt_id") != attempt_id or
                row.get("attempt_witness_artifact") != row.get("candidate_path") or
                not _plain_targeted_replay_input(run_dir, sp_id, row)
                for row in observed_inputs)):
            raise ValueError("SP Fuzzer retained Crash witness is unproven")
        timed_out_witness = expected_status == "TIMED_OUT" and bool(observed_inputs)
        if (seed_report.get("status") not in
                {"RAN", "CRASH_OBSERVED_INCOMPLETE"} and
                not timed_out_witness):
            raise RuntimeError("SP Fuzzer did not complete a valid fuzz campaign")
        crash_ids = record_targeted_fuzzer_observations(
            run_dir, sp_id, seed_report)
        if not isinstance(crash_ids, set):
            raise RuntimeError("SP Fuzzer Crash index is unavailable")
        stage = "CRASH_CONSUMER"
        consumer_rows = []
        replay_inputs = seed_report.get("crash_inputs") or []
        for row in replay_inputs[:replay_limit]:
            pin("before_consumer", [str(binary), "{input}"])
            replay_envelope = adapter._envelope_type(
                adapter.ledger, work_item_id=adapter.task_id,
                assertion_id=sp_id,
                attempt_id=pov_id + "_sp_consumer",
                output_limit_bytes=adapter.output_limit_bytes,
                total_wall_seconds=replay_wall_seconds, pin_hook=pin)
            consumer_rows.append(consume_fuzzer_crash_observation(
                run_dir, row["observed_crash_id"], row["sha256"],
                binary=binary, expected_binary_sha256=binary_sha,
                command=[str(binary), "{input}"],
                target_repository=q.source_root, harness_path=q.harness,
                official_qualification=q, process_envelope=replay_envelope,
                timeout_seconds=10.0))
        if len(replay_inputs) > replay_limit:
            consumer_rows.extend({"status": "PENDING_REPLAY_LIMIT",
                                  "input_sha256": row["sha256"]}
                                 for row in replay_inputs[replay_limit:])
        if seed_report.get("pending_crash_inputs"):
            consumer_rows.extend({"status": "PENDING_OVERSIZE_INPUT",
                                  "input_sha256": row.get("sha256")}
                                 for row in seed_report["pending_crash_inputs"])
        snapshot, ledger_sha = adapter.ledger.receipt_snapshot()
        if snapshot["stop_status"] is not None or snapshot["active"]:
            raise RuntimeError("SP Fuzzer process account did not settle cleanly")
        before_consumer = after_fuzzer["finished"]
        finished = snapshot["finished"]
        consumer_leases = finished[len(before_consumer):]
        consumer_prefix = f"{adapter.task_id}:{sp_id}:{pov_id}_sp_consumer:"
        if (finished[:len(before_consumer)] != before_consumer or
                any(type(row.get("key")) is not str or
                    not row["key"].startswith(
                        f"{consumer_prefix}{ordinal:06d}:") or
                    re.fullmatch(r"[A-Za-z0-9_.-]+",
                        row["key"].removeprefix(
                            f"{consumer_prefix}{ordinal:06d}:")) is None or
                    row.get("kind") != "AUX_PROCESS" or
                    row.get("cleanup_complete") is not True or
                    row.get("output_limited") is not False or
                    row.get("overrun") is not False or
                    type(row.get("physical_seconds")) not in (int, float) or
                    row["physical_seconds"] <= 0
                    for ordinal, row in enumerate(consumer_leases)) or
                not math.isclose(
                    snapshot["wall_spent_seconds"] -
                    after_fuzzer["wall_spent_seconds"],
                    math.fsum(row["physical_seconds"] for row in consumer_leases),
                    abs_tol=1e-9, rel_tol=1e-9) or
                not math.isclose(
                    snapshot["fuzz_spent_seconds"],
                    after_fuzzer["fuzz_spent_seconds"],
                    abs_tol=1e-9, rel_tol=1e-9)):
            raise RuntimeError("SP Fuzzer Consumer physical AUX leases are unproven")
        outcome = {
            "kind": "FBV2_QUALIFIED_SP_FUZZ_OUTCOME_V1",
            "status": "INCOMPLETE_FUZZ_WITH_OBSERVED_CRASH" if timed_out_witness else
                "PENDING_INDEPENDENT_VALIDATION" if crash_ids and
                (not consumer_rows or any(row.get("status") != "VERIFIED"
                                          for row in consumer_rows)) else
                "EXECUTED", "task_id": adapter.task_id, "run_id": adapter.run_id,
            "sp_id": sp_id, "pov_id": pov_id, "input_sha256": input_sha,
            "binary_sha256": binary_sha, "fuzzer_status":
                seed_report.get("status"), "crash_ids": sorted(crash_ids),
            "attempt_seed_receipt_path": str(immutable_seeds),
            "attempt_seed_receipt_sha256": _sha(immutable_seeds),
            "attempt_runtime_receipt_path": str(immutable_runtime),
            "attempt_runtime_receipt_sha256": _sha(immutable_runtime),
            "starting_process_ledger_sha256": starting_ledger_sha,
            "after_fuzzer_process_ledger_sha256": after_fuzzer_sha,
            "fuzzer_physical_lease_keys": [row["key"] for row in new_leases],
            "consumer_physical_lease_keys": [row["key"] for row in consumer_leases],
            "consumer_rows": consumer_rows,
            "process_ledger_sha256": ledger_sha,
            "process_wall_seconds": snapshot["wall_spent_seconds"],
            "process_fuzz_seconds": snapshot["fuzz_spent_seconds"],
            "automatic_discovery": False, "discovery_credit": "NOT_CREDITED",
        }
        outcome_path = claim_dir / "outcome.json"
        outcome_sha = _json_new(outcome_path, outcome)
        settled = collection.update_one(
            {"_id": ObjectId(pov_id), "sp_fuzz_claim": claim_row},
            {"$set": {"sp_fuzz_claim": {**claim_row, "status": "COMPLETED",
                                       "outcome_path": str(outcome_path),
                                       "outcome_sha256": outcome_sha}}})
        if settled.acknowledged is not True or settled.modified_count != 1:
            raise RuntimeError("SP Fuzzer result was not journaled")
        return outcome
    except BaseException as original:
        try:
            claim_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not (claim_dir / "incomplete.json").exists():
                _json_new(claim_dir / "incomplete.json", {
                    "kind": "FBV2_QUALIFIED_SP_FUZZ_INCOMPLETE_V1",
                    "task_id": adapter.task_id, "run_id": adapter.run_id,
                    "sp_id": sp_id, "pov_id": pov_id, "stage": stage,
                    "error_type": type(original).__name__,
                    "input_sha256": input_sha, "binary_sha256": binary_sha,
                })
            collection.update_one(
                {"_id": ObjectId(pov_id), "sp_fuzz_claim": claim_row},
                {"$set": {"sp_fuzz_claim": {**claim_row,
                                            "status": "INCOMPLETE",
                                            "stage": stage,
                                            "error_type": type(original).__name__}}})
        except BaseException as cleanup:
            original.add_note("SP Fuzzer incomplete receipt failed: " +
                              type(cleanup).__name__)
        raise
