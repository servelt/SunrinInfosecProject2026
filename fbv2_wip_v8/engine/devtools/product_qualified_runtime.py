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
import stat
import time
import inspect
from typing import Any, Callable

from bson import ObjectId
from pymongo.write_concern import WriteConcern

from fuzzingbrain.core.models.suspicious_point import SPStatus
from fuzzingbrain.tools.qualified_runtime import (
    QualifiedGeneratorRequest, QualifiedRuntimeBinding, QualifiedRuntimeOutcome,
    QualifiedRuntimeRequest,
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


def _canonical_json_sha256(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _bounded_regular_bytes(
    path: Path, *, limit: int = 16_000_000, require_owner: bool = True,
    require_single_link: bool = True,
) -> bytes:
    """Read a pinned source without following links or accepting special files."""
    path = Path(path)
    if (not path.is_absolute() or path != path.resolve(strict=False) or
            path.is_symlink() or any(parent.is_symlink() for parent in path.parents)):
        raise ValueError("source evidence path is not canonical")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or
                require_owner and info.st_uid != os.getuid() or
                require_single_link and info.st_nlink != 1 or
                info.st_size > limit):
            raise ValueError("source evidence file is unsafe")
        data = os.read(fd, limit + 1)
        if len(data) != info.st_size:
            raise ValueError("source evidence changed while reading")
        current = os.lstat(path)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("source evidence was replaced")
        return data
    finally:
        os.close(fd)


class ProductQualifiedPoVAdapter:
    """One task's bounded direct PoV observation with a durable process debit."""

    def __init__(self, *, qualification: Any, repos: Any, task_id: str,
                 work_item_id: str, run_id: str, fuzzer: str, sanitizer: str,
                 ledger: Any, output_dir: Path, timeout_seconds: float,
                 wall_seconds: float, output_limit_bytes: int,
                 seed_pin_hook: Callable[[str, list[str]], None] | None = None):
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
        binding = QualifiedRuntimeBinding(qualification, self.execute,
                                          self.generate)
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
        self._seed_pin_hook = seed_pin_hook
        self._envelope_type = DevelopmentProcessEnvelopeV2
        self._runtime_type = RuntimeExecutor

    def generate_seed(self, *, task_id: str, direction_id: str,
                      worker_id: str, attempt: int, code: str,
                      num_seeds: int) -> list[bytes]:
        """Charge one Direction Seed sandbox to this campaign's V2 ledger.

        Seed agents may run concurrently, so each call uses a distinct key
        instead of sharing an envelope's in-memory ordinal.
        """
        from fuzzingbrain.fuzzer.seed_sandbox import (
            DOCKER_CLEANUP_SECONDS, DOCKER_TIMEOUT_SECONDS,
            SeedSandboxCleanupError, SeedSandboxError,
            SeedSandboxOutputLimitError, execute_seed_generator,
        )

        direction = (self.repos.directions.find_by_id(direction_id)
                     if type(direction_id) is str and _ID.fullmatch(direction_id)
                     else None)
        if (not callable(self._seed_pin_hook) or task_id != self.task_id or
                direction is None or direction.task_id != self.task_id or
                direction.fuzzer != self.fuzzer or
                type(worker_id) is not str or not _ID.fullmatch(worker_id) or
                type(attempt) is not int or attempt < 1 or
                type(code) is not str or
                type(num_seeds) is not int):
            raise SeedSandboxError("qualified Direction Seed identity changed")
        self.binding.pinned_binary()
        # The physical attempt is one-shot even if a caller changes code.
        # Model tool-event evidence separately pins the generator arguments.
        key = (f"{self.task_id}:{direction_id}:seed_generator:"
               f"{worker_id}:{attempt}")
        try:
            self._seed_pin_hook("before_seed_reserve", [])
        except BaseException as exc:
            self.ledger.mark_stop("STOPPED_PIN_DRIFT", "Seed source pin changed")
            raise SeedSandboxError("qualified Direction Seed source pin changed") from exc
        # Existing PoV generator reservation: image inspection, Docker run,
        # CLI reap, and bounded removal/absence checks are one physical lease.
        reserved = (5.0 + DOCKER_TIMEOUT_SECONDS + 2.0 +
                    3.0 * DOCKER_CLEANUP_SECONDS + 5.0)
        self.ledger.reserve(key, "AUX_PROCESS", reserved)
        started = time.monotonic()
        cleanup_complete = False
        cleanup_uncertain = False
        output_limited = False
        try:
            try:
                seeds = execute_seed_generator(code, num_seeds)
            except SeedSandboxOutputLimitError:
                cleanup_complete = True
                output_limited = True
                raise
            except SeedSandboxCleanupError:
                cleanup_uncertain = True
                raise
            except SeedSandboxError:
                cleanup_complete = True
                raise
            cleanup_complete = True
            return seeds
        finally:
            try:
                row = self.ledger.finish(
                    key, physical_seconds=time.monotonic() - started,
                    cleanup_complete=cleanup_complete,
                    output_limited=output_limited)
            except BaseException as exc:
                raise SeedSandboxCleanupError(
                    "Direction Seed physical settlement is uncertain") from exc
            if not cleanup_uncertain:
                if row["overrun"] or self.ledger.snapshot()["stop_status"] is not None:
                    raise SeedSandboxError("Direction Seed physical account stopped")
                try:
                    self._seed_pin_hook("after_seed_process", [])
                except BaseException as exc:
                    self.ledger.mark_stop("STOPPED_PIN_DRIFT", "Seed source pin changed")
                    raise SeedSandboxError(
                        "qualified Direction Seed source pin changed") from exc

    def generate(self, request: QualifiedGeneratorRequest) -> list[bytes]:
        """Account one pinned Docker generator as an auxiliary physical process."""
        from fuzzingbrain.fuzzer.seed_sandbox import (
            DOCKER_CLEANUP_SECONDS, DOCKER_TIMEOUT_SECONDS,
            SeedSandboxCleanupError, SeedSandboxError,
            SeedSandboxOutputLimitError, execute_seed_generator,
        )

        if (type(request) is not QualifiedGeneratorRequest or
                request.task_id != self.task_id or
                any(type(value) is not str or not _ID.fullmatch(value)
                    for value in (request.suspicious_point_id,
                                  request.worker_id)) or
                type(request.attempt) is not int or request.attempt < 1 or
                type(request.code) is not str or
                type(request.num_variants) is not int):
            raise ValueError("qualified PoV generator identity changed")
        point = self.repos.suspicious_points.find_by_id(
            request.suspicious_point_id)
        if (point is None or point.task_id != self.task_id or
                point.status != SPStatus.GENERATING_POV.value or
                not any(source.get("harness_name") == self.fuzzer and
                            source.get("sanitizer") == self.sanitizer
                            for source in point.sources)):
            raise ValueError("PoV generator SP is not an eligible claimed candidate")
        self.binding.pinned_binary()
        code_sha = hashlib.sha256(request.code.encode("utf-8")).hexdigest()
        key = (f"{self.task_id}:{request.suspicious_point_id}:"
               f"pov_generator:{request.worker_id}:{request.attempt}:{code_sha}")
        # Image inspection (5s), Docker run (15s), CLI reap (2s), and up to
        # three cleanup subprocesses (6s each), plus bounded local overhead.
        reserved = 5.0 + DOCKER_TIMEOUT_SECONDS + 2.0 + \
            3.0 * DOCKER_CLEANUP_SECONDS + 5.0
        self.ledger.reserve(key, "AUX_PROCESS", reserved)
        started = time.monotonic()
        cleanup_complete = False
        cleanup_uncertain = False
        output_limited = False
        try:
            try:
                blobs = execute_seed_generator(request.code,
                                               request.num_variants)
            except SeedSandboxOutputLimitError:
                cleanup_complete = True
                output_limited = True
                raise
            except SeedSandboxCleanupError:
                cleanup_uncertain = True
                raise
            except SeedSandboxError:
                cleanup_complete = True
                raise
            cleanup_complete = True
            return blobs
        finally:
            row = self.ledger.finish(
                key, physical_seconds=time.monotonic() - started,
                cleanup_complete=cleanup_complete,
                output_limited=output_limited)
            if (not cleanup_uncertain and
                    (row["overrun"] or
                     self.ledger.snapshot()["stop_status"] is not None)):
                raise RuntimeError("qualified PoV generator physical account stopped")

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


def _original_sp_hypothesis_snapshot(
    adapter: ProductQualifiedPoVAdapter, sp_id: str,
    direction_id: str,
) -> dict[str, Any] | None:
    """Freeze an FBv2 SP as an untrusted product-Gate hypothesis.

    The snapshot gives the independent Gate a function and proposed mechanism
    to test.  It is deliberately not Evidence, does not copy FBv2's verdict,
    and cannot grant discovery or verification credit by itself.
    """
    if (not ObjectId.is_valid(sp_id) or not ObjectId.is_valid(direction_id)):
        return None
    point = adapter.repos.suspicious_points.find_by_id(sp_id)
    if (point is None or str(point.suspicious_point_id) != sp_id or
            str(point.task_id) != adapter.task_id or
            str(point.direction_id) != direction_id or
            type(point.function_name) is not str or not point.function_name or
            type(point.description) is not str or not point.description or
            type(point.vuln_type) is not str or not point.vuln_type):
        return None
    function = adapter.repos.functions.find_by_name(
        adapter.task_id, point.function_name)
    if (function is None or function.task_id != adapter.task_id or
            function.name != point.function_name or
            type(function.file_path) is not str or not function.file_path or
            type(function.start_line) is not int or function.start_line < 1):
        return None
    guidance = (point.pov_guidance if isinstance(point.pov_guidance, str)
                and point.pov_guidance else None)
    return {
        "kind": "FBV2_ORIGINAL_SP_UNTRUSTED_HYPOTHESIS_V1",
        "trust": "UNTRUSTED_MODEL_HYPOTHESIS",
        "task_id": adapter.task_id,
        "run_id": adapter.run_id,
        "sp_id": sp_id,
        "direction_id": direction_id,
        "function_name": point.function_name,
        "function_id": function.function_id,
        "source_file": function.file_path,
        "source_start_line": function.start_line,
        "source_end_line": function.end_line,
        "vulnerability_type": point.vuln_type,
        "hypothesis": point.description,
        "pov_guidance": guidance,
        "evidence_authority": "NONE",
        "independent_checks_requested": [
            "SANITIZER_TARGET_ATTRIBUTION",
            "SP_TO_CRASH_RELATION",
            "ROOT_CAUSE",
            "SECURITY_PROPERTY",
            "PRODUCT_PROMOTION_GATE",
        ],
    }


def _verified_lineage_hypothesis(
    lineage: dict[str, Any],
) -> dict[str, Any] | None:
    """Return a receipt-bound model hypothesis without inventing a location."""
    hypothesis = lineage.get("untrusted_sp_hypothesis")
    expected_sha = lineage.get("untrusted_sp_hypothesis_sha256")
    if (type(hypothesis) is not dict or not _SHA.fullmatch(str(expected_sha)) or
            _canonical_json_sha256(hypothesis) != expected_sha or
            hypothesis.get("kind") !=
                "FBV2_AUTHENTICATED_UNTRUSTED_SP_HYPOTHESIS_V1" or
            hypothesis.get("trust") != "UNTRUSTED_MODEL_HYPOTHESIS" or
            hypothesis.get("task_id") != lineage.get("task_id") or
            hypothesis.get("direction_id") != lineage.get("direction_id") or
            hypothesis.get("sp_id") != lineage.get("sp_id") or
            type(hypothesis.get("function_name")) is not str or
            not hypothesis["function_name"] or
            type(hypothesis.get("vulnerability_type")) is not str or
            not hypothesis["vulnerability_type"] or
            type(hypothesis.get("hypothesis")) is not str or
            not hypothesis["hypothesis"] or
            hypothesis.get("source_file") is not None or
            hypothesis.get("code_location") != "UNKNOWN" or
            hypothesis.get("exact_source_location_status") != "UNPROVEN" or
            hypothesis.get("evidence_authority") != "NONE" or
            hypothesis.get("automatic_discovery") is not False or
            hypothesis.get("discovery_credit") !=
                "NOT_CREDITED_BY_LINEAGE_ONLY"):
        return None
    # Round-trip through canonical JSON so callers cannot mutate a nested
    # object owned by a model-gate snapshot.
    return json.loads(json.dumps(hypothesis, sort_keys=True, allow_nan=False))


def _structured_gate_hypothesis(vulnerability_type: str) -> str | None:
    """Map one model label to one sanitizer family without using prose.

    The original SP description remains frozen in the untrusted hypothesis
    artifact for an auditor.  It is not passed to the product oracle matcher:
    prose can mention several bug families and accidentally satisfy more than
    one sanitizer result.
    """
    if type(vulnerability_type) is not str:
        return None
    label = re.sub(r"[^a-z0-9]+", "-", vulnerability_type.lower()).strip("-")
    families = {
        "use-after-free": {
            "uaf", "use-after-free", "heap-use-after-free",
        },
        "double-free": {"double-free"},
        "out-of-bounds": {
            "oob", "out-of-bounds", "out-of-bounds-access",
            "out-of-bounds-read", "out-of-bounds-write", "buffer-overflow",
            "heap-buffer-overflow", "stack-buffer-overflow",
        },
        "integer overflow": {
            "integer-overflow", "signed-integer-overflow", "signed-overflow",
        },
        "null dereference": {
            "null-dereference", "null-pointer-dereference", "null-pointer",
        },
    }
    matched = [canonical for canonical, aliases in families.items()
               if label in aliases]
    return matched[0] if len(matched) == 1 else None


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


POV_GATE_OUTCOME_KIND = "FBV2_POV_PRODUCT_GATE_OUTCOME_V1"
_PRIMARY_SEGMENT = "pov.primary_execution"
_OBSERVED_REPLAY_SEGMENT = "pov.observed_independent_replay"
_REPLAY_ROLES = frozenset({"product_runtime", "canonical_crash", "fixed_poc",
                           "fixed_input", "replay_validation", "replay_runtime"})
_VERIFIED_ROLES = _REPLAY_ROLES | frozenset({
    "candidate", "root_cause", "security_property"})
# reason -> (required product status, required process segments, evidence roles)
# Goal A.1.1: only a conclusive clean-exit non-reproduction may settle a crash.
# A single INCONSISTENT replay (F8) and an unsupported crash type without a
# signed out-of-scope policy (R9) stay pending.
_TERMINAL_POV_GATE_RULES: dict[str, tuple[str, tuple[str, ...], frozenset[str]]] = {}
# Goal A.1.2: a VERIFIED outcome is re-proven the same way (hash-bound
# artifacts, recomputed crash fingerprints, clean process receipts).
_VERIFIED_POV_GATE_RULES: dict[str, tuple[str, tuple[str, ...], frozenset[str]]] = {
    "GATE_VERIFIED": (
        "VERIFIED", (_PRIMARY_SEGMENT, _OBSERVED_REPLAY_SEGMENT), _VERIFIED_ROLES),
}


def _plain_claim_file(claim_root: Path, name: Any) -> Path | None:
    """A regular, unlinked file below one claim directory, or None."""
    if type(name) is not str or not name:
        return None
    path = Path(name)
    try:
        if (not path.is_absolute() or path != path.resolve() or
                not path.is_relative_to(claim_root) or path.is_symlink() or
                not stat.S_ISREG(path.lstat().st_mode)):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    return path


def verified_fuzzer_consumer_evidence(run_dir: Path, outcome: Any) -> bool:
    """Re-prove a Global/SP-Fuzzer consumer's saved crash identity.

    Callers additionally bind the consumer to their campaign/claim and process
    account. Every artifact read here is confined to that run, hash checked,
    and parsed from the same bytes. Legacy or incomplete receipts stay pending.
    """
    from vulnerabilityanalysis.final_verification import (
        _replay_status, completed_asan_crash, crash_fingerprint,
        promote_verified, replay_identity_proven)
    from vulnerabilityanalysis.models import (FixedPoC, IndependentValidation,
                                              RootCauseResult, RuntimeResult,
                                              SecurityPropertyResult, SuspiciousPoint)

    try:
        run_dir = Path(run_dir)
        if (run_dir != run_dir.resolve(strict=True) or type(outcome) is not dict or
                outcome.get("status") != "VERIFIED" or
                outcome.get("gate_status") != "VERIFIED"):
            return False

        def read(name, digest):
            path = _plain_claim_file(run_dir, name)
            if path is None or type(digest) is not str or not _SHA.fullmatch(digest):
                raise ValueError("unbound artifact")
            data = _bounded_regular_bytes(path)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("artifact hash changed")
            return json.loads(data)

        primary = RuntimeResult(**read(outcome.get("runtime_artifact"),
                                       outcome.get("runtime_sha256")))
        canonical = read(outcome.get("canonical_crash_artifact"),
                         outcome.get("canonical_crash_artifact_sha256"))
        crash_id = crash_fingerprint(primary)
        source = {"poc_id": outcome.get("poc_id"),
                  "input_sha256": outcome.get("input_sha256"),
                  "runtime_artifact": outcome.get("runtime_artifact")}
        resolution = canonical.get("independent_gate_resolution", {})
        replay = resolution.get("replay", {})
        trace = canonical.get("independent_gate_trace", {})
        if (not completed_asan_crash(primary) or
                (primary.crash_triage or {}).get("category") != "TARGET_CRASH" or
                outcome.get("canonical_crash_id") != crash_id or
                canonical.get("crash_id") != crash_id or
                canonical.get("independent_verification_source") != source or
                canonical.get("independent_verification_status") != "VERIFIED" or
                resolution.get("resolution") != "VERIFIED" or
                resolution.get("crash_id") != crash_id or
                trace.get("crash_id") != crash_id or
                trace.get("promotion_state") != "COMPLETED" or
                trace.get("promotion_result") is not True or
                trace.get("security_property_state") != "COMPLETED"):
            return False
        fixed = FixedPoC(**read(replay.get("fixed_poc_artifact"),
                               replay.get("fixed_poc_sha256")))
        validation = IndependentValidation(**read(replay.get("validation_artifact"),
                                                 replay.get("validation_sha256")))
        runtime = RuntimeResult(**read(replay.get("runtime_artifact"),
                                      replay.get("runtime_sha256")))
        candidate_path = canonical.get("independent_candidate_artifact")
        root_path = canonical.get("independent_root_cause_artifact")
        security_path = canonical.get("independent_security_artifact")
        candidate_file = _plain_claim_file(run_dir, candidate_path)
        root_file = _plain_claim_file(run_dir, root_path)
        security_file = _plain_claim_file(run_dir, security_path)
        if not all((candidate_file, root_file, security_file)):
            return False
        candidate_record = json.loads(_bounded_regular_bytes(candidate_file))
        candidate = SuspiciousPoint(**candidate_record["candidate"])
        root = RootCauseResult(**json.loads(_bounded_regular_bytes(root_file)))
        security = SecurityPropertyResult(**json.loads(_bounded_regular_bytes(security_file)))
        qualification = outcome.get("qualification_identity")
        if (type(qualification) is not dict or
                qualification.get("kind") not in {"OFFICIAL_PINNED", "LIVE_DIRECT"} or
                qualification.get("binary") != fixed.target_binary or
                qualification.get("binary_sha256") != fixed.binary_sha256 or
                fixed.run_command != [fixed.target_binary, "{input}"] or
                not Path(fixed.target_binary).is_file() or
                _sha(Path(fixed.target_binary)) != fixed.binary_sha256 or
                candidate.sp_id != crash_id or root.sp_id != crash_id or
                security.sp_id != crash_id):
            return False
        input_path = _plain_claim_file(run_dir, replay.get("fixed_input_artifact"))
        return bool(input_path is not None and
            _sha(input_path) == fixed.input_sha256 == outcome.get("input_sha256") ==
                replay.get("fixed_input_sha256") and
            fixed.binary_sha256 == outcome.get("binary_sha256") and
            fixed.poc_id == validation.poc_id == outcome.get("poc_id") and
            fixed.sp_id == validation.sp_id == crash_id and
            fixed.input_path == str(input_path) and
            validation.execution_result == replay.get("runtime_artifact") and
            canonical.get("independent_fixed_poc_artifact") == replay.get("fixed_poc_artifact") and
            canonical.get("independent_replay_artifact") == replay.get("validation_artifact") and
            validation.status == _replay_status(runtime, fixed)[0] == "REPRODUCED" and
            completed_asan_crash(runtime) and
            replay_identity_proven(primary, fixed, validation, runtime) and
            promote_verified(candidate, primary, root, fixed, validation, security))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError):
        return False


def _gate_attempt_rows(finished_rows: Any, prefix: str, segment: str) -> list[dict]:
    if type(finished_rows) is not list:
        return []
    return [row for row in finished_rows
            if type(row) is dict and type(row.get("key")) is str and
            row["key"].startswith(prefix) and row["key"].endswith(":" + segment) and
            re.fullmatch(r"\d{6}", row["key"][len(prefix):-len(segment) - 1] or "")]


def _process_receipt(row: dict) -> dict[str, Any]:
    return {key: row.get(key) for key in
            ("key", "kind", "cleanup_complete", "output_limited", "overrun")}


def verify_terminal_pov_gate(outcome: Any, *, claim_dir: Path,
                             finished_rows: Any) -> str | None:
    """Re-prove a TERMINAL_REJECTED PoV Gate outcome; None means proven.

    Any unexpected error on malformed but hash-consistent evidence is a
    failure code (pending), never an exception in run assembly.
    """
    try:
        return _verify_pov_gate(outcome, claim_dir=claim_dir,
                                finished_rows=finished_rows,
                                expected="TERMINAL_REJECTED")
    except Exception:  # fail closed: the crash stays pending
        return "EVIDENCE_MALFORMED"


def verify_verified_pov_gate(outcome: Any, *, claim_dir: Path,
                             finished_rows: Any) -> str | None:
    """Re-prove a VERIFIED PoV Gate outcome; None means proven (Goal A.1.2).

    The replay must be the same crash as the product primary and the original
    observation: both crash fingerprints are recomputed from the hash-bound
    RuntimeResults and must equal the frozen and recorded values. A VERIFIED
    label that cannot be re-proven is not counted and stays pending.
    """
    try:
        return _verify_pov_gate(outcome, claim_dir=claim_dir,
                                finished_rows=finished_rows, expected="VERIFIED")
    except Exception:  # fail closed
        return "EVIDENCE_MALFORMED"


def _verify_pov_gate(outcome: Any, *, claim_dir: Path, finished_rows: Any,
                     expected: str) -> str | None:
    """Implementation of the terminal and verified re-proofs.

    Shared by the adapter (before writing the outcome) and the run-result
    consumer (from the durable outcome). Every claimed artifact is re-hashed,
    the replay verdict is recomputed from the saved RuntimeResult, and the
    process-ledger rows for the primary and replay segments must show a clean,
    non-overrun completion. Any gap returns a failure code and the crash stays
    pending.
    """
    from vulnerabilityanalysis.final_verification import (
        GATE_TERMINAL_REJECTED, GATE_VERIFIED, _replay_status, completed_asan_crash,
        crash_fingerprint, independent_replay_resolution, promote_verified,
        replay_identity_proven)
    from vulnerabilityanalysis.models import (FixedPoC, IndependentValidation,
                                              RootCauseResult, RuntimeResult,
                                              SecurityPropertyResult, SuspiciousPoint)

    if type(outcome) is not dict or not isinstance(claim_dir, Path):
        return "OUTCOME_MALFORMED"
    rules = {GATE_TERMINAL_REJECTED: _TERMINAL_POV_GATE_RULES,
             GATE_VERIFIED: _VERIFIED_POV_GATE_RULES}.get(expected)
    reason = outcome.get("gate_resolution_reason")
    if (rules is None or outcome.get("kind") != POV_GATE_OUTCOME_KIND or
            outcome.get("gate_resolution") != expected or
            type(reason) is not str or reason not in rules):
        return "NOT_A_PROVABLE_OUTCOME"
    status, segments, roles = rules[reason]
    if (outcome.get("product_gate_status") != status or
            outcome.get("automatic_discovery") is not False or
            outcome.get("discovery_credit") != "NOT_CREDITED"):
        return "STATUS_OR_CREDIT_MISMATCH"
    try:
        claim_root = claim_dir.resolve(strict=True)
    except (OSError, RuntimeError):
        return "CLAIM_DIRECTORY_MISSING"
    if claim_root != claim_dir or claim_dir.is_symlink():
        return "CLAIM_DIRECTORY_LINKED"
    claim_path = _plain_claim_file(claim_root, str(claim_root / "claim.json"))
    try:
        claim = json.loads(claim_path.read_bytes()) if claim_path else None
    except (OSError, ValueError, RecursionError):
        claim = None
    identity = ("task_id", "run_id", "pov_id", "sp_id", "input_sha256", "binary_sha256")
    if (type(claim) is not dict or claim.get("kind") != "FBV2_POV_GATE_CLAIM_V1" or
            any(type(outcome.get(key)) is not str or claim.get(key) != outcome.get(key)
                for key in identity) or
            not ObjectId.is_valid(outcome["pov_id"])):
        return "IDENTITY_MISMATCH"
    evidence = outcome.get("gate_resolution_evidence")
    if (type(evidence) is not list or any(type(item) is not dict for item in evidence) or
            sorted(item.get("role") for item in evidence) != sorted(roles)):
        return "EVIDENCE_ROLES_MISMATCH"
    paths: dict[str, Path] = {}
    blobs: dict[str, bytes] = {}
    for item in evidence:
        path = _plain_claim_file(claim_root, item.get("path"))
        try:
            data = path.read_bytes() if path is not None else None
        except OSError:
            data = None
        # Hash and parse the same bytes (no re-read between check and use).
        if (data is None or type(item.get("sha256")) is not str or
                hashlib.sha256(data).hexdigest() != item["sha256"]):
            return "EVIDENCE_HASH_MISMATCH"
        paths[item["role"]], blobs[item["role"]] = path, data
    sha = {role: hashlib.sha256(data).hexdigest() for role, data in blobs.items()}
    if (str(paths["product_runtime"]) != outcome.get("product_runtime_artifact") or
            sha["product_runtime"] != outcome.get("product_runtime_sha256") or
            paths["product_runtime"].name != f"{outcome.get('evaluation_pov_id')}.json" or
            str(paths["canonical_crash"]) != outcome.get("canonical_crash_artifact") or
            sha["canonical_crash"] != outcome.get("canonical_crash_sha256")):
        return "EVIDENCE_OUTCOME_MISMATCH"

    def load(role: str) -> Any:
        return json.loads(blobs[role])

    try:
        runtime = RuntimeResult(**load("product_runtime"))
        record = load("canonical_crash")
    except (OSError, TypeError, ValueError, RecursionError):
        return "PRIMARY_EVIDENCE_UNREADABLE"
    crash_id = outcome.get("gate_crash_id")
    resolution = record.get("independent_gate_resolution") if type(record) is dict else None
    trace = record.get("independent_gate_trace") if type(record) is dict else None
    if (type(crash_id) is not str or not runtime.sanitizer or
            crash_fingerprint(runtime) != crash_id or
            paths["canonical_crash"].name != f"{crash_id}.json" or
            not completed_asan_crash(runtime) or
            (runtime.crash_triage or {}).get("category") != "TARGET_CRASH" or
            claim.get("original_crash_id") != crash_id or
            type(trace) is not dict or trace.get("crash_id") != crash_id or
            record.get("independent_verification_status") != status or
            type(resolution) is not dict or
            resolution.get("kind") != "VA_INDEPENDENT_GATE_RESOLUTION_V1" or
            resolution.get("crash_id") != crash_id or
            resolution.get("status") != status or
            resolution.get("resolution") != expected or
            resolution.get("reason") != reason or
            (expected == GATE_VERIFIED and (
                trace.get("promotion_state") != "COMPLETED" or
                trace.get("promotion_result") is not True or
                outcome.get("security_gate_result") is not True))):
        return "PRIMARY_EVIDENCE_INCONSISTENT"
    original_path = _plain_claim_file(claim_root.parent.parent,
                                      claim.get("original_runtime_receipt_path"))
    try:
        original_bytes = original_path.read_bytes() if original_path else None
        original = json.loads(original_bytes) if original_bytes else None
    except (OSError, ValueError, RecursionError):
        original = None
    if (type(original) is not dict or
            hashlib.sha256(original_bytes).hexdigest() !=
                claim.get("original_runtime_receipt_sha256") or
            original.get("kind") != "FBV2_DEV_QUALIFIED_POV_RUNTIME_V1" or
            any(original.get(key) != outcome[key]
                for key in ("task_id", "run_id", "pov_id", "input_sha256")) or
            type(original.get("runtime")) is not dict or
            crash_fingerprint(RuntimeResult(**original["runtime"])) != crash_id):
        return "ORIGINAL_OBSERVATION_MISMATCH"
    original_command = original.get("command")
    if reason in {"REPLAY_NOT_REPRODUCED_CLEAN_EXIT", "GATE_VERIFIED"}:
        try:
            fixed = FixedPoC(**load("fixed_poc"))
            validation = IndependentValidation(**load("replay_validation"))
            replay_runtime = RuntimeResult(**load("replay_runtime"))
        except (OSError, TypeError, ValueError, RecursionError):
            return "REPLAY_EVIDENCE_UNREADABLE"
        replay = resolution.get("replay")
        if (type(replay) is not dict or
                replay.get("process_segment") != _OBSERVED_REPLAY_SEGMENT or
                replay.get("status") != validation.status or
                outcome.get("independent_replay_status") != validation.status or
                record.get("independent_replay_artifact") != str(paths["replay_validation"]) or
                record.get("independent_fixed_poc_artifact") != str(paths["fixed_poc"]) or
                validation.execution_result != str(paths["replay_runtime"]) or
                fixed.input_path != str(paths["fixed_input"]) or
                fixed.input_sha256 != outcome["input_sha256"] or
                sha["fixed_input"] != outcome["input_sha256"] or
                fixed.binary_sha256 != outcome["binary_sha256"] or
                type(original_command) is not list or
                len(original_command) != 2 or
                type(fixed.target_binary) is not str or
                fixed.target_binary != original_command[0] or
                fixed.run_command != [fixed.target_binary, "{input}"] or
                original_command[1] != original.get("input_path") or
                not Path(fixed.target_binary).is_file() or
                _sha(Path(fixed.target_binary)) != fixed.binary_sha256 or
                fixed.sp_id != crash_id or
                fixed.poc_id != outcome.get("evaluation_pov_id") or
                validation.poc_id != fixed.poc_id or
                any(replay.get(key) != sha[role] for key, role in (
                    ("validation_sha256", "replay_validation"),
                    ("runtime_sha256", "replay_runtime"),
                    ("fixed_poc_sha256", "fixed_poc"),
                    ("fixed_input_sha256", "fixed_input")))):
            return "REPLAY_EVIDENCE_INCONSISTENT"
        if expected == GATE_VERIFIED:
            try:
                candidate_record = load("candidate")
                candidate = SuspiciousPoint(**candidate_record["candidate"])
                root = RootCauseResult(**load("root_cause"))
                security = SecurityPropertyResult(**load("security_property"))
            except (KeyError, TypeError, ValueError, RecursionError):
                return "PROMOTION_EVIDENCE_UNREADABLE"
            # The replay must be the same crash, recomputed from both runtimes.
            if (validation.status != "REPRODUCED" or
                    _replay_status(replay_runtime, fixed)[0] != "REPRODUCED" or
                    not completed_asan_crash(replay_runtime) or
                    not replay_identity_proven(runtime, fixed, validation,
                                               replay_runtime) or
                    crash_fingerprint(replay_runtime) != crash_id):
                return "REPLAY_IDENTITY_UNPROVEN"
            if (record.get("independent_candidate_artifact") != str(paths["candidate"]) or
                    record.get("independent_root_cause_artifact") != str(paths["root_cause"]) or
                    record.get("independent_security_artifact") != str(paths["security_property"]) or
                    candidate_record.get("original_sp_id") != outcome.get("evaluation_candidate_id") or
                    candidate.sp_id != crash_id or
                    root.sp_id != crash_id or security.sp_id != crash_id or
                    not promote_verified(candidate, runtime, root, fixed,
                                         validation, security)):
                return "PROMOTION_EVIDENCE_UNPROVEN"
        elif independent_replay_resolution(fixed, validation, replay_runtime) != (
                GATE_TERMINAL_REJECTED, reason):
            return "REPLAY_NOT_CONCLUSIVE"
    prefix = (f"{outcome['task_id']}:{outcome['sp_id']}:"
              f"{outcome['pov_id']}_gate:")
    receipts = outcome.get("gate_process_receipts")
    if type(receipts) is not list:
        return "PROCESS_RECEIPT_MISSING"
    for segment in segments:
        rows = _gate_attempt_rows(finished_rows, prefix, segment)
        if (len(rows) != 1 or rows[0].get("kind") != "AUX_PROCESS" or
                rows[0].get("cleanup_complete") is not True or
                rows[0].get("output_limited") is not False or
                rows[0].get("overrun") is not False or
                _process_receipt(rows[0]) not in receipts):
            return "PROCESS_RECEIPT_UNPROVEN"
    return None


def _pov_gate_resolution_fields(adapter: Any, gate: dict[str, Any],
                                crash_id: str | None, canonical: Path | None,
                                product_runtime: Path, claim_dir: Path,
                                draft: dict[str, Any]) -> dict[str, Any]:
    """Carry the producer's structured resolution and its proof into the outcome."""
    from vulnerabilityanalysis.final_verification import (
        GATE_INCOMPLETE, GATE_RESOLUTIONS, GATE_TERMINAL_REJECTED, GATE_VERIFIED)

    produced = gate.get("independent_gate_resolution")
    produced = produced if type(produced) is dict else {}
    replay = produced.get("replay") if type(produced.get("replay")) is dict else {}
    evidence = [{"role": "product_runtime", "path": str(product_runtime),
                 "sha256": _sha(product_runtime)}]
    if canonical is not None and canonical.is_file():
        evidence.append({"role": "canonical_crash", "path": str(canonical),
                         "sha256": _sha(canonical)})
    for role, key in (("fixed_poc", "fixed_poc_artifact"),
                      ("fixed_input", "fixed_input_artifact"),
                      ("replay_validation", "validation_artifact"),
                      ("replay_runtime", "runtime_artifact")):
        name = replay.get(key)
        if type(name) is str and Path(name).is_file() and not Path(name).is_symlink():
            evidence.append({"role": role, "path": name, "sha256": _sha(Path(name))})
    if draft["product_gate_status"] == "VERIFIED":
        for role, key in (("candidate", "independent_candidate_artifact"),
                          ("root_cause", "independent_root_cause_artifact"),
                          ("security_property", "independent_security_artifact")):
            name = gate.get(key)
            if type(name) is str and Path(name).is_file() and not Path(name).is_symlink():
                evidence.append({"role": role, "path": name, "sha256": _sha(Path(name))})
    prefix = f"{draft['task_id']}:{draft['sp_id']}:{draft['pov_id']}_gate:"
    finished = adapter.ledger.snapshot()["finished"]
    receipts = [_process_receipt(row) for segment in
                (_PRIMARY_SEGMENT, _OBSERVED_REPLAY_SEGMENT)
                for row in _gate_attempt_rows(finished, prefix, segment)]
    fields = {
        "gate_crash_id": crash_id,
        "producer_gate_resolution": produced.get("resolution"),
        "producer_gate_resolution_reason": produced.get("reason"),
        "independent_replay_status": replay.get("status"),
        "independent_replay_reason": replay.get("reason"),
        "gate_resolution_evidence": evidence,
        "gate_process_receipts": receipts,
    }
    status = draft["product_gate_status"]
    claimed = produced.get("resolution")
    if status == "VERIFIED":
        # The product's seven-condition promotion decided VERIFIED; the
        # adapter re-proves the replay identity from hash-bound artifacts
        # (Goal A.1.2). An unproven VERIFIED label is recorded as INCOMPLETE.
        failure = verify_verified_pov_gate(
            {**draft, **fields, "gate_resolution": GATE_VERIFIED,
             "gate_resolution_reason": "GATE_VERIFIED"},
            claim_dir=claim_dir, finished_rows=finished)
        resolution, reason = ((GATE_VERIFIED, "GATE_VERIFIED") if failure is None else
                              (GATE_INCOMPLETE, "VERIFIED_EVIDENCE_UNVERIFIED"))
        fields["gate_resolution_detail"] = failure
    elif canonical is None or not canonical.is_file():
        resolution, reason = GATE_INCOMPLETE, "NO_TARGET_CRASH_RECORD"
    elif (claimed not in GATE_RESOLUTIONS or produced.get("status") != status or
          produced.get("crash_id") != crash_id or type(produced.get("reason")) is not str):
        resolution, reason = GATE_INCOMPLETE, "PRODUCER_RESOLUTION_MISSING"
    elif claimed == GATE_TERMINAL_REJECTED:
        failure = verify_terminal_pov_gate(
            {**draft, **fields, "gate_resolution": GATE_TERMINAL_REJECTED,
             "gate_resolution_reason": produced["reason"]},
            claim_dir=claim_dir, finished_rows=finished)
        resolution, reason = ((GATE_TERMINAL_REJECTED, produced["reason"])
                              if failure is None else
                              (GATE_INCOMPLETE, "TERMINAL_EVIDENCE_UNVERIFIED"))
        fields["gate_resolution_detail"] = failure
    elif claimed == GATE_VERIFIED:
        resolution, reason = GATE_INCOMPLETE, "PRODUCER_RESOLUTION_INCONSISTENT"
    else:
        resolution, reason = GATE_INCOMPLETE, produced["reason"]
    fields["gate_resolution"] = resolution
    fields["gate_resolution_reason"] = reason
    fields["physical_step_completed"] = resolution in {GATE_VERIFIED,
                                                       GATE_TERMINAL_REJECTED}
    return fields


def verify_qualified_pov_runtime_lineage(
    adapter: ProductQualifiedPoVAdapter, pov_id: str,
    model_gate: Any, *, recheck: Callable[[], None],
    pov_admission_mode: str = "legacy_score",
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
        model_gate, adapter.repos, task_id=adapter.task_id, pov_id=pov_id,
        pov_admission_mode=pov_admission_mode)
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
    hypothesis = _verified_lineage_hypothesis(candidate_lineage)
    if hypothesis is None:
        return unproven("AUTHENTICATED_SP_HYPOTHESIS_MISSING")
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
            "input_path": str(input_path),
            "binary_path": str(binary),
            "runtime_status": runtime["status"],
            "runtime_receipt_path": str(runtime_path),
            "runtime_receipt_sha256": runtime_sha,
            "physical_receipt_path": str(physical_path),
            "physical_receipt_sha256": physical_sha,
            "source_tree_sha256": q.source_tree_sha256,
            "harness_sha256": q.harness_sha256,
            "binary_sha256": binary_sha,
            "contract_sha256": q.contract_sha256,
            "untrusted_sp_hypothesis": hypothesis,
            "untrusted_sp_hypothesis_sha256":
                candidate_lineage["untrusted_sp_hypothesis_sha256"],
            "discovery_credit": "NOT_CREDITED_BY_LINEAGE_ONLY",
        }
    except (ValueError, TypeError, KeyError, IndexError, AttributeError,
            OSError, binascii.Error, json.JSONDecodeError):
        return unproven("QUALIFIED_RUNTIME_EVIDENCE_UNPROVEN")


def prepare_qualified_uaf_gate_reevaluation(
    adapter: ProductQualifiedPoVAdapter, pov_id: str, model_gate: Any, *,
    recheck: Callable[[], None], evaluation_id: str, output_dir: Path,
    measurement_command: list[str],
    measurement_command_pins: dict[str, str],
    measurement_binary_path: str,
    measurement_build_provenance_path: str,
    measurement_emitter_path: str,
    measurement_environment: dict[str, str],
    measurement_profile: str,
    measurement_expected_operation: str,
    measurement_target_command: list[str],
    measurement_timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Authenticate frozen evidence and create a no-replay Gate plan.

    The original Runtime and physical receipts remain bound to their original
    run/ledger. This function never re-labels them as a new run and never
    launches the Target. A later, separately approved physical evaluation may
    reference this immutable plan by hash.
    """
    if (type(evaluation_id) is not str or not _ID.fullmatch(evaluation_id) or
            not callable(recheck) or
            type(measurement_command) is not list or
            not measurement_command or
            any(type(part) is not str or not part
                for part in measurement_command) or
            type(measurement_command_pins) is not dict or
            not measurement_command_pins or
            type(measurement_binary_path) is not str or
            not measurement_binary_path or
            type(measurement_build_provenance_path) is not str or
            not measurement_build_provenance_path or
            type(measurement_emitter_path) is not str or
            not measurement_emitter_path or
            type(measurement_environment) is not dict or
            not measurement_environment or
            any(type(key) is not str or not key or
                type(value) is not str
                for key, value in measurement_environment.items()) or
            measurement_profile not in {
                "SYNTHETIC_PROVIDER_FREE", "MD4C_INSTRUMENTED_V1"} or
            type(measurement_expected_operation) is not str or
            not measurement_expected_operation or
            type(measurement_target_command) is not list or
            not measurement_target_command or
            any(type(part) is not str or not part
                for part in measurement_target_command) or
            type(measurement_timeout_seconds) not in (int, float) or
            not math.isfinite(measurement_timeout_seconds) or
            not 0 < measurement_timeout_seconds <= 120):
        raise ValueError("invalid UAF Gate reevaluation identity")
    output_dir = Path(output_dir)
    if (not output_dir.is_absolute() or output_dir != output_dir.resolve() or
            output_dir.is_symlink() or
            any(parent.is_symlink() for parent in output_dir.parents) or
            not output_dir.parent.is_dir() or output_dir.exists()):
        raise ValueError("UAF Gate reevaluation directory must be new and canonical")
    lineage = verify_qualified_pov_runtime_lineage(
        adapter, pov_id, model_gate, recheck=recheck)
    if (lineage.get("status") != "VERIFIED" or
            lineage.get("runtime_status") != "CRASH_OBSERVED"):
        raise ValueError("original qualified UAF crash evidence is unproven")
    authenticated_hypothesis = _verified_lineage_hypothesis(lineage)
    function_snapshot = _original_sp_hypothesis_snapshot(
        adapter, lineage["sp_id"], lineage["direction_id"])
    if (not isinstance(authenticated_hypothesis, dict) or
            not isinstance(function_snapshot, dict) or
            function_snapshot.get("function_id") !=
                authenticated_hypothesis.get("campaign_function_id") or
            any(function_snapshot.get(key) != authenticated_hypothesis.get(key)
                for key in ("function_name", "vulnerability_type",
                            "hypothesis", "pov_guidance")) or
            function_snapshot.get("source_end_line") is None or
            type(function_snapshot.get("source_end_line")) is not int or
            function_snapshot["source_end_line"] <
                function_snapshot["source_start_line"]):
        raise ValueError("original SP function span is unproven")
    recheck()
    q = adapter.binding.qualification
    source_root = Path(q.source_root).resolve()
    source_path = (source_root / function_snapshot["source_file"]).resolve()
    if (not source_path.is_relative_to(source_root) or
            not source_path.is_file()):
        raise ValueError("original SP source file is outside pinned tree")
    source_bytes = _bounded_regular_bytes(source_path)
    command_pins: dict[str, str] = {}
    for raw_path, expected_sha in measurement_command_pins.items():
        path = Path(raw_path)
        if (type(raw_path) is not str or not _SHA.fullmatch(expected_sha) or
                raw_path not in measurement_command):
            raise ValueError("measurement command pin is invalid")
        content = _bounded_regular_bytes(
            path, limit=128_000_000, require_owner=False,
            require_single_link=False)
        if hashlib.sha256(content).hexdigest() != expected_sha:
            raise ValueError("measurement command artifact changed")
        command_pins[str(path)] = expected_sha
    measurement_binary = Path(measurement_binary_path)
    measurement_binary_bytes = _bounded_regular_bytes(
        measurement_binary, limit=128_000_000, require_owner=False,
        require_single_link=False)
    build_provenance = Path(measurement_build_provenance_path)
    build_provenance_bytes = _bounded_regular_bytes(build_provenance)
    if (measurement_binary_path not in measurement_command or
            lineage["input_path"] not in measurement_command or
            measurement_emitter_path not in measurement_command or
            measurement_emitter_path not in command_pins):
        raise ValueError("measurement command is not bound to frozen input/binary")
    output_dir.mkdir(mode=0o700, exist_ok=False)
    hypothesis_path = output_dir / "authenticated-untrusted-sp-hypothesis.json"
    hypothesis_sha = _json_new(hypothesis_path, authenticated_hypothesis)
    if (_canonical_json_sha256(authenticated_hypothesis) !=
            lineage["untrusted_sp_hypothesis_sha256"]):
        raise ValueError("authenticated SP hypothesis changed")
    function_map = {
        "kind": "FBV2_PINNED_FUNCTION_INDEX_MAPPING_V1",
        "authority": "PINNED_FUNCTION_INDEX_MAPPING_NOT_MODEL_EXACT_LOCATION",
        "exact_model_source_location_status": "UNPROVEN",
        "task_id": lineage["task_id"],
        "run_id": lineage["run_id"],
        "direction_id": lineage["direction_id"],
        "sp_id": lineage["sp_id"],
        "campaign_function_id": authenticated_hypothesis[
            "campaign_function_id"],
        "function_name": function_snapshot["function_name"],
        "source_file": function_snapshot["source_file"],
        "source_start_line": function_snapshot["source_start_line"],
        "source_end_line": function_snapshot["source_end_line"],
        "source_file_path": str(source_path),
        "source_file_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "source_tree_sha256": lineage["source_tree_sha256"],
    }
    function_map_path = output_dir / "measurement-function-map.json"
    function_map_sha = _json_new(function_map_path, function_map)
    plan = {
        "kind": "FBV2_UAF_GATE_REEVALUATION_PLAN_V1",
        "status": "PREPARED_NO_TARGET_REPLAY",
        "evaluation_id": evaluation_id,
        "original_task_id": lineage["task_id"],
        "original_run_id": lineage["run_id"],
        "original_sp_id": lineage["sp_id"],
        "original_pov_id": pov_id,
        "input_path": lineage["input_path"],
        "original_binary_path": lineage["binary_path"],
        "original_binary_sha256": lineage["binary_sha256"],
        "binary_path": measurement_binary_path,
        "input_sha256": lineage["input_sha256"],
        "input_size": Path(lineage["input_path"]).stat().st_size,
        "binary_sha256": hashlib.sha256(measurement_binary_bytes).hexdigest(),
        "source_tree_sha256": lineage["source_tree_sha256"],
        "harness_sha256": lineage["harness_sha256"],
        "original_runtime_receipt_path": lineage["runtime_receipt_path"],
        "original_runtime_receipt_sha256": lineage["runtime_receipt_sha256"],
        "original_physical_receipt_path": lineage["physical_receipt_path"],
        "original_physical_receipt_sha256": lineage["physical_receipt_sha256"],
        "untrusted_sp_hypothesis_path": str(hypothesis_path),
        "untrusted_sp_hypothesis_sha256": hypothesis_sha,
        "authenticated_untrusted_sp_hypothesis_sha256":
            lineage["untrusted_sp_hypothesis_sha256"],
        "measurement_function_map_path": str(function_map_path),
        "measurement_function_map_sha256": function_map_sha,
        "function_mapping_authority": function_map["authority"],
        "exact_model_source_location_status": "UNPROVEN",
        "function_name": function_map["function_name"],
        "source_file": function_map["source_file"],
        "source_root": str(source_root),
        "source_file_path": str(source_path),
        "source_file_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "source_start_line": function_map["source_start_line"],
        "source_end_line": function_map["source_end_line"],
        "vulnerability_type": authenticated_hypothesis[
            "vulnerability_type"],
        "measurement_ledger_path": str(output_dir / "process-ledger.json"),
        "measurement_work_item_id": evaluation_id,
        "measurement_assertion_id": "UAF_CAUSAL",
        "measurement_attempt_id": "ONE_SHOT",
        "measurement_segment": "uaf.causal_trace",
        "measurement_lease_key": (
            f"{evaluation_id}:UAF_CAUSAL:ONE_SHOT:000000:"
            "uaf.causal_trace"),
        "measurement_process_kind": "AUX_PROCESS",
        "measurement_command": list(measurement_command),
        "measurement_command_pins": command_pins,
        "measurement_emitter_path": measurement_emitter_path,
        "measurement_emitter_sha256": command_pins[measurement_emitter_path],
        "measurement_environment": dict(sorted(measurement_environment.items())),
        "measurement_build_provenance_path": str(build_provenance),
        "measurement_build_provenance_sha256":
            hashlib.sha256(build_provenance_bytes).hexdigest(),
        "measurement_profile": measurement_profile,
        "measurement_expected_operation": measurement_expected_operation,
        "measurement_target_command": list(measurement_target_command),
        "measurement_timeout_seconds": float(measurement_timeout_seconds),
        "measurement_wall_seconds": float(measurement_timeout_seconds) + 15.0,
        "measurement_output_limit_bytes": 2_000_000,
        "required_new_measurements": [
            "ASAN_ACCESS_FRAME_IN_ORIGINAL_FUNCTION_SPAN",
            "SAME_HEAP_OBJECT_ALLOCATION_FREE_ACCESS",
            "REALLOC_OBSERVED",
            "STALE_POINTER_OBSERVED",
            "SP_CONDITION_REACHED_TRUE",
            "EXTERNAL_INPUT_REACHED_TRUE",
        ],
        "product_gate_evaluated": False,
        "product_gate_verified": False,
    }
    plan_sha = _json_new(output_dir / "plan.json", plan)
    return {"status": plan["status"], "evaluation_id": evaluation_id,
            "plan_path": str(output_dir / "plan.json"),
            "plan_sha256": plan_sha, "plan": plan}


def _address(value: Any) -> int:
    if type(value) is not str or re.fullmatch(r"0x[0-9a-fA-F]+", value) is None:
        raise ValueError("raw trace address is malformed")
    return int(value, 16)


def _asan_uaf_memory_observation(stderr: str) -> dict[str, int]:
    """Extract the address, width and freed region from one ASan UAF report."""
    error = re.search(
        r"ERROR:\s*AddressSanitizer:\s*heap-use-after-free\s+on\s+address\s+"
        r"(0x[0-9a-fA-F]+)", stderr)
    access = re.search(
        r"\b(?:READ|WRITE)\s+of\s+size\s+(\d+)\s+at\s+"
        r"(0x[0-9a-fA-F]+)", stderr)
    region = re.search(
        r"\bis\s+located\s+\d+\s+bytes\s+(?:inside|to the right of|"
        r"to the left of)\s+of\s+(\d+)-byte\s+region\s+"
        r"\[(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+)\)", stderr)
    if not error or not access or not region:
        raise ValueError("ASan UAF address or freed region is absent")
    fault = _address(error.group(1))
    access_width = int(access.group(1))
    access_address = _address(access.group(2))
    region_size = int(region.group(1))
    region_base = _address(region.group(2))
    region_end = _address(region.group(3))
    if (fault != access_address or access_width <= 0 or region_size <= 0 or
            region_end - region_base != region_size or
            not region_base <= fault < region_end or
            fault + access_width > region_end):
        raise ValueError("ASan UAF address and region disagree")
    return {
        "fault_address": fault, "access_width": access_width,
        "region_base": region_base, "region_size": region_size,
        "region_end": region_end,
    }


def _frame_present(frames: list[tuple[str, str, int, str]],
                   event: dict[str, Any]) -> bool:
    return any((name, source, line) == (
        event.get("function_name"), event.get("source_file"),
        event.get("line")) for name, source, line, _ in frames)


def _derive_uaf_causal_measurement(
    plan: dict[str, Any], raw_trace: dict[str, Any], runtime_stderr: str,
) -> dict[str, Any]:
    """Derive UAF conditions from ordered raw addresses, never input booleans."""
    from vulnerabilityanalysis.runtime import _frames_by_section

    if (raw_trace.get("kind") != "FBV2_UAF_RAW_TRACE_V1" or
            raw_trace.get("evaluation_id") != plan.get("evaluation_id") or
            raw_trace.get("input_sha256") != plan.get("input_sha256") or
            type(raw_trace.get("events")) is not list):
        raise ValueError("raw UAF trace identity differs")
    target_execution = raw_trace.get("target_execution")
    if plan.get("measurement_profile") == "MD4C_INSTRUMENTED_V1":
        if (type(target_execution) is not dict or
                target_execution.get("binary_path") != plan.get("binary_path") or
                target_execution.get("binary_sha256") != plan.get("binary_sha256") or
                target_execution.get("input_path") != plan.get("input_path") or
                target_execution.get("input_sha256") != plan.get("input_sha256") or
                target_execution.get("command") !=
                    plan.get("measurement_target_command") or
                type(target_execution.get("returncode")) is not int or
                target_execution["returncode"] == 0 or
                target_execution.get("stderr_sha256") !=
                    hashlib.sha256(runtime_stderr.encode()).hexdigest()):
            raise ValueError("instrumented md4c target execution is unproven")
    by_kind: dict[str, list[dict[str, Any]]] = {
        "input_read": [], "allocation": [], "reallocation": [], "access": []}
    for event in raw_trace["events"]:
        if isinstance(event, dict) and event.get("kind") in by_kind:
            by_kind[event["kind"]].append(event)
    if any(len(rows) != 1 for rows in by_kind.values()):
        raise ValueError("raw UAF trace event cardinality differs")
    input_read = by_kind["input_read"][0]
    allocation = by_kind["allocation"][0]
    reallocation = by_kind["reallocation"][0]
    access = by_kind["access"][0]
    sequences = [event.get("sequence") for event in
                 (input_read, allocation, reallocation, access)]
    if (any(type(value) is not int or value < 0 for value in sequences) or
            not sequences[0] < sequences[1] < sequences[2] < sequences[3]):
        raise ValueError("raw UAF event order differs")
    old_base = _address(allocation.get("base"))
    old_size = allocation.get("size")
    realloc_old_base = _address(reallocation.get("old_base"))
    realloc_old_size = reallocation.get("old_size")
    new_base = _address(reallocation.get("new_base"))
    new_size = reallocation.get("new_size")
    pointer_before = _address(reallocation.get("pointer_before"))
    pointer_after = _address(reallocation.get("pointer_after"))
    pointer_base = _address(access.get("pointer_base"))
    pointer_offset = access.get("pointer_offset")
    access_address = _address(access.get("address"))
    access_width = access.get("width")
    if (type(old_size) is not int or old_size <= 0 or
            type(realloc_old_size) is not int or
            type(new_size) is not int or new_size <= 0 or new_base == 0 or
            type(pointer_offset) is not int or pointer_offset < 0 or
            type(access_width) is not int or access_width <= 0 or
            input_read.get("input_sha256") != plan.get("input_sha256") or
            input_read.get("input_size") != plan.get("input_size") or
            any(event.get("generation") != allocation.get("generation")
                for event in (reallocation, access)) or
            type(allocation.get("generation")) is not int or
            allocation["generation"] < 0):
        raise ValueError("raw UAF sizes, generation or input event differ")
    old_end = old_base + old_size
    new_end = new_base + new_size
    ranges_disjoint = new_end <= old_base or old_end <= new_base
    same_old_object = (old_base == realloc_old_base and
                       old_size == realloc_old_size and
                       old_base <= pointer_before < old_end and
                       old_base <= access_address and
                       access_address + access_width <= old_end)
    moved_reallocation = (new_base != old_base and ranges_disjoint)
    stale_pointer = (pointer_before == pointer_after == pointer_base and
                     access_address == pointer_base + pointer_offset and
                     moved_reallocation and same_old_object)
    input_reached = sequences[0] < sequences[3]
    if not (same_old_object and moved_reallocation and stale_pointer and
            input_reached):
        raise ValueError("raw UAF causal relation is not established")
    frames = _frames_by_section(runtime_stderr)
    if not frames["access"] or not frames["free"] or not frames["allocation"]:
        raise ValueError("raw ASan lifetime stacks are incomplete")
    access_frame = {
        "function_name": access.get("function_name"),
        "source_file": access.get("source_file"),
        "line": access.get("line"),
    }
    asan_memory = _asan_uaf_memory_observation(runtime_stderr)
    if (type(access_frame["function_name"]) is not str or
            type(access_frame["source_file"]) is not str or
            type(access_frame["line"]) is not int or
            access.get("operation") != plan.get("measurement_expected_operation") or
            not _frame_present(frames["access"], access) or
            not _frame_present(frames["free"], reallocation) or
            not _frame_present(frames["allocation"], allocation) or
            asan_memory["fault_address"] != access_address or
            asan_memory["access_width"] != access_width or
            asan_memory["region_base"] != old_base or
            asan_memory["region_size"] != old_size):
        raise ValueError("raw access or lifetime event differs from ASan")
    object_id = hashlib.sha256(
        f"{old_base:x}:{old_size}:{allocation['generation']}:"
        f"{sequences[1]}".encode()).hexdigest()
    return {
        "kind": "FBV2_UAF_CAUSAL_MEASUREMENT_V1",
        "evaluation_id": plan["evaluation_id"],
        "input_path": plan["input_path"],
        "input_sha256": plan["input_sha256"],
        "binary_path": plan["binary_path"],
        "binary_sha256": plan["binary_sha256"],
        "original_binary_path": plan["original_binary_path"],
        "original_binary_sha256": plan["original_binary_sha256"],
        "build_provenance_path": plan["measurement_build_provenance_path"],
        "build_provenance_sha256":
            plan["measurement_build_provenance_sha256"],
        "source_tree_sha256": plan["source_tree_sha256"],
        "harness_sha256": plan["harness_sha256"],
        "asan_stderr_sha256": hashlib.sha256(
            runtime_stderr.encode()).hexdigest(),
        "sanitizer_family": "use-after-free",
        "access_frame": access_frame,
        "mapped_source_file_path": plan["source_file_path"],
        "mapped_source_file_sha256": plan["source_file_sha256"],
        "allocation_object": object_id,
        "freed_object": object_id,
        "accessed_object": object_id,
        "allocation_base": allocation["base"],
        "allocation_size": old_size,
        "reallocation_new_base": reallocation["new_base"],
        "stale_pointer_address": reallocation["pointer_after"],
        "access_address": access["address"],
        "access_width": access_width,
        "event_sequences": sequences,
        "pointer_base": access["pointer_base"],
        "pointer_offset": pointer_offset,
        "asan_fault_address": hex(asan_memory["fault_address"]),
        "asan_access_width": asan_memory["access_width"],
        "asan_freed_region_base": hex(asan_memory["region_base"]),
        "asan_freed_region_size": asan_memory["region_size"],
        "access_operation": access.get("operation"),
        "realloc_observed": moved_reallocation,
        "stale_pointer_observed": stale_pointer,
        "sp_condition_reached": stale_pointer,
        "external_input_reached": input_reached,
        "measurement_profile": plan["measurement_profile"],
        "target_execution": target_execution,
    }


def _uaf_execution_output_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode(errors="replace")
    return b""


def _validate_uaf_measurement_plan(
    plan_path: Path, expected_plan_sha256: str,
) -> tuple[dict[str, Any], bytes, dict[Path, str]]:
    """Validate the externally approved plan before creating a physical ledger."""
    from devtools.campaign_model_gate import _private_bytes

    if not _SHA.fullmatch(expected_plan_sha256):
        raise ValueError("approved UAF plan SHA-256 is invalid")
    plan_bytes = _private_bytes(plan_path)
    if (plan_bytes is None or
            hashlib.sha256(plan_bytes).hexdigest() != expected_plan_sha256):
        raise ValueError("approved UAF plan changed")
    plan = json.loads(plan_bytes)
    required_ids = ("evaluation_id", "original_task_id", "original_run_id",
                    "original_sp_id", "original_pov_id")
    pins = plan.get("measurement_command_pins")
    command = plan.get("measurement_command")
    environment = plan.get("measurement_environment")
    emitter = plan.get("measurement_emitter_path")
    if (plan.get("kind") != "FBV2_UAF_GATE_REEVALUATION_PLAN_V1" or
            plan.get("status") != "PREPARED_NO_TARGET_REPLAY" or
            any(type(plan.get(key)) is not str or not plan[key]
                for key in required_ids) or
            type(command) is not list or not command or
            any(type(part) is not str or not part for part in command) or
            type(pins) is not dict or not pins or
            any(type(path) is not str or not _SHA.fullmatch(digest)
                for path, digest in pins.items()) or
            type(environment) is not dict or not environment or
            any(type(key) is not str or not key or type(value) is not str
                for key, value in environment.items()) or
            plan.get("measurement_profile") not in {
                "SYNTHETIC_PROVIDER_FREE", "MD4C_INSTRUMENTED_V1"} or
            type(plan.get("measurement_expected_operation")) is not str or
            not plan["measurement_expected_operation"] or
            type(plan.get("measurement_target_command")) is not list or
            not plan["measurement_target_command"] or
            any(type(part) is not str or not part
                for part in plan["measurement_target_command"]) or
            any(type(plan.get(key)) is not str or not plan[key]
                for key in ("original_binary_path", "binary_path",
                            "measurement_build_provenance_path",
                            "untrusted_sp_hypothesis_path",
                            "measurement_function_map_path")) or
            any(not _SHA.fullmatch(plan.get(key, ""))
                for key in ("original_binary_sha256", "binary_sha256",
                            "measurement_build_provenance_sha256",
                            "untrusted_sp_hypothesis_sha256",
                            "measurement_function_map_sha256",
                            "authenticated_untrusted_sp_hypothesis_sha256")) or
            plan.get("function_mapping_authority") !=
                "PINNED_FUNCTION_INDEX_MAPPING_NOT_MODEL_EXACT_LOCATION" or
            plan.get("exact_model_source_location_status") != "UNPROVEN" or
            type(emitter) is not str or emitter not in command or
            emitter not in pins or
            pins[emitter] != plan.get("measurement_emitter_sha256") or
            plan.get("binary_path") not in command or
            plan.get("input_path") not in command):
        raise ValueError("UAF measurement plan provenance is incomplete")
    if (plan["measurement_profile"] == "MD4C_INSTRUMENTED_V1" and
            "ASAN_OPTIONS" not in environment):
        raise ValueError("md4c measurement ASan environment is not pinned")
    frozen: dict[Path, str] = {
        plan_path: expected_plan_sha256,
        Path(plan["binary_path"]): plan["binary_sha256"],
        Path(plan["original_binary_path"]): plan["original_binary_sha256"],
        Path(plan["input_path"]): plan["input_sha256"],
        Path(plan["source_file_path"]): plan["source_file_sha256"],
        Path(plan["original_runtime_receipt_path"]):
            plan["original_runtime_receipt_sha256"],
        Path(plan["original_physical_receipt_path"]):
            plan["original_physical_receipt_sha256"],
        Path(plan["untrusted_sp_hypothesis_path"]):
            plan["untrusted_sp_hypothesis_sha256"],
        Path(plan["measurement_function_map_path"]):
            plan["measurement_function_map_sha256"],
        Path(plan["measurement_build_provenance_path"]):
            plan["measurement_build_provenance_sha256"],
        **{Path(path): digest for path, digest in pins.items()},
    }
    command_paths = {Path(path) for path in pins}
    for path, digest in frozen.items():
        data = _bounded_regular_bytes(
            path, limit=(128_000_000 if path in command_paths else 16_000_000),
            require_owner=path not in command_paths,
            require_single_link=path not in command_paths)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("UAF measurement plan artifact changed")
    try:
        hypothesis = json.loads(_bounded_regular_bytes(
            Path(plan["untrusted_sp_hypothesis_path"])))
        function_map = json.loads(_bounded_regular_bytes(
            Path(plan["measurement_function_map_path"])))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("UAF measurement provenance artifacts are invalid") from exc
    if (hypothesis.get("kind") !=
            "FBV2_AUTHENTICATED_UNTRUSTED_SP_HYPOTHESIS_V1" or
            hypothesis.get("trust") != "UNTRUSTED_MODEL_HYPOTHESIS" or
            hypothesis.get("task_id") != plan["original_task_id"] or
            hypothesis.get("direction_id") != function_map.get("direction_id") or
            hypothesis.get("sp_id") != plan["original_sp_id"] or
            hypothesis.get("campaign_function_id") !=
                function_map.get("campaign_function_id") or
            hypothesis.get("function_name") != plan.get("function_name") or
            hypothesis.get("vulnerability_type") !=
                plan.get("vulnerability_type") or
            hypothesis.get("source_file") is not None or
            hypothesis.get("code_location") != "UNKNOWN" or
            hypothesis.get("exact_source_location_status") != "UNPROVEN" or
            hypothesis.get("evidence_authority") != "NONE" or
            _canonical_json_sha256(hypothesis) !=
                plan.get("authenticated_untrusted_sp_hypothesis_sha256") or
            function_map.get("kind") !=
                "FBV2_PINNED_FUNCTION_INDEX_MAPPING_V1" or
            function_map.get("authority") !=
                "PINNED_FUNCTION_INDEX_MAPPING_NOT_MODEL_EXACT_LOCATION" or
            function_map.get("exact_model_source_location_status") !=
                "UNPROVEN" or
            function_map.get("task_id") != plan["original_task_id"] or
            function_map.get("run_id") != plan["original_run_id"] or
            function_map.get("sp_id") != plan["original_sp_id"] or
            function_map.get("function_name") != plan.get("function_name") or
            function_map.get("source_file") != plan.get("source_file") or
            function_map.get("source_start_line") !=
                plan.get("source_start_line") or
            function_map.get("source_end_line") != plan.get("source_end_line") or
            function_map.get("source_file_path") !=
                plan.get("source_file_path") or
            function_map.get("source_file_sha256") !=
                plan.get("source_file_sha256") or
            function_map.get("source_tree_sha256") !=
                plan.get("source_tree_sha256") or
            plan.get("function_mapping_authority") !=
                function_map.get("authority") or
            plan.get("exact_model_source_location_status") != "UNPROVEN"):
        raise ValueError("UAF measurement hypothesis/function mapping differs")
    input_info = Path(plan["input_path"]).stat()
    if plan.get("input_size") != input_info.st_size:
        raise ValueError("UAF measurement input size changed")
    return plan, plan_bytes, frozen


def run_enveloped_uaf_causal_measurement(
    plan_path: Path, *, expected_plan_sha256: str,
) -> dict[str, Any]:
    """Run one pinned trace command inside a new one-shot V2 envelope.

    The command must emit one raw trace JSON document on stdout and the real
    ASan report on stderr.  This function does not know or use model output and
    cannot grant product Gate credit.
    """
    from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
    from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
    from vulnerabilityanalysis.models import RuntimeResult
    from vulnerabilityanalysis.runtime import (
        _guarded_run, classify_runtime, parse_sanitizer)

    plan_path = Path(plan_path)
    plan, plan_bytes, pinned = _validate_uaf_measurement_plan(
        plan_path, expected_plan_sha256)
    output_dir = plan_path.parent
    ledger_path = Path(plan["measurement_ledger_path"])
    if (plan_path != output_dir / "plan.json" or
            ledger_path != output_dir / "process-ledger.json" or
            ledger_path.exists() or ledger_path.is_symlink() or
            plan.get("measurement_lease_key") !=
                f"{plan['evaluation_id']}:UAF_CAUSAL:ONE_SHOT:000000:"
                "uaf.causal_trace"):
        raise ValueError("UAF measurement one-shot identity differs")
    command = plan.get("measurement_command")
    pins = plan["measurement_command_pins"]

    def pin_hook(_phase: str, actual_command: list[str]) -> None:
        if actual_command != command:
            raise ValueError("UAF measurement command changed")
        command_pin_paths = {Path(path) for path in pins}
        for path, digest in pinned.items():
            content = _bounded_regular_bytes(
                path, limit=(128_000_000 if path in command_pin_paths
                             else 16_000_000),
                require_owner=path not in command_pin_paths,
                require_single_link=path not in command_pin_paths)
            if hashlib.sha256(content).hexdigest() != digest:
                raise ValueError("UAF measurement pin changed")

    if "wall_limit_scope" not in inspect.signature(
            DevelopmentProcessEnvelopeV2).parameters:
        raise ValueError("pinned process envelope lacks local wall isolation")
    ledger = PersistentProcessLedgerV2.create(
        ledger_path, wall_total_seconds=plan["measurement_wall_seconds"],
        fuzz_total_seconds=0)
    envelope_kwargs = {
        "work_item_id": plan["measurement_work_item_id"],
        "assertion_id": plan["measurement_assertion_id"],
        "attempt_id": plan["measurement_attempt_id"],
        "output_limit_bytes": plan["measurement_output_limit_bytes"],
        "total_wall_seconds": plan["measurement_wall_seconds"],
        "pin_hook": pin_hook,
    }
    envelope_kwargs["wall_limit_scope"] = "LOCAL"
    envelope = DevelopmentProcessEnvelopeV2(ledger, **envelope_kwargs)
    try:
        done = _guarded_run(
            command, cwd=output_dir, env=plan["measurement_environment"],
            timeout=plan["measurement_timeout_seconds"], text=False,
            process_envelope=envelope, process_kind="AUX_PROCESS",
            process_segment=plan["measurement_segment"])
        stdout_bytes = _uaf_execution_output_bytes(done.stdout)
        stderr_bytes = _uaf_execution_output_bytes(done.stderr)
        returncode = done.returncode
        process_error = None
    except BaseException as exc:
        stdout_bytes = _uaf_execution_output_bytes(
            getattr(exc, "stdout", getattr(exc, "output", b"")))
        stderr_bytes = _uaf_execution_output_bytes(getattr(exc, "stderr", b""))
        returncode = None
        process_error = exc
    stdout_path = output_dir / "stdout.raw"
    stderr_path = output_dir / "asan.stderr.raw"
    stdout_sha = _write_new(stdout_path, stdout_bytes)
    stderr_sha = _write_new(stderr_path, stderr_bytes)
    ledger_state, ledger_sha = ledger.receipt_snapshot()
    matches = [row for row in ledger_state["finished"]
               if row["key"] == plan["measurement_lease_key"]]
    execution = {
        "kind": "FBV2_UAF_CAUSAL_EXECUTION_V1",
        "evaluation_id": plan["evaluation_id"],
        "profile": plan["measurement_profile"],
        "plan_sha256": expected_plan_sha256,
        "ledger_path": str(ledger.path),
        "ledger_receipt_sha256": ledger_sha,
        "lease": matches[0] if len(matches) == 1 else None,
        "command": command,
        "environment": plan["measurement_environment"],
        "returncode": returncode,
        "signal": (-returncode if type(returncode) is int and returncode < 0
                   else None),
        "timed_out": type(process_error).__name__ == "TimeoutExpired",
        "error_type": type(process_error).__name__ if process_error else None,
        "stdout_path": str(stdout_path), "stdout_sha256": stdout_sha,
        "stderr_path": str(stderr_path), "stderr_sha256": stderr_sha,
        "input_path": plan["input_path"],
        "input_sha256": plan["input_sha256"],
        "binary_path": plan["binary_path"],
        "binary_sha256": plan["binary_sha256"],
        "original_binary_path": plan["original_binary_path"],
        "original_binary_sha256": plan["original_binary_sha256"],
        "build_provenance_path": plan["measurement_build_provenance_path"],
        "build_provenance_sha256":
            plan["measurement_build_provenance_sha256"],
        "emitter_path": plan["measurement_emitter_path"],
        "emitter_sha256": plan["measurement_emitter_sha256"],
    }
    execution_path = output_dir / "execution.json"
    execution_sha = _json_new(execution_path, execution)
    if process_error is not None or len(matches) != 1:
        incomplete = {
            "kind": "FBV2_UAF_CAUSAL_INCOMPLETE_V1",
            "evaluation_id": plan["evaluation_id"],
            "status": "UNPROVEN", "stage": "PHYSICAL_EXECUTION",
            "reason": (type(process_error).__name__ if process_error else
                       "MEASUREMENT_LEASE_NOT_SETTLED_EXACTLY_ONCE"),
            "execution_receipt_path": str(execution_path),
            "execution_receipt_sha256": execution_sha,
            "automatic_retry_permitted": False,
        }
        incomplete_path = output_dir / "incomplete.json"
        incomplete_sha = _json_new(incomplete_path, incomplete)
        return {"status": "INCOMPLETE", "reason": incomplete["reason"],
                "process_ledger": ledger,
                "incomplete_receipt_path": str(incomplete_path),
                "incomplete_receipt_sha256": incomplete_sha}
    stderr_text = stderr_bytes.decode(errors="replace")
    stdout_text = stdout_bytes.decode(errors="replace")
    sanitizer = parse_sanitizer(stderr_text)
    failure = classify_runtime(
        returncode, stderr_text, target_reached=True, sp_reached=None)
    runtime = RuntimeResult(
        returncode, stdout_text, stderr_text,
        -returncode if returncode < 0 else None, False, sanitizer, None,
        failure, crash_triage={
            "category": ("TARGET_CRASH" if sanitizer and returncode != 0
                         else "UNKNOWN")})
    try:
        raw_trace = json.loads(stdout_bytes)
        derived = _derive_uaf_causal_measurement(
            plan, raw_trace, stderr_text)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        incomplete = {
            "kind": "FBV2_UAF_CAUSAL_INCOMPLETE_V1",
            "evaluation_id": plan["evaluation_id"],
            "status": "UNPROVEN", "stage": "CAUSAL_DERIVATION",
            "reason": type(exc).__name__,
            "execution_receipt_path": str(execution_path),
            "execution_receipt_sha256": execution_sha,
            "stdout_sha256": stdout_sha, "stderr_sha256": stderr_sha,
            "automatic_retry_permitted": False,
        }
        incomplete_path = output_dir / "incomplete.json"
        incomplete_sha = _json_new(incomplete_path, incomplete)
        return {"status": "INCOMPLETE", "reason": incomplete["reason"],
                "process_ledger": ledger, "runtime": runtime,
                "incomplete_receipt_path": str(incomplete_path),
                "incomplete_receipt_sha256": incomplete_sha}
    raw_path = output_dir / "raw-trace.json"
    trace_path = output_dir / "trace.json"
    raw_sha = _json_new(raw_path, raw_trace)
    derived["raw_trace_receipt_path"] = str(raw_path)
    derived["raw_trace_receipt_sha256"] = raw_sha
    trace_sha = _json_new(trace_path, derived)
    physical = {
        "kind": "FBV2_UAF_CAUSAL_PHYSICAL_V1",
        "evaluation_id": plan["evaluation_id"],
        "input_path": plan["input_path"],
        "input_sha256": plan["input_sha256"],
        "binary_path": plan["binary_path"],
        "binary_sha256": plan["binary_sha256"],
        "original_binary_path": plan["original_binary_path"],
        "original_binary_sha256": plan["original_binary_sha256"],
        "build_provenance_path": plan["measurement_build_provenance_path"],
        "build_provenance_sha256":
            plan["measurement_build_provenance_sha256"],
        "plan_sha256": expected_plan_sha256,
        "ledger_path": str(ledger.path),
        "ledger_receipt_sha256": ledger_sha,
        "lease": matches[0],
        "command": command,
        "returncode": returncode,
        "signal": runtime.signal,
        "timed_out": runtime.timed_out,
        "sanitizer": runtime.sanitizer,
        "failure_classification": runtime.failure_classification,
        "crash_triage": runtime.crash_triage,
        "execution_receipt_path": str(execution_path),
        "execution_receipt_sha256": execution_sha,
        "stdout_receipt_path": str(stdout_path),
        "stdout_receipt_sha256": stdout_sha,
        "raw_trace_receipt_path": str(raw_path),
        "raw_trace_receipt_sha256": raw_sha,
        "asan_stderr_receipt_path": str(stderr_path),
        "asan_stderr_receipt_sha256": stderr_sha,
        "trace_receipt_path": str(trace_path),
        "trace_receipt_sha256": trace_sha,
    }
    physical_path = output_dir / "physical.json"
    physical_sha = _json_new(physical_path, physical)
    measurement = {
        **derived,
        "trace_receipt_path": str(trace_path),
        "trace_receipt_sha256": trace_sha,
        "physical_receipt_path": str(physical_path),
        "physical_receipt_sha256": physical_sha,
    }
    return {"status": "MEASURED", "measurement": measurement,
            "process_ledger": ledger, "runtime": runtime,
            "runtime_stderr": stderr_text}


def assess_uaf_gate_measurement(
    plan: dict[str, Any], measurement: dict[str, Any], *,
    runtime_stderr: str, process_ledger: Any,
) -> dict[str, Any]:
    """Fail closed on an independently metered UAF condition measurement.

    This is only causal admission to the existing product root-cause function;
    it cannot issue Security Gate VERIFIED or automatic-discovery credit.
    """
    from devtools.campaign_model_gate import _private_bytes
    from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
    from vulnerabilityanalysis.runtime import _frames_by_section

    reason = "MEASUREMENT_SCHEMA_OR_IDENTITY_MISMATCH"
    try:
        access = measurement["access_frame"]
        object_ids = [measurement[key] for key in (
            "allocation_object", "freed_object", "accessed_object")]
        trace_path = Path(measurement["trace_receipt_path"])
        physical_path = Path(measurement["physical_receipt_path"])
        trace_bytes = _private_bytes(trace_path)
        physical_bytes = _private_bytes(physical_path)
        if trace_bytes is None or physical_bytes is None:
            raise ValueError("measurement receipt is absent")
        trace_payload = json.loads(trace_bytes)
        physical = json.loads(physical_bytes)
        if type(process_ledger) is not PersistentProcessLedgerV2:
            raise ValueError("measurement process ledger is unavailable")
        ledger_state, ledger_sha = process_ledger.receipt_snapshot()
        lease = physical.get("lease")
        finished = ledger_state.get("finished")
        matching_leases = ([row for row in finished if row == lease]
                           if isinstance(finished, list) else [])
        plan_bytes = (json.dumps(plan, sort_keys=True, separators=(",", ":"),
                                 allow_nan=False) + "\n").encode()
        plan_sha = hashlib.sha256(plan_bytes).hexdigest()
        raw_path = Path(physical["raw_trace_receipt_path"])
        stderr_path = Path(physical["asan_stderr_receipt_path"])
        stdout_path = Path(physical["stdout_receipt_path"])
        execution_path = Path(physical["execution_receipt_path"])
        raw_bytes = _private_bytes(raw_path)
        stderr_bytes = _private_bytes(stderr_path)
        stdout_bytes = _private_bytes(stdout_path)
        execution_bytes = _private_bytes(execution_path)
        if any(value is None for value in (
                raw_bytes, stderr_bytes, stdout_bytes, execution_bytes)):
            raise ValueError("raw UAF measurement evidence is absent")
        execution = json.loads(execution_bytes)
        raw_trace = json.loads(raw_bytes)
        if stderr_bytes.decode() != runtime_stderr:
            raise ValueError("raw ASan stderr differs")
        derived = _derive_uaf_causal_measurement(
            plan, raw_trace, runtime_stderr)
        derived["raw_trace_receipt_path"] = str(raw_path)
        derived["raw_trace_receipt_sha256"] = hashlib.sha256(
            raw_bytes).hexdigest()
        expected_trace = {key: value for key, value in measurement.items()
                          if key not in {"trace_receipt_path",
                                         "trace_receipt_sha256",
                                         "physical_receipt_path",
                                         "physical_receipt_sha256"}}
        receipts_ok = (
            trace_payload == expected_trace == derived and
            hashlib.sha256(trace_bytes).hexdigest() ==
                measurement.get("trace_receipt_sha256") and
            hashlib.sha256(physical_bytes).hexdigest() ==
                measurement.get("physical_receipt_sha256") and
            physical.get("kind") == "FBV2_UAF_CAUSAL_PHYSICAL_V1" and
            physical.get("evaluation_id") == plan.get("evaluation_id") and
            physical.get("input_path") == plan.get("input_path") and
            physical.get("input_sha256") == plan.get("input_sha256") and
            physical.get("binary_path") == plan.get("binary_path") and
            physical.get("binary_sha256") == plan.get("binary_sha256") and
            physical.get("original_binary_path") ==
                plan.get("original_binary_path") and
            physical.get("original_binary_sha256") ==
                plan.get("original_binary_sha256") and
            physical.get("build_provenance_path") ==
                plan.get("measurement_build_provenance_path") and
            physical.get("build_provenance_sha256") ==
                plan.get("measurement_build_provenance_sha256") and
            physical.get("plan_sha256") == plan_sha and
            str(process_ledger.path) == plan.get("measurement_ledger_path") and
            physical.get("ledger_path") == plan.get("measurement_ledger_path") and
            physical.get("ledger_receipt_sha256") == ledger_sha and
            isinstance(lease, dict) and len(matching_leases) == 1 and
            lease.get("key") == plan.get("measurement_lease_key") and
            lease.get("kind") == plan.get("measurement_process_kind") ==
                "AUX_PROCESS" and
            lease.get("cleanup_complete") is True and
            lease.get("output_limited") is False and
            lease.get("overrun") is False and
            physical.get("command") == plan.get("measurement_command") and
            execution.get("kind") == "FBV2_UAF_CAUSAL_EXECUTION_V1" and
            execution.get("evaluation_id") == plan.get("evaluation_id") and
            execution.get("profile") == plan.get("measurement_profile") and
            execution.get("plan_sha256") == plan_sha and
            execution.get("ledger_path") == plan.get("measurement_ledger_path") and
            execution.get("ledger_receipt_sha256") == ledger_sha and
            execution.get("lease") == lease and
            execution.get("command") == plan.get("measurement_command") and
            execution.get("environment") == plan.get("measurement_environment") and
            execution.get("input_path") == plan.get("input_path") and
            execution.get("input_sha256") == plan.get("input_sha256") and
            execution.get("binary_path") == plan.get("binary_path") and
            execution.get("binary_sha256") == plan.get("binary_sha256") and
            execution.get("original_binary_path") ==
                plan.get("original_binary_path") and
            execution.get("original_binary_sha256") ==
                plan.get("original_binary_sha256") and
            execution.get("build_provenance_path") ==
                plan.get("measurement_build_provenance_path") and
            execution.get("build_provenance_sha256") ==
                plan.get("measurement_build_provenance_sha256") and
            execution.get("emitter_path") == plan.get("measurement_emitter_path") and
            execution.get("emitter_sha256") == plan.get("measurement_emitter_sha256") and
            physical.get("execution_receipt_path") == str(execution_path) and
            physical.get("execution_receipt_sha256") ==
                hashlib.sha256(execution_bytes).hexdigest() and
            physical.get("stdout_receipt_path") == str(stdout_path) and
            physical.get("stdout_receipt_sha256") ==
                hashlib.sha256(stdout_bytes).hexdigest() and
            execution.get("stdout_path") == str(stdout_path) and
            execution.get("stdout_sha256") ==
                hashlib.sha256(stdout_bytes).hexdigest() and
            execution.get("stderr_path") == str(stderr_path) and
            execution.get("stderr_sha256") ==
                hashlib.sha256(stderr_bytes).hexdigest() and
            type(physical.get("returncode")) is int and
            physical.get("returncode") != 0 and
            physical.get("returncode") == execution.get("returncode") and
            physical.get("signal") == execution.get("signal") and
            physical.get("timed_out") == execution.get("timed_out") is False and
            physical.get("sanitizer") is not None and
            physical.get("failure_classification") == "SANITIZER_CRASH" and
            isinstance(physical.get("crash_triage"), dict) and
            physical["crash_triage"].get("category") == "TARGET_CRASH" and
            physical.get("raw_trace_receipt_path") == str(raw_path) and
            physical.get("raw_trace_receipt_sha256") ==
                hashlib.sha256(raw_bytes).hexdigest() and
            physical.get("asan_stderr_receipt_path") == str(stderr_path) and
            physical.get("asan_stderr_receipt_sha256") ==
                hashlib.sha256(stderr_bytes).hexdigest() and
            physical.get("trace_receipt_path") == str(trace_path) and
            physical.get("trace_receipt_sha256") ==
                hashlib.sha256(trace_bytes).hexdigest() and
            ledger_state.get("stop_status") is None and
            not ledger_state.get("active"))
        frames = _frames_by_section(runtime_stderr)
        actual_access = [frame for frame in frames["access"]
                         if frame[0] == access.get("function_name") and
                         frame[1] == access.get("source_file") and
                         frame[2] == access.get("line")]
        source_path = Path(plan["source_file_path"])
        source_bytes = _bounded_regular_bytes(source_path)
        exact_source = (
            Path(access["source_file"]).resolve(strict=False) == source_path and
            measurement.get("mapped_source_file_path") == str(source_path) and
            measurement.get("mapped_source_file_sha256") ==
                hashlib.sha256(source_bytes).hexdigest() ==
                plan.get("source_file_sha256"))
        identity_ok = (
            plan.get("kind") == "FBV2_UAF_GATE_REEVALUATION_PLAN_V1" and
            plan.get("status") == "PREPARED_NO_TARGET_REPLAY" and
            _structured_gate_hypothesis(plan.get("vulnerability_type")) ==
                "use-after-free" and
            measurement.get("kind") == "FBV2_UAF_CAUSAL_MEASUREMENT_V1" and
            measurement.get("evaluation_id") == plan.get("evaluation_id") and
            all(measurement.get(key) == plan.get(key) for key in (
                "input_sha256", "binary_sha256", "source_tree_sha256",
                "harness_sha256")) and
            measurement.get("asan_stderr_sha256") ==
                hashlib.sha256(runtime_stderr.encode()).hexdigest() and
            "ERROR: AddressSanitizer: heap-use-after-free" in runtime_stderr)
        frame_ok = (
            isinstance(access, dict) and
            access.get("function_name") == plan.get("function_name") and
            exact_source and len(actual_access) == 1 and
            bool(frames["free"]) and bool(frames["allocation"]) and
            type(access.get("line")) is int and
            plan["source_start_line"] <= access["line"] <=
                plan["source_end_line"])
        target_execution = measurement.get("target_execution")
        target_execution_ok = (
            plan.get("measurement_profile") == "SYNTHETIC_PROVIDER_FREE" or
            isinstance(target_execution, dict) and
            target_execution.get("command") ==
                plan.get("measurement_target_command") and
            target_execution.get("returncode") == physical.get("returncode") and
            target_execution.get("signal") == physical.get("signal") and
            target_execution.get("stderr_sha256") ==
                physical.get("asan_stderr_receipt_sha256"))
        condition_ok = (
            measurement.get("sanitizer_family") == "use-after-free" and
            all(isinstance(value, str) and value for value in object_ids) and
            len(set(object_ids)) == 1 and
            measurement.get("realloc_observed") is True and
            measurement.get("stale_pointer_observed") is True and
            measurement.get("sp_condition_reached") is True and
            measurement.get("external_input_reached") is True and
            target_execution_ok and
            receipts_ok)
        if not identity_ok:
            reason = "MEASUREMENT_IDENTITY_MISMATCH"
        elif not frame_ok:
            reason = "ASAN_ACCESS_OUTSIDE_ORIGINAL_FUNCTION_SPAN"
        elif not condition_ok:
            reason = "UAF_CAUSAL_CONDITION_UNPROVEN"
        else:
            return {
                "status": "CAUSAL_LINK_SUPPORTED",
                "reason": "INDEPENDENT_FUNCTION_SPAN_AND_UAF_STATE_MEASURED",
                "evaluation_id": plan["evaluation_id"],
                "observed_code_location":
                    f"{access['source_file']}:{access['line']}",
                "observed_uaf_root_cause_status":
                    "SUPPORTED_BY_AUTHENTICATED_MEASUREMENT",
                "original_sp_causal_attribution_status":
                    "UNPROVEN_MECHANISM_NOT_STRUCTURED",
                "product_gate_credit": False,
                "automatic_discovery_credit": False,
            }
    except (KeyError, TypeError, ValueError, AttributeError, OSError, RuntimeError,
            json.JSONDecodeError):
        pass
    return {"status": "UNPROVEN", "reason": reason,
            "evaluation_id": plan.get("evaluation_id"),
            "observed_uaf_root_cause_status": "UNPROVEN",
            "original_sp_causal_attribution_status": "UNPROVEN",
            "product_gate_credit": False,
            "automatic_discovery_credit": False}


def evaluate_measured_uaf_with_product_root_cause(
    plan: dict[str, Any], measurement: dict[str, Any], runtime: Any, *,
    target_root: Path, harness_path: Path, process_ledger: Any,
) -> dict[str, Any]:
    """Invoke the real product root-cause function only after strict admission."""
    from dataclasses import replace
    from vulnerabilityanalysis.final_verification import verify_root_cause
    from vulnerabilityanalysis.models import SuspiciousPoint
    from devtools.campaign_model_gate import _private_bytes

    try:
        physical_bytes = _private_bytes(Path(measurement["physical_receipt_path"]))
        if physical_bytes is None:
            raise ValueError("physical measurement receipt is absent")
        physical = json.loads(physical_bytes)
        runtime_matches_physical = (
            runtime.exit_code == physical.get("returncode") and
            runtime.signal == physical.get("signal") and
            runtime.timed_out == physical.get("timed_out") and
            runtime.sanitizer == physical.get("sanitizer") and
            runtime.failure_classification ==
                physical.get("failure_classification") and
            runtime.crash_triage == physical.get("crash_triage") and
            hashlib.sha256(runtime.stdout.encode()).hexdigest() ==
                physical.get("stdout_receipt_sha256") and
            hashlib.sha256(runtime.stderr.encode()).hexdigest() ==
                physical.get("asan_stderr_receipt_sha256"))
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
        runtime_matches_physical = False
    if not runtime_matches_physical:
        return {
            "status": "UNPROVEN",
            "reason": "RUNTIME_RESULT_NOT_ISSUED_BY_MEASUREMENT_EXECUTION",
            "evaluation_id": plan.get("evaluation_id"),
            "observed_uaf_root_cause_status": "UNPROVEN",
            "original_sp_causal_attribution_status": "UNPROVEN",
            "product_gate_credit": False,
            "automatic_discovery_credit": False,
            "product_root_cause_invoked": False,
        }

    admitted = assess_uaf_gate_measurement(
        plan, measurement, runtime_stderr=runtime.stderr,
        process_ledger=process_ledger)
    if admitted["status"] != "CAUSAL_LINK_SUPPORTED":
        return {**admitted, "product_root_cause_invoked": False}
    access = measurement["access_frame"]
    point = SuspiciousPoint(
        f"reevaluation-{plan['evaluation_id']}", "INDEPENDENT_REEVALUATION",
        "INDEPENDENT_REEVALUATION", plan["function_name"],
        plan["source_file"], f"{access['source_file']}:{access['line']}",
        "independently observed stale-pointer access", "use-after-free",
        ["same heap object was reallocated, freed, and accessed"],
        "MEASURED_FROM_OFFICIAL_HARNESS_INPUT", [
            "realloc observed", "stale pointer observed"], [], [], [],
        security_property="memory safety")
    measured_runtime = replace(
        runtime, function_reached=True, sp_location_reached=True,
        sp_condition_reached=True)
    root = verify_root_cause(
        point, measured_runtime, Path(target_root), Path(harness_path))
    return {**admitted, "product_root_cause_invoked": True,
            "product_root_cause_verdict": root.verdict,
            "product_crash_relation": root.crash_relation,
            "product_root_cause_location": root.root_cause_location,
            "product_gate_credit": False,
            "automatic_discovery_credit": False}


def consume_qualified_pov_observation(
    adapter: ProductQualifiedPoVAdapter, pov_id: str, *,
    recheck: Callable[[], None], timeout_seconds: float = 10.0,
    model_gate: Any = None, gate_wall_seconds: float | None = None,
    pov_admission_mode: str = "legacy_score",
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
    explicitly_reserved = gate_wall_seconds is not None
    if gate_wall_seconds is None:
        gate_wall_seconds = adapter.wall_seconds
    if (type(gate_wall_seconds) not in (int, float) or
            not math.isfinite(gate_wall_seconds) or
            (explicitly_reserved and
             gate_wall_seconds < timeout_seconds + 9.5) or
            gate_wall_seconds > 3600):
        raise ValueError("invalid qualified Gate wall reservation")
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
                   adapter, pov_id, model_gate, recheck=recheck,
                   pov_admission_mode=pov_admission_mode))
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
    original_hypothesis = None
    if origin_verified:
        original_hypothesis = _verified_lineage_hypothesis(lineage)
    hypothesis_status = ("AVAILABLE_UNTRUSTED" if original_hypothesis is not None
                         else "UNAVAILABLE")
    evaluation_candidate_id = stable_id(
        "fbv2-pov-lead", adapter.task_id, pov_id, input_sha)
    product_pov_id = stable_id(
        "poc", "fbv2-pov-observation", pov_id, input_sha)

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
            # The product replay must re-observe this same crash before any
            # terminal Gate rejection can settle the original observation.
            "original_crash_id": crash_fingerprint(runtime),
            "original_runtime_receipt_path": str(runtime_path),
            "run_id": adapter.run_id, "pov_id": pov_id,
            "sp_id": str(raw["suspicious_point_id"]),
            "evaluation_candidate_id": evaluation_candidate_id,
            "evaluation_pov_id": product_pov_id,
            "input_sha256": input_sha, "binary_sha256": binary_sha,
            "original_runtime_receipt_sha256": _sha(runtime_path),
            "original_physical_receipt_sha256": _sha(physical_path),
        })
        hypothesis_path = claim_dir / "original-sp-hypothesis.json"
        hypothesis_sha256 = (_json_new(hypothesis_path, original_hypothesis)
                             if original_hypothesis is not None else None)
        origin_path = claim_dir / "origin-lineage.json"
        origin_sha256 = _json_new(origin_path, {
            "kind": "FBV2_POV_PRODUCT_ORIGIN_LINEAGE_V1",
            "task_id": adapter.task_id, "run_id": adapter.run_id,
            "pov_id": pov_id, "input_sha256": input_sha,
            "origin_verification_status": origin_status,
            "lineage": lineage,
            "original_sp_hypothesis_path": (
                str(hypothesis_path) if hypothesis_sha256 else None),
            "original_sp_hypothesis_sha256": hypothesis_sha256,
            "original_sp_hypothesis_trust": (
                "UNTRUSTED_MODEL_HYPOTHESIS" if hypothesis_sha256 else None),
            "original_sp_hypothesis_status": hypothesis_status,
            "automatic_discovery": False,
            "discovery_credit": "NOT_CREDITED",
        })
        binding_path = claim_dir / "evaluation-binding.json"
        binding_sha256 = _json_new(binding_path, {
            "kind": "FBV2_CONTROLLED_PRODUCT_REPLAY_BINDING_V1",
            "original_task_id": adapter.task_id,
            "original_run_id": adapter.run_id,
            "original_sp_id": str(raw["suspicious_point_id"]),
            "original_pov_id": pov_id,
            "evaluation_candidate_id": evaluation_candidate_id,
            "evaluation_pov_id": product_pov_id,
            "input_sha256": input_sha,
            "binary_sha256": binary_sha,
            "origin_lineage_receipt_sha256": origin_sha256,
            "untrusted_sp_hypothesis_sha256": hypothesis_sha256,
            "origin_lineage_status": origin_status,
            "original_sp_causal_relation_status": "UNPROVEN",
            "automatic_discovery": False,
            "automatic_discovery_credit": "NOT_CREDITED",
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
            "evaluation_binding_path": str(binding_path),
            "evaluation_binding_sha256": binding_sha256,
            "evaluation_candidate_id": evaluation_candidate_id,
            "original_sp_hypothesis_path": (
                str(hypothesis_path) if hypothesis_sha256 else None),
            "original_sp_hypothesis_sha256": hypothesis_sha256,
            "original_sp_hypothesis_trust": (
                "UNTRUSTED_MODEL_HYPOTHESIS" if hypothesis_sha256 else None),
            "original_sp_hypothesis_status": hypothesis_status,
            "automatic_discovery": False,
        })

        def pin(_phase: str, _command: list[str]) -> None:
            recheck()
            same_binary, same_sha = adapter.binding.pinned_binary()
            if (same_binary != binary or same_sha != binary_sha or
                    _sha(origin_path) != origin_sha256 or
                    _sha(binding_path) != binding_sha256 or
                    (hypothesis_sha256 is not None and
                     _sha(hypothesis_path) != hypothesis_sha256) or
                    (origin_verified and
                     verify_qualified_pov_runtime_lineage(
                         adapter, pov_id, model_gate,
                         recheck=recheck,
                         pov_admission_mode=pov_admission_mode) != lineage) or
                    _sha(retained) != input_sha or _sha(input_path) != input_sha or
                    _sha(runtime_path) != saved["runtime_receipt_sha256"] or
                    _sha(physical_path) != saved["physical_receipt_sha256"]):
                raise ValueError("PoV observation changed before product replay")

        envelope = adapter._envelope_type(
            adapter.ledger, work_item_id=adapter.task_id,
            assertion_id=str(raw["suspicious_point_id"]),
            attempt_id=pov_id + "_gate", output_limit_bytes=adapter.output_limit_bytes,
            total_wall_seconds=gate_wall_seconds, pin_hook=pin,
            wall_limit_scope="LOCAL")
        lead_id = evaluation_candidate_id
        if original_hypothesis is None:
            lead = SuspiciousPoint(
                lead_id, "FBV2_POV_OBSERVATION", "FBV2_POV_OBSERVATION",
                "UNKNOWN", None, "UNKNOWN",
                "unclassified FBv2 PoV crash input",
                "unverified sanitizer observation", [], "UNKNOWN", [], [], [],
                ["original FBv2 SP relation is not presumed"])
        else:
            guidance = original_hypothesis.get("pov_guidance")
            structured_hypothesis = _structured_gate_hypothesis(
                original_hypothesis["vulnerability_type"])
            lead = SuspiciousPoint(
                lead_id, "FBV2_ORIGINAL_SP_HYPOTHESIS",
                original_hypothesis["direction_id"],
                original_hypothesis["function_name"],
                None,
                "UNKNOWN",
                original_hypothesis["vulnerability_type"],
                (structured_hypothesis or
                 "unrecognized untrusted vulnerability type"),
                ([guidance] if guidance else []),
                "UNKNOWN", [], [], [],
                ["model hypothesis is not evidence; independently verify "
                 "sanitizer relation, root cause, and security property",
                 *([] if structured_hypothesis else
                   ["model vulnerability type has no unique sanitizer family"])])
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
                _sha(binding_path) != binding_sha256 or
                (hypothesis_sha256 is not None and
                 _sha(hypothesis_path) != hypothesis_sha256) or
                (origin_verified and
                 verify_qualified_pov_runtime_lineage(
                     adapter, pov_id, model_gate,
                     recheck=recheck,
                     pov_admission_mode=pov_admission_mode) != lineage)):
            from vulnerabilityanalysis.runtime import ProcessEnvelopeStop
            try:
                adapter.ledger.mark_stop(
                    "STOPPED_PIN_DRIFT",
                    "PoV origin lineage changed during product replay")
            except BaseException as audit_exc:
                stopped = ProcessEnvelopeStop(
                    "STOPPED_PIN_DRIFT",
                    "PoV origin lineage changed and stop receipt failed")
                stopped.add_note(
                    "Pin-drift stop receipt failed: " +
                    type(audit_exc).__name__)
                raise stopped from audit_exc
            raise ProcessEnvelopeStop(
                "STOPPED_PIN_DRIFT",
                "PoV origin lineage changed during product replay")
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
            "original_sp_id": str(raw["suspicious_point_id"]),
            "original_pov_id": pov_id,
            "evaluation_candidate_id": evaluation_candidate_id,
            "evaluation_pov_id": product_pov_id,
            "input_sha256": input_sha, "binary_sha256": binary_sha,
            "source": "FBV2_POV_OBSERVATION", "automatic_discovery": False,
            "claimed_input_origin": claimed_origin,
            "origin_verification_status": origin_status,
            "origin_lineage_receipt_path": str(origin_path),
            "origin_lineage_receipt_sha256": origin_sha256,
            "evaluation_binding_path": str(binding_path),
            "evaluation_binding_sha256": binding_sha256,
            "original_sp_hypothesis_path": (
                str(hypothesis_path) if hypothesis_sha256 else None),
            "original_sp_hypothesis_sha256": hypothesis_sha256,
            "original_sp_hypothesis_trust": (
                "UNTRUSTED_MODEL_HYPOTHESIS" if hypothesis_sha256 else None),
            "original_sp_hypothesis_status": hypothesis_status,
            "discovery_credit": "NOT_CREDITED",
            "automatic_discovery_credit": "NOT_CREDITED",
            "original_sp_causal_relation_status": "UNPROVEN",
            "product_runtime_artifact": str(product_runtime),
            "product_runtime_sha256": _sha(product_runtime),
            "canonical_crash_artifact": str(canonical) if canonical and canonical.is_file() else None,
            "canonical_crash_sha256": _sha(canonical) if canonical and canonical.is_file() else None,
            "product_gate_status": gate.get("independent_verification_status", "NOT_VERIFIED"),
            **trace_summary,
            "observed_sanitizer": actual.sanitizer,
        }
        # A BLOCKED_* label is not a settlement. Terminality is carried only
        # by an authenticated structured resolution.
        outcome.update(_pov_gate_resolution_fields(
            adapter, gate, crash_id, canonical if canonical and canonical.is_file()
            else None, product_runtime, claim_dir, outcome))
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
                any(not isinstance(result, dict) or
                    result.get("input_sha256") != row["sha256"]
                    for row, result in zip(replay_inputs[:replay_limit],
                                           consumer_rows)) or
                (any(row.get("status") == "VERIFIED"
                     for row in consumer_rows[:min(len(replay_inputs),
                                                   replay_limit)]) and
                 not consumer_leases) or
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
        proven_consumer_rows = all(
            row.get("status") == "VERIFIED" and
            verified_fuzzer_consumer_evidence(run_dir, row)
            for row in consumer_rows)
        outcome = {
            "kind": "FBV2_QUALIFIED_SP_FUZZ_OUTCOME_V1",
            "status": "INCOMPLETE_FUZZ_WITH_OBSERVED_CRASH" if timed_out_witness else
                "PENDING_INDEPENDENT_VALIDATION" if crash_ids and
                (not consumer_rows or not proven_consumer_rows) else
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
