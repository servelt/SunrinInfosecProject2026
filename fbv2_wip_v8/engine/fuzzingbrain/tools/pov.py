"""
POV Tools

MCP tools for POV Agent to generate and manage POVs (Proof of Vulnerability).

Uses a thread-safe global dict for context management, allowing multiple
POV agents to run concurrently without interfering with each other.
Each agent is identified by its worker_id.

Context isolation:
- _pov_contexts: Thread-safe dict keyed by worker_id (shared, protected by lock)
- _current_worker_id: ContextVar for asyncio task isolation (each async task has its own)
"""

import base64
import binascii
import hashlib
import os
import threading
import uuid
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from bson import ObjectId
from loguru import logger

from . import tools_mcp
from .coverage import (
    run_coverage_fuzzer,
    run_gdb_trace,
    parse_lcov,
    get_coverage_context,
)
from ..core.models import POV
from ..core.pov_packager import POVPackager
from ..core.utils import generate_id
from ..db import RepositoryManager
from .qualified_runtime import (
    QualifiedGeneratorRequest, QualifiedRuntimeBinding, QualifiedRuntimeRequest,
    validate_outcome,
)


# =============================================================================
# Thread-Safe Context for POV Tools
# =============================================================================

# Global dict to store context per worker_id
# Using a dict + lock because the context data is shared and mutable
_pov_contexts: Dict[str, Dict[str, Any]] = {}
_pov_contexts_lock = threading.Lock()

# Current active worker_id - using ContextVar for async task isolation
# Each asyncio.Task has its own value, preventing cross-contamination
_current_worker_id: ContextVar[Optional[str]] = ContextVar(
    "pov_current_worker_id", default=None
)


def set_pov_context(
    task_id: str,
    worker_id: str,
    output_dir: Path,
    repos: RepositoryManager,
    fuzzer: str = "",
    sanitizer: str = "address",
    suspicious_point_id: str = "",
    fuzzer_path: Optional[Path] = None,
    docker_image: Optional[str] = None,
    workspace_path: Optional[Path] = None,
    fuzzer_source: Optional[str] = None,
    fuzzer_manager=None,  # FuzzerManager instance for SP Fuzzer integration
    agent_id: Optional[str] = None,  # Agent ObjectId for tracking POV creator
    qualified_runtime_required: bool = False,
    qualified_runtime_binding: QualifiedRuntimeBinding | None = None,
) -> None:
    """
    Set the context for POV tools (thread-safe).

    Each concurrent POV agent gets its own isolated context, identified by worker_id.

    Args:
        task_id: Current task ID
        worker_id: Current worker ID
        output_dir: Directory to save POV blob files
        repos: Database repository manager
        fuzzer: Fuzzer name
        sanitizer: Sanitizer type
        suspicious_point_id: Current suspicious point being processed
        fuzzer_path: Path to fuzzer binary (for verification)
        docker_image: Docker image for running fuzzer
        workspace_path: Path to workspace directory
        fuzzer_source: Fuzzer harness source code
        fuzzer_manager: FuzzerManager instance for SP Fuzzer corpus integration
        agent_id: Agent ObjectId for tracking which POVAgent created POVs
    """
    if qualified_runtime_binding is not None and (
            not qualified_runtime_required or
            type(qualified_runtime_binding) is not QualifiedRuntimeBinding):
        raise ValueError("qualified Runtime binding requires the opt-in PoV path")
    ctx = {
        "task_id": task_id,
        "worker_id": worker_id,
        "output_dir": Path(output_dir).absolute() if output_dir else None,
        "repos": repos,
        "fuzzer": fuzzer,
        "sanitizer": sanitizer,
        "suspicious_point_id": suspicious_point_id,
        "iteration": 0,
        "attempt": 0,
        "fuzzer_path": Path(fuzzer_path).absolute() if fuzzer_path else None,
        "docker_image": docker_image,
        "workspace_path": Path(workspace_path).absolute() if workspace_path else None,
        "fuzzer_source": fuzzer_source,
        "fuzzer_manager": fuzzer_manager,
        "agent_id": agent_id,
        "qualified_runtime_required": qualified_runtime_required,
        "qualified_runtime_binding": qualified_runtime_binding,
    }
    with _pov_contexts_lock:
        _pov_contexts[worker_id] = ctx
    # Set current worker_id in context (async task-local)
    _current_worker_id.set(worker_id)


def update_pov_iteration(iteration: int, worker_id: Optional[str] = None) -> None:
    """
    Update current agent loop iteration (thread-safe).

    Args:
        iteration: Current iteration number
        worker_id: Worker ID (uses context-local if not provided)
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        logger.warning("[POV] update_pov_iteration: no worker_id available")
        return

    with _pov_contexts_lock:
        if wid in _pov_contexts:
            _pov_contexts[wid]["iteration"] = iteration


def get_pov_context(worker_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get the current POV context (thread-safe).

    Args:
        worker_id: Worker ID (uses context-local if not provided)

    Returns:
        Copy of the context dict
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        return {}

    with _pov_contexts_lock:
        if wid in _pov_contexts:
            return _pov_contexts[wid].copy()
    return {}


def clear_pov_context(worker_id: Optional[str] = None) -> None:
    """
    Clear the POV context for a worker (thread-safe).

    Args:
        worker_id: Worker ID (uses context-local if not provided)
    """
    wid = worker_id or _current_worker_id.get()
    if not wid:
        return

    with _pov_contexts_lock:
        if wid in _pov_contexts:
            del _pov_contexts[wid]

    # Clear context-local if matching
    if _current_worker_id.get() == wid:
        _current_worker_id.set(None)


def _get_current_context() -> Optional[Dict[str, Any]]:
    """Get the current context for tools (internal use)."""
    wid = _current_worker_id.get()
    if not wid:
        return None

    with _pov_contexts_lock:
        return _pov_contexts.get(wid)


def _get_context_by_worker_id(worker_id: str) -> Optional[Dict[str, Any]]:
    """
    Get context by explicit worker_id (for isolated MCP servers).

    This is the preferred method when worker_id is known, as it doesn't
    depend on ContextVar propagation.
    """
    if not worker_id:
        return None
    with _pov_contexts_lock:
        return _pov_contexts.get(worker_id)


def _get_all_fuzzers(ctx: Dict[str, Any]) -> List[Path]:
    """
    Get all available fuzzers from workspace.

    Looks in workspace_path/fuzz-tooling/build/out/{project}_{sanitizer}/
    for executable files.

    Returns:
        List of fuzzer paths
    """
    workspace_path = ctx.get("workspace_path")
    sanitizer = ctx.get("sanitizer", "address")

    if not workspace_path:
        return []

    # Find fuzzer output directory
    out_base = workspace_path / "fuzz-tooling" / "build" / "out"
    if not out_base.exists():
        return []

    # Find directories matching *_{sanitizer}
    fuzzers = []
    skip_files = {
        "llvm-symbolizer",
        "sancov",
        "clang",
        "clang++",
        "llvm-cov",
        "llvm-profdata",
        "llvm-ar",
    }
    skip_extensions = {
        ".bin",
        ".log",
        ".dict",
        ".options",
        ".bc",
        ".json",
        ".o",
        ".a",
        ".so",
        ".h",
        ".c",
        ".cpp",
        ".cc",
        ".py",
        ".sh",
        ".txt",
        ".md",
        ".zip",
        ".tar",
        ".gz",
    }

    for out_dir in out_base.iterdir():
        if not out_dir.is_dir():
            continue
        if not out_dir.name.endswith(f"_{sanitizer}"):
            continue

        # Find executables in this directory
        for f in out_dir.iterdir():
            if f.name in skip_files:
                continue
            if f.suffix.lower() in skip_extensions:
                continue
            if f.is_dir():
                continue
            if f.is_file() and os.access(f, os.X_OK):
                fuzzers.append(f)

    return fuzzers


def _ensure_context(worker_id: str = None) -> Optional[Dict[str, Any]]:
    """
    Ensure POV context is set. Returns error dict if not configured.

    Args:
        worker_id: If provided, use explicit worker_id instead of ContextVar
    """
    if worker_id:
        ctx = _get_context_by_worker_id(worker_id)
    else:
        ctx = _get_current_context()

    if ctx is None or ctx.get("task_id") is None:
        return {
            "success": False,
            "error": "POV context not set. Call set_pov_context first.",
        }
    if ctx.get("repos") is None:
        return {
            "success": False,
            "error": "Database repos not available in POV context.",
        }
    return None


# =============================================================================
# POV Tools - Implementation Functions (for mcp_factory)
# =============================================================================


def get_fuzzer_info_impl(worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of get_fuzzer_info (without MCP decorator).

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    fuzzer_source = ctx.get("fuzzer_source") or "(Fuzzer source code not available)"

    return {
        "success": True,
        "fuzzer": ctx.get("fuzzer", ""),
        "sanitizer": ctx.get("sanitizer", "address"),
        "fuzzer_source": fuzzer_source,
        "current_attempt": ctx.get("attempt", 0),
        "current_iteration": ctx.get("iteration", 0),
    }


def create_pov_impl(generator_code: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of create_pov (without MCP decorator).

    Args:
        generator_code: Python code with generate() function
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    suspicious_point_id = ctx.get("suspicious_point_id", "")

    if not suspicious_point_id:
        return {"success": False, "error": "suspicious_point_id not set in context"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}

    # Use the shared implementation logic
    return _create_pov_core(
        suspicious_point_id=suspicious_point_id,
        generator_code=generator_code,
        description="POV generated via isolated MCP",
        worker_id=worker_id,
    )


def verify_pov_impl(pov_id: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Implementation of verify_pov (without MCP decorator).

    Args:
        pov_id: POV ID to verify
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err

    return _verify_pov_core(pov_id=pov_id, worker_id=worker_id)


def trace_pov_impl(
    generator_code: str,
    target_functions: List[str] = None,
    agent_msg: str = None,
    worker_id: str = None,
) -> Dict[str, Any]:
    """
    Implementation of trace_pov (without MCP decorator).

    Flow:
    1. Execute generator_code to get blob
    2. Run ASAN fuzzer to detect crash (_run_fuzzer_docker)
    3. If crashed -> return success with processor="asan"
    4. If no crash -> run GDB trace for function tracking (processor="gdb")
    5. If GDB fails -> fallback to coverage fuzzer (processor="cov")

    Args:
        generator_code: Python code with generate() function that returns bytes
        target_functions: List of function names to check if reached
        agent_msg: What the agent wants to know about the trace
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    err = _ensure_context(worker_id=worker_id)
    if err:
        return err
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    if ctx and ctx.get("qualified_runtime_required"):
        return _pending_qualified_runtime()

    # =========================================================================
    # Step 1: Execute generator code to get blob
    # =========================================================================
    from ..fuzzer.seed_sandbox import SeedSandboxCleanupError

    try:
        blobs, error = _execute_generator_code(generator_code, num_variants=1)
    except SeedSandboxCleanupError as exc:
        return {"success": False, "error": str(exc),
                "fatal_sandbox_cleanup": True}
    if error:
        return {"success": False, "error": f"Generator code error: {error}"}
    if not blobs:
        return {"success": False, "error": "Generator code produced no blob"}

    blob = blobs[0]

    # Get context
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    coverage_fuzzer_dir, project_name, src_dir = get_coverage_context()

    fuzzer_name = ctx.get("fuzzer", "")
    if not fuzzer_name:
        return {"success": False, "error": "No fuzzer name in context"}

    # Get ASAN fuzzer path and docker image for verification
    fuzzer_path = ctx.get("fuzzer_path")
    docker_image = ctx.get("docker_image")
    sanitizer = ctx.get("sanitizer", "address")

    # Create work directory (avoid /tmp - Docker Snap can't mount it)
    output_dir = ctx.get("output_dir")
    workspace_path = ctx.get("workspace_path")
    trace_id = str(uuid.uuid4())[:8]
    if output_dir:
        work_dir = Path(output_dir) / "trace" / trace_id
    elif workspace_path:
        work_dir = Path(workspace_path) / ".trace" / trace_id
    else:
        work_dir = Path.cwd() / ".pov_trace" / trace_id
    work_dir.mkdir(parents=True, exist_ok=True)

    # Save blob to file for fuzzer
    blob_path = work_dir / "input.bin"
    blob_path.write_bytes(blob)

    logger.info(
        f"[POV] trace_pov: blob={len(blob)} bytes, fuzzer={fuzzer_name}, work_dir={work_dir}"
    )

    # =========================================================================
    # Step 2: Run ASAN fuzzer to detect crash (_run_fuzzer_docker)
    # =========================================================================
    if fuzzer_path and docker_image:
        fuzzer_path = Path(fuzzer_path)
        if fuzzer_path.exists():
            logger.info("[POV] Step 2: Running ASAN fuzzer to detect crash...")
            success, crashed, output, error = _run_fuzzer_docker(
                fuzzer_path=fuzzer_path,
                blob_path=blob_path,
                docker_image=docker_image,
                sanitizer=sanitizer,
            )

            if success and crashed:
                # =========================================================
                # CRASH DETECTED! Return immediately with processor="asan"
                # =========================================================
                vuln_type = _parse_vuln_type(output)
                hit_funcs = _extract_hit_functions(output, target_functions or [])
                logger.info(
                    f"[POV] ASAN detected CRASH! vuln_type={vuln_type}, hit_funcs={hit_funcs}"
                )
                return {
                    "success": True,
                    "crashed": True,
                    "processor": "asan",
                    "vuln_type": vuln_type,
                    "any_target_reached": len(hit_funcs) > 0,
                    "target_status": {
                        func: (func in hit_funcs) for func in (target_functions or [])
                    },
                    "executed_functions": hit_funcs,
                    "total_executed": len(hit_funcs),
                    "message": "CRASH DETECTED! This POV successfully triggered the vulnerability. "
                    "Please call create_pov directly to save and verify it.",
                    "sanitizer_output": output[:3000],
                }

            logger.info(
                "[POV] ASAN fuzzer: no crash detected, continuing to GDB trace..."
            )
        else:
            logger.warning(
                f"[POV] ASAN fuzzer not found: {fuzzer_path}, skipping crash detection"
            )
    else:
        logger.warning(
            "[POV] fuzzer_path or docker_image not set, skipping ASAN crash detection"
        )

    # =========================================================================
    # Step 3: No crash - Run GDB trace for function tracking (processor="gdb")
    # =========================================================================
    executed_functions = []
    target_status = {}
    any_target_reached = False
    gdb_failed = False

    logger.info("[POV] Step 3: Running GDB trace for function tracking...")
    gdb_success, hit_functions, gdb_crashed, gdb_output = run_gdb_trace(
        fuzzer_name, blob, work_dir, target_functions
    )

    if gdb_success:
        if gdb_crashed:
            # GDB detected crash (shouldn't happen if ASAN didn't, but handle it)
            vuln_type = _parse_vuln_type(gdb_output)
            logger.info(
                f"[POV] GDB detected CRASH! vuln_type={vuln_type}, hit_funcs={hit_functions}"
            )
            return {
                "success": True,
                "crashed": True,
                "processor": "gdb",
                "vuln_type": vuln_type,
                "any_target_reached": len(hit_functions) > 0,
                "target_status": {
                    func: (func in hit_functions) for func in (target_functions or [])
                },
                "executed_functions": hit_functions,
                "total_executed": len(hit_functions),
                "message": "CRASH DETECTED! This POV successfully triggered the vulnerability. "
                "Please call create_pov directly to save and verify it.",
                "sanitizer_output": gdb_output[:3000],
            }

        # GDB succeeded without crash - use breakpoint results
        if target_functions:
            for func in target_functions:
                hit = func in hit_functions
                target_status[func] = hit
                if hit:
                    any_target_reached = True

        executed_functions = hit_functions
        logger.info(
            f"[POV] GDB trace complete: {len(hit_functions)} functions hit, target_reached={any_target_reached}"
        )
    else:
        logger.warning(
            f"[POV] GDB trace failed: {gdb_output[:200]}, falling back to coverage..."
        )
        gdb_failed = True

    # =========================================================================
    # Step 4: GDB failed - Fallback to coverage fuzzer (processor="cov")
    # =========================================================================
    if gdb_failed:
        if coverage_fuzzer_dir is None:
            return {
                "success": False,
                "crashed": False,
                "processor": "none",
                "any_target_reached": False,
                "target_status": {func: False for func in (target_functions or [])},
                "executed_functions": [],
                "total_executed": 0,
                "error": "GDB failed and coverage context not set",
            }

        logger.info("[POV] Step 4: Running coverage fuzzer as fallback...")
        success, lcov_path, msg = run_coverage_fuzzer(fuzzer_name, blob, work_dir)

        if not success:
            # Check if coverage fuzzer crashed
            crashed = any(indicator in msg for indicator in CRASH_INDICATORS)
            if crashed:
                vuln_type = _parse_vuln_type(msg)
                hit_funcs = _extract_hit_functions(msg, target_functions or [])
                logger.info(
                    f"[POV] Coverage detected CRASH! vuln_type={vuln_type}, hit_funcs={hit_funcs}"
                )
                return {
                    "success": True,
                    "crashed": True,
                    "processor": "cov",
                    "vuln_type": vuln_type,
                    "any_target_reached": len(hit_funcs) > 0,
                    "target_status": {
                        func: (func in hit_funcs) for func in (target_functions or [])
                    },
                    "executed_functions": hit_funcs,
                    "total_executed": len(hit_funcs),
                    "message": "CRASH DETECTED! This POV successfully triggered the vulnerability. "
                    "Please call create_pov directly to save and verify it.",
                    "sanitizer_output": msg[:3000],
                }

            # True failure
            return {
                "success": False,
                "crashed": False,
                "processor": "cov",
                "any_target_reached": False,
                "target_status": {func: False for func in (target_functions or [])},
                "executed_functions": [],
                "total_executed": 0,
                "error": msg,
            }

        # Parse LCOV to get executed functions
        _, _, executed_functions = parse_lcov(lcov_path)

        # Check target functions
        target_status = {}
        any_target_reached = False
        if target_functions:
            for func in target_functions:
                hit = func in executed_functions
                target_status[func] = hit
                if hit:
                    any_target_reached = True

        logger.info(
            f"[POV] Coverage trace: {len(executed_functions)} functions, target_reached={any_target_reached}"
        )

    # =========================================================================
    # Return result with LLM analysis
    # =========================================================================
    analysis = _analyze_trace(
        blob=blob,
        executed_functions=executed_functions,
        target_functions=target_functions,
        any_target_reached=any_target_reached,
        agent_msg=agent_msg,
        ctx=ctx,
    )

    return {
        "success": True,
        "crashed": False,
        "processor": "cov" if gdb_failed else "gdb",
        "any_target_reached": any_target_reached,
        "target_status": target_status,
        "executed_functions": executed_functions[:30],
        "total_executed": len(executed_functions),
        "analysis": analysis,
    }


# =============================================================================
# Fuzzer Info Tool
# =============================================================================


@tools_mcp.tool
def get_fuzzer_info() -> Dict[str, Any]:
    """
    Get the fuzzer harness source code and current sanitizer type.

    Use this tool to refresh your memory about:
    - How the fuzzer processes input data
    - What sanitizer is being used (address, memory, undefined)
    - The fuzzer name and current attempt count

    Returns:
        {
            "success": True,
            "fuzzer": "fuzzer_name",
            "sanitizer": "address|memory|undefined",
            "fuzzer_source": "... source code ...",
            "current_attempt": N,
            "current_iteration": M,
        }
    """
    err = _ensure_context()
    if err:
        return err

    ctx = _get_current_context()

    fuzzer_source = ctx.get("fuzzer_source")
    if not fuzzer_source:
        fuzzer_source = "(Fuzzer source code not available)"

    return {
        "success": True,
        "fuzzer": ctx.get("fuzzer", ""),
        "sanitizer": ctx.get("sanitizer", "address"),
        "fuzzer_source": fuzzer_source,
        "current_attempt": ctx.get("attempt", 0),
        "current_iteration": ctx.get("iteration", 0),
    }


# =============================================================================
# POV Generator Code Execution
# =============================================================================


def _execute_generator_code(code: str, num_variants: int = 3,
                            *, context: Dict[str, Any] | None = None) -> tuple:
    """Generate PoV bytes in the pinned model-code sandbox, never on host."""
    from ..fuzzer.seed_sandbox import (
        SeedSandboxCleanupError, SeedSandboxError, execute_seed_generator,
    )

    try:
        if context is not None and context.get("qualified_runtime_required"):
            binding = context.get("qualified_runtime_binding")
            if (type(binding) is not QualifiedRuntimeBinding or
                    not callable(binding.generate)):
                raise RuntimeError(
                    "qualified PoV generator process accounting unavailable")
            request = QualifiedGeneratorRequest(
                task_id=context["task_id"],
                suspicious_point_id=context["suspicious_point_id"],
                worker_id=context["worker_id"],
                attempt=context["attempt"], code=code,
                num_variants=num_variants)
            return binding.generate(request), None
        return execute_seed_generator(code, num_variants), None
    except SeedSandboxCleanupError:
        raise
    except SeedSandboxError as exc:
        return [], str(exc)


def _pending_qualified_runtime() -> Dict[str, Any]:
    """A development PoV may be retained, but cannot use legacy execution."""
    return {
        "success": False,
        "crashed": False,
        "status": "PENDING_QUALIFIED_RUNTIME",
        "pending_runtime": True,
        "error": "qualified product Runtime is not connected",
    }


def _verify_qualified_pov_core(pov_id: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Execute saved PoV bytes once through a product-qualified callback.

    A crash is runtime feedback only. The original ``is_successful`` flag and
    product security Gate remain untouched until independent validation.
    """
    binding = ctx.get("qualified_runtime_binding")
    if binding is None:
        return _pending_qualified_runtime()
    if type(binding) is not QualifiedRuntimeBinding or not ObjectId.is_valid(pov_id):
        return {"success": False, "incomplete": True,
                "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME",
                "error": "qualified Runtime binding or PoV ID is invalid"}
    repos = ctx["repos"]
    collection = repos.povs.collection
    raw = collection.find_one({"_id": ObjectId(pov_id)})
    if (not isinstance(raw, dict) or
            raw.get("task_id") != ObjectId(ctx["task_id"]) or
            raw.get("suspicious_point_id") != ObjectId(ctx["suspicious_point_id"]) or
            raw.get("harness_name") != ctx.get("fuzzer") or
            raw.get("sanitizer") != ctx.get("sanitizer") or
            raw.get("is_successful") is not False or
            raw.get("is_active") is not True or
            not isinstance(raw.get("blob"), str)):
        return {"success": False, "incomplete": True,
                "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME",
                "error": "saved PoV identity changed"}
    try:
        data = base64.b64decode(raw["blob"], validate=True)
        if not data or len(data) > 2_097_152:
            raise ValueError("saved PoV input size is invalid")
        path_value = raw.get("blob_path")
        if path_value is not None:
            path = Path(path_value)
            if (not path.is_absolute() or path.is_symlink() or
                    any(parent.is_symlink() for parent in path.parents) or
                    not path.is_file() or path.stat().st_size != len(data) or
                    path.read_bytes() != data):
                raise ValueError("saved PoV file differs from DB bytes")
        binary_path, binary_sha = binding.pinned_binary()
        if (ctx.get("fuzzer_path") is None or
                Path(ctx["fuzzer_path"]).resolve() != binary_path):
            raise ValueError("PoV fuzzer path differs from product qualification")
    except (ValueError, OSError, binascii.Error) as exc:
        return {"success": False, "incomplete": True,
                "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME",
                "error": str(exc)}
    input_sha = hashlib.sha256(data).hexdigest()
    request = QualifiedRuntimeRequest(
        task_id=ctx["task_id"], suspicious_point_id=ctx["suspicious_point_id"],
        pov_id=pov_id, harness_name=ctx["fuzzer"], sanitizer=ctx["sanitizer"],
        input_bytes=data, input_sha256=input_sha,
        binary_path=binary_path, binary_sha256=binary_sha,
    )
    existing = raw.get("qualified_runtime")
    if isinstance(existing, dict):
        if existing.get("status") == "STARTED" or existing.get("status") == "INCOMPLETE":
            return {"success": False, "incomplete": True,
                    "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME",
                    "error": "qualified Runtime attempt already started or incomplete"}
        if existing.get("status") in {"NO_CRASH", "CRASH_OBSERVED"}:
            try:
                from .qualified_runtime import QualifiedRuntimeOutcome
                outcome = QualifiedRuntimeOutcome(
                    status=existing["status"], pov_id=pov_id,
                    input_sha256=existing["input_sha256"],
                    binary_sha256=existing["binary_sha256"],
                    runtime_receipt_path=Path(existing["runtime_receipt_path"]),
                    runtime_receipt_sha256=existing["runtime_receipt_sha256"],
                    physical_receipt_path=Path(existing["physical_receipt_path"]),
                    physical_receipt_sha256=existing["physical_receipt_sha256"],
                    output_summary=existing.get("output_summary", ""),
                    sanitizer=existing.get("sanitizer"),
                )
                validate_outcome(outcome, request)
            except (KeyError, TypeError, ValueError, OSError) as exc:
                return {"success": False, "incomplete": True,
                        "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME",
                        "error": f"cached qualified Runtime receipt changed: {exc}"}
            return _qualified_feedback(outcome)
        return {"success": False, "incomplete": True,
                "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME",
                "error": "unknown qualified Runtime state"}
    claim = collection.update_one(
        {"_id": ObjectId(pov_id), "qualified_runtime": {"$exists": False},
         "blob": raw["blob"], "blob_path": raw.get("blob_path"),
         "is_successful": False},
        {"$set": {"qualified_runtime": {
            "status": "STARTED", "input_sha256": input_sha,
            "binary_sha256": binary_sha,
        }}},
    )
    if claim.modified_count != 1:
        return {"success": False, "incomplete": True,
                "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME",
                "error": "qualified Runtime attempt could not be claimed"}
    try:
        outcome = binding.execute(request)
        validate_outcome(outcome, request)
        after_path, after_sha = binding.pinned_binary()
        if after_path != binary_path or after_sha != binary_sha:
            raise ValueError("qualified binary changed during PoV execution")
        evidence = {
            "status": outcome.status,
            "input_sha256": outcome.input_sha256,
            "binary_sha256": outcome.binary_sha256,
            "runtime_receipt_path": str(outcome.runtime_receipt_path),
            "runtime_receipt_sha256": outcome.runtime_receipt_sha256,
            "physical_receipt_path": str(outcome.physical_receipt_path),
            "physical_receipt_sha256": outcome.physical_receipt_sha256,
            "output_summary": outcome.output_summary,
            "sanitizer": outcome.sanitizer,
        }
        saved = collection.update_one(
            {"_id": ObjectId(pov_id), "qualified_runtime.status": "STARTED",
             "qualified_runtime.input_sha256": input_sha},
            {"$set": {"qualified_runtime": evidence}},
        )
        if saved.modified_count != 1:
            raise RuntimeError("qualified Runtime evidence could not be persisted")
        return _qualified_feedback(outcome)
    except BaseException as original:
        try:
            collection.update_one(
                {"_id": ObjectId(pov_id), "qualified_runtime.status": "STARTED"},
                {"$set": {"qualified_runtime.status": "INCOMPLETE",
                          "qualified_runtime.error": type(original).__name__}},
            )
        except BaseException as cleanup:
            original.add_note(
                f"qualified PoV status cleanup failed: {type(cleanup).__name__}")
        if not isinstance(original, Exception):
            raise
        return {"success": False, "incomplete": True,
                "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME",
                "error": f"qualified Runtime did not complete: {type(original).__name__}"}


def _qualified_feedback(outcome) -> Dict[str, Any]:
    observed = outcome.status == "CRASH_OBSERVED"
    return {
        "success": outcome.status != "INCOMPLETE",
        "incomplete": outcome.status == "INCOMPLETE",
        "crashed": False,  # Product Gate has not independently VERIFIED this input.
        "runtime_crashed": observed,
        "validation_pending": observed,
        "runtime_status": ("PENDING_INDEPENDENT_VALIDATION" if observed else
                           outcome.status),
        "pov_id": outcome.pov_id,
        "input_sha256": outcome.input_sha256,
        "binary_sha256": outcome.binary_sha256,
        "runtime_receipt_path": str(outcome.runtime_receipt_path),
        "runtime_receipt_sha256": outcome.runtime_receipt_sha256,
        "physical_receipt_path": str(outcome.physical_receipt_path),
        "physical_receipt_sha256": outcome.physical_receipt_sha256,
        "output_summary": outcome.output_summary,
        "sanitizer": outcome.sanitizer,
    }


# =============================================================================
# POV Tools - Core Implementation (shared by MCP-decorated and _impl versions)
# =============================================================================


def _create_pov_core(
    suspicious_point_id: str,
    generator_code: str,
    description: str,
    worker_id: str = None,
) -> Dict[str, Any]:
    """
    Core implementation of create_pov.

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    task_id = ctx["task_id"]
    ctx_worker_id = ctx["worker_id"]
    output_dir = ctx["output_dir"]

    repos = ctx["repos"]
    fuzzer = ctx.get("fuzzer", "")
    sanitizer = ctx.get("sanitizer", "address")
    docker_image = ctx.get("docker_image")
    current_iteration = ctx.get("iteration", 0)

    # Increment attempt counter (thread-safe)
    with _pov_contexts_lock:
        if ctx_worker_id in _pov_contexts:
            _pov_contexts[ctx_worker_id]["attempt"] += 1
            current_attempt = _pov_contexts[ctx_worker_id]["attempt"]
        else:
            current_attempt = 1

    # Use context SP if not provided
    if not suspicious_point_id and ctx.get("suspicious_point_id"):
        suspicious_point_id = ctx["suspicious_point_id"]

    # Validate inputs
    if not suspicious_point_id:
        return {"success": False, "error": "suspicious_point_id is required"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}
    if not description or not description.strip():
        return {"success": False, "error": "description is required"}

    # Generate unique generation_id for this batch
    generation_id = generate_id()

    # Execute generator code
    logger.info(f"[POV] Executing generator code for SP {suspicious_point_id[:8]}...")
    logger.info(f"[POV] Attempt #{current_attempt}, Iteration #{current_iteration}")

    num_variants = 3
    from ..fuzzer.seed_sandbox import SeedSandboxCleanupError

    try:
        blobs, error = _execute_generator_code(
            generator_code, num_variants,
            context=({**ctx, "suspicious_point_id": suspicious_point_id,
                      "attempt": current_attempt}
                     if ctx.get("qualified_runtime_required") else None))
    except SeedSandboxCleanupError as exc:
        return {"success": False, "error": str(exc),
                "fatal_sandbox_cleanup": True}
    except (RuntimeError, ValueError) as exc:
        if not ctx.get("qualified_runtime_required"):
            raise
        return {"success": False, "error": str(exc),
                "runtime_status": "INCOMPLETE_QUALIFIED_RUNTIME"}

    if error:
        logger.error(f"[POV] Generator code failed: {error}")
        return {"success": False, "error": error}

    if not blobs:
        return {"success": False, "error": "Generator code produced no blobs"}

    # Create output directory: povs/{task_id}/{ctx_worker_id}/attempt_{n}/
    attempt_dir = None
    if output_dir:
        attempt_dir = (
            output_dir / task_id / ctx_worker_id / f"attempt_{current_attempt:03d}"
        )
        attempt_dir.mkdir(parents=True, exist_ok=True)

    # Create POV records for each blob
    pov_ids = []
    blob_paths = []

    # Get FuzzerManager for SP Fuzzer integration
    fuzzer_manager = ctx.get("fuzzer_manager")

    for variant_idx, blob in enumerate(blobs, start=1):
        pov_id = generate_id()

        # Save blob to file
        blob_path = None
        if attempt_dir:
            blob_filename = f"v{variant_idx}.bin"
            blob_path = attempt_dir / blob_filename
            blob_path.write_bytes(blob)
            blob_paths.append(str(blob_path))
            logger.debug(f"[POV] Saved blob to {blob_path}")
        else:
            blob_paths.append(None)

        # Add blob to SP Fuzzer corpus for mutation
        if (fuzzer_manager and suspicious_point_id and
                not ctx.get("qualified_runtime_required")):
            try:
                fuzzer_manager.add_pov_blob(
                    blob=blob,
                    sp_id=suspicious_point_id,
                    attempt=current_attempt,
                    variant=variant_idx,
                )
                logger.debug(
                    f"[POV] Added blob to SP Fuzzer corpus: sp={suspicious_point_id[:8]}, v={variant_idx}"
                )
            except Exception as e:
                logger.warning(f"[POV] Failed to add blob to SP Fuzzer: {e}")

        # Create POV record
        pov = POV(
            pov_id=pov_id,
            task_id=task_id,
            suspicious_point_id=suspicious_point_id,
            generation_id=generation_id,
            agent_id=ctx.get("agent_id"),  # Track which POVAgent created this
            iteration=current_iteration,
            attempt=current_attempt,
            variant=variant_idx,
            blob=base64.b64encode(blob).decode("utf-8"),
            blob_path=str(blob_path) if blob_path else None,
            gen_blob=generator_code,
            harness_name=fuzzer,
            sanitizer=sanitizer,
            description=description,
            is_successful=False,
            is_active=True,
        )

        # Save to database
        if repos.povs.save(pov):
            pov_ids.append(pov_id)
            logger.info(
                f"[POV] Created POV {pov_id[:8]} (attempt={current_attempt}, variant={variant_idx})"
            )
        else:
            logger.error(f"[POV] Failed to save POV {pov_id[:8]} to database")

    if not pov_ids:
        return {"success": False, "error": "Failed to save any POV records to database"}

    logger.info(
        f"[POV] Successfully created {len(pov_ids)} POVs for SP {suspicious_point_id[:8]}"
    )

    # Get all available fuzzers for cross-fuzzer verification
    all_fuzzers = repos.fuzzers.find_by_task(task_id)
    current_fuzzer_name = ctx.get("fuzzer", "")
    other_fuzzers = [
        f for f in all_fuzzers if f.fuzzer_name != current_fuzzer_name and f.binary_path
    ] if not ctx.get("qualified_runtime_required") else []

    logger.info(
        f"[POV] Auto-verifying {len(pov_ids)} POVs on {1 + len(other_fuzzers)} fuzzers..."
    )

    # Auto-verify all generated POVs
    verify_results = []
    successful_povs = []
    cross_fuzzer_hits = 0
    qualified = bool(ctx.get("qualified_runtime_required"))

    for variant_index, pov_id in enumerate(pov_ids):
        # First verify on current fuzzer
        result = _verify_pov_core(pov_id=pov_id, worker_id=ctx_worker_id)
        verify_results.append(result)
        if result.get("crashed") and not qualified:
            successful_povs.append(pov_id)
            logger.info(
                f"[POV] ✓ POV {pov_id[:8]} triggered crash on {current_fuzzer_name}!"
            )
        else:
            logger.info(f"[POV] ✗ POV {pov_id[:8]} no crash on {current_fuzzer_name}")

        if qualified and (result.get("incomplete") or
                          result.get("validation_pending")):
            # A physical attempt with uncertain status must not be followed
            # by another Target call. An observed crash belongs in the
            # independent Gate before spending more executions. The other
            # generated variants remain saved, unclaimed, and unexecuted.
            verify_results.extend(
                {"pending_runtime": True} for _ in pov_ids[variant_index + 1:]
            )
            break

        # Then try on all other fuzzers
        pov = repos.povs.find_by_id(pov_id)
        if pov and pov.blob:
            blob_bytes = base64.b64decode(pov.blob)
            for other_fuzzer in other_fuzzers:
                try:
                    other_result = _verify_blob_on_fuzzer(
                        blob=blob_bytes,
                        fuzzer_path=Path(other_fuzzer.binary_path),
                        docker_image=docker_image,
                        sanitizer=sanitizer,
                    )
                    if other_result.get("crashed"):
                        cross_fuzzer_hits += 1
                        logger.info(
                            f"[POV] ✓ POV {pov_id[:8]} also crashed on {other_fuzzer.fuzzer_name}!"
                        )
                        # Create new POV record for this fuzzer
                        cross_pov_id = generate_id()
                        cross_pov = POV(
                            pov_id=cross_pov_id,
                            task_id=task_id,
                            suspicious_point_id=suspicious_point_id,
                            generation_id=generation_id,
                            agent_id=ctx.get("agent_id"),  # Inherit from original POV
                            iteration=current_iteration,
                            attempt=current_attempt,
                            variant=pov.variant,
                            blob=pov.blob,
                            blob_path=pov.blob_path,
                            gen_blob=generator_code,
                            harness_name=other_fuzzer.fuzzer_name,
                            sanitizer=sanitizer,
                            description=f"Cross-fuzzer hit from {current_fuzzer_name}",
                            is_successful=True,
                            is_active=True,
                            verified_at=datetime.now(),
                            sanitizer_output=other_result.get("output", "")[:5000],
                        )
                        repos.povs.save(cross_pov)
                        successful_povs.append(cross_pov_id)
                except Exception as e:
                    logger.debug(
                        f"[POV] Cross-fuzzer check failed on {other_fuzzer.fuzzer_name}: {e}"
                    )

    # Return results with verification info
    # Extract key info from verify_results for Agent feedback
    verify_details = []
    for i, result in enumerate(verify_results):
        detail = {
            "variant": i + 1,
            "crashed": result.get("crashed", False),
        }
        if qualified:
            detail["runtime_status"] = result.get("runtime_status", "UNKNOWN")
            detail["runtime_crashed"] = result.get("runtime_crashed", False)
            detail["pov_id"] = pov_ids[i]
        if result.get("pending_runtime"):
            detail["runtime_status"] = "PENDING_QUALIFIED_RUNTIME"
        if result.get("crashed"):
            detail["vuln_type"] = result.get("vuln_type")
        else:
            # Include LLM-generated summary for non-crash cases
            detail["output_summary"] = result.get("output_summary", "No details")
        verify_details.append(detail)

    qualified_status = None
    if qualified:
        if any(item.get("incomplete") for item in verify_results):
            qualified_status = "INCOMPLETE_QUALIFIED_RUNTIME"
        elif any(item.get("validation_pending") for item in verify_results):
            qualified_status = "PENDING_INDEPENDENT_VALIDATION"
        elif any(item.get("pending_runtime") for item in verify_results):
            qualified_status = "PENDING_QUALIFIED_RUNTIME"
        else:
            qualified_status = "NO_CRASH"

    return {
        "success": True,
        "pov_ids": pov_ids,
        "attempt": current_attempt,
        "count": len(pov_ids),
        "verified": (0 if qualified else
                     sum(result.get("success") is True for result in verify_results)),
        "crashed": len(successful_povs),
        "runtime_crashes": sum(bool(item.get("runtime_crashed"))
                               for item in verify_results) if qualified else 0,
        "validation_pending_pov_ids": ([pov_ids[i] for i, item in enumerate(verify_results)
                                        if item.get("validation_pending")]
                                       if qualified else []),
        "cross_fuzzer_hits": cross_fuzzer_hits,
        "successful_pov_ids": successful_povs,
        "verify_details": verify_details,
        "runtime_status": qualified_status,
    }


@tools_mcp.tool
def create_pov(
    generator_code: str,
    description: str = "POV generated by AI agent",
) -> Dict[str, Any]:
    """
    Generate 3 different test input blobs that may trigger the vulnerability.

    Write Python code with a generate(variant: int) function that returns bytes.
    The function receives variant number (1, 2, or 3) and MUST return DIFFERENT
    blobs for each variant to maximize chances of triggering the bug.
    Each returned blob must be at most 65,536 bytes.

    Args:
        generator_code: Python code with generate(variant) function.
            Example 1 - Different approaches per variant:
            ```python
            def generate(variant: int) -> bytes:
                import struct
                if variant == 1:
                    # Minimal trigger attempt
                    return struct.pack('<I', 0) + b'test'
                elif variant == 2:
                    # With overflow value
                    return struct.pack('<I', 0xFFFFFFFF) + b'test'
                else:
                    # Alternative structure
                    return b'\\x00' * 256
            ```

            Example 2 - Parameterized variants:
            ```python
            def generate(variant: int) -> bytes:
                sizes = [16, 256, 4096]
                return b'A' * sizes[variant - 1]
            ```
        description: Brief description of what this POV attempts to trigger

    Returns:
        {
            "success": True,
            "pov_ids": ["id1", "id2", "id3"],  # 3 POV IDs for verification
            "attempt": N,
            "count": 3,
            "crashed": 0,  # Number that triggered crash
            "successful_pov_ids": [],  # IDs of successful POVs
        }
    """
    err = _ensure_context()
    if err:
        return err

    ctx = _get_current_context()
    suspicious_point_id = ctx.get("suspicious_point_id", "")

    if not suspicious_point_id:
        return {"success": False, "error": "suspicious_point_id not set in context"}
    if not generator_code or not generator_code.strip():
        return {"success": False, "error": "generator_code is required"}

    return _create_pov_core(
        suspicious_point_id=suspicious_point_id,
        generator_code=generator_code,
        description=description or "POV generated by AI agent",
    )


# =============================================================================
# POV Verification
# =============================================================================

# Crash indicators from sanitizers
CRASH_INDICATORS = [
    "ERROR: AddressSanitizer:",
    "ERROR: MemorySanitizer:",
    "WARNING: MemorySanitizer:",
    "ERROR: ThreadSanitizer:",
    "WARNING: ThreadSanitizer:",
    "ERROR: UndefinedBehaviorSanitizer:",
    "ERROR: HWAddressSanitizer:",
    "SEGV on unknown address",
    "Segmentation fault",
    "runtime error:",
    "AddressSanitizer: heap-buffer-overflow",
    "AddressSanitizer: heap-use-after-free",
    "AddressSanitizer: stack-buffer-overflow",
    "AddressSanitizer: stack-use-after-return",
    "AddressSanitizer: global-buffer-overflow",
    "AddressSanitizer: use-after-poison",
    "UndefinedBehaviorSanitizer: undefined-behavior",
    "AddressSanitizer:DEADLYSIGNAL",
    "assertion failed",
    "libfuzzer exit=1",
]

# Patterns to extract vulnerability type
VULN_TYPE_PATTERNS = [
    (r"AddressSanitizer: ([\w-]+)", 1),  # heap-buffer-overflow, etc.
    (r"MemorySanitizer: ([\w-]+)", 1),
    (r"UndefinedBehaviorSanitizer: ([\w-]+)", 1),
    (r"ThreadSanitizer: ([\w-]+)", 1),
    (r"HWAddressSanitizer: ([\w-]+)", 1),
    (r"runtime error: ([\w\s-]+)", 1),
]


def _parse_vuln_type(output: str) -> Optional[str]:
    """Extract vulnerability type from sanitizer output."""
    import re

    for pattern, group in VULN_TYPE_PATTERNS:
        match = re.search(pattern, output)
        if match:
            return match.group(group).strip()

    # Fallback checks
    if "SEGV" in output or "Segmentation fault" in output:
        return "segmentation-fault"
    if "assertion failed" in output.lower():
        return "assertion-failure"

    return None


def _check_crash(output: str) -> bool:
    """Check if output contains crash indicators."""
    output_lower = output.lower()
    for indicator in CRASH_INDICATORS:
        if indicator.lower() in output_lower:
            return True
    return False


def _extract_hit_functions(output: str, target_functions: List[str]) -> List[str]:
    """
    Extract which target functions appear in crash backtrace.

    Parses backtrace lines like:
        #0 0x... in function_name /path/file.c:line:col
        #1 0x... in another_func ...

    Args:
        output: Sanitizer crash output
        target_functions: List of function names to look for

    Returns:
        List of target functions that appear in the backtrace
    """
    if not target_functions:
        return []

    hit_functions = []
    for line in output.split("\n"):
        # Look for backtrace lines: "#N 0x... in func_name"
        if " in " in line and ("#" in line or "at " in line):
            for func in target_functions:
                if func in line and func not in hit_functions:
                    hit_functions.append(func)
    return hit_functions


def _verify_blob_on_fuzzer(
    blob: bytes,
    fuzzer_path: Path,
    docker_image: str,
    sanitizer: str = "address",
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Verify a blob on a specific fuzzer.

    Args:
        blob: Raw blob bytes
        fuzzer_path: Path to fuzzer binary
        docker_image: Docker image to use
        sanitizer: Sanitizer type
        timeout: Execution timeout

    Returns:
        Dict with crashed, output, error
    """
    import tempfile

    # Write blob to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(blob)
        temp_blob_path = Path(f.name)

    try:
        success, crashed, output, error = _run_fuzzer_docker(
            fuzzer_path=fuzzer_path,
            blob_path=temp_blob_path,
            docker_image=docker_image,
            sanitizer=sanitizer,
            timeout=timeout,
        )
        return {
            "success": success,
            "crashed": crashed,
            "output": output,
            "error": error,
        }
    finally:
        if temp_blob_path.exists():
            temp_blob_path.unlink()


FALLBACK_DOCKER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"


def _run_fuzzer_docker(
    fuzzer_path: Path,
    blob_path: Path,
    docker_image: str,
    sanitizer: str = "address",
    timeout: int = 30,
) -> tuple:
    """
    Run fuzzer in Docker container with blob input.

    Includes fallback mechanism: if the primary docker_image fails due to
    missing shared libraries, automatically retry with base-runner.

    Returns:
        Tuple of (success, crashed, output, error)
    """
    import subprocess

    fuzzer_dir = fuzzer_path.parent
    fuzzer_name = fuzzer_path.name

    # Mount blob's parent directory directly — blob is already in worker workspace
    work_dir = blob_path.parent

    def run_with_image(image: str):
        """Run fuzzer with specified docker image."""
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--entrypoint",
            "",  # Bypass base-runner's entrypoint script
            "-e",
            "FUZZING_ENGINE=libfuzzer",
            "-e",
            f"SANITIZER={sanitizer}",
            "-e",
            "ARCHITECTURE=x86_64",
            "-e",
            "FUZZ_VERBOSE=1",  # Enable verbose output for debugging
            "-v",
            f"{fuzzer_dir}:/fuzzers:ro",
            "-v",
            f"{work_dir}:/work",
            image,
            f"/fuzzers/{fuzzer_name}",
            f"-timeout={timeout}",
            f"/work/{blob_path.name}",
        ]

        logger.info(f"[POV] Running Docker: {' '.join(docker_cmd)}")

        # TEST_ONLY: 写日志到文件
        with open("/tmp/pov_debug.log", "a") as f:
            f.write("\n=== _run_fuzzer_docker ===\n")
            f.write(f"fuzzer_path: {fuzzer_path}\n")
            f.write(f"blob_path: {blob_path}\n")
            f.write(f"docker_image: {docker_image}\n")
            f.write(f"docker_cmd: {' '.join(docker_cmd)}\n")

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",  # Handle binary output gracefully
            timeout=timeout + 30,  # Extra time for Docker overhead
        )

        combined_output = result.stderr + "\n" + result.stdout

        # TEST_ONLY: 写结果到文件
        with open("/tmp/pov_debug.log", "a") as f:
            f.write(f"returncode: {result.returncode}\n")
            f.write(f"output:\n{combined_output}\n")
            f.write("=== END ===\n")

        return result, combined_output

    try:
        # FuzzTest fuzzers MUST use base-runner image (only it has 'reproduce' command)
        if "@" in fuzzer_name:
            logger.debug(
                f"[POV] FuzzTest fuzzer detected, using {FALLBACK_DOCKER_IMAGE}"
            )
            result, combined_output = run_with_image(FALLBACK_DOCKER_IMAGE)
        else:
            # Try with primary image first
            result, combined_output = run_with_image(docker_image)

            # Check for library loading errors - need to fallback
            # This includes: "error while loading shared libraries" and "GLIBC" version errors
            if (
                "error while loading shared libraries" in combined_output
                or "GLIBC" in combined_output
            ):
                if docker_image != FALLBACK_DOCKER_IMAGE:
                    logger.warning(
                        f"[POV] Library error with {docker_image}, falling back to {FALLBACK_DOCKER_IMAGE}"
                    )
                    result, combined_output = run_with_image(FALLBACK_DOCKER_IMAGE)

        # Check for crash
        crashed = _check_crash(combined_output)

        # Also check return code
        if result.returncode != 0 and not crashed:
            # Non-zero exit but no crash indicator - might still be a crash
            if "ABORTING" in combined_output:
                crashed = True

        # Log execution result
        logger.info(
            f"[POV] _run_fuzzer_docker: image={docker_image}, returncode={result.returncode}, crashed={crashed}"
        )
        print(
            f"[POV-DEBUG] _run_fuzzer_docker: image={docker_image}, returncode={result.returncode}, crashed={crashed}",
            flush=True,
        )
        if crashed:
            # Log first 500 chars of crash output
            logger.info(
                f"[POV] _run_fuzzer_docker crash output: {combined_output[:500]}"
            )
            print(f"[POV-DEBUG] crash output: {combined_output[:300]}", flush=True)
        else:
            logger.debug(
                f"[POV] _run_fuzzer_docker output (no crash): {combined_output[:300]}"
            )

        return True, crashed, combined_output, None

    except subprocess.TimeoutExpired:
        logger.warning(f"[POV] _run_fuzzer_docker: TIMEOUT after {timeout}s")
        return False, False, "", "Execution timed out"
    except Exception as e:
        logger.error(f"[POV] _run_fuzzer_docker: EXCEPTION {e}")
        return False, False, "", str(e)
    finally:
        pass  # No temp files to clean — blob is in worker workspace


def _extract_output_summary(output: str) -> str:
    """
    Use a fast LLM to extract meaningful information from fuzzer output.

    This helps POV Agent understand why a POV didn't crash, e.g.:
    - Protocol state transitions (state [0] -> disconnect)
    - Protocol rejections
    - Connection errors

    Args:
        output: Full fuzzer output (may be very long)

    Returns:
        Brief summary (2-5 lines) of key information
    """
    if not output or len(output) < 100:
        return output or "No output"

    try:
        from ..llms import quick_call, CLAUDE_HAIKU_4_5

        # Truncate to avoid token explosion
        truncated = output[:8000] if len(output) > 8000 else output

        prompt = f"""Extract key debugging info (2-5 lines) from this fuzzer output:

Focus on:
- Protocol state transitions (e.g. "state [0]", "state [1]")
- Disconnection reasons (e.g. "Connection disconnected", "Protocol disabled")
- Error messages

Fuzzer output:
```
{truncated}
```

Key info (brief, 2-5 lines):"""

        summary = quick_call(prompt, model=CLAUDE_HAIKU_4_5)
        return summary[:500] if summary else "Failed to extract summary"
    except Exception as e:
        logger.warning(f"[POV] Failed to extract output summary: {e}")
        # Fallback: return first 500 chars
        return output[:500] if output else "No output"


def _verify_pov_core(pov_id: str, worker_id: str = None) -> Dict[str, Any]:
    """
    Core implementation of verify_pov.

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    if ctx and ctx.get("qualified_runtime_required"):
        return _verify_qualified_pov_core(pov_id, ctx)

    # TEST_ONLY
    with open("/tmp/pov_debug.log", "a") as f:
        f.write("\n=== _verify_pov_core called ===\n")
        f.write(f"pov_id: {pov_id}\n")
        f.write(f"worker_id: {worker_id}\n")

    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    repos = ctx["repos"]
    sanitizer = ctx.get("sanitizer", "address")

    # Get POV from database
    pov = repos.povs.find_by_id(pov_id)
    if not pov:
        with open("/tmp/pov_debug.log", "a") as f:
            f.write("ERROR: POV not found\n")
        return {"success": False, "error": f"POV {pov_id} not found"}

    # Get blob path
    blob_path = pov.blob_path
    # TEST_ONLY
    with open("/tmp/pov_debug.log", "a") as f:
        f.write(f"blob_path from pov: {blob_path}\n")
        f.write(
            f"blob_path exists: {Path(blob_path).exists() if blob_path else 'N/A'}\n"
        )

    if not blob_path or not Path(blob_path).exists():
        # Try to reconstruct from base64 blob
        if pov.blob:
            # Create temp file from base64
            temp_dir = ctx.get("output_dir")
            if temp_dir:
                temp_blob = Path(temp_dir) / f"verify_{pov_id[:8]}.bin"
                temp_blob.write_bytes(base64.b64decode(pov.blob))
                blob_path = str(temp_blob)
            else:
                with open("/tmp/pov_debug.log", "a") as f:
                    f.write("ERROR: No output_dir\n")
                return {
                    "success": False,
                    "error": "No blob path and no output_dir to reconstruct",
                }
        else:
            with open("/tmp/pov_debug.log", "a") as f:
                f.write("ERROR: POV has no blob data\n")
            return {"success": False, "error": "POV has no blob data"}

    blob_path = Path(blob_path)

    # Get fuzzer path from context or POV
    fuzzer_path = ctx.get("fuzzer_path")
    docker_image = ctx.get("docker_image")

    # TEST_ONLY
    with open("/tmp/pov_debug.log", "a") as f:
        f.write(f"fuzzer_path: {fuzzer_path}\n")
        f.write(f"docker_image: {docker_image}\n")

    if not fuzzer_path:
        return {"success": False, "error": "fuzzer_path not set in POV context"}
    if not docker_image:
        return {"success": False, "error": "docker_image not set in POV context"}

    fuzzer_path = Path(fuzzer_path)
    if not fuzzer_path.exists():
        return {"success": False, "error": f"Fuzzer not found: {fuzzer_path}"}

    logger.info(f"[POV] Verifying POV {pov_id[:8]} with fuzzer {fuzzer_path.name}")

    # Run fuzzer in Docker
    success, crashed, output, error = _run_fuzzer_docker(
        fuzzer_path=fuzzer_path,
        blob_path=blob_path,
        docker_image=docker_image,
        sanitizer=sanitizer,
    )

    if not success:
        logger.warning(f"[POV] Verification failed: {error}")
        return {
            "success": False,
            "crashed": False,
            "vuln_type": None,
            "sanitizer_output": "",
            "error": error,
        }

    # Parse vulnerability type if crashed
    vuln_type = None
    if crashed:
        vuln_type = _parse_vuln_type(output)
        logger.info(f"[POV] CRASH DETECTED! vuln_type={vuln_type}")

        # Prepare POV data for packaging (BEFORE saving is_successful=True)
        pov.vuln_type = vuln_type
        pov.sanitizer_output = output[:10000]  # Truncate for DB
        pov.verified_at = datetime.now()

        # Package POV with report BEFORE marking as successful
        # This ensures report is generated before dispatcher can stop
        try:
            workspace_path = ctx.get("workspace_path")
            task_id = ctx.get("task_id", "")
            ctx_worker_id = ctx.get("worker_id", "")
            if workspace_path:
                # Get TASK workspace (not worker workspace)
                # Worker workspace: {task_workspace}/worker_workspace/{harness_sanitizer}/
                # Task workspace: {task_workspace}/
                worker_ws = Path(workspace_path)
                if "worker_workspace" in str(worker_ws):
                    task_workspace = worker_ws.parent.parent
                else:
                    task_workspace = worker_ws
                results_dir = task_workspace / "results"
                # Capture analyzer context for restoration in packager's new event loop
                from .analyzer import get_analyzer_context

                analyzer_socket = get_analyzer_context()
                packager = POVPackager(
                    str(results_dir),
                    task_id=task_id,
                    worker_id=ctx_worker_id,
                    repos=repos,
                    analyzer_socket_path=analyzer_socket,
                )

                # Get SP record from database
                sp = repos.suspicious_points.find_by_id(pov.suspicious_point_id)
                if sp:
                    sp_dict = sp.to_dict() if hasattr(sp, "to_dict") else vars(sp)
                    pov_dict = pov.to_dict() if hasattr(pov, "to_dict") else vars(pov)

                    # Package synchronously (non-blocking for DB save)
                    zip_path = packager.package_pov(pov_dict, sp_dict)
                    if zip_path:
                        logger.info(f"[POV] Packaged POV to {zip_path}")
                    else:
                        logger.warning(f"[POV] Failed to package POV {pov_id[:8]}")
                else:
                    logger.warning(
                        f"[POV] SP not found for packaging: {pov.suspicious_point_id}"
                    )
        except Exception as e:
            # Don't let packaging errors block POV success
            logger.error(f"[POV] Packaging failed (non-fatal): {e}")

        # NOW mark as successful and save to DB
        # Dispatcher can detect this and stop, but report is already generated
        pov.is_successful = True
        repos.povs.save(pov)

        logger.info(f"[POV] POV {pov_id[:8]} marked as successful")
    else:
        logger.info(f"[POV] No crash detected for POV {pov_id[:8]}")
        # Don't delete, just don't mark as successful
        pov.sanitizer_output = output[:5000]  # Store output for debugging
        pov.verified_at = datetime.now()
        repos.povs.save(pov)

    # Return minimal info - LLM mainly needs crash status and vuln_type
    if crashed:
        return {
            "success": True,
            "crashed": True,
            "vuln_type": vuln_type,
            "summary": f"CRASH DETECTED: {vuln_type}",
        }
    else:
        # For non-crash, extract meaningful info using fast LLM
        output_summary = _extract_output_summary(output)
        return {
            "success": True,
            "crashed": False,
            "output_summary": output_summary,
        }


@tools_mcp.tool
def verify_pov(
    pov_id: str,
) -> Dict[str, Any]:
    """
    Verify if a POV triggers a crash in the target fuzzer.

    Runs the fuzzer with the POV blob in a Docker container and checks
    for sanitizer crash indicators.

    Args:
        pov_id: ID of the POV to verify

    Returns:
        {
            "success": True/False,
            "crashed": True/False,
            "vuln_type": "heap-buffer-overflow" or None,
            "sanitizer_output": "..." (truncated),
            "error": None or error message,
        }
    """
    err = _ensure_context()
    if err:
        return err

    return _verify_pov_core(pov_id=pov_id)


# =============================================================================
# POV Execution Trace
# =============================================================================


def _trace_pov_core(
    pov_id: str,
    target_functions: Optional[List[str]] = None,
    worker_id: str = None,
) -> Dict[str, Any]:
    """
    Core implementation of trace_pov.

    Args:
        worker_id: Explicit worker_id for context lookup (preferred over ContextVar)
    """
    ctx = _get_context_by_worker_id(worker_id) if worker_id else _get_current_context()
    if ctx and ctx.get("qualified_runtime_required"):
        return _pending_qualified_runtime()
    repos = ctx["repos"]

    # Get POV from database
    pov = repos.povs.find_by_id(pov_id)
    if not pov:
        return {"success": False, "error": f"POV {pov_id} not found"}

    # Get blob data
    blob_data = None
    if pov.blob:
        blob_data = base64.b64decode(pov.blob)
    elif pov.blob_path and Path(pov.blob_path).exists():
        blob_data = Path(pov.blob_path).read_bytes()
    else:
        return {"success": False, "error": "POV has no blob data"}

    # Check coverage context is set
    coverage_fuzzer_dir, project_name, src_dir = get_coverage_context()
    if coverage_fuzzer_dir is None:
        return {
            "success": False,
            "error": "Coverage context not set. Call set_coverage_context() first.",
        }

    # Get fuzzer name from POV or context
    fuzzer_name = pov.harness_name or ctx.get("fuzzer", "")
    if not fuzzer_name:
        return {"success": False, "error": "No fuzzer name in POV or context"}

    # Create work directory for coverage output (avoid /tmp - Docker Snap can't mount it)
    output_dir = ctx.get("output_dir")
    workspace_path = ctx.get("workspace_path")
    if output_dir:
        work_dir = Path(output_dir) / "trace" / pov_id[:8]
    elif workspace_path:
        work_dir = Path(workspace_path) / ".trace" / pov_id[:8]
    else:
        work_dir = Path.cwd() / ".pov_trace" / pov_id[:8]
    work_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"[POV] Tracing POV {pov_id[:8]} with fuzzer {fuzzer_name}")

    # =========================================================================
    # Strategy: Try GDB first (reliable crash detection), fallback to coverage
    # =========================================================================

    executed_functions = []
    target_reached = {}
    gdb_failed = False

    # Step 1: Try GDB trace first
    logger.info(f"[POV] Trying GDB trace first for POV {pov_id[:8]}...")
    gdb_success, hit_functions, crashed, gdb_output = run_gdb_trace(
        fuzzer_name, blob_data, work_dir, target_functions
    )

    if gdb_success:
        if crashed:
            # GDB detected crash - POV is correct!
            vuln_type = _parse_vuln_type(gdb_output)
            logger.info(
                f"[POV] GDB detected CRASH! POV {pov_id[:8]} is correct. vuln_type={vuln_type}, hit_funcs={hit_functions}"
            )
            return {
                "success": True,
                "crashed": True,
                "processor": "gdb",
                "vuln_type": vuln_type,
                "executed_functions": hit_functions,
                "target_reached": {
                    func: (func in hit_functions) for func in (target_functions or [])
                },
                "executed_function_count": len(hit_functions),
                "message": "CRASH DETECTED! This POV successfully triggered the vulnerability. "
                "Please call create_pov directly to save and verify it.",
                "sanitizer_output": gdb_output[:3000],
            }

        # GDB succeeded without crash - check which functions were hit
        if target_functions:
            for func in target_functions:
                target_reached[func] = func in hit_functions

        any_target_reached = any(target_reached.values()) if target_reached else False

        # If no target hit, try coverage for more detail
        if not any_target_reached and target_functions:
            logger.info("[POV] GDB: no target hit, trying coverage...")
            gdb_failed = True
        else:
            executed_functions = hit_functions
            logger.info(
                f"[POV] GDB trace complete: {len(hit_functions)} breakpoints hit"
            )
    else:
        logger.warning(
            f"[POV] GDB trace failed: {gdb_output[:200]}, falling back to coverage..."
        )
        gdb_failed = True

    # Step 2: Fallback to coverage if GDB failed
    if gdb_failed:
        success, lcov_path, msg = run_coverage_fuzzer(fuzzer_name, blob_data, work_dir)

        if not success:
            crashed = any(indicator in msg for indicator in CRASH_INDICATORS)
            if crashed:
                vuln_type = _parse_vuln_type(msg)
                hit_funcs = _extract_hit_functions(msg, target_functions or [])
                logger.info(
                    f"[POV] Coverage detected CRASH! POV {pov_id[:8]} is correct. vuln_type={vuln_type}, hit_funcs={hit_funcs}"
                )
                return {
                    "success": True,
                    "crashed": True,
                    "processor": "cov",
                    "vuln_type": vuln_type,
                    "executed_functions": hit_funcs,
                    "target_reached": {
                        func: (func in hit_funcs) for func in (target_functions or [])
                    },
                    "executed_function_count": len(hit_funcs),
                    "message": "CRASH DETECTED! This POV successfully triggered the vulnerability. "
                    "Please call create_pov directly to save and verify it.",
                    "sanitizer_output": msg[:3000],
                }

            logger.warning(f"[POV] Trace failed: {msg}")
            return {
                "success": False,
                "crashed": False,
                "processor": "cov",
                "executed_functions": [],
                "target_reached": {func: False for func in (target_functions or [])},
                "executed_function_count": 0,
                "error": msg,
            }

        # Parse LCOV
        _, _, executed_functions = parse_lcov(lcov_path)

        target_reached = {}
        if target_functions:
            for func in target_functions:
                target_reached[func] = func in executed_functions

        logger.info(
            f"[POV] Coverage trace complete: {len(executed_functions)} functions executed"
        )

    return {
        "success": True,
        "crashed": False,
        "processor": "cov" if gdb_failed else "gdb",
        "executed_functions": executed_functions[:20],
        "target_reached": target_reached,
        "total_executed": len(executed_functions),
    }


def _load_trace_analysis_prompt() -> str:
    """Load trace analysis prompt from markdown file."""
    prompt_path = (
        Path(__file__).parent.parent / "agents" / "prompts" / "trace_analysis_prompt.md"
    )
    if prompt_path.exists():
        return prompt_path.read_text()
    return ""


def _analyze_trace(
    blob: bytes,
    executed_functions: List[str],
    target_functions: Optional[List[str]],
    any_target_reached: bool,
    agent_msg: Optional[str],
    ctx: Dict[str, Any],
) -> str:
    """
    Use LLM to analyze trace results and provide actionable feedback.
    """
    try:
        from ..llms import quick_call, CLAUDE_HAIKU_4_5

        fuzzer_name = ctx.get("fuzzer", "unknown")

        # Blob preview (hex, first 100 bytes)
        blob_hex = blob[:100].hex()
        blob_preview = " ".join(
            blob_hex[i : i + 2] for i in range(0, min(len(blob_hex), 60), 2)
        )
        if len(blob) > 100:
            blob_preview += f"... ({len(blob)} bytes total)"

        # Load and format prompt
        prompt_template = _load_trace_analysis_prompt()
        prompt = prompt_template.format(
            target_functions=target_functions or "not specified",
            any_target_reached=any_target_reached,
            fuzzer_name=fuzzer_name,
            blob_preview=blob_preview,
            executed_functions=", ".join(executed_functions[:20]),
            total_executed=len(executed_functions),
            agent_msg=agent_msg or "Why did execution stop before reaching target?",
        )

        analysis = quick_call(prompt, model=CLAUDE_HAIKU_4_5)
        return analysis[:800] if analysis else "Analysis failed"
    except Exception as e:
        logger.warning(f"[POV] Trace analysis failed: {e}")
        return f"Analysis unavailable: {e}"


@tools_mcp.tool
def trace_pov(
    generator_code: str,
    target_functions: Optional[List[str]] = None,
    agent_msg: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Trace execution path of a generated blob to debug why it doesn't crash.

    Args:
        generator_code: Python code with a generate() function that returns bytes.
        target_functions: List of function names to check if reached (e.g. ["vulnerable_func"])
        agent_msg: What you want to know - helps focus the analysis (e.g. "why is magic byte check failing?")

    Returns:
        {
            "success": True/False,
            "any_target_reached": True/False,
            "target_status": {"func_name": True/False, ...},
            "executed_functions": [...] (first 30),
            "total_executed": N,
            "analysis": "LLM analysis of why execution stopped and what to fix",
        }
    """
    err = _ensure_context()
    if err:
        return err
    ctx = _get_current_context()
    if ctx and ctx.get("qualified_runtime_required"):
        return _pending_qualified_runtime()

    # Execute generator code to get blob
    from ..fuzzer.seed_sandbox import SeedSandboxCleanupError

    try:
        blobs, error = _execute_generator_code(generator_code, num_variants=1)
    except SeedSandboxCleanupError as exc:
        return {"success": False, "error": str(exc),
                "fatal_sandbox_cleanup": True}
    if error:
        return {"success": False, "error": f"Generator code error: {error}"}
    if not blobs:
        return {"success": False, "error": "Generator code produced no blob"}

    blob = blobs[0]

    # Get context for coverage
    ctx = _get_current_context()
    coverage_fuzzer_dir, project_name, src_dir = get_coverage_context()
    if coverage_fuzzer_dir is None:
        return {"success": False, "error": "Coverage context not set"}

    fuzzer_name = ctx.get("fuzzer", "")
    if not fuzzer_name:
        return {"success": False, "error": "No fuzzer name in context"}

    # Create temp work directory (avoid /tmp - Docker Snap can't mount it)
    output_dir = ctx.get("output_dir")
    workspace_path = ctx.get("workspace_path")
    trace_id = str(uuid.uuid4())[:8]
    if output_dir:
        work_dir = Path(output_dir) / "trace" / trace_id
    elif workspace_path:
        work_dir = Path(workspace_path) / ".trace" / trace_id
    else:
        work_dir = Path.cwd() / ".pov_trace" / trace_id
    work_dir.mkdir(parents=True, exist_ok=True)

    logger.info(
        f"[POV] Tracing blob ({len(blob)} bytes) with fuzzer {fuzzer_name}, work_dir={work_dir}"
    )

    # =========================================================================
    # Strategy: Try GDB first (reliable crash detection), fallback to coverage
    # =========================================================================

    executed_functions = []
    target_status = {}
    any_target_reached = False
    gdb_failed = False

    # Step 1: Try GDB trace first
    logger.info("[POV] Trying GDB trace first...")
    gdb_success, hit_functions, crashed, gdb_output = run_gdb_trace(
        fuzzer_name, blob, work_dir, target_functions
    )

    if gdb_success:
        if crashed:
            # GDB detected crash - POV is correct!
            vuln_type = _parse_vuln_type(gdb_output)
            logger.info(
                f"[POV] GDB detected CRASH! POV is correct. vuln_type={vuln_type}, hit_funcs={hit_functions}"
            )
            return {
                "success": True,
                "crashed": True,
                "processor": "gdb",
                "vuln_type": vuln_type,
                "any_target_reached": len(hit_functions) > 0,
                "target_status": {
                    func: (func in hit_functions) for func in (target_functions or [])
                },
                "executed_functions": hit_functions,
                "total_executed": len(hit_functions),
                "message": "CRASH DETECTED! This POV successfully triggered the vulnerability. "
                "Please call create_pov directly to save and verify it.",
                "sanitizer_output": gdb_output[:3000],
            }

        # GDB succeeded without crash - check which functions were hit
        if target_functions:
            for func in target_functions:
                hit = func in hit_functions
                target_status[func] = hit
                if hit:
                    any_target_reached = True

        # GDB gives us limited function info, try coverage for more detail
        if not any_target_reached and target_functions:
            logger.info("[POV] GDB: no target hit, trying coverage for more detail...")
            gdb_failed = True  # Fall through to coverage
        else:
            executed_functions = hit_functions
            logger.info(
                f"[POV] GDB trace complete: {len(hit_functions)} breakpoints hit, target_reached={any_target_reached}"
            )
    else:
        logger.warning(
            f"[POV] GDB trace failed: {gdb_output[:200]}, falling back to coverage..."
        )
        gdb_failed = True

    # Step 2: Fallback to coverage if GDB failed or didn't give enough info
    if gdb_failed:
        success, lcov_path, msg = run_coverage_fuzzer(fuzzer_name, blob, work_dir)

        if not success:
            # Check if failure was due to a crash (crash = success!)
            crashed = any(indicator in msg for indicator in CRASH_INDICATORS)
            if crashed:
                vuln_type = _parse_vuln_type(msg)
                hit_funcs = _extract_hit_functions(msg, target_functions or [])
                logger.info(
                    f"[POV] Coverage detected CRASH! POV is correct. vuln_type={vuln_type}, hit_funcs={hit_funcs}"
                )
                return {
                    "success": True,
                    "crashed": True,
                    "processor": "cov",
                    "vuln_type": vuln_type,
                    "any_target_reached": len(hit_funcs) > 0,
                    "target_status": {
                        func: (func in hit_funcs) for func in (target_functions or [])
                    },
                    "executed_functions": hit_funcs,
                    "total_executed": len(hit_funcs),
                    "message": "CRASH DETECTED! This POV successfully triggered the vulnerability. "
                    "Please call create_pov directly to save and verify it.",
                    "sanitizer_output": msg[:3000],
                }

            # True failure - no crash and no coverage
            return {
                "success": False,
                "crashed": False,
                "processor": "cov",
                "any_target_reached": False,
                "target_status": {func: False for func in (target_functions or [])},
                "executed_functions": [],
                "total_executed": 0,
                "error": msg,
            }

        # Parse LCOV to get executed functions
        _, _, executed_functions = parse_lcov(lcov_path)

        # Check target functions
        target_status = {}
        any_target_reached = False
        if target_functions:
            for func in target_functions:
                hit = func in executed_functions
                target_status[func] = hit
                if hit:
                    any_target_reached = True

        logger.info(
            f"[POV] Coverage trace: {len(executed_functions)} functions, target_reached={any_target_reached}"
        )

    # LLM analysis
    analysis = _analyze_trace(
        blob=blob,
        executed_functions=executed_functions,
        target_functions=target_functions,
        any_target_reached=any_target_reached,
        agent_msg=agent_msg,
        ctx=ctx,
    )

    return {
        "success": True,
        "crashed": False,
        "processor": "cov" if gdb_failed else "gdb",
        "any_target_reached": any_target_reached,
        "target_status": target_status,
        "executed_functions": executed_functions[:30],
        "total_executed": len(executed_functions),
        "analysis": analysis,
    }


# Export public API
__all__ = [
    # Context
    "set_pov_context",
    "update_pov_iteration",
    "get_pov_context",
    "clear_pov_context",
    # POV tools (MCP decorated)
    "get_fuzzer_info",
    "create_pov",
    "verify_pov",
    "trace_pov",
    # POV tools (implementation, for mcp_factory)
    "get_fuzzer_info_impl",
    "create_pov_impl",
    "verify_pov_impl",
    "trace_pov_impl",
]
