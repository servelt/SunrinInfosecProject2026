"""Small dev-smoke wrapper around the existing DevelopmentRequestLedger.

This records physical starts before provider transmission. It does not replace
the product campaign ledger or settle SP/Direction evidence by itself.
"""

import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time


DEFAULT_LEDGER_MODULE = Path(
    "/home/dawne/SunrinInfosecProject2026/reference/"
    "blind2_v2_preparation_20261027/evaluation_tools/dev_global_request_ledger.py")
DEFAULT_LEDGER_SHA256 = "8411b03770029fb70addccf220c8d3f77bf0660a706a4359b5c205d2ff999e9f"


def load_ledger_module(path=DEFAULT_LEDGER_MODULE,
                       expected_sha256=DEFAULT_LEDGER_SHA256):
    supplied = Path(path)
    if (not supplied.is_absolute() or supplied.is_symlink() or
            supplied != supplied.resolve(strict=True)):
        raise ValueError("development ledger module path must be canonical")
    path = supplied
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError("development ledger module identity mismatch")
    name = "fbv2_pinned_development_request_ledger"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("development ledger module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def create_smoke_ledger(module, *, checkpoint_path: Path, scope_id: str,
                        role: str, physical_max: int, wall_seconds: float):
    budget = module.DevelopmentBudget(
        physical_max=physical_max, logical_max=physical_max, retries_max=0,
        wall_seconds=wall_seconds, initial_starts_required=1,
        direction_turns_per_scope=physical_max,
        profile=module.GLOBAL_ONLY_DEV_PROFILE,
    )
    ledger = module.DevelopmentRequestLedger.create(budget, checkpoint_path)
    if role == module.DIRECTION_ROLE:
        ledger.register_direction(scope_id)
    elif role == "sp_generation":
        if not ledger.select_function(scope_id):
            raise RuntimeError("SP smoke function not admitted by model ledger")
    else:
        raise ValueError("unsupported dev smoke role")
    return ledger


def _request_hash(request):
    payload = {
        "role": request.role, "instructions": request.instructions,
        "payload": request.payload, "output_schema": request.output_schema,
        "session_key": request.session_key, "model": request.model,
        "effort": request.effort,
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class LedgeredProvider:
    """Predebit each LLMRequest; never retry an uncertain provider attempt."""

    def __init__(self, provider, ledger, *, scope_id: str, role: str):
        self.provider = provider
        self.ledger = ledger
        self.scope_id = scope_id
        self.role = role

    async def generate(self, request):
        digest = _request_hash(request)
        self.ledger.begin_turn(self.scope_id, self.role, digest)
        try:
            self.ledger.start_attempt(digest)
        except BaseException as original:
            try:
                self.ledger.abandon_turn("PRE_SEND_MODEL_START_FAILED",
                                         budget_exhausted=True)
            except BaseException as cleanup:
                original.add_note(f"ledger cleanup failed: {type(cleanup).__name__}")
            raise
        try:
            remaining = (self.ledger.budget.wall_seconds -
                         (time.time() - self.ledger.started_at))
            if remaining <= 0:
                raise TimeoutError("development model wall budget exhausted")
            response = await asyncio.wait_for(self.provider.generate(request),
                                              timeout=remaining)
        except BaseException as original:
            try:
                self.ledger.finish_attempt(completed=False,
                                           error=type(original).__name__)
                self.ledger.abandon_turn("UNCERTAIN_MODEL_ATTEMPT")
            except BaseException as cleanup:
                original.add_note(f"ledger cleanup failed: {type(cleanup).__name__}")
            raise
        self.ledger.finish_attempt(completed=True)
        return response

    async def close(self):
        await self.provider.close()


def ledger_summary(ledger):
    try:
        if ledger.checkpoint_path.is_symlink():
            raise OSError("ledger checkpoint is a symbolic link")
        checkpoint_sha256 = hashlib.sha256(
            ledger.checkpoint_path.read_bytes()).hexdigest()
        checkpoint_error = (
            None if checkpoint_sha256 == getattr(ledger, "_checkpoint_sha256", None)
            else "CHECKPOINT_BYTE_MISMATCH"
        )
    except OSError as exc:
        checkpoint_sha256 = None
        checkpoint_error = type(exc).__name__
    return {
        "ledger_path": str(ledger.checkpoint_path),
        "ledger_checkpoint_sha256": checkpoint_sha256,
        "ledger_checkpoint_error": checkpoint_error,
        "ledger_scope_id": ledger.direction_scopes[0] if ledger.direction_scopes
                           else ledger.selected_functions[0],
        "ledger_physical": ledger.physical,
        "ledger_logical": ledger.logical,
        "ledger_physical_cap": ledger.budget.physical_max,
        "ledger_wall_seconds_cap": ledger.budget.wall_seconds,
        "ledger_pending_states": [row["state"] for row in ledger.pending_work],
        "ledger_active_turn": ledger.active_turn is not None,
        "ledger_tainted": ledger.tainted,
    }


def appserver_event_summary(path: Path):
    """Report observed App Server turns separately from predebit reservations."""
    path = Path(path)
    try:
        if path.is_symlink():
            raise OSError("App Server event log is a symbolic link")
        data = path.read_bytes()
        started = set()
        completed = set()
        usage = {}
        for line in data.splitlines():
            row = json.loads(line)
            method = row.get("method")
            params = row.get("params") or {}
            turn = params.get("turn") or {}
            turn_id = (row.get("turn_id") or params.get("turnId") or
                       (turn.get("id") if isinstance(turn, dict) else None))
            if method == "turn/started":
                if not turn_id or turn_id in started:
                    raise ValueError("duplicate or missing App Server turn start ID")
                started.add(turn_id)
            elif method == "turn/completed":
                if not turn_id or turn_id in completed:
                    raise ValueError("duplicate or missing App Server turn completion ID")
                completed.add(turn_id)
            elif method == "thread/tokenUsage/updated" and turn_id:
                usage[turn_id] = row["params"]["tokenUsage"]["last"]
        if not completed <= started or not set(usage) <= started:
            raise ValueError("App Server event log has orphaned turn evidence")
        return {
            "event_log_sha256": hashlib.sha256(data).hexdigest(),
            "event_log_error": None,
            "appserver_turns_started": len(started),
            "appserver_turns_completed": len(completed),
            "appserver_input_tokens_reported": sum(
                row.get("inputTokens", 0) for row in usage.values()),
            "appserver_output_tokens_reported": sum(
                row.get("outputTokens", 0) for row in usage.values()),
        }
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return {"event_log_sha256": None, "event_log_error": type(exc).__name__,
                "appserver_turns_started": None,
                "appserver_turns_completed": None,
                "appserver_input_tokens_reported": None,
                "appserver_output_tokens_reported": None}
