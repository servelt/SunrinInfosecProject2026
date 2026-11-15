"""Opt-in Stage17a process envelope for synthetic development executions.

The official --execute route does not accept this development contract.  A
future pinned official adapter must supply its own identity hook and budget.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import time
from typing import Callable

from dev_persistent_physical_fuzz_ledger import PhysicalBudgetExhausted
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from vulnerabilityanalysis.runtime import ProcessEnvelopeStop


@dataclass(frozen=True)
class ProcessLease:
    key: str
    kind: str
    segment: str
    command: tuple[str, ...]


class DevelopmentProcessEnvelopeV2:
    """One work item, one V2 ledger, and deterministic per-process keys."""

    def __init__(self, ledger: PersistentProcessLedgerV2, *,
                 work_item_id: str, assertion_id: str, attempt_id: str,
                 output_limit_bytes: int, total_wall_seconds: float,
                 pin_hook: Callable[[str, list[str]], None],
                 cleanup_envelope_seconds: float = 9.5):
        if (type(ledger) is not PersistentProcessLedgerV2 or
                any(type(value) is not str or not value or ":" in value
                    for value in (work_item_id, assertion_id, attempt_id)) or
                type(output_limit_bytes) is not int or output_limit_bytes < 1 or
                type(total_wall_seconds) not in (int, float) or
                not math.isfinite(total_wall_seconds) or total_wall_seconds <= 0 or
                type(cleanup_envelope_seconds) not in (int, float) or
                not math.isfinite(cleanup_envelope_seconds) or
                cleanup_envelope_seconds < 9.5 or not callable(pin_hook)):
            raise ValueError("invalid development process envelope")
        self.ledger = ledger
        self.work_item_id = work_item_id
        self.assertion_id = assertion_id
        self.attempt_id = attempt_id
        self.output_limit_bytes = output_limit_bytes
        self.cleanup_envelope_seconds = float(cleanup_envelope_seconds)
        self.deadline_monotonic = time.monotonic() + float(total_wall_seconds)
        self.pin_hook = pin_hook
        self._next_ordinal = 0
        self._prefix = f"{work_item_id}:{assertion_id}:{attempt_id}:"
        if any(key.startswith(self._prefix) for key in ledger.snapshot()["active"]) or any(
                row["key"].startswith(self._prefix)
                for row in ledger.snapshot()["finished"]):
            raise RuntimeError("a V2 process attempt cannot be resumed or resent")

    def _pin(self, phase: str, command: list[str]) -> None:
        try:
            self.pin_hook(phase, list(command))
        except BaseException as exc:
            try:
                self.ledger.mark_stop("STOPPED_PIN_DRIFT",
                                      f"{phase}: {type(exc).__name__}")
            except BaseException as audit_exc:
                exc.add_note("V2 pin stop receipt failed: " +
                             type(audit_exc).__name__)
            raise ProcessEnvelopeStop("STOPPED_PIN_DRIFT",
                                      f"process identity changed at {phase}") from exc

    def before_process(self, command: list[str], *, cwd: Path | None,
                       env: dict[str, str] | None, timeout: float,
                       kind: str, segment: str) -> ProcessLease:
        if (kind not in {"AUX_PROCESS", "HP_FUZZ", "GLOBAL_FUZZ", "SP_FUZZ"} or
                type(segment) is not str or not segment or
                type(timeout) not in (int, float) or
                not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("V2 process segment is invalid")
        # A finished segment is never replayed under a fresh UUID.  The
        # ordinal is deterministic for this work-item attempt.
        key = f"{self._prefix}{self._next_ordinal:06d}:{segment}"
        self._pin("before_reserve", command)
        reserved = float(timeout) + self.cleanup_envelope_seconds
        if time.monotonic() + reserved > self.deadline_monotonic:
            self.ledger.mark_stop("STOPPED_WALL_LIMIT",
                                  f"no wall reservation for {segment}")
            raise ProcessEnvelopeStop("STOPPED_WALL_LIMIT",
                                      "process cannot fit the total wall deadline")
        try:
            self.ledger.reserve(key, kind, reserved)
        except PhysicalBudgetExhausted as exc:
            raise ProcessEnvelopeStop("PENDING_PHYSICAL_BUDGET",
                                      "V2 process has no prelaunch reservation") from exc
        # A drift in the reserve-to-launch window leaves an active durable
        # reservation.  Restore will stop the run; it is never zero-cost retry.
        self._pin("after_reserve_before_launch", command)
        self._next_ordinal += 1
        return ProcessLease(key, kind, segment, tuple(command))

    def after_process(self, lease: ProcessLease, *, elapsed_seconds: float,
                      cleanup_complete: bool, output_limited: bool,
                      error: BaseException | None) -> None:
        if type(lease) is not ProcessLease or not lease.key.startswith(self._prefix):
            raise ValueError("V2 process lease changed")
        row = self.ledger.finish(lease.key, physical_seconds=elapsed_seconds,
                                 cleanup_complete=cleanup_complete,
                                 output_limited=output_limited)
        stop = self.ledger.snapshot()["stop_status"]
        # Settlement comes first.  No successful return or post-pin success is
        # possible after a cleanup, output, or physical-cap stop.
        if row["overrun"] or stop is not None:
            raise ProcessEnvelopeStop(
                stop or "STOPPED_PHYSICAL_CAP_UNPROVEN",
                "V2 process stopped during physical settlement")
        # The process time is durable before a post-run pin error can occur.
        self._pin("after_process", list(lease.command))
        if time.monotonic() > self.deadline_monotonic:
            self.ledger.mark_stop("STOPPED_WALL_LIMIT",
                                  f"total wall deadline passed at {lease.segment}")
            raise ProcessEnvelopeStop("STOPPED_WALL_LIMIT",
                                      "total process wall deadline exceeded")
