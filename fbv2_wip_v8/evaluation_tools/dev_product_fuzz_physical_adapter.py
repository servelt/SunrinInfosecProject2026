"""Development-only durable physical cap for one product ``fuzz_locally`` call.

This adapter is an opt-in guarded runner for the product's existing libFuzzer
command. It uses the same ``runtime._guarded_run`` subreaper path as the
default product call and reserves persistent time before that call. The
development Scan SP and HP Guided paths can pass it explicitly; Global and
the formal runner are not connected to it.
The ledger can be rolled back by the same UID and needs an external freeze
authority before it can support a Blind 3 total-budget claim.
"""

from __future__ import annotations

import math
from pathlib import Path
import subprocess
import time
from uuid import uuid4

from vulnerabilityanalysis import runtime

from dev_persistent_physical_fuzz_ledger import (
    PersistentPhysicalFuzzLedger, PhysicalBudgetExhausted)


class PhysicalFuzzLedgerStop(runtime.PhysicalFuzzStop):
    """The guarded process finished but its global budget is not proven."""


class ProductFuzzPhysicalRunner:
    """An explicitly selected SP, HP, or Global product libFuzzer run."""

    def __init__(self, ledger: PersistentPhysicalFuzzLedger, *, kind: str,
                 cleanup_envelope_seconds: float = 9.5):
        if kind not in {"SP", "HP", "GLOBAL"}:
            raise ValueError("invalid product fuzzer role")
        if (type(cleanup_envelope_seconds) not in (int, float) or
                not math.isfinite(cleanup_envelope_seconds) or
                cleanup_envelope_seconds < 9.5):
            raise ValueError("cleanup envelope must cover product subreaper deadlines")
        self.ledger = ledger
        self.kind = kind
        self.cleanup_envelope_seconds = float(cleanup_envelope_seconds)

    @staticmethod
    def _validate_command(command: list[str], cwd: Path | None,
                          timeout: float) -> None:
        if (not isinstance(command, list) or len(command) < 3 or
                any(not isinstance(arg, str) or not arg for arg in command) or
                type(timeout) not in (int, float) or not math.isfinite(timeout) or
                timeout <= 15 or cwd is None):
            raise ValueError("invalid product libFuzzer command")
        binary, corpus = Path(command[0]), Path(command[1])
        if (not binary.is_absolute() or not corpus.is_absolute() or
                not binary.is_file() or not corpus.is_dir() or
                Path(cwd).resolve() != corpus.resolve()):
            raise ValueError("product libFuzzer binary or corpus differs")
        budgets = [arg for arg in command if arg.startswith("-max_total_time=")]
        if len(budgets) != 1:
            raise ValueError("product libFuzzer time argument missing")
        try:
            seconds = int(budgets[0].split("=", 1)[1])
        except ValueError as exc:
            raise ValueError("product libFuzzer time argument invalid") from exc
        if seconds < 1 or timeout != seconds + 15:
            raise ValueError("product libFuzzer timeout differs from requested time")

    def __call__(self, command: list[str], *, cwd: Path | None,
                 timeout: float) -> subprocess.CompletedProcess[str]:
        try:
            self._validate_command(command, cwd, timeout)
        except ValueError as exc:
            raise PhysicalFuzzLedgerStop(
                "STOPPED_PHYSICAL_LEDGER_ERROR",
                "product fuzzer command differs from development contract") from exc
        key = f"{self.kind}:{uuid4().hex}"
        try:
            self.ledger.reserve(key, self.kind,
                                float(timeout) + self.cleanup_envelope_seconds)
        except PhysicalBudgetExhausted as exc:
            raise runtime.PhysicalFuzzBudgetPending(
                "shared physical fuzzer budget has no prelaunch reservation") from exc
        except (ValueError, RuntimeError, OSError) as exc:
            stop = self.ledger.snapshot()["stop_status"]
            raise PhysicalFuzzLedgerStop(
                stop or "STOPPED_PHYSICAL_LEDGER_ERROR",
                "physical fuzzer ledger stopped or rejected prelaunch integrity") from exc
        started = time.monotonic()
        try:
            result = runtime._guarded_run(command, cwd=cwd, timeout=timeout)
        except BaseException as exc:
            # TimeoutExpired is emitted only after the product helper reports
            # complete descendant cleanup. Other errors cannot prove that.
            complete = isinstance(exc, subprocess.TimeoutExpired)
            try:
                self.ledger.finish(
                    key, physical_seconds=max(0.0, time.monotonic() - started),
                    cleanup_complete=complete)
            except BaseException as audit_exc:
                exc.add_note("physical fuzz ledger settlement failed: " +
                             type(audit_exc).__name__)
                if complete:
                    raise PhysicalFuzzLedgerStop(
                        "STOPPED_PHYSICAL_LEDGER_ERROR",
                        "product fuzzer timed out and physical settlement failed"
                    ) from exc
                if isinstance(exc, Exception) and not isinstance(
                        exc, runtime.RuntimeCleanupError):
                    raise PhysicalFuzzLedgerStop(
                        "STOPPED_PHYSICAL_LEDGER_ERROR",
                        "product fuzzer failed and physical settlement failed"
                    ) from exc
            stop = self.ledger.snapshot()["stop_status"]
            if complete and stop is not None:
                raise PhysicalFuzzLedgerStop(
                    stop, "product fuzzer timed out after shared physical stop"
                ) from exc
            if not complete and isinstance(exc, Exception) and not isinstance(
                    exc, runtime.RuntimeCleanupError):
                raise PhysicalFuzzLedgerStop(
                    stop or "STOPPED_PHYSICAL_LEDGER_ERROR",
                    "product fuzzer failed without proven cleanup"
                ) from exc
            raise
        try:
            row = self.ledger.finish(
                key, physical_seconds=max(0.0, time.monotonic() - started),
                cleanup_complete=True)
        except (ValueError, RuntimeError, OSError) as exc:
            raise PhysicalFuzzLedgerStop(
                "STOPPED_PHYSICAL_LEDGER_ERROR",
                "product fuzzer completed but physical settlement failed") from exc
        stop = self.ledger.snapshot()["stop_status"]
        if row["overrun"] or stop is not None:
            raise PhysicalFuzzLedgerStop(
                stop or "STOPPED_PHYSICAL_CAP_UNPROVEN",
                f"product fuzzer completed with unproven physical cap: {stop}")
        return result
