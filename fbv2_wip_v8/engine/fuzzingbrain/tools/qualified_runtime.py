"""Typed handoff from original FBv2 PoV tools to the qualified product Runtime.

The model cannot construct this binding through MCP. A development launcher
installs it only after product official V2 qualification and physical budget
setup. This module does not execute a target or decide the security Gate.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any, Callable


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_STATUSES = frozenset({"NO_CRASH", "CRASH_OBSERVED", "INCOMPLETE"})


@dataclass(frozen=True)
class QualifiedRuntimeRequest:
    task_id: str
    suspicious_point_id: str
    pov_id: str
    harness_name: str
    sanitizer: str
    input_bytes: bytes
    input_sha256: str
    binary_path: Path
    binary_sha256: str


@dataclass(frozen=True)
class QualifiedRuntimeOutcome:
    """A physical execution observation, never a VERIFIED Gate verdict."""

    status: str
    pov_id: str
    input_sha256: str
    binary_sha256: str
    runtime_receipt_path: Path
    runtime_receipt_sha256: str
    physical_receipt_path: Path
    physical_receipt_sha256: str
    output_summary: str = ""
    sanitizer: str | None = None


@dataclass(frozen=True)
class QualifiedGeneratorRequest:
    """One PoV code execution, bound to the claimed task and SP attempt."""

    task_id: str
    suspicious_point_id: str
    worker_id: str
    attempt: int
    code: str
    num_variants: int


@dataclass(frozen=True)
class QualifiedRuntimeBinding:
    qualification: Any
    execute: Callable[[QualifiedRuntimeRequest], QualifiedRuntimeOutcome]
    generate: Callable[[QualifiedGeneratorRequest], list[bytes]] | None = None

    def pinned_binary(self) -> tuple[Path, str]:
        """Reissue product V2 authority before every physical PoV attempt."""
        try:
            from vulnerabilityanalysis.official_harness import (
                OfficialPinnedQualification, _qualification_pins_ok,
            )
        except ImportError as exc:
            raise ValueError("product official qualification is unavailable") from exc
        q = self.qualification
        if (not isinstance(q, OfficialPinnedQualification) or
                q.product_issued is not True or
                q.contract_kind != "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2" or
                not _qualification_pins_ok(q)):
            raise ValueError("product-issued official V2 qualification changed")
        binary = Path(q.binary)
        if (binary.is_symlink() or not binary.is_file() or
                binary != binary.resolve() or
                not _SHA256.fullmatch(q.binary_sha256) or
                hashlib.sha256(binary.read_bytes()).hexdigest() != q.binary_sha256):
            raise ValueError("qualified binary identity changed")
        return binary, q.binary_sha256


def validate_outcome(outcome: QualifiedRuntimeOutcome,
                     request: QualifiedRuntimeRequest) -> None:
    """Check exact input/binary binding and durable runtime/physical receipts."""
    if (type(outcome) is not QualifiedRuntimeOutcome or
            outcome.status not in _STATUSES or
            outcome.pov_id != request.pov_id or
            outcome.input_sha256 != request.input_sha256 or
            outcome.binary_sha256 != request.binary_sha256 or
            (outcome.status == "CRASH_OBSERVED" and not outcome.sanitizer) or
            (outcome.status == "NO_CRASH" and outcome.sanitizer is not None) or
            not isinstance(outcome.output_summary, str) or
            len(outcome.output_summary) > 8_000 or
            (outcome.sanitizer is not None and
             (not isinstance(outcome.sanitizer, str) or
              len(outcome.sanitizer) > 200))):
        raise ValueError("qualified Runtime returned a mismatched outcome")
    for path, wanted in (
        (outcome.runtime_receipt_path, outcome.runtime_receipt_sha256),
        (outcome.physical_receipt_path, outcome.physical_receipt_sha256),
    ):
        if (not isinstance(path, Path) or not path.is_absolute() or
                path.is_symlink() or not path.is_file() or
                path.stat().st_size > 16_000_000 or
                not _SHA256.fullmatch(wanted) or
                hashlib.sha256(path.read_bytes()).hexdigest() != wanted):
            raise ValueError("qualified Runtime receipt changed or is missing")
