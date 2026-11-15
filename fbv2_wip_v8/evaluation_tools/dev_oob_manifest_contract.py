"""Externally pinned development wrapper for a narrow public-toy OOB witness.

The expected Manifest SHA must come from an independent freeze/approval record.
This module cannot turn a caller-chosen SHA into an approval.  It never creates
an official qualification, product Root Cause, or VERIFIED Gate result.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from dev_oob_causal_witness import (
    ApprovedDebugger, OOBPins, OOBWitnessResult, OOBWitnessSpec,
    _approved_debugger_matches, issue_development_oob_witness,
)
from vulnerabilityanalysis.official_harness import (
    _v2_contract_shape, validate_v2_local_pins,
)


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PIN_KEYS = {"source_sha256", "compiled_source_sha256", "binary_sha256",
             "crash_input_sha256", "normal_input_sha256"}
_PATH_KEYS = {"source_root", "source_path", "binary_path",
              "crash_input_path", "normal_input_path"}
_DEBUG_KEYS = {"invocation_path", "invocation_sha256", "resolved_path",
               "backend_path", "backend_sha256"}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _regular_absolute(value: Any, *, directory: bool = False) -> Path:
    if not isinstance(value, str):
        raise ValueError("approval path must be a string")
    path = Path(value)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path or
            not (path.is_dir() if directory else path.is_file())):
        raise ValueError("approval path is not an unchanged absolute regular path")
    return path


def _private_file(path: Path) -> bool:
    return (path.is_file() and not path.is_symlink() and
            path.stat().st_mode & 0o777 == 0o600 and
            path.parent.is_dir() and path.parent.stat().st_mode & 0o077 == 0)


def _load_approval(path: Path, expected_sha256: str) -> tuple[dict[str, Any],
                                                             OOBPins,
                                                             OOBWitnessSpec,
                                                             ApprovedDebugger]:
    if not isinstance(expected_sha256, str) or not _SHA.fullmatch(expected_sha256):
        raise ValueError("external approval SHA-256 is missing")
    _regular_absolute(str(path))
    if not _private_file(path):
        raise ValueError("approval Manifest must be private")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("external approval SHA-256 changed")
    row = json.loads(raw)
    if (not isinstance(row, dict) or set(row) !=
            {"kind", "scope", "pins", "spec", "approved_debugger",
             "official_v2"} | _PATH_KEYS or
            row["kind"] != "OOB_PUBLIC_TOY_DEV_APPROVAL_V1" or
            row["scope"] != "PUBLIC_TOY_NO_GATE" or
            row["official_v2"] is not None):
        raise ValueError("approval Manifest has unsupported scope or shape")
    pins_row, spec_row, debugger_row = (row[key] for key in
                                         ("pins", "spec", "approved_debugger"))
    if (not isinstance(pins_row, dict) or set(pins_row) != _PIN_KEYS or
            any(not isinstance(value, str) or not _SHA.fullmatch(value)
                for value in pins_row.values()) or
            not isinstance(spec_row, dict) or
            set(spec_row) != {"object_kind", "claimed_capacity"} or
            spec_row["object_kind"] not in {"heap", "stack"} or
            type(spec_row["claimed_capacity"]) is not int or
            not 2 <= spec_row["claimed_capacity"] <= 4096 or
            not isinstance(debugger_row, dict) or
            set(debugger_row) != _DEBUG_KEYS):
        raise ValueError("approval values are malformed")
    root = _regular_absolute(row["source_root"], directory=True)
    paths = {key: _regular_absolute(row[key]) for key in _PATH_KEYS - {"source_root"}}
    if (not paths["source_path"].is_relative_to(root) or
            len(set(paths.values())) != len(paths) or
            any(_digest(paths[key]) != pins_row[sha_key] for key, sha_key in (
                ("source_path", "source_sha256"),
                ("binary_path", "binary_sha256"),
                ("crash_input_path", "crash_input_sha256"),
                ("normal_input_path", "normal_input_sha256"))) or
            pins_row["source_sha256"] != pins_row["compiled_source_sha256"]):
        raise ValueError("approval source, binary or input pin changed")
    debugger = ApprovedDebugger(**debugger_row)
    if not _approved_debugger_matches(Path(debugger.invocation_path), debugger):
        raise ValueError("approved debugger bytes changed")
    return row, OOBPins(**pins_row), OOBWitnessSpec(**spec_row), debugger


def _write_private_once(path: Path, data: dict[str, Any]) -> None:
    payload = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def issue_manifest_bound_oob_witness(
        manifest_path: Path, expected_manifest_sha256: str,
        artifacts_root: Path, *, timeout_seconds: float = 10) -> OOBWitnessResult:
    """Use a preapproved toy Manifest, then bind the inner witness to its SHA."""
    try:
        row, pins, spec, debugger = _load_approval(
            manifest_path, expected_manifest_sha256)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        status = ("BLOCKED_APPROVAL_PINS" if "pin changed" in str(exc) or
                  "bytes changed" in str(exc) else "BLOCKED_APPROVAL_MANIFEST")
        return OOBWitnessResult(status, str(exc))
    result = issue_development_oob_witness(
        Path(row["source_root"]), Path(row["source_path"]),
        Path(row["binary_path"]), Path(row["crash_input_path"]),
        Path(row["normal_input_path"]), spec=spec, pins=pins,
        debugger=Path(debugger.invocation_path), approved_debugger=debugger,
        artifacts_root=artifacts_root, timeout_seconds=timeout_seconds)
    if result.status != "ISSUED_DEVELOPMENT_WITNESS":
        return result
    try:
        again, _, _, _ = _load_approval(manifest_path, expected_manifest_sha256)
        if again != row:
            raise ValueError("approval Manifest changed during issue")
        evidence = result.evidence
        inner = _regular_absolute(evidence["receipt_path"])
        if (not _private_file(inner) or _digest(inner) !=
                evidence["receipt_sha256"] or
                evidence["run_id"] != inner.parent.name or
                evidence["source_sha256"] != pins.source_sha256 or
                evidence["binary_sha256"] != pins.binary_sha256 or
                evidence["input_sha256"] != pins.crash_input_sha256 or
                evidence["normal_input_sha256"] != pins.normal_input_sha256 or
                evidence["debugger_sha256"] != debugger.invocation_sha256 or
                evidence["debugger_backend_sha256"] != debugger.backend_sha256):
            raise ValueError("inner witness identity changed")
        binding_path = inner.parent / "approval_binding.json"
        binding = {
            "kind": "OOB_DEV_MANIFEST_BINDING_V1",
            "status": "ISSUED_MANIFEST_BOUND_DEV_WITNESS",
            "scope": "PUBLIC_TOY_NO_GATE",
            "approval_manifest_path": str(manifest_path),
            "approval_manifest_sha256": expected_manifest_sha256,
            "inner_receipt_path": str(inner),
            "inner_receipt_sha256": evidence["receipt_sha256"],
            "run_id": evidence["run_id"],
            "source_path": row["source_path"],
            "binary_path": row["binary_path"],
            "crash_input_path": row["crash_input_path"],
            "normal_input_path": row["normal_input_path"],
            "pins": asdict(pins),
            "approved_debugger": asdict(debugger),
            "qualification_identity": "NONE",
            "gate_eligible": False,
        }
        _write_private_once(binding_path, binding)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        return OOBWitnessResult("BLOCKED_MANIFEST_BINDING", str(exc))
    bound_evidence = dict(result.evidence)
    bound_evidence.update({
        "approval_manifest_path": str(manifest_path),
        "approval_manifest_sha256": expected_manifest_sha256,
        "manifest_binding_receipt_path": str(binding_path),
        "manifest_binding_receipt_sha256": _digest(binding_path),
        "gate_eligible": False,
    })
    return OOBWitnessResult("ISSUED_MANIFEST_BOUND_DEV_WITNESS",
                            "narrow public toy witness bound to preapproved Manifest",
                            bound_evidence, False)


def verify_manifest_bound_oob_witness(result: OOBWitnessResult,
                                      expected_manifest_sha256: str,
                                      expected_binding_sha256: str) -> bool:
    """Recheck bytes against two independently retained SHA values.

    The caller must retain the binding SHA outside the writable artifact tree
    at issue time. Reading it back from ``result.evidence`` would let an
    artifact writer rehash changed measurements and approve their own edit.
    """
    try:
        if (not isinstance(expected_binding_sha256, str) or
                not _SHA.fullmatch(expected_binding_sha256) or
                result.status != "ISSUED_MANIFEST_BOUND_DEV_WITNESS" or
                result.gate_eligible or
                result.evidence.get("gate_eligible") is not False or
                result.evidence.get("qualification_identity") != "NONE" or
                result.evidence.get("approval_manifest_sha256") !=
                expected_manifest_sha256 or
                result.evidence.get("manifest_binding_receipt_sha256") !=
                expected_binding_sha256):
            return False
        evidence = result.evidence
        manifest = _regular_absolute(evidence["approval_manifest_path"])
        row, pins, spec, debugger = _load_approval(manifest,
                                                   expected_manifest_sha256)
        outer = _regular_absolute(evidence["manifest_binding_receipt_path"])
        inner = _regular_absolute(evidence["receipt_path"])
        if (not _private_file(outer) or not _private_file(inner) or
                outer.parent != inner.parent or
                _digest(outer) != expected_binding_sha256 or
                _digest(inner) != evidence["receipt_sha256"]):
            return False
        binding = json.loads(outer.read_text(encoding="utf-8"))
        original = json.loads(inner.read_text(encoding="utf-8"))
        if (set(binding) != {"kind", "status", "scope", "approval_manifest_path",
                             "approval_manifest_sha256", "inner_receipt_path",
                             "inner_receipt_sha256", "run_id", "source_path",
                             "binary_path", "crash_input_path", "normal_input_path",
                             "pins", "approved_debugger", "qualification_identity",
                             "gate_eligible"} or
                binding["kind"] != "OOB_DEV_MANIFEST_BINDING_V1" or
                binding["status"] != result.status or
                binding["scope"] != "PUBLIC_TOY_NO_GATE" or
                binding["approval_manifest_path"] != str(manifest) or
                binding["approval_manifest_sha256"] != expected_manifest_sha256 or
                binding["inner_receipt_path"] != str(inner) or
                binding["inner_receipt_sha256"] != evidence["receipt_sha256"] or
                binding["run_id"] != evidence["run_id"] or
                binding["run_id"] != inner.parent.name or
                any(binding[key] != row[key] for key in
                    ("source_path", "binary_path", "crash_input_path",
                     "normal_input_path")) or
                binding["pins"] != asdict(pins) or
                binding["approved_debugger"] != asdict(debugger) or
                binding["qualification_identity"] != "NONE" or
                binding["gate_eligible"] is not False or
                original.get("run_id") != binding["run_id"] or
                original.get("pins") != asdict(pins) or
                original.get("spec") != asdict(spec) or
                original.get("approved_debugger") != asdict(debugger) or
                original.get("source_path") != row["source_path"] or
                original.get("binary_path") != row["binary_path"] or
                original.get("crash_input_path") != row["crash_input_path"] or
                original.get("normal_input_path") != row["normal_input_path"]):
            return False
        artifacts = original.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != {
            "normal_runtime.json", "crash_runtime.json", "commands.gdb",
            "witness.json", "gdb_stdout.txt", "gdb_stderr.txt"}:
            return False
        for name, item in artifacts.items():
            path = _regular_absolute(item["path"])
            if (path != inner.parent / name or not _private_file(path) or
                    path.stat().st_size != item["size"] or
                    _digest(path) != item["sha256"]):
                return False
        return True
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _compiled_source_reaches_binary(receipt: dict[str, Any],
                                    source_key: tuple[str, str],
                                    binary_key: tuple[str, str]) -> bool:
    """Recheck one source's lineage after the product validates the full V2 receipt.

    Membership in ``compiled_sources`` alone does not prove participation in
    the final binary. This graph does not authenticate commands without the
    independent V2 review.
    """
    compiled = receipt.get("compiled_sources")
    steps = receipt.get("build_steps")
    if not isinstance(compiled, list) or not isinstance(steps, list) or not steps:
        return False

    def key(row: Any) -> tuple[str, str] | None:
        if (not isinstance(row, dict) or not isinstance(row.get("path"), str) or
                not Path(row["path"]).is_absolute() or
                not isinstance(row.get("sha256"), str) or
                not _SHA.fullmatch(row["sha256"])):
            return None
        return row["path"], row["sha256"]

    roots = [key(row) for row in compiled]
    if any(root is None for root in roots) or source_key not in roots:
        return False
    provenance = {root: frozenset({root}) for root in roots}
    pending: list[tuple[list[tuple[str, str]], list[tuple[str, str]]]] = []
    produced_paths: set[str] = set()
    for step in steps:
        if (not isinstance(step, dict) or not isinstance(step.get("inputs"), list) or
                not isinstance(step.get("outputs"), list) or
                not step["inputs"] or not step["outputs"]):
            return False
        inputs = [key(row) for row in step["inputs"]]
        outputs = [key(row) for row in step["outputs"]]
        if any(item is None for item in (*inputs, *outputs)):
            return False
        if any(path in produced_paths for path, _ in outputs):
            return False
        produced_paths.update(path for path, _ in outputs)
        pending.append((inputs, outputs))
    while pending:
        remaining = []
        for inputs, outputs in pending:
            if all(item in provenance for item in inputs):
                ancestry = frozenset(root for item in inputs
                                     for root in provenance[item])
                for item in outputs:
                    provenance[item] = ancestry
            else:
                remaining.append((inputs, outputs))
        if len(remaining) == len(pending):
            return False
        pending = remaining
    return source_key in provenance.get(binary_key, frozenset())


def validate_official_v2_source_pin(
        contract_path: Path, expected_contract_sha256: str,
        source: Path, binary: Path, normal_seed: Path,
        oss_fuzz_checkout: Path, upstream_checkout: Path) -> bool:
    """Require the genuine V2 receipt chain and one compiled source byte pin.

    This is an authority prerequisite for a future formal OOB path. The public
    toy has no such contract, so its witness remains Gate-ineligible.
    """
    try:
        if (not isinstance(expected_contract_sha256, str) or
                not _SHA.fullmatch(expected_contract_sha256)):
            return False
        contract_path = _regular_absolute(str(contract_path))
        source = _regular_absolute(str(source))
        binary = _regular_absolute(str(binary))
        normal_seed = _regular_absolute(str(normal_seed))
        if _digest(contract_path) != expected_contract_sha256:
            return False
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        if not _v2_contract_shape(contract):
            return False
        root = _regular_absolute(contract["target"]["source_root"],
                                 directory=True)
        if (not source.is_relative_to(root) or
                str(binary) != contract["local"]["binary"] or
                str(normal_seed) != contract["local"]["normal_seed"]):
            return False
        harness = _regular_absolute(contract["local"]["harness_file"])
        if validate_v2_local_pins(
                contract, source_root=root, harness=harness, binary=binary,
                normal_seed=normal_seed, oss_fuzz_checkout=oss_fuzz_checkout,
                upstream_checkout=upstream_checkout) is None:
            return False
        receipt = _regular_absolute(contract["build_receipt"]["file"])
        if _digest(receipt) != contract["build_receipt"]["sha256"]:
            return False
        receipt_row = json.loads(receipt.read_text(encoding="utf-8"))
        rows = receipt_row["compiled_sources"]
        relative = source.relative_to(root)
        source_hash = _digest(source)
        matches = []
        for row in rows:
            if (not isinstance(row, dict) or
                    set(row) != {"path", "sha256"} or
                    not isinstance(row["path"], str)):
                return False
            path = _regular_absolute(row["path"])
            if (path.is_relative_to(upstream_checkout.resolve()) and
                    path.relative_to(upstream_checkout.resolve()) == relative and
                    row["sha256"] == source_hash and _digest(path) == source_hash):
                matches.append(path)
        return (len(matches) == 1 and _compiled_source_reaches_binary(
            receipt_row, (str(matches[0]), source_hash),
            (str(binary), _digest(binary))))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False
