"""Official V2 Stage15 Assertion handoff; no Target or Provider execution.

The SHA-pinned execution contract is separate from the v24/v25 model route.
It admits one already proposed Assertion at a time, writes a crash-safe
companion receipt, and proves the HP physical runner shares the official
ledger. Build, seed probe, guided fuzz, official replay and Gate remain pending.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import uuid4

from dev_blind3_official_interleaved_adapter import (
    OfficialInterleavedAdapter, sha256,
)
from dev_product_fuzz_physical_adapter import ProductFuzzPhysicalRunner
from vulnerabilityanalysis import assertions, interleaved_assertion_dev
from vulnerabilityanalysis import interleaved_dev as base

KIND = "OFFICIAL_V2_ASSERTION_HANDOFF_DEV_V1"
STATUS = "DEV_HANDOFF_NO_TARGET_EXECUTION"
SPEC_KEYS = frozenset({
    "kind", "status", "route_sha256", "qualification_source_root",
    "qualification_harness", "qualification_harness_sha256",
    "qualification_binary", "qualification_binary_sha256",
    "qualification_seed", "qualification_seed_sha256",
    "builder_path", "builder_sha256", "manifest_path", "manifest_sha256",
    "toolchain_files_sha256", "toolchain_trees_sha256",
    "product_assertions_sha256", "product_interleaved_sha256",
    "product_handoff_validator_sha256", "handoff_adapter_sha256",
    "physical_adapter_sha256", "build_command", "run_command",
    "oracle_queries", "blind3_runs", "target_executions",
})
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _pinned_file(path_text: str, digest: str, *, private: bool = False) -> Path:
    path = Path(path_text)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            not path.is_file() or path.stat().st_nlink != 1 or
            path.resolve(strict=True) != path or sha256(path) != digest or
            private and (path.stat().st_uid != os.getuid() or
                         stat.S_IMODE(path.stat().st_mode) != 0o600)):
        raise ValueError("official Assertion execution file pin changed")
    return path


def _toolchain_pins(manifest: dict) -> None:
    files = manifest.get("toolchain_files")
    loader = manifest.get("toolchain_loader_files")
    trees = manifest.get("toolchain_trees")
    if (type(files) is not dict or not files or type(loader) is not dict or
            type(trees) is not dict or not trees):
        raise ValueError("Assertion toolchain manifest is incomplete")
    for name, digest in files.items():
        path = Path(name)
        if (not path.is_absolute() or not path.resolve(strict=True).is_file() or
                sha256(path.resolve(strict=True)) != digest):
            raise ValueError("Assertion toolchain file changed")
    for row in loader.values():
        if type(row) is not dict or set(row) != {"path", "sha256"}:
            raise ValueError("Assertion compiler loader receipt changed")
        path = Path(row["path"])
        if (not path.is_absolute() or not path.resolve(strict=True).is_file() or
                sha256(path.resolve(strict=True)) != row["sha256"]):
            raise ValueError("Assertion compiler loader changed")
    for name, expected in trees.items():
        root = Path(name)
        if (not root.is_absolute() or root.is_symlink() or not root.is_dir() or
                type(expected) is not dict or
                set(expected) != {"file_count", "sha256"}):
            raise ValueError("Assertion toolchain tree changed")
        paths = sorted(root.rglob("*"))
        if any(path.is_symlink() or not (path.is_file() or path.is_dir())
               for path in paths):
            raise ValueError("Assertion toolchain tree has unsafe entry")
        members = [path for path in paths if path.is_file()]
        digest = hashlib.sha256()
        for member in members:
            digest.update(member.relative_to(root).as_posix().encode() + b"\0")
            digest.update(bytes.fromhex(sha256(member)))
        if (len(members) != expected["file_count"] or
                digest.hexdigest() != expected["sha256"]):
            raise ValueError("Assertion compiler resources changed")


def _private_companion_json(path: Path, root: Path, value: dict,
                            *, replace: bool) -> None:
    """Write beneath a verified directory FD, without following a parent link."""
    if root not in path.parents:
        raise ValueError("Assertion companion escaped the partial run")
    if any(parent.is_symlink() for parent in (root, *root.parents)):
        raise ValueError("Assertion companion root has a linked ancestor")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                         getattr(os, "O_NOFOLLOW", 0))
    try:
        root_info = os.fstat(descriptor)
        if (root_info.st_uid != os.getuid() or
                stat.S_IMODE(root_info.st_mode) != 0o700):
            raise ValueError("Assertion companion root is unsafe")
        parts = path.relative_to(root).parts
        for part in parts[:-1]:
            if part in {"", ".", ".."}:
                raise ValueError("Assertion companion directory component changed")
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                  getattr(os, "O_NOFOLLOW", 0),
                                  dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                  getattr(os, "O_NOFOLLOW", 0),
                                  dir_fd=descriptor)
            info = os.fstat(next_fd)
            mode = stat.S_IMODE(info.st_mode)
            if (not stat.S_ISDIR(info.st_mode) or
                    info.st_uid != os.getuid() or mode & 0o022):
                os.close(next_fd)
                raise ValueError("Assertion companion directory is unsafe")
            # Older stage receipts created intermediate directories with the
            # process umask (usually 0755). Tighten owner-controlled paths
            # before writing any execution receipt beneath them.
            if mode != 0o700:
                os.fchmod(next_fd, 0o700)
                os.fsync(next_fd)
            os.close(descriptor)
            descriptor = next_fd
        name = parts[-1]
        if name not in {"ASSERTION_EXECUTION_STATE.json",
                        "ASSERTION_EXECUTION_ATTEMPT.json"}:
            raise ValueError("Assertion companion basename changed")
        try:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        if (replace and (info is None or not stat.S_ISREG(info.st_mode) or
                         info.st_nlink != 1 or info.st_uid != os.getuid() or
                         stat.S_IMODE(info.st_mode) != 0o600) or
                not replace and info is not None):
            raise ValueError("Assertion companion replacement is unsafe")
        temporary = ".ASSERTION_EXECUTION_STATE." + uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600,
                     dir_fd=descriptor)
        try:
            payload = (json.dumps(value, sort_keys=True, indent=2,
                                  allow_nan=False) + "\n").encode()
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if replace:
                os.replace(temporary, name, src_dir_fd=descriptor,
                           dst_dir_fd=descriptor)
            else:
                os.link(temporary, name, src_dir_fd=descriptor,
                        dst_dir_fd=descriptor, follow_symlinks=False)
            os.fsync(descriptor)
        finally:
            try:
                os.unlink(temporary, dir_fd=descriptor)
            except FileNotFoundError:
                pass
    finally:
        os.close(descriptor)


def load_execution_contract(path: Path, digest: str,
                            adapter: OfficialInterleavedAdapter) -> dict:
    """Validate every execution byte before admitting a handoff."""
    if type(adapter) is not OfficialInterleavedAdapter:
        raise ValueError("official interleaved adapter changed")
    raw = _pinned_file(str(path), digest, private=True)
    spec = json.loads(raw.read_text(encoding="utf-8"))
    q = adapter.qualification
    if (type(spec) is not dict or set(spec) != SPEC_KEYS or
            spec["kind"] != KIND or spec["status"] != STATUS or
            spec["oracle_queries"] != 0 or spec["blind3_runs"] != 0 or
            spec["target_executions"] != 0 or
            spec["route_sha256"] != adapter.route_sha256 or
            spec["qualification_source_root"] != str(q.source_root) or
            spec["qualification_harness"] != str(q.harness) or
            spec["qualification_harness_sha256"] != q.harness_sha256 or
            spec["qualification_binary"] != str(q.binary) or
            spec["qualification_binary_sha256"] != q.binary_sha256 or
            spec["qualification_seed"] != str(q.normal_seed) or
            spec["qualification_seed_sha256"] != q.normal_seed_sha256 or
            spec["build_command"] != [spec["builder_path"], "{source}",
                                      "-o", "{binary}"] or
            spec["run_command"] != ["{binary}", "{input}"] or
            any(type(value) is not str or HEX64.fullmatch(value) is None
                for key, value in spec.items() if key.endswith("_sha256"))):
        raise ValueError("official Assertion handoff contract changed")
    pins = (
        (spec["qualification_harness"], spec["qualification_harness_sha256"]),
        (spec["qualification_binary"], spec["qualification_binary_sha256"]),
        (spec["qualification_seed"], spec["qualification_seed_sha256"]),
        (spec["builder_path"], spec["builder_sha256"]),
        (spec["manifest_path"], spec["manifest_sha256"]),
        (str(Path(assertions.__file__).resolve()), spec["product_assertions_sha256"]),
        (str(Path(base.__file__).resolve()), spec["product_interleaved_sha256"]),
        (str(Path(interleaved_assertion_dev.__file__).resolve()),
         spec["product_handoff_validator_sha256"]),
        (str(Path(__file__).resolve()), spec["handoff_adapter_sha256"]),
        (str(Path(__file__).with_name("dev_product_fuzz_physical_adapter.py")),
         spec["physical_adapter_sha256"]),
    )
    for filename, expected in pins:
        _pinned_file(filename, expected)
    if os.environ.get("VA_ASSERTION_BUILD_MANIFEST") != spec["manifest_path"]:
        raise ValueError("Assertion builder manifest environment differs")
    manifest = json.loads(Path(spec["manifest_path"]).read_text(encoding="utf-8"))
    if (type(manifest) is not dict or
            manifest.get("builder_sha256") != spec["builder_sha256"] or
            manifest.get("official_binary") != spec["qualification_binary"] or
            manifest.get("official_binary_sha256") !=
            spec["qualification_binary_sha256"] or
            manifest.get("harness_source") != spec["qualification_harness"] or
            manifest.get("source_root") != spec["qualification_source_root"] or
            manifest.get("official_receipt") !=
            str(q.build_receipt_path) or
            manifest.get("official_receipt_sha256") !=
            q.build_receipt_sha256 or
            _canonical_sha(manifest.get("toolchain_files")) !=
            spec["toolchain_files_sha256"] or
            _canonical_sha(manifest.get("toolchain_trees")) !=
            spec["toolchain_trees_sha256"]):
        raise ValueError("Assertion builder manifest differs from qualification")
    _pinned_file(manifest["official_receipt"],
                 manifest["official_receipt_sha256"])
    source_files = manifest.get("source_files")
    if type(source_files) is not dict or not source_files:
        raise ValueError("Assertion builder source inventory is missing")
    root = Path(spec["qualification_source_root"])
    for relative, expected in source_files.items():
        member = root / relative
        if (not relative or Path(relative).is_absolute() or
                ".." in Path(relative).parts or member.is_symlink() or
                not member.is_file() or sha256(member) != expected):
            raise ValueError("Assertion builder source inventory changed")
    _toolchain_pins(manifest)
    return spec


def handoff_next_assertion(adapter: OfficialInterleavedAdapter, ordinal: int,
                           contract_path: Path, contract_sha256: str) -> Path:
    """Arm one proposal, with no model call and no physical Target call."""
    with adapter._role_lock():
        adapter._check_identity()
        spec = load_execution_contract(contract_path, contract_sha256, adapter)

        def recheck_execution_identity() -> None:
            # The manifest environment and the builder's source/toolchain
            # inputs are outside the partial-state lock. A successful entry
            # check cannot attest to their bytes at handoff completion.
            if load_execution_contract(contract_path, contract_sha256,
                                       adapter) != spec:
                raise ValueError("Assertion execution identity changed in flight")

        state = adapter.read()
        if type(ordinal) is not int or not 0 <= ordinal < len(state["work_items"]):
            raise ValueError("Assertion handoff ordinal invalid")
        item = state["work_items"][ordinal]
        if (item.get("hp_state") != "PENDING_ASSERTION_EXECUTION" or
                state.get("role_active") is not None):
            raise ValueError("Assertion handoff lacks settled HP proposal")
        receipts = [receipt for receipt in state.get("role_turns", []) if
                    receipt.get("ordinal") == ordinal and
                    receipt.get("role") == "assertion_generator"]
        if len(receipts) != 1:
            raise ValueError("Assertion handoff proposal receipt differs")
        receipt = receipts[0]
        proposal_path = Path(receipt["artifact_path"])
        proposal = json.loads(proposal_path.read_text(encoding="utf-8"))
        anchors = state.setdefault("assertion_execution_handoffs", [])
        used = {anchor["proposal_index"] for anchor in anchors if
                anchor["ordinal"] == ordinal}
        pending = [(index, row) for index, row in
                   enumerate(proposal["assertions"]) if
                   row["status"] == "PROPOSED" and index not in used]
        if not pending:
            raise ValueError("Assertion handoff has no remaining proposal")
        index, assertion = pending[0]
        # A handoff does not claim that the instrumented binary, normal seed,
        # Guided fuzzer, or official original replay has run.
        runner = ProductFuzzPhysicalRunner(adapter.physical_ledger, kind="HP")
        if (runner.ledger is not adapter.physical_ledger or runner.kind != "HP" or
                runner.ledger.path != Path(adapter.spec["physical_ledger_path"])):
            raise ValueError("Assertion handoff physical ledger split")
        physical_before = sha256(adapter.physical_ledger.path)
        scope = item["work_item_id"]
        adapter._write_role_guard("assertion_execution_handoff", ordinal,
                                  scope, "PENDING", assertion["assertion_id"])
        guard_id = adapter._active_guard[3]
        companion_path = (adapter.state_path.parent / "work_items" /
                          f"{ordinal:06d}-{scope}" / "assertion_execution" /
                          f"{index:06d}" / "ASSERTION_EXECUTION_STATE.json")
        anchor = {
            "kind": interleaved_assertion_dev.ANCHOR_KIND,
            "ordinal": ordinal, "work_item_id": scope,
            "assertion_id": assertion["assertion_id"], "proposal_index": index,
            "proposal_path": str(proposal_path),
            "proposal_sha256": receipt["artifact_sha256"],
            "contract_path": str(contract_path),
            "contract_sha256": contract_sha256,
            "physical_ledger_path": str(adapter.physical_ledger.path),
            "companion_path": str(companion_path), "companion_sha256": None,
            "guard_id": guard_id, "status": "ARMED",
        }
        try:
            anchors.append(anchor)
            base._private_json(adapter.state_path, state, replace=True)
            companion = {
                "kind": interleaved_assertion_dev.COMPANION_KIND,
                "guard_id": guard_id, "status": "ARMED",
                "ordinal": ordinal, "work_item_id": scope,
                "assertion_id": assertion["assertion_id"],
                "proposal_index": index,
                "proposal_sha256": receipt["artifact_sha256"],
                "contract_sha256": contract_sha256,
                "execution_count": 0, "guided_fuzz_seconds": 0,
                "official_replay_count": 0,
                "physical_ledger_path": str(adapter.physical_ledger.path),
                "physical_ledger_sha256": physical_before,
            }
            _private_companion_json(companion_path, adapter.state_path.parent,
                                    companion, replace=False)
            recheck_execution_identity()
            companion["status"] = "EXECUTION_HANDOFF_READY"
            _private_companion_json(companion_path, adapter.state_path.parent,
                                    companion, replace=True)
            anchor["status"] = "EXECUTION_HANDOFF_READY"
            anchor["companion_sha256"] = sha256(companion_path)
            base._private_json(adapter.state_path, state, replace=True)
            if sha256(adapter.physical_ledger.path) != physical_before:
                raise ValueError("Assertion handoff unexpectedly spent physical budget")
            adapter._check_identity(allow_pending_guard=True)
            recheck_execution_identity()
            adapter._write_role_guard("assertion_execution_handoff", ordinal,
                                      scope, "VALIDATED_COMPLETE",
                                      assertion["assertion_id"])
            return companion_path
        except BaseException as original:
            # A pending ROLE_GUARD and/or write-ahead anchor blocks all resume.
            try:
                adapter._record_pin_failure("assertion_execution_handoff",
                                            ordinal, original)
            except BaseException as marker_error:
                original.add_note("Assertion handoff stop marker failed: " +
                                  type(marker_error).__name__)
            raise
