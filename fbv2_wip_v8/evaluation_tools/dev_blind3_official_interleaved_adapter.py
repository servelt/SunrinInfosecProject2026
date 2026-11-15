"""Official V2 identity boundary for the development interleaved role queue.

This module does not authorize a Blind 3 run. It joins a qualified Phase 1
worklist to one partial state, one request ledger and one App Server bridge.
A pending role guard prohibits resume after process death or failed cleanup.
This development boundary does not complete Assertion, Runtime, Gate or Scan.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from dataclasses import asdict, fields
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any
from uuid import uuid4

from dev_global_appserver_bridge import DevelopmentGlobalAppServer
from dev_global_request_ledger import (
    DevelopmentBudget, DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE,
)
from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
from vulnerabilityanalysis.interleaved_dev import (
    _pinned_harness, create_interleaved_dev, generate_sp_stage,
    read_interleaved_dev,
)
from vulnerabilityanalysis.interleaved_roles_dev import (
    run_assertion_generation_stage, run_hp_context_stage,
    run_hp_first_stage, run_hp_followup_stage, run_pov_stage,
    run_sp_verifier_stage,
)
from vulnerabilityanalysis.official_harness import (
    OfficialPinnedQualification, _qualification_pins_ok,
)
from vulnerabilityanalysis.llm import CodexAppServerClient
from vulnerabilityanalysis.source import SourceRepository

KIND = "OFFICIAL_V2_INTERLEAVED_DEV_ROUTE_V1"
STATUS = "DEV_PUBLIC_V2_NOT_READY"
SPEC_KEYS = frozenset({
    "kind", "status", "source_run", "worklist_path", "worklist_sha256",
    "output_dir", "target_repository", "qualification", "role_models",
    "default_model", "default_effort", "code_sha256", "config_path",
    "config_sha256", "codex_executable", "codex_executable_sha256",
    "sandbox_launcher", "sandbox_launcher_sha256", "python_executable",
    "python_executable_sha256", "model_cwd", "event_log_path",
    "codex_home",
    "model_ledger_path", "physical_ledger_path", "physical_resource_seconds",
    "model_budget", "role_route_sha256", "workspace_route_sha256",
    "allow_synthetic_wire",
    "oracle_queries", "blind3_runs",
})
REQUIRED_ROLES = frozenset({
    "sp_generation", "sp_verifier", "poc_generator",
    "function_analysis", "assertion_generator",
})
CODE_FILES = {
    "adapter": Path(__file__).resolve(),
    "runner": Path(__file__).with_name("dev_blind3_official_interleaved_runner.py"),
    "product_interleaved": Path(__import__(
        "vulnerabilityanalysis.interleaved_dev", fromlist=["__file__"]).__file__).resolve(),
    "product_roles": Path(__import__(
        "vulnerabilityanalysis.interleaved_roles_dev", fromlist=["__file__"]).__file__).resolve(),
    "product_agents": Path(__import__(
        "vulnerabilityanalysis.agents", fromlist=["__file__"]).__file__).resolve(),
    "product_context": Path(__import__(
        "vulnerabilityanalysis.context", fromlist=["__file__"]).__file__).resolve(),
    "product_scan": Path(__import__(
        "vulnerabilityanalysis.scan", fromlist=["__file__"]).__file__).resolve(),
    "product_assertions": Path(__import__(
        "vulnerabilityanalysis.assertions", fromlist=["__file__"]).__file__).resolve(),
    "product_llm": Path(__import__(
        "vulnerabilityanalysis.llm", fromlist=["__file__"]).__file__).resolve(),
    "product_qualification": Path(__import__(
        "vulnerabilityanalysis.official_harness", fromlist=["__file__"]).__file__).resolve(),
    "product_source": Path(__import__(
        "vulnerabilityanalysis.source", fromlist=["__file__"]).__file__).resolve(),
    "appserver_bridge": Path(__import__(
        "dev_global_appserver_bridge", fromlist=["__file__"]).__file__).resolve(),
    "model_ledger": Path(__import__(
        "dev_global_request_ledger", fromlist=["__file__"]).__file__).resolve(),
    "physical_ledger": Path(__import__(
        "dev_persistent_physical_fuzz_ledger", fromlist=["__file__"]).__file__).resolve(),
    "route_guard": Path(__file__).with_name("blind2_runner_draft.py"),
}
QUALIFICATION_PATHS = (
    "source_root", "harness", "binary", "normal_seed", "contract_path",
    "review_artifact", "build_receipt_path", "oss_fuzz_checkout",
    "upstream_checkout",
)
QUALIFICATION_HASHES = (
    "source_tree_sha256", "harness_sha256", "binary_sha256",
    "normal_seed_sha256", "contract_sha256", "review_sha256",
    "build_receipt_sha256",
)


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _file(path_text: str, digest: str) -> Path:
    path = Path(path_text)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            not path.is_file() or path.resolve(strict=True) != path or
            path.stat().st_nlink != 1 or sha256(path) != digest):
        raise ValueError(f"official interleaved file pin changed: {path}")
    return path


def _dir(path_text: str, *, private: bool = False) -> Path:
    path = Path(path_text)
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            not path.is_dir() or path.resolve(strict=True) != path or
            private and stat.S_IMODE(path.stat().st_mode) != 0o700):
        raise ValueError(f"official interleaved directory changed: {path}")
    return path


def load_route_spec(path: Path, expected_sha256: str) -> dict[str, Any]:
    """Load an externally SHA-pinned route; reject synthetic-wire settings."""
    if (not path.is_absolute() or path.is_symlink() or
            any(parent.is_symlink() for parent in path.parents) or
            path.resolve(strict=True) != path):
        raise ValueError("official interleaved route path changed")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("official interleaved route is not a single regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read()
    finally:
        os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("official interleaved route SHA changed")
    row = json.loads(raw)
    if (type(row) is not dict or set(row) != SPEC_KEYS or
            row["kind"] != KIND or row["status"] != STATUS or
            row["allow_synthetic_wire"] is not False or
            row["oracle_queries"] != 0 or row["blind3_runs"] != 0 or
            type(row["physical_resource_seconds"]) not in (int, float) or
            not math.isfinite(row["physical_resource_seconds"]) or
            row["physical_resource_seconds"] <= 0 or
            type(row["role_models"]) is not dict or
            set(row["role_models"]) != REQUIRED_ROLES or
            not all(type(route) is dict and set(route) == {"model", "reasoning"}
                    and all(type(value) is str and value for value in route.values())
                    for route in row["role_models"].values()) or
            type(row["code_sha256"]) is not dict or
            set(row["code_sha256"]) != set(CODE_FILES) or
            row["role_route_sha256"] != hashlib.sha256(json.dumps(
                row["role_models"], sort_keys=True, separators=(",", ":")
            ).encode()).hexdigest() or
            type(row["workspace_route_sha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", row["workspace_route_sha256"]) is None or
            type(row["default_model"]) is not str or
            type(row["default_effort"]) is not str or
            type(row["model_budget"]) is not dict or
            set(row["model_budget"]) != {field.name for field in fields(DevelopmentBudget)}):
        raise ValueError("official interleaved route schema changed")
    budget = DevelopmentBudget(**row["model_budget"])
    if budget.profile != GLOBAL_ONLY_DEV_PROFILE:
        raise ValueError("official interleaved route requires global-only ledger")
    for name, code_path in CODE_FILES.items():
        _file(str(code_path), row["code_sha256"][name])
    _file(row["config_path"], row["config_sha256"])
    from blind2_runner_draft import check_zero_retry_config
    check_zero_retry_config(Path(row["config_path"]), row["default_model"],
                            row["default_effort"])
    _file(row["codex_executable"], row["codex_executable_sha256"])
    _file(row["sandbox_launcher"], row["sandbox_launcher_sha256"])
    _file(row["python_executable"], row["python_executable_sha256"])
    if (Path(sys.executable).resolve() != Path(row["python_executable"]) or
            sys.flags.isolated != 1):
        raise ValueError("official interleaved interpreter is not pinned isolated Python")
    codex_home = _dir(row["codex_home"], private=True)
    if os.environ.get("CODEX_HOME") != str(codex_home):
        raise ValueError("official interleaved Codex home changed")
    config_copy = _file(str(codex_home / "config.toml"), row["config_sha256"])
    auth = codex_home / "auth.json"
    if (stat.S_IMODE(config_copy.stat().st_mode) != 0o600 or
            auth.is_symlink() or not auth.is_file() or
            stat.S_IMODE(auth.stat().st_mode) != 0o600 or
            auth.stat().st_nlink != 1):
        raise ValueError("official interleaved Codex credentials unavailable")
    _file(row["worklist_path"], row["worklist_sha256"])
    _dir(row["source_run"])
    _dir(row["target_repository"])
    _dir(row["output_dir"], private=True)
    _dir(row["model_cwd"], private=True)
    for name in ("event_log_path", "model_ledger_path", "physical_ledger_path"):
        file = Path(row[name])
        if (not file.is_absolute() or file.is_symlink() or
                any(parent.is_symlink() for parent in file.parents) or
                file.resolve(strict=False) != file or
                file.parent != Path(row["output_dir"])):
            raise ValueError("official interleaved output path changed")
    return row


def _qualified(spec: dict[str, Any], q: OfficialPinnedQualification) -> None:
    if (type(q) is not OfficialPinnedQualification or not q.product_issued or
            q.contract_kind != "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2" or
            not _qualification_pins_ok(q) or
            type(spec["qualification"]) is not dict or
            set(spec["qualification"]) !=
            set(QUALIFICATION_PATHS) | set(QUALIFICATION_HASHES) |
            {"contract_kind", "reviewer_id", "upstream_revision", "oss_fuzz_revision"}):
        raise ValueError("product-issued official V2 qualification changed")
    expected = spec["qualification"]
    for name in QUALIFICATION_PATHS:
        value = getattr(q, name)
        if value is None or str(Path(value).resolve(strict=True)) != expected[name]:
            raise ValueError(f"official qualification path changed: {name}")
    for name in QUALIFICATION_HASHES:
        if getattr(q, name) != expected[name]:
            raise ValueError(f"official qualification hash changed: {name}")
    for name in ("contract_kind", "reviewer_id", "upstream_revision", "oss_fuzz_revision"):
        if getattr(q, name) != expected[name]:
            raise ValueError(f"official qualification field changed: {name}")
    if (spec["target_repository"] != str(q.source_root.resolve(strict=True)) or
            q.binary is None):
        raise ValueError("official target binary or source root missing")


class OfficialInterleavedAdapter:
    """One in-memory owner of the qualified partial queue and both ledgers."""

    def __init__(self, *, route_spec: Path, route_sha256: str,
                 qualification: OfficialPinnedQualification,
                 ledger: DevelopmentRequestLedger,
                 physical_ledger: PersistentPhysicalFuzzLedger,
                 backend: DevelopmentGlobalAppServer):
        self.route_spec = Path(route_spec)
        self.route_sha256 = route_sha256
        self.spec = load_route_spec(self.route_spec, route_sha256)
        self.qualification = qualification
        self.ledger = ledger
        self.physical_ledger = physical_ledger
        self.backend = backend
        self.state_path = Path(self.spec["output_dir"]) / "partial_work" / "WORK_ITEM_STATE.json"
        self._blocked = False
        self._active_guard: tuple[str, int, str, str, str | None] | None = None
        if backend.retry_route_check is not None:
            raise ValueError("official retry route callback was preinstalled")
        backend.retry_route_check = self._retry_route_check
        self._check_identity()

    async def _retry_route_check(self) -> None:
        self._check_identity(allow_pending_guard=True)
        from blind2_runner_draft import check_live_route
        await check_live_route(self.backend, self.spec["workspace_route_sha256"],
                               self.spec["role_models"])

    def _check_identity(self, *, allow_pending_guard: bool = False) -> None:
        if self._blocked or (self.state_path.parent / "OFFICIAL_PIN_FAILURE.json").exists():
            raise ValueError("official interleaved post-role pin failure blocks continuation")
        guard = self.state_path.parent / "ROLE_GUARD.json"
        if guard.exists() or guard.is_symlink():
            if (guard.is_symlink() or not guard.is_file() or
                    guard.stat().st_nlink != 1 or
                    stat.S_IMODE(guard.stat().st_mode) != 0o600):
                raise ValueError("official role guard is unsafe")
            guard_row = json.loads(guard.read_text(encoding="utf-8"))
            if (type(guard_row) is not dict or
                    set(guard_row) != {"kind", "route_sha256", "role", "ordinal",
                                       "work_item_id", "sp_id", "status", "nonce",
                                       "state_sha256", "ledger_sha256",
                                       "ledger_logical", "ledger_physical"} or
                    guard_row["kind"] != "OFFICIAL_V2_ROLE_GUARD_V1" or
                    guard_row.get("route_sha256") != self.route_sha256 or
                    guard_row.get("status") not in {
                        "PENDING", "VALIDATED_COMPLETE", "VALIDATED_INCOMPLETE"} or
                    guard_row["status"] == "PENDING" and (
                        not allow_pending_guard or self._active_guard != (
                            guard_row.get("role"), guard_row.get("ordinal"),
                            guard_row.get("work_item_id"), guard_row.get("nonce"),
                            guard_row.get("sp_id"))) or
                    guard_row["status"] != "PENDING" and (
                        guard_row["state_sha256"] != sha256(self.state_path) or
                        guard_row["ledger_sha256"] !=
                        sha256(self.ledger.checkpoint_path) or
                        guard_row["ledger_logical"] != self.ledger.logical or
                        guard_row["ledger_physical"] != self.ledger.physical)):
                raise ValueError("official role guard is pending or changed")
        spec = load_route_spec(self.route_spec, self.route_sha256)
        if spec != self.spec:
            raise ValueError("official interleaved route changed")
        _qualified(spec, self.qualification)
        bridge = DevelopmentGlobalAppServer
        backend = self.backend
        if (type(self.ledger) is not DevelopmentRequestLedger or
                type(self.physical_ledger) is not PersistentPhysicalFuzzLedger or
                type(backend) is not bridge):
            raise ValueError("official App Server or ledger class changed")
        self.ledger._validate()
        self.physical_ledger._verify_checkpoint_current()
        if (asdict(self.ledger.budget) != spec["model_budget"] or
                self.physical_ledger.snapshot()["total_seconds"] !=
                float(spec["physical_resource_seconds"]) or
                sha256(self.ledger.checkpoint_path) !=
                getattr(self.ledger, "_checkpoint_sha256", None) or
                backend.ledger is not self.ledger or
                backend.physical_ledger is not self.physical_ledger or
                backend.role_models != spec["role_models"] or
                getattr(backend.retry_route_check, "__self__", None) is not self or
                getattr(backend.retry_route_check, "__func__", None) is not
                OfficialInterleavedAdapter._retry_route_check or
                "_transport_request" in vars(backend) or
                backend._transport_request.__func__ is not bridge._transport_request or
                CodexAppServerClient._request.__module__ != "vulnerabilityanalysis.llm" or
                CodexAppServerClient._request.__qualname__ !=
                "CodexAppServerClient._request" or
                backend._request.__func__ is not bridge._request or
                backend.generate.__func__ is not bridge.generate or
                backend.model != spec["default_model"] or
                backend.effort != spec["default_effort"] or
                backend.timeout_seconds != 300 or
                backend.executable != spec["codex_executable"] or
                backend.executable_sha256 != spec["codex_executable_sha256"] or
                backend.launch_prefix !=
                (spec["python_executable"], spec["sandbox_launcher"]) or
                backend.wire_cwd != "/work" or
                backend.cwd != Path(spec["model_cwd"]) or
                backend.event_log_path != Path(spec["event_log_path"]) or
                self.ledger.checkpoint_path != Path(spec["model_ledger_path"]) or
                self.physical_ledger.path != Path(spec["physical_ledger_path"]) or
                backend.forbidden_tool_event or backend.audit_log_failed):
            raise ValueError("official App Server, ledger or sandbox route changed")
        if self.state_path.exists():
            state = read_interleaved_dev(self.state_path)
            if (state["source_run"] != spec["source_run"] or
                    state["worklist_path"] != spec["worklist_path"] or
                    state["worklist_sha256"] != spec["worklist_sha256"] or
                    state["target_repository"] != spec["target_repository"] or
                    state["scan_count"] != 0 or
                    state["completed_work_items"] != 0):
                raise ValueError("official interleaved state identity changed")
            selected = [item["work_item_id"] for item in
                        state["work_items"][:state["next_sp_ordinal"]]]
            current_ordinal = state["next_sp_ordinal"]
            if current_ordinal < len(state["work_items"]):
                current = state["work_items"][current_ordinal]
                if current["state"] in {
                    "SP_REQUEST_ARMED", "INCOMPLETE_UNCERTAIN_MODEL_TURN",
                    "INCOMPLETE_PRODUCT_RESPONSE", "INCOMPLETE_LOCAL_POSTPROCESS",
                }:
                    selected.append(current["work_item_id"])
            if self.ledger.selected_functions != selected:
                raise ValueError("official interleaved ledger worklist changed")
            harness = _pinned_harness(state, Path(state["source_run"]),
                                      self.qualification.source_root)
            repository = SourceRepository(self.qualification.source_root,
                                          harness.function_catalog)
            spans = {}
            for item in state["work_items"]:
                function_id = item["function_id"]
                if function_id not in spans:
                    span = repository.open_function_span(function_id)
                    spans[function_id] = (span.source_file_sha256,
                                          span.source_sha256)
                if spans[function_id] != (item["source_file_sha256"],
                                          item["source_span_sha256"]):
                    raise ValueError("official pending SourceSpan identity changed")

    def prepare(self) -> Path:
        """Admit exactly the pinned Phase 1 worklist, without model or Target."""
        self._check_identity()
        if self.state_path.exists() or self.state_path.is_symlink():
            raise ValueError("official interleaved state already exists")
        state = create_interleaved_dev(
            Path(self.spec["source_run"]), Path(self.spec["worklist_path"]),
            self.spec["worklist_sha256"], self.state_path.parent,
            target_repository=Path(self.spec["target_repository"]))
        self.state_path = state
        self._check_identity()
        return state

    def read(self) -> dict[str, Any]:
        self._check_identity()
        return read_interleaved_dev(self.state_path)

    def _write_role_guard(self, role: str, ordinal: int, scope: str,
                          status: str, sp_id: str | None = None) -> None:
        guard = self.state_path.parent / "ROLE_GUARD.json"
        temporary = guard.with_name(".ROLE_GUARD." + uuid4().hex)
        if status == "PENDING":
            nonce = uuid4().hex
        else:
            active = self._active_guard
            if active is None or active[:3] != (role, ordinal, scope) or active[4] != sp_id:
                raise ValueError("official role guard owner changed")
            nonce = active[3]
        row = {"kind": "OFFICIAL_V2_ROLE_GUARD_V1",
               "route_sha256": self.route_sha256, "role": role,
               "ordinal": ordinal, "work_item_id": scope, "sp_id": sp_id,
               "status": status, "nonce": nonce,
               "state_sha256": sha256(self.state_path),
               "ledger_sha256": sha256(self.ledger.checkpoint_path),
               "ledger_logical": self.ledger.logical,
               "ledger_physical": self.ledger.physical}
        data = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, guard)
            directory = os.open(guard.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self._active_guard = ((role, ordinal, scope, nonce, sp_id)
                                  if status == "PENDING" else None)
        finally:
            temporary.unlink(missing_ok=True)

    def _record_pin_failure(self, role: str, ordinal: int,
                            failure: BaseException) -> None:
        self._blocked = True
        marker = self.state_path.parent / "OFFICIAL_PIN_FAILURE.json"
        row = {"kind": "OFFICIAL_V2_POST_ROLE_PIN_FAILURE_V1",
               "route_sha256": self.route_sha256, "role": role,
               "ordinal": ordinal, "error_type": type(failure).__name__,
               "reason_code": ("STATE_LEDGER_MISMATCH" if
                   "ledger worklist changed" in str(failure) else
                   "PIN_OR_AUDIT_DRIFT")}
        data = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @contextmanager
    def _role_lock(self):
        path = self.state_path.parent / "OFFICIAL_ROLE.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT |
                             getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError("official role lock is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("another official role is active") from exc
            current = path.lstat()
            if (not stat.S_ISREG(current.st_mode) or
                    (current.st_dev, current.st_ino) !=
                    (info.st_dev, info.st_ino)):
                raise ValueError("official role lock inode changed")
            yield
        finally:
            os.close(descriptor)

    async def _role(self, role: str, ordinal: int, sp_id: str | None = None) -> Path:
        with self._role_lock():
            return await self._role_locked(role, ordinal, sp_id)

    async def _role_locked(self, role: str, ordinal: int,
                           sp_id: str | None = None) -> Path:
        self._check_identity()
        state = self.read()
        if type(ordinal) is not int or not 0 <= ordinal < len(state["work_items"]):
            raise ValueError("official work item ordinal invalid")
        scope = state["work_items"][ordinal]["work_item_id"]
        if self.backend.scope_id is not None:
            raise ValueError("official App Server scope is already bound")
        if role not in {"sp_generation", "function_analysis", "hp_context_resolution",
                        "hp_followup", "assertion_generator", "sp_verifier",
                        "poc_generator"} or role in {
                            "sp_verifier", "poc_generator"} and not sp_id:
            raise ValueError("unsupported official role or missing candidate")
        self._write_role_guard(role, ordinal, scope, "PENDING", sp_id)
        self.backend.bind_scope(scope)
        original: BaseException | None = None
        try:
            kwargs = dict(target_repository=self.qualification.source_root,
                          role_models=self.spec["role_models"],
                          accounting_owner="APP_SERVER_TURN_START_V1",
                          bridge_source_sha256=self.spec["code_sha256"]["appserver_bridge"])
            if role == "sp_generation":
                return await generate_sp_stage(
                    self.state_path, ordinal, self.backend, self.ledger,
                    target_binary=self.qualification.binary, **kwargs)
            if role == "function_analysis":
                return await run_hp_first_stage(
                    self.state_path, ordinal, self.backend, self.ledger, **kwargs)
            if role == "hp_context_resolution":
                return run_hp_context_stage(
                    self.state_path, ordinal, self.backend, self.ledger, **kwargs)
            if role == "hp_followup":
                return await run_hp_followup_stage(
                    self.state_path, ordinal, self.backend, self.ledger, **kwargs)
            if role == "assertion_generator":
                return await run_assertion_generation_stage(
                    self.state_path, ordinal, self.backend, self.ledger, **kwargs)
            if role == "sp_verifier" and sp_id is not None:
                return await run_sp_verifier_stage(
                    self.state_path, ordinal, sp_id, self.backend, self.ledger,
                    **kwargs)
            if role == "poc_generator" and sp_id is not None:
                return await run_pov_stage(
                    self.state_path, ordinal, sp_id, self.backend, self.ledger,
                    **kwargs)
            raise ValueError("unsupported official role or missing candidate")
        except BaseException as exc:
            original = exc
            raise
        finally:
            cleanup_error: BaseException | None = None
            try:
                self.backend.unbind_scope()
            except BaseException as exc:
                cleanup_error = exc
            if cleanup_error is None:
                try:
                    self._check_identity(allow_pending_guard=True)
                    self._write_role_guard(
                        role, ordinal, scope,
                        "VALIDATED_INCOMPLETE" if original is not None else
                        "VALIDATED_COMPLETE", sp_id)
                except BaseException as exc:
                    cleanup_error = exc
            if cleanup_error is not None:
                try:
                    self._record_pin_failure(role, ordinal, cleanup_error)
                except BaseException as marker_error:
                    cleanup_error.add_note("pin-failure marker failed: " +
                                           type(marker_error).__name__)
                    if original is not None:
                        original.add_note("pin-failure marker failed; supervisor "
                                          "must prohibit resume: " +
                                          type(marker_error).__name__)
                if original is None:
                    raise cleanup_error
                original.add_note("post-role identity check failed: " +
                                  type(cleanup_error).__name__)

    async def sp(self, ordinal: int) -> Path:
        return await self._role("sp_generation", ordinal)

    async def hp(self, ordinal: int) -> Path:
        return await self._role("function_analysis", ordinal)

    async def hp_context(self, ordinal: int) -> Path:
        return await self._role("hp_context_resolution", ordinal)

    async def hp_followup(self, ordinal: int) -> Path:
        return await self._role("hp_followup", ordinal)

    async def assertions(self, ordinal: int) -> Path:
        return await self._role("assertion_generator", ordinal)

    async def verifier(self, ordinal: int, sp_id: str) -> Path:
        return await self._role("sp_verifier", ordinal, sp_id)

    async def pov(self, ordinal: int, sp_id: str) -> Path:
        return await self._role("poc_generator", ordinal, sp_id)
