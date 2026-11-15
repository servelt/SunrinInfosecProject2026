"""Explicit, signed public-development HP extension after the original Worker.

The original FBv2 result is immutable here. HP uses its campaign model gate,
has a separate one-shot run claim and result receipt, and never grants Gate or
automatic-discovery credit. Import this module only after the live entry pins
the engine, product, evaluation code and HP prompt assets.
"""

from __future__ import annotations

import asyncio
import base64
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

from devtools.original_hp_post_worker import (
    _current_direction_ids, _preflight, _private_directory, _settled_model,
    run_post_worker_hp)


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HP_ASSETS = {
    "function_analysis_prompt_sha256": Path("prompts/function_analysis.md"),
    "assertion_generator_prompt_sha256": Path("prompts/assertion_generator.md"),
    "config_sha256": Path("config/default.yaml"),
}
_HP_RESULT = "HP_PUBLIC_DEV_RESULT.json"
_ASSUMPTION_LIFECYCLE_CONTRACT = "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5"
_ASSUMPTION_LIFECYCLE_APPROVAL = (
    "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_APPROVAL_V2")
_ASSUMPTION_LIFECYCLE_SCOPE = (
    "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_SCOPE_V2")
_ASSUMPTION_LIFECYCLE_ADMISSION = (
    "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_ADMISSION_V2")
_ASSUMPTION_LIFECYCLE_SIGNATURE = "ED25519_CANONICAL_JSON_V1"
# A signed spec cannot nominate its own trust anchor. Public keys enter this
# set only through a separately reviewed source change; private keys never
# enter the agent workspace or execution contract.
_TRUSTED_HUMAN_APPROVAL_PUBLIC_KEY_SHA256 = frozenset({
    "8d68a3290a43e29ad4834269d1a9843ac9fac0fdc617910780c278f557b852c5",
})
_HP_PHYSICAL_FIELDS = frozenset({
    "enabled", "builder_path", "builder_sha256", "manifest_path",
    "manifest_sha256", "guided_seconds", "total_wall_seconds",
    "output_limit_bytes",
})
_TRUSTED_MD4C_BUILDER = Path(
    "/home/dawne/SunrinInfosecProject2026/reference/"
    "blind2_v2_preparation_20261027/tools/multi_tu_assertion_build.py")
_TRUSTED_MD4C_BUILDER_SHA256 = (
    "fbe9616f102d76205bb6d20b49c225f7043f5393d675c6387ea965d423139ffc")
_TRUSTED_MD4C_MANIFEST_SHA256 = (
    "200d5248f835e3942dcd853934d309949b9b73354cb64956ca15cf5750539dd1")
_TRUSTED_CJSON_BUILDER = Path(
    "/home/dawne/SunrinInfosecProject2026/reference/"
    "hp_cjson_official_qualification_toctou_v2_20261108/"
    "cjson_assertion_build.py")
_TRUSTED_CJSON_BUILDER_SHA256 = (
    "6e6f22fd6e70197e2ee6773c564af8c742e1db8fba1e8c9f272cf988baddd3f4")
_TRUSTED_CJSON_MANIFEST_SHA256 = (
    "c5ed78a9a37b438bcb501f8698e959a888486fe9572825b6d5ebc49f562a44dc")


def _trusted_hp_physical_pair(builder: Path, builder_sha256: object,
                              manifest: Path,
                              manifest_sha256: object) -> bool:
    """Recognize exact reviewed build recipes; never trust self-signed input."""
    recipes = (
        (_TRUSTED_MD4C_BUILDER, _TRUSTED_MD4C_BUILDER_SHA256,
         "multi_tu_assertion_build_manifest.json",
         _TRUSTED_MD4C_MANIFEST_SHA256),
        (_TRUSTED_CJSON_BUILDER, _TRUSTED_CJSON_BUILDER_SHA256,
         "cjson_assertion_build_manifest.json",
         _TRUSTED_CJSON_MANIFEST_SHA256),
    )
    return any(
        builder == expected_builder and
        builder_sha256 == expected_builder_sha and
        manifest == expected_builder.with_name(expected_manifest_name) and
        manifest_sha256 == expected_manifest_sha
        for (expected_builder, expected_builder_sha, expected_manifest_name,
             expected_manifest_sha) in recipes)


def _validate_hp_physical_spec(physical: Any) -> None:
    """Pin one reviewed target recipe; this is not generic build approval."""
    if physical is None:
        return
    if (type(physical) is not dict or set(physical) != _HP_PHYSICAL_FIELDS or
            physical.get("enabled") is not True or
            type(physical.get("guided_seconds")) is not int or
            not 1 <= physical["guided_seconds"] <= 10 or
            type(physical.get("total_wall_seconds")) is not int or
            not 60 <= physical["total_wall_seconds"] <= 180 or
            type(physical.get("output_limit_bytes")) is not int or
            not 1 <= physical["output_limit_bytes"] <= 4_000_000):
        raise ValueError("signed HP physical cap is invalid")
    for name, digest_name in (("builder_path", "builder_sha256"),
                              ("manifest_path", "manifest_sha256")):
        path = Path(physical[name]) if type(physical.get(name)) is str else None
        digest = physical.get(digest_name)
        if (path is None or not path.is_absolute() or path.is_symlink() or
                not path.is_file() or path != path.resolve(strict=True) or
                type(digest) is not str or not _SHA.fullmatch(digest) or
                hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError("signed HP physical recipe pin changed")
    builder = Path(physical["builder_path"])
    manifest = Path(physical["manifest_path"])
    if not _trusted_hp_physical_pair(
            builder, physical["builder_sha256"], manifest,
            physical["manifest_sha256"]):
        raise ValueError("signed HP physical builder is not trusted")


def hp_asset_hashes(product_src: Path) -> dict[str, str]:
    """Read fixed product asset paths; a spec cannot select other files."""
    root = Path(product_src).parent
    if (not root.is_absolute() or root.is_symlink() or
            root != root.resolve(strict=True) or not root.is_dir()):
        raise ValueError("HP product root is not canonical")
    values: dict[str, str] = {}
    for key, relative in _HP_ASSETS.items():
        path = root / relative
        if (path.is_symlink() or not path.is_file() or
                path != path.resolve(strict=True) or root not in path.parents):
            raise ValueError("HP prompt/config path is unavailable")
        values[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def validate_hp_spec(hp: Any, product_src: Path, *, enabled: bool,
                     hp_only: bool = False,
                     bounded_nohint_hp: bool = False) -> None:
    """Require an exact opt-in contract before runtime import or any HP turn."""
    if not enabled:
        if hp is not None and hp != {"enabled": False}:
            raise ValueError("ordinary public development cannot enable HP")
        return
    if (type(hp) is not dict or set(hp) not in (
            {"enabled", "max_items", "max_model_calls", "assets"},
            {"enabled", "max_items", "max_model_calls", "assets", "physical"}) or
            hp["enabled"] is not True or hp["max_items"] != 1 or
            type(hp["max_items"]) is not int or
            hp["max_model_calls"] not in (
                (5,) if bounded_nohint_hp else
                (4, 5) if hp_only else (3,)) or
            type(hp["max_model_calls"]) is not int or
            type(hp["assets"]) is not dict or
            set(hp["assets"]) != set(_HP_ASSETS) or
            any(type(value) is not str or not _SHA.fullmatch(value)
                for value in hp["assets"].values())):
        raise ValueError("signed HP opt-in or cap is invalid")
    if hp_asset_hashes(product_src) != hp["assets"]:
        raise ValueError("HP prompt/config SHA-256 changed")
    _validate_hp_physical_spec(hp.get("physical"))


def _check_signed_spec(path: Path, expected_sha256: str) -> bytes:
    if (type(expected_sha256) is not str or
            not _SHA.fullmatch(expected_sha256) or
            not path.is_absolute() or path.is_symlink() or
            path != path.resolve(strict=True) or not path.is_file()):
        raise ValueError("HP signed public-development spec changed")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("HP signed public-development spec changed")
    return raw


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")


def _canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _signed_spec_subject_sha256(spec: Any) -> str:
    """Hash a spec while excluding only its circular approval reference."""
    if type(spec) is not dict:
        raise ValueError("HP assumption lifecycle signed spec is malformed")
    normalized = deepcopy(spec)
    control = normalized.get("hp_only")
    closure = (control.get("assumption_evidence_closure")
               if type(control) is dict else None)
    if type(closure) is not dict:
        raise ValueError("HP assumption lifecycle signed spec is incomplete")
    closure["approval_path"] = "<HUMAN_APPROVAL_PATH>"
    closure["approval_sha256"] = "<HUMAN_APPROVAL_SHA256>"
    return _canonical_json_sha256(normalized)


def _verify_assumption_lifecycle_human_signature(
        approval: Any, *, public_key_path: Path,
        public_key_sha256: str) -> bool:
    """Authenticate the approval issuer with a separately pinned public key."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)

        if (type(approval) is not dict or set(approval) != {
                "kind", "status", "decision", "reviewer_id", "reviewed_at",
                "scope", "signature"}):
            return False
        signature = approval.get("signature")
        if (type(signature) is not dict or set(signature) != {
                "kind", "key_id", "value_base64"} or
                signature.get("kind") != _ASSUMPTION_LIFECYCLE_SIGNATURE or
                signature.get("key_id") != public_key_sha256 or
                public_key_sha256 not in
                    _TRUSTED_HUMAN_APPROVAL_PUBLIC_KEY_SHA256 or
                type(signature.get("value_base64")) is not str):
            return False
        raw_key = public_key_path.read_bytes()
        if hashlib.sha256(raw_key).hexdigest() != public_key_sha256:
            return False
        key = serialization.load_pem_public_key(raw_key)
        if not isinstance(key, Ed25519PublicKey):
            return False
        signed = {key: value for key, value in approval.items()
                  if key != "signature"}
        value = base64.b64decode(signature["value_base64"], validate=True)
        key.verify(value, _canonical_json_bytes(signed))
        return True
    except (InvalidSignature, OSError, TypeError, ValueError):
        return False


def _pinned_file_sha256(path: Path, label: str) -> str:
    path = Path(path)
    if (not path.is_absolute() or path.is_symlink() or not path.is_file() or
            path != path.resolve(strict=True)):
        raise ValueError(label + " is not a canonical pinned file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assumption_lifecycle_engine_pins(product_src: Path) -> dict[str, str]:
    """Hash the exact code and Prompt that implement the V5 live policy."""
    product_src = Path(product_src)
    product_root = product_src.parent
    integration_root = Path(__file__).resolve().parent
    paths = {
        "product_agents_sha256":
            product_src / "vulnerabilityanalysis" / "agents.py",
        "product_models_sha256":
            product_src / "vulnerabilityanalysis" / "models.py",
        "function_analysis_prompt_sha256":
            product_root / "prompts" / "function_analysis.md",
        "integration_preparation_sha256":
            integration_root / "original_hp_preparation.py",
        "integration_live_optin_sha256": Path(__file__).resolve(),
        "integration_live_entry_sha256":
            integration_root / "original_public_live_entry.py",
        "integration_requirements_sha256":
            integration_root.parent / "requirements.txt",
    }
    return {key: _pinned_file_sha256(path, key)
            for key, path in paths.items()}


def _assumption_lifecycle_live_scope(
        bound: Any, hp: dict[str, Any], control: dict[str, Any], *,
        signed_spec_subject_sha256: str) -> dict[str, Any]:
    """Build the complete human-reviewed scope without sending a model call."""
    from vulnerabilityanalysis.agents import function_analysis_schema_sha256

    closure = control.get("assumption_evidence_closure")
    if (type(closure) is not dict or
            set(closure) != {"enabled", "contract_kind", "one_attempt",
                             "approval_path", "approval_sha256",
                             "approval_public_key_path",
                             "approval_public_key_sha256"} or
            closure.get("enabled") is not True or
            closure.get("contract_kind") != _ASSUMPTION_LIFECYCLE_CONTRACT or
            closure.get("one_attempt") is not True or
            type(signed_spec_subject_sha256) is not str or
            not _SHA.fullmatch(signed_spec_subject_sha256)):
        raise ValueError("HP assumption lifecycle live opt-in is invalid")
    q = bound.admission.qualification
    identity = bound.identity
    caps = bound.caps
    routes = {}
    for role in ("function_analysis", "assertion_generator"):
        route = ((identity.codex_role_models or {}).get(role) or {
            "model": identity.codex_model, "reasoning": identity.codex_effort})
        if (type(route) is not dict or set(route) != {"model", "reasoning"} or
                any(type(route[key]) is not str or not route[key]
                    for key in ("model", "reasoning"))):
            raise ValueError("HP assumption lifecycle model route is invalid")
        routes[role] = dict(route)
    scope = {
        "kind": _ASSUMPTION_LIFECYCLE_SCOPE,
        "contract_kind": _ASSUMPTION_LIFECYCLE_CONTRACT,
        "execution": {
            "task_id": identity.task_id,
            "run_id": identity.run_id,
            "signed_spec_subject_sha256": signed_spec_subject_sha256,
        },
        "selection": {
            "function_name": control.get("function_name"),
            "automatic_discovery": control.get("automatic_discovery"),
            "one_attempt": True,
        },
        "engine_pins": _assumption_lifecycle_engine_pins(identity.product_src),
        "function_analysis_schema_sha256":
            function_analysis_schema_sha256(),
        "qualification_pins": {
            "source_tree_sha256": q.source_tree_sha256,
            "contract_sha256": q.contract_sha256,
            "harness_sha256": q.harness_sha256,
            "binary_sha256": q.binary_sha256,
            "normal_seed_sha256": getattr(q, "normal_seed_sha256", None),
            "functions_json_sha256": control.get("functions_json_sha256"),
            "catalog_manifest_sha256": bound.admission.summary.get(
                "manifest_sha256"),
        },
        "model": {
            "codex_executable_sha256": identity.codex_executable_sha256,
            "routes": routes,
        },
        "human_approval": {
            "signature_kind": _ASSUMPTION_LIFECYCLE_SIGNATURE,
            "public_key_sha256": closure.get(
                "approval_public_key_sha256"),
        },
        "budgets": {
            "max_model_calls": hp.get("max_model_calls"),
            "max_context_reanalyses": control.get(
                "max_context_reanalyses", 2),
            "max_context_requests_per_turn": 2,
            "physical_model_calls": caps.physical_model_calls,
            "calls_per_agent": caps.calls_per_agent,
            "model_wall_seconds": caps.model_wall_seconds,
            "model_turn_seconds": caps.model_turn_seconds,
            "physical": hp.get("physical"),
        },
        "credit": {
            "automatic_discovery": False,
            "security_gate_credit": "NOT_CREDITED",
        },
    }
    # Fail here rather than allowing a human receipt to bless an incomplete
    # runtime identity.
    if (scope["execution"] != {
            "task_id": identity.task_id, "run_id": identity.run_id,
            "signed_spec_subject_sha256": signed_spec_subject_sha256} or
            any(type(scope["execution"][key]) is not str or
                re.fullmatch(r"[0-9a-f]{24}", scope["execution"][key]) is None
                for key in ("task_id", "run_id")) or
            scope["selection"] != {
            "function_name": control.get("function_name"),
            "automatic_discovery": False, "one_attempt": True} or
            any(type(value) is not str or not _SHA.fullmatch(value)
                for key, value in scope["qualification_pins"].items()
                if key != "normal_seed_sha256") or
            (scope["qualification_pins"]["normal_seed_sha256"] is not None and
             (type(scope["qualification_pins"]["normal_seed_sha256"]) is not str or
              not _SHA.fullmatch(
                  scope["qualification_pins"]["normal_seed_sha256"]))) or
            any(type(value) is not str or not _SHA.fullmatch(value)
                for value in scope["engine_pins"].values()) or
            type(scope["model"]["codex_executable_sha256"]) is not str or
            not _SHA.fullmatch(scope["model"]["codex_executable_sha256"]) or
            scope["human_approval"] != {
                "signature_kind": _ASSUMPTION_LIFECYCLE_SIGNATURE,
                "public_key_sha256": closure.get(
                    "approval_public_key_sha256")} or
            type(scope["human_approval"]["public_key_sha256"]) is not str or
            not _SHA.fullmatch(
                scope["human_approval"]["public_key_sha256"])):
        raise ValueError("HP assumption lifecycle live scope is incomplete")
    return scope


def _validate_assumption_lifecycle_live_approval(
        bound: Any, hp: dict[str, Any], control: dict[str, Any], *,
        spec_path: Path, spec_sha256: str) -> dict[str, Any] | None:
    """Verify the human receipt and return a recheckable live-admission token."""
    closure = control.get("assumption_evidence_closure")
    if closure is None:
        return None
    spec_raw = _check_signed_spec(Path(spec_path), spec_sha256)
    try:
        signed_spec = json.loads(spec_raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("HP assumption lifecycle signed spec is malformed") from exc
    subject_sha256 = _signed_spec_subject_sha256(signed_spec)
    identity = signed_spec.get("identity") if type(signed_spec) is dict else None
    if (type(identity) is not dict or
            identity.get("task_id") != bound.identity.task_id or
            identity.get("run_id") != bound.identity.run_id):
        raise ValueError("HP assumption lifecycle approval run identity changed")
    scope = _assumption_lifecycle_live_scope(
        bound, hp, control,
        signed_spec_subject_sha256=subject_sha256)
    approval_path = (Path(closure["approval_path"])
                     if type(closure.get("approval_path")) is str else Path())
    approval_sha256 = closure.get("approval_sha256")
    if (type(approval_sha256) is not str or
            not _SHA.fullmatch(approval_sha256)):
        raise ValueError("HP assumption lifecycle approval SHA-256 is invalid")
    raw = _check_signed_spec(approval_path, approval_sha256)
    public_key_path = (Path(closure["approval_public_key_path"])
                       if type(closure.get("approval_public_key_path")) is str
                       else Path())
    public_key_sha256 = closure.get("approval_public_key_sha256")
    if (type(public_key_sha256) is not str or
            not _SHA.fullmatch(public_key_sha256) or
            _pinned_file_sha256(
                public_key_path,
                "HP assumption lifecycle approval public key") !=
                    public_key_sha256):
        raise ValueError("HP assumption lifecycle approval key changed")
    try:
        approval = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("HP assumption lifecycle approval is malformed") from exc
    if (type(approval) is not dict or set(approval) != {
            "kind", "status", "decision", "reviewer_id", "reviewed_at",
            "scope", "signature"} or
            approval.get("kind") != _ASSUMPTION_LIFECYCLE_APPROVAL or
            approval.get("status") != "APPROVED" or
            type(approval.get("decision")) is not bool or
            approval["decision"] is not True or
            type(approval.get("reviewer_id")) is not str or
            not approval["reviewer_id"].strip() or
            type(approval.get("reviewed_at")) is not str or
            re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T"
                         r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                         approval["reviewed_at"]) is None or
            _canonical_json_bytes(approval.get("scope")) !=
                _canonical_json_bytes(scope) or
            not _verify_assumption_lifecycle_human_signature(
                approval, public_key_path=public_key_path,
                public_key_sha256=public_key_sha256)):
        raise ValueError("HP assumption lifecycle human approval differs from live scope")
    return {
        "kind": _ASSUMPTION_LIFECYCLE_ADMISSION,
        "contract_kind": _ASSUMPTION_LIFECYCLE_CONTRACT,
        "task_id": bound.identity.task_id,
        "run_id": bound.identity.run_id,
        "signed_spec_subject_sha256": subject_sha256,
        "spec_path": str(Path(spec_path)),
        "spec_sha256": spec_sha256,
        "approval_path": str(approval_path),
        "approval_sha256": approval_sha256,
        "approval_public_key_path": str(public_key_path),
        "approval_public_key_sha256": public_key_sha256,
        "scope_sha256": _canonical_json_sha256(scope),
        "scope": scope,
    }


def _check_signed_hp_spec(path: Path, expected_sha256: str,
                          hp: dict[str, Any]) -> None:
    raw = _check_signed_spec(path, expected_sha256)
    try:
        signed_hp = json.loads(raw)["hp"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError("HP signed opt-in is unavailable") from exc
    if signed_hp != hp:
        raise ValueError("HP opt-in differs from signed spec")


def _signed_bounded_hp_pair(bound: Any, worker_receipt: dict[str, Any],
                            spec_path: Path, spec_sha256: str
                            ) -> tuple[str, str] | None:
    """Bind bounded HP to the single signed, persisted automatic SP choice."""
    try:
        spec = json.loads(_check_signed_spec(spec_path, spec_sha256))
        scope = spec.get("development_scope")
        bounded = getattr(bound.caps, "bounded_nohint_dev", False)
        if scope is None:
            if bounded:
                raise ValueError
            return None
        expected_scope = {
                "kind": "BOUNDED_NOHINT_DEV_V1",
                "seed_directions": 2, "sp_functions": 1,
                "sp_max_iterations": 7}
        if (bounded is not True or type(scope) is not dict or
                {key: scope.get(key) for key in expected_scope} != expected_scope or
                scope.get("selection") not in {
                    "DIRECTION_RISK_PHASE_CANONICAL_V1",
                    "DIRECTION_RISK_PHASE_ROUND_ROBIN_MODEL_ORDER_V2",
                    "DIRECTION_RISK_PHASE_ROUND_ROBIN_MODEL_ORDER_V3",
                    "DIRECTION_RISK_PHASE_GENERIC_SURFACE_MODEL_TIE_V4"} or
                set(scope) != {*expected_scope, "selection"} or
                spec.get("hp", {}).get("enabled") is not True or
                spec["hp"].get("max_items") != 1 or
                bound.executor.development_auto_scope.get("sp_functions") != 1 or
                bound.strategy._development_auto_scope is not
                    bound.executor.development_auto_scope):
            raise ValueError
        path = (Path(bound.identity.run_dir) / "worker" / "results" /
                "BOUNDED_AUTO_SELECTION.json")
        if (not path.is_file() or path.is_symlink() or
                path != path.resolve(strict=True) or
                path != bound.strategy.results_path /
                    "BOUNDED_AUTO_SELECTION.json"):
            raise ValueError
        raw = path.read_bytes()
        if len(raw) > 1_000_000:
            raise ValueError
        digest = hashlib.sha256(raw).hexdigest()
        saved = json.loads(raw)
        current = bound.strategy._development_sp_scope
        reported = worker_receipt.get("analysis_scope")
        if (type(saved) is not dict or type(current) is not dict or
                type(reported) is not dict or
                saved.get("kind") != "BOUNDED_NOHINT_SELECTION_V1" or
                saved.get("status") != "PARTIAL_SCOPE" or
                saved.get("task_id") != bound.identity.task_id or
                saved.get("run_id") != bound.identity.run_id or
                saved.get("selection") != scope["selection"] or
                saved.get("direction_plan_sha256") !=
                    bound.strategy._development_direction_plan[1] or
                saved.get("function_limit") != 1 or
                type(saved.get("selected_functions")) is not list or
                len(saved["selected_functions"]) != 1 or
                any(row.get("selected_functions") != saved["selected_functions"] or
                    row.get("function_limit") != 1 or
                    row.get("selection_receipt_path") != str(path) or
                    row.get("selection_receipt_sha256") != digest
                    for row in (current, reported))):
            raise ValueError
        selected = saved["selected_functions"][0]
        function_id = selected.get("function_id")
        direction_id = selected.get("direction_id")
        if (type(function_id) is not str or not function_id or
                type(direction_id) is not str or not direction_id):
            raise ValueError
        return function_id, direction_id
    except (AttributeError, KeyError, OSError, TypeError, ValueError,
            UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("HP_SIGNED_SELECTION_UNPROVEN") from exc


def _write_once(path: Path, row: dict[str, Any]) -> str:
    data = (json.dumps(row, sort_keys=True, default=str,
                       separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return hashlib.sha256(data).hexdigest()


def _combined_concurrent_hp_selection(
        bound: Any, worker_receipt: dict[str, Any], spec_path: Path,
        spec_sha256: str) -> tuple[tuple[str, str] | None, str] | None:
    """Freeze the generic first post-Worker HP pair for the combined profile."""
    spec = json.loads(_check_signed_spec(Path(spec_path), spec_sha256))
    scope = spec.get("development_seed_scope")
    if (type(scope) is not dict or scope.get("kind") !=
            "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1"):
        return None
    if (set(scope) != {"kind", "seed_directions", "sp_function_limit",
                       "sp_queue_policy", "security_invariant_focus",
                       "direction_selection", "pov_attempts_per_candidate",
                       "worker_pool"} or
            scope.get("sp_queue_policy") !=
                "PERSISTENT_CONCURRENT_QUEUE_V1" or
            scope.get("worker_pool") !=
                {"discovery": 3, "verifier": 2, "pov": 2} or
            spec.get("hp", {}).get("enabled") is not True or
            spec["hp"].get("max_items") != 1 or
            spec["hp"].get("max_model_calls") != 3):
        raise ValueError("HP_COMBINED_PROFILE_INVALID")
    # A Crash/Gate result leaves its SP pending independent validation; this
    # profile has no Gate-to-SP settlement yet, so HP must not start. Report
    # that cause explicitly instead of a generic receipt identity failure.
    if (worker_receipt.get("status") ==
            "EXECUTED_GATE_VERIFIED_DISCOVERY_UNPROVEN" or
            worker_receipt.get("verification_status") in {
                "MODEL_POV_PRODUCT_GATE_VERIFIED_DISCOVERY_UNPROVEN",
                "PRODUCT_GATE_VERIFIED_MODEL_ORIGIN_UNPROVEN",
                "POV_CRASH_GATE_TERMINAL_NOT_VERIFIED"} or
            worker_receipt.get("pov_crashes_gate_verified_count", 0) != 0 or
            worker_receipt.get(
                "pov_crashes_gate_terminal_not_verified_count", 0) != 0):
        raise ValueError("HP_BLOCKED_GATE_RESULT_NOT_QUEUE_SETTLED")
    repos = bound.server.repos
    collection = repos.suspicious_points.collection
    from bson import ObjectId
    candidate_rows = list(collection.find(
        {"task_id": ObjectId(bound.identity.task_id)},
        {"_id": 1, "status": 1, "processor_id": 1,
         "verification_claim_token": 1, "pov_active_claims": 1,
         "pending_pov_ids": 1, "pending_pov_artifacts": 1},
    ))
    normalized_candidates = []
    # This is a fresh-run proof, so accept only statuses which the current
    # pipeline treats as fully settled.  A denylist would silently certify a
    # new or unknown interruption state as terminal.
    settled_statuses = {"reviewed_not_admitted", "pov_generated", "failed",
                        "skipped"}
    required = {"_id", "status", "processor_id",
                "verification_claim_token", "pov_active_claims",
                "pending_pov_ids", "pending_pov_artifacts"}
    for row in candidate_rows:
        if (not required <= set(row) or type(row.get("status")) is not str or
                row.get("processor_id") is not None or
                row.get("verification_claim_token") is not None or
                type(row.get("pov_active_claims")) is not list or
                row["pov_active_claims"] or
                type(row.get("pending_pov_ids")) is not list or
                row["pending_pov_ids"] or
                type(row.get("pending_pov_artifacts")) is not list or
                row["pending_pov_artifacts"] or
                row["status"] not in settled_statuses):
            raise ValueError("HP_CONCURRENT_QUEUE_UNSETTLED")
        normalized_candidates.append({
            "id": str(row["_id"]), "status": row["status"],
            "processor_id": None, "verification_claim_token": None,
            "pov_active_claims": [], "pending_pov_ids": [],
            "pending_pov_artifacts": [],
        })
    normalized_candidates.sort(key=lambda row: row["id"])
    queue_settlement_sha256 = _canonical_json_sha256(normalized_candidates)
    current_ids = _current_direction_ids(bound)
    if current_ids is None:
        raise ValueError("CURRENT_DIRECTION_PLAN_UNPROVEN")
    task_id = bound.identity.task_id
    fuzzer = bound.executor.fuzzer
    directions = {row.direction_id: row for row in
                  repos.directions.find_by_fuzzer(task_id, fuzzer)
                  if row.task_id == task_id and row.fuzzer == fuzzer and
                  row.direction_id in current_ids}
    if set(directions) != current_ids:
        raise ValueError("CURRENT_DIRECTION_ROWS_MISSING")
    eligible = sorted({
        (function.function_id, direction_id)
        for function in repos.functions.find_by_task(task_id)
        if function.task_id == task_id
        for direction_id in set(function.analyzed_by_directions)
        if direction_id in directions
    }, key=lambda pair: (pair[1], pair[0]))
    selected = eligible[0] if eligible else None
    plan = getattr(bound.strategy, "_development_direction_plan", None)
    if (type(plan) is not tuple or len(plan) != 2 or
            type(plan[1]) is not str or not _SHA.fullmatch(plan[1])):
        raise ValueError("CURRENT_DIRECTION_PLAN_UNPROVEN")
    original = worker_receipt.get("original_result")
    if (type(original) is not dict or
            worker_receipt.get("task_id") != task_id or
            worker_receipt.get("run_id") != bound.identity.run_id or
            worker_receipt.get("status") != "EXECUTED_UNVERIFIED" or
            worker_receipt.get("execution_status") != "EXECUTED" or
            worker_receipt.get("sp_analysis_status") != "COMPLETED" or
            worker_receipt.get("verification_status") not in {
                "NO_PENDING_OBSERVATION",
                "PRODUCT_CONSUMER_VERIFIED_ORIGIN_UNPROVEN",
                "MODEL_POV_PRODUCT_GATE_VERIFIED_DISCOVERY_UNPROVEN"} or
            worker_receipt.get("pending_global_crashes") != 0 or
            worker_receipt.get(
                "pov_crashes_pending_independent_validation") != 0):
        raise ValueError("HP_WORKER_RECEIPT_IDENTITY_INVALID")
    row = {
        "kind": "FBV2_HP_POST_WORKER_SELECTION_V1",
        "task_id": task_id,
        "run_id": bound.identity.run_id,
        "worker_id": original.get("worker_id"),
        "spec_sha256": spec_sha256,
        "direction_plan_sha256": plan[1],
        "worker_receipt_sha256": _canonical_json_sha256(worker_receipt),
        "original_result_sha256": _canonical_json_sha256(original),
        "queue_candidate_count": len(normalized_candidates),
        "queue_settlement_sha256": queue_settlement_sha256,
        "eligible_pairs": [list(pair) for pair in eligible],
        "eligible_pairs_sha256": _canonical_json_sha256(eligible),
        "selected_pair": list(selected) if selected is not None else None,
        "selection_policy": "DIRECTION_ID_FUNCTION_ID_ASC_WRITE_ONCE_V1",
        "model_calls": 0,
        "target_calls": 0,
    }
    path = Path(bound.identity.run_dir) / "HP_POST_WORKER_SELECTION.json"
    data = (json.dumps(row, sort_keys=True, default=str,
                       separators=(",", ":")) + "\n").encode("utf-8")
    if path.exists():
        if (path.is_symlink() or not path.is_file() or
                path.read_bytes() != data):
            raise ValueError("HP_POST_WORKER_SELECTION_CHANGED")
        digest = hashlib.sha256(data).hexdigest()
    else:
        digest = _write_once(path, row)
    return selected, digest


def _persist_hp_only_result(bound: Any, result_path: Path,
                            result_sha256: str) -> dict[str, str]:
    """Insert and immediately read back one immutable HP-only result.

    The on-disk receipt remains the primary append-only artifact.  A real
    public-development bound also mirrors the exact parsed receipt into
    MongoDB so later automation cannot confuse a transient return value with
    a durably settled HP result.  Small unit fixtures without ``bound.server``
    deliberately remain file-only; a live-shaped bound with a server must
    expose the database or fail closed.
    """
    server = getattr(bound, "server", None)
    if server is None:
        return {"status": "NOT_AVAILABLE_TEST_FIXTURE", "record_id": ""}
    repos = getattr(server, "repos", None)
    database = getattr(repos, "db", None) if repos is not None else None
    if database is None:
        raise RuntimeError("HP-only MongoDB repository is unavailable")
    if (result_path.is_symlink() or not result_path.is_file() or
            hashlib.sha256(result_path.read_bytes()).hexdigest() !=
                result_sha256):
        raise RuntimeError("HP-only result changed before MongoDB settlement")
    raw = result_path.read_bytes()
    if len(raw) > 15_000_000:
        raise RuntimeError("HP-only result exceeds the MongoDB receipt limit")
    try:
        parsed = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("HP-only result is not canonical JSON") from exc
    record_id = (f"hp-only-result:{bound.identity.task_id}:"
                 f"{bound.identity.run_id}")
    record = {
        "_id": record_id,
        "kind": "FBV2_HP_ONLY_MONGO_RESULT_V1",
        "task_id": bound.identity.task_id,
        "run_id": bound.identity.run_id,
        "receipt_path": str(result_path),
        "receipt_sha256": result_sha256,
        "receipt": parsed,
        "status": parsed.get("status"),
        "automatic_discovery": False,
        "security_gate_credit": "NOT_CREDITED",
    }
    collection = database["hp_only_results"]
    inserted = collection.insert_one(record)
    if not inserted.acknowledged:
        raise RuntimeError("HP-only MongoDB insert was not acknowledged")
    observed = collection.find_one({"_id": record_id})
    if observed != record:
        raise RuntimeError("HP-only MongoDB readback differs from receipt")
    return {"status": "PERSISTED_AND_READ_BACK", "record_id": record_id}


def _verified_hp_provenance(gate: Any, work: Any, worker_id: str,
                            row: dict[str, Any], *,
                            max_analysis_turns: int = 2) -> dict[str, Any]:
    """Re-read both HP role responses immediately before a physical claim."""
    provenance = row.get("hp_model_provenance")
    if (row.get("proposal_origin") != "VERIFIED_CAMPAIGN_MODEL" or
            type(provenance) is not dict or
            set(provenance) != {"function_analysis_turns",
                                "assertion_generator_turn"}):
        raise ValueError("HP model proposal provenance is unavailable")
    analysis_turns = provenance["function_analysis_turns"]
    assertion_turn = provenance["assertion_generator_turn"]
    if (type(max_analysis_turns) is not int or
            max_analysis_turns not in (2, 3, 4) or
            type(analysis_turns) is not list or
            not 1 <= len(analysis_turns) <= max_analysis_turns or
            type(assertion_turn) is not dict):
        raise ValueError("HP model role provenance is incomplete")
    turns = [*analysis_turns, assertion_turn]
    records = gate.snapshot()["records"]
    seen: set[str] = set()
    responses: dict[str, list[dict[str, Any]]] = {
        "function_analysis": [], "assertion_generator": []}
    for index, turn in enumerate(turns):
        role = ("function_analysis" if index < len(analysis_turns)
                else "assertion_generator")
        owner = f"hp:{work.function_id}:{work.direction_id}:{role}"
        if (type(turn) is not dict or set(turn) != {
                "role", "owner_id", "request_id", "response_sha256",
                "thread_id", "turn_id"} or
                turn.get("role") != role or turn.get("owner_id") != owner or
                type(turn.get("request_id")) is not str or
                not turn["request_id"] or turn["request_id"] in seen or
                type(turn.get("response_sha256")) is not str or
                not _SHA.fullmatch(turn["response_sha256"])):
            raise ValueError("HP model role provenance changed")
        seen.add(turn["request_id"])
        matching = [entry for entry in records
                    if entry.get("request_id") == turn["request_id"]]
        evidence = gate.verify_response_evidence(turn["request_id"])
        if (len(matching) != 1 or
                matching[0].get("status") != "COMPLETED" or
                matching[0].get("role") != role or
                matching[0].get("owner_id") != owner or
                evidence.get("status") != "VERIFIED" or
                any(evidence.get(key) != turn[key] for key in (
                    "request_id", "response_sha256", "thread_id", "turn_id"))):
            raise ValueError("HP model response evidence changed")
        raw = Path(evidence["response_path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != turn["response_sha256"]:
            raise ValueError("HP model response bytes changed")
        parsed = json.loads(raw)
        if type(parsed) is not dict:
            raise ValueError("HP model response body is invalid")
        responses[role].append(parsed)
    # The two verified turns must explain the exact selected Assertion. An
    # unrelated completed request with the right role is not its provenance.
    final_analysis = responses["function_analysis"][-1]
    generated = responses["assertion_generator"][0]
    raw_safes = final_analysis.get("safe_assumptions")
    judgments = final_analysis.get("hypothesis_evaluations")
    generated_rows = generated.get("assertions")
    dispositions = generated.get("dispositions")
    proposals = row.get("assertion_proposals")
    if (type(raw_safes) is not list or type(judgments) is not list or
            type(generated_rows) is not list or type(dispositions) is not list or
            type(proposals) is not list):
        raise ValueError("HP model SAFE or Assertion body is incomplete")
    linked = {item.get("safe_assumption") for item in judgments
              if type(item) is dict and
              item.get("judgment") == "EXPLICIT_SAFE_JUDGMENT" and
              item.get("safe_assumption")}
    canonical = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    pinned_safes = row.get("assertion_input_safe_assumptions")
    pinned_safes_sha = row.get("assertion_input_safe_assumptions_sha256")
    closure = row.get("candidate_context_closure")
    if pinned_safes is None and closure is None:
        # Compatibility for historical, non-scoped receipts.  New results
        # always pin the post-validation input list explicitly.
        safes = [safe for safe in raw_safes if safe in linked]
    else:
        if (type(pinned_safes) is not list or not pinned_safes or
                any(type(safe) is not str or not safe or safe not in linked
                    for safe in pinned_safes) or
                len(set(pinned_safes)) != len(pinned_safes) or
                type(pinned_safes_sha) is not str or
                pinned_safes_sha != hashlib.sha256(
                    canonical(pinned_safes)).hexdigest()):
            raise ValueError("HP Assertion input SAFE handoff changed")
        safes = list(pinned_safes)
        if closure is not None:
            ledger = row.get("assumption_lifecycle_ledger")
            eligible_ids = (closure.get("eligible_assumption_ids")
                            if type(closure) is dict else None)
            if (type(ledger) is not list or type(eligible_ids) is not list or
                    any(type(value) is not str or not value
                        for value in eligible_ids)):
                raise ValueError("HP scoped SAFE handoff is incomplete")
            eligible_text = {
                item.get("safe_assumption") for item in ledger
                if type(item) is dict and
                item.get("assumption_id") in set(eligible_ids) and
                item.get("disposition") == "VALIDATED_SAFE" and
                item.get("required_context") == [] and
                type(item.get("safe_assumption")) is str
            }
            if (len(eligible_text) != len(eligible_ids) or
                    set(safes) != eligible_text):
                raise ValueError("HP scoped SAFE handoff differs from ledger")
    from vulnerabilityanalysis.models import stable_id
    if len(proposals) != len(generated_rows):
        raise ValueError("HP saved Assertion count differs from model response")
    expected_rows = []
    for item in generated_rows:
        if (type(item) is not dict or
                type(item.get("safe_id")) is not int or
                type(item.get("runtime_expression")) is not str or
                type(item.get("source_line")) is not int or
                type(item.get("safe_assumption")) is not str):
            raise ValueError("HP model Assertion row is invalid")
        safe_id = item["safe_id"]
        valid_id = 0 <= safe_id < len(safes)
        safe = (safes[safe_id] if valid_id else item["safe_assumption"])
        identity_kind = "LLM" if valid_id else "LLM_INVALID_SAFE_ID"
        expected_rows.append((
            stable_id("assert", identity_kind, worker_id,
                      work.direction_id, work.function_name, safe,
                      item["runtime_expression"], item["source_line"]),
            safe, item["runtime_expression"],
            f"{work.source_file}:{item['source_line']}",
            "LLM"))
    actual_rows = []
    for proposal in proposals:
        if type(proposal) is not dict:
            raise ValueError("HP saved Assertion row is invalid")
        actual_rows.append((
            proposal.get("assertion_id"), proposal.get("safe_assumption"),
            proposal.get("runtime_expression"),
            proposal.get("source_location"),
            proposal.get("generation_method")))
    if any(any(type(value) is not str for value in item)
           for item in actual_rows):
        raise ValueError("HP saved Assertion identity is invalid")
    if sorted(actual_rows) != sorted(expected_rows):
        raise ValueError("HP saved Assertions differ from model response")
    for proposal in proposals:
        if type(proposal) is not dict or proposal.get("status") != "PROPOSED":
            continue
        safe = proposal.get("safe_assumption")
        if (type(safe) is not str or safe not in safes or safe not in linked or
                proposal.get("generation_method") != "LLM" or
                proposal.get("worker_id") != worker_id or
                proposal.get("function") != work.function_name or
                proposal.get("direction_id") != work.direction_id):
            raise ValueError("HP proposal is not linked to Function Analysis")
        matches = [item for item in generated_rows if
                   type(item) is dict and
                   type(item.get("safe_id")) is int and
                   0 <= item["safe_id"] < len(safes) and
                   safes[item["safe_id"]] == safe and
                   item.get("runtime_expression") ==
                       proposal.get("runtime_expression") and
                   proposal.get("source_location") ==
                       f"{work.source_file}:{item.get('source_line')}"]
        if len(matches) != 1:
            raise ValueError("HP proposal differs from Assertion response")
        selected = matches[0]
        disposition = [item for item in dispositions if
                       type(item) is dict and
                       type(item.get("safe_id")) is int and
                       item["safe_id"] == selected["safe_id"]]
        if (len(disposition) != 1 or
                disposition[0].get("status") != "PROPOSED" or
                type(disposition[0].get("reason")) is not str or
                not disposition[0]["reason"].strip() or
                proposal.get("assertion_id") != stable_id(
                    "assert", "LLM", worker_id, work.direction_id,
                    work.function_name, safe,
                    proposal["runtime_expression"], selected["source_line"])):
            raise ValueError("HP proposal identity differs from model response")
    return provenance


def _claim_hp_run(bound: Any, worker_receipt: dict[str, Any],
                  hp: dict[str, Any], spec_sha256: str,
                  selection_receipt_sha256: str | None = None,
                  selected_pair: tuple[str, str] | None = None) -> str:
    root = bound.identity.run_dir
    if (not _private_directory(root) or type(spec_sha256) is not str or
            not _SHA.fullmatch(spec_sha256)):
        raise ValueError("HP run claim identity is unsafe")
    original = worker_receipt.get("original_result")
    if (type(original) is not dict or
            type(original.get("worker_id")) is not str or
            worker_receipt.get("task_id") != bound.identity.task_id or
            worker_receipt.get("run_id") != bound.identity.run_id):
        raise ValueError("HP run claim Worker identity is unavailable")
    process, process_sha = bound.process_ledger.receipt_snapshot()
    if (process.get("stop_status") is not None or
            bool(process.get("active"))):
        raise ValueError("HP run claim process account is unsettled")
    if (selection_receipt_sha256 is not None and
            (type(selection_receipt_sha256) is not str or
             not _SHA.fullmatch(selection_receipt_sha256))):
        raise ValueError("HP selection receipt identity is unsafe")
    if ((selected_pair is None) != (selection_receipt_sha256 is None) or
            (selected_pair is not None and
             (type(selected_pair) is not tuple or len(selected_pair) != 2 or
              any(type(value) is not str or not value
                  for value in selected_pair)))):
        raise ValueError("HP selected pair identity is unsafe")
    row = {"kind": ("FBV2_HP_RUN_CLAIM_V2" if
                    selection_receipt_sha256 is not None else
                    "FBV2_HP_RUN_CLAIM_V1"),
           "task_id": bound.identity.task_id,
           "run_id": bound.identity.run_id,
           "worker_id": original["worker_id"],
           "spec_sha256": spec_sha256,
           "hp_assets": hp["assets"],
           "model_physical_before": bound.model_gate.snapshot()["physical"],
           "process_receipt_sha256_before": process_sha,
           "original_result_sha256": hashlib.sha256(json.dumps(
               original, sort_keys=True, default=str,
               separators=(",", ":")).encode()).hexdigest()}
    if selection_receipt_sha256 is not None:
        row["selection_receipt_sha256"] = selection_receipt_sha256
        row["selected_pair"] = list(selected_pair)
    return _write_once(root / "HP_RUN_CLAIM.json", row)


def _hp_client_type(asset_check):
    """Reuse isolated process startup without FBv2 host-MCP instructions."""
    from fuzzingbrain.llms.codex_tool_bridge import (
        isolated_codex_appserver_client_class)
    from vulnerabilityanalysis.llm import CodexAppServerClient

    isolated = isolated_codex_appserver_client_class(CodexAppServerClient)

    class PinnedHPClient(isolated):
        async def _request(self, method: str, params: dict[str, Any], *,
                           response_envelope=None):
            # The isolated class changes developerInstructions for FBv2 host
            # MCP proposals. HP must retain the product's no-tool instructions.
            prior = self._fbv2_request_stage
            self._fbv2_request_stage = method
            try:
                if response_envelope is None:
                    return await CodexAppServerClient._request(
                        self, method, params)
                return await CodexAppServerClient._request(
                    self, method, params, response_envelope=response_envelope)
            finally:
                self._fbv2_request_stage = prior

        async def generate(self, request):
            asset_check()
            result = await super().generate(request)
            asset_check()
            return result

    return PinnedHPClient


def _pipeline_factory(bound: Any, hp: dict[str, Any], role: str,
                      spec_path: Path, spec_sha256: str,
                      extra_check=None, *, hp_only: bool = False):
    from devtools.campaign_model_gate import CampaignLedgeredProvider
    from vulnerabilityanalysis.agents import AgentPipeline

    def check():
        _check_signed_hp_spec(spec_path, spec_sha256, hp)
        bound.recheck()
        validate_hp_spec(hp, bound.identity.product_src, enabled=True,
                         hp_only=hp_only,
                         bounded_nohint_hp=bool(getattr(
                             getattr(bound, "caps", None),
                             "bounded_nohint_dev", False)))
        if extra_check is not None:
            extra_check()

    client_type = _hp_client_type(check)

    boundary_lock = None
    if getattr(getattr(bound, "executor", None),
               "parallel_hp_async_factory", None) is not None:
        factory = getattr(getattr(bound, "strategy", None),
                          "llm_client_factory", None)
        boundary_lock = getattr(factory, "_fbv2_campaign_boundary_lock", None)
        if (getattr(factory, "_fbv2_campaign_gate", None) is not
                bound.model_gate or not isinstance(boundary_lock,
                                                  asyncio.Lock)):
            raise ValueError("HP parallel model boundary is not shared")

    def build(work):
        check()
        event_dir = bound.identity.run_dir / "model_events"
        if not _private_directory(event_dir):
            raise ValueError("HP event directory is unsafe")
        route = ((bound.identity.codex_role_models or {}).get(role) or {
            "model": bound.identity.codex_model,
            "reasoning": bound.identity.codex_effort,
        })
        transport = client_type(
            cwd=bound.identity.task_path, model=route["model"],
            effort=route["reasoning"],
            timeout_seconds=bound.caps.model_turn_seconds,
            executable=str(bound.identity.codex_executable),
            executable_sha256=bound.identity.codex_executable_sha256,
            event_log_path=event_dir / f"hp_{role}_{uuid4().hex}.jsonl")
        provider = CampaignLedgeredProvider(
            transport, bound.model_gate, role=role,
            owner_id=f"hp:{work.function_id}:{work.direction_id}:{role}",
            boundary_lock=boundary_lock)
        return AgentPipeline(provider, max_context_requests=2)

    return build


def _hp_physical_budget_available(state: dict[str, Any],
                                  physical: dict[str, Any], *,
                                  parallel_hp_execution: bool) -> bool:
    """Check unspent shared capacity including every active reservation."""
    if (type(state) is not dict or type(state.get("active")) is not dict or
            state.get("stop_status") is not None or
            (state["active"] and not parallel_hp_execution)):
        return False
    return (
        state["wall_total_seconds"] - state["wall_spent_seconds"] -
        state["wall_reserved_seconds"] >= physical["total_wall_seconds"] and
        state["fuzz_total_seconds"] - state["fuzz_spent_seconds"] -
        state["fuzz_reserved_seconds"] >= physical["guided_seconds"] + 24.5)


def _physical_handoff_factory(bound: Any, hp: dict[str, Any],
                              worker_receipt: dict[str, Any] | None,
                              spec_path: Path, spec_sha256: str,
                              *, actor_id: str | None = None,
                              signed_max_analysis_turns: int | None = None,
                              extra_check=None,
                              parallel_hp_execution: bool = False):
    """Return one target-pinned, signed V2 physical handoff for HP proposals.

    This is constructed only by the pinned public development runner. It is
    deliberately not a generic repository build adapter; the public entry
    independently checks the signed profile and one-shot run claim.
    """
    physical = hp.get("physical")
    _validate_hp_physical_spec(physical)
    if physical is None:
        return None
    if (signed_max_analysis_turns is not None and
            (actor_id is None or signed_max_analysis_turns not in (3, 4))):
        raise ValueError("HP signed analysis-turn provenance cap is invalid")
    if (type(parallel_hp_execution) is not bool or
            parallel_hp_execution and (
                actor_id is None or worker_receipt is not None or
                not callable(extra_check) or
                getattr(getattr(bound, "caps", None),
                        "sp_concurrent_queue", False) is not True)):
        raise ValueError("HP parallel physical admission is invalid")
    from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
    from devtools.original_hp_preparation import (
        PreparedHPFunction, _prepared_pins_ok,
        _qualified_manifest_target_ok, _qualified_relink_recipe_ok,
        _reviewed_relink_build_command, run_prepared_hp_assertion_handoff)
    builder = Path(physical["builder_path"])
    manifest = Path(physical["manifest_path"])
    build_command = _reviewed_relink_build_command(
        builder, manifest, physical["manifest_sha256"])
    q = bound.admission.qualification
    root = bound.identity.run_dir
    worker_id = (actor_id if actor_id is not None else
                 worker_receipt["original_result"]["worker_id"])
    qualified_recipe = _qualified_manifest_target_ok(
        qualification=q, builder=builder,
        builder_sha256=physical["builder_sha256"], manifest_path=manifest,
        manifest_sha256=physical["manifest_sha256"])
    if not qualified_recipe:
        raise ValueError("HP physical recipe is not qualified for this target")

    def recheck(work: PreparedHPFunction, claim: Path | None = None,
                claim_sha: str | None = None) -> None:
        _check_signed_hp_spec(spec_path, spec_sha256, hp)
        validate_hp_spec(hp, bound.identity.product_src, enabled=True,
                         hp_only=actor_id is not None and
                             not parallel_hp_execution,
                         bounded_nohint_hp=bool(getattr(
                             getattr(bound, "caps", None),
                             "bounded_nohint_dev", False)))
        bound.recheck()
        if extra_check is not None:
            extra_check()
        if (not _prepared_pins_ok(work, q) or
                not _qualified_relink_recipe_ok(
                    work=work, qualification=q, build_command=build_command,
                    manifest_path=manifest,
                    manifest_sha256=physical["manifest_sha256"])):
            raise ValueError("HP qualified md4c build recipe changed")
        if claim is not None and (claim_sha is None or
                claim.is_symlink() or not claim.is_file() or
                hashlib.sha256(claim.read_bytes()).hexdigest() != claim_sha):
            raise ValueError("HP one-shot physical claim changed")

    def handoff(work: PreparedHPFunction, row: dict[str, Any]) -> dict[str, Any]:
        if type(work) is not PreparedHPFunction or type(row) is not dict:
            raise ValueError("HP physical work or proposal is invalid")
        if (parallel_hp_execution and work.selection_origin !=
                "PARALLEL_HP_PRE_SP_SELECTION_V1"):
            raise ValueError("HP parallel work origin is invalid")
        recheck(work)
        proposals = row.get("assertion_proposals")
        canonical = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode()
        if (row.get("status") != "ASSERTIONS_PROPOSED_UNVERIFIED" or
                row.get("assertion_execution") != "NOT_RUN" or
                row.get("function_id") != work.function_id or
                row.get("direction_id") != work.direction_id or
                type(proposals) is not list or
                row.get("assertion_count") != len(proposals) or
                row.get("proposed_assertion_count") != sum(
                    type(item) is dict and item.get("status") == "PROPOSED"
                    for item in proposals) or
                row.get("prepared_work_sha256") != hashlib.sha256(
                    canonical(asdict(work))).hexdigest() or
                row.get("assertion_proposals_sha256") != hashlib.sha256(
                    canonical(proposals)).hexdigest()):
            raise ValueError("HP physical proposal receipt changed")
        # AgentPipeline can derive STATIC_RULE Assertions when the model
        # returns assertions=[]. The saved HP row pins context files but not
        # the exact excerpts presented to that derivation. Recomputing from
        # current source could silently use evidence the model never saw.
        if any(type(item) is dict and item.get("status") == "PROPOSED" and
               item.get("generation_method") == "STATIC_RULE"
               for item in proposals):
            return {"status": "HP_ASSERTION_HANDOFF_BLOCKED",
                    "reason": "MODEL_SAFE_STATIC_ASSERTION_CONTEXT_UNPROVEN",
                    "sp_global_effect": "UNCHANGED",
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED"}
        provenance_cap = (2 if parallel_hp_execution else
                          signed_max_analysis_turns
                          if signed_max_analysis_turns is not None else
                          4 if getattr(getattr(bound, "caps", None),
                                       "bounded_nohint_dev", False) else
                          3 if actor_id is not None else 2)
        provenance = _verified_hp_provenance(
            bound.model_gate, work, worker_id, row,
            max_analysis_turns=provenance_cap)
        proposal_ids = [item.get("assertion_id") for item in proposals
                        if type(item) is dict]
        if (len(proposal_ids) != len(proposals) or
                any(type(identifier) is not str or
                    re.fullmatch(r"[A-Za-z0-9_-]+", identifier) is None
                    for identifier in proposal_ids) or
                len(set(proposal_ids)) != len(proposal_ids)):
            raise ValueError("HP Assertion IDs are missing or duplicated")
        proposed = [item for item in proposals if type(item) is dict and
                    item.get("status") == "PROPOSED"]
        if not proposed:
            return {"status": "HP_ASSERTION_HANDOFF_BLOCKED",
                    "reason": "NO_PROPOSED_ASSERTION",
                    "sp_global_effect": "UNCHANGED",
                    "security_gate_credit": "NOT_CREDITED",
                    "discovery_credit": "NOT_CREDITED"}
        try:
            ranked = sorted(proposed, key=lambda item: (
                int(item["source_location"].rsplit(":", 1)[1]),
                item["assertion_id"]))
            if any(int(item["source_location"].rsplit(":", 1)[1]) < 1
                   for item in ranked):
                raise ValueError("HP Assertion source line is invalid")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ValueError("HP Assertion selection input is invalid") from exc
        assertion_id = ranked[0]["assertion_id"]
        selection = {"policy": "SOURCE_LINE_THEN_ASSERTION_ID_V1",
                     "proposed_count": len(ranked),
                     "selected_assertion_id": assertion_id,
                     "not_run": [
                         {"assertion_id": item["assertion_id"],
                          "status": "NOT_RUN",
                          "reason": "BUDGET_NOT_SELECTED"}
                         for item in ranked[1:]]}
        state, before_sha = bound.process_ledger.receipt_snapshot()
        if not _hp_physical_budget_available(
                state, physical,
                parallel_hp_execution=parallel_hp_execution):
            raise ValueError("HP physical shared budget is unavailable")
        if not _private_directory(root):
            raise ValueError("HP physical claim directory is unsafe")
        proposal_sha = hashlib.sha256(canonical(row)).hexdigest()
        # A fixed run-level path forbids a second physical attempt even if a
        # different Assertion ID is later presented to this factory.
        claim_path = root / "HP_PHYSICAL_CLAIM.json"
        claim = {"kind": "FBV2_HP_PHYSICAL_CLAIM_V1",
                 "task_id": bound.identity.task_id,
                 "run_id": bound.identity.run_id,
                 "worker_id": worker_id,
                 "function_id": work.function_id,
                 "direction_id": work.direction_id,
                 "assertion_id": assertion_id,
                 "assertion_selection": selection,
                 "proposal_sha256": proposal_sha,
                 "hp_model_provenance": provenance,
                 "hp_model_provenance_sha256": hashlib.sha256(
                     canonical(provenance)).hexdigest(),
                 "source_sha256": work.source_sha256,
                 "source_tree_sha256": work.source_tree_sha256,
                 "harness_sha256": work.harness_sha256,
                 "binary_sha256": work.binary_sha256,
                 "builder_sha256": physical["builder_sha256"],
                 "manifest_sha256": physical["manifest_sha256"],
                 "build_command": build_command,
                 "build_command_sha256": hashlib.sha256(
                     canonical(build_command)).hexdigest(),
                 "spec_sha256": spec_sha256,
                 "process_ledger_sha256_before": before_sha}
        claim_sha = _write_once(claim_path, claim)

        def pin(_phase: str, _command: list[str]) -> None:
            recheck(work, claim_path, claim_sha)

        envelope = DevelopmentProcessEnvelopeV2(
            bound.process_ledger, work_item_id=bound.identity.task_id,
            assertion_id=assertion_id, attempt_id=bound.identity.run_id,
            output_limit_bytes=physical["output_limit_bytes"],
            total_wall_seconds=physical["total_wall_seconds"], pin_hook=pin,
            wall_limit_scope=("LOCAL" if parallel_hp_execution else "GLOBAL"))
        result = run_prepared_hp_assertion_handoff(
            work=work, qualification=q, analysis_result=row,
            worker_id=worker_id, assertion_id=assertion_id,
            output_dir=root / "hp-physical" / assertion_id,
            build_command=build_command,
            run_command=["{binary}", "{input}"],
            guided_seconds=physical["guided_seconds"],
            timeout_seconds=30.0, provider_free_fixture=False,
            builder_manifest_path=manifest,
            builder_manifest_sha256=physical["manifest_sha256"],
            live_process_envelope=envelope,
            live_claim_path=claim_path,
            live_claim_sha256=claim_sha)
        result["physical_claim_path"] = str(claim_path)
        result["physical_claim_sha256"] = claim_sha
        result["process_ledger_sha256_before"] = before_sha
        result["assertion_selection"] = selection
        return result

    return handoff


def _prepare_signed_hp_only(bound: Any, hp: dict[str, Any],
                            control: dict[str, Any], *,
                            spec_path: Path, spec_sha256: str):
    """Claim one explicit manual HP function without inventing an SP Worker.

    The function comes from the qualified prebuilt catalog. The Direction is
    labelled as manual context and is never inserted as an FBv2 model result.
    This only establishes eligibility for model analysis, not a SAFE or bug.
    """
    from bson import ObjectId
    from fuzzingbrain.core.models.direction import Direction
    from fuzzingbrain.core.models.function import Function
    from devtools.original_hp_preparation import (
        PreparedHPFunction, prepare_hp_function)

    raw = _check_signed_spec(Path(spec_path), spec_sha256)
    signed = json.loads(raw)
    control_keys = {
        "enabled", "function_name", "automatic_discovery",
        "source_tree_sha256", "functions_json_sha256"}
    optional_control_keys = {"max_context_reanalyses",
                             "assumption_evidence_closure"}
    if (signed.get("hp") != hp or signed.get("hp_only") != control or
            type(control) is not dict or
            not control_keys <= set(control) or
            set(control) - control_keys - optional_control_keys or
            control.get("enabled") is not True or
            control.get("automatic_discovery") is not False):
        raise ValueError("HP-only manual selection differs from signed spec")
    validate_hp_spec(hp, bound.identity.product_src, enabled=True,
                     hp_only=True)
    bound.recheck()
    identity = bound.identity
    q = bound.admission.qualification
    if (control["source_tree_sha256"] != q.source_tree_sha256 or
            bound.model_gate.snapshot().get("physical") != 0 or
            bound.model_gate.snapshot().get("records") != []):
        raise ValueError("HP-only source pin or model account is not fresh")
    lifecycle_admission = _validate_assumption_lifecycle_live_approval(
        bound, hp, control, spec_path=Path(spec_path),
        spec_sha256=spec_sha256)
    state, state_sha = bound.process_ledger.receipt_snapshot()
    if (state.get("stop_status") is not None or state.get("active") or
            state.get("finished") != [] or not _private_directory(identity.run_dir)):
        raise ValueError("HP-only process account is not fresh")
    catalog_path = (Path(bound.admission.prepared["prebuild_dir"]) /
                    "mongodb" / "functions.json")
    catalog_raw = catalog_path.read_bytes()
    if (catalog_path.is_symlink() or
            hashlib.sha256(catalog_raw).hexdigest() !=
                control["functions_json_sha256"]):
        raise ValueError("HP-only qualified function catalog changed")
    catalog = json.loads(catalog_raw)
    if type(catalog) is not list:
        raise ValueError("HP-only function catalog is invalid")
    fuzzer = bound.executor.fuzzer
    matching = [row for row in catalog if type(row) is dict and
                row.get("name") == control["function_name"] and
                type(row.get("reached_by_fuzzers")) is list and
                fuzzer in row.get("reached_by_fuzzers", [])]
    if len(matching) != 1:
        raise ValueError("HP-only selected function is not uniquely reachable")
    row = matching[0]
    if (type(row.get("file_path")) is not str or
            type(row.get("content")) is not str or
            type(row.get("start_line")) is not int or
            type(row.get("end_line")) is not int):
        raise ValueError("HP-only function catalog row is incomplete")
    function = Function(
        task_id=identity.task_id, name=row["name"],
        file_path=row["file_path"], content=row["content"],
        start_line=row["start_line"], end_line=row["end_line"],
        reached_by_fuzzers=[fuzzer])
    direction = Direction(
        direction_id=str(ObjectId()), task_id=identity.task_id,
        fuzzer=fuzzer, name="Manual HP control context",
        risk_level="unknown",
        risk_reason="Explicitly selected for HP integration control",
        core_functions=[function.name], entry_functions=[])
    actor_id = "hp-control:" + identity.run_id
    claim = {
        "kind": "FBV2_HP_ONLY_SELECTION_CLAIM_V1",
        "task_id": identity.task_id, "run_id": identity.run_id,
        "actor_id": actor_id, "function_id": function.function_id,
        "function_name": function.name, "direction_id": direction.direction_id,
        "source_tree_sha256": q.source_tree_sha256,
        "contract_sha256": q.contract_sha256,
        "functions_json_sha256": control["functions_json_sha256"],
        "catalog_row_sha256": hashlib.sha256(json.dumps(
            row, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode()).hexdigest(),
        "spec_sha256": spec_sha256,
        "model_receipt_before_sha256": hashlib.sha256(json.dumps(
            bound.model_gate.snapshot(), sort_keys=True, default=str,
            separators=(",", ":")).encode()).hexdigest(),
        "process_receipt_before_sha256": state_sha,
        "automatic_discovery": False,
    }
    claim_path = identity.run_dir / "HP_ONLY_SELECTION_CLAIM.json"
    claim_sha = _write_once(claim_path, claim)
    evidence = {
        "origin": "SIGNED_MANUAL_HP_CONTROL",
        "task_id": identity.task_id, "run_id": identity.run_id,
        "function_id": function.function_id,
        "direction_id": direction.direction_id,
        "source_tree_sha256": q.source_tree_sha256,
        "contract_sha256": q.contract_sha256,
        "spec_sha256": spec_sha256,
        "selection_claim_sha256": claim_sha,
    }

    def recheck_selection():
        current = _check_signed_spec(Path(spec_path), spec_sha256)
        body = json.loads(current)
        if (body.get("hp") != hp or body.get("hp_only") != control or
                catalog_path.is_symlink() or
                hashlib.sha256(catalog_path.read_bytes()).hexdigest() !=
                    control["functions_json_sha256"] or
                claim_path.is_symlink() or
                hashlib.sha256(claim_path.read_bytes()).hexdigest() != claim_sha or
                json.loads(claim_path.read_bytes()) != claim or
                q.source_tree_sha256 != control["source_tree_sha256"]):
            raise ValueError("HP-only signed selection or claim changed")
        if lifecycle_admission is not None:
            current_admission = _validate_assumption_lifecycle_live_approval(
                bound, hp, control, spec_path=Path(spec_path),
                spec_sha256=spec_sha256)
            if current_admission != lifecycle_admission:
                raise ValueError("HP assumption lifecycle live approval changed")
        bound.recheck()

    recheck_selection()
    prepared = prepare_hp_function(
        function=function, direction=direction, qualification=q,
        fuzzer=fuzzer, sanitizer="address",
        signed_manual_hp_selection_evidence=evidence)
    if type(prepared) is not PreparedHPFunction:
        return prepared, actor_id, recheck_selection, claim_sha
    if (prepared.selection_origin != "SIGNED_MANUAL_HP_CONTROL" or
            prepared.analysis_scope.get("selection_evidence") != evidence):
        raise ValueError("HP-only prepared selection provenance changed")
    return prepared, actor_id, recheck_selection, claim_sha


def run_signed_hp_only(bound: Any, hp: dict[str, Any],
                       control: dict[str, Any], *, spec_path: Path,
                       spec_sha256: str) -> dict[str, Any]:
    """One manual HP control using actual model roles and qualified execution.

    This run has no original Worker or SP selection and earns no automatic
    discovery/Gate credit. The model and process accounts remain shared with
    the pinned public-development bound, but no FBv2 Worker is launched.
    """
    from devtools.original_hp_preparation import (
        PreparedHPFunction, _qualified_context_build_command,
        _qualified_context_process_envelope,
        run_prepared_hp_analysis)

    prepared, actor_id, selection_check, claim_sha = _prepare_signed_hp_only(
        bound, hp, control, spec_path=spec_path, spec_sha256=spec_sha256)
    lifecycle_admission = _validate_assumption_lifecycle_live_approval(
        bound, hp, control, spec_path=Path(spec_path),
        spec_sha256=spec_sha256)
    root = bound.identity.run_dir
    before = bound.model_gate.snapshot()["physical"]
    analysis_row: dict[str, Any]
    physical: dict[str, Any] | None = None
    close_error = False
    if type(prepared) is not PreparedHPFunction:
        analysis_row = prepared
    else:
        selection_check()
        analysis = _pipeline_factory(
            bound, hp, "function_analysis", spec_path, spec_sha256,
            extra_check=selection_check, hp_only=True)(prepared)
        assertion = _pipeline_factory(
            bound, hp, "assertion_generator", spec_path, spec_sha256,
            extra_check=selection_check, hp_only=True)(prepared)
        async def analyze_and_close():
            nonlocal close_error
            try:
                context_command, context_pins, context_environment = (
                    _qualified_context_build_command(
                        prepared, bound.admission.qualification,
                        hp.get("physical")))
                context_envelope = _qualified_context_process_envelope(
                    bound, prepared, bound.admission.qualification,
                    hp.get("physical"), selection_check)
                return await run_prepared_hp_analysis(
                    work=prepared,
                    qualification=bound.admission.qualification,
                    analysis_pipeline=analysis, assertion_pipeline=assertion,
                    worker_id=actor_id,
                    context_build_command=context_command,
                    context_source_hashes=context_pins,
                    context_build_environment=context_environment,
                    context_process_envelope=context_envelope,
                    catalog_manifest_path=Path(
                        bound.admission.summary["manifest_path"]),
                    catalog_manifest_sha256=bound.admission.summary[
                        "manifest_sha256"],
                    max_context_reanalyses=control.get(
                        "max_context_reanalyses", 2),
                    signed_manual_third_context_round=(
                        control.get("max_context_reanalyses") == 3),
                    per_assumption_evidence_closure=(
                        lifecycle_admission is not None),
                    assumption_lifecycle_live_admission=lifecycle_admission)
            finally:
                for pipeline in (assertion, analysis):
                    try:
                        await pipeline.provider.close()
                    except Exception:
                        close_error = True
        try:
            analysis_row = asyncio.run(analyze_and_close())
        except Exception as exc:
            analysis_row = {"status": "INCOMPLETE_HP_MODEL_ERROR",
                            "error_type": type(exc).__name__}
    try:
        selection_check()
        after_model = bound.model_gate.snapshot()
        process_before, process_before_sha = bound.process_ledger.receipt_snapshot()
        after_count = after_model.get("physical")
        accounts_ok = (not close_error and
                       type(after_count) is int and
                       before <= after_count <= before +
                           hp["max_model_calls"] and
                       _settled_model(bound.model_gate, after_model) and
                       process_before.get("stop_status") is None and
                       not process_before.get("active"))
    except Exception:
        accounts_ok = False
        after_model = bound.model_gate.snapshot()
        process_before, process_before_sha = bound.process_ledger.receipt_snapshot()
    if not accounts_ok:
        status = "HP_ONLY_ACCOUNT_UNSETTLED"
        physical_status = "NOT_RUN"
    elif (type(prepared) is PreparedHPFunction and
          analysis_row.get("status") == "ASSERTIONS_PROPOSED_UNVERIFIED" and
          not (type(analysis_row.get("proposed_assertion_count")) is int and
               analysis_row["proposed_assertion_count"] == 0 and
               analysis_row.get("assertion_proposals") == [])):
        before_finished = process_before.get("finished")
        if type(before_finished) is not list:
            raise ValueError("HP-only physical ledger is unavailable")
        before_keys = {item.get("key") for item in before_finished
                       if type(item) is dict}
        try:
            physical = _physical_handoff_factory(
                bound, hp, None, spec_path, spec_sha256,
                actor_id=actor_id,
                signed_max_analysis_turns=(
                    control.get("max_context_reanalyses", 2) + 1),
                extra_check=selection_check)(
                    prepared, analysis_row)
        except Exception as exc:
            physical = {"status": "INCOMPLETE_HP_ASSERTION_HANDOFF",
                        "error_type": type(exc).__name__}
        process_after, process_after_sha = bound.process_ledger.receipt_snapshot()
        finished = process_after.get("finished")
        new = ([item for item in finished if type(item) is dict and
                item.get("key") not in before_keys]
               if type(finished) is list else [])
        prefix = (f"{bound.identity.task_id}:"
                  f"{physical.get('assertion_id')}:"
                  f"{bound.identity.run_id}:")
        numeric = lambda value: (type(value) in (int, float) and
                                 math.isfinite(value) and value >= 0)
        accounted = (
            bool(new) and process_after.get("stop_status") is None and
            not process_after.get("active") and
            all(type(item.get("key")) is str and
                item["key"].startswith(prefix) and
                item.get("kind") in {"AUX_PROCESS", "HP_FUZZ"} and
                item.get("cleanup_complete") is True and
                item.get("overrun") is False and
                numeric(item.get("physical_seconds")) for item in new) and
            any(item.get("kind") == "HP_FUZZ" and
                item["key"].endswith(":guided.initial_campaign")
                for item in new) and
            all(numeric(value) for value in (
                process_before.get("wall_spent_seconds"),
                process_after.get("wall_spent_seconds"),
                process_before.get("fuzz_spent_seconds"),
                process_after.get("fuzz_spent_seconds"))) and
            math.isclose(
                process_after["wall_spent_seconds"] -
                process_before["wall_spent_seconds"],
                math.fsum(item["physical_seconds"] for item in new),
                rel_tol=0, abs_tol=1e-9) and
            math.isclose(
                process_after["fuzz_spent_seconds"] -
                process_before["fuzz_spent_seconds"],
                math.fsum(item["physical_seconds"] for item in new
                          if item["kind"] == "HP_FUZZ"),
                rel_tol=0, abs_tol=1e-9))
        guided = physical.get("guided_report")
        complete = (
            physical.get("status") == "HP_ASSERTION_HANDOFF_COMPLETE" and
            physical.get("function_id") == prepared.function_id and
            physical.get("direction_id") == prepared.direction_id and
            physical.get("source_sha256") == prepared.source_sha256 and
            physical.get("seed_sha256") ==
                bound.admission.qualification.normal_seed_sha256 and
            physical.get("guided_status") in
                {"RAN", "ASSERTION_WITNESS_OBSERVED"} and
            type(guided) is dict and
            guided.get("status") == physical.get("guided_status") and
            guided.get("assertion_id") == physical.get("assertion_id") and
            type(guided.get("fuzzer_run_count")) is int and
            guided["fuzzer_run_count"] >= 1 and accounted and
            process_before_sha != process_after_sha)
        status = "HP_ONLY_PHYSICAL_COMPLETE" if complete else "HP_ONLY_PHYSICAL_INCOMPLETE"
        physical_status = "COMPLETE" if complete else "INCOMPLETE"
    else:
        status = ("HP_ONLY_NO_PROPOSAL" if
                  analysis_row.get("status") in {
                    "NO_SAFE_ASSUMPTION", "NO_ASSERTION_PROPOSAL"} or
                  (analysis_row.get("status") ==
                       "ASSERTIONS_PROPOSED_UNVERIFIED" and
                   type(analysis_row.get("proposed_assertion_count")) is int and
                   analysis_row["proposed_assertion_count"] == 0 and
                   analysis_row.get("assertion_proposals") == []) else
                  "HP_ONLY_ANALYSIS_INCOMPLETE")
        physical_status = ("NOT_RUN_NO_PROPOSAL" if
                           status == "HP_ONLY_NO_PROPOSAL" else
                           "NOT_RUN_ANALYSIS_INCOMPLETE")
    model_snapshot = bound.model_gate.snapshot()
    process_snapshot, process_sha = bound.process_ledger.receipt_snapshot()
    receipt = {
        "kind": "FBV2_HP_ONLY_RESULT_V1",
        "task_id": bound.identity.task_id, "run_id": bound.identity.run_id,
        "actor_id": actor_id, "selection_origin": "SIGNED_MANUAL_HP_CONTROL",
        "selection_claim_sha256": claim_sha,
        "spec_sha256": spec_sha256, "analysis": analysis_row,
        "physical": physical, "status": status,
        "physical_execution_status": physical_status,
        "model_physical_calls": model_snapshot.get("physical"),
        "process_receipt_sha256": process_sha,
        "process_active_count": len(process_snapshot.get("active", {})),
        "automatic_discovery": False,
        "security_gate_credit": "NOT_CREDITED",
    }
    result_path = root / "HP_ONLY_RESULT.json"
    result_sha = _write_once(result_path, receipt)
    mongo = _persist_hp_only_result(bound, result_path, result_sha)
    return {"status": status, "result_path": str(result_path),
            "result_sha256": result_sha,
            "mongo_persistence_status": mongo["status"],
            "mongo_record_id": mongo["record_id"],
            "model_physical_calls": model_snapshot.get("physical"),
            "process_active_count": receipt["process_active_count"],
            "physical_execution_status": physical_status,
            "automatic_discovery": False,
            "security_gate_credit": "NOT_CREDITED"}


def run_signed_hp_after_worker(bound: Any, worker_receipt: dict[str, Any],
                               hp: dict[str, Any], *, spec_path: Path,
                               spec_sha256: str
                               ) -> dict[str, Any]:
    """Consume one signed HP opportunity; persist outcome separately."""
    spec_path = Path(spec_path)
    _check_signed_hp_spec(spec_path, spec_sha256, hp)
    validate_hp_spec(hp, bound.identity.product_src, enabled=True,
                     bounded_nohint_hp=bool(getattr(
                         getattr(bound, "caps", None),
                         "bounded_nohint_dev", False)))
    bound.recheck()
    before = bound.model_gate.snapshot()["physical"]
    root = bound.identity.run_dir
    selection_error = None
    selection_receipt_sha256 = None
    selection_contract_kind = None
    try:
        expected_pair = _signed_bounded_hp_pair(
            bound, worker_receipt, spec_path, spec_sha256)
        if expected_pair is not None:
            selection_contract_kind = "SIGNED_BOUNDED_AUTO_SELECTION_V1"
        if expected_pair is None:
            combined = _combined_concurrent_hp_selection(
                bound, worker_receipt, spec_path, spec_sha256)
            if combined is not None:
                expected_pair, selection_receipt_sha256 = combined
                selection_contract_kind = (
                    "SIGNED_CONCURRENT_POST_WORKER_SELECTION_V1")
                if expected_pair is None:
                    selection_error = "HP_NO_ELIGIBLE_POST_WORKER_PAIR"
    except ValueError as exc:
        expected_pair = None
        selection_error = str(exc)
    if selection_error is None:
        selection_error = _preflight(bound, worker_receipt)
    if selection_error is not None:
        hp_result = {"status": "HP_POST_WORKER_BLOCKED",
                     "reason": selection_error,
                     "sp_global_effect": "UNCHANGED",
                     "security_gate_credit": "NOT_CREDITED"}
        claim_sha = None
    elif before + hp["max_model_calls"] > bound.caps.physical_model_calls:
        hp_result = {"status": "HP_POST_WORKER_BLOCKED",
                     "reason": "HP_MODEL_BUDGET_UNAVAILABLE",
                     "sp_global_effect": "UNCHANGED",
                     "security_gate_credit": "NOT_CREDITED"}
        claim_sha = None
    else:
        claim_sha = _claim_hp_run(
            bound, worker_receipt, hp, spec_sha256,
            selection_receipt_sha256=selection_receipt_sha256,
            selected_pair=(expected_pair
                           if selection_receipt_sha256 is not None else None))
        def selection_check() -> None:
            _check_signed_hp_spec(spec_path, spec_sha256, hp)
            current_pair = _signed_bounded_hp_pair(
                bound, worker_receipt, spec_path, spec_sha256)
            current_selection_sha = None
            if current_pair is None and selection_receipt_sha256 is not None:
                current = _combined_concurrent_hp_selection(
                    bound, worker_receipt, spec_path, spec_sha256)
                if current is None:
                    raise ValueError("HP signed selection changed")
                current_pair, current_selection_sha = current
            if (current_pair != expected_pair or
                    current_selection_sha != selection_receipt_sha256 or
                    hashlib.sha256((root / "HP_RUN_CLAIM.json").read_bytes()
                                   ).hexdigest() != claim_sha):
                raise ValueError("HP signed selection changed")
            bound.recheck()
        try:
            physical_factory = _physical_handoff_factory(
                bound, hp, worker_receipt, spec_path, spec_sha256,
                extra_check=selection_check)
            hp_result = asyncio.run(run_post_worker_hp(
                bound=bound, worker_receipt=worker_receipt,
                analysis_pipeline_factory=_pipeline_factory(
                    bound, hp, "function_analysis", spec_path, spec_sha256,
                    extra_check=selection_check),
                assertion_pipeline_factory=_pipeline_factory(
                    bound, hp, "assertion_generator", spec_path, spec_sha256,
                    extra_check=selection_check),
                max_items=hp["max_items"],
                physical_handoff_factory=physical_factory,
                expected_selected_pair=expected_pair,
                hp_run_claim_sha256=claim_sha,
                signed_post_worker_selection_sha256=
                    selection_receipt_sha256,
                selection_contract_kind=selection_contract_kind,
                context_physical=hp.get("physical"),
                context_pin_check=selection_check))
        except BaseException as exc:
            hp_result = {"status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                         "reason": "HP_UNEXPECTED_EXCEPTION",
                         "error_type": type(exc).__name__,
                         "sp_global_effect": "UNCHANGED",
                         "security_gate_credit": "NOT_CREDITED"}
    after = bound.model_gate.snapshot()["physical"]
    process, process_sha = bound.process_ledger.receipt_snapshot()
    try:
        _check_signed_hp_spec(spec_path, spec_sha256, hp)
        validate_hp_spec(hp, bound.identity.product_src, enabled=True,
                         bounded_nohint_hp=bool(getattr(
                             getattr(bound, "caps", None),
                             "bounded_nohint_dev", False)))
        bound.recheck()
        pins_ok = True
    except Exception:
        pins_ok = False
    if (not pins_ok or after < before or
            after - before > hp["max_model_calls"] or
            process.get("stop_status") is not None or process.get("active")):
        hp_result = {"status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                     "reason": "HP_PHYSICAL_ACCOUNT_UNSETTLED",
                     "sp_global_effect": "UNCHANGED",
                     "security_gate_credit": "NOT_CREDITED"}
    elif hp_result.get("status") == "HP_POST_WORKER_COMPLETE":
        rows = hp_result.get("rows")
        if type(rows) is not list or hp_result.get("selected_count") == 0:
            hp_result = {**hp_result, "status": "HP_POST_WORKER_NO_OPPORTUNITY",
                         "reason": "NO_SP_ANALYZED_FUNCTION"}
        elif any(type(row) is not dict or
                 str(row.get("status", "")).startswith("INCOMPLETE")
                 for row in rows):
            hp_result = {**hp_result,
                         "status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                         "reason": "HP_ITEM_INCOMPLETE"}
    physical_requested = hp.get("physical") is not None
    if hp_result.get("status") == "HP_POST_WORKER_COMPLETE":
        physical_status = hp_result.get("physical_execution_status")
        if not physical_requested:
            hp_result = {**hp_result,
                         "analysis_status": "COMPLETE",
                         "physical_execution_status": "NOT_REQUESTED"}
        elif physical_status not in {"COMPLETE", "NOT_RUN_NO_PROPOSAL"}:
            hp_result = {**hp_result,
                         "status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                         "reason": "HP_PHYSICAL_COMPLETION_UNPROVEN"}
    physical_status = hp_result.get("physical_execution_status", "UNKNOWN")
    receipt = {"kind": "FBV2_PUBLIC_DEV_HP_RESULT_V1",
               "task_id": bound.identity.task_id,
               "run_id": bound.identity.run_id,
               "worker_id": worker_receipt["original_result"]["worker_id"],
               "claim_sha256": claim_sha,
               "hp_assets": hp["assets"],
               "max_items": hp["max_items"],
               "max_model_calls": hp["max_model_calls"],
               "model_physical_before": before,
               "model_physical_after": after,
               "process_receipt_sha256_after": process_sha,
               "hp_result": hp_result,
               "analysis_status": hp_result.get("analysis_status", "INCOMPLETE"),
               "physical_execution_status": physical_status,
               "completion_scope": ("PHYSICAL_HANDOFF_COMPLETE" if
                   physical_status == "COMPLETE" else "ANALYSIS_ONLY" if
                   physical_status in {"NOT_REQUESTED", "NOT_RUN_NO_PROPOSAL"}
                   else "INCOMPLETE"),
               "original_status": worker_receipt.get("status"),
               "sp_global_effect": "UNCHANGED",
               "security_gate_credit": "NOT_CREDITED"}
    if selection_receipt_sha256 is not None:
        receipt["selection_receipt_sha256"] = selection_receipt_sha256
        receipt["selected_pair"] = list(expected_pair)
    receipt_sha = _write_once(root / _HP_RESULT, receipt)
    return {"status": hp_result["status"], "result_path": str(root / _HP_RESULT),
            "result_sha256": receipt_sha, "model_physical_calls": after - before,
            "analysis_status": receipt["analysis_status"],
            "physical_execution_status": physical_status,
            "completion_scope": receipt["completion_scope"],
            "sp_global_effect": "UNCHANGED",
            "security_gate_credit": "NOT_CREDITED"}
