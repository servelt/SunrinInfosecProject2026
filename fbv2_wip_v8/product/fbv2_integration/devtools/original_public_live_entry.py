"""Fresh-process, explicit public-development entry for original FBv2.

Run this file by absolute path with ``python -I -B``. It imports no FBv2 or
product code before checking an externally pinned spec and runtime source
trees. It never runs Blind 3 or Oracle. This is a development execution path;
its output is not a VERIFIED vulnerability verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TRUSTED_MD4C_HP_BUILDER = Path(
    "/home/dawne/SunrinInfosecProject2026/reference/"
    "blind2_v2_preparation_20261027/tools/multi_tu_assertion_build.py")
_TRUSTED_MD4C_HP_BUILDER_SHA256 = (
    "fbe9616f102d76205bb6d20b49c225f7043f5393d675c6387ea965d423139ffc")
_TRUSTED_MD4C_HP_MANIFEST_SHA256 = (
    "200d5248f835e3942dcd853934d309949b9b73354cb64956ca15cf5750539dd1")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _plain_pin(path: Path, wanted: str, label: str) -> None:
    if (not _SHA.fullmatch(wanted or "") or not path.is_absolute() or
            path.is_symlink() or path != path.resolve() or
            not path.is_file() or _sha(path) != wanted):
        raise ValueError(f"{label} pin changed before importing runtime")


def _runtime_tree_pin(root: Path, wanted: str, *, engine: bool) -> None:
    if (not _SHA.fullmatch(wanted or "") or not root.is_absolute() or
            root.is_symlink() or root != root.resolve() or not root.is_dir() or
            any(path.is_symlink() for path in root.rglob("*"))):
        raise ValueError("runtime source root changed before import")
    files = set(root.rglob("*.py"))
    if engine:
        prompts = root / "fuzzingbrain" / "agents" / "prompts"
        assets = {root / "fuzzingbrain" / "llm_config.yaml",
                  root / "fuzzingbrain" / "tools" / "tools.yaml"}
        if not prompts.is_dir():
            raise ValueError("original prompt directory missing")
        assets.update(prompts.glob("*.md"))
        if (len(assets) < 3 or
                any(not path.is_file() or path.is_symlink() for path in assets)):
            raise ValueError("original prompt/config assets missing")
        files.update(assets)
    if not files:
        raise ValueError("runtime source tree empty")
    digest = hashlib.sha256()
    for path in sorted(files):
        if not path.is_file() or path.is_symlink():
            raise ValueError("runtime source tree changed")
        name = path.relative_to(root).as_posix().encode()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    if digest.hexdigest() != wanted:
        raise ValueError("runtime source tree SHA-256 changed before import")


def _hp_preimport_admission(spec: dict, *, hp_mode: bool,
                            check_only: bool) -> bool:
    """Admit only fixed, pinned product HP assets before runtime imports."""
    hp = spec.get("hp")
    enabled = type(hp) is dict and hp.get("enabled") is True
    if not enabled:
        if hp_mode or hp not in (None, {"enabled": False}):
            raise ValueError("signed HP opt-in is absent")
        return False
    if not (hp_mode or check_only):
        raise ValueError("ordinary public development cannot enable HP")
    expected_keys = {"enabled", "max_items", "max_model_calls", "assets"}
    if "physical" in hp:
        expected_keys.add("physical")
    if (set(hp) != expected_keys or
            type(hp.get("max_items")) is not int or hp["max_items"] != 1 or
            type(hp.get("max_model_calls")) is not int or
            hp["max_model_calls"] != 3 or
            type(hp.get("assets")) is not dict or
            set(hp["assets"]) != {
                "function_analysis_prompt_sha256",
                "assertion_generator_prompt_sha256", "config_sha256"}):
        raise ValueError("signed HP item/model cap is invalid")
    root = Path(spec["identity"]["product_src"]).parent
    paths = {
        "function_analysis_prompt_sha256":
            root / "prompts" / "function_analysis.md",
        "assertion_generator_prompt_sha256":
            root / "prompts" / "assertion_generator.md",
        "config_sha256": root / "config" / "default.yaml",
    }
    for key, path in paths.items():
        _plain_pin(path, hp["assets"].get(key), "HP " + key)
    physical = hp.get("physical")
    if physical is not None:
        if (type(physical) is not dict or set(physical) != {
                "enabled", "builder_path", "builder_sha256",
                "manifest_path", "manifest_sha256", "guided_seconds",
                "total_wall_seconds", "output_limit_bytes"} or
                physical.get("enabled") is not True or
                type(physical.get("guided_seconds")) is not int or
                not 1 <= physical["guided_seconds"] <= 10 or
                type(physical.get("total_wall_seconds")) is not int or
                not 60 <= physical["total_wall_seconds"] <= 180 or
                type(physical.get("output_limit_bytes")) is not int or
                not 1 <= physical["output_limit_bytes"] <= 4_000_000 or
                type(physical.get("builder_path")) is not str or
                type(physical.get("manifest_path")) is not str):
            raise ValueError("signed HP physical recipe or cap is invalid")
        builder = Path(physical["builder_path"])
        manifest = Path(physical["manifest_path"])
        if (builder != _TRUSTED_MD4C_HP_BUILDER or
                physical.get("builder_sha256") !=
                    _TRUSTED_MD4C_HP_BUILDER_SHA256 or
                manifest != builder.with_name(
                    "multi_tu_assertion_build_manifest.json") or
                physical.get("manifest_sha256") !=
                    _TRUSTED_MD4C_HP_MANIFEST_SHA256):
            raise ValueError("signed HP physical builder is not trusted")
        _plain_pin(builder, physical.get("builder_sha256"), "HP physical builder")
        _plain_pin(manifest, physical.get("manifest_sha256"),
                   "HP physical builder manifest")
    return True


def _manual_sp_preimport_admission(spec: dict, *, manual_mode: bool,
                                   function_name: str | None,
                                   check_only: bool) -> None:
    """Pin one manually selected function and a narrow model budget."""
    control = spec.get("manual_sp_control")
    if control is None:
        if manual_mode:
            raise ValueError("signed manual SP control is absent")
        return
    if (type(control) is not dict or set(control) != {
            "enabled", "function_name", "max_model_calls_by_role",
            "automatic_discovery"} or control.get("enabled") is not True or
            control.get("automatic_discovery") is not False or
            type(control.get("function_name")) is not str or
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",
                             control["function_name"]) or
            control.get("max_model_calls_by_role") !=
                {"sp": 3, "verifier": 6, "pov": 6}):
        raise ValueError("signed manual SP control is invalid")
    caps = spec.get("caps")
    if (type(caps) is not dict or caps.get("calls_per_agent") != 6 or
            caps.get("physical_model_calls") != 15):
        raise ValueError("manual SP physical model cap is invalid")
    if manual_mode:
        if function_name != control["function_name"]:
            raise ValueError("manual SP function differs from signed spec")
    elif not check_only:
        raise ValueError("manual SP spec requires its explicit entry mode")


def _sp_fuzz_preimport_admission(spec: dict, *, check_only: bool) -> bool:
    """Admit a pinned SP process cap without opening its live execution path."""
    caps = spec.get("caps")
    optin = spec.get("sp_fuzz")
    if caps is None and optin is None:
        # Preserve the older source-pin failure order for a deliberately
        # minimal malformed spec. PublicDevCaps rejects it after imports.
        return False
    if type(caps) is not dict:
        raise ValueError("SP fuzz physical caps are absent")
    seconds = caps.get("sp_fuzz_seconds", 0)
    items = caps.get("sp_fuzz_max_items", 0)
    if optin is None:
        if (type(seconds) is not int or seconds != 0 or
                type(items) is not int or items != 0):
            raise ValueError("SP fuzz cap lacks signed opt-in")
        return False
    if (type(optin) is not dict or
            set(optin) != {"enabled", "seconds_per_item", "max_items"} or
            optin.get("enabled") is not True or
            type(seconds) is not int or not 1 <= seconds <= 10 or
            type(items) is not int or items != 1 or
            type(optin.get("seconds_per_item")) is not int or
            optin.get("seconds_per_item") != seconds or
            type(optin.get("max_items")) is not int or
            optin.get("max_items") != items or
            spec.get("manual_sp_control") is not None or
            type(spec.get("hp")) is dict and
            spec["hp"].get("enabled") is True):
        raise ValueError("signed SP fuzz opt-in or physical cap is invalid")
    if not check_only:
        raise ValueError("SP_FUZZ_LIVE_MODE_NOT_CONNECTED")
    return True


def _bootstrap(spec_path: Path, spec_sha256: str, *, authorized: bool,
               hp_mode: bool = False, manual_mode: bool = False,
               function_name: str | None = None,
               check_only: bool = False) -> dict:
    """Pin every import root before importing original/product/evaluation code."""
    if sys.flags.isolated != 1:
        raise ValueError("public live development requires python -I isolation")
    if authorized is not True:
        raise ValueError("explicit public development authorization is required")
    if any(name == "fuzzingbrain" or name.startswith("fuzzingbrain.") or
           name == "vulnerabilityanalysis" or
           name.startswith("vulnerabilityanalysis.") or
           name.startswith("dev_global_campaign") for name in sys.modules):
        raise ValueError("live development needs a fresh Python interpreter")
    _plain_pin(spec_path, spec_sha256, "public development spec")
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    if (type(spec) is not dict or spec.get("kind") !=
            "FBV2_ORIGINAL_PUBLIC_DEV_LIVE_SPEC_V1" or
            spec.get("blind3_runs") != 0 or spec.get("oracle_queries") != 0 or
            spec.get("allow_synthetic_wire") is not False):
        raise ValueError("only explicit public development is admitted")
    _manual_sp_preimport_admission(
        spec, manual_mode=manual_mode, function_name=function_name,
        check_only=check_only)
    _sp_fuzz_preimport_admission(spec, check_only=check_only)
    identity = spec["identity"]
    pin_fields = {
        "engine_root": "engine_py_sha256",
        "product_src": "product_py_sha256",
        "evaluation_dir": "evaluation_py_sha256",
    }
    for key, pin_field in pin_fields.items():
        root = Path(identity[key])
        _runtime_tree_pin(root, identity[pin_field],
                          engine=key == "engine_root")
    engine = Path(identity["engine_root"])
    if engine != Path(__file__).resolve().parent.parent:
        raise ValueError("launcher is outside pinned original engine")
    _plain_pin(Path(identity["codex_executable"]),
               identity["codex_executable_sha256"], "Codex executable")
    admission = spec["admission"]
    for key in ("contract", "manifest"):
        _plain_pin(Path(admission[key + "_path"]),
                   admission[key + "_sha256"], key)
    _plain_pin(Path(identity["product_src"]) / "vulnerabilityanalysis" /
               "official_harness.py", admission["product_issuer_sha256"],
               "product V2 qualification issuer")
    _hp_preimport_admission(spec, hp_mode=hp_mode, check_only=check_only)
    return spec


def _write_result_once(run_dir: Path, result: dict) -> None:
    """Preserve one final development receipt without replacing evidence."""
    if not run_dir.is_dir() or run_dir.is_symlink():
        return
    path = run_dir / "PUBLIC_DEV_RESULT.json"
    data = (json.dumps(result, sort_keys=True, default=str) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    parent_fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--spec-sha256", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--authorize-public-dev", action="store_true")
    mode.add_argument("--authorize-manual-sp-control", action="store_true")
    mode.add_argument("--authorize-public-dev-hp", action="store_true")
    mode.add_argument("--check-only", action="store_true")
    parser.add_argument("--function-name",
                        help="public development manual SP control, never discovery credit")
    args = parser.parse_args(argv)
    if args.authorize_manual_sp_control and not args.function_name:
        parser.error("--function-name is required for manual SP control")
    if args.function_name and not args.authorize_manual_sp_control:
        parser.error("--function-name is only valid for manual SP control")
    # The signed HP transport is still under provider-free review. Preserve
    # its spec/check-only path, but do not admit a physical HP campaign yet.
    if args.authorize_public_dev_hp:
        print(json.dumps({"status": "INCOMPLETE_ADMISSION",
                          "reason": "HP_LIVE_MODE_NOT_VALIDATED"}, sort_keys=True))
        return 2
    try:
        spec = _bootstrap(args.spec, args.spec_sha256,
                          authorized=(args.authorize_public_dev or
                                      args.authorize_manual_sp_control or
                                      args.authorize_public_dev_hp or
                                      args.check_only),
                          hp_mode=args.authorize_public_dev_hp,
                          manual_mode=args.authorize_manual_sp_control,
                          function_name=args.function_name,
                          check_only=args.check_only)
    except BaseException as exc:
        print(json.dumps({"status": "INCOMPLETE_ADMISSION",
                          "error_type": type(exc).__name__,
                          "reason": str(exc)}, sort_keys=True))
        return 2
    if args.check_only and type(spec.get("hp")) is dict and spec["hp"].get("enabled") is True:
        print(json.dumps({"status": "INCOMPLETE_ADMISSION",
                          "reason": "HP_LIVE_MODE_NOT_VALIDATED",
                          "hp_preimport_pins_verified": True,
                          "hp_physical_recipe_files_pinned":
                              type(spec["hp"].get("physical")) is dict,
                          "model_physical_calls": 0}, sort_keys=True))
        return 2

    # This witness is created only after this fresh __main__ script checked
    # the external spec/source pins, before loading any engine/product module.
    globals()["_PINNED_PUBLIC_BOOTSTRAP"] = {
        "pid": os.getpid(), "spec_path": str(args.spec),
        "spec_sha256": args.spec_sha256,
        "token": object(), "used": False,
        "engine_py_sha256": spec["identity"]["engine_py_sha256"],
        "product_py_sha256": spec["identity"]["product_py_sha256"],
        "evaluation_py_sha256": spec["identity"]["evaluation_py_sha256"],
        "hp_mode": args.authorize_public_dev_hp,
        "manual_sp_mode": args.authorize_manual_sp_control,
    }

    # A fresh bytecode cache prevents reuse of old pyc bytes from a prior run.
    # All roots are rechecked by the binder after import and before any call.
    with tempfile.TemporaryDirectory(prefix="fbv2-public-import-cache-") as cache:
        sys.pycache_prefix = cache
        identity_row = dict(spec["identity"])
        if args.check_only:
            identity_row["run_dir"] = str(Path(cache) / "preflight-run")
            identity_row["mongo_database"] += "_preflight"
        engine = Path(identity_row["engine_root"])
        product = Path(identity_row["product_src"])
        for root in (engine, product):
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
        from devtools.original_public_dev import admit_pinned
        from devtools.original_public_live import (
            PublicDevCaps, PublicDevIdentity, bind_original_public_dev,
            original_analysis_server_session, run_original_public_dev)

        admission_row = spec["admission"]
        bound = None
        try:
            admitted = admit_pinned(
                product_src=product,
                product_issuer_sha256=admission_row["product_issuer_sha256"],
                contract_path=Path(admission_row["contract_path"]),
                contract_sha256=admission_row["contract_sha256"],
                manifest_path=Path(admission_row["manifest_path"]),
                manifest_sha256=admission_row["manifest_sha256"],
                task_path=Path(identity_row["task_path"]),
                oss_fuzz_checkout=Path(admission_row["oss_fuzz_checkout"]),
                upstream_checkout=Path(admission_row["upstream_checkout"]))
            identity = PublicDevIdentity(**{
                key: Path(value) if key in {
                    "engine_root", "product_src", "evaluation_dir",
                    "codex_executable", "task_path", "run_dir"} else value
                for key, value in identity_row.items()})
            caps = PublicDevCaps(**spec["caps"])
            with original_analysis_server_session(admitted, identity) as server:
                bound = bind_original_public_dev(
                    admitted, identity, caps, server=server,
                    bootstrap_token=globals()["_PINNED_PUBLIC_BOOTSTRAP"]["token"])
                if args.check_only:
                    result = {
                        "status": "PREFLIGHT_READY", "task_id": identity.task_id,
                        "run_id": identity.run_id,
                        "model_physical_calls": bound.model_gate.snapshot()["physical"],
                        "process_wall_seconds": bound.process_ledger.snapshot()
                            ["wall_spent_seconds"],
                        "global_accounted": bound.global_campaign.ledger is
                            bound.process_ledger,
                        "pov_accounted": bound.pov_adapter.ledger is
                            bound.process_ledger,
                        "hp_enabled": (type(spec.get("hp")) is dict and
                                       spec["hp"].get("enabled") is True),
                        "hp_asset_pins_verified": True,
                        "sp_fuzz_enabled": spec.get("sp_fuzz") is not None,
                        "sp_fuzz_seconds_max": caps.sp_fuzz_seconds,
                    }
                else:
                    if args.authorize_manual_sp_control:
                        from devtools.manual_sp_control import run_manual_sp_control
                        result = run_manual_sp_control(
                            bound, args.function_name,
                            explicit_public_dev_authorization=True)
                    else:
                        result = run_original_public_dev(
                            bound, explicit_public_dev_authorization=True)
                    if args.authorize_public_dev_hp:
                        from devtools.original_hp_live_optin import (
                            run_signed_hp_after_worker)
                        try:
                            hp_result = run_signed_hp_after_worker(
                                bound, result, spec["hp"],
                                spec_path=args.spec,
                                spec_sha256=args.spec_sha256)
                        except BaseException as hp_exc:
                            hp_result = {"status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                                         "reason": "HP_SIGNED_EXECUTION_INCOMPLETE",
                                         "error_type": type(hp_exc).__name__,
                                         "sp_global_effect": "UNCHANGED",
                                         "security_gate_credit": "NOT_CREDITED"}
                        result = {**result, "hp_result": hp_result}
        except BaseException as exc:
            result = {"status": "INCOMPLETE", "error_type": type(exc).__name__,
                      "reason": str(exc),
                      "task_id": identity_row.get("task_id"),
                      "run_id": identity_row.get("run_id")}
            if bound is not None:
                try:
                    model = bound.model_gate.snapshot()
                    process = bound.process_ledger.snapshot()
                    result.update({
                        "model_physical_calls": model["physical"],
                        "process_wall_seconds": process["wall_spent_seconds"],
                        "process_fuzz_seconds": process["fuzz_spent_seconds"],
                        "process_stop_status": process["stop_status"],
                        "process_active_count": len(process["active"]),
                        "global_status": (bound.global_campaign.final_result or {})
                            .get("status"),
                    })
                except BaseException as accounting_exc:
                    result["accounting_error_type"] = type(accounting_exc).__name__
        try:
            _write_result_once(Path(identity_row["run_dir"]), result)
        except BaseException as receipt_exc:
            result["receipt_error_type"] = type(receipt_exc).__name__
            result["status"] = "INCOMPLETE"
        print(json.dumps(result, sort_keys=True, default=str))
        hp_ok = (not args.authorize_public_dev_hp or
                 result.get("hp_result", {}).get("status") ==
                    "HP_POST_WORKER_COMPLETE")
        return 0 if hp_ok and result.get("status") in {
            "PREFLIGHT_READY", "EXECUTED_UNVERIFIED",
            "MANUAL_SP_CONTROL_EXECUTED", "MANUAL_SP_CONTROL_NO_CANDIDATE",
        } else 1


if __name__ == "__main__":
    raise SystemExit(main())
