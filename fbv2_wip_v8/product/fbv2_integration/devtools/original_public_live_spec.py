"""Create a reviewable, provider-free public-development live spec.

This only records current source/artifact pins and narrow physical caps. A
separate SHA-256 must be reviewed and supplied to the fresh live entry. No
model, target, fuzzer, Blind 3, or Oracle operation occurs here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from bson import ObjectId

from devtools.original_public_dev import admit_pinned
from devtools.original_public_live import python_tree_sha256
from devtools.original_hp_live_optin import hp_asset_hashes


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("product-src", "evaluation-dir", "contract-path",
                 "manifest-path", "task-path", "oss-fuzz-checkout",
                 "upstream-checkout", "codex-executable", "run-dir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--codex-model", required=True)
    parser.add_argument("--enable-hp", action="store_true",
                        help="pin a separate one-item, three-turn HP opt-in")
    parser.add_argument("--hp-physical-builder", type=Path,
                        help="pin the existing qualified md4c Assertion relinker")
    parser.add_argument("--hp-physical-manifest", type=Path,
                        help="pin that relinker's source/binary manifest")
    parser.add_argument("--manual-sp-function",
                        help="pin one public-development manual SP control function")
    parser.add_argument("--enable-sp-fuzz", action="store_true",
                        help="pin one bounded SP fuzz attempt for Provider-free admission")
    parser.add_argument("--sp-fuzz-seconds", type=int, default=0,
                        help="SP fuzz seconds, 1..10 only with --enable-sp-fuzz")
    parser.add_argument("--mongo-url", required=True)
    parser.add_argument("--mongo-database-prefix", default="fbv2_public_dev")
    args = parser.parse_args(argv)
    if args.enable_hp and args.manual_sp_function:
        parser.error("manual SP control and HP opt-in require separate specs")
    if (args.hp_physical_builder is None) != (args.hp_physical_manifest is None):
        parser.error("HP physical builder and manifest must be supplied together")
    if args.hp_physical_builder is not None and not args.enable_hp:
        parser.error("HP physical recipe requires --enable-hp")
    if args.enable_sp_fuzz and (args.enable_hp or args.manual_sp_function):
        parser.error("SP fuzz, HP, and manual SP controls require separate specs")
    if ((args.enable_sp_fuzz and not 1 <= args.sp_fuzz_seconds <= 10) or
            (not args.enable_sp_fuzz and args.sp_fuzz_seconds != 0)):
        parser.error("SP fuzz seconds require an explicit 1..10 second opt-in")
    engine = Path(__file__).resolve().parent.parent
    product = args.product_src.resolve(strict=True)
    evaluation = args.evaluation_dir.resolve(strict=True)
    task = args.task_path.resolve(strict=True)
    contract = args.contract_path.resolve(strict=True)
    manifest = args.manifest_path.resolve(strict=True)
    executable = args.codex_executable.resolve(strict=True)
    output = args.output
    run_dir = args.run_dir
    if (not output.is_absolute() or output != output.resolve() or
            output.exists() or output.is_symlink() or
            not output.parent.is_dir() or
            not run_dir.is_absolute() or run_dir != run_dir.resolve() or
            run_dir.exists() or run_dir.is_symlink() or
            not run_dir.parent.is_dir() or not os.access(executable, os.X_OK)):
        raise ValueError("spec output, run directory, or Codex executable is unsafe")
    issuer = product / "vulnerabilityanalysis" / "official_harness.py"
    admit_pinned(product_src=product, product_issuer_sha256=_sha(issuer),
                 contract_path=contract, contract_sha256=_sha(contract),
                 manifest_path=manifest, manifest_sha256=_sha(manifest),
                 task_path=task, oss_fuzz_checkout=args.oss_fuzz_checkout,
                 upstream_checkout=args.upstream_checkout)
    task_id = str(ObjectId())
    run_id = str(ObjectId())
    spec = {
        "kind": "FBV2_ORIGINAL_PUBLIC_DEV_LIVE_SPEC_V1",
        "blind3_runs": 0, "oracle_queries": 0,
        "allow_synthetic_wire": False,
        "identity": {
            "task_id": task_id, "run_id": run_id,
            "engine_root": str(engine),
            "engine_py_sha256": python_tree_sha256(engine),
            "product_src": str(product),
            "product_py_sha256": python_tree_sha256(product),
            "evaluation_dir": str(evaluation),
            "evaluation_py_sha256": python_tree_sha256(evaluation),
            "codex_executable": str(executable),
            "codex_executable_sha256": _sha(executable),
            "codex_model": args.codex_model, "codex_effort": "medium",
            "mongo_url": args.mongo_url,
            "mongo_database": args.mongo_database_prefix + "_" + run_id,
            "task_path": str(task), "run_dir": str(run_dir),
        },
        "admission": {
            "product_issuer_sha256": _sha(issuer),
            "contract_path": str(contract),
            "contract_sha256": _sha(contract),
            "manifest_path": str(manifest),
            "manifest_sha256": _sha(manifest),
            "oss_fuzz_checkout": str(args.oss_fuzz_checkout),
            "upstream_checkout": str(args.upstream_checkout),
        },
        "caps": {
            "physical_model_calls": 15 if args.manual_sp_function else 32,
            "model_wall_seconds": 600,
            "calls_per_agent": 6 if args.manual_sp_function else 12,
            "total_wall_seconds": 2000 if args.enable_sp_fuzz else 1800,
            "total_fuzz_seconds": 90, "global_fuzz_seconds": 30,
            "global_reservation_seconds": 45,
            "global_replay_limit": 1, "pov_timeout_seconds": 10,
            "pov_wall_seconds": 25,
            "process_output_limit_bytes": 2_000_000,
            "gate_aux_reservation_seconds_per_observation": 600,
            "sp_fuzz_seconds": args.sp_fuzz_seconds,
            "sp_fuzz_max_items": 1 if args.enable_sp_fuzz else 0,
        },
        "hp": ({"enabled": True, "max_items": 1,
                "max_model_calls": 3, "assets": hp_asset_hashes(product)}
               if args.enable_hp else {"enabled": False}),
    }
    if args.enable_sp_fuzz:
        spec["sp_fuzz"] = {
            "enabled": True, "seconds_per_item": args.sp_fuzz_seconds,
            "max_items": 1,
        }
    if args.manual_sp_function:
        spec["manual_sp_control"] = {
            "enabled": True,
            "function_name": args.manual_sp_function,
            "max_model_calls_by_role": {"sp": 3, "verifier": 6, "pov": 6},
            "automatic_discovery": False,
        }
    if args.hp_physical_builder is not None:
        builder = args.hp_physical_builder
        builder_manifest = args.hp_physical_manifest
        if (not builder.is_absolute() or not builder_manifest.is_absolute() or
                builder.is_symlink() or builder_manifest.is_symlink() or
                builder != builder.resolve(strict=True) or
                builder_manifest != builder_manifest.resolve(strict=True) or
                builder_manifest != builder.with_name(
                    "multi_tu_assertion_build_manifest.json") or
                not builder.is_file() or not builder_manifest.is_file()):
            raise ValueError("HP physical builder and manifest are not pinned files")
        spec["hp"]["physical"] = {
            "enabled": True, "builder_path": str(builder),
            "builder_sha256": _sha(builder),
            "manifest_path": str(builder_manifest),
            "manifest_sha256": _sha(builder_manifest),
            "guided_seconds": 1, "total_wall_seconds": 120,
            "output_limit_bytes": 4_000_000,
        }
    data = (json.dumps(spec, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    print(json.dumps({"spec": str(output), "sha256": _sha(output),
                      "task_id": task_id, "run_id": run_id,
                      "model_calls_max": spec["caps"]["physical_model_calls"],
                      "global_seconds_max": 30,
                      "total_wall_seconds_max": spec["caps"]["total_wall_seconds"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
