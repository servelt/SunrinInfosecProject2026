"""Create a reviewable, provider-free public-development live spec.

This only records current source/artifact pins and narrow physical caps. A
separate SHA-256 must be reviewed and supplied to the fresh live entry. No
model, target, fuzzer, Blind 3, or Oracle operation occurs here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re

from bson import ObjectId

from devtools.original_public_dev import admit_pinned
from devtools.original_public_live import (
    FULL_NOHINT_SP_ITERATION_POLICY, product_fbv2_role_models,
    python_tree_sha256, required_global_wall_reservation,
    required_total_fuzz_reservation, required_total_wall_reservation)
from devtools.original_hp_live_optin import hp_asset_hashes


_SECURITY_INVARIANT_FAMILIES = (
    "BOUNDS_EXTENT", "LIFETIME_OWNERSHIP", "ARITHMETIC_RANGE",
    "INITIALIZATION", "NULLABILITY", "STATE_CONSISTENCY",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("product-src", "evaluation-dir", "contract-path",
                 "manifest-path", "task-path", "oss-fuzz-checkout",
                 "upstream-checkout", "codex-executable", "run-dir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--codex-model", required=True)
    parser.add_argument("--bounded-nohint-dev", action="store_true",
                        help="pin two automatic Seed directions and three automatically selected SP functions")
    parser.add_argument("--sp-priority-one-seed-dev", action="store_true",
                        help="pin one automatic Seed direction and drain candidate queues between SP functions while keeping the full SP pool")
    parser.add_argument("--sp-concurrent-queue-dev", action="store_true",
                        help="replace per-function drain with concurrent persistent Discovery/Verifier/PoV pools under one shared campaign envelope")
    parser.add_argument("--parallel-hp-dev", action="store_true",
                        help="draft a separate SP/HP parallel profile for review; requires the concurrent SP queue and pinned HP physical recipe")
    parser.add_argument("--hp-gate-max-leads", type=int,
                        help="parallel HP Gate: number of frozen crash leads to examine (1..3, pinned in the spec)")
    parser.add_argument("--hp-gate-replay-wall-seconds", type=int,
                        help="parallel HP Gate: per-lead original replay wall cap")
    parser.add_argument("--hp-gate-source-wall-seconds", type=int,
                        help="parallel HP Gate: per-lead source attribution wall cap")
    parser.add_argument("--hp-guided-seconds", type=int,
                        help="parallel HP: explicit Guided fuzz duration (1..10 seconds)")
    parser.add_argument("--parallel-hp-model-turn-seconds", type=int,
                        help="parallel HP: explicit shared per-turn model deadline (300..600 seconds)")
    parser.add_argument("--sp-invariant-focus",
                        choices=_SECURITY_INVARIANT_FAMILIES,
                        help="target-independent invariant family used only for SP breadth scheduling")
    parser.add_argument("--sp-completion-dev", action="store_true",
                        help="one separately accounted no-hint SP completion diagnostic (80 total, 32 per agent, 1200 model seconds)")
    parser.add_argument("--sp-completion-extended-dev", action="store_true",
                        help="one separately accounted no-hint SP diagnostic (120 total, 64 per agent, 1500 model seconds)")
    parser.add_argument("--full-nohint-sp", action="store_true",
                        help="all five automatic Directions and the full SP pool, with no shared model call-count or campaign model wall cap; per-request timeout remains")
    parser.add_argument("--full-nohint-sp-process-wall-seconds", type=int,
                        help="required finite physical-process deadline for a new full SP profile")
    parser.add_argument("--full-nohint-sp-model-turn-seconds", type=int,
                        default=300,
                        help="signed per-request FullScan model deadline (300..1200 seconds)")
    parser.add_argument("--enable-hp", action="store_true",
                        help="pin a separate one-item HP opt-in (up to four analysis turns in bounded no-hint mode)")
    parser.add_argument("--hp-only-function",
                        help="manual HP control function; never discovery credit")
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
    if args.sp_completion_dev and args.sp_completion_extended_dev:
        parser.error("SP completion diagnostics are mutually exclusive")
    if args.sp_concurrent_queue_dev and not args.sp_priority_one_seed_dev:
        parser.error("concurrent SP queue requires --sp-priority-one-seed-dev")
    if args.sp_concurrent_queue_dev and not args.sp_completion_extended_dev:
        parser.error("concurrent SP queue requires the extended campaign wall envelope")
    if args.full_nohint_sp and (args.bounded_nohint_dev or
            args.sp_priority_one_seed_dev or args.sp_completion_dev or
            args.sp_completion_extended_dev or args.enable_hp or
            args.hp_only_function or args.manual_sp_function):
        parser.error("full no-hint SP requires the ordinary automatic SP path only")
    if args.full_nohint_sp and args.full_nohint_sp_process_wall_seconds is None:
        parser.error("full no-hint SP requires explicit process wall seconds")
    if args.full_nohint_sp_process_wall_seconds is not None and (
            not args.full_nohint_sp or
            args.full_nohint_sp_process_wall_seconds <= 0):
        parser.error("full SP process wall seconds require a positive full no-hint SP profile")
    if ((args.full_nohint_sp and not
         300 <= args.full_nohint_sp_model_turn_seconds <= 1200) or
            (not args.full_nohint_sp and
             args.full_nohint_sp_model_turn_seconds != 300)):
        parser.error("FullScan model turn seconds require a 300..1200 second full no-hint profile")
    if (args.sp_completion_dev and not
            (args.sp_priority_one_seed_dev or args.bounded_nohint_dev)):
        parser.error("SP completion diagnostic requires bounded or SP-priority development")
    if args.sp_completion_extended_dev and not args.sp_priority_one_seed_dev:
        parser.error("extended SP completion diagnostic requires --sp-priority-one-seed-dev")
    if args.enable_hp and args.manual_sp_function:
        parser.error("manual SP control and HP opt-in require separate specs")
    if args.bounded_nohint_dev and (args.manual_sp_function or
                                   args.enable_sp_fuzz or args.hp_only_function):
        parser.error("bounded no-hint development excludes manual controls and SP fuzz")
    combined_concurrent_hp = (
        args.sp_priority_one_seed_dev and args.sp_concurrent_queue_dev and
        args.sp_completion_extended_dev and args.enable_hp)
    if args.parallel_hp_dev and not combined_concurrent_hp:
        parser.error("parallel HP requires the concurrent SP/HP envelope")
    gate_limits = (args.hp_gate_max_leads,
                   args.hp_gate_replay_wall_seconds,
                   args.hp_gate_source_wall_seconds)
    if args.parallel_hp_dev and any(value is None for value in gate_limits):
        parser.error("parallel HP requires explicit Gate lead and wall limits")
    if args.parallel_hp_dev and args.hp_guided_seconds is None:
        parser.error("parallel HP requires explicit Guided fuzz seconds")
    if args.hp_guided_seconds is not None and (
            not args.parallel_hp_dev or
            not 1 <= args.hp_guided_seconds <= 10):
        parser.error("HP Guided seconds require a 1..10 second parallel profile")
    if (args.parallel_hp_dev and
            (args.parallel_hp_model_turn_seconds is None or
             not 300 <= args.parallel_hp_model_turn_seconds <= 600)):
        parser.error("parallel HP requires an explicit 300..600 second model turn cap")
    if (not args.parallel_hp_dev and
            args.parallel_hp_model_turn_seconds is not None):
        parser.error("parallel HP model turn cap requires the parallel profile")
    if not args.parallel_hp_dev and any(value is not None
                                        for value in gate_limits):
        parser.error("HP Gate limits require --parallel-hp-dev")
    if args.sp_priority_one_seed_dev and (
            args.bounded_nohint_dev or args.manual_sp_function or
            args.hp_only_function or
            (args.enable_hp and not combined_concurrent_hp) or
            args.enable_sp_fuzz):
        parser.error("SP-priority one-Seed development requires the ordinary no-hint SP path")
    if combined_concurrent_hp and args.hp_physical_builder is None:
        parser.error("concurrent post-Worker HP requires a pinned physical builder")
    if args.sp_priority_one_seed_dev != (args.sp_invariant_focus is not None):
        parser.error("SP-priority development requires exactly one invariant family")
    if (args.bounded_nohint_dev and args.enable_hp and
            args.hp_physical_builder is None):
        parser.error("bounded no-hint HP requires a pinned physical builder")
    if args.hp_only_function and not args.enable_hp:
        parser.error("HP-only control requires --enable-hp")
    if args.hp_only_function and args.hp_physical_builder is None:
        parser.error("HP-only control requires a pinned physical builder")
    if args.hp_only_function and not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", args.hp_only_function):
        parser.error("HP-only function name is invalid")
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
    admitted = admit_pinned(
        product_src=product, product_issuer_sha256=_sha(issuer),
        contract_path=contract, contract_sha256=_sha(contract),
        manifest_path=manifest, manifest_sha256=_sha(manifest),
        task_path=task, oss_fuzz_checkout=args.oss_fuzz_checkout,
        upstream_checkout=args.upstream_checkout)
    catalog_path = (Path(admitted.prepared["prebuild_dir"]) /
                    "mongodb" / "functions.json")
    if args.hp_only_function:
        catalog = json.loads(catalog_path.read_bytes())
        matches = [row for row in catalog if
                   type(row) is dict and
                   row.get("name") == args.hp_only_function and
                   type(row.get("reached_by_fuzzers")) is list and
                   admitted.prepared["fuzzer_name"] in
                       row.get("reached_by_fuzzers", [])]
        if len(matches) != 1:
            raise ValueError("HP-only function is not uniquely reachable in the pinned catalog")
    task_id = str(ObjectId())
    run_id = str(ObjectId())
    codex_role_models, codex_role_models_sha256 = product_fbv2_role_models(product)
    global_fuzz_seconds = 30
    sp_fuzz_max_items = 1 if args.enable_sp_fuzz else 0
    global_reservation_seconds = required_global_wall_reservation(
        global_fuzz_seconds)
    total_fuzz_seconds = required_total_fuzz_reservation(
        global_fuzz_seconds, args.sp_fuzz_seconds, sp_fuzz_max_items)
    model_wall_seconds = (None if args.full_nohint_sp else
                          600 if (args.manual_sp_function or
                                   args.hp_only_function) else
                          1500 if args.sp_completion_extended_dev else
                          1200 if args.sp_completion_dev else 900)
    baseline_total_wall_seconds = (
        args.full_nohint_sp_process_wall_seconds
        if args.full_nohint_sp else
        2400 if args.sp_completion_extended_dev else
        2100 if args.sp_completion_dev else 1800)
    derived_total_wall_seconds = math.ceil(required_total_wall_reservation(
        model_wall_seconds=model_wall_seconds,
        global_reservation_seconds=global_reservation_seconds,
        pov_wall_seconds=25,
        global_replay_limit=1,
        gate_aux_reservation_seconds_per_observation=600,
        sp_fuzz_seconds=args.sp_fuzz_seconds,
        sp_fuzz_max_items=sp_fuzz_max_items,
    ))
    total_wall_seconds = (
        baseline_total_wall_seconds if args.full_nohint_sp else
        max(baseline_total_wall_seconds, derived_total_wall_seconds)
    )
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
            "codex_role_models": codex_role_models,
            "codex_role_models_sha256": codex_role_models_sha256,
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
            "physical_model_calls": (None if (args.full_nohint_sp or
                                               args.parallel_hp_dev) else
                                      18 if args.manual_sp_function else
                                      4 if args.hp_only_function else
                                      120 if args.sp_completion_extended_dev else
                                      80 if args.sp_completion_dev else 48),
            "model_wall_seconds": model_wall_seconds,
            "calls_per_agent": (None if (args.full_nohint_sp or
                                         args.parallel_hp_dev) else
                                6 if args.manual_sp_function else
                                4 if args.hp_only_function else
                                64 if args.sp_completion_extended_dev else
                                32 if args.sp_completion_dev else 20),
            "bounded_nohint_dev": args.bounded_nohint_dev,
            "full_nohint_sp": args.full_nohint_sp,
            "total_wall_seconds": total_wall_seconds,
            "total_fuzz_seconds": total_fuzz_seconds,
            "global_fuzz_seconds": global_fuzz_seconds,
            "global_reservation_seconds": global_reservation_seconds,
            "global_replay_limit": 1, "pov_timeout_seconds": 10,
            "pov_wall_seconds": 25,
            "process_output_limit_bytes": 2_000_000,
            "model_turn_seconds": (args.parallel_hp_model_turn_seconds
                                   if args.parallel_hp_dev else
                                   args.full_nohint_sp_model_turn_seconds
                                   if args.full_nohint_sp else 300),
            "gate_aux_reservation_seconds_per_observation": 600,
            "sp_fuzz_seconds": args.sp_fuzz_seconds,
            "sp_fuzz_max_items": sp_fuzz_max_items,
            "seed_direction_limit": 1 if args.sp_priority_one_seed_dev else 5,
            "sp_iteration_policy": (
                dict(FULL_NOHINT_SP_ITERATION_POLICY)
                if args.full_nohint_sp else None),
            "security_invariant_focus": args.sp_invariant_focus,
            "pov_attempts_per_candidate": (
                3 if args.sp_priority_one_seed_dev else 20),
            # This signed envelope is derived from the completed V6/V7 role
            # ledgers. It stops admission of a *new* SP function; it is not a
            # per-turn timeout and never cancels a started transport.
            "sp_start_min_remaining_calls": (
                30 if (args.sp_completion_extended_dev and
                       not args.sp_concurrent_queue_dev) else None),
            "sp_start_min_remaining_wall_seconds": (
                600 if (args.sp_completion_extended_dev and
                        not args.sp_concurrent_queue_dev) else None),
            "sp_concurrent_queue": args.sp_concurrent_queue_dev,
            "sp_discovery_agents": 3 if args.sp_concurrent_queue_dev else 1,
            "sp_verify_agents": 2 if args.sp_concurrent_queue_dev else 1,
            "sp_pov_agents": 2 if args.sp_concurrent_queue_dev else 1,
            "seed_required_unique": 5 if args.sp_concurrent_queue_dev else None,
        },
        "hp": ({"enabled": True, "max_items": 1,
                "max_model_calls": (5 if args.bounded_nohint_dev else
                                    4 if args.hp_only_function else 3),
                "assets": hp_asset_hashes(product)}
               if args.enable_hp else {"enabled": False}),
    }
    if args.bounded_nohint_dev:
        spec["development_scope"] = {
            "kind": ("BOUNDED_NOHINT_COMPLETION_DEV_V1" if
                     args.sp_completion_dev else "BOUNDED_NOHINT_DEV_V1"),
            "seed_directions": 2,
            "sp_functions": 1 if args.enable_hp else 3,
            "sp_max_iterations": 7,
            "selection": "DIRECTION_RISK_PHASE_GENERIC_SURFACE_MODEL_TIE_V4",
        }
    if args.sp_priority_one_seed_dev:
        spec["development_seed_scope"] = {
            "kind": (
                     "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1" if
                     args.parallel_hp_dev else
                     "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1" if
                     combined_concurrent_hp else
                     "SP_PERSISTENT_CONCURRENT_QUEUE_DEV_V1" if
                     args.sp_concurrent_queue_dev else
                     "SP_PRIORITY_ONE_SEED_EXTENDED_DEV_V3" if
                     args.sp_completion_extended_dev else
                     "SP_PRIORITY_ONE_SEED_COMPLETION_DEV_V2" if
                     args.sp_completion_dev else "SP_PRIORITY_ONE_SEED_DEV_V3"),
            "seed_directions": 1,
            "sp_function_limit": None,
            "sp_queue_policy": (
                "PERSISTENT_CONCURRENT_QUEUE_V1" if
                args.sp_concurrent_queue_dev else
                "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"),
            "security_invariant_focus": args.sp_invariant_focus,
            "direction_selection":
                "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
            "pov_attempts_per_candidate": 3,
        }
        if args.sp_concurrent_queue_dev:
            spec["development_seed_scope"]["worker_pool"] = {
                "discovery": 3, "verifier": 2, "pov": 2,
            }
        elif args.sp_completion_extended_dev:
            spec["development_seed_scope"].update({
                "sp_start_min_remaining_calls": 30,
                "sp_start_min_remaining_wall_seconds": 600,
            })
    if args.enable_sp_fuzz:
        spec["sp_fuzz"] = {
            "enabled": True, "seconds_per_item": args.sp_fuzz_seconds,
            "max_items": 1,
        }
    if args.hp_only_function:
        spec["hp_only"] = {
            "enabled": True,
            "function_name": args.hp_only_function,
            "automatic_discovery": False,
            "source_tree_sha256": admitted.qualification.source_tree_sha256,
            "functions_json_sha256": _sha(catalog_path),
        }
    if args.manual_sp_function:
        spec["manual_sp_control"] = {
            "enabled": True,
            "function_name": args.manual_sp_function,
            "max_model_calls_by_role": {"sp": 6, "verifier": 6, "pov": 6},
            "automatic_discovery": False,
        }
    if args.hp_physical_builder is not None:
        builder = args.hp_physical_builder
        builder_manifest = args.hp_physical_manifest
        if (not builder.is_absolute() or not builder_manifest.is_absolute() or
                builder.is_symlink() or builder_manifest.is_symlink() or
                builder != builder.resolve(strict=True) or
                builder_manifest != builder_manifest.resolve(strict=True) or
                builder_manifest.name not in {
                    "multi_tu_assertion_build_manifest.json",
                    "cjson_assertion_build_manifest.json"} or
                builder_manifest.parent != builder.parent or
                not builder.is_file() or not builder_manifest.is_file()):
            raise ValueError("HP physical builder and manifest are not pinned files")
        spec["hp"]["physical"] = {
            "enabled": True, "builder_path": str(builder),
            "builder_sha256": _sha(builder),
            "manifest_path": str(builder_manifest),
            "manifest_sha256": _sha(builder_manifest),
            "guided_seconds": (args.hp_guided_seconds if args.parallel_hp_dev
                               else 1), "total_wall_seconds": 120,
            "output_limit_bytes": 4_000_000,
        }
    if args.parallel_hp_dev:
        from devtools.hp_gate_handoff import validate_hp_gate_policy
        spec["sp_gate_unsupported_crash_policy"] = (
            "PENDING_HUMAN_REVIEW_NO_TERMINAL_CREDIT_V1")
        policy = {
            "enabled": True,
            "max_leads": args.hp_gate_max_leads,
            "replay_timeout_seconds":
                spec["caps"]["pov_timeout_seconds"],
            "replay_wall_seconds": args.hp_gate_replay_wall_seconds,
            "source_wall_seconds": args.hp_gate_source_wall_seconds,
            "output_limit_bytes":
                spec["hp"]["physical"]["output_limit_bytes"],
        }
        spec["hp_gate"] = validate_hp_gate_policy(
            policy,
            max_wall_seconds=spec["caps"][
                "gate_aux_reservation_seconds_per_observation"],
            max_output_bytes=spec["hp"]["physical"]["output_limit_bytes"])
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
