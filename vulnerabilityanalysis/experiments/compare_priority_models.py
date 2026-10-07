"""Run the existing Tinyproxy fixture workflow with a selected model profile.

The scheduler sees only harness/catalog/source evidence. The script contains
no known-vulnerability function name, advisory, crash input, or root cause.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

import yaml

from vulnerabilityanalysis.llm import AppServerError, CodexAppServerClient, LLMRequest
from vulnerabilityanalysis.models import FunctionPoolItem, NormalizedHarness
from vulnerabilityanalysis.scan import scan_selected
from vulnerabilityanalysis.scheduler import Scheduler, source_evidence_for_pool
from vulnerabilityanalysis.workflow import run_phase1, write_json


class MeteredProvider:
    """Record request roles and timings without storing Agent prompt contents."""

    def __init__(self, client: CodexAppServerClient):
        self.client = client
        self.requests: list[dict[str, object]] = []

    async def generate(self, request: LLMRequest) -> dict:
        started = time.perf_counter()
        row: dict[str, object] = {
            "role": request.role,
            "model": request.model or self.client.model or "CONFIG_DEFAULT",
            "reasoning": request.effort or self.client.effort,
        }
        try:
            result = await self.client.generate(request)
            row["status"] = "COMPLETED"
            return result
        except Exception as exc:
            row["status"] = "ERROR"
            row["error_type"] = type(exc).__name__
            raise
        finally:
            row["elapsed_seconds"] = round(time.perf_counter() - started, 3)
            self.requests.append(row)

    async def close_session(self, session_key: str) -> None:
        await self.client.close_session(session_key)

    async def close(self) -> None:
        await self.client.close()


async def run(args: argparse.Namespace) -> Path:
    target = args.target_repository.resolve()
    binary = args.target_binary.resolve()
    artifact = args.artifact.resolve()
    runner = args.harness_runner.resolve()
    if not all(path.is_file() for path in (binary, runner, artifact / "manifest.json")):
        raise FileNotFoundError("target binary, local runner, or fixture manifest unavailable")
    config = yaml.safe_load(args.config.read_text(encoding="utf-8"))
    role_models = config["models"] if args.profile == "role_split_5_6" else None
    provider_model = "gpt-6-sol" if args.profile == "scheduler_gpt6" else "gpt-5.6-sol"
    output = args.resume_run.resolve() if args.resume_run else run_phase1(
        artifact, args.result_root, target_repository=target)
    harness = NormalizedHarness(**json.loads((output / "harness.json").read_text()))
    if harness.source_kind != "regression_fixture" or not harness.build_verified:
        raise ValueError("experiment requires a validated local regression fixture")
    pool = [FunctionPoolItem(**row) for row in json.loads((output / "function_pool.json").read_text())]
    sources = source_evidence_for_pool(harness, pool)
    scheduler = Scheduler.default()
    scheduler.turn = 1
    first = json.loads((output / "selection.json").read_text())
    order = (json.loads((output / "analysis_order.json").read_text()) if args.resume_run
             else [dict(first, analysis_order=1)])
    if args.resume_run:
        metadata = json.loads((output / "experiment_metadata.json").read_text())
        if metadata["profile"] != args.profile or metadata["function_budget"] != args.limit or (
                metadata["sp_verification_budget_per_function"] != args.max_candidates):
            raise ValueError("resume profile or budget differs from saved experiment")
        if (Path(metadata["artifact"]).resolve() != artifact or
                Path(metadata["target_repository"]).resolve() != target or
                metadata["target_binary_sha256"] != hashlib.sha256(binary.read_bytes()).hexdigest()):
            raise ValueError("resume artifact, target repository, or binary differs")
        # Reconstruct the same scheduler state without overwriting completed
        # function artifacts or using any post-blind vulnerability information.
        for prior in order[1:]:
            replayed = scheduler.select(pool, sources=sources)
            if replayed.function_id != prior["function_id"]:
                raise ValueError("saved function order differs from current scheduler")
    command = [sys.executable, str(runner), str(binary), "{input}"]
    if not args.resume_run:
        write_json(output / "experiment_metadata.json", {
        "profile": args.profile,
        "provider": "Codex app-server; existing ChatGPT login, no API key",
        "provider_default_model": provider_model,
        "role_models": role_models,
        "model_entitlement_probed": True,
        "function_budget": args.limit,
        "sp_verification_budget_per_function": args.max_candidates,
        "baseline_run_ids_preserved": ["20261007T134854Z-5eacaf54", "20261007T142604Z-305db618"],
        "artifact": str(artifact), "target_repository": str(target),
        "target_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "harness_source": "REGRESSION_FIXTURE", "project_harness": False,
        "blind_prompt_rule": "No known vulnerability, CVE, prior root cause, or crash input in Agent payloads",
        })
    previous_elapsed = (json.loads((output / "experiment_progress.json").read_text())
                        .get("elapsed_seconds", 0) if args.resume_run else 0)
    started = time.perf_counter()
    async with CodexAppServerClient(cwd=args.project.resolve(), model=provider_model,
                                    effort="medium", timeout_seconds=300) as client:
        provider = MeteredProvider(client)
        for rank in range(1, args.limit + 1):
            if rank == 1:
                folder = output
                selected = first
            elif rank <= len(order):
                selected = order[rank - 1]
                folder = output / "function_runs" / f"{rank:02d}_{selected['function_name']}"
            else:
                item = scheduler.select(pool, sources=sources)
                selected = asdict(item)
                folder = output / "function_runs" / f"{rank:02d}_{item.function_name}"
                folder.mkdir(parents=True, exist_ok=False)
                for name in ("run.json", "harness.json", "workers.json", "directions.json"):
                    shutil.copy2(output / name, folder / name)
                row = json.loads((folder / "run.json").read_text())
                row["selected_function_id"] = item.function_id
                write_json(folder / "run.json", row)
                write_json(folder / "function_pool.json", [asdict(x) for x in pool])
                write_json(folder / "selection.json", selected)
                order.append(dict(selected, analysis_order=rank))
            write_json(output / "analysis_order.json", order)
            prior_timing = folder / "experiment_timing.json"
            if (folder / "scan.json").is_file() and prior_timing.is_file() and json.loads(
                    prior_timing.read_text()).get("status") == "COMPLETED":
                print(f"[{args.profile}] rank {rank}: PRESERVED", flush=True)
                continue
            (folder / "runtime").mkdir(exist_ok=True)
            old_profile = os.environ.get("LLVM_PROFILE_FILE")
            os.environ["LLVM_PROFILE_FILE"] = str(folder / "runtime/coverage-%p.profraw")
            before = len(provider.requests)
            previous_calls = (json.loads((folder / "llm_requests.json").read_text())
                              if (folder / "llm_requests.json").is_file() else [])
            previous_timing = (json.loads(prior_timing.read_text()).get("elapsed_seconds", 0)
                               if prior_timing.is_file() else 0)
            started_function = time.perf_counter()
            print(f"[{args.profile}] rank {rank}: {selected['function_name']} score={selected['priority_score']}", flush=True)
            try:
                for attempt in range(2):
                    try:
                        await scan_selected(folder, provider, target_repository=target,
                                            run_command=command, runtime_sanitizers=["ASAN"],
                                            max_candidates=args.max_candidates, target_binary=binary,
                                            role_models=role_models)
                        status = "COMPLETED"
                        break
                    except AppServerError as exc:
                        if attempt == 0 and "timed out" in str(exc):
                            print(f"[{args.profile}] rank {rank}: transport timeout; one fresh-process retry", flush=True)
                            continue
                        raise
            except Exception as exc:
                status = "ERROR"
                write_json(folder / "experiment_error.json",
                           {"error_type": type(exc).__name__, "message": str(exc)[:1000]})
            finally:
                if old_profile is None:
                    os.environ.pop("LLVM_PROFILE_FILE", None)
                else:
                    os.environ["LLVM_PROFILE_FILE"] = old_profile
            calls = provider.requests[before:]
            write_json(folder / "llm_requests.json", previous_calls + calls)
            write_json(folder / "experiment_timing.json", {
                "rank": rank, "function": selected["function_name"], "status": status,
                "elapsed_seconds": previous_timing + time.perf_counter() - started_function,
            })
            all_requests = [row for path in [output / "llm_requests.json", *sorted(
                (output / "function_runs").glob("*/llm_requests.json"))] if path.is_file()
                            for row in json.loads(path.read_text())]
            write_json(output / "experiment_progress.json", {
                "completed_rank": rank,
                "elapsed_seconds": previous_elapsed + time.perf_counter() - started,
                "latest_status": status,
                "model_calls_by_status": dict(Counter(str(x["status"]) for x in all_requests)),
            })
            print(f"[{args.profile}] rank {rank}: {status}", flush=True)
        all_requests = [row for path in [output / "llm_requests.json", *sorted(
            (output / "function_runs").glob("*/llm_requests.json"))] if path.is_file()
                        for row in json.loads(path.read_text())]
        counts = Counter((str(x["model"]), str(x["status"])) for x in all_requests)
    completed_runs = sum((output / "function_runs" / f"{rank:02d}_{order[rank-1]['function_name']}" / "scan.json").is_file()
                         for rank in range(2, args.limit + 1)) + int((output / "scan.json").is_file())
    write_json(output / "experiment_summary.json", {
        "profile": args.profile, "function_budget": args.limit,
        "scheduled_functions": len(order), "analyzed_functions": completed_runs,
        "analysis_order": [{"rank": x["analysis_order"], "function": x["function_name"],
                            "score": x["priority_score"], "reasons": x["priority_reasons"],
                            "risk_level": x["risk_level"],
                            "tie_break_reason": x.get("tie_break_reason")} for x in order],
        "model_calls": [{"model": model, "status": status, "count": count}
                        for (model, status), count in sorted(counts.items())],
        "elapsed_seconds": previous_elapsed + time.perf_counter() - started,
        "completed_function_runs": completed_runs,
    })
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--target-repository", type=Path, required=True)
    parser.add_argument("--target-binary", type=Path, required=True)
    parser.add_argument("--harness-runner", type=Path, required=True)
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config/default.yaml")
    parser.add_argument("--profile", choices=["scheduler_gpt6", "role_split_5_6"], required=True)
    parser.add_argument("--limit", type=int, default=15)
    parser.add_argument("--max-candidates", type=int, default=2)
    parser.add_argument("--resume-run", type=Path,
                        help="continue only missing/failed functions in a saved run")
    args = parser.parse_args()
    print(asyncio.run(run(args)).resolve())


if __name__ == "__main__":
    main()
