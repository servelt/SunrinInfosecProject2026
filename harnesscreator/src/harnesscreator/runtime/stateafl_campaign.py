"""Run an explicitly configured, research-only StateAFL server campaign.

The source run supplies observed message bytes; the caller supplies a server
already compiled with StateAFL's compiler. This backend never confers the
libFuzzer harness QUALIFIED verdict or classifies a crash as a vulnerability.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..storage import ArtifactStore
from .stateafl_build import has_instrumentation_evidence


@dataclass(frozen=True)
class StateAFLCampaignSpec:
    run_dir: Path
    output_dir: Path
    afl_fuzz: Path
    server_command: tuple[str, ...]
    transport: str
    host: str
    port: int
    seconds: int
    afl_showmap: Path | None = None
    coverage_probe_timeout_ms: int | None = None
    coverage_probe_budget_seconds: int | None = None
    seed_replay_timeout_ms: int | None = None
    seed_replay_budget_seconds: int | None = None
    seed_tier: str = "proven"
    research_only: bool = False
    state_aware: bool = False
    startup_delay_us: int | None = None
    execution_timeout_ms: int | None = None
    memory_limit_mb: int | None = None
    memory_limit_unlimited: bool = False
    graceful_sigterm: bool = False
    replay_server_command: tuple[str, ...] = ()
    replay_timeout_ms: int | None = None
    server_build_manifest: Path | None = None
    expected_source_root: Path | None = None


def prepare_stateafl_campaign(spec: StateAFLCampaignSpec) -> dict[str, Any]:
    """Stage original-run seeds and write the exact StateAFL argv.

    No guessed protocol, build command, startup delay, or state model is
    introduced. Diagnostic seeds require an explicit research-only choice.
    """
    if spec.transport not in {"tcp", "udp"}:
        raise ValueError("StateAFL campaign transport must be tcp or udp")
    if not spec.host or not 1 <= spec.port <= 65535:
        raise ValueError("a concrete host and valid port are required")
    if spec.seconds < 1:
        raise ValueError("campaign seconds must be positive")
    if sum(value is not None for value in (
        spec.afl_showmap, spec.coverage_probe_timeout_ms,
        spec.coverage_probe_budget_seconds,
    )) not in (0, 3):
        raise ValueError("coverage probe requires executable, timeout, and total budget together")
    if (spec.coverage_probe_timeout_ms is not None
        and spec.coverage_probe_timeout_ms < 20):
        raise ValueError("coverage probe timeout must be at least 20 ms")
    if (spec.coverage_probe_budget_seconds is not None
        and spec.coverage_probe_budget_seconds < 1):
        raise ValueError("coverage probe total budget must be positive")
    if ((spec.seed_replay_timeout_ms is None)
        != (spec.seed_replay_budget_seconds is None)):
        raise ValueError("seed replay requires both per-seed timeout and total budget")
    if spec.seed_replay_timeout_ms is not None and spec.seed_replay_timeout_ms < 1:
        raise ValueError("seed replay timeout must be positive")
    if spec.seed_replay_budget_seconds is not None and spec.seed_replay_budget_seconds < 1:
        raise ValueError("seed replay total budget must be positive")
    if spec.seed_tier not in {"proven", "exploratory", "diagnostic"}:
        raise ValueError("unknown seed proof tier")
    if spec.seed_tier != "proven" and not spec.research_only:
        raise ValueError("unproven seed tiers require --research-only")
    if spec.startup_delay_us is not None and spec.startup_delay_us < 0:
        raise ValueError("startup delay cannot be negative")
    if spec.execution_timeout_ms is not None and spec.execution_timeout_ms < 1:
        raise ValueError("execution timeout must be positive")
    if spec.memory_limit_mb is not None and spec.memory_limit_mb < 1:
        raise ValueError("memory limit must be positive")
    if spec.memory_limit_mb is not None and spec.memory_limit_unlimited:
        raise ValueError("choose either a memory limit or --no-memory-limit")
    if bool(spec.replay_server_command) != (spec.replay_timeout_ms is not None):
        raise ValueError("original crash replay requires both server command and timeout")
    if spec.replay_timeout_ms is not None and spec.replay_timeout_ms < 1:
        raise ValueError("original crash replay timeout must be positive")
    if not spec.server_command:
        raise ValueError("an instrumented server command is required")
    afl_binary, server_binary, server_build_evidence = verify_stateafl_build(spec)
    if spec.afl_showmap is not None:
        showmap = spec.afl_showmap.resolve(strict=True)
        if not showmap.is_file() or not os.access(showmap, os.X_OK):
            raise ValueError(f"afl-showmap is not runnable: {showmap}")
    if spec.replay_server_command:
        replay_binary = Path(spec.replay_server_command[0]).resolve(strict=True)
        if not replay_binary.is_file() or not os.access(replay_binary, os.X_OK):
            raise ValueError(f"original replay executable is not runnable: {replay_binary}")
        if (hashlib.sha256(replay_binary.read_bytes()).digest()
            == hashlib.sha256(server_binary.read_bytes()).digest()):
            raise ValueError(
                "original replay executable is byte-identical to the instrumented server"
            )
    run_dir = spec.run_dir.resolve(strict=True)
    manifest_path = run_dir / "research/stateafl/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("qualified_harness_claim") is not False:
        raise ValueError("seed manifest lacks the unqualified-evidence boundary")
    selected = [
        row for row in manifest.get("rows", [])
        if isinstance(row, dict)
        if row.get("seed_path")
        and row.get("channel") == spec.transport
        and Path(str(row["seed_path"])).parts[:3]
            == ("research", "stateafl", spec.seed_tier)
    ]
    if not selected:
        raise ValueError(
            f"no {spec.seed_tier} {spec.transport} original-run seeds; "
            "no campaign was started"
        )
    # Resolve and authenticate every seed before writing an output artifact.
    seeds: list[tuple[dict[str, Any], bytes]] = []
    for row in selected:
        path = (run_dir / str(row["seed_path"])).resolve(strict=True)
        if run_dir not in path.parents:
            raise ValueError("seed path escapes the run directory")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != row.get("sha256"):
            raise ValueError(f"seed bytes changed since the manifest: {path}")
        if not _valid_replay(data):
            raise ValueError(f"invalid StateAFL message sequence: {path}")
        seeds.append((row, data))
    output_dir = spec.output_dir.resolve()
    if output_dir == run_dir or output_dir in run_dir.parents:
        raise ValueError("campaign output must not replace the source run")
    if output_dir.exists() and (
        not output_dir.is_dir() or any(output_dir.iterdir())
    ):
        raise ValueError("campaign output directory must be empty")
    store = ArtifactStore(output_dir)
    input_dir = store.directory("inputs")
    for index, (row, data) in enumerate(seeds):
        store.write_bytes(f"inputs/{index:04d}-{row['sha256'][:12]}.replay", data)
    argv = [
        str(afl_binary), "-i", str(input_dir),
        "-o", str(output_dir / "results"),
        "-N", f"{spec.transport}://{spec.host}/{spec.port}",
    ]
    if spec.startup_delay_us is not None:
        argv.extend(["-D", str(spec.startup_delay_us)])
    if spec.execution_timeout_ms is not None:
        argv.extend(["-t", str(spec.execution_timeout_ms)])
    if spec.memory_limit_mb is not None:
        argv.extend(["-m", str(spec.memory_limit_mb)])
    if spec.memory_limit_unlimited:
        argv.extend(["-m", "none"])
    if spec.graceful_sigterm:
        argv.append("-K")
    if spec.state_aware:
        argv.append("-E")
    argv.extend(["--", str(server_binary), *spec.server_command[1:]])
    prepared = {
        "status": "PREPARED_UNQUALIFIED",
        "argv": argv,
        "source_run": str(run_dir),
        "original_run": manifest.get("source_snapshot_of", str(run_dir)),
        "seed_tier": spec.seed_tier,
        "seed_count": len(seeds),
        "state_aware_requested": spec.state_aware,
        "server_build_evidence": server_build_evidence,
        "research_only": spec.research_only,
        "qualified_harness_claim": False,
        "vulnerability_claim": False,
        "reference": "https://github.com/stateafl/stateafl",
        "reason": (
            "StateAFL requires an instrumented server; preparation does not "
            "establish handler reach, valid protocol state, or crash validity"
        ),
    }
    if spec.seed_replay_timeout_ms is not None:
        # This is a response-oracle comparison against the separately built
        # server. It does not establish Entry/handler attribution or semantic
        # equivalence for all inputs.
        prepared["seed_replay_probe"] = probe_stateafl_seed_responses(
            spec, seeds,
        )
        store.write_json("seed-replay-probe.json", prepared["seed_replay_probe"])
    store.write_json("campaign.json", prepared)
    return prepared


def verify_stateafl_build(
    spec: StateAFLCampaignSpec,
) -> tuple[Path, Path, dict[str, Any] | None]:
    """Check toolchain and source identity without requiring run seeds."""
    if not spec.server_command:
        raise ValueError("an instrumented server command is required")
    if spec.expected_source_root is not None and spec.server_build_manifest is None:
        raise ValueError("source-bound StateAFL use requires a server build manifest")
    afl_binary = spec.afl_fuzz.resolve(strict=True)
    server_binary = Path(spec.server_command[0]).resolve(strict=True)
    if not afl_binary.is_file() or not os.access(afl_binary, os.X_OK):
        raise ValueError(f"StateAFL executable is not runnable: {afl_binary}")
    if not server_binary.is_file() or not os.access(server_binary, os.X_OK):
        raise ValueError(f"server executable is not runnable: {server_binary}")
    server_build_evidence: dict[str, Any] | None = None
    if spec.server_build_manifest is not None:
        build_manifest = spec.server_build_manifest.resolve(strict=True)
        build_report = json.loads(build_manifest.read_text(encoding="utf-8"))
        if not isinstance(build_report, dict):
            raise ValueError("server build manifest must be an object")
        if not has_instrumentation_evidence(build_report):
            raise ValueError("server build did not observe AFL runtime and compiler-inserted coverage")
        if Path(str(build_report.get("server_binary", ""))).resolve() != server_binary:
            raise ValueError("server build manifest describes a different executable")
        digest = hashlib.sha256(server_binary.read_bytes()).hexdigest()
        if build_report.get("server_sha256") != digest:
            raise ValueError("server binary changed since the instrumented build")
        if spec.expected_source_root is not None:
            recorded_source = Path(str(build_report.get("source_root", ""))).resolve()
            if recorded_source != spec.expected_source_root.resolve(strict=True):
                raise ValueError("instrumented build uses a different source checkout")
        server_build_evidence = {
            "manifest": str(build_manifest),
            "server_sha256": digest,
            "instrumentation_evidence": True,
            "source_root": str(spec.expected_source_root.resolve()) if spec.expected_source_root else None,
        }
    return afl_binary, server_binary, server_build_evidence


def probe_stateafl_seed_responses(
    spec: StateAFLCampaignSpec,
    seeds: list[tuple[dict[str, Any], bytes]],
) -> dict[str, Any]:
    """Replay original-run requests on the instrumented server before fuzzing.

    Only compare the original run's explicit success markers. An observed
    marker is evidence that this build handled this concrete request; it is
    neither request-to-handler attribution nor an equivalence proof.
    """
    assert spec.seed_replay_timeout_ms is not None
    assert spec.seed_replay_budget_seconds is not None
    overall_deadline = time.monotonic() + spec.seed_replay_budget_seconds
    records: list[dict[str, Any]] = []
    for row, data in seeds:
        if time.monotonic() >= overall_deadline:
            records.append({
                "seed_sha256": row["sha256"], "status": "BUDGET_EXHAUSTED",
                "reason": "operator-specified total seed replay budget expired",
            })
            continue
        markers = row.get("expected_success_markers_hex")
        responses = row.get("original_responses_hex")
        prelude_hex = row.get("connection_prelude_hex")
        messages = _replay_messages(data)
        if (not isinstance(markers, list) or len(markers) != len(messages)
            or not isinstance(responses, list) or len(responses) != len(messages)
            or not isinstance(prelude_hex, str)):
            records.append({
                "seed_sha256": row["sha256"], "status": "NOT_TESTABLE",
                "reason": "original-run response or pre-request observation is unavailable",
            })
            continue
        try:
            expected = [
                [bytes.fromhex(value) for value in group]
                for group in markers
            ]
            original = [bytes.fromhex(value) for value in responses]
            prelude = bytes.fromhex(prelude_hex)
        except (TypeError, ValueError):
            expected = []
            original = []
            prelude = b""
        if (len(expected) != len(messages)
            or any(not group for group in expected)
            or any(not any(marker in response for marker in group)
                   for group, response in zip(expected, original))):
            records.append({
                "seed_sha256": row["sha256"], "status": "NOT_TESTABLE",
                "reason": "no original response attests every supplied marker",
            })
            continue
        records.append(_probe_one_seed_response(
            spec, row["sha256"], messages, expected, prelude,
            overall_deadline=overall_deadline,
        ))
    return {
        "status": (
            "ORACLE_MARKERS_OBSERVED" if records and all(
                row["status"] == "ORACLE_MARKERS_OBSERVED" for row in records
            ) else "INCONCLUSIVE"
        ),
        "records": records,
        "qualified_harness_claim": False,
        "target_reach_claim": False,
        "vulnerability_claim": False,
        "scope": "concrete original-run response markers on one instrumented build",
        "total_budget_seconds": spec.seed_replay_budget_seconds,
        "budget_exhausted": any(row["status"] == "BUDGET_EXHAUSTED" for row in records),
    }


def _probe_one_seed_response(
    spec: StateAFLCampaignSpec, seed_sha256: str,
    messages: list[bytes], markers: list[list[bytes]], prelude: bytes,
    *, overall_deadline: float | None = None,
) -> dict[str, Any]:
    assert spec.seed_replay_timeout_ms is not None
    timeout = spec.seed_replay_timeout_ms / 1000.0
    deadline = min(time.monotonic() + timeout, overall_deadline or float("inf"))
    observed: list[str] = []
    process: subprocess.Popen[bytes] | None = None
    channel: socket.socket | None = None
    try:
        # Never infer that a response came from our instrumented process if
        # another server already owns the configured endpoint.
        family = socket.SOCK_STREAM if spec.transport == "tcp" else socket.SOCK_DGRAM
        addresses = socket.getaddrinfo(spec.host, spec.port, type=family)
        if not addresses:
            raise ConnectionError("configured endpoint has no socket address")
        af, socktype, protocol, _name, destination = addresses[0]
        with socket.socket(af, socktype, protocol) as guard:
            if spec.transport == "tcp":
                guard.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            guard.bind(destination)
        process = subprocess.Popen(
            list(spec.server_command), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
        if spec.startup_delay_us:
            time.sleep(min(spec.startup_delay_us / 1_000_000, max(0.0, deadline - time.monotonic())))
        if spec.transport == "tcp":
            while time.monotonic() < deadline:
                try:
                    attempt = socket.socket(af, socktype, protocol)
                    attempt.settimeout(max(0.001, deadline - time.monotonic()))
                    try:
                        attempt.connect(destination)
                    except OSError:
                        attempt.close()
                        raise
                    channel = attempt
                    break
                except OSError:
                    if process.poll() is not None:
                        break
                    time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            if channel is None:
                raise ConnectionError("instrumented server did not accept a connection")
        else:
            channel = socket.socket(af, socktype, protocol)
        if prelude:
            if spec.transport != "tcp":
                raise ConnectionError("a server-first prelude requires TCP")
            received_prelude = bytearray()
            while len(received_prelude) < len(prelude) and time.monotonic() < deadline:
                channel.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = channel.recv(len(prelude) - len(received_prelude))
                if not chunk:
                    break
                received_prelude.extend(chunk)
            if received_prelude != prelude:
                raise ConnectionError("instrumented server prelude differs from the original run")
        for message, expected in zip(messages, markers):
            if process.poll() is not None:
                raise ConnectionError("instrumented server exited before the next request")
            channel.settimeout(max(0.001, deadline - time.monotonic()))
            if spec.transport == "tcp":
                channel.sendall(message)
            else:
                channel.sendto(message, destination)
            response = bytearray()
            while time.monotonic() < deadline:
                channel.settimeout(max(0.001, deadline - time.monotonic()))
                try:
                    chunk = channel.recv(65536 - len(response))
                except socket.timeout:
                    break
                if not chunk:
                    break
                response.extend(chunk)
                if any(marker in response for marker in expected):
                    break
                if len(response) == 65536:
                    break
            observed.append(bytes(response).hex())
            if not any(marker in response for marker in expected):
                break
        status = (
            "ORACLE_MARKERS_OBSERVED" if len(observed) == len(messages)
            and all(any(marker in bytes.fromhex(response) for marker in expected)
                    for response, expected in zip(observed, markers))
            else "ORACLE_NOT_OBSERVED"
        )
        reason = "concrete response marker observed after each request" if status == "ORACLE_MARKERS_OBSERVED" else "a response marker was not observed within the explicit timeout"
    except (OSError, ConnectionError) as exc:
        status = "INCONCLUSIVE"
        reason = f"{type(exc).__name__}: {exc}"
    finally:
        if channel is not None:
            channel.close()
        if process is not None and process.poll() is None:
            _stop_campaign_process(process)
    return {
        "seed_sha256": seed_sha256, "status": status,
        "reason": reason, "observed_responses_hex": observed,
    }


def run_stateafl_campaign(
    spec: StateAFLCampaignSpec, *,
    environment: dict[str, str] | None = None,
    stop_event: threading.Event | None = None,
) -> dict[str, Any]:
    env = os.environ.copy()
    if environment:
        env.update(environment)
    # StateAFL's own afl-fuzz checks these Linux settings before it reads a
    # seed. Check them before creating campaign artifacts so an impossible
    # launch does not look like a target or input failure.
    _check_stateafl_host(env)
    prepared = prepare_stateafl_campaign(spec)
    store = ArtifactStore(spec.output_dir)
    if stop_event is not None and stop_event.is_set():
        result = {
            **prepared, "status": "CANCELLED_BEFORE_FUZZING",
            "reason": "the parent analysis stopped before the network campaign began",
        }
        store.write_json("campaign.json", result)
        return result
    if spec.afl_showmap is not None:
        probe = probe_stateafl_seed_coverage(spec, prepared)
        store.write_json("coverage-probe.json", probe)
        if probe["status"] == "NO_COVERAGE_OBSERVED":
            result = {
                **prepared,
                "status": "SEED_COVERAGE_NOT_OBSERVED",
                "coverage_probe": probe,
                "reason": "the instrumented server produced no AFL map for an "
                          "actual seed in two fresh runs; fuzzing was not started",
            }
            store.write_json("campaign.json", result)
            return result
        prepared["coverage_probe"] = probe
    if stop_event is not None and stop_event.is_set():
        result = {
            **prepared, "status": "CANCELLED_BEFORE_FUZZING",
            "reason": "the parent analysis stopped before the network campaign began",
        }
        store.write_json("campaign.json", result)
        return result
    started = time.monotonic()
    with (store.directory("logs") / "afl-fuzz.log").open("wb") as log:
        process = subprocess.Popen(
            prepared["argv"], stdout=log, stderr=subprocess.STDOUT,
            env=env, start_new_session=True,
        )
        timed_out = False
        try:
            while process.poll() is None:
                remaining = spec.seconds - (time.monotonic() - started)
                if remaining <= 0 or (stop_event is not None and stop_event.is_set()):
                    timed_out = remaining <= 0
                    _stop_campaign_process(process)
                    break
                try:
                    process.wait(timeout=min(1.0, remaining))
                except subprocess.TimeoutExpired:
                    pass
        except BaseException:
            _stop_campaign_process(process)
            raise
    stats_path = spec.output_dir / "results/fuzzer_stats"
    stats = _read_fuzzer_stats(stats_path)
    try:
        executions = int(stats.get("execs_done", "0"))
    except ValueError:
        executions = 0
    bitmap_text = stats.get("bitmap_cvg", "")
    try:
        bitmap_percent = float(bitmap_text.rstrip("%"))
    except ValueError:
        bitmap_percent = None
    # StateAFL rounds bitmap_cvg to two decimal places. A displayed 0.00%
    # alone cannot distinguish an empty bitmap from a few instrumented bits;
    # its dry-run log reports the exact bitmap range for that distinction.
    log_text = (spec.output_dir / "logs/afl-fuzz.log").read_text(
        encoding="utf-8", errors="replace"
    )
    # StateAFL emits ANSI SGR colour codes even when redirected to a file.
    # They can occur between the label and its number, so parsing the raw
    # text silently loses the bitmap range from real campaign logs.
    log_text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", log_text)
    dry_run_ranges = re.findall(
        r"Bitmap range\s*:\s*(\d+)\s+to\s+(\d+)\s+bits",
        log_text,
    )
    dry_run_max_bits = (
        max(int(high) for _low, high in dry_run_ranges)
        if dry_run_ranges else None
    )
    # StateAFL prints the initialization bitmap range even when SIGTERM
    # interrupted the first seed's calibration. In that case bitmap_size and
    # exec_us have not yet been assigned (afl-fuzz.c:4318, 4458, 6297). The
    # zero range is therefore not evidence that the target lacked coverage.
    calibrated_seed_observed = bool(re.search(
        r"\blen\s*=\s*\d+\s*,\s*map size\s*=\s*\d+\s*,\s*exec speed\s*=",
        log_text,
    ))
    instrumentation_rejected = "No instrumentation detected" in log_text
    seed_dry_run_timeout = bool(re.search(
        r"Test case .* results in a timeout", log_text,
    )) and "perform_dry_run()" in log_text
    if stop_event is not None and stop_event.is_set():
        status = "CANCELLED_PARENT_ANALYSIS"
    elif instrumentation_rejected:
        status = "NO_INSTRUMENTATION_DETECTED"
    elif seed_dry_run_timeout:
        status = "SEED_DRY_RUN_TIMEOUT"
    elif executions <= 0:
        status = "NO_FUZZING_OBSERVED"
    elif bitmap_percent is not None and bitmap_percent > 0:
        status = "FUZZING_OBSERVED_UNQUALIFIED"
    elif dry_run_max_bits is not None and dry_run_max_bits > 0:
        status = "FUZZING_OBSERVED_UNQUALIFIED"
    elif timed_out and dry_run_max_bits == 0 and not calibrated_seed_observed:
        status = "CALIBRATION_INTERRUPTED_COVERAGE_UNKNOWN"
    else:
        status = "EXECUTIONS_OBSERVED_COVERAGE_UNKNOWN"
    result = {
        **prepared,
        "status": status,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "exit_code": process.returncode,
        "time_limit_reached": timed_out,
        "fuzzer_stats": stats,
        # StateAFL reports crashes found by its instrumented execution.  Its
        # crash-handling opt-out can also make that count unreliable.  Neither
        # case establishes a crash on the original server or a vulnerability.
        "reported_unique_crashes": stats.get("unique_crashes"),
        "crash_handling_check_bypassed": (
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES" in env
        ),
        "reported_crashes_verified": False,
        "dry_run_max_bitmap_bits": dry_run_max_bits,
        "calibrated_seed_observed": calibrated_seed_observed,
        "seed_dry_run_timeout": seed_dry_run_timeout,
        "log_path": "logs/afl-fuzz.log",
        "qualified_harness_claim": False,
        "vulnerability_claim": False,
    }
    if spec.replay_server_command and status != "CANCELLED_PARENT_ANALYSIS":
        result["original_crash_replays"] = _replay_crash_artifacts(spec)
    store.write_json("campaign.json", result)
    return result


def probe_stateafl_seed_coverage(
    spec: StateAFLCampaignSpec, prepared: dict[str, Any],
) -> dict[str, Any]:
    """Compare AFL maps for an idle connection and one real replay seed.

    This checks whether the configured instrumented server observes input at
    all. It does not identify a product handler or qualify a C harness. The
    operator explicitly supplies afl-showmap and the per-run timeout because
    a daemon has no universal startup or shutdown duration.
    """
    assert spec.afl_showmap is not None
    assert spec.coverage_probe_timeout_ms is not None
    assert spec.coverage_probe_budget_seconds is not None
    deadline = time.monotonic() + spec.coverage_probe_budget_seconds
    seed_paths = sorted((spec.output_dir / "inputs").glob("*.replay"))
    if not seed_paths:
        return {"status": "INCONCLUSIVE", "reason": "no staged seed"}
    argv = prepared["argv"]
    server_argv = argv[argv.index("--") + 1:]
    directory = spec.output_dir / "coverage-probe"
    directory.mkdir()
    baseline = []
    for index in (1, 2):
        if time.monotonic() >= deadline:
            break
        baseline.append(_probe_one_map(
            spec, server_argv, directory / f"baseline-{index}.map", [],
        ))
    if len(baseline) < 2:
        return {
            "status": "INCONCLUSIVE", "reason": "coverage probe budget expired during baseline",
            "baseline_runs": baseline, "seed_count": len(seed_paths),
            "qualified_harness_claim": False, "target_reach_claim": False,
            "vulnerability_claim": False,
        }
    candidates: list[dict[str, Any]] = []
    exhausted = False
    for seed_index, seed_path in enumerate(seed_paths):
        seed_bytes = seed_path.read_bytes()
        messages = _replay_messages(seed_bytes)
        seed = []
        for index in (1, 2):
            if time.monotonic() >= deadline:
                exhausted = True
                break
            seed.append(_probe_one_map(
                spec, server_argv,
                directory / f"seed-{seed_index:04d}-{index}.map", messages,
            ))
        if len(seed) < 2:
            exhausted = True
            break
        runs = [*baseline, *seed]
        if any(row["error"] or row["returncode"] not in (0, 1)
               for row in runs):
            seed_status = "INCONCLUSIVE"
        elif all(row["map_entries"] == 0 for row in runs):
            seed_status = "NO_COVERAGE_OBSERVED"
        elif (baseline[0]["map_sha256"] != baseline[1]["map_sha256"]
              or seed[0]["map_sha256"] != seed[1]["map_sha256"]):
            seed_status = "UNSTABLE_COVERAGE"
        elif baseline[0]["map_sha256"] != seed[0]["map_sha256"]:
            seed_status = "INPUT_AFFECTED_COVERAGE"
        else:
            seed_status = "UNCHANGED_COVERAGE"
        candidates.append({
            "seed_sha256": hashlib.sha256(seed_bytes).hexdigest(),
            "status": seed_status,
            "runs": seed,
        })
        # One actual seed with nonzero coverage is enough to reject the
        # no-instrumentation hypothesis. Further seed coverage is a fuzzing
        # result, not a prerequisite for starting the campaign.
        if seed_status in {"INPUT_AFFECTED_COVERAGE", "UNCHANGED_COVERAGE"}:
            break
    statuses = {candidate["status"] for candidate in candidates}
    status = (
        "INPUT_AFFECTED_COVERAGE" if "INPUT_AFFECTED_COVERAGE" in statuses
        else "UNCHANGED_COVERAGE" if "UNCHANGED_COVERAGE" in statuses
        else "NO_COVERAGE_OBSERVED"
        if (not exhausted and len(candidates) == len(seed_paths)
            and statuses == {"NO_COVERAGE_OBSERVED"}) else "INCONCLUSIVE"
    )
    return {
        "status": status,
        "seed_count": len(seed_paths),
        "seeds_probed": len(candidates),
        "budget_exhausted": exhausted,
        "baseline_runs": baseline,
        "seed_results": candidates,
        "qualified_harness_claim": False,
        "target_reach_claim": False,
        "vulnerability_claim": False,
    }


def _probe_one_map(
    spec: StateAFLCampaignSpec, server_argv: list[str], map_path: Path,
    messages: list[bytes],
) -> dict[str, Any]:
    assert spec.afl_showmap is not None
    assert spec.coverage_probe_timeout_ms is not None
    command = [
        str(spec.afl_showmap), "-q", "-e", "-o", str(map_path),
        "-t", str(spec.coverage_probe_timeout_ms),
    ]
    if spec.memory_limit_mb is not None:
        command.extend(["-m", str(spec.memory_limit_mb)])
    else:
        command.extend(["-m", "none"])
    command.extend(["--", *server_argv])
    error = ""
    returncode: int | None = None
    process: subprocess.Popen[bytes] | None = None
    started = time.monotonic()
    # Let afl-showmap's own per-target timer terminate the inferior and write
    # the map. The total budget prevents *new* trials, but interrupting a
    # running showmap can orphan the daemon it started in a separate session.
    run_deadline = started + spec.coverage_probe_timeout_ms / 1000
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        socket_type = socket.SOCK_STREAM if spec.transport == "tcp" else socket.SOCK_DGRAM
        addresses = socket.getaddrinfo(spec.host, spec.port, type=socket_type)
        if not addresses:
            raise OSError("coverage probe host has no socket address")
        family, kind, protocol, _name, destination = addresses[0]
        if spec.transport == "udp" and spec.startup_delay_us is None:
            raise ValueError("UDP coverage probe requires an explicit startup_delay_us")
        if spec.startup_delay_us is not None:
            remaining = run_deadline - time.monotonic()
            delay = spec.startup_delay_us / 1_000_000
            if delay >= remaining:
                raise TimeoutError("startup delay exceeds coverage probe timeout")
            time.sleep(delay)
        with socket.socket(family, kind, protocol) as channel:
            channel.settimeout(max(0.001, run_deadline - time.monotonic()))
            if spec.transport == "tcp":
                while True:
                    try:
                        channel.connect(destination)
                        break
                    except (ConnectionRefusedError, TimeoutError, OSError):
                        if process.poll() is not None or time.monotonic() >= run_deadline:
                            raise OSError("instrumented server did not accept probe connection")
                        time.sleep(min(0.02, max(0, run_deadline - time.monotonic())))
                for message in messages:
                    channel.sendall(message)
            else:
                for message in (messages or [b""]):
                    channel.sendto(message, destination)
        _out, stderr = process.communicate(
            timeout=max(1.0, run_deadline - time.monotonic() + 1.0)
        )
        returncode = process.returncode
        if returncode not in (0, 1):
            error = stderr.decode("utf-8", errors="replace")[-600:]
    except (OSError, TimeoutError, ValueError, subprocess.TimeoutExpired) as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    try:
        rows = map_path.read_bytes().splitlines()
    except OSError:
        rows = []
    return {
        "map_entries": len(rows),
        "map_sha256": hashlib.sha256(b"\n".join(rows)).hexdigest(),
        "returncode": returncode,
        "error": error,
        "map_path": str(map_path.relative_to(spec.output_dir)),
    }


def _check_stateafl_host(
    environment: dict[str, str], *, proc_sys: Path = Path("/proc/sys/kernel"),
) -> None:
    """Mirror only the fail-fast Linux checks in StateAFL's afl-fuzz.c.

    A missing procfs file is left to the upstream binary, as in its own
    check_aslr/check_crash_handling implementations.  We do not change host
    settings or silently opt out of reliable crash reporting.
    """
    if not sys.platform.startswith("linux"):
        return
    try:
        aslr = (proc_sys / "randomize_va_space").read_text(encoding="ascii")
    except OSError:
        aslr = ""
    if aslr and aslr[0] != "0":
        raise ValueError(
            "StateAFL cannot start while ASLR is enabled "
            "(/proc/sys/kernel/randomize_va_space); its afl-fuzz.c "
            "check_aslr aborts before the first seed"
        )
    try:
        core_pattern = (proc_sys / "core_pattern").read_text(encoding="ascii")
    except OSError:
        core_pattern = ""
    if (core_pattern.startswith("|")
        and "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES" not in environment):
        raise ValueError(
            "StateAFL cannot start with a piped core_pattern unless "
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES is explicitly set; "
            "that opt-out can miss crashes, so it is never set automatically"
        )


def _replay_crash_artifacts(spec: StateAFLCampaignSpec) -> list[dict[str, Any]]:
    """Replay StateAFL crash inputs on an explicit fresh original server.

    This is a process-level reproducibility check. It neither establishes a
    request's handler nor classifies a reproducible abort as a vulnerability.
    A clean or timed-out replay is inconclusive because scheduling and server
    state may differ from the fuzz campaign.
    """
    crash_dir = spec.output_dir / "results/replayable-crashes"
    if not crash_dir.is_dir():
        return []
    assert spec.replay_timeout_ms is not None
    timeout = spec.replay_timeout_ms / 1000.0
    records: list[dict[str, Any]] = []
    for artifact in sorted(crash_dir.iterdir()):
        if (artifact.name == "README.txt" or artifact.is_symlink()
            or not artifact.is_file()):
            continue
        try:
            data = artifact.read_bytes()
        except OSError as exc:
            records.append({
                "artifact": str(artifact.relative_to(spec.output_dir)),
                "status": "ORIGINAL_REPLAY_ERROR",
                "reason": f"cannot read crash artifact: {type(exc).__name__}: {exc}",
                "vulnerability_claim": False,
            })
            continue
        if not _valid_replay(data):
            records.append({
                "artifact": str(artifact.relative_to(spec.output_dir)),
                "status": "INVALID_REPLAY_INPUT", "vulnerability_claim": False,
            })
            continue
        try:
            records.append(_replay_one_crash(spec, artifact, data, timeout))
        except OSError as exc:
            records.append({
                "artifact": str(artifact.relative_to(spec.output_dir)),
                "sha256": hashlib.sha256(data).hexdigest(),
                "status": "ORIGINAL_REPLAY_ERROR",
                "reason": f"original replay could not start: {type(exc).__name__}: {exc}",
                "vulnerability_claim": False,
            })
    return records


def _replay_one_crash(
    spec: StateAFLCampaignSpec, artifact: Path, data: bytes,
    timeout: float,
) -> dict[str, Any]:
    argv = list(spec.replay_server_command)
    started = time.monotonic()
    log_path = spec.output_dir / "logs" / (
        f"original-replay-{hashlib.sha256(data).hexdigest()[:16]}.stderr.log"
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            argv, stdout=subprocess.DEVNULL, stderr=log,
            start_new_session=True,
        )
    messages = _replay_messages(data)
    sent = 0
    transport_error = ""
    try:
        family = socket.SOCK_STREAM if spec.transport == "tcp" else socket.SOCK_DGRAM
        addresses = socket.getaddrinfo(spec.host, spec.port, type=family)
        if not addresses:
            raise ConnectionError("original replay host has no socket address")
        address_family, socket_type, protocol, _name, destination = addresses[0]
        with socket.socket(address_family, socket_type, protocol) as channel:
            channel.settimeout(max(0.001, timeout - (time.monotonic() - started)))
            if spec.transport == "tcp":
                deadline = started + timeout
                while True:
                    try:
                        if process.poll() is not None:
                            raise ConnectionError(
                                "original server exited before accepting the replay"
                            )
                        channel.connect(destination)
                        break
                    except (ConnectionRefusedError, TimeoutError, OSError) as exc:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise ConnectionError(f"original server connection failed: {exc}") from exc
                        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            for message in messages:
                if process.poll() is not None:
                    raise ConnectionError(
                        "original server exited before the next replay message"
                    )
                channel.settimeout(max(0.001, timeout - (time.monotonic() - started)))
                if spec.transport == "tcp":
                    channel.sendall(message)
                else:
                    channel.sendto(message, destination)
                sent += 1
                try:
                    channel.recv(65536)
                except socket.timeout:
                    # A silent protocol may still have consumed the input.
                    pass
                if process.poll() is not None:
                    break
    except (ConnectionError, OSError, TimeoutError) as exc:
        transport_error = f"{type(exc).__name__}: {exc}"
    # Allow an asynchronous server to finish its request. The explicit
    # timeout also bounds this observation; no crash is never a negative proof.
    try:
        process.wait(timeout=max(0.0, timeout - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        pass
    natural_returncode = process.poll()
    if natural_returncode is None:
        _stop_campaign_process(process)
    with log_path.open("rb") as log:
        stderr = log.read(1024 * 1024)
    sanitizer = any(marker in stderr for marker in (
        b"ERROR: AddressSanitizer", b"WARNING: MemorySanitizer",
        b"WARNING: ThreadSanitizer", b"ERROR: UndefinedBehaviorSanitizer",
    ))
    crash_observed = sent > 0 and natural_returncode is not None and (
        natural_returncode < 0 or (natural_returncode != 0 and sanitizer)
    )
    return {
        "artifact": str(artifact.relative_to(spec.output_dir)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "status": (
            "ORIGINAL_REPLAY_CRASH_OBSERVED" if crash_observed
            else "ORIGINAL_REPLAY_INCONCLUSIVE"
        ),
        "messages_sent": sent,
        "message_count": len(messages),
        "original_returncode": natural_returncode,
        "sanitizer_report_observed": sanitizer,
        "transport_error": transport_error,
        "stderr_log_path": str(log_path.relative_to(spec.output_dir)),
        "request_caused_crash_proven": False,
        "vulnerability_claim": False,
    }


def _replay_messages(data: bytes) -> list[bytes]:
    messages: list[bytes] = []
    offset = 0
    while offset < len(data):
        size = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        messages.append(data[offset:offset + size])
        offset += size
    return messages


def _stop_campaign_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _valid_replay(data: bytes) -> bool:
    if not data:
        return False
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            return False
        size = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        if size == 0 or len(data) - offset < size:
            return False
        offset += size
    return offset == len(data)


def _read_fuzzer_stats(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            result[key.strip()] = value.strip()
    return result
