"""Bind an Action run to a separately instrumented StateAFL server.

The configuration is trusted operator input. The resulting process-level
network harness remains independent of C/libFuzzer qualification.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .stateafl_campaign import (
    StateAFLCampaignSpec,
    prepare_stateafl_campaign,
    run_stateafl_campaign,
    verify_stateafl_build,
)
from .stateafl_build import (
    StateAFLBuildSpec, build_stateafl_server, has_instrumentation_evidence,
)


_REQUIRED = frozenset({
    "afl_fuzz", "server_command",
    "transport", "host", "port", "seconds", "seed_tier",
})
_OPTIONAL = frozenset({
    "server_build_manifest", "build",
    "afl_showmap", "coverage_probe_timeout_ms", "coverage_probe_budget_seconds",
    "seed_replay_timeout_ms", "seed_replay_budget_seconds",
    "research_only", "state_aware", "startup_delay_us",
    "execution_timeout_ms", "memory_limit_mb", "memory_limit_unlimited",
    "graceful_sigterm", "execute", "replay_server_command", "replay_timeout_ms",
})
_BUILD_REQUIRED = frozenset({"compiler", "command", "server_relative_path"})
_BUILD_OPTIONAL = frozenset({
    "cxx_compiler", "steps", "timeout_seconds", "linker_flags", "container_image",
})


@dataclass(frozen=True)
class NetworkHarnessConfig:
    path: Path
    data: dict[str, Any]

    @classmethod
    def load(cls, path: Path) -> "NetworkHarnessConfig":
        resolved = path.expanduser().resolve(strict=True)
        data = json.loads(resolved.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("network harness config must be a JSON object")
        missing = _REQUIRED - data.keys()
        unknown = data.keys() - _REQUIRED - _OPTIONAL
        if missing or unknown:
            raise ValueError(
                f"network harness config keys: missing={sorted(missing)}, "
                f"unknown={sorted(unknown)}"
            )
        if not isinstance(data["server_command"], list) or not data["server_command"]:
            raise ValueError("server_command must be a nonempty argv array")
        if any(not isinstance(part, str) or not part or "\x00" in part
               for part in data["server_command"]):
            raise ValueError("server_command contains an invalid argument")
        if ("build" in data) == ("server_build_manifest" in data):
            raise ValueError("choose exactly one of build or server_build_manifest")
        if ("replay_server_command" in data) != ("replay_timeout_ms" in data):
            raise ValueError(
                "original crash replay requires both replay_server_command "
                "and replay_timeout_ms"
            )
        if len({"afl_showmap", "coverage_probe_timeout_ms", "coverage_probe_budget_seconds"}
               & data.keys()) not in (0, 3):
            raise ValueError(
                "coverage probe requires afl_showmap, coverage_probe_timeout_ms, "
                "and coverage_probe_budget_seconds together"
            )
        if ("seed_replay_timeout_ms" in data) != ("seed_replay_budget_seconds" in data):
            raise ValueError(
                "seed response probe requires seed_replay_timeout_ms and "
                "seed_replay_budget_seconds together"
            )
        if "afl_showmap" in data and (
            not isinstance(data["afl_showmap"], str)
            or not data["afl_showmap"] or "\x00" in data["afl_showmap"]
        ):
            raise ValueError("afl_showmap must be a nonempty executable path")
        if "replay_server_command" in data:
            _validate_argv(data["replay_server_command"], "replay_server_command")
            if (type(data["replay_timeout_ms"]) is not int
                or data["replay_timeout_ms"] < 1):
                raise ValueError("replay_timeout_ms must be positive")
        for name in ("afl_fuzz", "transport", "host", "seed_tier"):
            if not isinstance(data[name], str) or not data[name]:
                raise ValueError(f"{name} must be a nonempty string")
        if "server_build_manifest" in data and (
            not isinstance(data["server_build_manifest"], str)
            or not data["server_build_manifest"]
        ):
            raise ValueError("server_build_manifest must be a nonempty string")
        if "build" in data:
            build = data["build"]
            if not isinstance(build, dict):
                raise ValueError("build must be a JSON object")
            missing_build = _BUILD_REQUIRED - build.keys()
            unknown_build = build.keys() - _BUILD_REQUIRED - _BUILD_OPTIONAL
            if missing_build or unknown_build:
                raise ValueError(
                    f"build keys: missing={sorted(missing_build)}, "
                    f"unknown={sorted(unknown_build)}"
                )
            for name in ("compiler", "server_relative_path", "cxx_compiler", "container_image"):
                if name in build and (
                    not isinstance(build[name], str) or not build[name]
                    or "\x00" in build[name]
                ):
                    raise ValueError(f"build.{name} must be a nonempty string")
            _validate_argv(build["command"], "build.command")
            if "steps" in build:
                if not isinstance(build["steps"], list):
                    raise ValueError("build.steps must be an array of argv arrays")
                for index, step in enumerate(build["steps"]):
                    _validate_argv(step, f"build.steps[{index}]")
            if "linker_flags" in build:
                flags = build["linker_flags"]
                if (not isinstance(flags, list)
                    or any(not isinstance(flag, str) or not flag or "\x00" in flag
                           for flag in flags)):
                    raise ValueError("build.linker_flags must be an argument array")
            if "timeout_seconds" in build and (
                type(build["timeout_seconds"]) is not int or build["timeout_seconds"] < 1
            ):
                raise ValueError("build.timeout_seconds must be positive")
            relative = Path(build["server_relative_path"])
            if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                raise ValueError("build.server_relative_path must stay inside the copied source")
            if data["server_command"][0] != "{server_binary}":
                raise ValueError("build mode requires server_command[0] = {server_binary}")
        elif data["server_command"][0] == "{server_binary}":
            raise ValueError("{server_binary} requires an automatic build")
        for name in ("port", "seconds", "startup_delay_us", "execution_timeout_ms", "memory_limit_mb"):
            if name in data and (type(data[name]) is not int):
                raise ValueError(f"{name} must be an integer")
        if "coverage_probe_timeout_ms" in data and (
            type(data["coverage_probe_timeout_ms"]) is not int
            or data["coverage_probe_timeout_ms"] < 20
        ):
            raise ValueError("coverage_probe_timeout_ms must be at least 20")
        if "coverage_probe_budget_seconds" in data and (
            type(data["coverage_probe_budget_seconds"]) is not int
            or data["coverage_probe_budget_seconds"] < 1
        ):
            raise ValueError("coverage_probe_budget_seconds must be positive")
        if "seed_replay_timeout_ms" in data and (
            type(data["seed_replay_timeout_ms"]) is not int
            or data["seed_replay_timeout_ms"] < 1
        ):
            raise ValueError("seed_replay_timeout_ms must be positive")
        if "seed_replay_budget_seconds" in data and (
            type(data["seed_replay_budget_seconds"]) is not int
            or data["seed_replay_budget_seconds"] < 1
        ):
            raise ValueError("seed_replay_budget_seconds must be positive")
        for name in ("research_only", "state_aware", "memory_limit_unlimited", "graceful_sigterm", "execute"):
            if name in data and type(data[name]) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if data["transport"] not in {"tcp", "udp"}:
            raise ValueError("network harness transport must be tcp or udp")
        if data["seed_tier"] not in {"proven", "exploratory", "diagnostic"}:
            raise ValueError("network harness seed_tier is invalid")
        if data["seed_tier"] != "proven" and data.get("research_only") is not True:
            raise ValueError("unproven network seeds require research_only=true")
        if not 1 <= data["port"] <= 65535 or data["seconds"] < 1:
            raise ValueError("network harness port or seconds is invalid")
        if data.get("startup_delay_us", 0) < 0:
            raise ValueError("startup_delay_us cannot be negative")
        for name in ("execution_timeout_ms", "memory_limit_mb"):
            if name in data and data[name] < 1:
                raise ValueError(f"{name} must be positive")
        if data.get("memory_limit_mb") is not None and data.get("memory_limit_unlimited", False):
            raise ValueError("memory_limit_mb conflicts with memory_limit_unlimited")
        return cls(resolved, data)

    def _path(self, value: str) -> Path:
        raw = Path(value).expanduser()
        return raw if raw.is_absolute() else self.path.parent / raw

    def spec(
        self, run_dir: Path, source_root: Path, *,
        server_binary: Path | None = None,
        build_manifest: Path | None = None,
        seed_run_dir: Path | None = None,
        campaign_name: str = "network-harness",
    ) -> StateAFLCampaignSpec:
        if campaign_name not in {"network-harness", "network-harness-refined"}:
            raise ValueError("unknown network campaign artifact name")
        data = self.data
        server = list(data["server_command"])
        server[0] = str(server_binary or self._path(server[0]))
        selected_manifest = build_manifest or (
            self._path(data["server_build_manifest"])
            if "server_build_manifest" in data else None
        )
        return StateAFLCampaignSpec(
            run_dir=seed_run_dir or run_dir,
            output_dir=run_dir / "research/stateafl" / campaign_name,
            afl_fuzz=self._path(data["afl_fuzz"]),
            afl_showmap=(self._path(data["afl_showmap"])
                         if "afl_showmap" in data else None),
            coverage_probe_timeout_ms=data.get("coverage_probe_timeout_ms"),
            coverage_probe_budget_seconds=data.get("coverage_probe_budget_seconds"),
            seed_replay_timeout_ms=data.get("seed_replay_timeout_ms"),
            seed_replay_budget_seconds=data.get("seed_replay_budget_seconds"),
            server_command=tuple(server),
            transport=data["transport"], host=data["host"], port=data["port"],
            seconds=data["seconds"], seed_tier=data["seed_tier"],
            research_only=data.get("research_only", False),
            state_aware=data.get("state_aware", False),
            startup_delay_us=data.get("startup_delay_us"),
            execution_timeout_ms=data.get("execution_timeout_ms"),
            memory_limit_mb=data.get("memory_limit_mb"),
            memory_limit_unlimited=data.get("memory_limit_unlimited", False),
            graceful_sigterm=data.get("graceful_sigterm", False),
            server_build_manifest=selected_manifest,
            expected_source_root=source_root,
            replay_server_command=(
                (str(self._path(data["replay_server_command"][0]).resolve()),
                 *data["replay_server_command"][1:])
                if "replay_server_command" in data else ()
            ),
            replay_timeout_ms=data.get("replay_timeout_ms"),
        )

    def prepare_or_run(
        self, run_dir: Path, source_root: Path, *,
        seed_run_dir: Path | None = None,
        stop_event: threading.Event | None = None,
        reuse_build_manifest: Path | None = None,
        campaign_name: str = "network-harness",
    ) -> dict[str, Any]:
        if stop_event is not None and stop_event.is_set():
            return {
                "status": "CANCELLED_BEFORE_PREPARATION",
                "reason": "the parent analysis stopped before network preparation",
                "qualified_harness_claim": False,
                "vulnerability_claim": False,
                "config_path": str(self.path),
                "config_sha256": hashlib.sha256(self.path.read_bytes()).hexdigest(),
            }
        try:
            server_binary: Path | None = None
            build_manifest: Path | None = None
            selected_seed_root = seed_run_dir or run_dir
            if "build" in self.data:
                manifest = json.loads(
                    (selected_seed_root / "research/stateafl/manifest.json").read_text(encoding="utf-8")
                )
                if not any(
                    isinstance(row, dict) and row.get("seed_path")
                    and row.get("channel") == self.data["transport"]
                    and Path(str(row["seed_path"])).parts[:3]
                        == ("research", "stateafl", self.data["seed_tier"])
                    for row in manifest.get("rows", [])
                ):
                    raise ValueError("no selected network seeds; automatic build was skipped")
                if reuse_build_manifest is not None:
                    build_manifest = reuse_build_manifest.resolve(strict=True)
                    report = json.loads(build_manifest.read_text(encoding="utf-8"))
                    if not isinstance(report, dict):
                        raise ValueError("reused server build manifest is invalid")
                else:
                    root = source_root.resolve(strict=True)
                    run = run_dir.resolve()
                    run_output_root = run.parent
                    excluded_run_artifacts = (
                        (run_output_root,)
                        if root in run_output_root.parents else
                        (run,) if root in run.parents else ()
                    )
                    build_output = (
                        root.parent / ".harnesscreator-stateafl-builds" / run.name
                        if root in run.parents else
                        run / "research/stateafl/instrumented-build"
                    )
                    build = self.data["build"]
                    report = build_stateafl_server(StateAFLBuildSpec(
                        source_root=root, output_dir=build_output,
                        compiler=self._path(build["compiler"]),
                        cxx_compiler=(self._path(build["cxx_compiler"])
                                      if build.get("cxx_compiler") else None),
                        build_command=tuple(build["command"]),
                        build_steps=tuple(tuple(step) for step in build.get("steps", [])),
                        server_relative_path=Path(build["server_relative_path"]),
                        timeout_seconds=build.get("timeout_seconds"),
                        linker_flags=tuple(build.get("linker_flags", [])),
                        container_image=build.get("container_image"),
                        excluded_paths=excluded_run_artifacts,
                        stop_event=stop_event,
                    ))
                    build_manifest = build_output / "build.json"
                if not has_instrumentation_evidence(report):
                    raise ValueError("automatic build produced no verified AFL instrumentation")
                server_binary = Path(report["server_binary"])
            elif reuse_build_manifest is not None:
                raise ValueError("a supplied server build cannot be reused in config mode")
            spec = self.spec(
                run_dir, source_root,
                server_binary=server_binary, build_manifest=build_manifest,
                seed_run_dir=selected_seed_root,
                campaign_name=campaign_name,
            )
            if self.data.get("execute", False):
                try:
                    result = run_stateafl_campaign(spec, stop_event=stop_event)
                except ValueError as exc:
                    # StateAFL checks host ASLR/crash settings before it
                    # creates the package. Preserve a valid replay artifact
                    # while reporting that no fuzz execution was observed.
                    if (spec.output_dir / "campaign.json").exists():
                        raise
                    result = prepare_stateafl_campaign(spec)
                    result["status"] = "PREPARED_EXECUTION_BLOCKED"
                    result["execution_blocker"] = str(exc)
            else:
                result = prepare_stateafl_campaign(spec)
        except (OSError, ValueError) as exc:
            result = {
                "status": "BLOCKED_UNQUALIFIED",
                "reason": f"{type(exc).__name__}: {exc}",
                "qualified_harness_claim": False,
                "vulnerability_claim": False,
            }
        result["config_path"] = str(self.path)
        result["config_sha256"] = hashlib.sha256(self.path.read_bytes()).hexdigest()
        return result

    def preflight(self, source_root: Path) -> None:
        # Validate the supplied, instrumented executable before an expensive
        # source inventory. Replay seeds cannot be checked until they exist.
        if "replay_server_command" in self.data:
            replay = self._path(self.data["replay_server_command"][0]).resolve(strict=True)
            if not replay.is_file() or not os.access(replay, os.X_OK):
                raise ValueError(f"original replay executable is not runnable: {replay}")
        if "afl_showmap" in self.data:
            probe = self._path(self.data["afl_showmap"]).resolve(strict=True)
            if not probe.is_file() or not os.access(probe, os.X_OK):
                raise ValueError(f"afl_showmap is not executable: {probe}")
        if "build" in self.data:
            afl = self._path(self.data["afl_fuzz"]).resolve(strict=True)
            if not afl.is_file() or not os.access(afl, os.X_OK):
                raise ValueError(f"afl_fuzz is not executable: {afl}")
            build = self.data["build"]
            for name in ("compiler", "cxx_compiler"):
                if name in build:
                    path = self._path(build[name]).resolve(strict=True)
                    if not path.is_file() or not os.access(path, os.X_OK):
                        raise ValueError(f"build.{name} is not executable: {path}")
            return
        verify_stateafl_build(self.spec(self.path.parent, source_root))


def _validate_argv(value: Any, name: str) -> None:
    if (not isinstance(value, list) or not value
        or any(not isinstance(part, str) or not part or "\x00" in part
               for part in value)):
        raise ValueError(f"{name} must be a nonempty argv array")
