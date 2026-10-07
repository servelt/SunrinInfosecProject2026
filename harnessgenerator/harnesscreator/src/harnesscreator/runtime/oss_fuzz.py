from __future__ import annotations

import dataclasses
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from ..analysis.graph import GraphStore
from ..models import CommandReport, HarnessDraft, ProjectSpec, SeedSpec, VerificationResult
from .runner import write_seed_suite


class OssFuzzBackendError(RuntimeError):
    """Raised when the paper-compatible QuartetFuzz backend is unavailable."""


@dataclasses.dataclass(frozen=True)
class _LocalSourceOverlay:
    source_root: Path
    output_root: Path
    project: str
    container_path: str
    harness_source_filename: str


@dataclasses.dataclass(frozen=True)
class _CampaignResult:
    corpus_dir: str
    corpus_size: int
    edges_covered: int
    features: int
    total_executions: int
    exec_per_second: int
    peak_rss_mb: int
    elapsed_seconds: float
    error: str | None
    output: str
    artifacts: tuple[Path, ...]


# Quartet creates a second BuildValidator internally for its coverage rebuild.
# Keying this hook by the isolated worker workspace makes the same local-source
# overlay apply to both the address and coverage builds without editing the
# checked-in QuartetFuzz reference implementation.
_LOCAL_SOURCE_OVERLAYS: dict[Path, _LocalSourceOverlay] = {}


def preflight_oss_fuzz_backend(
    project: ProjectSpec,
    *,
    check_docker: bool = True,
) -> dict[str, str]:
    """Fail before LLM work when the real verification path is unusable."""

    quartet_root = project.quartet_root or _default_quartet_root()
    dynamic_runner = _load_quartet_dynamic_runner(quartet_root)

    oss_fuzz_dir = project.oss_fuzz_dir
    oss_fuzz_project = project.oss_fuzz_project or ""
    if oss_fuzz_dir is None or not (oss_fuzz_dir / "infra" / "helper.py").is_file():
        raise OssFuzzBackendError(
            f"OSS-Fuzz checkout is not usable: {oss_fuzz_dir or '<unset>'}"
        )
    project_dir = oss_fuzz_dir / "projects" / oss_fuzz_project
    required_files = [
        project_dir / "Dockerfile",
        project_dir / "build.sh",
        project_dir / project.harness_source_filename,
    ]
    missing = [str(path) for path in required_files if not path.is_file()]
    if missing:
        raise OssFuzzBackendError(
            "canonical OSS-Fuzz project recipe is incomplete; missing: "
            + ", ".join(missing)
        )

    docker_version = "not checked"
    if check_docker:
        docker = shutil.which("docker")
        if not docker:
            raise OssFuzzBackendError(
                "Docker CLI is required by the OSS-Fuzz verifier but was not found"
            )
        try:
            result = subprocess.run(
                [docker, "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OssFuzzBackendError(
                f"failed to query the Docker daemon: {exc}"
            ) from exc
        docker_version = (result.stdout or "").strip()
        if result.returncode != 0 or not docker_version:
            detail = (result.stderr or result.stdout or "unknown Docker error").strip()
            raise OssFuzzBackendError(
                "Docker daemon is not directly accessible to HarnessCreator: "
                + detail[-1000:]
            )

    return {
        "quartet_dynamic_runner": (
            f"{dynamic_runner.__module__}.{dynamic_runner.__name__}"
        ),
        "oss_fuzz_project_dir": str(project_dir),
        "canonical_harness": str(project_dir / project.harness_source_filename),
        "docker_server_version": docker_version,
    }


def _load_quartet_dynamic_runner(quartet_root: Path) -> type[Any]:
    quartet_root = quartet_root.expanduser().resolve()
    dynamic_path = quartet_root / "harness" / "checker" / "dynamic.py"
    if not dynamic_path.is_file():
        raise OssFuzzBackendError(
            "QuartetFuzz reference implementation is unavailable at "
            f"{quartet_root}; pass --quartet-root"
        )
    root_text = str(quartet_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    try:
        from harness.checker.dynamic import DynamicRunner  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - depends on local extras
        raise OssFuzzBackendError(
            f"failed to import QuartetFuzz DynamicRunner from {quartet_root}: {exc}"
        ) from exc

    module = sys.modules.get(DynamicRunner.__module__)
    module_file = Path(str(getattr(module, "__file__", ""))).resolve()
    try:
        module_file.relative_to(quartet_root)
    except ValueError as exc:
        raise OssFuzzBackendError(
            "Python imported a different 'harness' package instead of the configured "
            f"QuartetFuzz checkout: {module_file}"
        ) from exc
    _install_local_source_overlay_hook(DynamicRunner)
    return DynamicRunner


class QuartetOssFuzzVerifierAgent:
    """Adapter around QuartetFuzz's real OSS-Fuzz ``DynamicRunner``.

    The command backend is useful for local projects, but it cannot establish
    the same build and coverage boundary used by QuartetFuzz.  This adapter
    intentionally reuses the checked-in reference implementation for:

    * isolated, pinned OSS-Fuzz workspaces;
    * replacement of the canonical fuzzer source;
    * project-image builds against real project objects;
    * sanitizer blob replay and in-container GDB reachability; and
    * a coverage-sanitized rebuild followed by llvm-cov collection.

    HarnessCreator still owns Entry/Small/Large Feature discovery and supplies
    those contracts to the generated harness; only the execution/measurement
    mechanism is delegated to the paper implementation.
    """

    def __init__(
        self,
        project: ProjectSpec,
        graph: GraphStore,
        *,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.project = project
        self.graph = graph
        self.progress = progress
        self._runners: dict[str, Any] = {}
        self._dynamic_runner_type: type[Any] | None = None

    def _emit(self, message: str) -> None:
        if self.progress:
            self.progress(message)

    def _load_dynamic_runner(self) -> type[Any]:
        if self._dynamic_runner_type is not None:
            return self._dynamic_runner_type
        quartet_root = self.project.quartet_root
        if quartet_root is None:
            quartet_root = _default_quartet_root()
        DynamicRunner = _load_quartet_dynamic_runner(quartet_root)
        self._dynamic_runner_type = DynamicRunner
        return DynamicRunner

    def _runner(self, harness_id: str) -> Any:
        existing = self._runners.get(harness_id)
        if existing is not None:
            return existing
        project = self.project.oss_fuzz_project
        fuzzer = self.project.oss_fuzz_fuzzer
        if not project or not fuzzer:
            raise OssFuzzBackendError(
                "OSS-Fuzz verification needs a resolved project and fuzzer target"
            )
        dynamic_runner = self._load_dynamic_runner()
        workspace = Path(
            tempfile.mkdtemp(prefix=f"harnesscreator-{project}-{harness_id[:12]}-")
        )
        if not self.project.oss_fuzz_source_path:
            raise OssFuzzBackendError(
                "local source overlay path is unresolved; pass --oss-fuzz-source-path"
            )
        source_snapshot = workspace / "local-source-snapshot"
        _copy_local_source_tree(
            self.project.source_root,
            source_snapshot,
            self.project.output_root,
        )
        _LOCAL_SOURCE_OVERLAYS[workspace.resolve()] = _LocalSourceOverlay(
            source_root=source_snapshot,
            output_root=workspace / "excluded-output-does-not-exist",
            project=project,
            container_path=self.project.oss_fuzz_source_path,
            harness_source_filename=self.project.harness_source_filename,
        )
        suffix = Path(self.project.harness_source_filename).suffix.lower()
        runner = dynamic_runner(
            project=project,
            source_oss_fuzz_dir=self.project.oss_fuzz_dir,
            worker_workspace=workspace,
            sanitizer="address",
            fuzzer_name=fuzzer,
            language="c" if suffix == ".c" else "c++",
        )
        self._runners[harness_id] = runner
        return runner

    async def probe_canonical_build(self) -> str:
        """Build the pinned canonical harness against the requested checkout.

        This is a startup calibration, not a generated result.  It proves that
        the local source overlay, pinned OSS-Fuzz recipe, compiler image, and
        canonical fuzzer integration work together before model calls begin.
        """

        harness_id = "__canonical_preflight__"
        source_filename = self.project.harness_source_filename
        source = _read_pinned_project_file(self.project, source_filename)
        if not source:
            raise OssFuzzBackendError(
                "cannot read the pinned canonical OSS-Fuzz harness source: "
                f"projects/{self.project.oss_fuzz_project}/{source_filename}"
            )
        runner = self._runner(harness_id)
        self._emit(
            "OSS-Fuzz canonical/local-checkout build probe started: "
            f"{self.project.oss_fuzz_project}/{self.project.oss_fuzz_fuzzer}"
        )
        try:
            try:
                result = runner.build(source, source_filename)
            except Exception as exc:
                raise OssFuzzBackendError(
                    f"canonical OSS-Fuzz build infrastructure failed: {exc}"
                ) from exc
            if not bool(getattr(result, "build_ok", False)):
                error = str(getattr(result, "build_error", "") or "unknown build error")
                log = str(getattr(result, "build_log_tail", "") or "")
                raise OssFuzzBackendError(
                    "canonical harness does not build against the requested local checkout: "
                    + error
                    + ("\n" + log[-4000:] if log else "")
                )
            binary = str(
                getattr(result, "binary_name", "")
                or self.project.oss_fuzz_fuzzer
                or ""
            )
            self._emit(
                f"OSS-Fuzz canonical/local-checkout build probe passed: {binary}"
            )
            # A successful image build does not prove that Docker can execute
            # the produced fuzzer.  Exercise the exact AP_Run_check path now,
            # before hours of LLM work, so mount/runtime failures cannot first
            # appear after harness generation.
            try:
                replay = _run_seed_with_project_options(
                    runner,
                    b"",
                    project=self.project.oss_fuzz_project or "",
                    binary_name=binary,
                    detect_leaks=_target_detect_leaks(
                        runner,
                        self.project.oss_fuzz_project or "",
                        binary,
                    ),
                )
            except Exception as exc:
                raise OssFuzzBackendError(
                    f"canonical OSS-Fuzz runtime probe failed: {exc}"
                ) from exc
            replay_error = str(replay.get("error") or "")
            if replay_error or bool(replay.get("crashed", False)):
                detail = replay_error or str(replay.get("output") or "")[-2000:]
                raise OssFuzzBackendError(
                    "canonical OSS-Fuzz runtime probe did not complete cleanly: "
                    + (detail or f"exit={replay.get('exit_code')}")
                )
            self._emit(
                f"OSS-Fuzz canonical/local-checkout runtime probe passed: {binary}"
            )
            return binary
        finally:
            await self.close_harness(harness_id)

    async def verify(
        self,
        draft: HarnessDraft,
        artifact_dir: Path,
        llm_seeds: list[SeedSpec] | None = None,
        *,
        runtime_checks: bool = True,
    ) -> VerificationResult:
        started = time.monotonic()
        backend = "quartet-oss-fuzz"
        try:
            runner = self._runner(draft.manifest.harness_id)
        except Exception as exc:
            return VerificationResult(
                qualified=False,
                build=None,
                replays=[],
                fuzz=None,
                harness_faults=[],
                target_findings=[],
                coverage_grew=None,
                reason=f"OSS-Fuzz backend initialization failed: {exc}",
                backend=backend,
                infrastructure_error=str(exc),
            )

        source_filename = Path(draft.manifest.source_file).name
        self._emit(
            f"OSS-Fuzz build started: {draft.manifest.harness_id} -> "
            f"{self.project.oss_fuzz_project}/{self.project.oss_fuzz_fuzzer}"
        )
        try:
            # QuartetFuzz's reference runner is synchronous by design.  Run it
            # on the orchestrator turn so build/run ordering and its mutable
            # worker workspace cannot overlap or outlive the event loop.
            built = runner.build(draft.code, source_filename)
        except Exception as exc:
            build = _report(
                ["quartet-oss-fuzz", "build", source_filename],
                1,
                stderr=str(exc),
                duration=time.monotonic() - started,
            )
            return VerificationResult(
                qualified=False,
                build=build,
                replays=[],
                fuzz=None,
                harness_faults=[],
                target_findings=[],
                coverage_grew=None,
                reason=f"OSS-Fuzz build infrastructure failed: {exc}",
                backend=backend,
                infrastructure_error=str(exc),
            )

        build_ok = bool(getattr(built, "build_ok", False))
        build_error = str(getattr(built, "build_error", ""))
        build_log = str(getattr(built, "build_log_tail", ""))
        binary_name = str(
            getattr(built, "binary_name", "") or self.project.oss_fuzz_fuzzer or ""
        )
        build = _report(
            ["quartet-oss-fuzz", "build", source_filename],
            0 if build_ok else 1,
            stdout=f"binary={binary_name}" if build_ok else "",
            stderr=(build_error + "\n" + build_log).strip(),
            duration=time.monotonic() - started,
        )
        self._emit(
            f"OSS-Fuzz build completed: {'PASS' if build_ok else 'FAIL'}"
        )
        if not build_ok:
            return VerificationResult(
                qualified=False,
                build=build,
                replays=[],
                fuzz=None,
                harness_faults=[],
                target_findings=[],
                coverage_grew=None,
                reason=f"OSS-Fuzz project build failed: {build_error or 'unknown build error'}",
                backend=backend,
            )
        if not runtime_checks:
            return VerificationResult(
                qualified=False,
                build=build,
                replays=[],
                fuzz=None,
                harness_faults=[],
                target_findings=[],
                coverage_grew=None,
                reason="OSS-Fuzz build-only validation passed; runtime qualification was disabled",
                build_ok=True,
                backend=backend,
            )

        seed_dir = artifact_dir / "seeds"
        seed_dir.mkdir(parents=True, exist_ok=True)
        seeds = write_seed_suite(
            seed_dir,
            draft.manifest.min_size,
            draft.manifest.variant_count,
            llm_seeds or [],
            max_size=draft.manifest.max_size,
        )
        replays: list[CommandReport] = []
        harness_faults: list[str] = []
        target_findings: list[str] = []
        target_finding_seeds: list[SeedSpec] = []
        regression_seeds: list[SeedSpec] = []
        replay_infrastructure_errors: list[str] = []
        baseline_edges: int | None = None
        detect_leaks = _target_detect_leaks(runner, self.project.oss_fuzz_project or "", binary_name)
        coverage_metrics_seed: dict[str, Any] = {
            "target_detect_leaks": detect_leaks,
        }
        self._emit(f"OSS-Fuzz adversarial replay started: {len(seeds)} seeds")
        for index, seed in enumerate(seeds, start=1):
            data = seed.read_bytes()
            replay_started = time.monotonic()
            try:
                result = _run_seed_with_project_options(
                    runner,
                    data,
                    project=self.project.oss_fuzz_project or "",
                    binary_name=binary_name,
                    detect_leaks=detect_leaks,
                )
            except Exception as exc:
                replay_infrastructure_errors.append(
                    f"{seed.name}: AP_Run_check raised {type(exc).__name__}: {exc}"
                )
                break
            output = str(result.get("output", ""))
            if not data:
                baseline_edges = _last_libfuzzer_coverage(output)
            error = str(result.get("error") or "")
            crashed = bool(result.get("crashed", False))
            report = _report(
                ["quartet-oss-fuzz", "AP_Run_check", seed.name],
                int(result.get("exit_code", 0)),
                stdout=output,
                stderr=error,
                duration=time.monotonic() - replay_started,
            )
            replays.append(report)
            if error and not crashed:
                replay_infrastructure_errors.append(
                    f"{seed.name}: AP_Run_check infrastructure error: {error}"
                )
                continue
            if crashed:
                try:
                    stack = runner.gdb(
                        data,
                        binary_name=binary_name,
                        max_output_bytes=12_000,
                    )
                except Exception as exc:
                    replay_infrastructure_errors.append(
                        f"{seed.name}: GDB attribution raised {type(exc).__name__}: {exc}"
                    )
                    break
                attribution = _crash_attribution(
                    str(stack),
                    source_filename,
                    target_source_path=self.project.oss_fuzz_source_path,
                    target_source_basenames={
                        Path(function.file).name
                        for function in self.graph.bundle.functions.values()
                    },
                )
                detail = (
                    f"sanitizer={result.get('sanitizer') or 'signal/unknown'}; "
                    f"exit={result.get('exit_code')}; attribution={attribution};\n"
                    f"{str(stack)[-8000:]}"
                )
                if attribution == "target":
                    finding = f"{seed.name}: {detail}"
                    target_findings.append(finding)
                    target_finding_seeds.append(SeedSpec(
                        name=f"finding-{seed.name}"[:80],
                        data_hex=data.hex(),
                        rationale=finding[:1000],
                    ))
                else:
                    harness_faults.append(f"{seed.name}: {detail}")
                    regression_seeds.append(
                        SeedSpec(
                            name=f"regression-{seed.name}"[:80],
                            data_hex=data.hex(),
                            rationale=detail[:1000],
                        )
                    )
            if index == len(seeds) or index % 5 == 0:
                self._emit(f"OSS-Fuzz adversarial replay {index}/{len(seeds)}")
        if replay_infrastructure_errors:
            detail = "\n".join(replay_infrastructure_errors)
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=None,
                harness_faults=[],
                target_findings=target_findings,
                target_finding_seeds=target_finding_seeds,
                coverage_grew=None,
                reason="OSS-Fuzz adversarial replay infrastructure failed",
                build_ok=True,
                backend=backend,
                infrastructure_error=detail,
            )
        if harness_faults:
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=None,
                harness_faults=harness_faults,
                target_findings=target_findings,
                target_finding_seeds=target_finding_seeds,
                coverage_grew=None,
                reason="adversarial replay exposed a harness or unattributed fault",
                harness_fault_seeds=regression_seeds,
                build_ok=True,
                backend=backend,
            )

        reachability, reached, reach_error = await self._verify_reachability(
            runner, binary_name, seeds, draft
        )
        if reach_error:
            infrastructure_error = (
                reach_error
                if reach_error.startswith("verification infrastructure failed")
                else None
            )
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=None,
                harness_faults=[] if infrastructure_error else [reach_error],
                target_findings=target_findings,
                target_finding_seeds=target_finding_seeds,
                coverage_grew=None,
                reason="expected application anchor reachability was not established",
                reachability=reachability,
                reachable_seed_count=reached,
                build_ok=True,
                backend=backend,
                infrastructure_error=infrastructure_error,
            )

        self._emit(
            f"OSS-Fuzz qualification fuzzing started: {self.project.fuzz_seconds}s"
        )
        fuzz_started = time.monotonic()
        try:
            fuzz_result = _run_qualification_campaign(
                runner,
                project=self.project.oss_fuzz_project or "",
                binary_name=binary_name,
                duration=self.project.fuzz_seconds,
                max_len=draft.manifest.max_size,
                artifact_dir=artifact_dir / "crashes",
                detect_leaks=detect_leaks,
            )
        except Exception as exc:
            detail = f"qualification runner raised {type(exc).__name__}: {exc}"
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=None,
                harness_faults=[],
                target_findings=target_findings,
                target_finding_seeds=target_finding_seeds,
                coverage_grew=None,
                reason="OSS-Fuzz qualification infrastructure failed",
                reachability=reachability,
                reachable_seed_count=reached,
                build_ok=True,
                backend=backend,
                infrastructure_error=detail,
            )
        fuzz_error = str(getattr(fuzz_result, "error", "") or "")
        fuzz = _report(
            ["quartet-oss-fuzz", "libfuzzer", binary_name],
            1 if fuzz_error else 0,
            stdout=(str(getattr(fuzz_result, "output", "")) or (
                f"edges={getattr(fuzz_result, 'edges_covered', 0)} "
                f"features={getattr(fuzz_result, 'features', 0)} "
                f"corpus={getattr(fuzz_result, 'corpus_size', 0)} "
                f"executions={getattr(fuzz_result, 'total_executions', 0)}"
            )),
            stderr=fuzz_error,
            duration=time.monotonic() - fuzz_started,
        )
        if fuzz_error:
            if fuzz_error.startswith("Fuzzer infrastructure error:"):
                return VerificationResult(
                    qualified=False,
                    build=build,
                    replays=replays,
                    fuzz=fuzz,
                    harness_faults=[],
                    target_findings=target_findings,
                    target_finding_seeds=target_finding_seeds,
                    coverage_grew=None,
                    reason="OSS-Fuzz qualification infrastructure failed",
                    reachability=reachability,
                    reachable_seed_count=reached,
                    build_ok=True,
                    backend=backend,
                    infrastructure_error=fuzz_error,
                )
            fuzz_artifacts = list(getattr(fuzz_result, "artifacts", ()) or ())
            attributed_harness_faults: list[str] = []
            campaign_target_findings: list[str] = []
            campaign_infrastructure_errors: list[str] = []
            for crash_path in fuzz_artifacts:
                data = crash_path.read_bytes()
                try:
                    stack = runner.gdb(
                        data,
                        binary_name=binary_name,
                        max_output_bytes=12_000,
                    )
                except Exception as exc:
                    campaign_infrastructure_errors.append(
                        f"{crash_path.name}: GDB attribution raised "
                        f"{type(exc).__name__}: {exc}"
                    )
                    continue
                attribution = _crash_attribution(
                    str(stack),
                    source_filename,
                    target_source_path=self.project.oss_fuzz_source_path,
                    target_source_basenames={
                        Path(function.file).name
                        for function in self.graph.bundle.functions.values()
                    },
                )
                detail = (
                    f"qualification artifact={crash_path.name}; attribution={attribution};\n"
                    f"{str(stack)[-8000:]}"
                )
                if attribution == "target":
                    campaign_target_findings.append(detail)
                    target_findings.append(detail)
                    target_finding_seeds.append(SeedSpec(
                        name=f"finding-{crash_path.name}"[:80],
                        data_hex=data.hex(),
                        rationale=detail[:1000],
                    ))
                else:
                    attributed_harness_faults.append(detail)
                    regression_seeds.append(SeedSpec(
                        name=f"regression-{crash_path.name}"[:80],
                        data_hex=data.hex(),
                        rationale=detail[:1000],
                    ))
            if campaign_infrastructure_errors:
                return VerificationResult(
                    qualified=False,
                    build=build,
                    replays=replays,
                    fuzz=fuzz,
                    harness_faults=[],
                    target_findings=target_findings,
                    target_finding_seeds=target_finding_seeds,
                    coverage_grew=None,
                    reason="OSS-Fuzz qualification attribution infrastructure failed",
                    reachability=reachability,
                    reachable_seed_count=reached,
                    build_ok=True,
                    backend=backend,
                    infrastructure_error="\n".join(campaign_infrastructure_errors),
                )
            if campaign_target_findings and not attributed_harness_faults:
                return VerificationResult(
                    qualified=True,
                    build=build,
                    replays=replays,
                    fuzz=fuzz,
                    harness_faults=[],
                    target_findings=target_findings,
                    target_finding_seeds=target_finding_seeds,
                    coverage_grew=None,
                    reason=(
                        "qualification campaign exposed a GDB-attributed target finding"
                    ),
                    reachability=reachability,
                    reachable_seed_count=reached,
                    build_ok=True,
                    backend=backend,
                    coverage_metrics=coverage_metrics_seed,
                )
            fault_details = attributed_harness_faults or [
                fuzz_error + (
                    "; no crash artifact was available for target attribution"
                    if not fuzz_artifacts else ""
                )
            ]
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=fuzz,
                harness_faults=fault_details,
                target_findings=target_findings,
                target_finding_seeds=target_finding_seeds,
                coverage_grew=False,
                reason="OSS-Fuzz qualification fuzzing failed",
                reachability=reachability,
                reachable_seed_count=reached,
                harness_fault_seeds=regression_seeds,
                build_ok=True,
                backend=backend,
            )

        self._emit("OSS-Fuzz coverage rebuild and llvm-cov collection started")
        try:
            coverage = runner.coverage(
                binary_name=binary_name,
                fuzz_seconds=0,
            )
        except Exception as exc:
            detail = f"coverage runner raised {type(exc).__name__}: {exc}"
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=fuzz,
                harness_faults=[],
                target_findings=target_findings,
                target_finding_seeds=target_finding_seeds,
                coverage_grew=None,
                reason="OSS-Fuzz coverage infrastructure failed",
                reachability=reachability,
                reachable_seed_count=reached,
                build_ok=True,
                backend=backend,
                infrastructure_error=detail,
            )
        coverage_metrics = _coverage_dict(coverage)
        coverage_metrics.update(coverage_metrics_seed)
        coverage_metrics.update(
            _scoped_target_coverage(
                runner,
                self.project.oss_fuzz_project or "",
                binary_name,
                self.project.oss_fuzz_source_path or "",
                source_filename,
            )
        )
        coverage_metrics["source_provenance"] = _source_provenance(
            self.project.source_root
        )
        coverage_error = str(getattr(coverage, "error", "") or "")
        corpus_size = int(getattr(fuzz_result, "corpus_size", 0) or 0)
        edges = int(getattr(fuzz_result, "edges_covered", 0) or 0)
        campaign_cov_values = _libfuzzer_coverage_values(
            str(getattr(fuzz_result, "output", ""))
        )
        effective_baseline_edges = baseline_edges
        baseline_source = "empty-seed-replay"
        if effective_baseline_edges is None and campaign_cov_values:
            effective_baseline_edges = campaign_cov_values[0]
            baseline_source = "first-campaign-cov"
        project_functions = int(coverage_metrics.get("target_functions_covered", 0) or 0)
        project_lines = int(coverage_metrics.get("target_lines_covered", 0) or 0)
        coverage_metrics.update({
            "baseline_edges": effective_baseline_edges,
            "baseline_source": baseline_source,
            "campaign_cov_values": campaign_cov_values,
            "final_edges": edges,
            "fresh_corpus_size": corpus_size,
        })
        # AP_Run_check above executes the empty input before the fresh-corpus
        # fuzz run. Comparing that INITED/one-run cov value with the final
        # libFuzzer cov value proves growth; non-zero project llvm-cov prevents
        # harness-only selector branches from satisfying qualification.
        coverage_grew = bool(
            not coverage_error
            and effective_baseline_edges is not None
            and edges > effective_baseline_edges
            and corpus_size > 0
            and coverage_metrics.get("target_coverage_scope_verified") is True
            and project_functions > 0
            and project_lines > 0
        )
        qualified = coverage_grew
        return VerificationResult(
            qualified=qualified,
            build=build,
            replays=replays,
            fuzz=fuzz,
            harness_faults=([] if qualified else [coverage_error or (
                "fresh-corpus growth and non-zero project llvm-cov were not both established"
            )]),
            target_findings=target_findings,
            target_finding_seeds=target_finding_seeds,
            coverage_grew=coverage_grew,
            reason=(
                "OSS-Fuzz build, adversarial replay, target reachability, fresh-corpus fuzzing, and llvm-cov passed"
                if qualified
                else "application coverage qualification failed"
            ),
            reachability=reachability,
            reachable_seed_count=reached,
            build_ok=True,
            backend=backend,
            coverage_metrics=coverage_metrics,
        )

    async def _verify_reachability(
        self,
        runner: Any,
        binary_name: str,
        seeds: list[Path],
        draft: HarnessDraft,
    ) -> tuple[list[CommandReport], int, str | None]:
        reports: list[CommandReport] = []
        anchors = [
            self.graph.bundle.functions[item]
            for item in draft.manifest.expected_anchors
            if item in self.graph.bundle.functions
        ]
        if not anchors:
            return reports, 0, "manifest has no graph-resolved application anchor"
        anchor_name = anchors[0].name
        required = min(5, len(seeds))
        reached = 0
        for seed in seeds:
            started = time.monotonic()
            try:
                result = runner.check_target_reached(
                    _blob_generator(seed.read_bytes()),
                    anchor_name,
                    binary_name=binary_name,
                )
            except Exception as exc:
                return reports, reached, (
                    "verification infrastructure failed during GDB reachability: "
                    f"{type(exc).__name__}: {exc}"
                )
            hit = bool(result.get("hit", False))
            error = str(result.get("error") or "")
            debugger_error = _debugger_infrastructure_error(result)
            reports.append(_report(
                ["quartet-oss-fuzz", "AP_Reach_check", anchor_name, seed.name],
                0 if hit and not error else 1,
                stdout=str(result.get("gdb_output", "")),
                stderr=error,
                duration=time.monotonic() - started,
            ))
            if debugger_error:
                return reports, reached, debugger_error
            if hit:
                reached += 1
                if reached >= required:
                    break
        if reached < required:
            return reports, reached, (
                f"only {reached}/{required} adversarial seeds reached expected anchor {anchor_name}"
            )

        for variant in draft.manifest.variant_targets:
            selector = str(variant.get("selector", ""))
            function = self.graph.bundle.functions.get(
                str(variant.get("function_id", ""))
            )
            pattern = re.compile(rf"^(?:llm-)?variant-{re.escape(selector)}(?:$|[-_.])")
            selected = [seed for seed in seeds if pattern.search(seed.name)]
            if function is None or not selected:
                return reports, reached, (
                    f"variant {selector} has no graph-resolved target or selector seed"
                )
            hit = False
            for seed in selected:
                started = time.monotonic()
                try:
                    result = runner.check_target_reached(
                        _blob_generator(seed.read_bytes()),
                        function.name,
                        binary_name=binary_name,
                    )
                except Exception as exc:
                    return reports, reached, (
                        "verification infrastructure failed during GDB reachability: "
                        f"{type(exc).__name__}: {exc}"
                    )
                error = str(result.get("error") or "")
                variant_hit = bool(result.get("hit", False))
                debugger_error = _debugger_infrastructure_error(result)
                reports.append(_report(
                    [
                        "quartet-oss-fuzz", "AP_Reach_check", function.name,
                        seed.name,
                    ],
                    0 if variant_hit and not error else 1,
                    stdout=str(result.get("gdb_output", "")),
                    stderr=error,
                    duration=time.monotonic() - started,
                ))
                if debugger_error:
                    return reports, reached, debugger_error
                if variant_hit:
                    hit = True
                    break
            if not hit:
                return reports, reached, (
                    f"selector {selector} did not reach Small Feature target {function.name}"
                )
        return reports, reached, None

    async def close(self) -> None:
        for harness_id in list(self._runners):
            await self.close_harness(harness_id)

    async def close_harness(self, harness_id: str) -> None:
        runner = self._runners.pop(harness_id, None)
        if runner is not None:
            workspace = getattr(runner, "worker_workspace", None)
            if workspace is not None:
                _LOCAL_SOURCE_OVERLAYS.pop(Path(workspace).resolve(), None)
            try:
                runner.cleanup()
            except Exception:
                # Cleanup must not replace an already written verification
                # result. QuartetFuzz's runner logs its own cleanup failures.
                pass


def _default_quartet_root() -> Path:
    workspace = Path(__file__).resolve().parents[4]
    return workspace / "QuartetFuzz" / "QuartetFuzz"


def _read_pinned_project_file(project: ProjectSpec, filename: str) -> str:
    if project.oss_fuzz_dir is None or not project.oss_fuzz_project:
        return ""
    relative = Path("projects") / project.oss_fuzz_project / filename
    if project.oss_fuzz_revision:
        try:
            result = subprocess.run(
                [
                    "git",
                    "show",
                    f"{project.oss_fuzz_revision}:{relative.as_posix()}",
                ],
                cwd=project.oss_fuzz_dir,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        if result is not None and result.returncode == 0:
            return result.stdout
    path = project.oss_fuzz_dir / relative
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    return ""


def _install_local_source_overlay_hook(dynamic_runner_type: type[Any]) -> None:
    """Inject a workspace-scoped source overlay into Quartet's validators.

    ``DynamicRunner`` creates one validator for ASan and another for coverage.
    Hooking the shared private validator class at its build boundary ensures
    both builds consume the same local checkout. The original build method is
    still responsible for invoking the unmodified OSS-Fuzz helper.
    """

    module = sys.modules.get(dynamic_runner_type.__module__)
    validator_type = getattr(module, "_BuildValidatorKeepArtifacts", None)
    if validator_type is None or getattr(
        validator_type, "_harnesscreator_local_source_hook", False
    ):
        return
    original_build = validator_type._build

    def build_with_local_source(instance: Any, workspace_dir: Path) -> Any:
        key = Path(instance.workspace_root).resolve()
        overlay = _LOCAL_SOURCE_OVERLAYS.get(key)
        if overlay is not None:
            _install_local_source_overlay(Path(workspace_dir), overlay)
        return original_build(instance, workspace_dir)

    validator_type._build = build_with_local_source
    validator_type._harnesscreator_local_source_hook = True


def _install_local_source_overlay(
    oss_fuzz_workspace: Path,
    overlay: _LocalSourceOverlay,
) -> None:
    project_dir = oss_fuzz_workspace / "projects" / overlay.project
    dockerfile = project_dir / "Dockerfile"
    if not dockerfile.is_file():
        raise OssFuzzBackendError(
            f"OSS-Fuzz project Dockerfile is missing: {dockerfile}"
        )
    context_source = project_dir / ".harnesscreator-local-source"
    if context_source.exists():
        shutil.rmtree(context_source)

    _copy_local_source_tree(
        overlay.source_root,
        context_source,
        overlay.output_root,
    )

    begin = "# HARNESSCREATOR_LOCAL_SOURCE_BEGIN"
    end = "# HARNESSCREATOR_LOCAL_SOURCE_END"
    lines = dockerfile.read_text(encoding="utf-8", errors="replace").splitlines()
    cleaned: list[str] = []
    skipping = False
    for line in lines:
        if line.strip() == begin:
            skipping = True
            continue
        if line.strip() == end:
            skipping = False
            continue
        if not skipping:
            cleaned.append(line)
    insert_at = next(
        (
            index for index, line in enumerate(cleaned)
            if line.strip().startswith(f"COPY {overlay.harness_source_filename} ")
        ),
        next(
            (
                index for index, line in enumerate(cleaned)
                if line.strip().startswith("WORKDIR")
            ),
            len(cleaned),
        ),
    )
    block = [
        begin,
        (
            "RUN command -v gdb >/dev/null 2>&1 || "
            "(apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "
            "--no-install-recommends gdb && rm -rf /var/lib/apt/lists/*)"
        ),
        f"RUN rm -rf {overlay.container_path}",
        f"COPY .harnesscreator-local-source {overlay.container_path}",
        end,
    ]
    cleaned[insert_at:insert_at] = block
    dockerfile.write_text("\n".join(cleaned) + "\n", encoding="utf-8")


def _copy_local_source_tree(source_root: Path, destination: Path, output_root: Path) -> None:
    """Take a deterministic per-harness snapshot while excluding run artifacts."""

    ignored_roots = {".git", ".hg", ".svn", "__pycache__", ".fuzz-introspector"}
    try:
        relative_output = output_root.resolve().relative_to(source_root.resolve())
        if relative_output.parts:
            ignored_roots.add(relative_output.parts[0])
    except ValueError:
        pass

    def ignore(directory: str, names: list[str]) -> set[str]:
        if Path(directory).resolve() == source_root.resolve():
            return {
                name for name in names
                if name in ignored_roots
                or name == "runs"
                or name.startswith("runs-")
                or name == "harnesscreator-runs"
            }
        return {name for name in names if name in {".git", "__pycache__"}}

    shutil.copytree(
        source_root,
        destination,
        symlinks=True,
        ignore=ignore,
    )


def _blob_generator(data: bytes) -> str:
    # The code is executed only by the trusted QuartetFuzz runner.  Hex keeps
    # arbitrary bytes and embedded NULs deterministic without escaping bugs.
    return f"def generate() -> bytes:\n    return bytes.fromhex({data.hex()!r})\n"


def _target_detect_leaks(runner: Any, project: str, binary_name: str) -> bool:
    """Honor the target's canonical OSS-Fuzz ``.options`` leak policy."""

    workspace = getattr(runner, "_workspace_dir", None)
    if workspace is None:
        return True
    options = Path(workspace) / "build" / "out" / project / f"{binary_name}.options"
    if not options.is_file():
        return True
    try:
        content = options.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    match = re.search(
        r"(?im)^\s*detect_leaks\s*=\s*(0|1|true|false|yes|no)\s*$",
        content,
    )
    if not match:
        return True
    return match.group(1).casefold() in {"1", "true", "yes"}


def _run_seed_with_project_options(
    runner: Any,
    data: bytes,
    *,
    project: str,
    binary_name: str,
    detect_leaks: bool,
) -> dict[str, Any]:
    """Run Quartet AP_Run_check, correcting only its ignored leak option.

    Most targets use the reference implementation unchanged.  For a target
    whose canonical OSS-Fuzz options explicitly disable leak detection, use
    the same image/binary/input mounting scheme with that setting.  This
    avoids rejecting the gold integration for process-lifetime initialization
    allocations while retaining ASan for memory-safety faults.
    """

    if detect_leaks or not _has_real_quartet_binary(runner, binary_name):
        return runner.run_blob(
            _blob_generator(data),
            binary_name=binary_name,
        )
    binary_dir = _address_binary_dir(runner, project)
    with tempfile.NamedTemporaryFile(
        prefix="hc-replay-",
        suffix=".bin",
        dir=runner.worker_workspace,
        delete=False,
    ) as handle:
        handle.write(data)
        input_path = Path(handle.name)
    command = [
        "docker", "run", "--rm",
        "-e", "ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=0:print_summary=1:symbolize=1",
        "-e", "LSAN_OPTIONS=exitcode=23:print_summary=1",
        "-e", "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
        "-v", f"{binary_dir}:/out:ro",
        "-v", f"{input_path}:/input.bin:ro",
        f"gcr.io/oss-fuzz/{project}",
        f"/out/{binary_name}",
        "/input.bin",
    ]
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=40,
            errors="replace",
            check=False,
        )
        output = (process.stdout or "") + (process.stderr or "")
        sanitizer = _sanitizer_name(output)
        crashed = sanitizer is not None or process.returncode not in {0, 77}
        return {
            "crashed": crashed,
            "sanitizer": sanitizer,
            "output": output[:12_000],
            "exit_code": process.returncode,
            "error": None,
        }
    except subprocess.TimeoutExpired as exc:
        output = _subprocess_text(exc.stdout) + _subprocess_text(exc.stderr)
        return {
            "crashed": True,
            "sanitizer": None,
            "output": output[:12_000],
            "exit_code": -9,
            "error": "timeout",
        }
    except OSError as exc:
        return {
            "crashed": False,
            "sanitizer": None,
            "output": "",
            "exit_code": -1,
            "error": f"docker replay failed: {exc}",
        }
    finally:
        try:
            input_path.unlink()
        except OSError:
            pass


def _run_qualification_campaign(
    runner: Any,
    *,
    project: str,
    binary_name: str,
    duration: int,
    max_len: int,
    artifact_dir: Path,
    detect_leaks: bool,
) -> Any:
    """Run the Quartet campaign while preserving crash artifacts.

    The checked-in runner discards libFuzzer's default crash files inside the
    transient container.  This extension uses the same address binary/image
    and fresh system-check corpus, but mounts an explicit artifact directory
    so every campaign failure can be attributed with Quartet's GDB path.
    """

    if not _has_real_quartet_binary(runner, binary_name):
        return runner.run(duration, binary_name=binary_name)
    workspace = Path(runner._workspace_dir)
    corpus = (
        workspace / "build" / "corpus" / project
        / f"{binary_name}_systemcheck"
    )
    if corpus.exists():
        shutil.rmtree(corpus)
    corpus.mkdir(parents=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for existing in artifact_dir.iterdir():
        if existing.is_file():
            existing.unlink()
    binary_dir = _address_binary_dir(runner, project)
    asan = (
        f"detect_leaks={1 if detect_leaks else 0}:halt_on_error=1:"
        "abort_on_error=0:print_summary=1:symbolize=1"
    )
    command = [
        "docker", "run", "--rm",
        "-e", f"ASAN_OPTIONS={asan}",
        "-e", "LSAN_OPTIONS=exitcode=23:print_summary=1",
        "-e", "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1",
        "-v", f"{binary_dir}:/out:ro",
        "-v", f"{corpus}:/corpus",
        "-v", f"{artifact_dir}:/artifacts",
        f"gcr.io/oss-fuzz/{project}",
        f"/out/{binary_name}",
        "/corpus",
        f"-max_total_time={duration}",
        f"-max_len={max(1, max_len)}",
        "-rss_limit_mb=0",
        "-print_final_stats=1",
        "-artifact_prefix=/artifacts/",
    ]
    started = time.monotonic()
    error: str | None = None
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=duration + 120,
            errors="replace",
            check=False,
        )
        output = (process.stdout or "") + (process.stderr or "")
        if process.returncode != 0:
            error = f"Fuzzer exited with code {process.returncode}"
    except subprocess.TimeoutExpired as exc:
        output = _subprocess_text(exc.stdout) + _subprocess_text(exc.stderr)
        error = f"Fuzzer timed out after {duration + 120}s"
    except OSError as exc:
        output = ""
        error = f"Fuzzer infrastructure error: {exc}"
    stats = _libfuzzer_stats(output)
    artifacts = tuple(
        sorted(
            (path for path in artifact_dir.iterdir() if path.is_file()),
            key=lambda path: path.stat().st_mtime_ns,
        )
    )
    return _CampaignResult(
        corpus_dir=str(corpus),
        corpus_size=sum(1 for path in corpus.iterdir() if path.is_file()),
        edges_covered=stats.get("cov", 0),
        features=stats.get("ft", 0),
        total_executions=stats.get("execs", 0),
        exec_per_second=stats.get("exec_s", 0),
        peak_rss_mb=stats.get("rss", 0),
        elapsed_seconds=time.monotonic() - started,
        error=error,
        output=output[-20_000:],
        artifacts=artifacts,
    )


def _subprocess_text(value: str | bytes | None) -> str:
    """Normalize TimeoutExpired output before concatenating stdout/stderr.

    Python may expose either stream as bytes even when ``text=True`` was used.
    Decode each stream independently so a bytes/str combination cannot crash
    the verifier's timeout-reporting path after a long build or fuzz run.
    """

    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _has_real_quartet_binary(runner: Any, binary_name: str) -> bool:
    workspace = getattr(runner, "_workspace_dir", None)
    worker_workspace = getattr(runner, "worker_workspace", None)
    return bool(
        workspace is not None
        and worker_workspace is not None
        and (_address_binary_dir(runner, getattr(runner, "project", "")) / binary_name).is_file()
    )


def _address_binary_dir(runner: Any, project: str) -> Path:
    snapshot = getattr(runner, "_address_binary_snapshot", None)
    if snapshot is not None and Path(snapshot).is_file():
        return Path(snapshot).parent
    return Path(runner._workspace_dir) / "build" / "out" / project


def _sanitizer_name(output: str) -> str | None:
    for marker, name in (
        ("LeakSanitizer:", "LeakSanitizer"),
        ("UndefinedBehaviorSanitizer:", "UndefinedBehaviorSanitizer"),
        ("MemorySanitizer:", "MemorySanitizer"),
        ("ThreadSanitizer:", "ThreadSanitizer"),
        ("AddressSanitizer:", "AddressSanitizer"),
    ):
        if marker in output:
            return name
    return None


def _debugger_infrastructure_error(result: dict[str, Any]) -> str | None:
    error = str(result.get("error") or "").strip()
    output = str(result.get("gdb_output") or "")
    combined = (error + "\n" + output).casefold()
    markers = (
        "gdb: command not found",
        "error: docker gdb",
        "docker: permission denied",
        "cannot connect to the docker daemon",
        "not in executable format",
    )
    if error:
        return f"verification infrastructure failed during GDB reachability: {error}"
    if any(marker in combined for marker in markers):
        detail = output.strip()[-2000:]
        return f"verification infrastructure failed during GDB reachability: {detail}"
    return None


def _libfuzzer_stats(output: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in reversed(output.splitlines()):
        match = re.search(
            r"\bcov:\s*(\d+)\s+ft:\s*(\d+).*?exec/s:\s*(\d+).*?rss:\s*(\d+)",
            line,
        )
        if not match:
            continue
        executions = re.search(r"#(\d+)", line)
        result = {
            "cov": int(match.group(1)),
            "ft": int(match.group(2)),
            "exec_s": int(match.group(3)),
            "rss": int(match.group(4)),
            "execs": int(executions.group(1)) if executions else 0,
        }
        break
    return result


def _report(
    argv: list[str],
    returncode: int,
    *,
    stdout: str = "",
    stderr: str = "",
    duration: float = 0.0,
) -> CommandReport:
    return CommandReport(
        argv=argv,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
        timed_out=False,
    )


def _crash_attribution(
    stack: str,
    source_filename: str,
    *,
    target_source_path: str | None = None,
    target_source_basenames: set[str] | None = None,
) -> str:
    """Classify the first application-or-harness source-bearing GDB frame.

    A stack that cannot prove a target frame remains a harness failure.  This
    conservative rule prevents infrastructure/signal failures from being
    reported as discovered application bugs. Compiler runtime, sanitizer, and
    third-party dependency frames are skipped rather than labelled target.
    """

    source_basename = Path(source_filename).name
    target_prefix = (target_source_path or "").rstrip("/") + "/"
    allowed_basenames = target_source_basenames or set()
    for line in stack.splitlines():
        if not re.match(r"\s*#\d+\b", line):
            continue
        path_match = re.search(
            r"(?:\bat\s+|\bfrom\s+)([^\s:]+\.(?:c|cc|cpp|cxx|h|hpp))(?::\d+)?",
            line,
            re.IGNORECASE,
        )
        if not path_match:
            continue
        path = path_match.group(1)
        basename = Path(path).name
        if basename == source_basename:
            return "harness"
        if target_prefix and path.startswith(target_prefix):
            return "target"
        if allowed_basenames and basename in allowed_basenames:
            return "target"
    return "unknown"


def _coverage_dict(coverage: Any) -> dict[str, Any]:
    # ``is_dataclass`` is also true for a dataclass *type*, while ``asdict``
    # accepts only an instance. Treat a mistakenly returned class as generic
    # metadata instead of crashing the final coverage-report path.
    if dataclasses.is_dataclass(coverage) and not isinstance(coverage, type):
        return dataclasses.asdict(coverage)
    names: Iterable[str] = (
        "lines_covered", "lines_total", "lines_pct",
        "branches_covered", "branches_total", "branches_pct",
        "functions_covered", "functions_total", "functions_pct",
        "regions_covered", "regions_total", "regions_pct", "error",
    )
    return {name: getattr(coverage, name) for name in names if hasattr(coverage, name)}


def _scoped_target_coverage(
    runner: Any,
    project: str,
    binary_name: str,
    container_source_path: str,
    harness_source_filename: str,
) -> dict[str, Any]:
    """Aggregate llvm-cov only for files in the overlaid application tree.

    Quartet's top-level totals can include generated harness lines and runtime
    support.  Qualification therefore requires a parseable per-file summary
    and non-zero coverage below the exact application checkout path, excluding
    the generated harness itself.
    """

    workspace = getattr(runner, "_workspace_dir", None)
    if workspace is None:
        return {
            "target_coverage_scope_verified": False,
            "target_coverage_error": "Quartet runner did not expose its OSS-Fuzz workspace",
        }
    out = Path(workspace) / "build" / "out" / project
    candidates = (
        out / "report_target" / binary_name / "linux" / "summary.json",
        out / "report" / "linux" / "summary.json",
    )
    summary_path = next((path for path in candidates if path.is_file()), None)
    if summary_path is None:
        return {
            "target_coverage_scope_verified": False,
            "target_coverage_error": "per-file llvm-cov summary.json is missing",
        }
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
        files = payload["data"][0]["files"]
    except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        return {
            "target_coverage_scope_verified": False,
            "target_coverage_error": f"invalid per-file llvm-cov summary: {exc}",
        }

    prefix = container_source_path.rstrip("/") + "/"
    target_files = 0
    target_lines_covered = 0
    target_lines_total = 0
    target_functions_covered = 0
    target_functions_total = 0
    covered_files: list[str] = []
    for item in files:
        filename = str(item.get("filename", ""))
        if not filename.startswith(prefix):
            continue
        if Path(filename).name == Path(harness_source_filename).name:
            continue
        summary = item.get("summary", {})
        lines = summary.get("lines", {})
        functions = summary.get("functions", {})
        target_files += 1
        target_lines_covered += int(lines.get("covered", 0) or 0)
        target_lines_total += int(lines.get("count", 0) or 0)
        target_functions_covered += int(functions.get("covered", 0) or 0)
        target_functions_total += int(functions.get("count", 0) or 0)
        if int(lines.get("covered", 0) or 0) > 0:
            covered_files.append(filename)

    return {
        "target_coverage_scope_verified": target_files > 0,
        "target_coverage_summary": str(summary_path),
        "target_files_measured": target_files,
        "target_lines_covered": target_lines_covered,
        "target_lines_total": target_lines_total,
        "target_functions_covered": target_functions_covered,
        "target_functions_total": target_functions_total,
        "target_covered_files": covered_files[:200],
        "target_coverage_error": (
            "" if target_files > 0
            else f"llvm-cov contains no files under {container_source_path}"
        ),
    }


def _source_provenance(source_root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"local_source_root": str(source_root.resolve())}
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if head.returncode == 0:
            result["git_commit"] = head.stdout.strip()
        result["tracked_changes_present"] = bool(status.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        result["git_commit"] = None
        result["tracked_changes_present"] = None
    result["overlay_applied_to"] = "oss-fuzz-builder-image"
    return result


def _last_libfuzzer_coverage(output: str) -> int | None:
    values = _libfuzzer_coverage_values(output)
    return values[-1] if values else None


def _libfuzzer_coverage_values(output: str) -> list[int]:
    return [
        int(match.group(1))
        for match in re.finditer(r"\bcov:\s*(\d+)", output)
    ]
