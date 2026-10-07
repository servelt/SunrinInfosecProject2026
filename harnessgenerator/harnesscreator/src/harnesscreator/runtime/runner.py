from __future__ import annotations

import asyncio
import os
import re
import resource
import shutil
import time
from pathlib import Path
from typing import Callable, Iterable

from ..analysis.graph import GraphStore
from ..models import CommandReport, HarnessDraft, ProjectSpec, SeedSpec, VerificationResult


SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    "runtime error:",
    "ERROR: libFuzzer",
)


class CommandRunner:
    """No-shell subprocess runner with time, output, and address-space limits."""

    def __init__(self, *, max_output_bytes: int = 2_000_000, memory_mb: int = 0):
        self.max_output_bytes = max_output_bytes
        self.memory_mb = memory_mb

    async def run(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        env: dict[str, str] | None = None,
    ) -> CommandReport:
        if not argv or not argv[0]:
            raise ValueError("empty command")
        executable = argv[0]
        if "/" not in executable and not shutil.which(executable):
            raise FileNotFoundError(f"executable not found: {executable}")
        started = time.monotonic()
        process_env = os.environ.copy()
        process_env.update(env or {})
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            env=process_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            preexec_fn=self._limits,
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            timed_out = True
            try:
                os.killpg(process.pid, 15)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3)
            except asyncio.TimeoutError:
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
                stdout, stderr = await process.communicate()
        return CommandReport(
            argv=argv,
            returncode=process.returncode,
            stdout=_bounded_decode(stdout, self.max_output_bytes),
            stderr=_bounded_decode(stderr, self.max_output_bytes),
            duration_seconds=time.monotonic() - started,
            timed_out=timed_out,
        )

    def _limits(self) -> None:
        # ASan reserves a very large virtual shadow mapping; RLIMIT_AS breaks it.
        # A non-zero limit is therefore opt-in for non-sanitized custom runners.
        if self.memory_mb:
            memory = self.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class HarnessVerifierAgent:
    def __init__(
        self,
        runner: CommandRunner,
        project: ProjectSpec,
        graph: GraphStore | None = None,
        progress: Callable[[str], None] | None = None,
    ):
        self.runner = runner
        self.project = project
        self.graph = graph
        self.progress = progress

    def _emit(self, message: str) -> None:
        if self.progress:
            self.progress(message)

    async def verify(
        self,
        draft: HarnessDraft,
        artifact_dir: Path,
        llm_seeds: list[SeedSpec] | None = None,
        *,
        runtime_checks: bool = True,
    ) -> VerificationResult:
        manifest = draft.manifest
        if not manifest.build_command:
            return VerificationResult(
                qualified=False, build=None, replays=[], fuzz=None, harness_faults=[], target_findings=[],
                coverage_grew=None,
                reason="no trusted build command configured; generation completed but dynamic verification was not run",
            )

        source_path = artifact_dir / Path(manifest.source_file).name
        substitutions = {
            "{harness}": str(source_path),
            "{source_root}": str(self.project.source_root),
            "{output}": str(artifact_dir),
        }
        build_argv = [_substitute(value, substitutions) for value in manifest.build_command]
        self._emit(f"dynamic build started: {manifest.harness_id}")
        try:
            build = await self.runner.run(
                build_argv,
                cwd=self.project.source_root,
                timeout_seconds=900,
            )
        except Exception as exc:
            detail = f"command build runner raised {type(exc).__name__}: {exc}"
            return VerificationResult(
                qualified=False,
                build=None,
                replays=[],
                fuzz=None,
                harness_faults=[],
                target_findings=[],
                coverage_grew=None,
                reason="command verification infrastructure failed",
                backend="command",
                infrastructure_error=detail,
            )
        self._emit(
            f"dynamic build completed: returncode={build.returncode}, timed_out={build.timed_out}"
        )
        if build.returncode != 0 or build.timed_out:
            return VerificationResult(
                qualified=False, build=build, replays=[], fuzz=None, harness_faults=[], target_findings=[],
                coverage_grew=None, reason="harness build failed or timed out",
            )
        if not manifest.binary:
            return VerificationResult(
                qualified=False, build=build, replays=[], fuzz=None, harness_faults=[], target_findings=[],
                coverage_grew=None, reason="build succeeded but no trusted harness binary path is configured",
            )
        binary = Path(_substitute(manifest.binary, substitutions))
        if not binary.is_file():
            return VerificationResult(
                qualified=False, build=build, replays=[], fuzz=None, harness_faults=[], target_findings=[],
                coverage_grew=None, reason=f"configured harness binary does not exist: {binary}",
            )
        missing_instrumentation = _missing_sanitizer_instrumentation(
            binary, manifest.sanitizers
        )
        if missing_instrumentation:
            detail = (
                "built binary lacks required sanitizer instrumentation: "
                + ", ".join(missing_instrumentation)
            )
            return VerificationResult(
                qualified=False,
                build=build,
                replays=[],
                fuzz=None,
                harness_faults=[detail],
                target_findings=[],
                coverage_grew=None,
                reason=detail,
            )

        # Build validation is never optional.  ``--no-dynamic-verification``
        # disables seed replay/GDB/fuzzing only; it must not turn an
        # uncompilable source draft into a successful harness.  This mirrors
        # QuartetFuzz's build-before-submit invariant while still allowing a
        # caller to stop before runtime probes.
        if not runtime_checks:
            return VerificationResult(
                qualified=False,
                build=build,
                replays=[],
                fuzz=None,
                harness_faults=[],
                target_findings=[],
                coverage_grew=None,
                reason="build-only validation passed; runtime qualification was disabled",
                build_ok=True,
                backend="command",
            )

        seed_dir = artifact_dir / "seeds"
        seed_dir.mkdir(parents=True, exist_ok=True)
        seeds = write_seed_suite(
            seed_dir,
            manifest.min_size,
            manifest.variant_count,
            llm_seeds or [],
            max_size=manifest.max_size,
        )
        replays: list[CommandReport] = []
        harness_faults: list[str] = []
        harness_fault_seeds: list[SeedSpec] = []
        target_findings: list[str] = []
        target_finding_seeds: set[Path] = set()
        target_finding_specs: list[SeedSpec] = []
        self._emit(f"deterministic replay started: {len(seeds)} seeds, three runs per process")
        for seed_index, seed in enumerate(seeds, start=1):
            try:
                report = await self.runner.run(
                    # File arguments are replayed without fuzzing. Repeating the
                    # same file in one process exercises per-iteration reset and
                    # catches stale globals that one-process-per-seed replay misses.
                    [
                        str(binary), str(seed), str(seed), str(seed),
                        "-runs=3", "-timeout=10",
                    ],
                    cwd=artifact_dir,
                    timeout_seconds=20,
                    env=_sanitizer_env(),
                )
            except Exception as exc:
                detail = (
                    f"{seed.name}: command replay raised {type(exc).__name__}: {exc}"
                )
                return VerificationResult(
                    qualified=False,
                    build=build,
                    replays=replays,
                    fuzz=None,
                    harness_faults=[],
                    target_findings=target_findings,
                    target_finding_seeds=target_finding_specs,
                    coverage_grew=None,
                    reason="command verification infrastructure failed",
                    build_ok=True,
                    backend="command",
                    infrastructure_error=detail,
                )
            replays.append(report)
            if _crashed(report):
                try:
                    attribution, detail = await self._attribute(
                        binary, seed, report, source_path
                    )
                except Exception as exc:
                    infrastructure = (
                        f"{seed.name}: command GDB attribution raised "
                        f"{type(exc).__name__}: {exc}"
                    )
                    return VerificationResult(
                        qualified=False,
                        build=build,
                        replays=replays,
                        fuzz=None,
                        harness_faults=[],
                        target_findings=target_findings,
                        target_finding_seeds=target_finding_specs,
                        coverage_grew=None,
                        reason="command verification infrastructure failed",
                        build_ok=True,
                        backend="command",
                        infrastructure_error=infrastructure,
                    )
                if attribution == "harness":
                    harness_faults.append(f"{seed.name}: {detail}")
                    harness_fault_seeds.append(_regression_seed(seed, detail))
                elif attribution == "target":
                    finding = f"{seed.name}: {detail}"
                    target_findings.append(finding)
                    target_finding_seeds.add(seed)
                    target_finding_specs.append(_finding_seed(seed, finding))
                else:
                    harness_faults.append(f"{seed.name}: unattributed crash; {detail}")
                    harness_fault_seeds.append(
                        _regression_seed(seed, f"unattributed crash; {detail}")
                    )
            if seed_index == len(seeds) or seed_index % 5 == 0:
                self._emit(f"deterministic replay {seed_index}/{len(seeds)}")
        if harness_faults:
            return VerificationResult(
                qualified=False, build=build, replays=replays, fuzz=None,
                harness_faults=harness_faults, target_findings=target_findings,
                target_finding_seeds=target_finding_specs,
                coverage_grew=None, reason="one or more deterministic seeds exposed a harness or unattributed fault",
                harness_fault_seeds=harness_fault_seeds,
                build_ok=True,
                backend="command",
            )
        try:
            reachability, reachable_seed_count, reachability_error = await self._verify_reachability(
                binary,
                seeds,
                manifest.expected_anchors,
                manifest.variant_targets,
                harness_source=source_path,
            )
        except Exception as exc:
            detail = f"command GDB reachability raised {type(exc).__name__}: {exc}"
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=None,
                harness_faults=[],
                target_findings=target_findings,
                target_finding_seeds=target_finding_specs,
                coverage_grew=None,
                reason="command verification infrastructure failed",
                build_ok=True,
                backend="command",
                infrastructure_error=detail,
            )
        if reachability_error:
            return VerificationResult(
                qualified=False, build=build, replays=replays, fuzz=None,
                harness_faults=[reachability_error], target_findings=target_findings,
                target_finding_seeds=target_finding_specs,
                coverage_grew=None, reason="expected application anchor reachability was not established",
                reachability=reachability,
                reachable_seed_count=reachable_seed_count,
                build_ok=True,
                backend="command",
            )
        corpus = artifact_dir / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)
        for seed in seeds:
            # Preserve deterministic target findings separately. Seeding the
            # qualification corpus with a known crashing input would terminate
            # libFuzzer immediately and falsely replace the required coverage run.
            if seed in target_finding_seeds:
                continue
            destination = corpus / seed.name
            if not destination.exists():
                destination.write_bytes(seed.read_bytes())
        crash_dir = artifact_dir / "crashes"
        crash_dir.mkdir(parents=True, exist_ok=True)
        self._emit(
            f"qualification fuzzing started: {self.project.fuzz_seconds}s, corpus={len(seeds)}"
        )
        try:
            fuzz = await self.runner.run(
                [
                    str(binary), str(corpus), f"-max_total_time={self.project.fuzz_seconds}",
                    f"-max_len={manifest.max_size}", "-print_final_stats=1", "-timeout=10",
                    f"-artifact_prefix={crash_dir}/",
                ],
                cwd=artifact_dir,
                timeout_seconds=self.project.fuzz_seconds + 30,
                env=_sanitizer_env(),
            )
        except Exception as exc:
            detail = f"command fuzz runner raised {type(exc).__name__}: {exc}"
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=None,
                harness_faults=[],
                target_findings=target_findings,
                target_finding_seeds=target_finding_specs,
                coverage_grew=None,
                reason="command verification infrastructure failed",
                reachability=reachability,
                reachable_seed_count=reachable_seed_count,
                build_ok=True,
                backend="command",
                infrastructure_error=detail,
            )
        self._emit(
            f"qualification fuzzing completed: returncode={fuzz.returncode}, timed_out={fuzz.timed_out}"
        )
        coverage = _coverage_values(fuzz.stdout + "\n" + fuzz.stderr)
        coverage_grew = len(coverage) >= 2 and max(coverage) > coverage[0]
        if _crashed(fuzz):
            crash_artifacts = sorted(
                (path for path in crash_dir.iterdir() if path.is_file()),
                key=lambda path: path.stat().st_mtime_ns,
                reverse=True,
            )
            if crash_artifacts:
                try:
                    attribution, detail = await self._attribute(
                        binary, crash_artifacts[0], fuzz, source_path
                    )
                except Exception as exc:
                    infrastructure = (
                        f"{crash_artifacts[0].name}: command GDB attribution raised "
                        f"{type(exc).__name__}: {exc}"
                    )
                    return VerificationResult(
                        qualified=False,
                        build=build,
                        replays=replays,
                        fuzz=fuzz,
                        harness_faults=[],
                        target_findings=target_findings,
                        target_finding_seeds=target_finding_specs,
                        coverage_grew=None,
                        reason="command verification infrastructure failed",
                        reachability=reachability,
                        reachable_seed_count=reachable_seed_count,
                        build_ok=True,
                        backend="command",
                        infrastructure_error=infrastructure,
                    )
                if attribution == "target":
                    target_findings.append(
                        f"{crash_artifacts[0].name}: qualification fuzzing found a target fault; {detail}"
                    )
                    target_finding_specs.append(
                        _finding_seed(crash_artifacts[0], detail)
                    )
                    return VerificationResult(
                        qualified=True,
                        build=build,
                        replays=replays,
                        fuzz=fuzz,
                        harness_faults=[],
                        target_findings=target_findings,
                        target_finding_seeds=target_finding_specs,
                        coverage_grew=coverage_grew,
                        reason="qualification fuzzing exposed an attributed target finding",
                        reachability=reachability,
                        reachable_seed_count=reachable_seed_count,
                        build_ok=True,
                        backend="command",
                    )
                fault = (
                    f"{crash_artifacts[0].name}: {detail}"
                    if attribution == "harness"
                    else f"{crash_artifacts[0].name}: unattributed crash; {detail}"
                )
            else:
                fault = "qualification fuzzing failed without a saved crash artifact"
            return VerificationResult(
                qualified=False,
                build=build,
                replays=replays,
                fuzz=fuzz,
                harness_faults=[fault],
                target_findings=target_findings,
                target_finding_seeds=target_finding_specs,
                coverage_grew=coverage_grew,
                reason="qualification fuzzing exposed a harness or unattributed fault",
                reachability=reachability,
                reachable_seed_count=reachable_seed_count,
                harness_fault_seeds=(
                    [_regression_seed(crash_artifacts[0], fault)]
                    if crash_artifacts else []
                ),
                build_ok=True,
                backend="command",
            )
        qualified = not fuzz.timed_out and fuzz.returncode == 0 and coverage_grew
        return VerificationResult(
            qualified=qualified,
            build=build,
            replays=replays,
            fuzz=fuzz,
            harness_faults=harness_faults,
            target_findings=target_findings,
            target_finding_seeds=target_finding_specs,
            coverage_grew=coverage_grew,
            reason=(
                "qualification completed; deterministic target findings were preserved"
                if qualified and target_findings
                else "qualification completed"
                if qualified
                else "coverage did not demonstrably grow or fuzzing failed"
            ),
            reachability=reachability,
            reachable_seed_count=reachable_seed_count,
            build_ok=True,
            backend="command",
        )

    async def _verify_reachability(
        self,
        binary: Path,
        seeds: list[Path],
        expected_anchor_ids: list[str],
        variant_targets: list[dict[str, str]] | None = None,
        *,
        harness_source: Path | None = None,
    ) -> tuple[list[CommandReport], int, str | None]:
        # Unit/custom users may construct the verifier without an analysis
        # graph. The production orchestrator always supplies it.
        if self.graph is None:
            return [], 0, None
        anchors = [
            self.graph.bundle.functions[identifier]
            for identifier in expected_anchor_ids
            if identifier in self.graph.bundle.functions
        ]
        if not anchors:
            return [], 0, "manifest has no graph-resolved application anchor"
        gdb = shutil.which("gdb")
        if not gdb:
            return [], 0, "GDB is unavailable; five-seed anchor reachability cannot be verified"
        reports: list[CommandReport] = []
        if harness_source is not None:
            try:
                harness_lines = harness_source.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError as exc:
                return [], 0, f"generated harness source cannot be read: {exc}"
            entry_line = next(
                (
                    index
                    for index, line in enumerate(harness_lines, start=1)
                    if "LLVMFuzzerTestOneInput" in line
                ),
                None,
            )
            if entry_line is None:
                return [], 0, "generated harness source has no LLVMFuzzerTestOneInput definition"
            harness_breakpoint = f"{harness_source}:{entry_line}"
            self._emit("GDB generated-harness identity check started")
            harness_reached = False
            for seed in seeds:
                report = await self.runner.run(
                    [
                        gdb,
                        "--batch",
                        "-ex", "set breakpoint pending on",
                        "-ex", f"break {harness_breakpoint}",
                        "-ex", "run",
                        "-ex", "bt 1",
                        "--args", str(binary), str(seed), "-runs=1", "-timeout=10",
                    ],
                    cwd=self.project.source_root,
                    timeout_seconds=30,
                    env=_sanitizer_env(),
                )
                reports.append(report)
                output = report.stdout + "\n" + report.stderr
                if re.search(r"\bBreakpoint\s+\d+(?:\.\d+)?,\s", output):
                    harness_reached = True
                    break
            if not harness_reached:
                self._emit("GDB generated-harness identity check failed")
                return (
                    reports,
                    0,
                    "configured binary did not execute the generated LLVMFuzzerTestOneInput source",
                )
            self._emit("GDB generated-harness identity check completed")
        anchor = anchors[0]
        symbol = anchor.qualified_name or anchor.name
        if not re.fullmatch(r"[A-Za-z_~][A-Za-z0-9_:~]*", symbol):
            symbol = anchor.name
        anchor_breakpoint = f"{anchor.file}:{anchor.start_line}"
        required = min(5, len(seeds))
        self._emit(
            f"GDB anchor reachability started: require {required} seeds at {symbol}"
        )
        reached = 0
        for seed in seeds:
            report = await self.runner.run(
                [
                    gdb,
                    "--batch",
                    "-ex", "set breakpoint pending on",
                    "-ex", "set follow-fork-mode child",
                    "-ex", f"break {anchor_breakpoint}",
                    "-ex", "run",
                    "-ex", "bt 1",
                    "--args", str(binary), str(seed), "-runs=1", "-timeout=10",
                ],
                cwd=self.project.source_root,
                timeout_seconds=30,
                env=_sanitizer_env(),
            )
            reports.append(report)
            output = report.stdout + "\n" + report.stderr
            if re.search(r"\bBreakpoint\s+\d+(?:\.\d+)?,\s", output):
                reached += 1
                self._emit(f"GDB anchor reachability {reached}/{required}")
                if reached >= required:
                    break
        if reached < required:
            self._emit(
                f"GDB anchor reachability failed: {reached}/{required} seeds reached {symbol}"
            )
            return (
                reports,
                reached,
                f"only {reached}/{required} deterministic seeds reached expected anchor {symbol}",
            )
        self._emit(f"GDB anchor reachability completed: {reached}/{required}")
        for variant in variant_targets or []:
            selector = str(variant.get("selector", ""))
            function_id = str(variant.get("function_id", ""))
            function = self.graph.bundle.functions.get(function_id)
            seed_pattern = re.compile(
                rf"^(?:llm-)?variant-{re.escape(selector)}(?:$|[-_.])"
            )
            variant_seeds = [item for item in seeds if seed_pattern.search(item.name)]
            if function is None or not variant_seeds:
                return (
                    reports,
                    reached,
                    f"variant {selector} has no graph-resolved target or deterministic selector seed",
                )
            variant_symbol = function.qualified_name or function.name
            if not re.fullmatch(r"[A-Za-z_~][A-Za-z0-9_:~]*", variant_symbol):
                variant_symbol = function.name
            variant_breakpoint = f"{function.file}:{function.start_line}"
            self._emit(
                f"GDB variant reachability started: selector={selector}, target={variant_symbol}"
            )
            variant_reached = False
            for seed in variant_seeds:
                report = await self.runner.run(
                    [
                        gdb,
                        "--batch",
                        "-ex", "set breakpoint pending on",
                        "-ex", "set follow-fork-mode child",
                        "-ex", f"break {variant_breakpoint}",
                        "-ex", "run",
                        "-ex", "bt 1",
                        "--args", str(binary), str(seed), "-runs=1", "-timeout=10",
                    ],
                    cwd=self.project.source_root,
                    timeout_seconds=30,
                    env=_sanitizer_env(),
                )
                reports.append(report)
                output = report.stdout + "\n" + report.stderr
                if re.search(r"\bBreakpoint\s+\d+(?:\.\d+)?,\s", output):
                    variant_reached = True
                    break
            if not variant_reached:
                self._emit(
                    f"GDB variant reachability failed: selector={selector}, target={variant_symbol}"
                )
                return (
                    reports,
                    reached,
                    f"selector {selector} did not reach Small Feature target {variant_symbol}",
                )
            self._emit(
                f"GDB variant reachability completed: selector={selector}, target={variant_symbol}"
            )
        return reports, reached, None

    async def _attribute(
        self, binary: Path, seed: Path, report: CommandReport, source_path: Path
    ) -> tuple[str, str]:
        output = report.stdout + "\n" + report.stderr
        top_frames = "\n".join(line for line in output.splitlines() if re.search(r"#\d+", line))[:8000]
        sanitizer_attribution = _first_relevant_stack_frame(
            top_frames,
            source_path,
            self.project.source_root,
        )
        gdb = shutil.which("gdb")
        gdb_attribution: str | None = None
        stack = ""
        if gdb:
            debug = await self.runner.run(
                [
                    gdb,
                    "--batch",
                    "-ex", "set breakpoint pending on",
                    "-ex", "set follow-fork-mode child",
                    "-ex", "run",
                    "-ex", "bt",
                    "--args", str(binary), str(seed), str(seed), str(seed),
                    "-runs=3", "-timeout=10",
                ],
                cwd=self.project.source_root,
                timeout_seconds=30,
                env=_sanitizer_env(),
            )
            stack = debug.stdout + "\n" + debug.stderr
            gdb_attribution = _first_relevant_stack_frame(
                stack,
                source_path,
                self.project.source_root,
            )
        attributions = {
            item for item in (sanitizer_attribution, gdb_attribution)
            if item in {"harness", "target"}
        }
        detail = (
            f"sanitizer={sanitizer_attribution or 'unresolved'}; "
            f"gdb={gdb_attribution or ('unavailable' if not gdb else 'unresolved')}; "
            f"sanitizer frames:\n{_stack_excerpt(top_frames)}"
        )
        if gdb:
            detail += f"\nGDB frames:\n{_stack_excerpt(stack)}"
        if len(attributions) == 1:
            return next(iter(attributions)), detail
        if len(attributions) > 1:
            return "unknown", "sanitizer and GDB attribution disagree; " + detail
        return "unknown", detail + "\nraw output:\n" + output[-1200:]


def write_seed_suite(
    directory: Path,
    min_size: int,
    variants: int,
    llm_seeds: Iterable[SeedSpec] = (),
    *,
    max_size: int = 1_048_576,
) -> list[Path]:
    maximum = max(1, max_size)
    payloads = [
        b"",
        b"\x00",
        b"\xff",
        b"\x7f",
        b"\x00" * min(max(1, min_size), maximum),
        b"A" * min(max(2, min(min_size + 1, 4096)), maximum),
        bytes(range(256))[:maximum],
        b"\x00\xff\x7f\x80\n\r\x00A"[:maximum],
    ]
    named_payloads = [
        (f"variant-{selector}", (bytes([selector & 0xFF]) + b"seed")[:maximum])
        for selector in range(max(variants, 1))
    ]
    named_payloads.extend(
        (f"seed-{index:03d}", payload) for index, payload in enumerate(payloads)
    )
    named_payloads.extend(
        (f"llm-{seed.name}", data)
        for seed in llm_seeds
        for data in [bytes.fromhex(seed.data_hex)]
        if len(data) <= maximum
    )
    result: list[Path] = []
    seen: set[bytes] = set()
    used_names: set[str] = set()
    for name, payload in named_payloads:
        if payload in seen:
            continue
        seen.add(payload)
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip(".-")[:100] or "seed"
        unique_name = safe_name
        suffix = 1
        while unique_name in used_names:
            suffix += 1
            unique_name = f"{safe_name[:90]}-{suffix}"
        used_names.add(unique_name)
        path = directory / unique_name
        path.write_bytes(payload)
        result.append(path)
    return result


def _bounded_decode(value: bytes, limit: int) -> str:
    if len(value) > limit:
        value = value[-limit:]
        prefix = "[output truncated to final bytes]\n"
    else:
        prefix = ""
    return prefix + value.decode(errors="replace")


def _regression_seed(path: Path, rationale: str) -> SeedSpec:
    return SeedSpec(
        name=f"regression-{path.name}"[:80],
        data_hex=path.read_bytes().hex(),
        rationale=rationale[:4000],
    )


def _finding_seed(path: Path, rationale: str) -> SeedSpec:
    return SeedSpec(
        name=f"finding-{path.name}"[:80],
        data_hex=path.read_bytes().hex(),
        rationale=rationale[:4000],
    )


def _substitute(value: str, substitutions: dict[str, str]) -> str:
    for key, replacement in substitutions.items():
        value = value.replace(key, replacement)
    return value


def _sanitizer_env() -> dict[str, str]:
    return {
        "LC_ALL": "C",
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=1:symbolize=1",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        "LSAN_OPTIONS": "exitcode=23",
    }


def _missing_sanitizer_instrumentation(
    binary: Path, required: Iterable[str]
) -> list[str]:
    """Conservatively verify that the trusted build really enabled sanitizers."""

    marker_sets = {
        "address": (b"__asan_init", b"__asan_report_", b"AddressSanitizer"),
        "undefined": (b"__ubsan_handle_", b"UndefinedBehaviorSanitizer"),
    }
    required_names = {
        str(item).casefold().replace("-", "") for item in required
    }
    selected = {
        name: markers
        for name, markers in marker_sets.items()
        if name in required_names
    }
    if not selected:
        return []
    found = {name: False for name in selected}
    longest = max(len(marker) for markers in selected.values() for marker in markers)
    overlap = b""
    try:
        with binary.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                window = overlap + chunk
                for name, markers in selected.items():
                    if not found[name] and any(marker in window for marker in markers):
                        found[name] = True
                if all(found.values()):
                    break
                overlap = window[-longest:]
    except OSError:
        return sorted(selected)
    return sorted(name for name, present in found.items() if not present)


def _crashed(report: CommandReport) -> bool:
    output = report.stdout + "\n" + report.stderr
    return report.timed_out or (report.returncode not in {0, None}) or any(marker in output for marker in SANITIZER_MARKERS)


def _coverage_values(output: str) -> list[int]:
    return [int(value) for value in re.findall(r"\bcov:\s*(\d+)", output)]


def _stack_excerpt(stack: str, limit: int = 2000) -> str:
    frames = [line for line in stack.splitlines() if re.search(r"^\s*#\d+\b", line)]
    text = "\n".join(frames) if frames else stack
    return text[-limit:] or "(no stack frames)"


def _first_relevant_stack_frame(
    stack: str,
    harness_source: Path,
    source_root: Path,
) -> str | None:
    """Classify by the first project-owned frame, not any frame in the stack.

    A genuine target crash normally has the generated adapter farther down the
    stack. Looking for the harness filename anywhere therefore reverses target
    findings into harness defects. Runtime/libc frames are skipped until the
    first generated-harness or target-source frame is found.
    """
    harness_name = harness_source.name
    harness_path = str(harness_source.resolve())
    root = str(source_root.resolve()).rstrip("/") + "/"
    frame_lines = [line for line in stack.splitlines() if re.search(r"^\s*#\d+\b", line)]
    for line in frame_lines:
        if harness_path in line or harness_name in line:
            return "harness"
        normalized = line.replace("\\", "/")
        if root.replace("\\", "/") in normalized:
            return "target"
        # Clang/GDB often preserve a path relative to the build cwd rather than
        # an absolute source-root prefix. Resolve only source-like path tokens
        # that actually exist under the trusted project root.
        for relative in re.findall(
            r"(?:^|[\s(])([^\s():]+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)):\d+",
            normalized,
            flags=re.IGNORECASE,
        ):
            candidate = Path(relative)
            if not candidate.is_absolute() and (source_root / candidate).is_file():
                return "target"
    return None


# Compatibility alias for callers written before the runtime component was
# given the same name as the sixth agent in the design document.
HarnessVerifier = HarnessVerifierAgent
