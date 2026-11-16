"""Native OSS-Fuzz build and smoke-test adapter for HarnessCreator.

This module invokes the **official OSS-Fuzz helper.py** CLI. It never imports
or runs QuartetFuzz. HarnessCreator's own generator and verifier own all
harness correctness decisions.

The helper's build/out tree is shared by project name. Build and replay for one
project are serialized with a cross-process lock, and generated harness sources
are written only into per-attempt copies of the OSS-Fuzz project recipe.

The native adapter conservatively reports BUILD_OK and observed runtime results.
It does not assert QUALIFIED without exact target reachability and root-cause
attribution, which the generic OSS-Fuzz helper CLI cannot establish alone.
"""
from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Callable

from ..analysis.graph import GraphStore
from ..models import CommandReport, HarnessDraft, ProjectSpec, SeedSpec, VerificationResult
from .runner import CommandRunner, write_seed_suite


class OssFuzzBackendError(RuntimeError):
    """Invalid OSS-Fuzz integration or unavailable runner."""



def _save_build_log(report: CommandReport, path: Path) -> Path | None:
    """Preserve both output streams from a failed OSS-Fuzz helper invocation.

    CommandRunner already keeps bounded tails of each stream.  Do not claim
    this is the complete Docker build log or silently discard stdout (where
    helper.py forwards the container's compiler errors).
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f'returncode={report.returncode} timed_out={report.timed_out} '
            f'duration_seconds={report.duration_seconds:.2f}\n'
            f'argv={report.argv!r}\n'
            f'\n--- stdout (captured tail) ---\n{report.stdout}'
            f'\n--- stderr (captured tail) ---\n{report.stderr}\n',
            encoding='utf-8',
        )
    except OSError:
        return None
    return path


def _build_failure_detail(report: CommandReport, log_path: Path | None) -> str:
    """Surface the compiler failure rather than only the helper's summary."""
    sections = [f'returncode={report.returncode}, timed_out={report.timed_out}']
    if log_path is not None:
        sections.append(f'captured output: {log_path}')
    if report.stdout.strip():
        sections.append('stdout tail:\n' + report.stdout[-10000:])
    if report.stderr.strip():
        sections.append('stderr tail:\n' + report.stderr[-4000:])
    return '\n'.join(sections)


def preflight_oss_fuzz_backend(
    project: ProjectSpec, *, check_docker: bool = True
) -> dict[str, str]:
    """Validate the project recipe without an external harness checker."""
    root = project.oss_fuzz_dir
    name = project.oss_fuzz_project
    target = project.oss_fuzz_fuzzer
    if root is None or not (root / 'infra' / 'helper.py').is_file():
        raise OssFuzzBackendError('provide an OSS-Fuzz checkout with infra/helper.py')
    if not name or not target:
        raise OssFuzzBackendError('OSS-Fuzz project and fuzzer identifiers are required')
    folder = root / 'projects' / name
    source = folder / project.harness_source_filename
    for path in (folder / 'Dockerfile', folder / 'build.sh', source):
        if not path.is_file():
            raise OssFuzzBackendError(f'OSS-Fuzz recipe is missing {path}')
    if not project.oss_fuzz_source_path:
        raise OssFuzzBackendError('explicit --oss-fuzz-source-path is required to mount the local checkout')
    version = 'not checked'
    if check_docker:
        docker = shutil.which('docker')
        if docker is None:
            raise OssFuzzBackendError('Docker CLI was not found')
        import subprocess
        try:
            result = subprocess.run(
                [docker, 'version', '--format', '{{.Server.Version}}'],
                text=True, capture_output=True, check=False, timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OssFuzzBackendError(f'Docker is unavailable: {exc}') from exc
        version = result.stdout.strip()
        if result.returncode or not version:
            raise OssFuzzBackendError(
                'Docker daemon is not accessible: ' + (result.stderr or result.stdout)[-800:]
            )
    return {
        'backend': 'harnesscreator-native-oss-fuzz',
        'oss_fuzz_project_dir': str(folder),
        'canonical_harness': str(source),
        'docker_server_version': version,
    }


_LOCK_REGISTRY_GUARD = threading.Lock()
_PROJECT_ASYNC_LOCKS: dict[tuple[str, str, int], asyncio.Lock] = {}


@asynccontextmanager
async def _project_lock(root: Path, name: str):
    """Serialize all builds for a shared OSS-Fuzz output directory.

    Never block the asyncio event loop while waiting for another build. A
    per-event-loop lock protects coroutines in the same process, and flock
    protects concurrent HarnessCreator processes.
    """
    import fcntl
    key = (str(root.resolve()), name, id(asyncio.get_running_loop()))
    with _LOCK_REGISTRY_GUARD:
        in_process_lock = _PROJECT_ASYNC_LOCKS.setdefault(key, asyncio.Lock())
    async with in_process_lock:
        lock_dir = root / '.harnesscreator-locks'
        lock_dir.mkdir(parents=True, exist_ok=True)
        with (lock_dir / f'{name}.lock').open('a+b') as lock:
            await asyncio.to_thread(fcntl.flock, lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _make_recipe_patch_idempotent(project_dir: Path) -> bool:
    """Preserve the original source-overlay behavior for OSS-Fuzz patches.

    The source snapshot may already include the patch expected by the pinned
    OSS-Fuzz recipe.  An applicable patch is applied exactly once, while an
    incompatible patch is still a hard error.  Only edit the ephemeral recipe,
    never the pinned OSS-Fuzz checkout or the user's source tree.

    Return True when a recognized build.sh `git apply .../patch.diff` command
    was wrapped.  For other build scripts, keep their original behavior.
    """
    build_sh = project_dir / 'build.sh'
    patch_file = project_dir / 'patch.diff'
    if not (build_sh.is_file() and patch_file.is_file()):
        return False
    contents = build_sh.read_text(encoding='utf-8', errors='replace')
    marker = '# HARNESSCREATOR_IDEMPOTENT_PATCH_BEGIN'
    if marker in contents:
        return True
    # Handle the canonical recipe's "$SRC/patch.diff" and its expanded
    # "/src/patch.diff" forms, preserving the exact original shell argument.
    patch_argument = r'(?:\$SRC|\$\{SRC\}|/src)/patch\.diff'
    pattern = re.compile(
        r'^(?P<indent>[ \t]*)git[ \t]+apply[ \t]+'
        r'(?P<argument>(?:"' + patch_argument + r'"|\x27' + patch_argument
        + r'\x27|' + patch_argument + r'))[ \t]*(?:#.*)?$',
        re.MULTILINE,
    )
    matches = list(pattern.finditer(contents))
    # Multiple patch commands can have different prerequisites.  Do not
    # silently rewrite a complex recipe in which the contract is ambiguous.
    if len(matches) != 1:
        return False
    match = matches[0]
    indent, arg = match.group('indent', 'argument')
    replacement = '\n'.join([
        indent + marker,
        indent + f'if git apply --check {arg}; then',
        indent + f'    git apply {arg}',
        indent + f'elif git apply --reverse --check {arg}; then',
        indent + '    echo "OSS-Fuzz patch already applied to local source"',
        indent + 'else',
        indent + '    echo "OSS-Fuzz patch is incompatible with local source" >&2',
        indent + '    exit 1',
        indent + 'fi',
        indent + '# HARNESSCREATOR_IDEMPOTENT_PATCH_END',
    ])
    build_sh.write_text(
        contents[:match.start()] + replacement + contents[match.end():],
        encoding='utf-8',
    )
    return True


class NativeOssFuzzVerifierAgent:
    """Own the OSS-Fuzz execution glue, not the semantic verification policy."""

    def __init__(
        self, project: ProjectSpec, graph: GraphStore | None,
        *, progress: Callable[[str], None] | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.project = project
        self.graph = graph
        self.progress = progress
        self.runner = runner or CommandRunner()

    def _emit(self, message: str) -> None:
        if self.progress:
            self.progress(message)

    async def _helper(
        self, arguments: list[str], *, timeout: float = 1200
    ) -> CommandReport:
        root = self.project.oss_fuzz_dir
        assert root is not None
        return await self.runner.run(
            [sys.executable, str(root / 'infra' / 'helper.py'), *arguments],
            cwd=root, timeout_seconds=timeout,
        )

    def _temporary_project(self, root: Path, source: str) -> Path:
        assert self.project.oss_fuzz_dir is not None
        assert self.project.oss_fuzz_project is not None
        recipe = self.project.oss_fuzz_dir / 'projects' / self.project.oss_fuzz_project
        # Preserve the project directory's basename: external OSS-Fuzz derives
        # the target identity from it. Never overwrite the user's recipe.
        destination = root / 'recipe' / self.project.oss_fuzz_project
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(recipe, destination, symlinks=True)
        # The original backend guarded against double application of the
        # pinned patch on a source overlay.  Keep that invariant in the native
        # backend, and do so *before* creating .clusterfuzzlite/build.sh.
        _make_recipe_patch_idempotent(destination)
        # The official OSS-Fuzz recipe uses Dockerfile/build.sh at its root.
        # helper.py's --external mode instead resolves the Dockerfile and
        # metadata through PROJECT/.clusterfuzzlite/.  Adapt the *temporary*
        # recipe to that layout without mutating the user's pinned checkout.
        # Keep the Docker build context at the recipe root: COPY directives in
        # the original Dockerfile must still see the original recipe files.
        integration = destination / '.clusterfuzzlite'
        if integration.is_symlink():
            integration.unlink()
        integration.mkdir(exist_ok=True)
        for filename in ('Dockerfile', 'build.sh', 'project.yaml'):
            original = destination / filename
            if original.is_file():
                adapted = integration / filename
                if adapted.is_symlink():
                    adapted.unlink()
                shutil.copy2(original, adapted)
        (destination / self.project.harness_source_filename).write_text(source, encoding='utf-8')
        return destination

    def _source_snapshot(self, root: Path) -> Path:
        destination = root / 'source'
        output = self.project.output_root
        source_root = self.project.source_root
        def ignored(directory: str, files: list[str]) -> list[str]:
            current = Path(directory).resolve()
            result = []
            for file in files:
                candidate = (current / file).resolve()
                if candidate == output or output in candidate.parents:
                    result.append(file)
                elif file in {'.git', '.venv', '__pycache__', '.mypy_cache', '.pytest_cache'}:
                    result.append(file)
            return result
        shutil.copytree(source_root, destination, symlinks=True, ignore=ignored)
        return destination

    async def _build(self, code: str, workspace: Path) -> CommandReport:
        recipe = self._temporary_project(workspace, code)
        src = self._source_snapshot(workspace)
        self._emit(f'OSS-Fuzz native build started: {self.project.oss_fuzz_project}')
        return await self._helper([
            'build_fuzzers', '--external', '--clean', '--engine', 'libfuzzer',
            '--sanitizer', 'address',
            '--mount_path', str(self.project.oss_fuzz_source_path),
            str(recipe), str(src),
        ])

    async def probe_canonical_build(self, *, svf_capture_dir: Path | None = None) -> str:
        if svf_capture_dir is not None:
            raise OssFuzzBackendError(
                'native OSS-Fuzz backend does not claim complete SVF bitcode capture'
            )
        preflight_oss_fuzz_backend(self.project)
        assert self.project.oss_fuzz_dir is not None
        assert self.project.oss_fuzz_project is not None
        original = (
            self.project.oss_fuzz_dir / 'projects' / self.project.oss_fuzz_project
            / self.project.harness_source_filename
        ).read_text(encoding='utf-8')
        async with _project_lock(self.project.oss_fuzz_dir, self.project.oss_fuzz_project):
            with tempfile.TemporaryDirectory(prefix='hc-canonical-') as directory:
                report = await self._build(original, Path(directory))
        if report.timed_out or report.returncode != 0:
            log_path = _save_build_log(
                report,
                self.project.output_root / '.oss-fuzz-build-logs' / 'canonical-build.log',
            )
            raise OssFuzzBackendError(
                'canonical native OSS-Fuzz build failed:\n'
                + _build_failure_detail(report, log_path)
            )
        return self.project.oss_fuzz_fuzzer or ''

    async def verify(
        self, draft: HarnessDraft, artifact_dir: Path,
        llm_seeds: list[SeedSpec] | None = None, *, runtime_checks: bool = True,
        replay_only: bool = False,
    ) -> VerificationResult:
        if replay_only and not runtime_checks:
            raise ValueError('replay_only requires runtime_checks')
        try:
            preflight_oss_fuzz_backend(self.project)
        except OssFuzzBackendError as exc:
            return VerificationResult(
                qualified=False, build=None, replays=[], fuzz=None,
                harness_faults=[], target_findings=[], coverage_grew=None,
                reason='native OSS-Fuzz infrastructure failed', backend='oss-fuzz-native',
                infrastructure_error=str(exc),
            )
        assert self.project.oss_fuzz_dir is not None
        assert self.project.oss_fuzz_project is not None
        assert self.project.oss_fuzz_fuzzer is not None
        try:
            async with _project_lock(self.project.oss_fuzz_dir, self.project.oss_fuzz_project):
                with tempfile.TemporaryDirectory(prefix='hc-native-') as directory:
                    workspace = Path(directory)
                    build = await self._build(draft.code, workspace)
                    if build.returncode != 0 or build.timed_out:
                        log_path = _save_build_log(
                            build, artifact_dir / 'oss-fuzz-build.log',
                        )
                        return VerificationResult(
                            qualified=False, build=build, replays=[], fuzz=None,
                            harness_faults=[], target_findings=[], coverage_grew=None,
                            reason=(
                                'native OSS-Fuzz generated harness build failed'
                                + (f'; captured output: {log_path}' if log_path else '')
                            ),
                            backend='oss-fuzz-native',
                        )
                    if not runtime_checks:
                        return VerificationResult(
                            qualified=False, build=build, replays=[], fuzz=None,
                            harness_faults=[], target_findings=[], coverage_grew=None,
                            reason='build-only validation passed; runtime qualification was disabled',
                            build_ok=True, backend='oss-fuzz-native',
                        )
                    recipe = workspace / 'recipe' / self.project.oss_fuzz_project
                    check = await self._helper([
                        'check_build', '--external', str(recipe), self.project.oss_fuzz_fuzzer,
                    ], timeout=180)
                    if check.returncode != 0 or check.timed_out:
                        return VerificationResult(
                            qualified=False, build=build, replays=[check], fuzz=None,
                            harness_faults=[], target_findings=[], coverage_grew=None,
                            reason='OSS-Fuzz check_build failed for the generated harness',
                            build_ok=True, backend='oss-fuzz-native',
                        )
                    seeds_dir = artifact_dir / 'seeds'
                    seeds_dir.mkdir(parents=True, exist_ok=True)
                    seeds = write_seed_suite(
                        seeds_dir, draft.manifest.min_size, draft.manifest.variant_count,
                        llm_seeds or [], max_size=draft.manifest.max_size,
                        include_defaults=not replay_only,
                    )
                    if replay_only and not seeds:
                        return VerificationResult(
                            qualified=False, build=build, replays=[check], fuzz=None,
                            harness_faults=[], target_findings=[], coverage_grew=None,
                            reason='exploratory replay has no in-range witnessed request',
                            build_ok=True, backend='oss-fuzz-native',
                        )
                    replays: list[CommandReport] = [check]
                    for seed in seeds[:12]:
                        report = await self._helper([
                            'reproduce', '--external', str(recipe),
                            self.project.oss_fuzz_fuzzer, str(seed),
                        ], timeout=40)
                        replays.append(report)
                        if report.timed_out:
                            return VerificationResult(
                                qualified=False, build=build, replays=replays, fuzz=None,
                                harness_faults=[], target_findings=[], coverage_grew=None,
                                reason='OSS-Fuzz replay timed out', build_ok=True,
                                backend='oss-fuzz-native',
                            )
                        if report.returncode != 0:
                            return VerificationResult(
                                qualified=False, build=build, replays=replays, fuzz=None,
                                harness_faults=[f'untriaged seed crash: {seed.name}'],
                                target_findings=[], coverage_grew=None,
                                reason='seed failure requires harness/target attribution',
                                build_ok=True, backend='oss-fuzz-native',
                            )
                    if replay_only:
                        return VerificationResult(
                            qualified=False, build=build, replays=replays, fuzz=None,
                            harness_faults=[], target_findings=[], coverage_grew=None,
                            reason=(
                                'exploratory seed replay passed; exact target reach '
                                'and original request attribution remain unproven'
                            ),
                            build_ok=True, backend='oss-fuzz-native',
                        )
                    corpus_dir = artifact_dir / 'corpus'
                    corpus_dir.mkdir(parents=True, exist_ok=True)
                    for seed in seeds:
                        shutil.copy2(seed, corpus_dir / seed.name)
                    fuzz = await self._helper([
                        'run_fuzzer', '--external', '--corpus-dir', str(corpus_dir),
                        str(recipe), self.project.oss_fuzz_fuzzer,
                        f'-max_total_time={self.project.fuzz_seconds}', '-timeout=10',
                    ], timeout=self.project.fuzz_seconds + 90)
                    # OSS-Fuzz helper's exit code and corpus count cannot
                    # establish exact target-function reachability or P1/P2
                    # equivalence. Refuse to claim a qualified harness.
                    return VerificationResult(
                        qualified=False, build=build, replays=replays, fuzz=fuzz,
                        harness_faults=[], target_findings=[], coverage_grew=None,
                        reason=(
                            'native OSS-Fuzz smoke test ran; exact target reach and '
                            'original-program equivalence remain unverified'
                            if fuzz.returncode == 0 and not fuzz.timed_out else
                            'native OSS-Fuzz fuzz run failed; requires triage'
                        ),
                        build_ok=True, backend='oss-fuzz-native',
                        coverage_metrics={'corpus_file_count': len(list(corpus_dir.iterdir()))},
                    )
        except Exception as exc:
            return VerificationResult(
                qualified=False, build=None, replays=[], fuzz=None,
                harness_faults=[], target_findings=[], coverage_grew=None,
                reason='native OSS-Fuzz infrastructure failed', backend='oss-fuzz-native',
                infrastructure_error=f'{type(exc).__name__}: {exc}',
            )

    async def close_harness(self, harness_id: str) -> None:
        return None

    async def close(self) -> None:
        return None
