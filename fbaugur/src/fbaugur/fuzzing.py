"""Global and per-candidate fuzzers, and the watcher that turns artifacts into records.

FuzzingBrain V2 §3.6 runs a Global Fuzzer continuously for breadth and an SP Fuzzer
per candidate for depth, sharing the corpus.  Code Augur §4.3 additionally builds the
instrumented program P' and makes the committed invariants the fuzzer's target, so the
global fuzzer here runs whichever build is current: the plain harness until the first
invariant is built, the instrumented one after that, with the corpus carried over.

Every libFuzzer artifact is replayed once to decide what it is: an invariant violation
(the abort from the assertion hook) or a real crash.  Violations go to triage, crashes
to confirmation; both keep the input file.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import shutil
import signal
import time
from pathlib import Path
from typing import Any, Callable

from .runner import NETNS, finding_type, is_finding, load_ub_baseline, parse_report, run_input, sanitizer_env
from .store import Store, new_id


@dataclasses.dataclass
class FuzzerSpec:
    name: str
    binary: Path
    corpus: Path
    artifacts: Path
    log: Path
    seconds: float | None = None            # None = until stopped
    max_len: int = 0
    continue_phis: list[int] = dataclasses.field(default_factory=list)
    extra: list[str] = dataclasses.field(default_factory=list)


class FuzzerProcess:
    """One libFuzzer process in its own network namespace."""

    def __init__(self, spec: FuzzerSpec):
        self.spec = spec
        self.process: asyncio.subprocess.Process | None = None
        self.started_at = 0.0

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.returncode is None

    def argv(self) -> list[str]:
        spec = self.spec
        argv = [*NETNS, str(spec.binary),
                f"-artifact_prefix={spec.artifacts}/", "-print_final_stats=1",
                "-timeout=20", "-rss_limit_mb=4096", "-error_exitcode=86"]
        if spec.max_len:
            argv.append(f"-max_len={spec.max_len}")
        if spec.seconds:
            argv.append(f"-max_total_time={int(spec.seconds)}")
        argv += spec.extra
        argv.append(str(spec.corpus))
        return argv

    async def start(self) -> None:
        spec = self.spec
        for directory in (spec.corpus, spec.artifacts, spec.log.parent):
            directory.mkdir(parents=True, exist_ok=True)
        env = sanitizer_env({"FBA_PHI_CONTINUE": ",".join(str(p) for p in spec.continue_phis)}
                            if spec.continue_phis else None)
        handle = spec.log.open("ab")
        handle.write(f"\n=== {time.strftime('%H:%M:%S')} {' '.join(self.argv())}\n".encode())
        handle.flush()
        self.process = await asyncio.create_subprocess_exec(
            *self.argv(), stdout=handle, stderr=handle, stdin=asyncio.subprocess.DEVNULL,
            cwd=str(spec.corpus.parent), env=env, start_new_session=True)
        self._log_handle = handle
        self.started_at = time.time()

    async def stop(self, grace: float = 5.0) -> None:
        process = self.process
        if process is None or process.returncode is not None:
            return
        # The fuzzer runs in its own session (and namespace); signal the group.
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(os.getpgid(process.pid), sig)
            except (ProcessLookupError, PermissionError):
                break
            try:
                await asyncio.wait_for(process.wait(), timeout=grace)
                break
            except asyncio.TimeoutError:
                grace = 2.0
        with contextlib.suppress(Exception):
            self._log_handle.close()


class CrashWatcher:
    """Turns new libFuzzer artifacts and corpus entries into store records.

    FBv2's CrashMonitor polls the artifact directories every few seconds and
    de-duplicates by file hash; this does the same and additionally replays each
    artifact once so an invariant violation is not recorded as a crash.
    """

    def __init__(self, store: Store, *, run_dir: Path, worker: str, harness: str, emit=None):
        self.store = store
        self.run_dir = Path(run_dir)
        self.worker = worker
        self.harness = harness
        self.emit = emit or (lambda message: None)
        self.seen: set[str] = set()
        self.watch: list[tuple[Path, str]] = []            # (artifact dir, source label)

    def add(self, directory: Path, source: str) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.watch.append((directory, source))

    def _store_input(self, data: bytes, kind: str) -> Path:
        directory = self.run_dir / "inputs" / kind
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{kind}-{hashlib.sha1(data).hexdigest()[:16]}.bin"
        if not path.exists():
            path.write_bytes(data)
        return path

    async def sweep(self, binary: Path, *, phis: dict[int, int] | None = None) -> list[dict[str, Any]]:
        """Classify every unseen artifact.  `phis` maps phi number -> invariant id."""
        found: list[dict[str, Any]] = []
        for directory, source in self.watch:
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if not path.is_file() or path.name.startswith("."):
                    continue
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                digest = hashlib.sha1(data).hexdigest()
                if digest in self.seen or not data:
                    continue
                self.seen.add(digest)
                result = await asyncio.to_thread(run_input, binary, data, timeout=15)
                now = time.time()
                if result.violations:
                    for phi in result.violations:
                        if phis is not None and phi not in phis:
                            continue
                        stored = self._store_input(data, "violation")
                        violation_id = new_id("vio")
                        self.store.insert("violations", {
                            "violation_id": violation_id, "phi_num": phi, "harness_id": self.harness,
                            "worker_id": self.worker, "input_path": str(stored), "status": "pending",
                            "created_at": now, "updated_at": now})
                        self.emit(f"[fuzz] invariant phi {phi} falsified by {source} ({len(data)} bytes)")
                        found.append({"kind": "violation", "phi": phi, "violation_id": violation_id})
                elif is_finding(result, load_ub_baseline(self.run_dir)):
                    stored = self._store_input(data, "crash")
                    crash_id = new_id("crash")
                    self.store.insert("crashes", {
                        "crash_id": crash_id, "worker_id": self.worker, "source": source, "sp_id": None,
                        "input_path": str(stored), "status": "pending",
                        "crash_type": finding_type(result, load_ub_baseline(self.run_dir)),
                        "frames": result.frames, "details": {"summary": result.summary(),
                                                              "stderr_tail": result.stderr_tail[-3000:]},
                        "created_at": now, "updated_at": now})
                    self.emit(f"[fuzz] {source} crash: {result.summary()[:160]}")
                    found.append({"kind": "crash", "crash_id": crash_id, "crash_type": result.crash_type})
                else:
                    # libFuzzer saved it (slow unit, OOM, leak) but a clean replay says nothing happened.
                    self.emit(f"[fuzz] {source} artifact {path.name} did not reproduce ({result.summary()[:80]})")
        return found


class GlobalFuzzer:
    """Keeps one global fuzzer running and swaps in each new instrumented build."""

    def __init__(self, store: Store, *, run_dir: Path, worker: str, harness: str, binary: Path,
                 seeds: list[tuple[str, bytes]], max_len: int = 0, emit=None):
        self.store = store
        self.run_dir = Path(run_dir)
        self.worker = worker
        self.harness = harness
        self.binary = binary
        self.max_len = max_len
        self.emit = emit or (lambda message: None)
        self.work = self.run_dir / "work" / harness
        self.corpus = self.work / "corpus"
        self.artifacts = self.work / "artifacts"
        self.log = self.run_dir / "logs" / f"{harness}-global-fuzzer.log"
        self.extra_corpus = self.work / "corpus-extra"
        self.process: FuzzerProcess | None = None
        self.share_from: Path | None = None       # another fuzzer's corpus to pull from at each start
        self.restarts: list[float] = []
        self.continue_phis: list[int] = []
        self.watcher = CrashWatcher(store, run_dir=run_dir, worker=worker, harness=harness, emit=self.emit)
        self.watcher.add(self.artifacts, "global_fuzzer")
        self.corpus.mkdir(parents=True, exist_ok=True)
        self.extra_corpus.mkdir(parents=True, exist_ok=True)
        for seed_id, blob in seeds:
            (self.corpus / f"hc-{seed_id}").write_bytes(blob)       # HarnessCreator's verified normal inputs

    def absorb_extra(self) -> int:
        """Move inputs agents produced (seeds, PoV attempts) into the fuzzer corpus.

        A fuzzer with `share_from` (the MemorySanitizer one) also copies in the inputs the other
        fuzzer of the same harness has found, so it starts from that coverage rather than from
        the seeds alone.  Inputs this fuzzer quarantined are not copied back.
        """
        moved = 0
        if self.share_from is not None and self.share_from.is_dir():
            jailed = {p.name for p in (self.work / "corpus-quarantine").glob("*")}
            for path in self.share_from.iterdir():
                target = self.corpus / path.name
                if path.is_file() and not target.exists() and path.name not in jailed:
                    shutil.copy(path, target)
                    moved += 1
        for path in list(self.extra_corpus.iterdir()):
            if path.is_file():
                target = self.corpus / path.name
                if not target.exists():
                    shutil.move(str(path), str(target))
                    moved += 1
                else:
                    path.unlink()
        return moved

    async def start(self, binary: Path | None = None, continue_phis: list[int] | None = None) -> None:
        if binary is not None:
            self.binary = binary
        if continue_phis is not None:
            self.continue_phis = sorted(set(continue_phis))
        self.absorb_extra()
        self.process = FuzzerProcess(FuzzerSpec(
            name=f"{self.harness}-global", binary=self.binary, corpus=self.corpus, artifacts=self.artifacts,
            log=self.log, max_len=self.max_len, continue_phis=self.continue_phis))
        await self.process.start()
        self.emit(f"[fuzz] global fuzzer on {self.binary.parent.parent.name or self.binary.name}"
                  f" ({len(list(self.corpus.iterdir()))} corpus inputs"
                  + (f", {len(self.continue_phis)} invariants in continue mode)" if self.continue_phis else ")"))

    async def swap(self, binary: Path, continue_phis: list[int]) -> None:
        """Restart on a new build, keeping the corpus (Code Augur persists C across calls)."""
        await self.stop()
        await self.start(binary, continue_phis)

    async def stop(self) -> None:
        if self.process is not None:
            await self.process.stop()
            self.process = None

    async def poll(self, phis: dict[int, int] | None = None) -> list[dict[str, Any]]:
        self.absorb_extra()
        events = await self.watcher.sweep(self.binary, phis=phis)
        if self.process is not None and not self.process.running:
            # libFuzzer exits after saving a crash or on an invariant abort; restart it.
            code = self.process.process.returncode if self.process.process else None
            removed = self.quarantine_seed_crash()
            self.restarts.append(time.time())
            recent = [s for s in self.restarts if s > time.time() - 600]
            self.emit(f"[fuzz] global fuzzer exited (code {code}); restarting"
                      + (f"; removed {removed} corpus input(s) that fault while the corpus loads" if removed else ""))
            if len(recent) >= 10 and not removed:
                # libFuzzer exits on every crash, and -fork / -merge cannot help here: an in-process
                # server harness binds its fixed port in the parent, so the children's inputs are
                # served -- and crash -- in the parent (measured on LightFTP).  Frequent restarts
                # therefore mean either a shallow known bug being re-found, or a harness that
                # returns before the program finishes an input.
                self.emit(f"[fuzz] WARNING: {len(recent)} restarts in 10 min without a removable seed -- "
                          "a shallow known bug is being re-found, or the harness returns before the program "
                          "finishes an input so faults land on later inputs")
            await self.start()
        return events

    def _last_session(self) -> str:
        """Log text of the most recent fuzzer start (each start writes an `=== HH:MM:SS` header)."""
        if not self.log.is_file():
            return ""
        text = self.log.read_text(encoding="utf-8", errors="replace")[-400000:]
        cut = text.rfind("\n=== ")
        return text[cut:] if cut >= 0 else text

    def quarantine_seed_crash(self) -> int:
        """Move out of the corpus an input that faulted while libFuzzer was loading the corpus.

        libFuzzer runs every corpus input before it mutates anything, so one faulting input in
        the corpus ends every start at the same place, and the restarts never get past it.
        Measured on LightFTP (control-connection context): 222 restarts, longest run 1,159 units.
        A fault before `INITED` is a seed, so the saved artifact has the seed's exact bytes and
        is matched by content hash.  Quarantined inputs are kept, not deleted.
        """
        session = self._last_session()
        if " INITED " in session or "INITED cov" in session:
            return 0
        match = None
        for match in re.finditer(r"Test unit written to (\S+)", session):
            pass
        if match is None:
            return 0
        artifact = Path(match.group(1))
        if not artifact.is_absolute():
            artifact = self.corpus.parent / artifact
        try:
            digest = hashlib.sha1(artifact.read_bytes()).hexdigest()
        except OSError:
            return 0
        jail = self.work / "corpus-quarantine"
        jail.mkdir(parents=True, exist_ok=True)
        removed = 0
        for path in list(self.corpus.iterdir()):
            try:
                if path.is_file() and hashlib.sha1(path.read_bytes()).hexdigest() == digest:
                    shutil.move(str(path), str(jail / path.name))
                    removed += 1
            except OSError:
                continue
        return removed

    def stats(self) -> dict[str, Any]:
        text = self.log.read_text(encoding="utf-8", errors="replace")[-20000:] if self.log.is_file() else ""
        executed = [int(m) for m in re.findall(r"stat::number_of_executed_units:\s*(\d+)", text)]
        covered = [int(m) for m in re.findall(r"#\d+\s+\w+\s+cov: (\d+)", text)]
        return {"corpus": len(list(self.corpus.iterdir())) if self.corpus.is_dir() else 0,
                "artifacts": len(list(self.artifacts.iterdir())) if self.artifacts.is_dir() else 0,
                "executed_units": max(executed) if executed else None,
                "coverage": max(covered) if covered else None,
                "running": bool(self.process and self.process.running)}


async def fuzz_candidate(store: Store, *, run_dir: Path, worker: str, harness: str, binary: Path, sp_id: str,
                         seconds: int, global_corpus: Path, emit=None) -> list[dict[str, Any]]:
    """Bounded per-candidate fuzzing of the inputs a PoV agent produced (FBv2 SP Fuzzer)."""
    emit = emit or (lambda message: None)
    base = Path(run_dir) / "work" / worker / "sp" / sp_id
    corpus, artifacts = base / "corpus", base / "artifacts"
    if not corpus.is_dir() or not any(corpus.iterdir()):
        return []
    watcher = CrashWatcher(store, run_dir=run_dir, worker=worker, harness=harness, emit=emit)
    watcher.add(artifacts, f"sp_fuzzer:{sp_id}")
    process = FuzzerProcess(FuzzerSpec(name=f"sp-{sp_id}", binary=binary, corpus=corpus, artifacts=artifacts,
                                       log=base / "fuzz.log", seconds=seconds,
                                       extra=[f"-max_total_time={seconds}"]))
    await process.start()
    try:
        await asyncio.wait_for(process.process.wait(), timeout=seconds + 60)
    except asyncio.TimeoutError:
        pass
    finally:
        await process.stop()
    events = await watcher.sweep(binary)
    # New inputs the mutation found are worth keeping for the global fuzzer.
    for path in corpus.iterdir():
        target = global_corpus / f"sp-{sp_id}-{path.name}"
        if path.is_file() and not target.exists():
            try:
                target.write_bytes(path.read_bytes())
            except OSError:
                pass
    for event in events:
        if event.get("kind") == "crash":
            store.update("crashes", "crash_id", event["crash_id"], {"sp_id": sp_id, "updated_at": time.time()})
    return events
