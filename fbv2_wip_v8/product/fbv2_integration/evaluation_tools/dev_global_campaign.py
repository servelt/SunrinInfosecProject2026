"""Development-only task-wide Global Fuzzer bridge; never a frozen runner.

No model is invoked here. A formal runner would need a new preregistration,
frozen worker and integration tests before enabling this path.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import threading
import time
from typing import Any

PRODUCT_SRC = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(PRODUCT_SRC))

from blind2_runner_draft import _kill_process_group, _launch_guarded
from vulnerabilityanalysis.analysis import RetryLedger
from vulnerabilityanalysis.official_harness import (OfficialPinnedQualification,
                                                     issue_official_pinned_qualification,
                                                     _qualification_pins_ok)
from vulnerabilityanalysis.scan import (consume_global_fuzzer_observations,
                                        record_global_fuzzer_observations,
                                        run_global_fuzz,
                                        _corpus_inputs,
                                        _observed_libfuzzer_crash_mutations)
from vulnerabilityanalysis.runtime import ProcessEnvelope


MAX_SEED_BYTES = 2_097_152
# The local guard cleanup waits at most 7s, then 5s after its hard fallback.
# Keep a small scheduler allowance inside the Global physical reservation.
GUARD_CLEANUP_ENVELOPE_SECONDS = 12.5


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    path.chmod(0o600)


@dataclass(frozen=True)
class DirectionSeed:
    direction_id: str
    path: Path
    sha256: str


class SharedPhysicalFuzzBudget:
    """One reservation ledger for overlapping physical fuzz processes."""

    def __init__(self, total_seconds: float):
        if (type(total_seconds) not in (int, float) or
                not math.isfinite(total_seconds) or
                not 0 < total_seconds <= 86_400):
            raise ValueError('invalid shared physical fuzz budget')
        self.total_seconds = float(total_seconds)
        self.spent_seconds = 0.0
        self.reservations: dict[str, float] = {}
        self.records: list[dict[str, Any]] = []

    @property
    def available(self) -> float:
        return self.total_seconds - self.spent_seconds - sum(self.reservations.values())

    def reserve(self, key: str, requested_seconds: float) -> None:
        if (key in self.reservations or type(requested_seconds) not in (int, float) or
                not math.isfinite(requested_seconds) or
                not 0 < requested_seconds <= self.available):
            raise ValueError('shared physical fuzz reservation exceeds available budget')
        self.reservations[key] = float(requested_seconds)

    def finish(self, key: str, physical_seconds: float) -> dict[str, Any]:
        if (key not in self.reservations or
                type(physical_seconds) not in (int, float) or
                not math.isfinite(physical_seconds) or
                physical_seconds < 0):
            raise ValueError('invalid measured physical fuzz seconds')
        reserved = self.reservations.pop(key)
        self.spent_seconds += float(physical_seconds)
        row = {'key': key, 'reserved_seconds': reserved,
               'physical_seconds': float(physical_seconds),
               'overrun': physical_seconds > reserved or
                          self.spent_seconds > self.total_seconds}
        self.records.append(row)
        return row

    def snapshot(self) -> dict[str, Any]:
        return {'total_seconds': self.total_seconds,
                'spent_seconds': self.spent_seconds,
                'reserved_seconds': sum(self.reservations.values()),
                'available_seconds': self.available, 'records': self.records}


def _worker_command(spec_path: Path, spec_sha256: str) -> list[str]:
    return [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
            '--worker', str(spec_path.resolve()), spec_sha256]


def _worker(spec_path: Path, spec_sha256: str) -> int:
    if (not re.fullmatch(r'[0-9a-f]{64}', spec_sha256) or
            spec_path.is_symlink() or not spec_path.is_file() or
            digest(spec_path) != spec_sha256):
        return 2
    spec = json.loads(spec_path.read_text())
    if (set(spec) != {'run_dir', 'binary', 'binary_sha256', 'run_command',
                      'seconds', 'product_src', 'direction_plan_path',
                      'direction_plan_sha256', 'seed_files'} or
            spec['product_src'] != str(PRODUCT_SRC) or
            type(spec['seconds']) is not int or spec['seconds'] < 1):
        return 2
    run_dir = Path(spec['run_dir'])
    plan_path = Path(spec['direction_plan_path'])
    if (run_dir.is_symlink() or not run_dir.is_dir() or
            spec_path.resolve() != (run_dir / 'worker_spec.json').resolve() or
            plan_path.is_symlink() or not plan_path.is_file() or
            digest(plan_path) != spec['direction_plan_sha256']):
        return 2
    corpus = run_dir / 'corpus' / 'global'
    expected = spec['seed_files']
    if (not isinstance(expected, list) or not expected or
            not corpus.is_dir() or corpus.is_symlink() or
            {str(path) for path in corpus.iterdir()} !=
            {row.get('path') for row in expected if isinstance(row, dict)}):
        return 2
    for row in expected:
        if (not isinstance(row, dict) or
                set(row) != {'path', 'sha256'} or
                not isinstance(row['path'], str) or
                not re.fullmatch(r'[0-9a-f]{64}', row['sha256']) or
                Path(row['path']).parent.resolve() != corpus.resolve() or
                Path(row['path']).is_symlink() or
                not Path(row['path']).is_file() or
                digest(Path(row['path'])) != row['sha256']):
            return 2
    binary = Path(spec['binary'])
    if binary.is_symlink() or not binary.is_file() or digest(binary) != spec['binary_sha256']:
        return 3
    worker_started = time.monotonic()
    report = run_global_fuzz(binary, run_dir, RetryLedger(max_attempts=1),
                             run_command=spec['run_command'],
                             seconds=spec['seconds'], enabled=True)
    worker_finished = time.monotonic()
    write_json(run_dir / 'runtime' / 'dev_global_worker_result.json', {
        'status': report['status'], 'binary_sha256': spec['binary_sha256'],
        'requested_seconds': spec['seconds'],
        'worker_started_monotonic': worker_started,
        'worker_finished_monotonic': worker_finished,
        'worker_execution_seconds': worker_finished - worker_started})
    return 0


def _consumer_worker_command(spec_path: Path, spec_sha256: str) -> list[str]:
    return [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
            '--consumer-worker', str(spec_path.resolve()), spec_sha256]


def _consumer_worker(spec_path: Path, spec_sha256: str) -> int:
    """Reissue product V2 authority before consuming a Global observation."""
    if (not re.fullmatch(r'[0-9a-f]{64}', spec_sha256) or
            spec_path.is_symlink() or not spec_path.is_file() or
            digest(spec_path) != spec_sha256):
        return 2
    try:
        spec = json.loads(spec_path.read_text())
    except (OSError, ValueError):
        return 2
    names = {'kind', 'run_dir', 'report_sha256', 'contract_path',
             'contract_sha256', 'source_root', 'harness', 'binary',
             'normal_seed', 'oss_fuzz_checkout', 'upstream_checkout',
             'replay_limit', 'deadline_monotonic', 'binary_sha256'}
    if (not isinstance(spec, dict) or set(spec) != names or
            spec['kind'] != 'DEV_GLOBAL_CONSUMER_WORKER_V1' or
            type(spec['replay_limit']) is not int or spec['replay_limit'] < 0 or
            type(spec['deadline_monotonic']) not in (int, float) or
            not math.isfinite(spec['deadline_monotonic'])):
        return 2
    run_dir = Path(spec['run_dir'])
    report_path = run_dir / 'runtime' / 'global_fuzz.json'
    result_path = run_dir / 'runtime' / 'dev_global_consumer_result.json'
    if (run_dir.is_symlink() or not run_dir.is_dir() or
            spec_path.resolve() != (run_dir / 'consumer_worker_spec.json').resolve() or
            report_path.is_symlink() or not report_path.is_file() or
            digest(report_path) != spec['report_sha256'] or result_path.exists()):
        return 2
    qualification = issue_official_pinned_qualification(
        contract_path=Path(spec['contract_path']),
        approved_contract_sha256=spec['contract_sha256'],
        source_root=Path(spec['source_root']), harness=Path(spec['harness']),
        binary=Path(spec['binary']), normal_seed=Path(spec['normal_seed']),
        oss_fuzz_checkout=Path(spec['oss_fuzz_checkout']),
        upstream_checkout=Path(spec['upstream_checkout']))
    if (qualification is None or not qualification.product_issued or
            qualification.contract_kind != 'OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2' or
            qualification.binary_sha256 != spec['binary_sha256']):
        return 3
    try:
        report = json.loads(report_path.read_text())
        rows = consume_global_fuzzer_observations(
            run_dir, report, target_binary=qualification.binary,
            run_command=[str(qualification.binary), '{input}'],
            target_repository=qualification.source_root,
            harness_path=qualification.harness,
            replay_limit=spec['replay_limit'],
            official_qualification=qualification,
            deadline_monotonic=spec['deadline_monotonic'])
    except (OSError, ValueError, TypeError, KeyError):
        return 4
    if not _qualification_pins_ok(qualification):
        return 3
    write_json(result_path, {
        'kind': 'DEV_GLOBAL_CONSUMER_RESULT_V1',
        'status': 'COMPLETED', 'rows': rows,
        'spec_sha256': spec_sha256,
        'report_sha256': spec['report_sha256'],
        'contract_sha256': qualification.contract_sha256,
        'binary_sha256': qualification.binary_sha256})
    return 0


class DevGlobalCampaign:
    """Own one bounded Global process while several functions are scanned."""

    def __init__(self, output: Path, qualification: OfficialPinnedQualification,
                 *, total_fuzz_seconds: float, global_seconds: int,
                 global_wall_reservation_seconds: float, replay_limit: int,
                 process_envelope: ProcessEnvelope | None = None,
                 require_accounted_consumer: bool = False):
        if (not isinstance(qualification, OfficialPinnedQualification) or
                qualification.contract_kind != 'OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2' or
                not qualification.product_issued):
            raise ValueError('a product-issued official V2 qualification is required')
        if type(global_seconds) is not int or global_seconds < 1:
            raise ValueError('Global seconds must be a positive preregistered integer')
        if (type(global_wall_reservation_seconds) not in (int, float) or
                global_wall_reservation_seconds < global_seconds):
            raise ValueError('Global physical reservation must include requested fuzz seconds')
        if type(replay_limit) is not int or replay_limit < 0:
            raise ValueError('invalid Global replay limit')
        if type(require_accounted_consumer) is not bool:
            raise ValueError('invalid Global consumer accounting policy')
        if (process_envelope is not None and
                (not callable(getattr(process_envelope, 'before_process', None)) or
                 not callable(getattr(process_envelope, 'after_process', None)) or
                 type(getattr(process_envelope, 'output_limit_bytes', None)) is not int or
                 process_envelope.output_limit_bytes < 1)):
            raise ValueError('Global consumer process envelope is incomplete')
        if require_accounted_consumer and process_envelope is not None:
            # The present official development bridge only admits the one
            # fsynced V2 process account. A duck-typed object may be useful
            # for an old toy test, but cannot claim durable physical cost.
            from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
            from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
            if (type(process_envelope) is not DevelopmentProcessEnvelopeV2 or
                    type(process_envelope.ledger) is not PersistentProcessLedgerV2 or
                    not process_envelope.ledger.path.is_file()):
                raise ValueError('accounted Global consumer needs durable V2 process ledger')
        self.output = output.resolve()
        self.run_dir = self.output / 'global_campaign'
        self.q = qualification
        self.global_seconds = global_seconds
        self.global_wall_reservation_seconds = float(global_wall_reservation_seconds)
        self.replay_limit = replay_limit
        self.process_envelope = process_envelope
        self.require_accounted_consumer = require_accounted_consumer
        self.budget = SharedPhysicalFuzzBudget(total_fuzz_seconds)
        self.seeds: list[dict[str, Any]] = []
        self.seed_provenance: str | None = None
        self.plan_path: Path | None = None
        self.plan_sha256: str | None = None
        self.process: subprocess.Popen | None = None
        self.status_read: int | None = None
        self.log_stream = None
        self.started_at: float | None = None
        self.absolute_deadline_monotonic: float | None = None
        self.guard_exited_at_monotonic: float | None = None
        self._guard_exit_lock = threading.Lock()
        self._guard_exit_event = threading.Event()
        self._guard_watcher: threading.Thread | None = None
        self._deadline_watcher: threading.Thread | None = None
        self._deadline_signalled = False
        self._guard_stop_lock = threading.Lock()
        self._guard_stop_requested = False
        self._guard_watcher_error: str | None = None
        self.function_windows: list[dict[str, Any]] = []
        self.final_result: dict[str, Any] | None = None

    def _authority_ok(self) -> bool:
        return (self.q.product_issued and _qualification_pins_ok(self.q) and
                self.q.binary.is_file() and digest(self.q.binary) == self.q.binary_sha256)

    def stage_direction_seeds(self, plan_path: Path, plan_sha256: str,
                              seeds: list[DirectionSeed]) -> None:
        if self.run_dir.exists():
            raise ValueError('Direction seeds already staged')
        if (plan_path.is_symlink() or not plan_path.is_file() or
                digest(plan_path) != plan_sha256):
            raise ValueError('Direction plan identity changed')
        plan = json.loads(plan_path.read_text())
        if (not isinstance(plan, dict) or plan.get('status') != 'COMPLETED' or
                not isinstance(plan.get('direction_ids'), list)):
            raise ValueError('Direction plan did not complete')
        if not self._authority_ok():
            raise ValueError('official V2 authority changed before Global staging')
        allowed = set(plan['direction_ids'])
        checked: list[tuple[DirectionSeed, bytes]] = []
        for seed in seeds:
            if (not re.fullmatch(r'[A-Za-z0-9_-]+', seed.direction_id) or
                    seed.direction_id not in allowed or
                    not re.fullmatch(r'[0-9a-f]{64}', seed.sha256) or
                    seed.path.is_symlink() or not seed.path.is_file() or
                    seed.path.stat().st_size > MAX_SEED_BYTES):
                raise ValueError('untrusted Direction seed')
            data = seed.path.read_bytes()
            if hashlib.sha256(data).hexdigest() != seed.sha256:
                raise ValueError('Direction seed bytes changed')
            checked.append((seed, data))
        self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        write_json(self.run_dir / 'run.json', {'run_id': self.run_dir.name,
                                               'kind': 'DEV_GLOBAL_CAMPAIGN'})
        corpus = self.run_dir / 'corpus' / 'global'
        corpus.mkdir(parents=True, mode=0o700)
        rows = []
        for seed, data in checked:
            target = corpus / f'direction_{seed.direction_id}_{seed.sha256[:16]}'
            if target.exists():
                if target.read_bytes() != data:
                    raise ValueError('Direction corpus name collision')
            else:
                descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                                     os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(data)
            rows.append({'direction_id': seed.direction_id,
                         'source_kind': 'DIRECTION_SEED_FIXED_DEV',
                         'source': str(seed.path.resolve()),
                         'source_sha256': seed.sha256,
                         'stored': str(target), 'stored_sha256': digest(target),
                         'size': len(data)})
        self.seeds = rows
        self.seed_provenance = 'DIRECTION_SEED_FIXED_DEV'
        self.plan_path = plan_path.resolve()
        self.plan_sha256 = plan_sha256
        write_json(self.run_dir / 'DIRECTION_SEEDS.json', {
            'direction_plan_path': str(plan_path.resolve()),
            'direction_plan_sha256': plan_sha256,
            'seed_count': len(rows), 'seeds': rows})

    def stage_harness_normal_seed(self) -> None:
        """Opt-in model-free baseline using only the qualified normal seed.

        This is not a Direction plan or a model-generated seed. The existing
        worker's legacy ``direction_plan_path`` field carries a pinned seed
        manifest, whose content explicitly records the baseline provenance.
        """
        if self.run_dir.exists() or self.seeds or self.plan_path is not None:
            raise ValueError('Global seed stage already exists')
        if not self._authority_ok():
            raise ValueError('official V2 authority changed before baseline staging')
        source = self.q.normal_seed
        if (source.is_symlink() or not source.is_file() or
                not 0 < source.stat().st_size <= MAX_SEED_BYTES):
            raise ValueError('qualified Harness normal seed is unavailable')
        data = source.read_bytes()
        seed_sha = hashlib.sha256(data).hexdigest()
        if seed_sha != self.q.normal_seed_sha256 or not self._authority_ok():
            raise ValueError('qualified Harness normal seed identity changed')
        self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        corpus = self.run_dir / 'corpus' / 'global'
        corpus.mkdir(parents=True, mode=0o700)
        target = corpus / f'harness_normal_{seed_sha[:16]}'
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                             os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self.seed_provenance = 'HARNESS_NORMAL_SEED'
        self.seeds = [{
            'source_kind': self.seed_provenance,
            'source': str(source.resolve()), 'source_sha256': seed_sha,
            'stored': str(target), 'stored_sha256': digest(target),
            'size': len(data)}]
        self.plan_path = self.run_dir / 'HARNESS_NORMAL_SEED_PLAN.json'
        write_json(self.plan_path, {
            'kind': 'HARNESS_NORMAL_SEED_BASELINE_V1',
            'seed_provenance': self.seed_provenance,
            'qualification_contract_sha256': self.q.contract_sha256,
            'harness_sha256': self.q.harness_sha256,
            'binary_sha256': self.q.binary_sha256,
            'normal_seed_sha256': seed_sha,
            'model_calls': 0, 'direction_plan_used': False})
        self.plan_sha256 = digest(self.plan_path)
        write_json(self.run_dir / 'run.json', {
            'run_id': self.run_dir.name, 'kind': 'DEV_GLOBAL_CAMPAIGN',
            'seed_provenance': self.seed_provenance,
            'discovery_claim': 'BASELINE_ONLY'})
        write_json(self.run_dir / 'HARNESS_NORMAL_SEED_HANDOFF.json', {
            'seed_provenance': self.seed_provenance,
            'seed_plan_path': str(self.plan_path),
            'seed_plan_sha256': self.plan_sha256,
            'seed_count': 1, 'seeds': self.seeds})

    def stage_upstream_seed_corpus(self, relative_directory: Path) -> None:
        """Stage committed upstream example inputs as a model-free corpus.

        The qualified normal seed must be present, and the source checkout is
        rechecked through the existing V2 authority. These inputs are distinct
        from model Direction seeds and from Fuzzer-produced continuation seeds.
        """
        root = self.q.upstream_checkout
        relative_directory = Path(relative_directory)
        if (self.run_dir.exists() or self.seeds or self.plan_path is not None or
                not self._authority_ok() or root is None or
                relative_directory.is_absolute() or
                not relative_directory.parts or
                any(part in ('', '.', '..') for part in relative_directory.parts)):
            raise ValueError('upstream corpus needs a fresh pinned checkout')
        directory = root / relative_directory
        if (directory.is_symlink() or not directory.is_dir() or
                directory.resolve() != directory or
                not directory.is_relative_to(root)):
            raise ValueError('upstream corpus directory is not pinned')
        tracked = subprocess.run(
            ['git', '-C', str(root), 'ls-files', '-z', '--',
             str(relative_directory)], check=True, capture_output=True,
        ).stdout
        tracked_names = {name.decode() for name in tracked.split(b'\0') if name}
        paths = sorted(directory.iterdir())
        if not 1 <= len(paths) <= 256:
            raise ValueError('upstream corpus count is outside bounds')
        checked = []
        total_bytes = 0
        for path in paths:
            if (path.is_symlink() or not path.is_file() or
                    path.relative_to(root).as_posix() not in tracked_names or
                    not 0 < path.stat().st_size <= MAX_SEED_BYTES):
                raise ValueError('upstream corpus contains an untrusted input')
            data = path.read_bytes()
            total_bytes += len(data)
            if total_bytes > 50_000_000:
                raise ValueError('upstream corpus exceeds size cap')
            checked.append((path, data, hashlib.sha256(data).hexdigest()))
        hashes = {item[2] for item in checked}
        if (len(hashes) != len(checked) or
                self.q.normal_seed_sha256 not in hashes or
                not self._authority_ok()):
            raise ValueError('upstream corpus lacks unique qualified normal seed')
        self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        corpus = self.run_dir / 'corpus/global'
        corpus.mkdir(parents=True, mode=0o700)
        rows = []
        for path, data, sha in checked:
            target = corpus / f'upstream_{sha}'
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                                 os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            rows.append({'source_kind': 'UPSTREAM_PINNED_SEED_CORPUS',
                         'source': str(path), 'source_sha256': sha,
                         'stored': str(target), 'stored_sha256': sha,
                         'size': len(data)})
        self.seeds = rows
        self.seed_provenance = 'UPSTREAM_PINNED_SEED_CORPUS'
        self.plan_path = self.run_dir / 'UPSTREAM_SEED_CORPUS_PLAN.json'
        write_json(self.plan_path, {
            'kind': 'UPSTREAM_PINNED_SEED_CORPUS_PLAN_V1',
            'seed_provenance': self.seed_provenance,
            'qualification_contract_sha256': self.q.contract_sha256,
            'upstream_revision': self.q.upstream_revision,
            'upstream_directory': str(directory),
            'harness_sha256': self.q.harness_sha256,
            'binary_sha256': self.q.binary_sha256,
            'model_calls': 0, 'direction_plan_used': False,
            'seed_count': len(rows), 'seeds': rows})
        self.plan_sha256 = digest(self.plan_path)
        write_json(self.run_dir / 'run.json', {
            'run_id': self.run_dir.name, 'kind': 'DEV_GLOBAL_CAMPAIGN',
            'seed_provenance': self.seed_provenance,
            'discovery_claim': 'EXPLORATION_ONLY'})
        write_json(self.run_dir / 'UPSTREAM_SEED_CORPUS_HANDOFF.json', {
            'seed_provenance': self.seed_provenance,
            'seed_plan_path': str(self.plan_path),
            'seed_plan_sha256': self.plan_sha256,
            'seed_count': len(rows), 'seeds': rows})

    def stage_md4c_spec_examples(self, *, combine_examples: bool = False,
                                 flag_profiles: bool = False) -> None:
        """Use ordinary committed CommonMark examples, never regression PoCs.

        The md4c Harness consumes two 32-bit flag words before Markdown.
        This development-only corpus uses zero flags and a deterministic,
        evenly spaced selection of public spec examples. An opt-in composite
        corpus joins adjacent selected examples without any bug-specific hint.
        Another opt-in corpus uses every atomic parser flag from the pinned
        public header and its documented GitHub dialect across those examples.
        """
        root = self.q.upstream_checkout
        if (type(combine_examples) is not bool or type(flag_profiles) is not bool or
                (combine_examples and flag_profiles) or self.run_dir.exists() or
                self.seeds or self.plan_path is not None or
                not self._authority_ok() or root is None or
                self.q.upstream_harness_path != 'test/fuzzers/fuzz-mdhtml.c'):
            raise ValueError('md4c spec corpus requires fresh pinned authority')
        spec = root / 'test/spec.txt'
        if spec.is_symlink() or not spec.is_file() or spec.resolve() != spec:
            raise ValueError('pinned CommonMark spec is unavailable')
        data = spec.read_bytes()
        committed = subprocess.run(
            ['git', '-C', str(root), 'show', 'HEAD:test/spec.txt'],
            check=True, capture_output=True).stdout
        if data != committed or not self._authority_ok():
            raise ValueError('CommonMark spec differs from pinned revision')
        try:
            lines = data.decode('utf-8').splitlines(keepends=True)
        except UnicodeError as exc:
            raise ValueError('CommonMark spec encoding changed') from exc
        marker = re.compile(r'`{32} example(?: [a-z]+)?\Z')
        closing = re.compile(r'`{32}\Z')
        examples: list[bytes] = []
        current: list[str] = []
        state = 0
        for line in lines:
            stripped = line.strip()
            if state == 0 and marker.fullmatch(stripped):
                current = []
                state = 1
            elif state == 1 and stripped == '.':
                example = ''.join(current).replace('→', '\t').encode('utf-8')
                if not example or len(example) + 8 > MAX_SEED_BYTES:
                    raise ValueError('CommonMark example outside seed bounds')
                examples.append(example)
                state = 2
            elif state == 2 and closing.fullmatch(stripped):
                state = 0
            elif state == 1:
                current.append(line)
        if state != 0 or len(examples) < 255:
            raise ValueError('CommonMark example framing changed')
        selected = [(index + 1, examples[index])
                    for index in ((i * (len(examples) - 1)) // 254
                                  for i in range(255))]
        normal = self.q.normal_seed.read_bytes()
        if (hashlib.sha256(normal).hexdigest() != self.q.normal_seed_sha256 or
                len({normal, *(b'\x00' * 8 + text for _, text in selected)}) != 256 or
                not self._authority_ok()):
            raise ValueError('spec corpus duplicated or authority changed')
        spec_sha = hashlib.sha256(data).hexdigest()
        source_rows = [(0, normal, str(self.q.normal_seed),
                        self.q.normal_seed_sha256)] + [
            (number, b'\x00' * 8 + text, str(spec), spec_sha)
            for number, text in selected]
        composite_numbers: dict[str, list[int]] = {}
        flag_meta: dict[str, dict[str, Any]] = {}
        header_sha = None
        if combine_examples:
            for group_size in (2, 4, 8, 16):
                for start in range(0, len(selected), group_size):
                    group = selected[start:start + group_size]
                    if len(group) < 2:
                        continue
                    label = f'combine_{group_size:02d}_{start:03d}'
                    composite_numbers[label] = [number for number, _ in group]
                    joined = b''.join(
                        text if text.endswith(b'\n') else text + b'\n'
                        for _, text in group)
                    content = b'\x00' * 8 + joined
                    if len(content) > MAX_SEED_BYTES:
                        raise ValueError('combined spec example exceeds seed bound')
                    source_rows.append((label, content, str(spec), spec_sha))
        if flag_profiles:
            header = root / 'src/md4c.h'
            if header.is_symlink() or not header.is_file() or header.resolve() != header:
                raise ValueError('pinned md4c public header is unavailable')
            header_data = header.read_bytes()
            committed_header = subprocess.run(
                ['git', '-C', str(root), 'show', 'HEAD:src/md4c.h'],
                check=True, capture_output=True).stdout
            if header_data != committed_header or not self._authority_ok():
                raise ValueError('md4c public header differs from pinned revision')
            header_sha = hashlib.sha256(header_data).hexdigest()
            header_text = header_data.decode('utf-8')
            atomic = {}
            for match in re.finditer(
                    r'^#define (MD_FLAG_[A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)\b',
                    header_text, re.MULTILINE):
                value = int(match.group(2), 16)
                if (match.group(1) in atomic or value >= 2**32 or
                        value == 0 or value & (value - 1)):
                    raise ValueError('invalid md4c parser flag definition')
                atomic[match.group(1)] = value
            if len(atomic) != 23 or len(set(atomic.values())) != 23:
                raise ValueError('md4c parser flag set changed')
            aliases = {}
            for match in re.finditer(
                    r'^#define (MD_FLAG_[A-Z0-9_]+)\s+\(([^\n]+)\)',
                    header_text, re.MULTILINE):
                parts = [part.strip() for part in match.group(2).split('|')]
                if (match.group(1) in aliases or match.group(1) in atomic or
                        not parts or any(re.fullmatch(r'MD_FLAG_[A-Z0-9_]+',
                                                      part) is None
                                         for part in parts)):
                    raise ValueError('invalid md4c parser flag alias')
                aliases[match.group(1)] = parts

            def resolve_flag(name: str, seen: frozenset[str]) -> int:
                if name in atomic:
                    return atomic[name]
                if name in seen or name not in aliases:
                    raise ValueError('md4c parser flag alias changed')
                value = 0
                for part in aliases[name]:
                    value |= resolve_flag(part, seen | {name})
                return value

            dialect = re.search(r'^#define MD_DIALECT_GITHUB\s+\(([^\n]+)\)',
                                header_text, re.MULTILINE)
            if dialect is None:
                raise ValueError('md4c GitHub dialect definition changed')
            dialect_names = [part.strip() for part in dialect.group(1).split('|')]
            if not dialect_names or len(dialect_names) != len(set(dialect_names)):
                raise ValueError('md4c GitHub dialect definition changed')
            github_flags = 0
            for name in dialect_names:
                github_flags |= resolve_flag(name, frozenset())
            one_hot = sorted(atomic.items(), key=lambda item: item[1])
            for index, (number, text) in enumerate(selected):
                name, value = one_hot[index % len(one_hot)]
                for label, profile, flags in (
                        (f'flag_onehot_{index:03d}', name, value),
                        (f'flag_github_{index:03d}', 'MD_DIALECT_GITHUB',
                         github_flags)):
                    content = struct.pack('=II', flags, 0) + text
                    source_rows.append((label, content, str(spec), spec_sha))
                    flag_meta[label] = {
                        'example_number': number, 'parser_flag_profile': profile,
                        'parser_flags': flags, 'renderer_flags': 0,
                        'header_sha256': header_sha}
        if len({row[1] for row in source_rows}) != len(source_rows):
            raise ValueError('spec composite corpus contains duplicate input')
        if not self._authority_ok():
            raise ValueError('spec authority changed before staging')
        self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        corpus = self.run_dir / 'corpus/global'
        corpus.mkdir(parents=True, mode=0o700)
        rows = []
        for number, content, source, source_sha in source_rows:
            sha = hashlib.sha256(content).hexdigest()
            label = f'{number:04d}' if type(number) is int else number
            target = corpus / f'spec_{label}_{sha[:16]}'
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                                 os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            row = {'source_kind': ('UPSTREAM_PINNED_SPEC_FLAG_PROFILE'
                                   if number in flag_meta else
                                   'UPSTREAM_PINNED_SPEC_COMPOSITES'
                                   if type(number) is str else
                                   'HARNESS_NORMAL_SEED' if number == 0 else
                                   'UPSTREAM_PINNED_SPEC_EXAMPLES'),
                   'example_number': number if type(number) is int else None,
                   'source': source, 'source_sha256': source_sha,
                   'stored': str(target), 'stored_sha256': sha,
                   'size': len(content)}
            if type(number) is str:
                if number in flag_meta:
                    row.update(flag_meta[number])
                else:
                    row['example_numbers'] = composite_numbers[number]
            rows.append(row)
        self.seeds = rows
        self.seed_provenance = ('UPSTREAM_PINNED_SPEC_FLAG_PROFILES'
                                if flag_profiles else
                                'UPSTREAM_PINNED_SPEC_COMPOSITES'
                                if combine_examples else
                                'UPSTREAM_PINNED_SPEC_EXAMPLES')
        stem = ('UPSTREAM_SPEC_FLAG_PROFILES' if flag_profiles else
                'UPSTREAM_SPEC_COMPOSITES' if combine_examples else
                'UPSTREAM_SPEC_EXAMPLES')
        self.plan_path = self.run_dir / f'{stem}_PLAN.json'
        plan = {
            'kind': ('UPSTREAM_PINNED_SPEC_FLAG_PROFILES_PLAN_V1'
                     if flag_profiles else
                     'UPSTREAM_PINNED_SPEC_COMPOSITES_PLAN_V1'
                     if combine_examples else
                     'UPSTREAM_PINNED_SPEC_EXAMPLES_PLAN_V1'),
            'seed_provenance': self.seed_provenance,
            'qualification_contract_sha256': self.q.contract_sha256,
            'upstream_revision': self.q.upstream_revision,
            'spec_sha256': spec_sha,
            'harness_sha256': self.q.harness_sha256,
            'binary_sha256': self.q.binary_sha256,
            'model_calls': 0, 'direction_plan_used': False,
            'seed_count': len(rows), 'seeds': rows}
        if flag_profiles:
            plan['header_sha256'] = header_sha
        write_json(self.plan_path, plan)
        self.plan_sha256 = digest(self.plan_path)
        write_json(self.run_dir / 'run.json', {
            'run_id': self.run_dir.name, 'kind': 'DEV_GLOBAL_CAMPAIGN',
            'seed_provenance': self.seed_provenance,
            'discovery_claim': 'EXPLORATION_ONLY'})
        write_json(self.run_dir / f'{stem}_HANDOFF.json', {
            'seed_provenance': self.seed_provenance,
            'seed_plan_path': str(self.plan_path),
            'seed_plan_sha256': self.plan_sha256,
            'seed_count': len(rows), 'seeds': rows})

    def stage_harness_continuation(
            self, prior_output: Path, *, spec_manifest: Path | None = None,
            spec_manifest_sha256: str | None = None) -> None:
        """Continue a settled model-free corpus from its exact reported bytes.

        This is a new physical campaign, never a retry of an uncertain turn.
        The prior result must account for every current corpus byte so that a
        manually supplied PoC cannot be silently relabeled as a Fuzzer seed.
        """
        if (self.run_dir.exists() or self.seeds or self.plan_path is not None or
                not self._authority_ok() or not prior_output.is_absolute() or
                prior_output.is_symlink() or prior_output.resolve() != prior_output or
                not prior_output.is_dir()):
            raise ValueError('continuation needs a fresh campaign and canonical prior output')
        spec_mode = spec_manifest is not None
        if spec_mode != (spec_manifest_sha256 is not None):
            raise ValueError('spec continuation requires both manifest and SHA-256')
        if spec_mode:
            manifest_path = Path(spec_manifest)
            if (not manifest_path.is_absolute() or
                    manifest_path.resolve() != manifest_path or
                    manifest_path.is_symlink() or
                    not manifest_path.is_file() or
                    not re.fullmatch(r'[0-9a-f]{64}', spec_manifest_sha256) or
                    digest(manifest_path) != spec_manifest_sha256):
                raise ValueError('pinned spec manifest is unavailable')
            manifest = json.loads(manifest_path.read_text())
            rows = manifest.get('files') if type(manifest) is dict else None
            if (type(manifest) is not dict or manifest.get('kind') !=
                    'MD4C_SPEC_EXAMPLES_EXPLORATION_MANIFEST_V1' or
                    type(rows) is not list or not rows):
                raise ValueError('prior spec manifest is malformed')
            expected_paths: set[str] = set()
            for row in rows:
                if type(row) is not dict or type(row.get('path')) is not str:
                    raise ValueError('prior spec manifest entry is malformed')
                relative = Path(row['path'])
                if (relative.is_absolute() or '..' in relative.parts or
                        relative.as_posix() != row['path'] or
                        row['path'] in expected_paths or
                        type(row.get('size')) is not int or row['size'] < 0 or
                        not isinstance(row.get('sha256'), str) or
                        not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):
                    raise ValueError('prior spec manifest path or hash is invalid')
                path = prior_output / relative
                if (path.is_symlink() or not path.is_file() or
                        path.stat().st_size != row['size'] or
                        digest(path) != row['sha256']):
                    raise ValueError('prior spec manifest bytes changed')
                expected_paths.add(row['path'])
            actual_paths = set()
            for path in prior_output.rglob('*'):
                if path.is_symlink():
                    raise ValueError('prior spec output contains a symlink')
                if path.is_file():
                    actual_paths.add(path.relative_to(prior_output).as_posix())
            if actual_paths != expected_paths:
                raise ValueError('prior spec output differs from pinned manifest')
        def read_json(name: str) -> tuple[dict[str, Any], str]:
            path = prior_output / name
            if path.is_symlink() or not path.is_file() or path.resolve() != path:
                raise ValueError('prior baseline evidence is unavailable')
            raw = path.read_bytes()
            value = json.loads(raw)
            if type(value) is not dict:
                raise ValueError('prior baseline evidence is malformed')
            return value, hashlib.sha256(raw).hexdigest()

        identity, identity_sha = read_json('BASELINE_IDENTITY.json')
        result, result_sha = read_json('BASELINE_RESULT.json')
        report, report_sha = read_json('global_campaign/runtime/global_fuzz.json')
        ledger, ledger_sha = read_json('process-ledger.json')
        prior_seed_hashes = {self.q.normal_seed_sha256}
        prior_seed_count = 1
        if spec_mode:
            plan, plan_sha = read_json(
                'global_campaign/UPSTREAM_SPEC_EXAMPLES_PLAN.json')
            seed_rows = plan.get('seeds')
            upstream = self.q.upstream_checkout
            spec = upstream / 'test/spec.txt' if upstream is not None else None
            if (self.q.upstream_harness_path != 'test/fuzzers/fuzz-mdhtml.c' or
                    spec is None or spec.is_symlink() or not spec.is_file() or
                    type(seed_rows) is not list or len(seed_rows) != 256 or
                    plan.get('kind') != 'UPSTREAM_PINNED_SPEC_EXAMPLES_PLAN_V1' or
                    plan.get('seed_provenance') != 'UPSTREAM_PINNED_SPEC_EXAMPLES' or
                    plan.get('seed_count') != 256 or
                    plan.get('model_calls') != 0 or
                    plan.get('direction_plan_used') is not False or
                    plan.get('qualification_contract_sha256') !=
                    self.q.contract_sha256 or
                    plan.get('binary_sha256') != self.q.binary_sha256 or
                    plan.get('harness_sha256') != self.q.harness_sha256 or
                    plan.get('upstream_revision') != self.q.upstream_revision or
                    plan.get('spec_sha256') != digest(spec) or
                    spec.read_bytes() != subprocess.run(
                        ['git', '-C', str(upstream), 'show', 'HEAD:test/spec.txt'],
                        check=True, capture_output=True).stdout):
                raise ValueError('prior spec plan does not match pinned source')
            if (any(type(row) is not dict or
                    not isinstance(row.get('stored_sha256'), str) or
                    not re.fullmatch(r'[0-9a-f]{64}', row['stored_sha256'])
                    for row in seed_rows)):
                raise ValueError('prior spec seed rows are invalid')
            normal_rows = [row for row in seed_rows
                           if type(row.get('example_number')) is int and
                           row['example_number'] == 0]
            if (len(normal_rows) != 1 or
                    normal_rows[0].get('stored_sha256') !=
                    self.q.normal_seed_sha256 or
                    normal_rows[0].get('source_sha256') !=
                    self.q.normal_seed_sha256 or
                    normal_rows[0].get('source') != str(self.q.normal_seed) or
                    normal_rows[0].get('source_kind') not in {
                        'HARNESS_NORMAL_SEED',
                        'UPSTREAM_PINNED_SPEC_EXAMPLES'} or
                    any(type(row.get('example_number')) is not int or
                        row['example_number'] < 1 or
                        row.get('source_kind') != 'UPSTREAM_PINNED_SPEC_EXAMPLES' or
                        row.get('source') != str(spec) or
                        row.get('source_sha256') != plan['spec_sha256']
                        for row in seed_rows if row is not normal_rows[0]) or
                    len({row['example_number'] for row in seed_rows}) != 256):
                raise ValueError('prior spec seed origins are invalid')
            prior_seed_hashes = {row['stored_sha256'] for row in seed_rows}
            prior_seed_count = len(seed_rows)
            if (len(prior_seed_hashes) != prior_seed_count or
                    self.q.normal_seed_sha256 not in prior_seed_hashes or
                    any(Path(row['stored']).parent !=
                        prior_output / 'global_campaign/corpus/global' or
                        not Path(row['stored']).is_file() or
                        digest(Path(row['stored'])) != row['stored_sha256']
                        for row in seed_rows)):
                raise ValueError('prior spec seed bytes are untrusted')
        new_hashes = report.get('new_seed_hashes')
        if (type(new_hashes) is not list or not new_hashes or
                any(type(value) is not str or
                    re.fullmatch(r'[0-9a-f]{64}', value) is None
                    for value in new_hashes) or
                len(new_hashes) != len(set(new_hashes))):
            raise ValueError('prior corpus report has invalid hashes')
        prior_kind = ('UPSTREAM_PINNED_SPEC_EXAMPLES_BASELINE_V1' if spec_mode
                      else 'HARNESS_NORMAL_SEED_GLOBAL_BASELINE_V1')
        prior_provenance = ('UPSTREAM_PINNED_SPEC_EXAMPLES' if spec_mode
                            else 'HARNESS_NORMAL_SEED')
        if (identity.get('kind') != prior_kind or
                identity.get('seed_provenance') != prior_provenance or
                identity.get('model_calls') != 0 or
                identity.get('direction_plan_used') is not False or
                identity.get('discovery_claim') !=
                ('EXPLORATION_ONLY' if spec_mode else 'BASELINE_ONLY') or
                identity.get('qualification_contract_sha256') != self.q.contract_sha256 or
                identity.get('binary_sha256') != self.q.binary_sha256 or
                identity.get('harness_sha256') != self.q.harness_sha256 or
                identity.get('normal_seed_sha256') != self.q.normal_seed_sha256 or
                result.get('status') != 'RAN' or
                result.get('cleanup_complete') is not True or
                result.get('observed_crash_count') != 0 or
                result.get('seed_provenance') != prior_provenance or
                result.get('model_calls') != 0 or
                result.get('direction_plan_used') is not False or
                result.get('durable_process_ledger_sha256') != ledger_sha or
                ledger.get('kind') != 'DEV_PERSISTENT_PROCESS_LEDGER_V2' or
                ledger.get('stop_status') is not None or ledger.get('active') != {} or
                report.get('status') != 'RAN' or
                report.get('binary_sha256') != self.q.binary_sha256 or
                report.get('seed_count') != prior_seed_count or
                report.get('observed_crashes') != [] or
                report.get('new_seed_count') != len(new_hashes)):
            raise ValueError('prior baseline is not a settled model-free source')
        corpus = prior_output / 'global_campaign/corpus/global'
        if corpus.is_symlink() or not corpus.is_dir() or corpus.resolve() != corpus:
            raise ValueError('prior corpus path changed')
        files = sorted(corpus.iterdir())
        if not 1 < len(files) <= 20_000:
            raise ValueError('prior corpus count is outside continuation bounds')
        checked: list[tuple[Path, bytes, str]] = []
        total_bytes = 0
        for path in files:
            if (path.is_symlink() or not path.is_file() or path.resolve().parent != corpus or
                    not 0 < path.stat().st_size <= MAX_SEED_BYTES):
                raise ValueError('prior corpus has an untrusted entry')
            data = path.read_bytes()
            if not data or len(data) > MAX_SEED_BYTES:
                raise ValueError('prior corpus entry changed')
            total_bytes += len(data)
            if total_bytes > 50_000_000:
                raise ValueError('prior corpus exceeds continuation size cap')
            checked.append((path, data, hashlib.sha256(data).hexdigest()))
        hashes = {item[2] for item in checked}
        if (len(hashes) != len(checked) or
                hashes != set(new_hashes) | prior_seed_hashes or
                len(checked) != len(new_hashes) + prior_seed_count or
                not self._authority_ok()):
            raise ValueError('prior corpus does not match Fuzzer-produced hashes')
        self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        destination = self.run_dir / 'corpus/global'
        destination.mkdir(parents=True, mode=0o700)
        rows = []
        for source, data, digest_value in checked:
            target = destination / f'continuation_{digest_value}'
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                                 os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            source_kind = 'HARNESS_NORMAL_SEED_FUZZ_CONTINUATION'
            if spec_mode:
                source_kind = (
                    'HARNESS_NORMAL_SEED' if digest_value ==
                    self.q.normal_seed_sha256 else
                    'UPSTREAM_PINNED_SPEC_EXAMPLES' if digest_value in
                    prior_seed_hashes else
                    'FUZZER_MUTATION_FROM_SPEC_CORPUS')
            rows.append({'source_kind': source_kind,
                         'source': str(source), 'source_sha256': digest_value,
                         'stored': str(target), 'stored_sha256': digest_value,
                         'size': len(data)})
        self.seeds = rows
        self.seed_provenance = ('UPSTREAM_PINNED_SPEC_FUZZ_CONTINUATION'
                                if spec_mode else
                                'HARNESS_NORMAL_SEED_FUZZ_CONTINUATION')
        self.plan_path = self.run_dir / 'HARNESS_CONTINUATION_PLAN.json'
        continuation_plan = {
            'kind': ('UPSTREAM_PINNED_SPEC_FUZZ_CONTINUATION_PLAN_V1'
                     if spec_mode else
                     'HARNESS_NORMAL_SEED_FUZZ_CONTINUATION_PLAN_V1'),
            'seed_provenance': self.seed_provenance,
            'model_calls': 0, 'direction_plan_used': False,
            'qualification_contract_sha256': self.q.contract_sha256,
            'binary_sha256': self.q.binary_sha256,
            'prior_output': str(prior_output),
            'prior_identity_sha256': identity_sha,
            'prior_result_sha256': result_sha,
            'prior_global_report_sha256': report_sha,
            'prior_process_ledger_sha256': ledger_sha,
            'seed_count': len(rows),
            'seed_sha256': sorted(hashes)}
        if spec_mode:
            continuation_plan.update({
                'prior_spec_manifest_sha256': spec_manifest_sha256,
                'prior_spec_seed_plan_sha256': plan_sha,
                'prior_normal_seed_label_corrected':
                normal_rows[0]['source_kind'] != 'HARNESS_NORMAL_SEED'})
        write_json(self.plan_path, continuation_plan)
        self.plan_sha256 = digest(self.plan_path)
        write_json(self.run_dir / 'run.json', {
            'run_id': self.run_dir.name, 'kind': 'DEV_GLOBAL_CAMPAIGN',
            'seed_provenance': self.seed_provenance,
            'discovery_claim': 'EXPLORATION_ONLY'})
        write_json(self.run_dir / 'HARNESS_CONTINUATION_HANDOFF.json', {
            'seed_provenance': self.seed_provenance,
            'seed_plan_path': str(self.plan_path),
            'seed_plan_sha256': self.plan_sha256,
            'seed_count': len(rows), 'seeds': rows})

    def start(self) -> str:
        if self.process is not None or not self.run_dir.is_dir():
            raise ValueError('stage Direction seeds once before start')
        if not self.seeds:
            self.final_result = {'status': 'NOT_STARTED_NO_DIRECTION_SEED',
                                 'seed_count': 0}
            write_json(self.run_dir / 'DEV_GLOBAL_RESULT.json', self.final_result)
            return self.final_result['status']
        if not self._authority_ok():
            raise ValueError('official V2 authority changed before Global start')
        if (self.plan_path is None or self.plan_sha256 is None or
                digest(self.plan_path) != self.plan_sha256 or
                any(digest(Path(row['stored'])) != row['stored_sha256']
                    for row in self.seeds)):
            raise ValueError('Direction seed or plan changed before Global start')
        # Refuse a reservation that cannot cover both the worker's permitted
        # lifetime and the guard's bounded descendant cleanup.
        worker_wait_limit = self._worker_wait_limit()
        self.budget.reserve('GLOBAL', self.global_wall_reservation_seconds)
        write_json(self.output / 'DEV_SHARED_FUZZ_BUDGET.json', self.budget.snapshot())
        spec_path = self.run_dir / 'worker_spec.json'
        write_json(spec_path, {
            'run_dir': str(self.run_dir), 'binary': str(self.q.binary),
            'binary_sha256': self.q.binary_sha256,
            'run_command': [str(self.q.binary), '{input}'],
            'seconds': self.global_seconds, 'product_src': str(PRODUCT_SRC),
            'direction_plan_path': str(self.plan_path),
            'direction_plan_sha256': self.plan_sha256,
            'seed_files': [{'path': row['stored'], 'sha256': row['stored_sha256']}
                           for row in self.seeds]})
        spec_sha256 = digest(spec_path)
        log_path = self.run_dir / 'worker.log'
        self.log_stream = log_path.open('wb')
        log_path.chmod(0o600)
        self.started_at = time.monotonic()
        self.absolute_deadline_monotonic = (
            self.started_at + worker_wait_limit)
        try:
            self.process, self.status_read = _launch_guarded(
                _worker_command(spec_path, spec_sha256), stdout=self.log_stream,
                stderr=subprocess.STDOUT)
        except BaseException:
            self.log_stream.close()
            self.log_stream = None
            self.budget.reservations.pop('GLOBAL')
            self.started_at = None
            self.absolute_deadline_monotonic = None
            raise
        process = self.process
        self._guard_watcher = threading.Thread(
            target=self._watch_guard, args=(process,), daemon=True,
            name='dev-global-guard-exit-observer')
        self._guard_watcher.start()
        self._deadline_watcher = threading.Thread(
            target=self._stop_guard_at_deadline, args=(process,), daemon=True,
            name='dev-global-guard-deadline')
        self._deadline_watcher.start()
        write_json(self.run_dir / 'DEV_GLOBAL_START.json', {
            'status': 'ACTIVE', 'guard_pid': self.process.pid,
            'seed_provenance': self.seed_provenance,
            'seed_count': len(self.seeds), 'binary_sha256': self.q.binary_sha256,
            'worker_spec_sha256': spec_sha256,
            'started_monotonic': self.started_at,
            'absolute_deadline_monotonic': self.absolute_deadline_monotonic,
            'global_reserved_seconds': self.global_wall_reservation_seconds})
        return 'ACTIVE'

    def _record_guard_exit(self, observed_at: float) -> None:
        with self._guard_exit_lock:
            if self.guard_exited_at_monotonic is None:
                self.guard_exited_at_monotonic = observed_at
                self._guard_exit_event.set()

    def _watch_guard(self, process: subprocess.Popen) -> None:
        try:
            process.wait()
        except BaseException as exc:
            self._guard_watcher_error = type(exc).__name__
            return
        self._record_guard_exit(time.monotonic())

    def _signal_guard_once(self, process: subprocess.Popen) -> None:
        """Make deadline, finish, and abort share one cooperative SIGTERM."""
        with self._guard_stop_lock:
            if self._guard_stop_requested:
                return
            try:
                os.kill(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self._guard_stop_requested = True

    def _request_cleanup_once(self, process: subprocess.Popen,
                              status_read: int) -> bool:
        """Wait for the subreaper's status without signalling it twice."""
        self._signal_guard_once(process)
        try:
            process.wait(timeout=7)
        except subprocess.TimeoutExpired:
            _kill_process_group(process.pid)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return False
            return False
        return self._guard_status(status_read) != -32768

    def _stop_guard_at_deadline(self, process: subprocess.Popen) -> None:
        """Enforce the reserved worker wall even while analysis is running."""
        deadline = self.absolute_deadline_monotonic
        if deadline is None:
            return
        while not self._guard_exit_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._guard_exit_event.wait(timeout=min(remaining, 0.05))
        if self._guard_exit_event.is_set() or process.poll() is not None:
            return
        self._deadline_signalled = True
        self._signal_guard_once(process)
        if not self._guard_exit_event.wait(timeout=7):
            # This fallback cannot prove adopted setsid descendants were
            # reaped. The missing guard status remains cleanup-incomplete.
            _kill_process_group(process.pid)

    def _await_guard_exit(self, process: subprocess.Popen) -> str:
        """Poll before each short wait; only the watcher can timestamp exit."""
        deadline = self.absolute_deadline_monotonic
        if deadline is None:
            raise ValueError('Global campaign has no absolute deadline')
        while True:
            if self._guard_exit_event.is_set():
                return 'WATCHER_WAIT'
            if process.poll() is not None:
                # A late poll proves termination, not when it happened.
                self._guard_exit_event.wait(timeout=0.05)
                return ('WATCHER_WAIT' if self._guard_exit_event.is_set() else
                        'PARENT_LATE_POLL_UNCERTAIN')
            if self._guard_watcher is not None and not self._guard_watcher.is_alive():
                return 'WATCHER_FAILED'
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 'DEADLINE'
            self._guard_exit_event.wait(timeout=min(remaining, 0.02))

    def _physical_elapsed(self, process: subprocess.Popen) -> tuple[float, bool, str]:
        end = self.guard_exited_at_monotonic
        complete = end is not None
        if end is None:
            # Exact lifetime is unknowable if the watcher failed. A stopped
            # guard gives an upper bound; a still-live guard gives a lower bound.
            stopped = process.poll() is not None
            end = time.monotonic()
            basis = ('PARENT_LATE_POLL_UPPER_BOUND_UNCERTAIN' if stopped else
                     'PARENT_DECISION_TIME_LOWER_BOUND_UNCERTAIN')
        else:
            basis = 'PARENT_MONOTONIC_GUARD_EXIT_OBSERVATION'
        return max(0.0, end - (self.started_at or end)), complete, basis

    @staticmethod
    def _guard_status(status_read: int) -> int:
        payload = os.read(status_read, 64)
        if payload == b'CLEANUP_INCOMPLETE\n':
            return -32768
        if re.fullmatch(rb'-?\d+\n', payload):
            return int(payload)
        return -32768

    def mark_function(self, function_id: str) -> None:
        if self.process is None or not re.fullmatch(r'[A-Za-z0-9_-]+', function_id):
            raise ValueError('Global is not started or function id is invalid')
        self.function_windows.append({
            'function_id': function_id, 'at_monotonic': time.monotonic(),
            'global_guard_alive': self.process.poll() is None,
            'global_guard_pid': self.process.pid})
        write_json(self.run_dir / 'FUNCTION_WINDOWS.json', self.function_windows)

    def _close_guard(self, process: subprocess.Popen, status_read: int) -> None:
        _kill_process_group(process.pid)
        os.close(status_read)
        self.status_read = None
        if self.log_stream is not None:
            self.log_stream.close()
            self.log_stream = None

    def _worker_wait_limit(self) -> float:
        reserved_worker = (self.global_wall_reservation_seconds -
                           GUARD_CLEANUP_ENVELOPE_SECONDS)
        if reserved_worker < self.global_seconds:
            raise ValueError('Global physical reservation omits guard cleanup')
        return min(self.global_seconds + 20.0, reserved_worker)

    def finish(self) -> dict[str, Any]:
        if self.final_result is not None:
            return self.final_result
        if self.process is None or self.status_read is None or self.started_at is None:
            raise ValueError('Global campaign did not start')
        process, status_read = self.process, self.status_read
        timed_out = False
        exit_source = 'NOT_OBSERVED'
        try:
            exit_source = self._await_guard_exit(process)
            if exit_source in ('WATCHER_WAIT', 'PARENT_LATE_POLL_UNCERTAIN'):
                return_code = self._guard_status(status_read)
            else:
                timed_out = exit_source == 'DEADLINE'
                cleaned = self._request_cleanup_once(process, status_read)
                return_code = 124 if cleaned else -32768
        finally:
            self._close_guard(process, status_read)
        if process.poll() is not None and not self._guard_exit_event.is_set():
            self._guard_exit_event.wait(timeout=0.05)
        measured, guard_end_observed, time_basis = self._physical_elapsed(process)
        if guard_end_observed:
            exit_source = 'WATCHER_WAIT'
        deadline_exceeded = (guard_end_observed and
                             self.guard_exited_at_monotonic >
                             self.absolute_deadline_monotonic)
        charge = self.budget.finish('GLOBAL', measured)
        write_json(self.output / 'DEV_SHARED_FUZZ_BUDGET.json', self.budget.snapshot())
        result: dict[str, Any] = {
            'status': ('STOPPED_CLEANUP_INCOMPLETE' if return_code == -32768 else
                       'INCOMPLETE_GUARD_EXIT_TIMESTAMP' if not guard_end_observed else
                       'STOPPED_GLOBAL_WALL_LIMIT' if timed_out or deadline_exceeded else
                       'STOPPED_GLOBAL_WORKER_ERROR' if return_code != 0 else
                       'INCOMPLETE_FUZZ_OVERRUN' if charge['overrun'] else
                       'PENDING_REPORT'),
            'return_code': return_code,
            'original_stop_reason': ('GLOBAL_WALL_LIMIT' if timed_out or
                                     deadline_exceeded else None),
            'cleanup_complete': return_code != -32768,
            'physical_seconds': measured, 'global_budget_charge': charge,
            'guard_end_observed': guard_end_observed,
            'guard_exit_time_trusted': guard_end_observed,
            'guard_exit_observation_source': exit_source,
            'guard_watcher_error': self._guard_watcher_error,
            'guard_watcher_health': ('EXIT_TIMESTAMP_RECORDED' if guard_end_observed
                                     else 'FAILED_EXCEPTION' if self._guard_watcher_error
                                     else 'EXIT_TIMESTAMP_MISSING'),
            'guard_exited_monotonic': self.guard_exited_at_monotonic,
            'physical_time_basis': time_basis,
            'function_windows': self.function_windows,
            'seed_provenance': self.seed_provenance,
            'seed_count': len(self.seeds), 'observed_crash_count': 0,
            'consumer_rows': [], 'observed_crash_rows': [],
            'staged_seed_sha256s': sorted({row['stored_sha256']
                                           for row in self.seeds})}
        worker_receipt = self.run_dir / 'runtime' / 'dev_global_worker_result.json'
        if worker_receipt.is_file() and not worker_receipt.is_symlink():
            result['worker_receipt_trust'] = 'UNTRUSTED_ADVISORY'
            try:
                worker = json.loads(worker_receipt.read_text())
                result['worker_receipt_sha256'] = digest(worker_receipt)
                started = worker.get('worker_started_monotonic')
                finished = worker.get('worker_finished_monotonic')
                elapsed = worker.get('worker_execution_seconds')
                numbers_ok = all(type(value) in (int, float) and
                                 math.isfinite(value)
                                 for value in (started, finished, elapsed))
                identity_ok = (worker.get('binary_sha256') == self.q.binary_sha256 and
                               worker.get('requested_seconds') == self.global_seconds)
                time_ok = (numbers_ok and 0 <= elapsed <= measured + 0.1 and
                           started <= finished and
                           abs((finished - started) - elapsed) <= 0.1 and
                           started >= self.started_at - 0.1 and
                           (not guard_end_observed or
                            finished <= self.guard_exited_at_monotonic + 0.1))
                if identity_ok and time_ok:
                    result['worker_receipt_status'] = 'INTERNALLY_CONSISTENT_ADVISORY'
                    result['worker_execution_seconds'] = elapsed
                    result['guard_minus_worker_seconds'] = (
                        measured - elapsed)
                else:
                    result['worker_receipt_status'] = (
                        'INVALID_INCONSISTENT_TIME' if identity_ok else
                        'INVALID_IDENTITY')
            except (OSError, ValueError, TypeError, AttributeError):
                result['worker_receipt_status'] = 'UNREADABLE_OR_INVALID'
        if result['status'] == 'PENDING_REPORT':
            report_path = self.run_dir / 'runtime' / 'global_fuzz.json'
            if report_path.is_symlink() or not report_path.is_file():
                result['status'] = 'INCOMPLETE_GLOBAL_REPORT_MISSING'
            elif not self._authority_ok():
                result['status'] = 'STOPPED_AUTHORITY_CHANGED'
            else:
                try:
                    report = json.loads(report_path.read_text())
                    if (not isinstance(report, dict) or
                            report.get('binary_sha256') != self.q.binary_sha256 or
                            report.get('requested_seconds') != self.global_seconds):
                        result['status'] = 'STOPPED_GLOBAL_REPORT_IDENTITY'
                    else:
                        listed = report.get('observed_crashes') or []
                        if type(listed) is not list:
                            raise ValueError('Global observation list is invalid')
                        observed_rows = []
                        for item in listed:
                            if type(item) is not dict:
                                raise ValueError('Global observation row is invalid')
                            crash_id, input_sha = (item.get('observed_crash_id'),
                                                   item.get('sha256'))
                            if (type(crash_id) is not str or not crash_id or
                                    type(input_sha) is not str or
                                    re.fullmatch(r'[0-9a-f]{64}', input_sha) is None):
                                raise ValueError('Global observation identity is invalid')
                            observed_rows.append({'crash_id': crash_id,
                                                  'input_sha256': input_sha})
                        if len({row['crash_id'] for row in observed_rows}) != len(observed_rows):
                            raise ValueError('Global observation IDs are duplicated')
                        mutations = report.get('crash_mutation_observations', [])
                        if type(mutations) is not list:
                            raise ValueError('Global mutation observations are invalid')
                        by_crash = {row['crash_id']: row['input_sha256']
                                    for row in observed_rows}
                        mutated_rows = []
                        for item in mutations:
                            if type(item) is not dict:
                                raise ValueError('Global mutation observation is invalid')
                            crash_id = item.get('observed_crash_id')
                            input_sha = item.get('input_sha256')
                            base_sha = item.get('base_sha256')
                            if (type(crash_id) is not str or
                                    by_crash.get(crash_id) != input_sha or
                                    type(base_sha) is not str or
                                    re.fullmatch(r'[0-9a-f]{64}', base_sha) is None or
                                    input_sha == base_sha or
                                    input_sha in result['staged_seed_sha256s']):
                                raise ValueError('Global mutation identity is invalid')
                            mutated_rows.append({'crash_id': crash_id,
                                                 'input_sha256': input_sha,
                                                 'base_sha256': base_sha})
                        if len({row['crash_id'] for row in mutated_rows}) != len(mutated_rows):
                            raise ValueError('Global mutation IDs are duplicated')
                        if mutated_rows:
                            runtime_path = Path(report.get('runtime_artifact', ''))
                            runtime_sha = report.get('runtime_artifact_sha256')
                            if (runtime_path.parent != self.run_dir / 'runtime' or
                                    runtime_path.is_symlink() or not runtime_path.is_file() or
                                    type(runtime_sha) is not str or
                                    re.fullmatch(r'[0-9a-f]{64}', runtime_sha) is None or
                                    digest(runtime_path) != runtime_sha):
                                raise ValueError('Global mutation runtime receipt is invalid')
                            runtime_row = json.loads(runtime_path.read_text())
                            if (type(runtime_row) is not dict or
                                    type(runtime_row.get('stderr')) is not str):
                                raise ValueError('Global mutation log is invalid')
                            recomputed = _observed_libfuzzer_crash_mutations(
                                runtime_row['stderr'], listed,
                                set(result['staged_seed_sha256s']),
                                _corpus_inputs(self.run_dir / 'corpus' / 'global'))
                            if recomputed != mutations:
                                raise ValueError('Global mutation log does not match observations')
                        result['observed_crash_rows'] = observed_rows
                        result['observed_mutated_crash_rows'] = mutated_rows
                        result['global_report_sha256'] = digest(report_path)
                        result['global_mutation_proven'] = report.get('mutation_proven') is True
                        result['global_crash_mutation_observed'] = (
                            bool(mutated_rows) and
                            report.get('crash_mutation_observed') is True)
                        observed = record_global_fuzzer_observations(self.run_dir, report)
                        result['observed_crash_count'] = len(observed)
                        result['status'] = report['status']
                        if observed:
                            # A report with retained crashes cannot be a clean
                            # fuzz completion, even when every consumer later
                            # reaches a terminal replay/Gate result.
                            if result['status'] == 'RAN':
                                result['status'] = 'CRASH_OBSERVED_INCOMPLETE'
                            consumer_started = time.monotonic()
                            if (self.require_accounted_consumer and
                                    self.replay_limit > 0 and
                                    self.process_envelope is None):
                                # Retain the indexed observations without
                                # starting an unaccounted replay or GDB probe.
                                observed_hashes = {
                                    row.get('observed_crash_id'): row.get('sha256')
                                    for row in report.get('observed_crashes', [])
                                    if isinstance(row, dict)}
                                result['consumer_rows'] = [
                                    {'crash_id': crash_id,
                                     'input_sha256': observed_hashes.get(crash_id),
                                     'status': 'PENDING_PROCESS_ACCOUNT'}
                                    for crash_id in sorted(observed)]
                                result['status'] = 'CRASH_OBSERVED_INCOMPLETE'
                            else:
                                result['consumer_rows'] = consume_global_fuzzer_observations(
                                    self.run_dir, report, target_binary=self.q.binary,
                                    run_command=[str(self.q.binary), '{input}'],
                                    target_repository=self.q.source_root,
                                    harness_path=self.q.harness,
                                    replay_limit=self.replay_limit,
                                    official_qualification=self.q,
                                    deadline_monotonic=time.monotonic() + 120,
                                    **({'process_envelope': self.process_envelope}
                                       if self.process_envelope is not None else {}))
                            # Product libFuzzer normally marks observed-crash
                            # reports incomplete already. Also reject an
                            # inconsistent RAN report whose observation was
                            # not actually consumed to a terminal result.
                            terminal_consumer = {
                                'VERIFIED', 'GATE_CHECKED_NOT_VERIFIED',
                                'ORIGINAL_REPLAY_NOT_REPRODUCED',
                                'BLOCKED_NON_TARGET_CRASH',
                                'ALREADY_REPLAYED_BY_GLOBAL_PATH'}
                            rows = result['consumer_rows']
                            observed_ids = set(observed)
                            consumed_ids = [row.get('crash_id') for row in rows
                                            if isinstance(row, dict)]
                            if (len(rows) != len(observed_ids) or
                                    len(consumed_ids) != len(rows) or
                                    set(consumed_ids) != observed_ids or
                                    any(row.get('status') not in terminal_consumer
                                        for row in rows)):
                                result['status'] = 'CRASH_OBSERVED_INCOMPLETE'
                            result['consumer_wall_seconds'] = (
                                time.monotonic() - consumer_started)
                            result['consumer_wall_accounted_in_shared_fuzz'] = False
                            result['consumer_process_account_installed'] = (
                                self.process_envelope is not None)
                            if not self._authority_ok():
                                result['status'] = 'STOPPED_AUTHORITY_CHANGED'
                                result['consumer_authority_invalidated'] = True
                except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
                    result['status'] = 'INCOMPLETE_GLOBAL_REPORT_OR_CONSUMER'
                    result['error_type'] = type(exc).__name__
                    try:
                        result['report_sha256'] = (digest(report_path)
                                                   if report_path.is_file() else None)
                    except OSError:
                        result['report_sha256'] = None
        self.final_result = result
        write_json(self.run_dir / 'DEV_GLOBAL_RESULT.json', result)
        return result

    def abort(self) -> dict[str, Any]:
        if self.final_result is not None:
            return self.final_result
        if self.process is None or self.status_read is None:
            return {'status': 'NOT_STARTED'}
        process, status_read = self.process, self.status_read
        if process.poll() is not None:
            self._guard_exit_event.wait(timeout=0.05)
            cleaned = self._guard_status(status_read) != -32768
        else:
            cleaned = self._request_cleanup_once(process, status_read)
        self._close_guard(process, status_read)
        if process.poll() is not None and not self._guard_exit_event.is_set():
            self._guard_exit_event.wait(timeout=0.05)
        measured, guard_end_observed, time_basis = self._physical_elapsed(process)
        charge = self.budget.finish('GLOBAL', measured)
        result = {'status': 'STOPPED_ABORTED' if cleaned else
                            'STOPPED_CLEANUP_INCOMPLETE',
                  'cleanup_complete': cleaned, 'physical_seconds': measured,
                  'guard_end_observed': guard_end_observed,
                  'guard_exit_time_trusted': guard_end_observed,
                  'guard_exit_observation_source': ('WATCHER_WAIT' if guard_end_observed
                                                    else 'PARENT_LATE_POLL_UNCERTAIN'),
                  'guard_watcher_error': self._guard_watcher_error,
                  'guard_watcher_health': ('EXIT_TIMESTAMP_RECORDED' if guard_end_observed
                                           else 'FAILED_EXCEPTION' if self._guard_watcher_error
                                           else 'EXIT_TIMESTAMP_MISSING'),
                  'guard_exited_monotonic': self.guard_exited_at_monotonic,
                  'physical_time_basis': time_basis,
                  'global_budget_charge': charge}
        self.final_result = result
        write_json(self.run_dir / 'DEV_GLOBAL_RESULT.json', result)
        write_json(self.output / 'DEV_SHARED_FUZZ_BUDGET.json', self.budget.snapshot())
        return result


def main() -> int:
    if len(sys.argv) == 4 and sys.argv[1] == '--worker':
        return _worker(Path(sys.argv[2]), sys.argv[3])
    if len(sys.argv) == 4 and sys.argv[1] == '--consumer-worker':
        return _consumer_worker(Path(sys.argv[2]), sys.argv[3])
    raise SystemExit('dev_global_campaign.py supports guarded workers only')


if __name__ == '__main__':
    sys.exit(main())
