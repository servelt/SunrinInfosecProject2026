"""Provider-free replay of retained Fuzzer evidence through the existing gates."""

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from vulnerabilityanalysis.analysis import RetryLedger
from vulnerabilityanalysis.final_verification import crash_fingerprint
from vulnerabilityanalysis.fuzzer_crash_consumer import consume_fuzzer_crash_observation
from vulnerabilityanalysis.models import RuntimeResult, stable_id
from vulnerabilityanalysis.runtime import ProcessEnvelopeStop
from vulnerabilityanalysis.official_harness import hash_source_tree_v2
from vulnerabilityanalysis.scan import (_record_fuzzer_crash,
                                        consume_global_fuzzer_observations,
                                        record_global_fuzzer_observations,
                                        run_global_fuzz)
from test_official_v2_contract import Fixture as OfficialV2Fixture


SOURCE = r'''#include <stdio.h>
#include <stdlib.h>

static int target_operation(int marker) {
    if (marker != 'X') return 0;
    char *buffer = (char *)malloc(8);
    if (buffer == NULL) return 2;
    buffer[0] = 1;
    free(buffer);
    volatile char observed = buffer[0];
    return observed;
}

int main(int argc, char **argv) {
    if (argc != 2) return 3;
    FILE *stream = fopen(argv[1], "rb");
    if (stream == NULL) return 4;
    int marker = fgetc(stream);
    fclose(stream);
    return target_operation(marker);
}
'''

OFFICIAL_FUZZ = r'''#include <stddef.h>
#include <stdint.h>
extern int target_operation(int marker);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0) target_operation(data[0]);
    return 0;
}
'''

OFFICIAL_TARGET = r'''#include <stdlib.h>
int target_operation(int marker) {
    if (marker != 'X') return 0;
    char *buffer = (char *)malloc(8);
    if (buffer == NULL) return 2;
    buffer[0] = 1;
    free(buffer);
    volatile char observed = buffer[0];
    return observed;
}
'''


class FuzzerCrashConsumerTest(unittest.TestCase):
    def test_fuzzer_record_does_not_follow_symlinked_crash_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = root / 'run'
            crash_dir = run / 'runtime' / 'fuzzer_crashes'
            crash_dir.mkdir(parents=True)
            outside = root / 'outside.json'
            original = b'{"crash_id": "outside", "observations": []}\n'
            outside.write_bytes(original)
            (crash_dir / 'fixture.json').symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'record path is linked'):
                _record_fuzzer_crash(
                    run, 'fixture', 'SP_FUZZER',
                    run / 'runtime' / 'sp.targeted_fuzz.json', 'sp_fixture')
            self.assertEqual(outside.read_bytes(), original)

    def test_observed_oob_without_causal_evidence_is_pending_not_gate_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, _, harness, _, seed_sha, observation_id = self._prepare(root)
            binary = root / 'binary'
            binary.write_bytes(b'never executed')
            runtime = RuntimeResult(
                1, '', 'ERROR: AddressSanitizer: heap-buffer-overflow',
                6, False, 'AddressSanitizer: heap-buffer-overflow', None,
                'SANITIZER_CRASH', crash_triage={'category': 'TARGET_CRASH'})
            crash_id = crash_fingerprint(runtime)

            def fake_runtime(poc, point, command, run_dir, **kwargs):
                path = run_dir / 'runtime' / f'{poc.poc_id}.json'
                path.write_text(json.dumps(asdict(runtime)))
                canonical = run_dir / 'runtime' / 'crashes' / f'{crash_id}.json'
                canonical.parent.mkdir(parents=True, exist_ok=True)
                canonical.write_text(json.dumps({
                    'observations': [{'runtime_artifact': str(path)}],
                    'independent_verification_status':
                        'TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE'}))
                return []

            with patch('vulnerabilityanalysis.scan.execute_poc',
                       side_effect=fake_runtime):
                outcome = consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    command=[str(binary), '{input}'],
                    target_repository=checkout, harness_path=harness)
            self.assertEqual(outcome['status'], 'PENDING_CAUSAL_EVIDENCE')
            self.assertEqual(outcome['independent_verification_status'],
                             'TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE')
            self.assertFalse(outcome['gate_evaluated'])
            self.assertEqual(outcome['gate_status'], 'NOT_EVALUATED')

    def test_mixed_seed_sp_labels_never_bind_observed_crash_to_original_sp(self):
        """Seed ancestry and SP/PoV labels are not causal evidence.

        A follow-up Fuzzer may retain a mutation below an SP-specific corpus
        directory and carry the seed PoV identity for accounting.  Those
        labels must not be reinterpreted as proof that the original model SP
        caused the sanitizer observation.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, _, harness, _, seed_sha, observation_id = self._prepare(root)
            record_path = run / 'runtime' / 'fuzzer_crashes' / f'{observation_id}.json'
            record = json.loads(record_path.read_text())
            record['corpus_provenance'] = 'MIXED_SEEDS'
            record['model_pov_contribution'] = 'UNDETERMINED'
            record['observations'][0]['source'] = 'SP_FOLLOWUP_FUZZER'
            record['observations'][0]['sp_id'] = 'sp-original-model-claim'
            record['observations'][0]['crash_input']['poc_id'] = 'poc-clean-seed'
            record_path.write_text(json.dumps(record))

            binary = root / 'binary'
            binary.write_bytes(b'never executed')
            runtime = RuntimeResult(
                1, '', 'ERROR: AddressSanitizer: heap-buffer-overflow',
                6, False, 'AddressSanitizer: heap-buffer-overflow', None,
                'SANITIZER_CRASH', crash_triage={'category': 'TARGET_CRASH'})
            crash_id = crash_fingerprint(runtime)
            observed_points = []

            def fake_runtime(poc, point, command, run_dir, **kwargs):
                observed_points.append(point)
                path = run_dir / 'runtime' / f'{poc.poc_id}.json'
                path.write_text(json.dumps(asdict(runtime)))
                canonical = run_dir / 'runtime' / 'crashes' / f'{crash_id}.json'
                canonical.parent.mkdir(parents=True, exist_ok=True)
                canonical.write_text(json.dumps({
                    'observations': [{'runtime_artifact': str(path)}],
                    'independent_verification_status':
                        'TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE'}))
                return []

            with patch('vulnerabilityanalysis.scan.execute_poc',
                       side_effect=fake_runtime):
                outcome = consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    command=[str(binary), '{input}'],
                    target_repository=checkout, harness_path=harness)

            self.assertEqual(outcome['status'], 'PENDING_CAUSAL_EVIDENCE')
            self.assertEqual(outcome['original_sp_relation'], 'UNVERIFIED')
            self.assertFalse(outcome['gate_evaluated'])
            lineage = outcome['untrusted_discovery_lineage']
            self.assertEqual(lineage['schema'],
                             'FBV2_UNTRUSTED_FUZZER_DISCOVERY_LINEAGE_V1')
            self.assertEqual(lineage['observation_id'], observation_id)
            self.assertEqual(lineage['input_sha256'], seed_sha)
            self.assertEqual(lineage['corpus_provenance'], 'MIXED_SEEDS')
            self.assertEqual(lineage['model_pov_contribution'], 'UNDETERMINED')
            self.assertEqual(lineage['evidence_authority'], 'NONE')
            self.assertEqual(lineage['causal_relation_status'], 'UNPROVEN')
            self.assertFalse(lineage['automatic_discovery'])
            self.assertEqual(lineage['discovery_credit'], 'NOT_CREDITED')
            self.assertFalse(lineage['gate_input'])
            self.assertEqual(lineage['observation_labels'], [{
                'source': 'SP_FOLLOWUP_FUZZER',
                'sp_id': 'sp-original-model-claim',
                'poc_id': 'poc-clean-seed',
            }])
            canonical = json.dumps(
                lineage, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
            ).encode()
            self.assertEqual(
                outcome['untrusted_discovery_lineage_sha256'],
                hashlib.sha256(canonical).hexdigest())
            self.assertEqual(len(observed_points), 1)
            self.assertEqual(observed_points[0].worker_id, 'FUZZER_OBSERVATION')
            self.assertEqual(observed_points[0].direction_id, 'FUZZER_OBSERVATION')
            self.assertNotEqual(observed_points[0].sp_id, 'sp-original-model-claim')
            self.assertEqual(observed_points[0].function_name, 'UNKNOWN')
            self.assertEqual(observed_points[0].code_location, 'UNKNOWN')
            self.assertEqual(observed_points[0].external_input_relation, 'UNKNOWN')

            # The cached result is bound to the exact canonical artifact.
            canonical_path = Path(outcome['canonical_crash_artifact'])
            canonical_before = canonical_path.read_bytes()
            canonical_changed = json.loads(canonical_before)
            canonical_changed['independent_verification_status'] = 'VERIFIED'
            canonical_path.write_text(json.dumps(canonical_changed))
            with self.assertRaisesRegex(
                    ValueError, 'cached Fuzzer canonical artifact changed'):
                consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256=hashlib.sha256(
                        binary.read_bytes()).hexdigest(),
                    command=[str(binary), '{input}'],
                    target_repository=checkout, harness_path=harness)
            canonical_path.write_bytes(canonical_before)

            # Accounting labels are pinned after the first replay.  They may
            # not be rewritten later to change the discovery narrative.
            changed = json.loads(record_path.read_text())
            changed['model_pov_contribution'] = 'ATTRIBUTED_AFTER_THE_FACT'
            record_path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(
                    ValueError, 'cached Fuzzer discovery lineage changed'):
                consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256=hashlib.sha256(
                        binary.read_bytes()).hexdigest(),
                    command=[str(binary), '{input}'],
                    target_repository=checkout, harness_path=harness)

    def test_coherent_dual_copy_cache_tamper_cannot_add_gate_verdict(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, _, harness, _, seed_sha, observation_id = self._prepare(
                root, b'Y')
            binary = root / 'binary'
            binary.write_bytes(b'never executed')
            runtime = RuntimeResult(0, '', '', None, False, None, None, 'NO_CRASH')

            def fake_runtime(poc, point, command, run_dir, **kwargs):
                path = run_dir / 'runtime' / f'{poc.poc_id}.json'
                path.write_text(json.dumps(asdict(runtime)))
                return []

            common = dict(
                binary=binary,
                expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                command=[str(binary), '{input}'],
                target_repository=checkout, harness_path=harness)
            with patch('vulnerabilityanalysis.scan.execute_poc', side_effect=fake_runtime):
                outcome = consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, **common)
            self.assertEqual(outcome['status'], 'ORIGINAL_REPLAY_NOT_REPRODUCED')

            record_path = run / 'runtime/fuzzer_crashes' / f'{observation_id}.json'
            record = json.loads(record_path.read_text())
            forged = dict(record['consumer_results'][seed_sha])
            forged.update({
                'gate_evaluated': True,
                'gate_status': 'VERIFIED',
                'independent_verification_status': 'VERIFIED',
            })
            record['consumer_results'][seed_sha] = forged
            record['consumer_attempts'][seed_sha][-1] = forged
            record_path.write_text(json.dumps(record))
            with self.assertRaisesRegex(
                    ValueError, 'cached Fuzzer outcome contradicts evidence'):
                consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, **common)

    def test_global_process_stop_blocks_later_replay_without_target_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, _, harness, seed, seed_sha, observation_id = self._prepare(root)
            binary = root / 'binary'
            binary.write_bytes(b'never executed')
            envelope = object()
            deadline = time.monotonic() + 30
            report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                      'observed_crashes': [
                          {'observed_crash_id': observation_id, 'sha256': seed_sha},
                          {'observed_crash_id': 'second-input', 'sha256': seed_sha}]}
            with patch('vulnerabilityanalysis.fuzzer_crash_consumer.'
                       'consume_fuzzer_crash_observation',
                       side_effect=ProcessEnvelopeStop(
                           'PENDING_PHYSICAL_BUDGET', 'no process lease')) as consume:
                rows = consume_global_fuzzer_observations(
                    run, report, target_binary=binary,
                    run_command=[str(binary), '{input}'],
                    target_repository=checkout, harness_path=harness,
                    replay_limit=2, process_envelope=envelope,
                    deadline_monotonic=deadline)
            self.assertEqual(consume.call_count, 1)
            self.assertIs(consume.call_args.kwargs['process_envelope'], envelope)
            self.assertEqual(
                consume.call_args.kwargs['observation_deadline_monotonic'],
                deadline)
            self.assertEqual([row['status'] for row in rows], [
                'PENDING_PHYSICAL_BUDGET', 'NOT_ADMITTED_AFTER_PROCESS_STOP'])
            self.assertEqual(rows[1]['process_stop_status'], 'PENDING_PHYSICAL_BUDGET')

    def test_observation_consumer_passes_same_envelope_to_product_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, _, seed_sha, observation_id = self._prepare(root)
            binary = root / 'binary'
            binary.write_bytes(b'never executed')
            envelope = object()
            deadline = time.monotonic() + 30

            def fake_runtime(poc, point, command, run_dir, **kwargs):
                path = run_dir / 'runtime' / f'{poc.poc_id}.json'
                path.write_text(json.dumps(asdict(RuntimeResult(
                    0, '', '', None, False, None, None, 'NO_CRASH'))))
                return []

            with patch('vulnerabilityanalysis.scan.execute_poc',
                       side_effect=fake_runtime) as execute:
                outcome = consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    command=[str(binary), '{input}'],
                    target_repository=checkout, harness_path=harness,
                    process_envelope=envelope,
                    observation_deadline_monotonic=deadline)
            self.assertEqual(outcome['status'], 'ORIGINAL_REPLAY_NOT_REPRODUCED')
            self.assertEqual(execute.call_count, 1)
            self.assertIs(execute.call_args.kwargs['process_envelope'], envelope)
            self.assertEqual(
                execute.call_args.kwargs['observation_deadline_monotonic'],
                deadline)

    def _real_official_uaf(self, root: Path):
        compiler = shutil.which('clang')
        if not compiler:
            self.skipTest('Clang with libFuzzer/ASan unavailable')
        fixture = OfficialV2Fixture(root / 'authority')
        fixture.upstream_source.write_text(OFFICIAL_FUZZ)
        source = fixture.upstream / 'target.c'
        source.write_text(OFFICIAL_TARGET)
        fixture.local.write_bytes(fixture.upstream_source.read_bytes())
        script = fixture.oss / 'projects/sample/build.sh'
        script.write_text('#!/bin/sh\nclang -g -O0 -fsanitize=fuzzer,address '
                          'tests/fuzz.c target.c -o fuzz\n')
        for folder in (fixture.oss, fixture.upstream):
            subprocess.run(['git', '-C', str(folder), 'add', '-A'], check=True)
            subprocess.run(['git', '-C', str(folder), '-c', 'user.name=Fixture',
                            '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'real-libfuzzer-build'], check=True)
        oss_revision = subprocess.check_output(
            ['git', '-C', str(fixture.oss), 'rev-parse', 'HEAD'], text=True).strip()
        upstream_revision = subprocess.check_output(
            ['git', '-C', str(fixture.upstream), 'rev-parse', 'HEAD'], text=True).strip()
        build_argv = [compiler, '-g', '-O0', '-fno-omit-frame-pointer',
                      '-fsanitize=fuzzer,address', str(fixture.upstream_source),
                      str(source), '-o', str(fixture.binary)]
        build = subprocess.run(build_argv, capture_output=True, text=True)
        if build.returncode:
            self.fail('real official fixture failed to compile: ' + build.stderr[:500])
        fixture.seed.write_bytes(b'Y')
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        inputs = [{'path': str(path), 'sha256': digest(path)}
                  for path in (fixture.upstream_source, source)]
        receipt = json.loads(fixture.receipt.read_text())
        receipt.update({'oss_fuzz_revision': oss_revision,
                        'upstream_revision': upstream_revision,
                        'target_revision': upstream_revision,
                        'build_script_sha256': digest(script),
                        'upstream_harness_sha256': digest(fixture.upstream_source),
                        'binary_sha256': digest(fixture.binary),
                        'compiled_sources': inputs,
                        'build_steps': [{'argv': build_argv, 'exit_code': 0,
                                         'inputs': inputs,
                                         'outputs': [{'path': str(fixture.binary),
                                                      'sha256': digest(fixture.binary)}]}]})
        review = json.loads(fixture.review.read_text())
        review.update({'harness_sha256': digest(fixture.upstream_source),
                       'oss_fuzz_revision': oss_revision,
                       'upstream_revision': upstream_revision,
                       'target_revision': upstream_revision,
                       'target_source_tree_sha256': hash_source_tree_v2(fixture.upstream),
                       'build_script_sha256': digest(script)})
        fixture.review.write_text(json.dumps(review))
        fixture.data['oss_fuzz']['revision'] = oss_revision
        fixture.data['oss_fuzz']['build_script']['sha256'] = digest(script)
        fixture.data['upstream_harness']['revision'] = upstream_revision
        fixture.data['upstream_harness']['sha256'] = digest(fixture.upstream_source)
        fixture.data['target']['revision'] = upstream_revision
        fixture.data['target']['source_tree_sha256'] = hash_source_tree_v2(fixture.upstream)
        fixture.data['local']['harness_sha256'] = digest(fixture.local)
        fixture.data['local']['binary_sha256'] = digest(fixture.binary)
        fixture.data['local']['normal_seed_sha256'] = digest(fixture.seed)
        fixture.replace_receipt(receipt)
        qualification = fixture.issue()
        self.assertIsNotNone(qualification, 'product must issue a real V2 token')
        return fixture, qualification

    def _prepare(self, root: Path, data: bytes = b'X'):
        run = root / 'run'
        corpus = run / 'corpus' / 'global'
        corpus.mkdir(parents=True)
        source_root = root / 'checkout'
        source_root.mkdir()
        source = source_root / 'target.c'
        source.write_text(SOURCE)
        harness = source_root / 'harness.c'
        harness.write_text('/* Nonblind deterministic development Harness. */\n')
        seed = corpus / 'crash-input'
        seed.write_bytes(data)
        seed_sha = hashlib.sha256(data).hexdigest()
        observation_id = 'fuzzer-input-one'
        artifact = run / 'runtime' / 'global_fuzz.json'
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{}')
        (run / 'scan.json').write_text('{}')
        _record_fuzzer_crash(run, observation_id, 'GLOBAL_FUZZER', artifact, None,
                             {'candidate_path': str(seed), 'sha256': seed_sha,
                              'size': len(data)})
        return run, source_root, source, harness, seed, seed_sha, observation_id

    def _compile(self, root: Path, source: Path) -> Path:
        compiler = shutil.which('gcc-13') or shutil.which('gcc')
        if not compiler:
            self.skipTest('GCC with static ASan runtime is unavailable')
        binary = root / 'asan-target'
        build = subprocess.run([compiler, '-g', '-O0', '-fno-omit-frame-pointer',
                                '-fsanitize=address', '-static-libasan',
                                str(source), '-o', str(binary)],
                               capture_output=True, text=True)
        if build.returncode != 0:
            self.skipTest('static ASan build unavailable: ' + build.stderr[:160])
        return binary

    def test_issued_official_token_must_match_replay_binary_harness_and_source_root(self):
        """An unrelated issued token must not bless a Global Fuzzer replay."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            authority = OfficialV2Fixture(root / 'authority')
            qualification = authority.issue()
            self.assertIsNotNone(qualification)
            run, checkout, source, harness, _, seed_sha, observation_id = self._prepare(
                root / 'case')
            other_binary = self._compile(root, source)
            for binary, used_harness, used_root in (
                (other_binary, authority.local, authority.upstream),
                (authority.binary, harness, authority.upstream),
                (authority.binary, authority.local, checkout),
            ):
                with self.subTest(binary=binary, harness=used_harness,
                                  source_root=used_root):
                    with self.assertRaisesRegex(ValueError, 'qualification'):
                        consume_fuzzer_crash_observation(
                            run, observation_id, seed_sha, binary=binary,
                            expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                            command=[str(binary), '{input}'], target_repository=used_root,
                            harness_path=used_harness,
                            official_qualification=qualification)
            self.assertFalse((run / 'runtime/fuzzer_validation').exists())

    def test_real_official_uaf_global_replay_needs_fresh_candidate_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture, qualification = self._real_official_uaf(root)
            run = root / 'run'
            corpus = run / 'corpus' / 'global'
            corpus.mkdir(parents=True)
            (run / 'run.json').write_text(json.dumps({'run_id': 'run-official-uaf'}))
            (run / 'scan.json').write_text('{}')
            seed = corpus / 'crash-uaf'
            seed.write_bytes(b'X')
            seed_sha = hashlib.sha256(seed.read_bytes()).hexdigest()
            observation_id = 'official-uaf-input'
            global_artifact = run / 'runtime' / 'global_fuzz.json'
            global_artifact.parent.mkdir(parents=True)
            global_artifact.write_text('{}')
            _record_fuzzer_crash(run, observation_id, 'GLOBAL_FUZZER',
                                 global_artifact, None,
                                 {'candidate_path': str(seed), 'sha256': seed_sha,
                                  'size': seed.stat().st_size})
            binary_sha = hashlib.sha256(fixture.binary.read_bytes()).hexdigest()
            report = {'binary_sha256': binary_sha,
                      'observed_crashes': [{'observed_crash_id': observation_id,
                                            'candidate_path': str(seed),
                                            'sha256': seed_sha, 'size': seed.stat().st_size}]}
            rows = consume_global_fuzzer_observations(
                run, report, target_binary=fixture.binary,
                run_command=[str(fixture.binary), '{input}'],
                target_repository=fixture.upstream, harness_path=fixture.local,
                replay_limit=1, official_qualification=qualification)
            self.assertEqual(len(rows), 1)
            outcome = rows[0]['consumer_result']
            self.assertEqual(outcome['status'], 'VERIFIED')
            canonical = json.loads(Path(outcome['canonical_crash_artifact']).read_text())
            self.assertEqual(canonical['independent_verification_status'], 'VERIFIED')
            self.assertEqual(canonical['original_sp_id'],
                             stable_id('fuzzer-lead', observation_id, seed_sha))
            self.assertFalse(canonical['observations'][0]['verified_for_original_sp'])
            candidate = json.loads(Path(canonical['independent_candidate_artifact']).read_text())
            self.assertEqual(candidate['candidate']['sp_id'], outcome['canonical_crash_id'])
            self.assertNotEqual(candidate['candidate']['sp_id'], canonical['original_sp_id'])
            security = json.loads(Path(canonical['independent_security_artifact']).read_text())
            self.assertEqual(security['status'], 'CONFIRMED')
            self.assertTrue(security['external_input_evidence'])
            self.assertTrue(security['harness_validity_evidence'])
            self.assertEqual(outcome['qualification_identity']['kind'], 'OFFICIAL_PINNED')
            self.assertEqual(outcome['qualification_identity']['contract_sha256'],
                             qualification.contract_sha256)

            # A qualification supplied after an unqualified Gate check cannot
            # rewrite that run's canonical runtime and independent receipts.
            late_run = root / 'late-run'
            late_corpus = late_run / 'corpus' / 'global'
            late_corpus.mkdir(parents=True)
            (late_run / 'run.json').write_text(json.dumps({'run_id': 'late-run'}))
            (late_run / 'scan.json').write_text('{}')
            late_seed = late_corpus / 'crash-uaf'
            late_seed.write_bytes(b'X')
            late_artifact = late_run / 'runtime' / 'global_fuzz.json'
            late_artifact.parent.mkdir(parents=True)
            late_artifact.write_text('{}')
            _record_fuzzer_crash(late_run, observation_id, 'GLOBAL_FUZZER',
                                 late_artifact, None,
                                 {'candidate_path': str(late_seed), 'sha256': seed_sha,
                                  'size': late_seed.stat().st_size})
            common = dict(binary=fixture.binary, expected_binary_sha256=binary_sha,
                          command=[str(fixture.binary), '{input}'],
                          target_repository=fixture.upstream, harness_path=fixture.local)
            unqualified = consume_fuzzer_crash_observation(
                late_run, observation_id, seed_sha, **common)
            self.assertEqual(unqualified['status'], 'GATE_CHECKED_NOT_VERIFIED')
            canonical_path = Path(unqualified['canonical_crash_artifact'])
            canonical_before = canonical_path.read_bytes()
            runtime_before = Path(unqualified['runtime_artifact']).read_bytes()
            record_path = late_run / 'runtime' / 'fuzzer_crashes' / f'{observation_id}.json'
            record_before = record_path.read_bytes()
            files_before = {str(path.relative_to(late_run)): hashlib.sha256(
                path.read_bytes()).hexdigest() for path in late_run.rglob('*') if path.is_file()}
            pending = consume_fuzzer_crash_observation(
                late_run, observation_id, seed_sha, official_qualification=qualification,
                **common)
            self.assertEqual(pending['status'], 'PENDING_NEW_QUALIFIED_RUN')
            self.assertTrue(pending['new_run_required'])
            self.assertEqual(pending['qualification_identity']['contract_sha256'],
                             qualification.contract_sha256)
            self.assertEqual(pending['prior_qualification_identity']['kind'], 'NONE')
            self.assertEqual(canonical_path.read_bytes(), canonical_before)
            self.assertEqual(Path(unqualified['runtime_artifact']).read_bytes(), runtime_before)
            self.assertEqual(record_path.read_bytes(), record_before)
            self.assertEqual({str(path.relative_to(late_run)): hashlib.sha256(
                path.read_bytes()).hexdigest() for path in late_run.rglob('*') if path.is_file()},
                             files_before)

            # The same retained bytes can be validated with the issued token
            # only in a separate run, which has fresh artifact identities.
            fresh_run = root / 'fresh-run'
            fresh_corpus = fresh_run / 'corpus' / 'global'
            fresh_corpus.mkdir(parents=True)
            (fresh_run / 'run.json').write_text(json.dumps({'run_id': 'fresh-run'}))
            (fresh_run / 'scan.json').write_text('{}')
            fresh_seed = fresh_corpus / 'crash-uaf'
            fresh_seed.write_bytes(b'X')
            fresh_artifact = fresh_run / 'runtime' / 'global_fuzz.json'
            fresh_artifact.parent.mkdir(parents=True)
            fresh_artifact.write_text('{}')
            _record_fuzzer_crash(fresh_run, observation_id, 'GLOBAL_FUZZER',
                                 fresh_artifact, None,
                                 {'candidate_path': str(fresh_seed), 'sha256': seed_sha,
                                  'size': fresh_seed.stat().st_size})
            qualified = consume_fuzzer_crash_observation(
                fresh_run, observation_id, seed_sha, official_qualification=qualification,
                **common)
            self.assertEqual(qualified['status'], 'VERIFIED')
            self.assertEqual(canonical_path.read_bytes(), canonical_before)

    def test_real_libfuzzer_retains_initial_crash_seed_and_global_gate_consumes_it(self):
        """Exercise execution/retention, not discovery by random mutation."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture, qualification = self._real_official_uaf(root)
            run = root / 'run'
            corpus = run / 'corpus' / 'global'
            corpus.mkdir(parents=True)
            (run / 'run.json').write_text(json.dumps({'run_id': 'run-global-initial-crash'}))
            (run / 'scan.json').write_text('{}')
            trigger = corpus / 'initial-trigger.bin'
            trigger.write_bytes(b'X')
            trigger_sha = hashlib.sha256(trigger.read_bytes()).hexdigest()
            self.assertFalse(list(corpus.glob('crash-*')))
            self.assertEqual(fixture.seed.read_bytes(), b'Y')

            command = [str(fixture.binary), '{input}']
            # libFuzzer must execute its sole initial unit.  The 5-second
            # mutation window is a physical bound, not a search success claim.
            report = run_global_fuzz(fixture.binary, run, RetryLedger(2),
                                     run_command=command, seconds=5, enabled=True)
            self.assertEqual(report['status'], 'CRASH_OBSERVED_INCOMPLETE')
            self.assertEqual(report['binary_sha256'],
                             hashlib.sha256(fixture.binary.read_bytes()).hexdigest())
            observed = [row for row in report['observed_crashes']
                        if row['sha256'] == trigger_sha]
            self.assertEqual(len(observed), 1, report)
            retained = Path(observed[0]['candidate_path'])
            self.assertEqual(retained.parent, corpus)
            self.assertTrue(retained.name.startswith('crash-'))
            self.assertEqual(retained.read_bytes(), b'X')
            self.assertEqual(observed[0]['size'], 1)

            self.assertEqual(record_global_fuzzer_observations(run, report),
                             {observed[0]['observed_crash_id']})
            rows = consume_global_fuzzer_observations(
                run, report, target_binary=fixture.binary, run_command=command,
                target_repository=fixture.upstream, harness_path=fixture.local,
                replay_limit=1, official_qualification=qualification,
                deadline_monotonic=time.monotonic() + 120)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['status'], 'VERIFIED', rows)
            outcome = rows[0]['consumer_result']
            canonical = json.loads(Path(outcome['canonical_crash_artifact']).read_text())
            self.assertEqual(canonical['independent_verification_status'], 'VERIFIED')
            self.assertEqual(canonical['original_sp_id'], stable_id(
                'fuzzer-lead', observed[0]['observed_crash_id'], trigger_sha))
            self.assertFalse(canonical['observations'][0]['verified_for_original_sp'])
            candidate = json.loads(Path(canonical['independent_candidate_artifact']).read_text())
            self.assertEqual(candidate['candidate']['sp_id'], outcome['canonical_crash_id'])
            security = json.loads(Path(canonical['independent_security_artifact']).read_text())
            self.assertEqual(security['status'], 'CONFIRMED')
            self.assertTrue(security['external_input_evidence'])
            self.assertTrue(security['harness_validity_evidence'])

    def test_nonblind_c_asan_crash_reaches_independent_gate_without_false_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, _, seed_sha, observation_id = self._prepare(root)
            binary = self._compile(root, source)
            binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            outcome = consume_fuzzer_crash_observation(
                run, observation_id, seed_sha, binary=binary,
                expected_binary_sha256=binary_sha,
                command=[str(binary), '{input}'], target_repository=checkout,
                harness_path=harness)
            self.assertEqual(outcome['status'], 'GATE_CHECKED_NOT_VERIFIED')
            self.assertEqual(outcome['gate_status'], 'BLOCKED_SECURITY_PROPERTY')
            self.assertTrue(outcome['gate_evaluated'])
            self.assertEqual(outcome['original_sp_relation'], 'UNVERIFIED')
            self.assertEqual(hashlib.sha256(Path(outcome['snapshot_path']).read_bytes()).hexdigest(),
                             seed_sha)
            canonical = json.loads(Path(outcome['canonical_crash_artifact']).read_text())
            self.assertEqual(canonical['independent_verification_status'],
                             'BLOCKED_SECURITY_PROPERTY')
            self.assertEqual(json.loads(Path(canonical['independent_root_cause_artifact'])
                                        .read_text())['verdict'], 'CONFIRMED')
            self.assertEqual(json.loads(Path(canonical['independent_replay_artifact'])
                                        .read_text())['status'], 'REPRODUCED')
            self.assertEqual(json.loads(Path(canonical['independent_security_artifact'])
                                        .read_text())['status'], 'UNKNOWN')
            index = json.loads((run / 'runtime/fuzzer_crashes' /
                                f'{observation_id}.json').read_text())
            self.assertEqual(index['consumer_results'][seed_sha], outcome)
            self.assertNotEqual(observation_id, outcome['canonical_crash_id'])
            summary = json.loads((run / 'scan.json').read_text())
            self.assertEqual(summary['fuzzer_observed_crash_ids'], [observation_id])
            self.assertEqual(summary['runtime_reproduced_crash_ids'],
                             [outcome['canonical_crash_id']])
            self.assertEqual(summary['verified_crash_ids'], [])
            self.assertEqual(consume_fuzzer_crash_observation(
                run, observation_id, seed_sha, binary=binary,
                expected_binary_sha256=binary_sha,
                command=[str(binary), '{input}'], target_repository=checkout,
                harness_path=harness), outcome)
            second = run / 'corpus/global/crash-input-two'
            second.write_bytes(b'XX')
            second_sha = hashlib.sha256(second.read_bytes()).hexdigest()
            _record_fuzzer_crash(run, 'fuzzer-input-two', 'GLOBAL_FUZZER',
                                 run / 'runtime/global_fuzz.json', None,
                                 {'candidate_path': str(second), 'sha256': second_sha,
                                  'size': second.stat().st_size})
            duplicate = consume_fuzzer_crash_observation(
                run, 'fuzzer-input-two', second_sha, binary=binary,
                expected_binary_sha256=binary_sha,
                command=[str(binary), '{input}'], target_repository=checkout,
                harness_path=harness)
            self.assertEqual(duplicate['canonical_crash_id'], outcome['canonical_crash_id'])
            self.assertEqual(duplicate['status'],
                             'DUPLICATE_CANONICAL_CRASH_INPUT_UNVALIDATED')
            index['consumer_results'][seed_sha]['status'] = 'VERIFIED'
            (run / 'runtime/fuzzer_crashes' / f'{observation_id}.json').write_text(
                json.dumps(index))
            with self.assertRaisesRegex(ValueError, 'attempt history changed'):
                consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256=binary_sha,
                    command=[str(binary), '{input}'], target_repository=checkout,
                    harness_path=harness)

    def test_nonblind_c_negative_control_never_reaches_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, _, seed_sha, observation_id = self._prepare(
                root, b'Y')
            binary = self._compile(root, source)
            outcome = consume_fuzzer_crash_observation(
                run, observation_id, seed_sha, binary=binary,
                expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                command=[str(binary), '{input}'], target_repository=checkout,
                harness_path=harness)
            self.assertEqual(outcome['status'], 'ORIGINAL_REPLAY_NOT_REPRODUCED')
            self.assertNotIn('canonical_crash_id', outcome)
            self.assertEqual(list((run / 'runtime/crashes').glob('*.json'))
                             if (run / 'runtime/crashes').exists() else [], [])

    def test_incomplete_replay_can_retry_once_without_overwriting_first_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, _, seed_sha, observation_id = self._prepare(
                root, b'Y')
            binary = self._compile(root, source)
            common = dict(binary=binary,
                          expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                          command=[str(binary), '{input}'], target_repository=checkout,
                          harness_path=harness)
            incomplete = RuntimeResult(None, '', '', None, True, None, None, 'TIMEOUT')
            with patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                       return_value=incomplete):
                first = consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, **common)
            self.assertEqual(first['status'], 'PENDING_ORIGINAL_REPLAY_INCOMPLETE')
            first_runtime = Path(first['runtime_artifact'])
            first_bytes = first_runtime.read_bytes()
            second = consume_fuzzer_crash_observation(
                run, observation_id, seed_sha, **common)
            self.assertEqual(second['status'], 'ORIGINAL_REPLAY_NOT_REPRODUCED')
            self.assertNotEqual(first['poc_id'], second['poc_id'])
            self.assertNotEqual(first['runtime_artifact'], second['runtime_artifact'])
            self.assertEqual(first_runtime.read_bytes(), first_bytes)
            self.assertEqual(first['attempt_number'], 1)
            self.assertEqual(second['attempt_number'], 2)
            record = json.loads((run / 'runtime/fuzzer_crashes' /
                                 f'{observation_id}.json').read_text())
            self.assertEqual(record['consumer_attempts'][seed_sha], [first, second])
            self.assertEqual(record['consumer_results'][seed_sha], second)
            self.assertEqual(consume_fuzzer_crash_observation(
                run, observation_id, seed_sha, **common), second)

    def test_preexisting_canonical_verified_status_is_not_inherited(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, seed, seed_sha, first_id = self._prepare(root)
            binary = self._compile(root, source)
            common = dict(binary=binary,
                          expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                          command=[str(binary), '{input}'], target_repository=checkout,
                          harness_path=harness)
            first = consume_fuzzer_crash_observation(run, first_id, seed_sha, **common)
            canonical_path = Path(first['canonical_crash_artifact'])
            new_id = 'fuzzer-input-two'
            _record_fuzzer_crash(run, new_id, 'GLOBAL_FUZZER',
                                 run / 'runtime/global_fuzz.json', None,
                                 {'candidate_path': str(seed), 'sha256': seed_sha,
                                  'size': seed.stat().st_size})
            new_poc_id = stable_id('poc', 'fuzzer-input', new_id, seed_sha)
            forged = json.loads(canonical_path.read_text())
            forged['observations'] = [{
                'runtime_artifact': str(run / 'runtime' / f'{new_poc_id}.json')}]
            forged['independent_verification_status'] = 'VERIFIED'
            canonical_path.write_text(json.dumps(forged))
            second = consume_fuzzer_crash_observation(run, new_id, seed_sha, **common)
            self.assertEqual(second['status'],
                             'DUPLICATE_CANONICAL_CRASH_INPUT_UNVALIDATED')
            self.assertNotEqual(second.get('gate_status'), 'VERIFIED')

    def test_two_incomplete_replays_do_not_get_an_unbounded_third_attempt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, _, harness, _, seed_sha, observation_id = self._prepare(root)
            binary = root / 'nonexecuted-binary'
            binary.write_bytes(b'pinned test binary')
            common = dict(binary=binary,
                          expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                          command=[str(binary), '{input}'], target_repository=checkout,
                          harness_path=harness)
            incomplete = RuntimeResult(None, '', '', None, True, None, None, 'TIMEOUT')
            with patch('vulnerabilityanalysis.scan.RuntimeExecutor.run',
                       return_value=incomplete) as runner:
                first = consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, **common)
                second = consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, **common)
                capped = consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, **common)
            self.assertEqual(runner.call_count, 2)
            self.assertEqual(first['status'], 'PENDING_ORIGINAL_REPLAY_INCOMPLETE')
            self.assertEqual(second['status'], 'PENDING_ORIGINAL_REPLAY_INCOMPLETE')
            self.assertEqual(capped['status'], 'PENDING_REPLAY_ATTEMPT_LIMIT')
            record = json.loads((run / 'runtime/fuzzer_crashes' /
                                 f'{observation_id}.json').read_text())
            self.assertEqual(record['consumer_attempts'][seed_sha], [first, second])

    def test_global_connection_reaches_gate_and_updates_three_tier_index(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, seed, seed_sha, observation_id = self._prepare(root)
            binary = self._compile(root, source)
            report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                      'observed_crashes': [{
                'observed_crash_id': observation_id, 'candidate_path': str(seed),
                'sha256': seed_sha, 'size': seed.stat().st_size}]}
            rows = consume_global_fuzzer_observations(
                run, report, target_binary=binary,
                run_command=[str(binary), '{input}'], target_repository=checkout,
                harness_path=harness, replay_limit=1)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['status'], 'GATE_CHECKED_NOT_VERIFIED')
            summary = json.loads((run / 'scan.json').read_text())
            self.assertEqual(summary['fuzzer_observed_crash_ids'], [observation_id])
            self.assertEqual(summary['runtime_reproduced_crash_ids'],
                             [rows[0]['consumer_result']['canonical_crash_id']])
            self.assertEqual(summary['verified_crash_ids'], [])
            self.assertEqual(json.loads((run / 'runtime/global_fuzzer_consumption.json')
                                        .read_text()), rows)

    def test_global_connection_preserves_budget_and_prior_targeted_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, seed, seed_sha, observation_id = self._prepare(root)
            binary = root / 'binary'
            binary.write_bytes(b'not executed')
            report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                      'observed_crashes': [{
                'observed_crash_id': observation_id, 'candidate_path': str(seed),
                'sha256': seed_sha, 'size': seed.stat().st_size}]}
            common = dict(target_binary=binary, run_command=[str(binary), '{input}'],
                          target_repository=checkout, harness_path=harness)
            no_budget = consume_global_fuzzer_observations(
                run, report, replay_limit=0, **common)
            self.assertEqual(no_budget[0]['status'], 'PENDING_RUNTIME_ATTEMPT_LIMIT')
            already_replayed = consume_global_fuzzer_observations(
                run, report, replay_limit=1,
                already_replayed_input_hashes={seed_sha}, **common)
            self.assertEqual(already_replayed[0]['status'],
                             'ALREADY_REPLAYED_BY_TARGETED_PATH')
            report['binary_sha256'] = '0' * 64
            mismatched_binary = consume_global_fuzzer_observations(
                run, report, replay_limit=1,
                already_replayed_input_hashes={seed_sha}, **common)
            self.assertEqual(mismatched_binary[0]['status'],
                             'PENDING_FUZZER_BINARY_IDENTITY')
            report['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
            process_command = [str(binary), '--wrapper', '{input}']
            unsupported = consume_global_fuzzer_observations(
                run, report, replay_limit=1,
                target_binary=binary, run_command=process_command,
                target_repository=checkout, harness_path=harness)
            self.assertEqual(unsupported[0]['status'],
                             'PENDING_UNSUPPORTED_OR_UNPINNED_REPLAY_COMMAND')
            self.assertFalse((run / 'runtime/fuzzer_validation').exists())

    def test_retained_input_and_binary_hashes_are_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, seed, seed_sha, observation_id = self._prepare(root)
            binary = root / 'binary'
            binary.write_bytes(b'not executed')
            binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            seed.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'input is changed'):
                consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256=binary_sha,
                    command=[str(binary), '{input}'], target_repository=checkout,
                    harness_path=harness)
            seed.write_bytes(b'X')
            with self.assertRaisesRegex(ValueError, 'binary changed'):
                consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256='0' * 64,
                    command=[str(binary), '{input}'], target_repository=checkout,
                    harness_path=harness)

    def test_symlinked_crash_input_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run, checkout, source, harness, seed, seed_sha, observation_id = self._prepare(root)
            outside = root / 'outside'
            outside.write_bytes(b'X')
            seed.unlink()
            seed.symlink_to(outside)
            binary = root / 'binary'
            binary.write_bytes(b'not executed')
            with self.assertRaisesRegex(ValueError, 'input is changed'):
                consume_fuzzer_crash_observation(
                    run, observation_id, seed_sha, binary=binary,
                    expected_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                    command=[str(binary), '{input}'], target_repository=checkout,
                    harness_path=harness)


if __name__ == '__main__':
    unittest.main()
