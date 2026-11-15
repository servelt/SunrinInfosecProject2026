"""Provider-free baseline admission and provenance checks."""

from __future__ import annotations

import json
import hashlib
import struct
import subprocess
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import dev_global_campaign as global_dev
import dev_harness_normal_global_baseline as baseline_dev
from dev_harness_normal_global_baseline import prepare_baseline, run_baseline
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from test_dev_global_campaign import product_v2_tests


class HarnessNormalGlobalBaselineTests(unittest.TestCase):
    def test_committed_spec_examples_stage_without_direction_or_poc(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = replace(fixture.issue(),
                        upstream_harness_path='test/fuzzers/fuzz-mdhtml.c')
            spec = fixture.upstream / 'test/spec.txt'
            spec.parent.mkdir(parents=True)
            fence = '`' * 32
            spec.write_text(''.join(
                f'{fence} example\nexample {index}\n.\n<p>ok</p>\n{fence}\n'
                for index in range(255)), encoding='utf-8')
            header = fixture.upstream / 'src/md4c.h'
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text(''.join(
                f'#define MD_FLAG_TEST_{index:02d} 0x{1 << index:x}\n'
                for index in range(23)) +
                '#define MD_FLAG_TEST_ALIAS '
                '(MD_FLAG_TEST_00 | MD_FLAG_TEST_01)\n'
                '#define MD_DIALECT_GITHUB (MD_FLAG_TEST_ALIAS)\n')
            subprocess.run(['git', '-C', str(fixture.upstream), 'add',
                            'test/spec.txt', 'src/md4c.h'], check=True)
            subprocess.run(['git', '-C', str(fixture.upstream),
                            '-c', 'user.name=Test', '-c',
                            'user.email=test@example.com', 'commit', '-qm',
                            'add spec examples'], check=True)
            campaign = global_dev.DevGlobalCampaign(
                root / 'spec-campaign', q, total_fuzz_seconds=14,
                global_seconds=1, global_wall_reservation_seconds=14,
                replay_limit=0)
            with patch.object(campaign, '_authority_ok', return_value=True):
                campaign.stage_md4c_spec_examples()
            self.assertEqual(len(campaign.seeds), 256)
            self.assertEqual(campaign.seed_provenance,
                             'UPSTREAM_PINNED_SPEC_EXAMPLES')
            self.assertEqual(campaign.seeds[0]['source_kind'],
                             'HARNESS_NORMAL_SEED')
            self.assertEqual(campaign.seeds[1]['source_kind'],
                             'UPSTREAM_PINNED_SPEC_EXAMPLES')
            self.assertEqual(Path(campaign.seeds[1]['stored']).read_bytes(),
                             b'\x00' * 8 + b'example 0\n')
            self.assertEqual(json.loads(campaign.plan_path.read_text())
                             ['direction_plan_used'], False)
            with patch.object(baseline_dev, '_qualification_pins_ok',
                              return_value=True), patch.object(
                                  global_dev.DevGlobalCampaign, '_authority_ok',
                                  return_value=True), patch.object(
                                      global_dev, '_launch_guarded') as launch:
                combined = prepare_baseline(
                    root / 'spec-composites', q, global_seconds=1,
                    global_wall_reservation_seconds=14,
                    wall_total_seconds=700, fuzz_total_seconds=14,
                    replay_limit=1, process_output_limit_bytes=4096,
                    run_id='spec-composites-one',
                    md4c_spec_composites=True)
            launch.assert_not_called()
            self.assertEqual(len(combined.seeds), 495)
            self.assertEqual(
                sum(row['source_kind'] == 'UPSTREAM_PINNED_SPEC_COMPOSITES'
                    for row in combined.seeds), 239)
            self.assertEqual(
                json.loads(combined.plan_path.read_text())['kind'],
                'UPSTREAM_PINNED_SPEC_COMPOSITES_PLAN_V1')
            self.assertEqual(
                json.loads((combined.output / 'BASELINE_IDENTITY.json')
                           .read_text())['discovery_claim'], 'EXPLORATION_ONLY')
            self.assertEqual(combined.seeds[0]['source_kind'],
                             'HARNESS_NORMAL_SEED')
            with patch.object(baseline_dev, '_qualification_pins_ok',
                              return_value=True), patch.object(
                                  global_dev.DevGlobalCampaign, '_authority_ok',
                                  return_value=True), patch.object(
                                      global_dev, '_launch_guarded') as launch:
                flagged = prepare_baseline(
                    root / 'spec-flags', q, global_seconds=1,
                    global_wall_reservation_seconds=14,
                    wall_total_seconds=700, fuzz_total_seconds=14,
                    replay_limit=1, process_output_limit_bytes=4096,
                    run_id='spec-flags-one', md4c_spec_flags=True)
            launch.assert_not_called()
            self.assertEqual(len(flagged.seeds), 766)
            profile_rows = [row for row in flagged.seeds if row['source_kind'] ==
                            'UPSTREAM_PINNED_SPEC_FLAG_PROFILE']
            self.assertEqual(len(profile_rows), 510)
            self.assertEqual(len({row['parser_flag_profile'] for row in profile_rows}),
                             24)
            self.assertEqual(sum(row['parser_flag_profile'] ==
                                 'MD_DIALECT_GITHUB' for row in profile_rows), 255)
            self.assertEqual(
                {struct.unpack('=II', Path(row['stored']).read_bytes()[:8])
                 for row in profile_rows if row['parser_flag_profile'] ==
                 'MD_DIALECT_GITHUB'}, {(3, 0)})
            self.assertEqual(
                json.loads(flagged.plan_path.read_text())['header_sha256'],
                hashlib.sha256(header.read_bytes()).hexdigest())
            self.assertEqual(
                json.loads((flagged.output / 'BASELINE_IDENTITY.json').read_text())
                ['discovery_claim'], 'EXPLORATION_ONLY')
            original_header = header.read_bytes()
            header.write_bytes(original_header + b'// uncommitted\n')
            changed_header = global_dev.DevGlobalCampaign(
                root / 'changed-header', q, total_fuzz_seconds=14,
                global_seconds=1, global_wall_reservation_seconds=14,
                replay_limit=0)
            with patch.object(changed_header, '_authority_ok', return_value=True):
                with self.assertRaisesRegex(ValueError, 'header differs from pinned'):
                    changed_header.stage_md4c_spec_examples(flag_profiles=True)
            self.assertFalse(changed_header.run_dir.exists())
            header.write_bytes(original_header)
            spec.write_text(spec.read_text() + 'uncommitted change\n')
            changed = global_dev.DevGlobalCampaign(
                root / 'changed-spec', q, total_fuzz_seconds=14,
                global_seconds=1, global_wall_reservation_seconds=14,
                replay_limit=0)
            with patch.object(changed, '_authority_ok', return_value=True):
                with self.assertRaisesRegex(ValueError, 'differs from pinned'):
                    changed.stage_md4c_spec_examples()
            self.assertFalse(changed.run_dir.exists())

    def test_upstream_committed_corpus_preserves_non_model_provenance(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            source = fixture.upstream / 'tests/seed-corpus'
            source.mkdir(parents=True)
            (source / 'normal').write_bytes(fixture.seed.read_bytes())
            (source / 'other').write_bytes(b'other normal syntax')
            subprocess.run(['git', '-C', str(fixture.upstream), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(fixture.upstream), '-c', 'user.name=Test',
                            '-c', 'user.email=test@example.com', 'commit', '-qm',
                            'add upstream seeds'], check=True)
            campaign = global_dev.DevGlobalCampaign(
                root / 'upstream', q, total_fuzz_seconds=14,
                global_seconds=1, global_wall_reservation_seconds=14,
                replay_limit=0)
            # The fixture qualification predates this fixture-only commit;
            # this test isolates seed identity while real admission rechecks q.
            with patch.object(campaign, '_authority_ok', return_value=True):
                campaign.stage_upstream_seed_corpus(Path('tests/seed-corpus'))
            self.assertEqual(campaign.seed_provenance,
                             'UPSTREAM_PINNED_SEED_CORPUS')
            self.assertEqual(len(campaign.seeds), 2)
            self.assertEqual({row['stored_sha256'] for row in campaign.seeds},
                             {q.normal_seed_sha256,
                              hashlib.sha256(b'other normal syntax').hexdigest()})
            self.assertEqual(json.loads(campaign.plan_path.read_text())
                             ['direction_plan_used'], False)
            with patch.object(baseline_dev, '_qualification_pins_ok',
                              return_value=True), patch.object(
                                  global_dev.DevGlobalCampaign, '_authority_ok',
                                  return_value=True):
                prepared = prepare_baseline(
                    root / 'upstream-baseline', q, global_seconds=1,
                    global_wall_reservation_seconds=14,
                    wall_total_seconds=700, fuzz_total_seconds=14,
                    replay_limit=1, process_output_limit_bytes=4096,
                    run_id='upstream-one',
                    upstream_seed_corpus=Path('tests/seed-corpus'))
            self.assertEqual(prepared.process_envelope.work_item_id,
                             'UPSTREAM_PINNED_SEED_CORPUS')
            self.assertEqual(prepared.reservation_key,
                             'GLOBAL_FUZZ:UPSTREAM_PINNED_SEED_CORPUS:upstream-one')
            identity = json.loads((prepared.output / 'BASELINE_IDENTITY.json').read_text())
            self.assertEqual(identity['discovery_claim'], 'EXPLORATION_ONLY')
            self.assertEqual(identity['work_item_id'], 'UPSTREAM_PINNED_SEED_CORPUS')

    def test_upstream_corpus_rejects_untracked_input(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            source = fixture.upstream / 'tests/seed-corpus'
            source.mkdir(parents=True)
            (source / 'normal').write_bytes(fixture.seed.read_bytes())
            subprocess.run(['git', '-C', str(fixture.upstream), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(fixture.upstream), '-c', 'user.name=Test',
                            '-c', 'user.email=test@example.com', 'commit', '-qm',
                            'add upstream seed'], check=True)
            (source / 'injected').write_bytes(b'not committed')
            campaign = global_dev.DevGlobalCampaign(
                root / 'upstream', q, total_fuzz_seconds=14,
                global_seconds=1, global_wall_reservation_seconds=14,
                replay_limit=0)
            with patch.object(campaign, '_authority_ok', return_value=True):
                with self.assertRaisesRegex(ValueError, 'untrusted input'):
                    campaign.stage_upstream_seed_corpus(Path('tests/seed-corpus'))
            self.assertFalse(campaign.run_dir.exists())

    def _settled_prior(self, root: Path, q, seed: bytes) -> Path:
        prior = root / 'prior'
        corpus = prior / 'global_campaign/corpus/global'
        corpus.mkdir(parents=True)
        prior.chmod(0o700)
        mutation = seed + b'\nmutation'
        mutation_sha = hashlib.sha256(mutation).hexdigest()
        (corpus / 'normal').write_bytes(seed)
        (corpus / 'mutation').write_bytes(mutation)
        ledger = PersistentProcessLedgerV2.create(
            prior / 'process-ledger.json', wall_total_seconds=700,
            fuzz_total_seconds=14)
        global_dev.write_json(prior / 'BASELINE_IDENTITY.json', {
            'kind': 'HARNESS_NORMAL_SEED_GLOBAL_BASELINE_V1',
            'seed_provenance': 'HARNESS_NORMAL_SEED',
            'model_calls': 0, 'direction_plan_used': False,
            'discovery_claim': 'BASELINE_ONLY',
            'qualification_contract_sha256': q.contract_sha256,
            'binary_sha256': q.binary_sha256,
            'harness_sha256': q.harness_sha256,
            'normal_seed_sha256': q.normal_seed_sha256})
        global_dev.write_json(prior / 'BASELINE_RESULT.json', {
            'status': 'RAN', 'cleanup_complete': True,
            'observed_crash_count': 0,
            'seed_provenance': 'HARNESS_NORMAL_SEED',
            'model_calls': 0, 'direction_plan_used': False,
            'durable_process_ledger_sha256': global_dev.digest(ledger.path)})
        global_dev.write_json(prior / 'global_campaign/runtime/global_fuzz.json', {
            'status': 'RAN', 'binary_sha256': q.binary_sha256,
            'seed_count': 1, 'observed_crashes': [],
            'new_seed_count': 1, 'new_seed_hashes': [mutation_sha]})
        return prior

    def test_continuation_stages_only_reported_fuzzer_corpus(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            prior = self._settled_prior(root, q, fixture.seed.read_bytes())
            with patch.object(global_dev, '_launch_guarded') as launch:
                campaign = prepare_baseline(
                    root / 'continuation', q, global_seconds=1,
                    global_wall_reservation_seconds=14,
                    wall_total_seconds=700, fuzz_total_seconds=14,
                    replay_limit=1, process_output_limit_bytes=4096,
                    run_id='continuation-one', prior_baseline=prior)
            launch.assert_not_called()
            self.assertEqual(campaign.seed_provenance,
                             'HARNESS_NORMAL_SEED_FUZZ_CONTINUATION')
            self.assertEqual(campaign.process_envelope.work_item_id,
                             'HARNESS_NORMAL_SEED_FUZZ_CONTINUATION')
            self.assertEqual(len(campaign.seeds), 2)
            self.assertEqual({row['stored_sha256'] for row in campaign.seeds},
                             {q.normal_seed_sha256,
                              hashlib.sha256(fixture.seed.read_bytes() +
                                             b'\nmutation').hexdigest()})
            identity = json.loads((campaign.output / 'BASELINE_IDENTITY.json').read_text())
            self.assertEqual(identity['discovery_claim'], 'EXPLORATION_ONLY')
            plan = json.loads(campaign.plan_path.read_text())
            self.assertEqual(plan['prior_process_ledger_sha256'],
                             global_dev.digest(prior / 'process-ledger.json'))
            self.assertEqual(plan['model_calls'], 0)

    def test_continuation_refuses_unreported_input_and_unsettled_ledger(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            prior = self._settled_prior(root, q, fixture.seed.read_bytes())
            corpus = prior / 'global_campaign/corpus/global'
            (corpus / 'injected-poc').write_bytes(b'forged')
            args = dict(global_seconds=1, global_wall_reservation_seconds=14,
                        wall_total_seconds=700, fuzz_total_seconds=14,
                        replay_limit=1, process_output_limit_bytes=4096,
                        run_id='continuation-one', prior_baseline=prior)
            with patch.object(global_dev, '_launch_guarded') as launch:
                with self.assertRaisesRegex(ValueError, 'does not match'):
                    prepare_baseline(root / 'rejected-input', q, **args)
            launch.assert_not_called()
            (corpus / 'injected-poc').unlink()
            ledger_path = prior / 'process-ledger.json'
            ledger_data = json.loads(ledger_path.read_text())
            ledger_data['stop_status'] = 'STOPPED_UNCERTAIN_PROCESS'
            global_dev.write_json(ledger_path, ledger_data)
            with patch.object(global_dev, '_launch_guarded') as launch:
                with self.assertRaisesRegex(ValueError, 'settled model-free source'):
                    prepare_baseline(root / 'rejected-ledger', q, **args)
            launch.assert_not_called()

    def test_pinned_spec_continuation_preserves_seed_origins_and_rejects_injection(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = replace(fixture.issue(),
                        upstream_harness_path='test/fuzzers/fuzz-mdhtml.c')
            spec = fixture.upstream / 'test/spec.txt'
            spec.parent.mkdir(parents=True)
            spec.write_text('public syntax examples\n', encoding='utf-8')
            subprocess.run(['git', '-C', str(fixture.upstream), 'add',
                            'test/spec.txt'], check=True)
            subprocess.run(['git', '-C', str(fixture.upstream), '-c',
                            'user.name=Test', '-c', 'user.email=test@example.com',
                            'commit', '-qm', 'add spec'], check=True)
            prior = root / 'prior-spec'
            corpus = prior / 'global_campaign/corpus/global'
            corpus.mkdir(parents=True)
            prior.chmod(0o700)
            normal = fixture.seed.read_bytes()
            rows = []
            for number in range(256):
                content = (normal if number == 0 else
                           b'\x00' * 8 + f'example {number}\n'.encode())
                path = corpus / f'spec_{number:04d}'
                path.write_bytes(content)
                rows.append({'source_kind': ('HARNESS_NORMAL_SEED' if number == 0
                                             else 'UPSTREAM_PINNED_SPEC_EXAMPLES'),
                             'example_number': number,
                             'source': str(fixture.seed if number == 0 else spec),
                             'source_sha256': (q.normal_seed_sha256 if number == 0
                                               else hashlib.sha256(
                                                   spec.read_bytes()).hexdigest()),
                             'stored': str(path),
                             'stored_sha256': hashlib.sha256(content).hexdigest()})
            mutation = b'\x00' * 8 + b'fuzzer mutation\n'
            mutation_sha = hashlib.sha256(mutation).hexdigest()
            (corpus / 'mutation').write_bytes(mutation)
            ledger = PersistentProcessLedgerV2.create(
                prior / 'process-ledger.json', wall_total_seconds=700,
                fuzz_total_seconds=14)
            global_dev.write_json(prior / 'BASELINE_IDENTITY.json', {
                'kind': 'UPSTREAM_PINNED_SPEC_EXAMPLES_BASELINE_V1',
                'seed_provenance': 'UPSTREAM_PINNED_SPEC_EXAMPLES',
                'model_calls': 0, 'direction_plan_used': False,
                'discovery_claim': 'EXPLORATION_ONLY',
                'qualification_contract_sha256': q.contract_sha256,
                'binary_sha256': q.binary_sha256,
                'harness_sha256': q.harness_sha256,
                'normal_seed_sha256': q.normal_seed_sha256})
            global_dev.write_json(prior / 'BASELINE_RESULT.json', {
                'status': 'RAN', 'cleanup_complete': True,
                'observed_crash_count': 0,
                'seed_provenance': 'UPSTREAM_PINNED_SPEC_EXAMPLES',
                'model_calls': 0, 'direction_plan_used': False,
                'durable_process_ledger_sha256': global_dev.digest(ledger.path)})
            global_dev.write_json(prior / 'global_campaign/runtime/global_fuzz.json', {
                'status': 'RAN', 'binary_sha256': q.binary_sha256,
                'seed_count': 256, 'observed_crashes': [],
                'new_seed_count': 1, 'new_seed_hashes': [mutation_sha]})
            global_dev.write_json(
                prior / 'global_campaign/UPSTREAM_SPEC_EXAMPLES_PLAN.json', {
                    'kind': 'UPSTREAM_PINNED_SPEC_EXAMPLES_PLAN_V1',
                    'seed_provenance': 'UPSTREAM_PINNED_SPEC_EXAMPLES',
                    'seed_count': 256, 'seeds': rows,
                    'qualification_contract_sha256': q.contract_sha256,
                    'binary_sha256': q.binary_sha256,
                    'harness_sha256': q.harness_sha256,
                    'upstream_revision': q.upstream_revision,
                    'spec_sha256': hashlib.sha256(spec.read_bytes()).hexdigest(),
                    'model_calls': 0, 'direction_plan_used': False})
            manifest = root / 'pinned-manifest.json'
            global_dev.write_json(manifest, {
                'kind': 'MD4C_SPEC_EXAMPLES_EXPLORATION_MANIFEST_V1',
                'files': [
                    {'path': path.relative_to(prior).as_posix(),
                     'size': path.stat().st_size,
                     'sha256': global_dev.digest(path)}
                    for path in sorted(prior.rglob('*')) if path.is_file()]})
            manifest_sha = global_dev.digest(manifest)
            kwargs = dict(global_seconds=1,
                          global_wall_reservation_seconds=14,
                          wall_total_seconds=700, fuzz_total_seconds=14,
                          replay_limit=1, process_output_limit_bytes=4096,
                          run_id='spec-continue', prior_baseline=prior,
                          prior_spec_manifest=manifest,
                          prior_spec_manifest_sha256=manifest_sha)
            with patch.object(baseline_dev, '_qualification_pins_ok',
                              return_value=True), patch.object(
                                  global_dev.DevGlobalCampaign, '_authority_ok',
                                  return_value=True), patch.object(
                                      global_dev, '_launch_guarded') as launch:
                campaign = prepare_baseline(root / 'spec-continue', q, **kwargs)
            launch.assert_not_called()
            self.assertEqual(campaign.seed_provenance,
                             'UPSTREAM_PINNED_SPEC_FUZZ_CONTINUATION')
            self.assertEqual(len(campaign.seeds), 257)
            self.assertEqual(
                {kind: sum(row['source_kind'] == kind for row in campaign.seeds)
                 for kind in ('HARNESS_NORMAL_SEED',
                              'UPSTREAM_PINNED_SPEC_EXAMPLES',
                              'FUZZER_MUTATION_FROM_SPEC_CORPUS')},
                {'HARNESS_NORMAL_SEED': 1,
                 'UPSTREAM_PINNED_SPEC_EXAMPLES': 255,
                 'FUZZER_MUTATION_FROM_SPEC_CORPUS': 1})
            (corpus / 'manual-poc').write_bytes(b'forged')
            with patch.object(baseline_dev, '_qualification_pins_ok',
                              return_value=True), patch.object(
                                  global_dev.DevGlobalCampaign, '_authority_ok',
                                  return_value=True):
                with self.assertRaisesRegex(ValueError,
                                            'differs from pinned manifest'):
                    prepare_baseline(root / 'injected', q, **kwargs)

    def _prepare(self, root: Path):
        fixture = product_v2_tests.Fixture(root / 'authority')
        qualification = fixture.issue()
        self.assertIsNotNone(qualification)
        campaign = prepare_baseline(
            root / 'baseline', qualification, global_seconds=1,
            global_wall_reservation_seconds=14,
            wall_total_seconds=700, fuzz_total_seconds=14,
            replay_limit=1, process_output_limit_bytes=4096,
            run_id='normal-seed-one')
        return fixture, campaign

    def test_preparation_uses_pinned_normal_seed_without_model_or_target(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(global_dev, '_launch_guarded') as launch, patch.object(
                    global_dev, 'run_global_fuzz') as fuzz:
                fixture, campaign = self._prepare(root)
            launch.assert_not_called()
            fuzz.assert_not_called()
            self.assertIs(type(campaign.ledger), PersistentProcessLedgerV2)
            self.assertIs(type(campaign.process_envelope),
                          DevelopmentProcessEnvelopeV2)
            self.assertIs(campaign.process_envelope.ledger, campaign.ledger)
            self.assertTrue(campaign.require_accounted_consumer)
            self.assertEqual(campaign.seed_provenance, 'HARNESS_NORMAL_SEED')
            self.assertEqual(campaign.process_envelope.work_item_id,
                             'HARNESS_NORMAL_SEED')
            self.assertEqual(len(campaign.seeds), 1)
            seed = campaign.seeds[0]
            self.assertEqual(seed['source_kind'], 'HARNESS_NORMAL_SEED')
            self.assertNotIn('direction_id', seed)
            self.assertEqual(Path(seed['stored']).read_bytes(), fixture.seed.read_bytes())
            self.assertEqual(campaign.plan_path.name,
                             'HARNESS_NORMAL_SEED_PLAN.json')
            plan = json.loads(campaign.plan_path.read_text())
            self.assertFalse(plan['direction_plan_used'])
            self.assertEqual(plan['model_calls'], 0)
            identity = json.loads((campaign.output / 'BASELINE_IDENTITY.json').read_text())
            self.assertEqual(identity['discovery_claim'], 'BASELINE_ONLY')
            self.assertEqual(identity['normal_seed_sha256'],
                             campaign.q.normal_seed_sha256)
            self.assertEqual(campaign.ledger.snapshot()['active'], {})

    def test_pinned_seed_drift_and_output_reuse_refuse_before_target(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            self.assertIsNotNone(q)
            fixture.seed.write_bytes(b'changed')
            with patch.object(global_dev, '_launch_guarded') as launch:
                with self.assertRaises(ValueError):
                    prepare_baseline(
                        root / 'baseline', q, global_seconds=1,
                        global_wall_reservation_seconds=14,
                        wall_total_seconds=30, fuzz_total_seconds=14,
                        replay_limit=1, process_output_limit_bytes=4096,
                        run_id='normal-seed-one')
            launch.assert_not_called()
            self.assertFalse((root / 'baseline').exists())

    def test_baseline_cannot_claim_model_direction_or_double_stage(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _fixture, campaign = self._prepare(root)
            with self.assertRaises(ValueError):
                campaign.stage_harness_normal_seed()
            self.assertEqual(campaign.seed_provenance, 'HARNESS_NORMAL_SEED')
            self.assertFalse((campaign.run_dir / 'DIRECTION_SEEDS.json').exists())
            with self.assertRaises(ValueError):
                prepare_baseline(
                    root / 'baseline', campaign.q, global_seconds=1,
                    global_wall_reservation_seconds=14,
                    wall_total_seconds=30, fuzz_total_seconds=14,
                    replay_limit=1, process_output_limit_bytes=4096,
                    run_id='normal-seed-two')

    def test_global_reservation_needs_aux_headroom(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            with self.assertRaisesRegex(ValueError, 'headroom'):
                prepare_baseline(
                    root / 'baseline', q, global_seconds=1,
                    global_wall_reservation_seconds=14,
                    wall_total_seconds=14, fuzz_total_seconds=14,
                    replay_limit=1, process_output_limit_bytes=4096,
                    run_id='normal-seed-one')
            self.assertFalse((root / 'baseline').exists())

    def test_global_charge_is_durable_before_any_target_launch(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _fixture, campaign = self._prepare(root)
            observed = []

            def fake_start():
                observed.append(campaign.ledger.snapshot()['active'])
                return 'ACTIVE'

            with patch.object(campaign.campaign, 'start', side_effect=fake_start), patch.object(
                    global_dev, '_launch_guarded') as launch:
                self.assertEqual(campaign.start(), 'ACTIVE')
            launch.assert_not_called()
            self.assertEqual(len(observed), 1)
            row = observed[0][campaign.reservation_key]
            self.assertEqual(row['kind'], 'GLOBAL_FUZZ')
            self.assertEqual(row['reserved_seconds'], 14)
            self.assertEqual(campaign.ledger.snapshot()['active'], observed[0])
            with self.assertRaisesRegex(RuntimeError, 'cannot be retried'):
                campaign.start()

    def test_unbounded_development_caps_reject_before_target(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = product_v2_tests.Fixture(root / 'authority')
            q = fixture.issue()
            base = dict(global_seconds=1, global_wall_reservation_seconds=14,
                        wall_total_seconds=700, fuzz_total_seconds=14,
                        replay_limit=1, process_output_limit_bytes=4096,
                        run_id='normal-seed-one')
            bad = [
                {'global_seconds': 61, 'global_wall_reservation_seconds': 74},
                {'global_wall_reservation_seconds': 121,
                 'fuzz_total_seconds': 121},
                {'wall_total_seconds': 3601},
                {'fuzz_total_seconds': 121},
                {'replay_limit': 3},
                {'process_output_limit_bytes': 16_777_217},
                {'wall_total_seconds': float('inf')},
                {'fuzz_total_seconds': float('nan')},
                {'wall_total_seconds': 613},
            ]
            with patch.object(global_dev, '_launch_guarded') as launch:
                for index, override in enumerate(bad):
                    with self.subTest(override=override):
                        with self.assertRaises(ValueError):
                            prepare_baseline(root / f'bad-{index}', q,
                                             **{**base, **override})
                        self.assertFalse((root / f'bad-{index}').exists())
            launch.assert_not_called()

    def test_failed_start_keeps_original_error_and_uncertain_receipt(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _fixture, campaign = self._prepare(root)

            def fail_after_predebit():
                campaign.ledger.reserve(campaign.reservation_key,
                                        'GLOBAL_FUZZ', 14)
                raise RuntimeError('original launch failure')

            with patch.object(campaign, 'start', side_effect=fail_after_predebit), patch.object(
                    global_dev, '_launch_guarded') as launch:
                with self.assertRaisesRegex(RuntimeError, 'original launch failure'):
                    run_baseline(campaign)
            launch.assert_not_called()
            snapshot = campaign.ledger.snapshot()
            self.assertEqual(snapshot['stop_status'], 'STOPPED_UNCERTAIN_PROCESS')
            self.assertIn(campaign.reservation_key, snapshot['active'])
            self.assertFalse((campaign.output / 'BASELINE_RESULT.json').exists())
            incomplete = json.loads(
                (campaign.output / 'BASELINE_INCOMPLETE.json').read_text())
            self.assertEqual(incomplete['error_type'], 'RuntimeError')
            self.assertTrue(incomplete['global_reservation_active'])


if __name__ == '__main__':
    unittest.main()
