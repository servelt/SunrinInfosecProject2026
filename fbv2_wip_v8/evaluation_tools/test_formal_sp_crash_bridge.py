"""Provider-free checks for the formal SP followup crash handoff."""

import asyncio
from contextlib import contextmanager
import copy
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

import blind2_runner_draft as runner

sys.path.insert(0, str(runner.PRODUCT / 'tests'))
import test_fuzzer_crash_consumer as product_consumer_test
from vulnerabilityanalysis.scan import _record_fuzzer_crash
from vulnerabilityanalysis.runtime import RuntimeCleanupError, RuntimeExecutor


class FormalSpCrashBridgeTests(TestCase):
    def test_two_functions_preserve_no_opportunity_after_consumer_wall_exhaustion(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / 'run-one'
            second = root / 'run-two'
            for run, function_id in ((first, 'fn-one'), (second, 'fn-two')):
                run.mkdir()
                (run / 'selection.json').write_text(json.dumps({
                    'function_id': function_id}))
            ledger = runner.Ledger(started_at=time.time())
            class Provider:
                def __init__(self):
                    self.ledger = ledger
                def begin_function(self, _function_id):
                    pass
                def end_function(self):
                    pass
            class Meter:
                def __init__(self, *_a, **_k):
                    self.records = []
                    self.zero_budget_assertion_runs = set()
                @contextmanager
                def patch_guided(self):
                    yield
            async def scan(folder, *_a, **_k):
                function_id = json.loads((folder / 'selection.json').read_text())[
                    'function_id']
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': function_id, 'sp_llm_calls': 0,
                    'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 4,
                    'combined_llm_call_limit': 8}))
            status_by_run = {}
            def checkpoint(run, status, _ledger):
                status_by_run[run.name] = status
                return run / 'FUNCTION_CHECKPOINT.json'
            with patch.object(runner, 'SharedFuzzMeter', Meter), \
                 patch.object(runner.scan_mod, 'scan_selected', scan), \
                 patch.object(runner, 'run_failed_pov_followups', return_value=[]), \
                 patch.object(runner, 'consume_reproduced_sp_followups',
                              side_effect=[
                                  [{'status': 'PENDING_ROOT_CAUSE',
                                    'budget_status': 'CONSUMER_WALL_OVERRUN'}],
                                  [{'status': 'PENDING_CONSUMER_WALL_LIMIT'}]]), \
                 patch.object(runner, 'continue_phase1', return_value=second), \
                 patch.object(runner, 'checkpoint_run', checkpoint), \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                rows = asyncio.run(runner.run_sequence(
                    first, Provider(), ledger, root,
                    root / 'BUDGET_CHECKPOINT.json', max_functions=2,
                    scan_options={'run_command': ['/toy/asan', '{input}'],
                                  'target_binary': Path('/toy/asan'),
                                  'official_qualification': SimpleNamespace(
                                      harness=Path('/toy/harness'))},
                    followup_fuzzer=Path('/toy/fuzzer'),
                    consumer_budget={'per_item_wall_seconds': 30,
                                     'combined_wall_seconds': 60}))
            self.assertEqual(rows[0]['status'], 'INCOMPLETE_CONSUMER_WALL_OVERRUN')
            self.assertEqual(rows[1]['status'], 'INCOMPLETE_CONSUMER_WALL_LIMIT')
            self.assertEqual(status_by_run['run-two'], 'INCOMPLETE_CONSUMER_WALL_LIMIT')

    def test_real_authority_change_during_item_blocks_final_credit(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture, token = product_consumer_test.FuzzerCrashConsumerTest()._real_official_uaf(
                root / 'authority')
            run, receipt = self._official_case(root / 'case', fixture, reproduced=True)
            original = fixture.local.read_bytes()
            args = dict(binary=fixture.binary, target_repository=fixture.upstream,
                harness_path=fixture.local, command=[str(fixture.binary), '{input}'],
                official_qualification=token, ledger=runner.Ledger(started_at=time.time()),
                checkpoint=root / 'budget.json',
                budget_checkpoint=root / 'consumer-budget.json',
                budget={'per_item_wall_seconds': 120, 'combined_wall_seconds': 120})
            canonical = run / 'runtime' / 'crashes' / 'synthetic-canonical.json'
            def mutate_and_return(*_a, **_k):
                canonical.parent.mkdir(parents=True, exist_ok=True)
                canonical.write_text(json.dumps({
                    'independent_verification_status': 'VERIFIED'}))
                fixture.local.write_bytes(original + b'\n/* changed */\n')
                return {'status': 'VERIFIED',
                        'canonical_crash_artifact': str(canonical)}
            with self.assertRaisesRegex(ValueError, 'pin changed'):
                runner.consume_reproduced_sp_followups(
                    run, [receipt], consumer=mutate_and_return, **args)
            handoff = json.loads((run / 'runtime/runner_sp_followup_consumer.json').read_text())
            self.assertEqual(handoff[0]['status'], 'STOPPED_CONSUMER_AUTHORITY_CHANGED')
            self.assertNotEqual(handoff[0]['status'], 'VERIFIED')
            self.assertTrue(canonical.is_file())
            self.assertEqual(json.loads(canonical.read_text())[
                'independent_verification_status'], 'VERIFIED')
            self.assertTrue(json.loads((run / 'scan.json').read_text())[
                'sp_followup_consumer_authority_invalidated'])
            self.assertTrue(json.loads((run / 'runtime/fuzzer_crashes/formal-sp-uaf.json').read_text())[
                'runner_consumer_handoff'][receipt['original_replays'][0]['sha256']][
                    'authority_changed_after_consumer'])

            fixture.local.write_bytes(original)
            cleanup = RuntimeCleanupError('toy cleanup failure', '', '')
            def mutate_and_fail(*_a, **_k):
                fixture.local.write_bytes(original + b'\n/* changed again */\n')
                raise cleanup
            with self.assertRaises(RuntimeCleanupError) as caught:
                runner.consume_reproduced_sp_followups(
                    run, [receipt], consumer=mutate_and_fail, **args)
            self.assertIs(caught.exception, cleanup)

    def test_real_authority_change_between_items_blocks_second_call(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture, token = product_consumer_test.FuzzerCrashConsumerTest()._real_official_uaf(
                root / 'authority')
            run, first = self._official_case(root / 'case', fixture, reproduced=True)
            second = copy.deepcopy(first)
            second_id = 'formal-sp-uaf-second'
            first_row = first['original_replays'][0]
            second_row = second['original_replays'][0]
            second_row['observed_crash_id'] = second_id
            replay_source = Path(first_row['artifact'])
            replay_copy = run / 'runtime' / f'{second_id}.original_replay.json'
            replay_copy.write_bytes(replay_source.read_bytes())
            second_row['artifact'] = str(replay_copy)
            second_row['artifact_sha256'] = runner.digest(replay_copy)
            first_central = json.loads((run / 'runtime/fuzzer_crashes/formal-sp-uaf.json').read_text())
            second_central = copy.deepcopy(first_central)
            second_central['crash_id'] = second_id
            second_central['runner_original_replays'] = {
                second_row['sha256']: second_row}
            (run / 'runtime/fuzzer_crashes' / f'{second_id}.json').write_text(
                json.dumps(second_central))
            original_validate = runner.validate_formal_crash_consumer_authority
            validation_count = 0
            calls = []
            original = (fixture.upstream / 'target.c').read_bytes()
            def validate(**kwargs):
                nonlocal validation_count
                validation_count += 1
                if validation_count == 4:
                    (fixture.upstream / 'target.c').write_bytes(original + b'\n/* changed */\n')
                return original_validate(**kwargs)
            def consumer(*_a, **_k):
                calls.append(1)
                return {'status': 'PENDING_ROOT_CAUSE'}
            with patch.object(runner, 'validate_formal_crash_consumer_authority', validate):
                with self.assertRaisesRegex(ValueError, 'pin changed'):
                    runner.consume_reproduced_sp_followups(
                        run, [first, second], binary=fixture.binary,
                        target_repository=fixture.upstream, harness_path=fixture.local,
                        command=[str(fixture.binary), '{input}'],
                        official_qualification=token,
                        ledger=runner.Ledger(started_at=time.time()),
                        checkpoint=root / 'budget.json',
                        budget_checkpoint=root / 'consumer-budget.json',
                        budget={'per_item_wall_seconds': 120,
                                'combined_wall_seconds': 120}, consumer=consumer)
            self.assertEqual(len(calls), 1)
            self.assertGreaterEqual(validation_count, 4)

    def test_formal_sequence_hands_followup_receipt_to_consumer(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn'}))
            binary = root / 'asan-binary'
            binary.write_bytes(b'toy')
            harness = root / 'harness.c'
            harness.write_text('/* toy */')
            token = SimpleNamespace(harness=harness)
            ledger = runner.Ledger(started_at=time.time())
            class Provider:
                def __init__(self):
                    self.ledger = ledger
                def begin_function(self, _function_id):
                    pass
                def end_function(self):
                    pass
            class Meter:
                def __init__(self, *_a, **_k):
                    self.records = []
                    self.zero_budget_assertion_runs = set()
                @contextmanager
                def patch_guided(self):
                    yield
            async def scan(folder, *_a, **_k):
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 0,
                    'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 4,
                    'combined_llm_call_limit': 8}))
            receipt = [{'original_replays': []}]
            with patch.object(runner, 'SharedFuzzMeter', Meter), \
                 patch.object(runner.scan_mod, 'scan_selected', scan), \
                 patch.object(runner, 'run_failed_pov_followups', return_value=receipt), \
                 patch.object(runner, 'consume_reproduced_sp_followups',
                              return_value=[{'budget_status': 'CONSUMER_WALL_OVERRUN'}]) as handoff, \
                 patch.object(runner, 'checkpoint_run', return_value=root / 'function-checkpoint'), \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                rows = asyncio.run(runner.run_sequence(
                    run, Provider(), ledger, root, root / 'BUDGET_CHECKPOINT.json',
                    max_functions=1,
                    scan_options={'run_command': [str(binary), '{input}'],
                                  'target_binary': binary,
                                  'official_qualification': token},
                    followup_fuzzer=root / 'coverage-fuzzer',
                    consumer_budget={'per_item_wall_seconds': 30,
                                     'combined_wall_seconds': 60}))
            self.assertEqual(handoff.call_count, 1)
            self.assertIs(handoff.call_args.kwargs['official_qualification'], token)
            self.assertEqual(handoff.call_args.args[1], receipt)
            self.assertEqual(rows[0]['status'], 'INCOMPLETE_CONSUMER_WALL_OVERRUN')
            self.assertIn('SP followup consumer', rows[0]['error'])

    def test_formal_sequence_does_not_complete_after_authority_stop(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = root / 'run'
            run.mkdir()
            (run / 'selection.json').write_text(json.dumps({'function_id': 'fn'}))
            ledger = runner.Ledger(started_at=time.time())
            class Provider:
                def __init__(self):
                    self.ledger = ledger
                def begin_function(self, _function_id):
                    pass
                def end_function(self):
                    pass
            class Meter:
                def __init__(self, *_a, **_k):
                    self.records = []
                    self.zero_budget_assertion_runs = set()
                @contextmanager
                def patch_guided(self):
                    yield
            async def scan(folder, *_a, **_k):
                (folder / 'scan.json').write_text(json.dumps({
                    'selected_function_id': 'fn', 'sp_llm_calls': 0,
                    'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 4,
                    'combined_llm_call_limit': 8}))
            statuses = []
            def checkpoint(_run, status, _ledger):
                statuses.append(status)
                return root / 'FUNCTION_CHECKPOINT.json'
            with patch.object(runner, 'SharedFuzzMeter', Meter), \
                 patch.object(runner.scan_mod, 'scan_selected', scan), \
                 patch.object(runner, 'run_failed_pov_followups', return_value=[]), \
                 patch.object(runner, 'consume_reproduced_sp_followups',
                              side_effect=ValueError('formal pin changed')), \
                 patch.object(runner, 'checkpoint_run', checkpoint), \
                 patch.object(runner, 'summarize_resource_exhaustion', return_value={
                     'resource_exhaustion_artifact_count': 0,
                     'environment_error_artifact_count': 0}):
                with self.assertRaisesRegex(ValueError, 'formal pin changed'):
                    asyncio.run(runner.run_sequence(
                        run, Provider(), ledger, root,
                        root / 'BUDGET_CHECKPOINT.json', max_functions=1,
                        scan_options={'run_command': ['/toy/asan', '{input}'],
                                      'target_binary': Path('/toy/asan'),
                                      'official_qualification': SimpleNamespace(
                                          harness=Path('/toy/harness'))},
                        followup_fuzzer=Path('/toy/fuzzer'),
                        consumer_budget={'per_item_wall_seconds': 30,
                                         'combined_wall_seconds': 60}))
            self.assertEqual(statuses, ['STOPPED_FAIL_CLOSED'])

    def test_real_official_oob_replay_does_not_invent_root_cause(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            oob_source = product_consumer_test.OFFICIAL_TARGET.replace(
                'free(buffer);\n    volatile char observed = buffer[0];',
                'volatile char observed = buffer[8];\n    free(buffer);')
            self.assertNotEqual(oob_source, product_consumer_test.OFFICIAL_TARGET)
            with patch.object(product_consumer_test, 'OFFICIAL_TARGET', oob_source):
                fixture, token = (
                    product_consumer_test.FuzzerCrashConsumerTest()._real_official_uaf(
                        root / 'oob'))
            run, receipt = self._official_case(root / 'oob-case', fixture, reproduced=True)
            rows = runner.consume_reproduced_sp_followups(
                run, [receipt], binary=fixture.binary,
                target_repository=fixture.upstream, harness_path=fixture.local,
                command=[str(fixture.binary), '{input}'], official_qualification=token,
                ledger=runner.Ledger(started_at=time.time()),
                checkpoint=root / 'oob-budget.json',
                budget_checkpoint=root / 'oob-consumer-budget.json',
                budget={'per_item_wall_seconds': 120, 'combined_wall_seconds': 120})
            self.assertNotEqual(rows[0]['status'], 'VERIFIED')
            outcome = rows[0]['consumer_result']
            canonical = json.loads(Path(outcome['canonical_crash_artifact']).read_text())
            self.assertEqual(canonical['independent_verification_status'],
                             'BLOCKED_UNSUPPORTED_CRASH_TYPE')
            self.assertFalse(json.loads((run / 'scan.json').read_text()).get(
                'verified_crash_ids'))

    def test_real_official_uaf_reaches_gate_and_fixed_build_stays_negative(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture, token = product_consumer_test.FuzzerCrashConsumerTest()._real_official_uaf(
                root / 'uaf')
            authority = dict(binary=fixture.binary,
                             target_repository=fixture.upstream,
                             harness_path=fixture.local,
                             command=[str(fixture.binary), '{input}'],
                             official_qualification=token)
            for pinned in (fixture.binary, fixture.local, fixture.upstream / 'target.c'):
                original = pinned.read_bytes()
                try:
                    pinned.write_bytes(original + b'\n/* changed after qualification */\n')
                    with self.assertRaisesRegex(ValueError, 'pin changed'):
                        runner.validate_formal_crash_consumer_authority(**authority)
                finally:
                    pinned.write_bytes(original)
            run, receipt = self._official_case(root / 'uaf-case', fixture, reproduced=True)
            rows = runner.consume_reproduced_sp_followups(
                run, [receipt], binary=fixture.binary,
                target_repository=fixture.upstream, harness_path=fixture.local,
                command=[str(fixture.binary), '{input}'], official_qualification=token,
                ledger=runner.Ledger(started_at=time.time()),
                checkpoint=root / 'uaf-budget.json',
                budget_checkpoint=root / 'uaf-consumer-budget.json',
                budget={'per_item_wall_seconds': 120, 'combined_wall_seconds': 120})
            self.assertEqual(rows[0]['status'], 'VERIFIED')
            self.assertEqual(rows[0]['consumer_result']['qualification_identity']['kind'],
                             'OFFICIAL_PINNED')
            self.assertEqual(json.loads((run / 'scan.json').read_text())['verified_crash_ids'],
                             [rows[0]['consumer_result']['canonical_crash_id']])

            fixed_source = product_consumer_test.OFFICIAL_TARGET.replace(
                'volatile char observed = buffer[0];', 'volatile char observed = 0;')
            with patch.object(product_consumer_test, 'OFFICIAL_TARGET', fixed_source):
                fixed, fixed_token = (
                    product_consumer_test.FuzzerCrashConsumerTest()._real_official_uaf(
                        root / 'fixed'))
            fixed_run, fixed_receipt = self._official_case(
                root / 'fixed-case', fixed, reproduced=False)
            fixed_rows = runner.consume_reproduced_sp_followups(
                fixed_run, [fixed_receipt], binary=fixed.binary,
                target_repository=fixed.upstream, harness_path=fixed.local,
                command=[str(fixed.binary), '{input}'], official_qualification=fixed_token,
                ledger=runner.Ledger(started_at=time.time()),
                checkpoint=root / 'fixed-budget.json',
                budget_checkpoint=root / 'fixed-consumer-budget.json',
                budget={'per_item_wall_seconds': 120, 'combined_wall_seconds': 120})
            self.assertEqual(fixed_rows[0]['status'],
                             'BLOCKED_ORIGINAL_REPLAY_NOT_REPRODUCED')
            self.assertFalse(json.loads((fixed_run / 'scan.json').read_text()).get(
                'verified_crash_ids'))

    def _official_case(self, root: Path, fixture, *, reproduced: bool):
        run = root / 'run'
        corpus = run / 'corpus' / 'candidate' / 'SP1'
        corpus.mkdir(parents=True)
        (run / 'run.json').write_text(json.dumps({'run_id': 'formal-public-toy'}))
        (run / 'scan.json').write_text('{}')
        seed = corpus / 'crash-uaf'
        seed.write_bytes(b'X')
        seed_sha = hashlib.sha256(seed.read_bytes()).hexdigest()
        observed = RuntimeExecutor(timeout_seconds=5).run(
            [str(fixture.binary), '{input}'], seed)
        self.assertEqual(bool(observed.sanitizer), reproduced)
        observation_id = 'formal-sp-uaf'
        artifact = run / 'runtime' / 'followup_observed.json'
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{}')
        central_path = _record_fuzzer_crash(
            run, observation_id, 'SP_FOLLOWUP_FUZZER', artifact, 'SP1',
            {'candidate_path': str(seed), 'sha256': seed_sha, 'size': 1})
        central = json.loads(central_path.read_text())
        central['status'] = ('REPRODUCED_ORIGINAL_BINARY_PENDING_ROOT_CAUSE'
                             if reproduced else 'ORIGINAL_REPLAY_NOT_REPRODUCED')
        central_path.write_text(json.dumps(central))
        replay_artifact = run / 'runtime' / f'{observation_id}.original_replay.json'
        replay_artifact.write_text(json.dumps(asdict(observed)))
        receipt = {'original_replays': [{
            'observed_crash_id': observation_id, 'sha256': seed_sha, 'size': 1,
            'status': 'REPLAYED', 'sanitizer': observed.sanitizer,
            'timed_out': observed.timed_out, 'artifact': str(replay_artifact),
            'artifact_sha256': runner.digest(replay_artifact),
            'input_path': str(seed.resolve()),
            'command': [str(fixture.binary), '{input}'],
            'binary_sha256': runner.digest(fixture.binary),
            'exit_code': observed.exit_code}]}
        central['runner_original_replays'] = {seed_sha: receipt['original_replays'][0]}
        central_path.write_text(json.dumps(central))
        return run, receipt

    def _case(self, root: Path, data: bytes = b'X', *, reproduced: bool = True):
        run = root / 'run'
        corpus = run / 'corpus' / 'candidate' / 'SP1'
        corpus.mkdir(parents=True)
        (run / 'runtime' / 'fuzzer_crashes').mkdir(parents=True)
        (run / 'scan.json').write_text('{}')
        binary = root / 'asan-binary'
        binary.write_bytes(b'pinned binary')
        harness = root / 'harness.c'
        harness.write_text('/* public toy */\n')
        source = root / 'source'
        source.mkdir()
        input_path = corpus / 'crash-one'
        input_path.write_bytes(data)
        input_sha = hashlib.sha256(data).hexdigest()
        observation_id = 'sp-fuzzer-input-one'
        observation = {
            'crash_id': observation_id,
            'status': ('REPRODUCED_ORIGINAL_BINARY_PENDING_ROOT_CAUSE'
                       if reproduced else 'ORIGINAL_REPLAY_NOT_REPRODUCED'),
            'observations': [{'crash_input': {
                'sha256': input_sha, 'size': len(data),
                'candidate_path': str(input_path)}}],
        }
        path = run / 'runtime' / 'fuzzer_crashes' / f'{observation_id}.json'
        path.write_text(json.dumps(observation))
        replay_artifact = run / 'runtime' / f'{observation_id}.original_replay.json'
        replay_artifact.write_text(json.dumps({
            'exit_code': 1 if reproduced else 0,
            'sanitizer': 'heap-use-after-free' if reproduced else None,
            'timed_out': False}))
        receipt = {'original_replays': [{
            'observed_crash_id': observation_id, 'sha256': input_sha,
            'size': len(data), 'status': 'REPLAYED' if reproduced else 'OBSERVED_PENDING_REPLAY',
            'sanitizer': 'heap-use-after-free' if reproduced else None,
            'timed_out': False, 'artifact': str(replay_artifact),
            'artifact_sha256': runner.digest(replay_artifact),
            'input_path': str(input_path.resolve()),
            'command': [str(binary), '{input}'],
            'binary_sha256': runner.digest(binary),
            'exit_code': 1 if reproduced else 0,
        }]}
        observation['runner_original_replays'] = {input_sha: receipt['original_replays'][0]}
        path.write_text(json.dumps(observation))
        token = SimpleNamespace(binary=binary.resolve(),
                                binary_sha256=runner.digest(binary),
                                harness=harness.resolve(),
                                source_root=source.resolve(),
                                product_issued=True)
        return run, binary, harness, source, receipt, token, input_sha, path

    def _invoke(self, root: Path, case, *, consumer, item_wall=30, total_wall=60):
        run, binary, harness, source, receipt, token, _, _ = case
        checkpoint = root / 'BUDGET_CHECKPOINT.json'
        budget_checkpoint = root / 'CRASH_CONSUMER_BUDGET.json'
        ledger = runner.Ledger(started_at=time.time())
        return runner.consume_reproduced_sp_followups(
            run, [receipt], binary=binary,
            target_repository=source, harness_path=harness,
            command=[str(binary), '{input}'],
            official_qualification=token, ledger=ledger,
            checkpoint=checkpoint, budget_checkpoint=budget_checkpoint,
            budget={'per_item_wall_seconds': item_wall,
                    'combined_wall_seconds': total_wall},
            consumer=consumer)

    def test_reproduced_input_uses_same_token_and_pinned_identity(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self._case(root)
            calls = []
            def consumer(*args, **kwargs):
                calls.append((args, kwargs))
                return {'status': 'VERIFIED', 'qualification_identity': {'kind': 'OFFICIAL_PINNED'}}
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                rows = self._invoke(root, case, consumer=consumer)
            self.assertEqual(rows[0]['status'], 'VERIFIED')
            self.assertIs(calls[0][1]['official_qualification'], case[5])
            self.assertEqual(calls[0][1]['expected_binary_sha256'], case[5].binary_sha256)
            self.assertEqual(calls[0][1]['harness_path'], case[2])
            self.assertEqual(calls[0][1]['target_repository'], case[3])
            self.assertTrue((root / 'CRASH_CONSUMER_BUDGET.json').is_file())

    def test_oversize_and_ambiguous_paths_are_blocked_before_consumer(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self._case(root, b'X' * (2 * 1024 * 1024 + 1))
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                rows = self._invoke(root, case, consumer=lambda *_a, **_k: self.fail('called'))
            self.assertEqual(rows[0]['status'], 'BLOCKED_CONSUMER_INPUT_SIZE_UNSUPPORTED')
            central = json.loads(case[7].read_text())
            self.assertEqual(central['status'],
                             'REPRODUCED_ORIGINAL_BINARY_PENDING_ROOT_CAUSE')
            self.assertEqual(central['runner_consumer_handoff'][case[6]]['status'],
                             'BLOCKED_CONSUMER_INPUT_SIZE_UNSUPPORTED')

            case = self._case(root / 'ambiguous')
            run, _, _, _, _, _, sha, path = case
            second = run / 'corpus' / 'candidate' / 'SP1' / 'crash-two'
            second.write_bytes(b'X')
            record = json.loads(path.read_text())
            record['observations'].append({'crash_input': {
                'sha256': sha, 'size': 1, 'candidate_path': str(second)}})
            path.write_text(json.dumps(record))
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                rows = self._invoke(root / 'ambiguous', case,
                                    consumer=lambda *_a, **_k: self.fail('called'))
            self.assertEqual(rows[0]['status'], 'BLOCKED_CONSUMER_INPUT_AMBIGUOUS')

    def test_replay_artifact_or_corpus_path_mismatch_blocks_handoff(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self._case(root)
            replay = case[4]['original_replays'][0]
            replay['sanitizer'] = 'heap-buffer-overflow'
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                rows = self._invoke(root, case,
                                    consumer=lambda *_a, **_k: self.fail('called'))
            self.assertEqual(rows[0]['status'], 'BLOCKED_ORIGINAL_REPLAY_ARTIFACT')

            case = self._case(root / 'path')
            run, _, _, _, _, _, sha, central_path = case
            external = root / 'external-crash'
            external.write_bytes(b'X')
            central = json.loads(central_path.read_text())
            central['observations'][0]['crash_input']['candidate_path'] = str(external)
            central_path.write_text(json.dumps(central))
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                rows = self._invoke(root / 'path', case,
                                    consumer=lambda *_a, **_k: self.fail('called'))
            self.assertEqual(rows[0]['status'], 'BLOCKED_CONSUMER_INPUT_UNTRUSTED')

    def test_replay_identity_fields_must_match_central_and_runtime_artifact(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for field, changed in (
                ('input_path', '/tmp/unrelated-input'),
                ('command', ['/tmp/unrelated-binary', '{input}']),
                ('binary_sha256', '0' * 64),
                ('artifact_sha256', '1' * 64),
                ('exit_code', 0),
            ):
                with self.subTest(field=field):
                    case_root = root / field
                    case = self._case(case_root)
                    case[4]['original_replays'][0][field] = changed
                    with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                        rows = self._invoke(case_root, case,
                            consumer=lambda *_a, **_k: self.fail('called'))
                    self.assertEqual(rows[0]['status'],
                                     'BLOCKED_ORIGINAL_REPLAY_ARTIFACT')

    def test_nonreproduced_and_unsupported_oob_never_become_verified(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self._case(root, reproduced=False)
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                rows = self._invoke(root, case, consumer=lambda *_a, **_k: self.fail('called'))
            self.assertEqual(rows[0]['status'], 'PENDING_ORIGINAL_REPLAY')

            case = self._case(root / 'oob')
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                rows = self._invoke(root / 'oob', case,
                    consumer=lambda *_a, **_k: {
                        'status': 'GATE_CHECKED_NOT_VERIFIED',
                        'gate_status': 'BLOCKED_UNSUPPORTED_CRASH_TYPE'})
            self.assertEqual(rows[0]['status'], 'GATE_CHECKED_NOT_VERIFIED')
            self.assertEqual(rows[0]['gate_status'], 'BLOCKED_UNSUPPORTED_CRASH_TYPE')

    def test_consumer_timeout_keeps_original_exception_and_checkpoints(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self._case(root)
            def consumer(*_args, **_kwargs):
                raise TimeoutError('synthetic consumer timeout')
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                with self.assertRaisesRegex(TimeoutError, 'synthetic consumer timeout'):
                    self._invoke(root, case, consumer=consumer)
            self.assertTrue((root / 'BUDGET_CHECKPOINT.json').is_file())
            budget = json.loads((root / 'CRASH_CONSUMER_BUDGET.json').read_text())
            self.assertEqual(budget['last_status'], 'INCOMPLETE_CONSUMER_TIMEOUT')

    def test_cleanup_error_remains_primary_after_consumer_checkpoint(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self._case(root)
            error = RuntimeCleanupError('toy cleanup incomplete', '', '')
            def consumer(*_args, **_kwargs):
                raise error
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                with self.assertRaises(RuntimeCleanupError) as caught:
                    self._invoke(root, case, consumer=consumer)
            self.assertIs(caught.exception, error)
            budget = json.loads((root / 'CRASH_CONSUMER_BUDGET.json').read_text())
            self.assertEqual(budget['last_status'], 'STOPPED_CLEANUP_INCOMPLETE')
            self.assertEqual(json.loads(case[7].read_text())[
                'runner_consumer_handoff'][case[6]]['status'],
                'STOPPED_CLEANUP_INCOMPLETE')

    def test_duplicate_replay_sha_is_consumed_once(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self._case(root)
            run, binary, harness, source, receipt, token, _, _ = case
            ledger = runner.Ledger(started_at=time.time())
            calls = []
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                rows = runner.consume_reproduced_sp_followups(
                    run, [receipt, receipt], binary=binary,
                    target_repository=source, harness_path=harness,
                    command=[str(binary), '{input}'],
                    official_qualification=token, ledger=ledger,
                    checkpoint=root / 'BUDGET_CHECKPOINT.json',
                    budget_checkpoint=root / 'CRASH_CONSUMER_BUDGET.json',
                    budget={'per_item_wall_seconds': 30,
                            'combined_wall_seconds': 60},
                    consumer=lambda *_a, **_k: (
                        calls.append(1) or {'status': 'PENDING_ROOT_CAUSE'}))
            self.assertEqual(len(calls), 1)
            self.assertEqual(rows[1]['status'], 'SKIPPED_DUPLICATE_CONSUMER_REQUEST')

    def test_postcharged_wall_overrun_blocks_later_consumer_admission(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = self._case(root)
            run, binary, harness, source, receipt, token, _, _ = case
            ledger = runner.Ledger(started_at=time.time())
            state = {'spent_seconds': 0.0}
            calls = []
            def slow_consumer(*_args, **_kwargs):
                calls.append(1)
                time.sleep(0.03)
                return {'status': 'PENDING_ROOT_CAUSE'}
            args = dict(binary=binary, target_repository=source,
                harness_path=harness, command=[str(binary), '{input}'],
                official_qualification=token, ledger=ledger,
                checkpoint=root / 'BUDGET_CHECKPOINT.json',
                budget_checkpoint=root / 'CRASH_CONSUMER_BUDGET.json',
                budget={'per_item_wall_seconds': 0.01,
                        'combined_wall_seconds': 0.02},
                budget_state=state, consumer=slow_consumer)
            with patch.object(runner, 'validate_formal_crash_consumer_authority'):
                first = runner.consume_reproduced_sp_followups(run, [receipt], **args)
                second = runner.consume_reproduced_sp_followups(run, [receipt], **args)
            self.assertEqual(len(calls), 1)
            self.assertGreater(first[0]['item_wall_overrun_seconds'], 0)
            self.assertEqual(second[0]['status'], 'PENDING_CONSUMER_WALL_LIMIT')
            self.assertEqual(json.loads((run / 'scan.json').read_text())[
                'sp_followup_consumer_handoff'][0]['status'],
                'PENDING_CONSUMER_WALL_LIMIT')
            budget = json.loads((root / 'CRASH_CONSUMER_BUDGET.json').read_text())
            self.assertEqual(budget['last_status'],
                             'COMPLETE_WITH_CONSUMER_WALL_OVERRUN')
            self.assertTrue(budget['had_overrun'])
