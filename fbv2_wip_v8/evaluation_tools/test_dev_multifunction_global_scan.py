"""Provider-free product Scan across three functions with one global ledger.

This exercises the opt-in Scan/Phase 1 boundary only. It is not the Blind 3
runner, does not spend a real model turn, and never executes the target.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PREP = Path(__file__).resolve().parents[1]
PRODUCT = (Path(__file__).resolve().parents[1] / "product")
sys.path[:0] = [str(PRODUCT / 'src'), str(PRODUCT / 'tests'),
                str(PREP / 'evaluation_tools'), str(PREP / 'review_tools')]

from dev_global_request_ledger import (DevelopmentBudget,
                                       DevelopmentRequestLedger,
                                       GLOBAL_ONLY_DEV_PROFILE)
from dev_global_appserver_bridge import request_hash as bridge_request_hash
from dev_no_k_three_function_gate import make_public_fixture
from dev_phase1_chain_pin import issue_pin, verify_pin
from vulnerabilityanalysis.scan import (_external_multifunction_requests,
                                        scan_selected)
from vulnerabilityanalysis.workflow import continue_phase1, run_phase1


class _Qualification:
    product_issued = True

    def __init__(self, source_root: Path, harness: Path, binary: Path):
        self.source_root = source_root.resolve()
        self.harness = harness.resolve()
        self.binary = binary.resolve()


class _Provider:
    def __init__(self, ledger: DevelopmentRequestLedger, function_id: str):
        self.ledger = ledger
        self.scope_id = function_id
        self.calls: list[str] = []
        self.backend = SimpleNamespace(ledger=ledger, scope_id=function_id,
                                       _request=self._unexpected_transport)

    @staticmethod
    async def _unexpected_transport(*_args, **_kwargs):
        raise AssertionError('real App Server transport is forbidden')

    async def generate(self, request):
        digest = bridge_request_hash(request)
        self.ledger.begin_turn(self.scope_id, request.role, digest)
        self.ledger.start_attempt(digest)
        self.calls.append(request.role)
        try:
            if request.role != 'sp_generation':
                raise AssertionError(f'unexpected role {request.role}')
            response = {'suspicious_points': []}
        except BaseException as exc:
            self.ledger.finish_attempt(completed=False, error=str(exc))
            self.ledger.abandon_turn(type(exc).__name__)
            raise
        self.ledger.finish_attempt(completed=True)
        return response


class _NoDebitProvider(_Provider):
    """Return a plausible response without recording the physical request."""

    async def generate(self, request):
        self.calls.append(request.role)
        if request.role != 'sp_generation':
            raise AssertionError(f'unexpected role {request.role}')
        return {'suspicious_points': []}


class _ModelArtifactTamperProvider(_Provider):
    """Change only the persisted effective model after a genuine ledger debit."""

    def __init__(self, ledger, function_id, run):
        super().__init__(ledger, function_id)
        self.run = run

    async def generate(self, request):
        result = await super().generate(request)
        artifacts = list((self.run / 'logs').glob('*_request.json'))
        if len(artifacts) != 1:
            raise AssertionError('expected one public toy request artifact')
        artifact = artifacts[0]
        record = json.loads(artifact.read_text())
        record['model'] = 'tampered-model'
        record['reasoning'] = 'tampered-effort'
        artifact.write_text(json.dumps(record) + '\n')
        return result


class MultiFunctionGlobalScanTests(unittest.TestCase):
    @staticmethod
    def _pin_path(run: Path) -> Path:
        return run.parent.parent.parent / 'evaluator_pins' / f'{run.name}.json'

    def _fixture(self, root: Path):
        artifact, repo, plan = make_public_fixture(root / 'fixture')
        run = run_phase1(artifact, repo / 'runs', target_repository=repo,
                         direction_plan=plan,
                         selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
        binary = repo / 'target.bin'
        binary.write_bytes(b'public synthetic binary; never executed\n')
        qualification = _Qualification(repo, repo / 'fuzz.c', binary)
        budget = DevelopmentBudget(
            physical_max=4, logical_max=4, retries_max=0, wall_seconds=60,
            initial_starts_required=1, profile=GLOBAL_ONLY_DEV_PROFILE)
        ledger = DevelopmentRequestLedger.create(budget, root / 'MODEL_LEDGER.json')
        ledger.register_direction('public-direction')
        digest = 'a' * 64
        ledger.begin_turn('public-direction', 'direction_generator', digest)
        ledger.start_attempt(digest)
        ledger.finish_attempt(completed=True)
        pin_path = self._pin_path(run)
        pin_path.parent.mkdir(mode=0o700)
        issue_pin(run, pin_path)
        self._pin_hashes = {run: hashlib.sha256(pin_path.read_bytes()).hexdigest()}
        return run, repo, binary, qualification, ledger

    def _scan(self, run, repo, binary, qualification, ledger, *, enabled=True):
        self.assertEqual(hashlib.sha256(self._pin_path(run).read_bytes()).hexdigest(),
                         self._pin_hashes[run])
        self.assertEqual(verify_pin(self._pin_path(run))['selected_function_id'],
                         json.loads((run / 'selection.json').read_text())['function_id'])
        function_id = json.loads((run / 'selection.json').read_text())['function_id']
        provider = _Provider(ledger, function_id)
        self._invoke_scan(run, repo, binary, qualification, ledger, provider,
                          enabled=enabled)
        return provider

    def _invoke_scan(self, run, repo, binary, qualification, ledger, provider,
                     *, enabled=True):
        with (patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                    _Qualification),
              patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                    return_value=True),
              patch('vulnerabilityanalysis.scan.execute_poc',
                    side_effect=AssertionError('Target execution is forbidden'))):
            kwargs = {'external_multifunction_dev': True} if enabled else {}
            asyncio.run(scan_selected(
                run, provider, target_repository=repo, target_binary=binary,
                official_qualification=qualification,
                external_turn_budget=ledger, candidate_budget_policy='QUEUE_FIRST_DEV',
                max_candidates=1, targeted_fuzz_seconds=0,
                global_fuzz_enabled=False, hallucination_prevent='off', **kwargs))

    def _next(self, run, ledger):
        function_id = json.loads((run / 'selection.json').read_text())['function_id']
        ledger.mark_scan_recorded(function_id)
        new_run = continue_phase1(run)
        issue_pin(new_run, self._pin_path(new_run),
                  parent_pin=self._pin_path(run))
        self._pin_hashes[new_run] = hashlib.sha256(
            self._pin_path(new_run).read_bytes()).hexdigest()
        next_id = json.loads((new_run / 'selection.json').read_text())['function_id']
        self.assertTrue(ledger.select_function(next_id))
        return new_run

    def _ready_second(self, root):
        run, repo, binary, qualification, ledger = self._fixture(root)
        first_id = json.loads((run / 'selection.json').read_text())['function_id']
        self.assertTrue(ledger.select_function(first_id))
        self.assertEqual(self._scan(run, repo, binary, qualification, ledger).calls,
                         ['sp_generation'])
        second = self._next(run, ledger)
        return run, second, repo, binary, qualification, ledger

    def test_three_product_scans_share_one_no_k_ledger(self):
        with TemporaryDirectory() as tmp:
            run, second, repo, binary, qualification, ledger = self._ready_second(
                Path(tmp))
            order = [json.loads((run / 'selection.json').read_text())['function_id']]
            self.assertEqual(self._scan(second, repo, binary, qualification,
                                        ledger).calls, ['sp_generation'])
            order.append(json.loads((second / 'selection.json').read_text())['function_id'])
            third = self._next(second, ledger)
            self.assertEqual(self._scan(third, repo, binary, qualification,
                                        ledger).calls, ['sp_generation'])
            order.append(json.loads((third / 'selection.json').read_text())['function_id'])
            ledger.mark_scan_recorded(order[-1])
            self.assertEqual(order, ['fn-a', 'fn-c', 'fn-b'])
            self.assertEqual((ledger.logical, ledger.physical), (4, 4))
            self.assertEqual(ledger.selected_functions, order)
            self.assertEqual(ledger.summary(order)['status'],
                             'ACCOUNTING_COMPLETE_AWAITING_EVIDENCE')
            self.assertTrue(all(json.loads((path / 'scan.json').read_text())[
                'external_multifunction_dev'] for path in (run, second, third)))
            with self.assertRaisesRegex(ValueError, 'pool exhausted'):
                continue_phase1(third)

    def test_evaluator_pin_rejects_changed_pool_before_first_model_request(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self._fixture(Path(tmp))
            function_id = json.loads((run / 'selection.json').read_text())['function_id']
            self.assertTrue(ledger.select_function(function_id))
            pool_path = run / 'function_pool.json'
            pool_path.write_bytes(pool_path.read_bytes() + b' \n')
            with self.assertRaises(ValueError):
                self._scan(run, repo, binary, qualification, ledger)
            self.assertEqual((ledger.logical, ledger.physical), (1, 1))
            self.assertFalse((run / 'scan.json').exists())

    def test_new_pin_is_snapshot_not_scheduler_authority(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self._fixture(Path(tmp))
            pool = json.loads((run / 'function_pool.json').read_text())
            alternate = next(row for row in pool if row['function_id'] !=
                             json.loads((run / 'selection.json').read_text())['function_id'])
            (run / 'selection.json').write_text(json.dumps(alternate) + '\n')
            run_record_path = run / 'run.json'
            run_record = json.loads(run_record_path.read_text())
            run_record['selected_function_id'] = alternate['function_id']
            run_record_path.write_text(json.dumps(run_record) + '\n')
            forged_snapshot = self._pin_path(run).with_name('forged.json')
            self.assertEqual(issue_pin(run, forged_snapshot)['selected_function_id'],
                             alternate['function_id'])
            self.assertTrue(ledger.select_function(alternate['function_id']))
            provider = _Provider(ledger, alternate['function_id'])
            with self.assertRaises(ValueError):
                self._invoke_scan(run, repo, binary, qualification, ledger, provider)
            self.assertEqual(provider.calls, [])
            self.assertEqual((ledger.logical, ledger.physical), (1, 1))

    def test_second_scan_requires_opt_in_and_unchanged_prior_receipt(self):
        for mutation in ('no_flag', 'not_recorded', 'changed_scan', 'pending_sp',
                         'pending_direction', 'changed_parent', 'changed_checkpoint',
                         'changed_pool_role', 'changed_pool_rank',
                         'changed_selection', 'changed_current_pool_rank',
                         'tainted_ledger'):
            with self.subTest(mutation=mutation), TemporaryDirectory() as tmp:
                run, second, repo, binary, qualification, ledger = self._ready_second(
                    Path(tmp))
                if mutation == 'no_flag':
                    enabled = False
                else:
                    enabled = True
                if mutation == 'not_recorded':
                    ledger.function_states[ledger.selected_functions[0]] = 'SELECTED_NOT_STARTED'
                    ledger.checkpoint()
                elif mutation in {'changed_scan', 'pending_sp'}:
                    path = run / 'scan.json'
                    row = json.loads(path.read_text())
                    if mutation == 'changed_scan':
                        row['selected_function_id'] = 'fn-other'
                    else:
                        row['pending_sp_ids'] = ['sp-unresolved']
                    path.write_text(json.dumps(row) + '\n')
                elif mutation == 'pending_direction':
                    ledger.mark_pending('pending-direction', 'public-direction',
                                        'DIRECTION', 'DIRECTION_NOT_SETTLED')
                elif mutation == 'changed_parent':
                    path = second / 'run.json'
                    row = json.loads(path.read_text())
                    row['parent_run_id'] = 'missing-parent'
                    path.write_text(json.dumps(row) + '\n')
                elif mutation == 'changed_checkpoint':
                    path = ledger.checkpoint_path
                    row = json.loads(path.read_text())
                    row['physical'] = 1
                    path.write_text(json.dumps(row) + '\n')
                elif mutation in {'changed_pool_role', 'changed_pool_rank'}:
                    path = run / 'function_pool.json'
                    rows = json.loads(path.read_text())
                    rows[0]['role' if mutation == 'changed_pool_role'
                            else 'priority_score'] = 'tampered'
                    path.write_text(json.dumps(rows) + '\n')
                elif mutation == 'changed_selection':
                    path = run / 'selection.json'
                    row = json.loads(path.read_text())
                    row['priority_score'] = 'tampered'
                    path.write_text(json.dumps(row) + '\n')
                elif mutation == 'changed_current_pool_rank':
                    selected = json.loads((second / 'selection.json').read_text())
                    path = second / 'function_pool.json'
                    rows = json.loads(path.read_text())
                    next(row for row in rows if row['function_id'] ==
                         selected['function_id'])['priority_score'] = 'tampered'
                    path.write_text(json.dumps(rows) + '\n')
                elif mutation == 'tainted_ledger':
                    ledger.tainted = True
                second_id = json.loads((second / 'selection.json').read_text())[
                    'function_id']
                provider = _Provider(ledger, second_id)
                with (patch('vulnerabilityanalysis.scan.OfficialPinnedQualification',
                            _Qualification),
                      patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                            return_value=True)):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        asyncio.run(scan_selected(
                            second, provider, target_repository=repo, target_binary=binary,
                            official_qualification=qualification,
                            external_turn_budget=ledger,
                            candidate_budget_policy='QUEUE_FIRST_DEV', max_candidates=1,
                            targeted_fuzz_seconds=0, global_fuzz_enabled=False,
                            hallucination_prevent='off',
                            external_multifunction_dev=enabled))
                self.assertEqual(provider.calls, [])
                self.assertEqual((ledger.logical, ledger.physical), (2, 2))

    def test_changed_first_selection_is_rejected_before_model_request(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self._fixture(Path(tmp))
            original = json.loads((run / 'selection.json').read_text())
            pool = json.loads((run / 'function_pool.json').read_text())
            alternate = next(row for row in pool if
                             row['function_id'] != original['function_id'])
            (run / 'selection.json').write_text(json.dumps(alternate) + '\n')
            record_path = run / 'run.json'
            record = json.loads(record_path.read_text())
            record['selected_function_id'] = alternate['function_id']
            record_path.write_text(json.dumps(record) + '\n')
            self.assertTrue(ledger.select_function(alternate['function_id']))
            provider = _Provider(ledger, alternate['function_id'])
            with self.assertRaises(ValueError):
                self._invoke_scan(run, repo, binary, qualification, ledger,
                                  provider)
            self.assertEqual(provider.calls, [])
            self.assertEqual((ledger.logical, ledger.physical), (1, 1))

    def test_changed_checkpoint_turn_hash_is_rejected_before_model_request(self):
        with TemporaryDirectory() as tmp:
            _, second, repo, binary, qualification, ledger = self._ready_second(
                Path(tmp))
            checkpoint_path = ledger.checkpoint_path
            checkpoint = json.loads(checkpoint_path.read_text())
            checkpoint['turns'][0]['hash'] = 'b' * 64
            checkpoint_path.write_text(json.dumps(checkpoint) + '\n')
            function_id = json.loads((second / 'selection.json').read_text())[
                'function_id']
            provider = _Provider(ledger, function_id)
            with self.assertRaises(ValueError):
                self._invoke_scan(second, repo, binary, qualification, ledger,
                                  provider)
            self.assertEqual(provider.calls, [])
            self.assertEqual((ledger.logical, ledger.physical), (2, 2))

    def test_provider_response_without_ledger_debit_is_rejected(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self._fixture(Path(tmp))
            function_id = json.loads((run / 'selection.json').read_text())[
                'function_id']
            self.assertTrue(ledger.select_function(function_id))
            provider = _NoDebitProvider(ledger, function_id)
            with self.assertRaises(ValueError):
                self._invoke_scan(run, repo, binary, qualification, ledger,
                                  provider)
            self.assertEqual(provider.calls, ['sp_generation'])
            self.assertEqual((ledger.logical, ledger.physical), (1, 1))
            self.assertFalse((run / 'scan.json').exists())

    def test_changed_effective_model_artifact_is_rejected(self):
        with TemporaryDirectory() as tmp:
            run, repo, binary, qualification, ledger = self._fixture(Path(tmp))
            function_id = json.loads((run / 'selection.json').read_text())[
                'function_id']
            self.assertTrue(ledger.select_function(function_id))
            provider = _ModelArtifactTamperProvider(ledger, function_id, run)
            with self.assertRaises(ValueError):
                self._invoke_scan(run, repo, binary, qualification, ledger,
                                  provider)
            self.assertEqual(provider.calls, ['sp_generation'])
            self.assertFalse((run / 'scan.json').exists())

    def test_changed_prior_model_artifact_is_rejected_before_next_request(self):
        with TemporaryDirectory() as tmp:
            first, second, repo, binary, qualification, ledger = self._ready_second(
                Path(tmp))
            row = json.loads((first / 'logs' / 'agent_requests.jsonl').read_text(
                ).splitlines()[0])
            artifact = Path(row['request_artifact'])
            record = json.loads(artifact.read_text())
            record['model'] = 'tampered-model'
            record['reasoning'] = 'tampered-effort'
            artifact.write_text(json.dumps(record) + '\n')
            function_id = json.loads((second / 'selection.json').read_text())[
                'function_id']
            provider = _Provider(ledger, function_id)
            with self.assertRaises(ValueError):
                self._invoke_scan(second, repo, binary, qualification, ledger,
                                  provider)
            self.assertEqual(provider.calls, [])
            self.assertEqual((ledger.logical, ledger.physical), (2, 2))

    def test_corrected_verifier_schema_error_remains_a_counted_request(self):
        """The product can log ERROR then COMPLETED for a schema correction."""
        with TemporaryDirectory() as tmp:
            run, _, _, _, ledger = self._fixture(Path(tmp))
            function_id = json.loads((run / 'selection.json').read_text())[
                'function_id']
            self.assertTrue(ledger.select_function(function_id))
            logs = run / 'logs'
            logs.mkdir(exist_ok=True)
            records = []
            for index, response in enumerate(({}, {'verdict': 'UNKNOWN'}), 1):
                request = SimpleNamespace(
                    role='sp_verifier', instructions='public schema test',
                    payload={'candidate': 'toy', 'attempt': index},
                    output_schema={'type': 'object', 'required': ['verdict']},
                    model=None, effort=None)
                request.session_key = None
                digest = bridge_request_hash(request)
                ledger.begin_turn(function_id, request.role, digest)
                ledger.start_attempt(digest)
                ledger.finish_attempt(completed=True)
                request_path = logs / f'verifier_{index}_request.json'
                response_path = logs / f'verifier_{index}_parsed.json'
                request_path.write_text(json.dumps({
                    'role': request.role, 'instructions': request.instructions,
                    'payload': request.payload,
                    'output_schema': request.output_schema,
                    'model': None, 'reasoning': None}) + '\n')
                response_path.write_text(json.dumps(response) + '\n')
                request_path.chmod(0o600)
                response_path.chmod(0o600)
                records.append({'role': request.role,
                                'status': 'ERROR' if index == 1 else 'COMPLETED',
                                'request_artifact': str(request_path.resolve()),
                                'response_artifact': str(response_path.resolve())})
            (logs / 'agent_requests.jsonl').write_text(
                ''.join(json.dumps(row) + '\n' for row in records))
            _external_multifunction_requests(run, function_id, ledger, 2, 0)


if __name__ == '__main__':
    unittest.main()
