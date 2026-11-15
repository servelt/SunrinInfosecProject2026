"""Provider-free regressions for the supervised official V2 component route."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'review_tools'),
                '/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src']
import blind3_md4c_live_full_candidate_supervised_dev as live
import dev_live_direction_sp_hp_supervisor as base


class FakeProcess:
    def __init__(self, outcome: str) -> None:
        self.outcome = outcome
        self.pid = 999_999
        self.returncode = None
        self.wait_deadlines: list[float] = []

    def wait(self, timeout: float) -> int:
        self.wait_deadlines.append(timeout)
        if self.outcome in {'timeout', 'cleanup_failed'} and len(self.wait_deadlines) == 1:
            raise subprocess.TimeoutExpired('scripted child', timeout)
        self.returncode = 0 if self.outcome == 'success' else -9
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode


class FakeRunner:
    def __init__(self, outcome: str) -> None:
        self.child = FakeProcess(outcome)
        self.cleaned = False
        self.killed = False

    def _launch_guarded(self, command, *, stdout, stderr, env):
        stdout.write(b'scripted fake child\n')
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        return self.child, read_fd

    def _guarded_return_code(self, child, status_fd):
        return child.returncode

    def _request_guard_cleanup(self, child, status_fd):
        self.cleaned = True
        child.returncode = -9
        return child.outcome != 'cleanup_failed'

    def _kill_process_group(self, pid):
        self.killed = True


class SupervisedComponentTests(unittest.TestCase):
    def _output(self) -> Path:
        temp = tempfile.TemporaryDirectory(prefix='live-component-test-')
        self.addCleanup(temp.cleanup)
        path = Path(temp.name)
        path.chmod(0o700)
        return path

    def _repair_evidence(self, output: Path) -> tuple[dict, dict, str]:
        folder = output / 'direction'
        folder.mkdir()
        identities = []
        for name in ('DIRECTION_REQUEST.json', 'DIRECTION_REPAIR_REQUEST.json'):
            request = {'role': 'direction_generator', 'instructions': name,
                       'payload': {}, 'output_schema': {}, 'model': 'test',
                       'reasoning': 'high'}
            raw = json.dumps(request).encode()
            (folder / name).write_bytes(raw)
            identities.append(live._request_artifact_hash(raw))
        for name, marker in (('DIRECTION_RAW.txt', 'first'),
                             ('DIRECTION_REPAIR_RAW.txt', 'repaired')):
            (folder / name).write_text(json.dumps({
                'directions': [{'name': marker}], 'unknowns': []}))
        response = json.loads((folder / 'DIRECTION_REPAIR_RAW.txt').read_text())
        (folder / 'DIRECTION_PLAN.json').write_text(json.dumps({'response': {
            **response,
            'pool_preservation_rule': 'all Catalog functions remain candidates; Direction output only changes priority evidence',
            'indirect_runtime_status': 'UNVERIFIED'}}))
        evidence = {'direction_turn_count': 2,
            'direction_request_sha256': live.sha(folder / 'DIRECTION_REQUEST.json'),
            'direction_raw_sha256': live.sha(folder / 'DIRECTION_RAW.txt'),
            'direction_repair_request_sha256': live.sha(
                folder / 'DIRECTION_REPAIR_REQUEST.json'),
            'direction_repair_raw_sha256': live.sha(
                folder / 'DIRECTION_REPAIR_RAW.txt'),
            'direction_logical_turn_id': 'L000002',
            'direction_physical_starts': 2}
        status = {'kind': 'DIRECTION_GRAPH_REPAIR_DEV_V1',
            'status': 'VALIDATED', 'direction_turn_count': 2,
            'first_request_sha256': evidence['direction_request_sha256'],
            'first_raw_sha256': evidence['direction_raw_sha256'],
            'repair_request_sha256': evidence['direction_repair_request_sha256'],
            'repair_raw_sha256': evidence['direction_repair_raw_sha256']}
        (folder / 'DIRECTION_REPAIR_STATUS.json').write_text(json.dumps(status))
        evidence['direction_repair_status_sha256'] = live.sha(
            folder / 'DIRECTION_REPAIR_STATUS.json')
        ledger = {'kind': 'DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1',
            'active_turn': None, 'physical': 2, 'logical': 2, 'retries': 0,
            'direction_counts': {'scope': 2},
            'turns': [{'id': f'L{index:06d}', 'role': 'direction_generator',
                       'status': 'COMPLETED', 'scope_id': 'scope',
                       'hash': identity} for index, identity in
                      enumerate(identities, 1)],
            'attempts': [{'status': 'COMPLETED', 'scope_id': 'scope'}] * 2,
            'selected_functions': [],
            'no_opportunity': {'function': 'NO_OPPORTUNITY_BUDGET'},
            'budget': {'profile': 'GLOBAL_ONLY_DEV',
                       'direction_turns_per_scope': 2}}
        return ledger, evidence, live.sha(folder / 'DIRECTION_PLAN.json')

    def test_global_budget_is_explicit_and_has_no_sp4_hp4(self):
        value = {'physical_max': 12, 'logical_max': 10, 'retries_max': 2,
                 'wall_seconds': 600, 'initial_starts_required': 2}
        budget = live._budget(value)
        self.assertEqual(budget.profile, 'GLOBAL_ONLY_DEV')
        self.assertEqual((budget.sp_per_function, budget.hp_per_function), (1, 1))
        with self.assertRaises(ValueError):
            live._budget({**value, 'physical_max': 100})
        self.assertEqual(live._budget({**value,
            'initial_starts_required': 1}).initial_starts_required, 1)
        with self.assertRaises(ValueError):
            live._budget({**value, 'initial_starts_required': 0})

    def test_two_direction_turns_are_charged_before_sp_hp_and_pinned(self):
        output = self._output()
        ledger, evidence, plan_sha = self._repair_evidence(output)
        budget = {'physical_max': 4, 'logical_max': 4, 'retries_max': 0,
                  'wall_seconds': 600, 'initial_starts_required': 2}
        ledger['budget'].update(budget)
        for index, role in enumerate(('sp_generation', 'function_analysis'), 3):
            ledger['turns'].append({'id': f'L{index:06d}', 'role': role,
                                    'status': 'COMPLETED', 'scope_id': 'function',
                                    'hash': 'a' * 64})
            ledger['attempts'].append({'status': 'COMPLETED',
                                       'scope_id': 'function'})
        ledger['logical'] = ledger['physical'] = 4
        (output / live.LEDGER_NAME).write_text(json.dumps(ledger))
        (output / 'MODEL_EVENTS.jsonl').write_text('{}\n')
        run = output / 'direction/product_runs/first'
        (run / 'sp').mkdir(parents=True)
        (run / 'scan.json').write_text('{}')
        (run / 'sp/candidates.json').write_text('[]')
        receipt = {'kind': live.KIND, 'status': 'PENDING_UNVERIFIED_DEV',
            'spec_sha256': 'b' * 64, 'global_budget': budget,
            'direction_evidence': evidence, 'direction_plan_sha256': plan_sha,
            'roles': [turn['role'] for turn in ledger['turns']],
            'phase1_run_relative': 'direction/product_runs/first',
            'scan_sha256': live.sha(run / 'scan.json'),
            'candidate_evidence': {'path': 'sp/candidates.json',
                'sha256': live.sha(run / 'sp/candidates.json'), 'sp_ids': []},
            'physical': 4, 'logical': 4, 'retries': 0,
            'ledger_sha256': live.sha(output / live.LEDGER_NAME),
            'model_events_sha256': live.sha(output / 'MODEL_EVENTS.jsonl'),
            'target_runs': 0, 'fuzz_seconds': 0,
            'vulnerability_verdict': 'NOT_EVALUATED'}
        (output / live.RECEIPT_NAME).write_text(json.dumps(receipt))
        child = {'status': 'BOUNDED_LIVE_COMPONENT_TRACE_RECORDED',
            'spec_sha256': 'b' * 64,
            'receipt_sha256': live.sha(output / live.RECEIPT_NAME),
            'ledger_sha256': receipt['ledger_sha256'],
            'model_events_sha256': receipt['model_events_sha256'],
            'physical': 4, 'logical': 4, 'retries': 0}
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        check = lambda: live._completion_predicate(child, fd, output,
            spec_sha256='b' * 64, budget=budget, direction_turn_cap=2)
        self.assertTrue(check())
        raw = output / 'direction/DIRECTION_REPAIR_RAW.txt'
        original = raw.read_bytes()
        raw.write_bytes(original + b'changed')
        self.assertFalse(check())
        raw.write_bytes(original)
        self.assertTrue(check())
        plan = output / 'direction/DIRECTION_PLAN.json'
        original_plan = plan.read_bytes()
        plan.write_text('[]')
        typed_receipt = dict(receipt)
        typed_receipt['direction_plan_sha256'] = live.sha(plan)
        self.assertFalse(live._direction_trace_ok(fd,
            json.loads((output / live.LEDGER_NAME).read_text()),
            typed_receipt, 2))
        plan.write_bytes(original_plan)
        self.assertFalse(live._completion_predicate(child, fd, output,
            spec_sha256='b' * 64, budget=budget, direction_turn_cap=1))

    def test_two_direction_turns_exhaust_function_credit_as_no_opportunity(self):
        output = self._output()
        ledger, evidence, plan_sha = self._repair_evidence(output)
        budget = {'physical_max': 2, 'logical_max': 2, 'retries_max': 0,
                  'wall_seconds': 600, 'initial_starts_required': 2}
        ledger['budget'].update(budget)
        spec = output / live.SPEC_NAME
        spec.write_text(json.dumps({'direction_graph_repair_max_turns': 2,
                                    'global_budget': budget}))
        spec_sha = live.sha(spec)
        (output / live.LEDGER_NAME).write_text(json.dumps(ledger))
        (output / 'MODEL_EVENTS.jsonl').write_text('{}\n')
        receipt = {'kind': live.KIND, 'status': 'NO_OPPORTUNITY_BUDGET',
            'spec_sha256': spec_sha, 'selected_function_id': 'function',
            'direction_evidence': evidence, 'direction_plan_sha256': plan_sha,
            'global_budget': budget,
            'roles': ['direction_generator', 'direction_generator'],
            'physical': 2, 'logical': 2, 'retries': 0,
            'ledger_sha256': live.sha(output / live.LEDGER_NAME),
            'model_events_sha256': live.sha(output / 'MODEL_EVENTS.jsonl'),
            'target_runs': 0, 'fuzz_seconds': 0,
            'vulnerability_verdict': 'NOT_EVALUATED'}
        (output / live.RECEIPT_NAME).write_text(json.dumps(receipt))
        child = {'status': 'NO_OPPORTUNITY_BUDGET',
            'spec_sha256': spec_sha,
            'receipt_sha256': live.sha(output / live.RECEIPT_NAME),
            'physical': 2, 'logical': 2, 'retries': 0}
        (output / live.CHILD_NAME).write_text(json.dumps(child))
        supervised = {'status': 'CHILD_EXITED_INCONCLUSIVE',
            'child_result': {'sha256': live.sha(output / live.CHILD_NAME)}}
        self.assertEqual(live._verified_component_status(output, spec_sha,
            supervised), ('NO_OPPORTUNITY_BUDGET',
                          'FUNCTION_START_CREDIT_UNAVAILABLE'))
        spec.write_text('{"direction_graph_repair_max_turns":1}')
        self.assertEqual(live._verified_component_status(output, spec_sha,
            supervised)[0], 'UNVERIFIED_CHILD_RESULT')

    def test_postcheck_rejects_mutated_repair_raw_before_ledger_restore(self):
        import blind3_md4c_live_direction_sp_hp_dev as flow
        output = self._output()
        _, evidence, plan_sha = self._repair_evidence(output)
        folder = output / 'direction'
        (folder / 'DIRECTION_INPUT_PINS.json').write_text('{}')
        run = folder / 'product_runs/first'
        run.mkdir(parents=True)
        (run / 'direction_plan.json').write_bytes(
            (folder / 'DIRECTION_PLAN.json').read_bytes())
        direction = {**evidence, 'direction_plan_sha256': plan_sha,
            'source_pins_sha256': live.sha(folder / 'DIRECTION_INPUT_PINS.json'),
            'phase1_run': str(run)}
        (folder / 'DIRECTION_PHASE1_RESULT.json').write_text(json.dumps(direction))
        (folder / 'DIRECTION_REPAIR_RAW.txt').write_text('{"tampered":true}')
        with patch.object(flow, '_official_preflight'):
            with self.assertRaisesRegex(ValueError, 'Direction stored request'):
                flow._postcheck(folder, folder, folder, folder, folder, None,
                                'all_catalog_prefix', direction, None, None, [])

    def test_one_credit_is_no_opportunity_and_two_credits_preserve_pending(self):
        from dev_global_request_ledger import DevelopmentRequestLedger
        for cap in (1, 2):
            with self.subTest(cap=cap):
                output = self._output()
                ledger = DevelopmentRequestLedger.create(live._budget({
                    'physical_max': cap, 'logical_max': cap, 'retries_max': 0,
                    'wall_seconds': 60, 'initial_starts_required': 1,
                }), output / 'GLOBAL_LEDGER.json')
                ledger.register_direction('scope')
                ledger.begin_turn('scope', 'direction_generator', 'a' * 64)
                ledger.start_attempt('a' * 64)
                ledger.finish_attempt(completed=True, accepted=True,
                                      response_saved=True)
                selected = ledger.select_function('function')
                self.assertEqual(selected, cap == 2)
                if cap == 1:
                    self.assertEqual(ledger.no_opportunity['function'],
                                     'NO_OPPORTUNITY_BUDGET')
                    continue
                ledger.begin_turn('function', 'sp_generation', 'b' * 64)
                ledger.start_attempt('b' * 64)
                ledger.finish_attempt(completed=True, accepted=True,
                                      response_saved=True)
                from dev_global_request_ledger import DevelopmentBudgetExhausted
                with self.assertRaises(DevelopmentBudgetExhausted):
                    ledger.begin_turn('function', 'function_analysis', 'c' * 64)
                self.assertEqual(ledger.physical, 2)
                self.assertEqual(ledger.logical, 2)
                from dev_global_appserver_product_flow import (
                    DevelopmentBudgetStop, ProductBudgetAdapter)
                from vulnerabilityanalysis.llm import LLMRequest
                class NoCreditBackend:
                    scope_id = 'function'
                    model = 'fake'
                    effort = 'low'
                    async def generate(self, request):
                        raise DevelopmentBudgetExhausted('scripted prewire cap')
                adapter = ProductBudgetAdapter(NoCreditBackend(), ledger,
                                               'function')
                request = LLMRequest('function_analysis', 'synthetic', {}, {},
                                     model='fake', effort='low')
                with self.assertRaises(DevelopmentBudgetStop):
                    asyncio.run(adapter.generate(request))
                self.assertEqual(adapter.rejected_prewire['physical_delta'], '0')
                self.assertEqual(ledger.function_states['function'],
                                 'INCOMPLETE_BUDGET')
                self.assertEqual(ledger.pending_work[-1]['state'], 'PENDING_BUDGET')

    def test_direct_live_entry_is_rejected_without_source_bootstrap(self):
        with self.assertRaisesRegex(ValueError, 'external source pin'):
            live._require_external_source_pin()

    def test_changed_code_pin_rejects_before_helper_import_side_effect(self):
        output = self._output()
        spec = output / live.SPEC_NAME
        spec.write_text(json.dumps({
            'driver_sha256': live.sha(Path(live.__file__)),
            'base_supervisor_sha256': live.sha(live.SUPERVISOR),
            'direction_boundary_sha256': live.sha(live.DIRECTION),
            'code_pins': {'evaluation_tools': '0' * 64},
        }))
        with patch.object(live, '_base', side_effect=AssertionError(
                'helper import side effect reached')):
            with self.assertRaisesRegex(ValueError, 'pre-import'):
                live.load_spec(spec, live.sha(spec))

    def test_child_cache_must_be_empty_before_import(self):
        output = self._output()
        cache = output / 'child_pycache'
        cache.mkdir(mode=0o700)
        (cache / 'stale.pyc').write_bytes(b'stale')
        with self.assertRaisesRegex(ValueError, 'cache changed'):
            live._fresh_import_cache(child_output=output)

    def test_model_tool_event_still_fails_closed(self):
        from dev_global_request_ledger import DevelopmentRequestLedger
        from dev_global_appserver_bridge import verify_model_event_order
        output = self._output()
        ledger = DevelopmentRequestLedger.create(live._budget({
            'physical_max': 1, 'logical_max': 1, 'retries_max': 0,
            'wall_seconds': 60, 'initial_starts_required': 1}),
            output / 'GLOBAL_LEDGER.json')
        events = output / 'MODEL_EVENTS.jsonl'
        events.write_text(json.dumps({'method': 'item/started',
            'server_request': False, 'item_type': 'commandExecution',
            'thread_id': 't', 'turn_id': 'x',
            'params': {'threadId': 't', 'turnId': 'x',
                       'item': {'type': 'commandExecution'}}}) + '\n')
        with self.assertRaisesRegex(ValueError, 'tool or server request'):
            verify_model_event_order(ledger, events)

    def test_scripted_child_hard_wall_and_cleanup_stop_receipt(self):
        for outcome, expected in [('timeout', 'STOPPED_WALL_LIMIT'),
                                  ('cleanup_failed', 'STOPPED_CLEANUP_INCOMPLETE')]:
            with self.subTest(outcome=outcome):
                output = self._output()
                runner = FakeRunner(outcome)
                row = base.supervise_command(
                    ['/scripted/fake-child'], output, wall_seconds=0.02,
                    runner=runner, spec_sha256='a' * 64)
                self.assertEqual(row['status'], expected)
                self.assertTrue(runner.cleaned)
                self.assertTrue(runner.killed)
                self.assertEqual(runner.child.wait_deadlines[0], 0.02)
                saved = json.loads((output / base.RESULT_NAME).read_text())
                self.assertEqual(saved['status'], expected)

    def test_parent_requires_receipt_ledger_and_event_bytes(self):
        output = self._output()
        spec_sha = 'a' * 64
        budget = {'physical_max': 12, 'logical_max': 10,
                  'retries_max': 2, 'wall_seconds': 600,
                  'initial_starts_required': 2}
        ledger = {'kind': 'DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1',
                  'budget': {**budget, 'profile': 'GLOBAL_ONLY_DEV'},
                  'physical': 3, 'logical': 3, 'retries': 0,
                  'active_turn': None,
                  'turns': [{'role': role, 'status': 'COMPLETED'} for role in
                      ('direction_generator', 'sp_generation',
                       'function_analysis')],
                  'attempts': [{'status': 'COMPLETED'}] * 3}
        events = b'{"method":"turn/completed"}\n'
        ledger_bytes = json.dumps(ledger).encode()
        (output / live.LEDGER_NAME).write_bytes(ledger_bytes)
        (output / 'MODEL_EVENTS.jsonl').write_bytes(events)
        run = output / 'direction/product_runs/first'
        run.mkdir(parents=True)
        (run / 'scan.json').write_text('{}')
        (run / 'sp').mkdir()
        (run / 'sp/candidates.json').write_text('[]')
        receipt = {'kind': live.KIND, 'status': 'PENDING_UNVERIFIED_DEV',
                   'spec_sha256': spec_sha, 'global_budget': budget,
                   'vulnerability_verdict': 'NOT_EVALUATED',
                   'target_runs': 0, 'fuzz_seconds': 0,
                   'phase1_run_relative': 'direction/product_runs/first',
                   'scan_sha256': live.sha(run / 'scan.json'),
                   'candidate_evidence': {'path': 'sp/candidates.json',
                      'sha256': live.sha(run / 'sp/candidates.json'),
                      'sp_ids': []},
                   'ledger_sha256': live.sha_bytes(ledger_bytes),
                   'model_events_sha256': live.sha_bytes(events),
                   'physical': 3, 'logical': 3, 'retries': 0}
        receipt_bytes = json.dumps(receipt).encode()
        (output / live.RECEIPT_NAME).write_bytes(receipt_bytes)
        child = {'status': 'BOUNDED_LIVE_COMPONENT_TRACE_RECORDED',
                 'spec_sha256': spec_sha,
                 'receipt_sha256': live.sha_bytes(receipt_bytes),
                 'ledger_sha256': receipt['ledger_sha256'],
                 'model_events_sha256': receipt['model_events_sha256'],
                 'physical': 3, 'logical': 3, 'retries': 0}
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        check = lambda: live._completion_predicate(
            child, fd, output, spec_sha256=spec_sha, budget=budget)
        self.assertTrue(check())
        (output / 'MODEL_EVENTS.jsonl').write_bytes(events + b'changed')
        self.assertFalse(check())
        (output / 'MODEL_EVENTS.jsonl').write_bytes(events)
        (run / 'scan.json').write_text('{"tampered":true}')
        self.assertFalse(check())
        (run / 'scan.json').write_text('{}')
        ledger['tainted'] = False  # Not part of the persisted schema.
        (output / live.LEDGER_NAME).write_text(json.dumps(ledger))
        self.assertFalse(check())

    def test_stop_receipt_keeps_primary_error_and_no_success(self):
        output = self._output()
        class Ledger:
            physical = 2
            logical = 2
        live._stop(output, Ledger(), RuntimeError('scripted model audit failure'))
        row = json.loads((output / live.STOP_NAME).read_text())
        self.assertEqual(row['error_type'], 'RuntimeError')
        self.assertEqual(row['status'], 'STOPPED')
        self.assertEqual(row['physical'], 2)
        self.assertEqual(row['vulnerability_verdict'], 'NOT_EVALUATED')
        self.assertFalse((output / live.RECEIPT_NAME).exists())

    def test_verified_no_opportunity_is_visible_but_not_supervisor_success(self):
        output = self._output()
        (output / live.SPEC_NAME).write_text('{}')
        spec_sha = live.sha(output / live.SPEC_NAME)
        ledger = {'kind': 'DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1',
            'physical': 1, 'logical': 1, 'retries': 0,
            'active_turn': None,
            'turns': [{'role': 'direction_generator', 'status': 'COMPLETED'}],
            'attempts': [{'status': 'COMPLETED'}],
            'selected_functions': [],
            'no_opportunity': {'fn': 'NO_OPPORTUNITY_BUDGET'}}
        (output / live.LEDGER_NAME).write_text(json.dumps(ledger))
        (output / 'MODEL_EVENTS.jsonl').write_text('{}\n')
        receipt = {'kind': live.KIND, 'status': 'NO_OPPORTUNITY_BUDGET',
            'spec_sha256': spec_sha, 'selected_function_id': 'fn',
            'physical': 1, 'logical': 1, 'retries': 0,
            'ledger_sha256': live.sha(output / live.LEDGER_NAME),
            'model_events_sha256': live.sha(output / 'MODEL_EVENTS.jsonl'),
            'target_runs': 0, 'fuzz_seconds': 0,
            'vulnerability_verdict': 'NOT_EVALUATED'}
        (output / live.RECEIPT_NAME).write_text(json.dumps(receipt))
        child = {'status': 'NO_OPPORTUNITY_BUDGET',
            'spec_sha256': spec_sha,
            'receipt_sha256': live.sha(output / live.RECEIPT_NAME),
            'physical': 1, 'logical': 1, 'retries': 0}
        (output / live.CHILD_NAME).write_text(json.dumps(child))
        supervised = {'status': 'CHILD_EXITED_INCONCLUSIVE',
            'child_result': {'sha256': live.sha(output / live.CHILD_NAME)}}
        self.assertEqual(live._verified_component_status(output, spec_sha,
            supervised), ('NO_OPPORTUNITY_BUDGET',
                          'FUNCTION_START_CREDIT_UNAVAILABLE'))
        receipt['selected_function_id'] = 'other'
        (output / live.RECEIPT_NAME).write_text(json.dumps(receipt))
        self.assertEqual(live._verified_component_status(output, spec_sha,
            supervised)[0], 'UNVERIFIED_CHILD_RESULT')

    def test_supervised_return_keeps_inconclusive_and_adds_component_status(self):
        output = self._output()
        spec = output / live.SPEC_NAME
        spec.write_text('{}')
        identity = output.stat()
        row = {'output_dir': str(output), 'python_path': '/usr/bin/python3.12',
               'driver_sha256': 'a' * 64,
               'global_budget': {'wall_seconds': 60},
               'output_identity': {'dev': identity.st_dev, 'ino': identity.st_ino}}
        generic = {'status': 'CHILD_EXITED_INCONCLUSIVE',
                   'child_result': {'sha256': None},
                   'physical_ledger': {'sha256': None}}
        def fake_supervise(*args, **kwargs):
            base._write_once(output / base.RESULT_NAME, generic)
            return generic
        with (patch.object(live, '_require_external_source_pin'),
              patch.object(live, 'load_spec', return_value=row),
              patch.object(live, '_contract_routes',
                           return_value=({}, None, None, {})),
              patch.object(base, '_route_pinned_codex'),
              patch.object(base, '_imports',
                           return_value=(object(), None, None, None, None)),
              patch.object(base, 'supervise_command', side_effect=fake_supervise),
              patch.object(live, '_verified_component_status',
                           return_value=('NO_OPPORTUNITY_BUDGET',
                               'FUNCTION_START_CREDIT_UNAVAILABLE'))):
            result = live.run_supervised(spec, 'a' * 64)
        self.assertEqual(result['status'], 'CHILD_EXITED_INCONCLUSIVE')
        self.assertEqual(result['component_status'], 'NO_OPPORTUNITY_BUDGET')
        supplement = json.loads((output / live.SUPERVISION_NAME).read_text())
        self.assertEqual(supplement['supervisor_status'],
                         'CHILD_EXITED_INCONCLUSIVE')
        self.assertEqual(supplement['component_status'],
                         'NO_OPPORTUNITY_BUDGET')
        self.assertIsNone(supplement['model_events']['sha256'])

    def test_verified_prewire_budget_stop_is_pending_not_complete(self):
        output = self._output()
        (output / live.SPEC_NAME).write_text('{}')
        spec_sha = live.sha(output / live.SPEC_NAME)
        ledger = {'kind': 'DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1',
            'physical': 2, 'logical': 2, 'retries': 0,
            'active_turn': None,
            'turns': [{'role': role, 'status': 'COMPLETED'} for role in
                      ('direction_generator', 'sp_generation')],
            'attempts': [{'status': 'COMPLETED'}] * 2,
            'selected_functions': ['fn'],
            'pending_work': [{'state': 'PENDING_BUDGET'}]}
        (output / live.LEDGER_NAME).write_text(json.dumps(ledger))
        (output / 'MODEL_EVENTS.jsonl').write_text('{}\n')
        receipt = {'kind': live.KIND, 'status': 'PENDING_BUDGET',
            'spec_sha256': spec_sha, 'physical': 2, 'logical': 2, 'retries': 0,
            'ledger_sha256': live.sha(output / live.LEDGER_NAME),
            'model_events_sha256': live.sha(output / 'MODEL_EVENTS.jsonl'),
            'budget_stopped': True,
            'rejected_prewire': {'role': 'function_analysis',
                                 'physical_delta': '0'},
            'candidate_evidence': {'path': None, 'sha256': None, 'sp_ids': []},
            'target_runs': 0, 'fuzz_seconds': 0,
            'vulnerability_verdict': 'NOT_EVALUATED'}
        (output / live.RECEIPT_NAME).write_text(json.dumps(receipt))
        child = {'status': 'BOUNDED_LIVE_COMPONENT_TRACE_RECORDED',
            'spec_sha256': spec_sha,
            'receipt_sha256': live.sha(output / live.RECEIPT_NAME),
            'physical': 2, 'logical': 2, 'retries': 0}
        (output / live.CHILD_NAME).write_text(json.dumps(child))
        supervised = {'status': 'CHILD_EXITED_INCONCLUSIVE',
            'child_result': {'sha256': live.sha(output / live.CHILD_NAME)}}
        self.assertEqual(live._verified_component_status(output, spec_sha,
            supervised), ('PENDING_BUDGET',
                          'GLOBAL_MODEL_REQUEST_CREDIT_EXHAUSTED'))
        receipt['rejected_prewire'] = None
        (output / live.RECEIPT_NAME).write_text(json.dumps(receipt))
        self.assertEqual(live._verified_component_status(output, spec_sha,
            supervised)[0], 'UNVERIFIED_CHILD_RESULT')

    def test_archived_v4_evidence_read_only_without_status_change(self):
        output = (live.ROOT / 'review/DEV_LIVE_FULL_CANDIDATE_PREP_20261030_v4')
        if not (output / live.RECEIPT_NAME).is_file():
            self.skipTest('archived v4 development receipt unavailable')
        paths = [output / name for name in (
            live.LEDGER_NAME, live.RECEIPT_NAME, live.CHILD_NAME,
            'MODEL_EVENTS.jsonl', base.RESULT_NAME, live.SUPERVISION_NAME)]
        before = {path.name: live.sha(path) for path in paths}
        receipt = json.loads((output / live.RECEIPT_NAME).read_text())
        child = json.loads((output / live.CHILD_NAME).read_text())
        supervisor = json.loads((output / base.RESULT_NAME).read_text())
        self.assertEqual(supervisor['status'], 'CHILD_EXITED_INCONCLUSIVE')
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.assertTrue(live._completion_predicate(child, fd, output,
                spec_sha256=receipt['spec_sha256'],
                budget=receipt['global_budget']))
        finally:
            os.close(fd)
        # The old supervisor verdict stays INCONCLUSIVE. Reassessment is
        # separate audit evidence, never a retroactive promotion.
        self.assertEqual(live._verified_component_status(
            output, receipt['spec_sha256'], supervisor),
            ('UNVERIFIED_CHILD_RESULT', 'RECEIPT_MISMATCH'))
        for change in ({'status': 'CHILD_ERROR', 'return_code': 17},
                       {'cleanup_incomplete': True},
                       {'output_identity_ok': False}):
            with self.subTest(change=change):
                altered = {**supervisor, **change}
                self.assertNotEqual(live._verified_component_status(
                    output, receipt['spec_sha256'], altered)[0],
                    'PENDING_UNVERIFIED_DEV')
        self.assertEqual(before, {path.name: live.sha(path) for path in paths})


if __name__ == '__main__':
    unittest.main()
