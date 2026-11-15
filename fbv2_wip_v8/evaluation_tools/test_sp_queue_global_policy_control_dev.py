"""Provider-free public control for the two opt-in SP queue policies.

The two arms use the product Scan, the same synthetic Generator response,
the same ordering, and the same global physical/logical cap.  This measures
opportunity accounting only; it does not measure bug detection.
"""

from __future__ import annotations

import asyncio
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

from dev_global_request_ledger import (  # noqa: E402
    DevelopmentBudget, DevelopmentRequestLedger, GLOBAL_ONLY_DEV_PROFILE,
)
from dev_global_ledger_product_flow import request_sha  # noqa: E402
from test_direction_plan import fixture  # noqa: E402
from test_external_global_scan_budget_dev import _Qualification  # noqa: E402
from test_sp_queue_drain_dev import _DuplicateProvider  # noqa: E402
from vulnerabilityanalysis.agents import AgentPipeline  # noqa: E402
from vulnerabilityanalysis.models import VerificationResult  # noqa: E402
from vulnerabilityanalysis.scan import scan_selected  # noqa: E402
from vulnerabilityanalysis.workflow import run_phase1  # noqa: E402


class _TwoCandidateProvider(_DuplicateProvider):
    def __init__(self, ledger: DevelopmentRequestLedger, function_id: str,
                 *, opposite: bool):
        super().__init__(candidate_count=2)
        self.ledger = ledger
        self.scope_id = function_id
        self.backend = SimpleNamespace(
            ledger=ledger, scope_id=function_id,
            _request=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError('App Server is forbidden in this control')))
        self.opposite = opposite

    async def generate(self, request):
        digest = request_sha(request)
        self.ledger.begin_turn(self.scope_id, request.role, digest)
        self.ledger.start_attempt(digest)
        self.calls.append(request.role)
        try:
            if request.role == 'sp_generation':
                response = await _DuplicateProvider.generate(self, request)
                if self.opposite:
                    # Same location and bug class, different causal order.
                    # Product dedup must keep both for either policy.
                    second = response['suspicious_points'][1]
                    second['required_state'] = ['ptr read before freed']
                    second['trigger_conditions'] = ['ptr read before freed']
            elif request.role == 'sp_verifier':
                response = {}
            else:
                raise AssertionError(f'unexpected role {request.role}')
        except BaseException as exc:
            self.ledger.finish_attempt(completed=False, error=str(exc))
            self.ledger.abandon_turn(type(exc).__name__)
            raise
        self.ledger.finish_attempt(completed=True)
        return response


async def _refute_with_public_request(self, point, *_args, **_kwargs):
    await self.provider.generate(SimpleNamespace(
        role='sp_verifier', instructions='public toy accounting control',
        payload={'sp_id': point.sp_id}, output_schema={},
        model='scripted', effort='none'))
    self.last_request_count = 1
    point.status = 'REFUTED'
    point.status_history.append('REFUTED')
    self.verifications[point.sp_id] = VerificationResult(
        point.sp_id, 'UNKNOWN', 'UNKNOWN', [], [], [], [], [],
        'REFUTED', 'REFUTE', 'public control response; no target evidence')
    return point


def _run_arm(root: Path, policy: str, *, opposite: bool) -> dict:
    root.mkdir(parents=True)
    artifact, repo, plan = fixture(root)
    run = run_phase1(artifact, repo / 'runs', target_repository=repo,
                     direction_plan=plan,
                     selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV')
    function_id = json.loads((run / 'selection.json').read_text())['function_id']
    binary = repo / 'target.bin'
    binary.write_bytes(b'public synthetic binary; never executed\n')
    qualification = _Qualification(repo, repo / 'fuzz.c', binary)
    budget = DevelopmentBudget(
        physical_max=3, logical_max=3, retries_max=0, wall_seconds=60,
        initial_starts_required=1, profile=GLOBAL_ONLY_DEV_PROFILE)
    ledger = DevelopmentRequestLedger.create(budget, root / 'LEDGER.json')
    ledger.register_direction('public-control-direction')
    if not ledger.select_function(function_id):
        raise AssertionError('public function was not selected')
    provider = _TwoCandidateProvider(ledger, function_id, opposite=opposite)
    with (patch('vulnerabilityanalysis.scan.OfficialPinnedQualification', _Qualification),
          patch('vulnerabilityanalysis.scan._official_pin_matches_qualification',
                return_value=True),
          patch.object(AgentPipeline, 'verify_sp', _refute_with_public_request),
          patch('vulnerabilityanalysis.scan.execute_poc',
                side_effect=AssertionError('Target execution is forbidden in this control'))):
        asyncio.run(scan_selected(
            run, provider, target_repository=repo, target_binary=binary,
            official_qualification=qualification, external_turn_budget=ledger,
            candidate_budget_policy=policy, max_candidates=1,
            targeted_fuzz_seconds=0, global_fuzz_enabled=False,
            hallucination_prevent='off'))
    scan = json.loads((run / 'scan.json').read_text())
    candidate_rows = json.loads((run / 'sp/candidates.json').read_text())
    dedup_rows = json.loads((run / 'sp/dedup_relations.json').read_text())
    return {
        'policy': policy,
        'candidate_ids': [row['sp_id'] for row in candidate_rows],
        'roles': [row['role'] for row in ledger.turns],
        'logical': ledger.logical,
        'physical': ledger.physical,
        'global_cap': ledger.budget.logical_max,
        'selected_ids': scan['selected_sp_ids'],
        'pending_ids': scan['pending_sp_ids'],
        'deduplicated_ids': scan['deduplicated_sp_ids'],
        'duplicate_relation_ids': sorted(row['sp_id'] for row in dedup_rows),
        'queue_status': scan.get('sp_queue_status', {}),
        'verified_status': scan['sp_verification_status'],
        'poc_count': scan['poc_count'],
        'ledger_kind': json.loads((root / 'LEDGER.json').read_text())['kind'],
        'ledger_turn_status': [row['status'] for row in ledger.turns],
        'ledger_attempt_status': [row['status'] for row in ledger.attempts],
    }


class SpQueueGlobalPolicyControlTest(unittest.TestCase):
    def test_same_cause_exposes_accounting_difference_without_claiming_benefit(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            drain = _run_arm(root / 'drain', 'DRAIN_RANKED_DEV', opposite=False)
            queue = _run_arm(root / 'queue', 'QUEUE_FIRST_DEV', opposite=False)
        self.assertEqual(drain['candidate_ids'], queue['candidate_ids'])
        self.assertEqual(drain['global_cap'], queue['global_cap'])
        self.assertEqual(len(drain['duplicate_relation_ids']), 1)
        self.assertEqual(drain['duplicate_relation_ids'], queue['duplicate_relation_ids'])
        self.assertEqual(drain['roles'], ['sp_generation', 'sp_verifier'])
        self.assertEqual(queue['roles'], ['sp_generation', 'sp_verifier', 'sp_verifier'])
        self.assertEqual((drain['logical'], drain['physical']), (2, 2))
        self.assertEqual((queue['logical'], queue['physical']), (3, 3))
        for arm in (drain, queue):
            self.assertEqual(arm['ledger_kind'],
                             'DEV_GLOBAL_REQUEST_LEDGER_GLOBAL_ONLY_V1')
            self.assertEqual(arm['ledger_attempt_status'],
                             ['COMPLETED'] * arm['physical'])
            self.assertEqual(arm['ledger_turn_status'],
                             ['COMPLETED'] * arm['logical'])
        self.assertEqual(len(drain['deduplicated_ids']), 1)
        self.assertEqual(queue['deduplicated_ids'], [])
        self.assertEqual(len(drain['selected_ids']), 1)
        self.assertEqual(len(queue['selected_ids']), 2)
        self.assertEqual((drain['poc_count'], queue['poc_count']), (0, 0))

    def test_opposite_cause_is_not_deduplicated_by_either_policy(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            drain = _run_arm(root / 'drain', 'DRAIN_RANKED_DEV', opposite=True)
            queue = _run_arm(root / 'queue', 'QUEUE_FIRST_DEV', opposite=True)
        self.assertEqual(drain['candidate_ids'], queue['candidate_ids'])
        self.assertEqual(drain['duplicate_relation_ids'], [])
        self.assertEqual(queue['duplicate_relation_ids'], [])
        self.assertEqual(drain['roles'], queue['roles'])
        self.assertEqual(drain['roles'], ['sp_generation', 'sp_verifier', 'sp_verifier'])
        self.assertEqual((drain['logical'], drain['physical']), (3, 3))
        self.assertEqual((queue['logical'], queue['physical']), (3, 3))
        self.assertEqual(drain['selected_ids'], queue['selected_ids'])


if __name__ == '__main__':
    unittest.main()
