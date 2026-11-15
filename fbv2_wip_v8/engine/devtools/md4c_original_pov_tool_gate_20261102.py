from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
from uuid import uuid4

ENGINE = Path('/home/dawne/work/SunrinInfosecProject2026/fbv2_hp_integration')
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
EVAL = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027/evaluation_tools')
for path in (ENGINE, PRODUCT, EVAL):
    sys.path.insert(0, str(path))

import mongomock
from bson import ObjectId
from fuzzingbrain.core.models import SPStatus, SuspiciousPoint
from fuzzingbrain.db.repository import RepositoryManager
from fuzzingbrain.tools.pov import (
    clear_pov_context, create_pov_impl, set_pov_context)
from vulnerabilityanalysis.official_harness import issue_official_pinned_qualification, _qualification_pins_ok
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from devtools.product_qualified_runtime import ProductQualifiedPoVAdapter, consume_qualified_pov_observation

spec = json.loads(Path('/tmp/fbv2-public-md4c-v3.json').read_text())
contract_path = Path(spec['admission']['contract_path'])
contract = json.loads(contract_path.read_text())
local, target = contract['local'], contract['target']
q = issue_official_pinned_qualification(
    contract_path=contract_path,
    approved_contract_sha256=spec['admission']['contract_sha256'],
    source_root=Path(target['source_root']),
    harness=Path(local['harness_file']), binary=Path(local['binary']),
    normal_seed=Path(local['normal_seed']),
    oss_fuzz_checkout=Path(spec['admission']['oss_fuzz_checkout']),
    upstream_checkout=Path(spec['admission']['upstream_checkout']))
assert q is not None and _qualification_pins_ok(q)
input_path = ENGINE / 'documentation/md4c_oob_retained_input_20261101.bin'
input_bytes = input_path.read_bytes()
input_sha = hashlib.sha256(input_bytes).hexdigest()
assert input_sha == '9de288250d625a75471a2da8f876d22472f871190eec592664fcd201130d5613'
root = Path(tempfile.mkdtemp(prefix='fbv2-pov-product-gate-controlled-'))
run_id = 'controlled' + uuid4().hex
task_id, sp_id = map(lambda _: str(ObjectId()), range(2))
repos = RepositoryManager(mongomock.MongoClient().controlled_pov_gate)
point = SuspiciousPoint(suspicious_point_id=sp_id, task_id=task_id,
                        function_name='md_collect_marks',
                        status=SPStatus.PENDING_POV.value, score=0.9,
                        sources=[{'harness_name':'fuzz-mdhtml', 'sanitizer':'address'}])
assert repos.suspicious_points.save(point)
assert repos.suspicious_points.claim_for_pov(
    task_id, 'controlled_pov_agent', harness_name='fuzz-mdhtml', sanitizer='address')
ledger = PersistentProcessLedgerV2.create(
    root/'process-ledger.json', wall_total_seconds=300, fuzz_total_seconds=0)
adapter = ProductQualifiedPoVAdapter(
    qualification=q, repos=repos, task_id=task_id, work_item_id=task_id,
    run_id=run_id, fuzzer='fuzz-mdhtml', sanitizer='address', ledger=ledger,
    output_dir=root/'pov-runtime', timeout_seconds=3, wall_seconds=180,
    output_limit_bytes=4000000)
worker_id = str(ObjectId())
set_pov_context(
    task_id=task_id, worker_id=worker_id, output_dir=root/'generated',
    repos=repos, fuzzer='fuzz-mdhtml', sanitizer='address',
    suspicious_point_id=sp_id, fuzzer_path=q.binary, agent_id=worker_id,
    qualified_runtime_required=True, qualified_runtime_binding=adapter.binding)
try:
    with patch('fuzzingbrain.tools.pov._execute_generator_code',
               return_value=([input_bytes], None)):
        generated = create_pov_impl(
            'def generate(variant): return b"controlled existing input"',
            worker_id=worker_id)
finally:
    clear_pov_context(worker_id)
assert generated['success'] is True and generated['count'] == 1
assert generated['runtime_status'] == 'PENDING_INDEPENDENT_VALIDATION'
pov_id = generated['pov_ids'][0]
observed = json.loads((adapter.root/pov_id/'runtime.json').read_text())
assert observed['status'] == 'CRASH_OBSERVED'

def recheck():
    if not _qualification_pins_ok(q):
        raise ValueError('official qualification drift')
row = consume_qualified_pov_observation(adapter, pov_id, recheck=recheck,
                                        timeout_seconds=3)
assert _qualification_pins_ok(q)
state, receipt_sha = ledger.receipt_snapshot()
report = {
    'kind':'CONTROLLED_PREEXISTING_FBV2_POV_TO_PRODUCT_GATE_NOT_AUTO_DISCOVERY',
    'run_id':run_id,'task_id':task_id,'sp_id':sp_id,'pov_id':pov_id,
    'input_sha256':input_sha,'binary_sha256':q.binary_sha256,
    'source_tree_sha256':q.source_tree_sha256,
    'harness_sha256':q.harness_sha256,
    'contract_sha256':q.contract_sha256,
    'review_sha256':q.review_sha256,
    'upstream_revision':q.upstream_revision,
    'source_root':str(q.source_root),'harness_path':str(q.harness),
    'observed_runtime_status':observed['status'],
    'original_pov_tool_result':generated,
    'gate_outcome':row,'physical_finished':len(state['finished']),
    'physical_active':len(state['active']),
    'physical_wall_seconds':state['wall_spent_seconds'],
    'process_stop_status':state['stop_status'],
    'process_ledger_receipt_sha256':receipt_sha,
    'model_calls':0,'new_fuzzing':False,'automatic_discovery':False,
}
(root/'CONTROLLED_RESULT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
print(json.dumps({'run_dir':str(root),'gate_status':row['product_gate_status'],
                  'physical_finished':len(state['finished']),
                  'physical_wall_seconds':state['wall_spent_seconds']}))
