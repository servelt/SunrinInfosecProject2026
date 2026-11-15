from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

ENGINE = Path('/home/dawne/work/SunrinInfosecProject2026/fbv2_hp_integration')
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
EVAL = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027/evaluation_tools')
for path in (ENGINE, PRODUCT, EVAL):
    sys.path.insert(0, str(path))

import mongomock
from bson import ObjectId
from fuzzingbrain.core.models import POV, SPStatus, SuspiciousPoint
from fuzzingbrain.db.repository import RepositoryManager
from fuzzingbrain.tools.qualified_runtime import QualifiedRuntimeRequest
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
task_id, sp_id, pov_id = map(lambda _: str(ObjectId()), range(3))
repos = RepositoryManager(mongomock.MongoClient().controlled_pov_gate)
point = SuspiciousPoint(suspicious_point_id=sp_id, task_id=task_id,
                        function_name='md_collect_marks',
                        status=SPStatus.PENDING_POV.value, score=0.9,
                        sources=[{'harness_name':'fuzz-mdhtml', 'sanitizer':'address'}])
assert repos.suspicious_points.save(point)
assert repos.suspicious_points.claim_for_pov(
    task_id, 'controlled_pov_agent', harness_name='fuzz-mdhtml', sanitizer='address')
assert repos.povs.save(POV(pov_id=pov_id, task_id=task_id,
                           suspicious_point_id=sp_id, harness_name='fuzz-mdhtml',
                           sanitizer='address', blob=base64.b64encode(input_bytes).decode()))
assert repos.povs.collection.update_one(
    {'_id':ObjectId(pov_id)}, {'$set':{'qualified_runtime':{
        'status':'STARTED','input_sha256':input_sha,
        'binary_sha256':q.binary_sha256}}}).modified_count == 1
ledger = PersistentProcessLedgerV2.create(
    root/'process-ledger.json', wall_total_seconds=300, fuzz_total_seconds=0)
adapter = ProductQualifiedPoVAdapter(
    qualification=q, repos=repos, task_id=task_id, work_item_id=task_id,
    run_id=run_id, fuzzer='fuzz-mdhtml', sanitizer='address', ledger=ledger,
    output_dir=root/'pov-runtime', timeout_seconds=3, wall_seconds=180,
    output_limit_bytes=4000000)
request = QualifiedRuntimeRequest(
    task_id=task_id, suspicious_point_id=sp_id, pov_id=pov_id,
    harness_name='fuzz-mdhtml', sanitizer='address', input_bytes=input_bytes,
    input_sha256=input_sha, binary_path=q.binary, binary_sha256=q.binary_sha256)
observed = adapter.execute(request)
assert observed.status == 'CRASH_OBSERVED'
assert repos.povs.collection.update_one(
    {'_id':ObjectId(pov_id), 'qualified_runtime.status':'STARTED'},
    {'$set':{'qualified_runtime':{
        'status':observed.status,'input_sha256':observed.input_sha256,
        'binary_sha256':observed.binary_sha256,
        'runtime_receipt_path':str(observed.runtime_receipt_path),
        'runtime_receipt_sha256':observed.runtime_receipt_sha256,
        'physical_receipt_path':str(observed.physical_receipt_path),
        'physical_receipt_sha256':observed.physical_receipt_sha256,
        'sanitizer':observed.sanitizer}}}).modified_count == 1

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
    'observed_runtime_status':observed.status,
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
