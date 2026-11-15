from pathlib import Path
import json, tempfile, hashlib
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from vulnerabilityanalysis.models import PoC, SuspiciousPoint
from vulnerabilityanalysis.official_harness import issue_official_pinned_qualification, _qualification_pins_ok
from vulnerabilityanalysis.scan import execute_poc
spec=json.loads(Path('/tmp/fbv2-public-md4c-v3.json').read_text())
contract_path=Path(spec['admission']['contract_path'])
contract=json.loads(contract_path.read_text())
local,target=contract['local'],contract['target']
q=issue_official_pinned_qualification(contract_path=contract_path,approved_contract_sha256=spec['admission']['contract_sha256'],source_root=Path(target['source_root']),harness=Path(local['harness_file']),binary=Path(local['binary']),normal_seed=Path(local['normal_seed']),oss_fuzz_checkout=Path(spec['admission']['oss_fuzz_checkout']),upstream_checkout=Path(spec['admission']['upstream_checkout']))
assert q is not None and _qualification_pins_ok(q)
root=Path(tempfile.mkdtemp(prefix='md4c-manual-uaf-product-'))
(root/'run.json').write_text(json.dumps({'run_id':root.name,'automatic_discovery':False},sort_keys=True)+'\n')
ledger=PersistentProcessLedgerV2.create(root/'process-ledger.json',wall_total_seconds=90,fuzz_total_seconds=0)
def pin_hook(phase,command):
    if not _qualification_pins_ok(q):
        raise ValueError('pin changed')
envelope=DevelopmentProcessEnvelopeV2(ledger,work_item_id='manual-uaf-control',assertion_id='manual-uaf-sp',attempt_id=root.name,output_limit_bytes=4_000_000,total_wall_seconds=90,pin_hook=pin_hook)
point=SuspiciousPoint(sp_id='manual-uaf-sp',worker_id='MANUAL_CONTROL',direction_id='MANUAL_CONTROL',function_name='md_consume_link_reference_definitions',source_file='src/md4c.c',code_location='src/md4c.c:5887',suspicious_operation='memmove after realloc uses cached lines pointer',vulnerability_hypothesis='use-after-free after realloc in thematic break block processing',trigger_conditions=['reference definition followed by thematic break and many remaining lines'],external_input_relation='public fuzz-mdhtml harness parses the supplied Markdown bytes',required_state=['md_push_block_bytes reallocates'],supporting_evidence=[],contradicting_evidence=[],unknowns=[])
source_input=Path('/home/dawne/work/SunrinInfosecProject2026/fbv2_hp_integration/documentation/md4c_sp_uaf_manual_validation_20261102/uaf.bin')
poc=PoC(poc_id='manual-uaf-poc',sp_id=point.sp_id,generator_script='manually constructed after model SP hypothesis',generated_input=str(source_input),run_command=None,expected_behavior='AddressSanitizer: heap-use-after-free')
try:
    evidence=execute_poc(poc,point,[str(q.binary),'{input}'],root,target_repository=q.source_root,harness_path=q.harness,source_artifact_sanitizers=['address'],runtime_sanitizers=['address'],official_qualification=q,target_binary=q.binary,timeout_seconds=5,process_envelope=envelope)
    status='RETURNED'
except Exception as exc:
    status=f'EXCEPTION:{type(exc).__name__}:{str(exc)[:180]}'
    evidence=[]
process,process_sha=ledger.receipt_snapshot()
summary={'run_dir':str(root),'status':status,'point_status':point.status,'poc_status':poc.status,'evidence_count':len(evidence),'process_finished':len(process.get('finished',[])),'process_active':len(process.get('active',{})),'process_stop':process.get('stop_status'),'process_sha256':process_sha,'input_sha256':hashlib.sha256(source_input.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(q.binary.read_bytes()).hexdigest()}
(root/'control-summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
print(json.dumps(summary,sort_keys=True))
