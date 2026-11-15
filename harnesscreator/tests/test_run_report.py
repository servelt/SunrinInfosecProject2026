"""An incomplete run is diagnosable without falsely claiming success."""
from __future__ import annotations
import json
from pathlib import Path
from harnesscreator.cli import main
from harnesscreator.runtime.run_report import summarize_run, format_run_report


def test_interrupted_run_shows_partial_inventory_and_no_fake_final_count(tmp_path: Path,capsys):
    (tmp_path/'actions').mkdir()
    (tmp_path/'actions/inventory.jsonl').write_text(json.dumps({'action_id':'GET','status':'POSSIBLE'})+'\n')
    data=summarize_run(tmp_path)
    assert not data['completed']
    assert data['action_inventory_count']==1
    assert data['candidate_lifecycle_count']==0
    assert 'CANDIDATE_LIFECYCLE_NOT_YET_WRITTEN' in data['blocker_counts']
    assert main(['report',str(tmp_path)])==0
    out=capsys.readouterr().out
    assert 'Completed: False' in out
    assert 'NOT' not in out or 'Completed' in out


def test_completed_run_does_not_conflate_backend_with_semantic_proof(tmp_path: Path):
    (tmp_path/'workflow').mkdir()
    (tmp_path/'actions').mkdir()
    (tmp_path/'actions/inventory.jsonl').write_text(json.dumps({'action_id':'GET'})+'\n')
    (tmp_path/'summary.json').write_text(json.dumps({'harnesses_qualified':0,'harnesses_backend_qualified':1}))
    (tmp_path/'workflow/candidate-lifecycle.jsonl').write_text(json.dumps({
        'action_id':'GET','disposition':'BACKEND_VERIFIED_EQUIVALENCE_UNKNOWN',
        'discovery_proof':'POSSIBLE', 'scenario_ids':['sc'], 'plan_ids':['p'],
        'generated_harness_ids':['h'], 'build_verified_ids':['h'],
        'backend_verified_ids':['h'], 'semantic_verified_ids':[],
        'obligations':['ORIGINAL_RUNTIME_NOT_PROVEN: no causal witness'],
    })+'\n')
    data=summarize_run(tmp_path)
    assert data['completed']
    assert data['actions'][0]['semantic_verified']==0
    assert 'ORIGINAL_RUNTIME_NOT_PROVEN' in data['blocker_counts']
    assert 'BACKEND_VERIFIED_EQUIVALENCE_UNKNOWN' in format_run_report(data)
