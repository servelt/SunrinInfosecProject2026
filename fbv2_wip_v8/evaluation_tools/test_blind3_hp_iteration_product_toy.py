"""Real public C toy through scan_selected; all model responses are scripted."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import time
import unittest

from blind3_hp_iteration_dev import DevHPLedger, DevHPPolicy, run_sequence_dev
from vulnerabilityanalysis.hp_project_state import (attach_threat_model_proposal,
    load_hp_project_state)
from vulnerabilityanalysis.workflow import run_phase1, write_json

PREP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PREP / 'review_tools'))
import compare_hp_budget_fixture as toy  # noqa: E402


def _manual_threat_proposal(source: Path, harness: Path) -> dict:
    """A source-cited toy T with no claim about the guard's correctness."""
    root = source.parent
    doc, build = root / 'THREAT.md', root / 'build.txt'
    doc.write_text('The public toy accepts a byte through its fuzz harness.\n')
    build.write_text('clang -fsanitize=fuzzer,address target.c fuzz.c\n')

    def citation(kind: str, path: Path, snippet: str) -> dict:
        matches = [(number, line) for number, line in enumerate(
            path.read_text().splitlines(), 1) if snippet in line]
        if len(matches) != 1:
            raise AssertionError('manual T citation is ambiguous')
        number, quote = matches[0]
        return {'kind': kind,
                'path': str(path.resolve()) if kind == 'HARNESS' else
                        path.relative_to(root).as_posix(),
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'line': number, 'quote': quote}

    harness_entry = citation('HARNESS', harness, 'int LLVMFuzzerTestOneInput')
    source_entry = citation('SOURCE', source, 'void A(const uint8_t *data')
    source_value = citation('SOURCE', source, 'unsigned value = B(data[0]);')
    source_capacity = citation('SOURCE', source, 'unsigned cap = value + 1u;')
    source_write = citation('SOURCE', source, 'buf[value] = data[0];')
    documented_input = citation('DOC', doc, 'accepts a byte')
    build_line = citation('BUILD', build, '-fsanitize=fuzzer,address')

    def claim(value: str, evidence: list[dict]) -> dict:
        return {'claim': value, 'status': 'PROPOSED', 'evidence': evidence}

    return {'kind': 'HP_THREAT_MODEL_PROPOSAL_DEV_V1',
            'claims': {
                'attacker_control': [claim('The harness supplies an input byte',
                                           [harness_entry, documented_input])],
                'in_scope': [claim('The toy build exercises A through the harness',
                                   [source_entry, harness_entry, build_line])],
                'trust_boundary': [claim('Input data reaches A as an argument',
                                         [harness_entry, source_value])],
                'security_relevant_state': [claim(
                    'A derives a capacity and uses a byte-derived index',
                    [source_capacity, source_write])],
                'out_of_scope': []},
            'unknowns': ['The toy does not establish a production API attack surface']}


class ScriptedToyProvider:
    provider_free = True

    def __init__(self, ledger, checkpoint, guard_line, guard_quote):
        self.ledger, self.checkpoint, self.guard_line = ledger, checkpoint, guard_line
        self.guard_quote = guard_quote
        self.function_id = None
        self.fa = self.ag = 0
        self.function_analysis_payloads: list[dict] = []

    def begin_function(self, function_id):
        if not self.checkpoint.is_file():
            raise AssertionError('checkpoint missing before scripted provider')
        self.function_id = function_id

    def end_function(self):
        self.function_id = None

    async def generate(self, request):
        role = request.role
        digest = hashlib.sha256((role + str(self.fa) + str(self.ag)).encode()).hexdigest()
        self.ledger.begin_turn(self.function_id, role, digest)
        self.ledger.checkpoint(self.checkpoint)
        self.ledger.start_attempt(digest)
        self.ledger.checkpoint(self.checkpoint)
        self.ledger.finish_attempt(completed=True)
        self.ledger.checkpoint(self.checkpoint)
        if role == 'sp_generation':
            return {'suspicious_points': []}
        if role == 'function_analysis':
            self.function_analysis_payloads.append(request.payload)
            self.fa += 1
            safe = ('The input-derived value is at most 200.' if self.fa == 2
                    else 'cap > value' if self.fa == 3 else None)
            return {'summary': 'scripted public C toy',
                'input_flow': 'harness byte determines value',
                'state_dependencies': [],
                'context_requests': ([{'target': 'B', 'request_type': 'FUNCTION',
                    'reason': 'inspect helper', 'expected_information': 'body'}]
                    if self.fa == 1 else []),
                'safe_assumptions': [safe] if safe else [],
                'unknowns': [] if safe else ['context needed'],
                'input_sources': ['fuzzer data[0] determines value'],
                'security_sensitive_operations': ['buf[value] write'],
                'validations': ['value > 200 returns before buffer write'],
                'memory_operations': [], 'evidence': [],
                'hypothesis_evaluations': ([{
                    'source_location': f'target.c:{self.guard_line}',
                    'security_property': 'scripted input relation',
                    'source_file': 'target.c', 'source_line': self.guard_line,
                    'source_quote': self.guard_quote,
                    'input_influence': 'INPUT_DEPENDENT', 'hypothesis': safe,
                    'judgment': 'EXPLICIT_SAFE_JUDGMENT',
                    'reason': 'fixed toy response', 'safe_assumption': safe}]
                    if safe else [])}
        if role == 'assertion_generator':
            self.ag += 1
            safe = ('The input-derived value is at most 200.' if self.ag == 1
                    else 'cap > value')
            expression = 'value <= 200' if self.ag == 1 else 'cap > value'
            return {'assertions': [{'safe_id': 0, 'safe_assumption': safe,
                'runtime_expression': expression, 'source_line': self.guard_line,
                'required_context': [], 'rationale': 'fixed toy control'}],
                'dispositions': [{'safe_id': 0, 'safe_assumption': safe,
                    'status': 'PROPOSED', 'reason': 'fixed toy control'}]}
        raise AssertionError(role)


class ProductToyIterationTests(unittest.TestCase):
    @unittest.skipUnless((PREP / 'review_tools/local_clang/clang').is_file(),
                         'public toy Clang wrapper unavailable')
    def test_real_product_scan_refines_scripted_safe(self):
        self._exercise_product_toy(defect=False)

    @unittest.skipUnless((PREP / 'review_tools/local_clang/clang').is_file(),
                         'public toy Clang wrapper unavailable')
    def test_original_asan_defect_blocks_refinement(self):
        self._exercise_product_toy(defect=True)

    @unittest.skipUnless((PREP / 'review_tools/local_clang/clang').is_file(),
                         'public toy Clang wrapper unavailable')
    def test_manual_cited_t_first_violation_and_second_guided(self):
        self._exercise_product_toy(defect=False, with_threat=True)

    def _exercise_product_toy(self, *, defect: bool, with_threat: bool = False):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = toy.prepare_fixture(root / 'fixture')
            source = fixture['source']
            guard = ('  if (value > 200) { unsigned char *p = malloc(1); '
                     'p[value] = 1; free(p); return; }' if defect else
                     '  if (value > 200) return;')
            source.write_text('#include <stdint.h>\n#include <stddef.h>\n'
                '#include <stdlib.h>\nunsigned B(unsigned x) { return x; }\n'
                'void A(const uint8_t *data, size_t size) {\n'
                '  if (!size) return;\n'
                '  unsigned value = B(data[0]);\n'
                '  unsigned cap = value + 1u;\n'
                f'{guard}\n'
                '  unsigned char *buf = malloc(cap);\n'
                '  if (!buf) return;\n'
                '  buf[value] = data[0];\n'
                '  free(buf);\n}\n')
            harness = fixture['harness']
            harness.write_text(harness.read_text().replace(
                'extern int A(const uint8_t *, size_t);',
                'extern void A(const uint8_t *, size_t);'))
            manifest = fixture['artifact'] / 'manifest.json'
            manifest_row = json.loads(manifest.read_text())
            manifest_row['harness_sha256'] = hashlib.sha256(harness.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(manifest_row))
            plan_row = json.loads(fixture['plan'].read_text())
            plan_row['harness_sha256'] = manifest_row['harness_sha256']
            fixture['plan'].write_text(json.dumps(plan_row))
            guard_line = toy.source_line(source, 'if (value > 200)')
            run = run_phase1(fixture['artifact'], root / 'runs',
                             target_repository=source.parent,
                             direction_plan=fixture['plan'],
                             selection_policy='FBV2_FIRST_PASS_UNIQUE_DEV',
                             hp_project_state_dev=with_threat)
            matches = [row for row in json.loads((run / 'function_pool.json').read_text())
                       if row['function_name'] == 'A']
            self.assertEqual(len(matches), 1)
            write_json(run / 'selection.json', {**matches[0], 'analyzed': False})
            run_metadata = json.loads((run / 'run.json').read_text())
            run_metadata['selected_function_id'] = matches[0]['function_id']
            write_json(run / 'run.json', run_metadata)
            threat = None
            if with_threat:
                threat = attach_threat_model_proposal(
                    run, source.parent, _manual_threat_proposal(source, harness))['T']
                self.assertEqual(threat['status'], 'PROVENANCE_VALIDATED_DEV')
                self.assertFalse(threat['gate_eligible'])
            policy = DevHPPolicy()
            contract = root / 'contract.json'
            contract.write_text(json.dumps({'kind': 'BLIND3_HP_ITERATION_DEV',
                                            'limits': asdict(policy)}, sort_keys=True))
            contract_hash = hashlib.sha256(contract.read_bytes()).hexdigest()
            ledger = DevHPLedger(started_at=time.time(), policy=asdict(policy),
                                 contract_sha256=contract_hash)
            provider = ScriptedToyProvider(ledger, root / 'ledger.json',
                                           guard_line, guard.strip())
            build = [str(PREP / 'review_tools/local_clang/clang'), '-DLIBFUZZER',
                     '-fsanitize=fuzzer,address', '-g', '-O0', '{source}',
                     str(fixture['harness']), '-o', '{binary}']
            rows = asyncio.run(run_sequence_dev(
                run, provider, ledger, source.parent, root / 'ledger.json',
                policy=policy, contract_path=contract, scan_options={
                    'hallucination_prevent': 'on',
                    'assertion_build_command': build,
                    'assertion_run_command': ['{binary}', '{input}'],
                    'assertion_seed': fixture['challenge']}))
            history = json.loads((run / 'assertions/refinement_history.json').read_text())
            assertions = json.loads((run / 'assertions/results.json').read_text())
            if with_threat:
                self.assertEqual(len(provider.function_analysis_payloads), 3)
                for payload in provider.function_analysis_payloads:
                    self.assertEqual(payload['analysis_scope']['hp_project_state']['T'],
                                     threat)
                carried_state = load_hp_project_state(run, source.parent)
                self.assertEqual(carried_state['T'], threat)
                self.assertFalse(carried_state['gate_eligible'])
                scan = json.loads((run / 'scan.json').read_text())
                self.assertFalse(scan['verified_crash_ids'])
            runtime_path = Path(assertions[0]['execution_result'])
            triage = json.loads((runtime_path.parent / 'triage.json').read_text())
            if with_threat:
                provenance = triage['hp_threat_model_provenance']
                snapshot = Path(provenance['state_snapshot_path'])
                observed = snapshot.lstat()
                self.assertTrue(stat.S_ISREG(observed.st_mode))
                self.assertEqual(stat.S_IMODE(observed.st_mode), 0o600)
                self.assertEqual(observed.st_nlink, 1)
                self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                                 provenance['state_snapshot_sha256'])
                self.assertEqual(provenance['state_snapshot_sha256'],
                                 provenance['state_sha256'])
                self.assertEqual(json.loads(snapshot.read_text())['T'], threat)
                self.assertFalse(provenance['gate_eligible'])
            jobs = json.loads((run / 'runtime/runner_fuzz_jobs.json').read_text())
            if defect:
                self.assertEqual(rows[0]['status'],
                                 'INCONCLUSIVE_NO_REFINED_ASSERTION')
                self.assertEqual(history['status'], 'NO_ELIGIBLE_VIOLATION')
                self.assertEqual(provider.ag, 1)
                self.assertEqual(triage['classification'], 'SECURITY_DEFECT_POSSIBLE')
                self.assertEqual(triage['security_verdict'], 'UNKNOWN')
            else:
                self.assertEqual(rows[0]['status'], 'BOUNDARY_ACCOUNTED',
                                 json.dumps({'history': history,
                                             'triage': triage}, default=str)[:1800])
                self.assertEqual((provider.fa, provider.ag), (3, 2))
                self.assertEqual((ledger.logical, ledger.physical), (6, 6))
                self.assertEqual(history['refinements'][0]['status'],
                                 'REFINED_AND_TESTED')
                self.assertEqual(history['refinements'][0]['revisions'][0]
                                 ['assertion']['status'], 'HELD_FOR_EXECUTION')
                self.assertIsNotNone(history['refinements'][0]['revisions'][0]
                                     ['guided_fuzz'])
                guided_jobs = [row for row in jobs if row['kind'] == 'ASSERTION']
                self.assertEqual(len(guided_jobs), 2, jobs)
                self.assertEqual(len({row['id'] for row in guided_jobs}), 2)
                self.assertEqual([row.get('result_status') for row in guided_jobs],
                                 ['ASSERTION_WITNESS_OBSERVED', 'RAN'], guided_jobs)
                for job in guided_jobs:
                    self.assertGreater(job.get('physical_actual', 0), 0, job)
                initial_guided = runtime_path.parent / 'guided_fuzz' / 'guided_fuzz.json'
                revised_guided = Path(history['refinements'][0]['revisions'][0]
                                      ['guided_fuzz'])
                if with_threat:
                    revision = history['refinements'][0]['revisions'][0]
                    prior_pin = revision['prior_corpus_pin']
                    self.assertEqual(prior_pin['status'], 'PINNED')
                    self.assertTrue(prior_pin['allowlist'])
                    imported = json.loads(revised_guided.read_text())['carried_corpus']
                    self.assertEqual({row['sha256'] for row in imported},
                                     {row['sha256'] for row in prior_pin['allowlist']})
                    self.assertTrue(all(
                        Path(row['destination']).is_file() and
                        hashlib.sha256(Path(row['destination']).read_bytes()).hexdigest()
                        == row['sha256'] for row in imported))
                self.assertNotEqual(initial_guided, revised_guided)
                for artifact, expected_status in (
                        (initial_guided, 'ASSERTION_WITNESS_OBSERVED'),
                        (revised_guided, 'RAN')):
                    self.assertTrue(artifact.is_file(), artifact)
                    report = json.loads(artifact.read_text())
                    self.assertEqual(report.get('status'), expected_status, report)
                    self.assertGreater(report.get('fuzz_seconds_actual', 0), 0, report)
                physical = sum(row['physical_actual'] for row in guided_jobs)
                overrun = sum(row['overrun_seconds'] for row in guided_jobs)
                self.assertAlmostEqual(ledger.fuzz_physical_actual, physical)
                self.assertAlmostEqual(ledger.fuzz_overrun_seconds, overrun)
                self.assertEqual(ledger.fuzz_overrun_blocked, overrun > 0)
            self.assertLessEqual(ledger.fuzz_budget_used(),
                                 policy.fuzz_seconds_combined)


if __name__ == '__main__':
    unittest.main()
