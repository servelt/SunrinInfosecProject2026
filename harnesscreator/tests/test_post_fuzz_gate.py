from __future__ import annotations

import asyncio
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.agents.scenario_harness import ScenarioStaticHarnessGate, ScenarioHarnessVerifierSeedPlanner
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    AnalysisBundle, HarnessDraft, HarnessManifest, HarnessPlan,
    ScenarioStep, ScenarioWitness, ScenarioStatus,
)


def fixture():
    fuzz = ScenarioStep(0, 'set', 'entry', b'SET k\n'.hex(), {}, [b'OK\n'.hex()])
    post = ScenarioStep(1, 'get', 'entry', b'GET k\n'.hex(), {}, [b'VALUE:yes\n'.hex()])
    witness = ScenarioWitness('w','s','set',[fuzz,post],[],['./server'],'stdin',0,
                              ScenarioStatus.PROVEN_RUNTIME,'synthetic witness',fuzz_step_index=0)
    plan = HarnessPlan('p','w','s','set',[],fuzz,[],[],
                       'raw_fuzz_request','in_process_reset','example',0,4096,
                       post_steps=[post],fuzz_step_index=0,
                       boundary_contract={'mode':'original_input_transport'})
    manifest = HarnessManifest('h','s','fuzz_target.cc','example','libfuzzer',
                               ['address'],'in_process_reset',[],[],0,4096,
                               'one_scenario_per_harness',[],[])
    return witness, plan, manifest


def test_missing_post_is_a_separate_static_failure():
    witness, plan, manifest = fixture()
    draft = HarnessDraft(manifest, '''
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size){
const uint8_t *hc_fuzz_request = Data;
size_t hc_fuzz_request_size = Size;
(void)hc_fuzz_request; (void)hc_fuzz_request_size;
return 0;
}
''', [], [])
    report = ScenarioStaticHarnessGate(GraphStore(AnalysisBundle({}, []))).check(
        draft, plan, witness)
    checks = {item.check_id: item for item in report.checks}
    assert str(checks['HC15'].status) == 'FAIL'
    assert str(checks['HC16'].status) == 'FAIL'


def test_seed_is_fuzz_not_post_request():
    witness, plan, manifest = fixture()
    draft = HarnessDraft(manifest, '', [], [])
    planner = ScenarioHarnessVerifierSeedPlanner(ScriptedLLM([{'seeds': []}]))
    seeds = asyncio.run(planner.run(draft, plan, witness))
    assert seeds[0].data_hex == b'SET k\n'.hex()
    assert seeds[0].data_hex != b'GET k\n'.hex()
