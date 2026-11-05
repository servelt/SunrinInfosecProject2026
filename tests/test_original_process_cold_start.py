"""Real subprocess regression: startup slowness is not a failed request."""
from __future__ import annotations
import asyncio
import sys
from pathlib import Path

from harnesscreator.models import (ActionExample, Evidence, ExternalActionSchema,
    ProjectSpec, ProofStatus, ScenarioCandidate, ScenarioStatus, ScenarioStep)
from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier
from harnesscreator.analysis import StaticAnalyzer, GraphStore


def test_initial_response_may_use_startup_budget_without_loosening_later_steps(tmp_path: Path):
    script = (
        "import sys,time\n"
        "time.sleep(0.30)\n"
        "for line in sys.stdin.buffer:\n"
        "  sys.stdout.buffer.write(b'OK\\n'); sys.stdout.buffer.flush()\n"
    )
    (tmp_path / 'a.c').write_text('#include <stdio.h>\nint handler(void){return getchar();}\n')
    graph = GraphStore(StaticAnalyzer(tmp_path).index())
    handler = next(f for f in graph.bundle.functions.values() if f.name == 'handler')
    evidence = [Evidence('source', handler.function_id, handler.file, handler.start_line, 'fixture')]
    action = ExternalActionSchema('read', 'e', 'read', 'original input',
        handler.function_id, handler.function_id, 'X', 'stdin', [],
        [ActionExample(b'X\n'.hex(), {})], [b'OK\n'.hex()], [], evidence,
        ['handler'], status=ProofStatus.PROVEN_STATIC,
        source_api='getchar', entry_function_id=handler.function_id,
        success_evidence=evidence)
    project = ProjectSpec(
        source_root=tmp_path, output_root=tmp_path/'out',
        scenario_command=[sys.executable,'-u','-c',script],
        scenario_channel='stdin', scenario_attribution='trace',
        scenario_exploratory_drafts=True,
        scenario_step_timeout=0.10, scenario_startup_timeout=5.0,
    ).normalized()
    candidate = ScenarioCandidate('cold', 'read',
        [ScenarioStep(0,'read','e',b'X\n'.hex(),{},[b'OK\n'.hex()])],['e'],[],[])
    result = asyncio.run(ScenarioRuntimeVerifier(project, [action], graph).verify(candidate))
    assert result.status in {ScenarioStatus.REPLAYED_RUNTIME, ScenarioStatus.OBSERVED_RUNTIME}, result.rationale
    assert result.observations[0].response_success
    assert not result.observations[0].target_reached  # no request-correlated probe
