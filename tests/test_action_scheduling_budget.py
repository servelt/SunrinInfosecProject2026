"""Regression checks for evidence-based Action source navigation."""
import pytest
from harnesscreator.agents.scenario import (
    InputActionAgent, _input_controlled_call_candidates, _written_buffer_names,
)
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.models import AnalysisBundle, EntryRecord, FunctionMetadata, Verdict


def test_read_buffer_expression_does_not_taint_owner_or_offset():
    assert _written_buffer_names("c->rbuf + c->rbytes") == set()
    assert _written_buffer_names("buf + used") == {"buf"}
    assert _written_buffer_names("&ctx.buffer[slot]") == set()


def test_semantic_action_mode_does_not_use_legacy_branch_work_budgets():
    # Introspect public defaults without requiring an LLM or graph fixture.
    import inspect
    parameters = inspect.signature(InputActionAgent.__init__).parameters
    assert parameters['semantic_action_mode'].default is True
    assert parameters['budget'].default == 0


def test_syntax_branch_worker_cannot_be_enabled():
    graph = GraphStore(AnalysisBundle(functions={}, edges=[]))
    with pytest.raises(ValueError, match='syntax-branch Action discovery is retired'):
        InputActionAgent(None, graph, semantic_action_mode=False)


def test_missing_acquisition_declaration_is_unresolved_not_empty_proof():
    function = FunctionMetadata.create(
        name='receive', signature='int receive(int fd)', file='server.c',
        start_line=1, end_line=1,
        source='int receive(int fd) { char input[1]; read(fd,input,1); return 0; }',
    )
    function.external_call_sites = [{
        'provider': 'clang-ast-c', 'line': 1, 'api': 'read',
        'analysis_unit': 'server.c', 'offset': 37,
        'direct_argument_identifiers': ['fd', 'input', ''],
        'direct_argument_declaration_ids': ['', '', ''],
    }]
    entry = EntryRecord(
        entry_id='entry', candidate_id='candidate', status=Verdict.VERIFIED,
        entry_function_id=function.function_id, source_api='read',
        channel_kind='tcp', attacker_control='remote', provenance_path=[],
        consumer_hints=[], evidence=[], unknowns=[], verifier_confidence=0.9,
        entry_line=1, first_acquisition_confirmed=True,
    )
    graph = GraphStore(AnalysisBundle(functions={function.function_id: function}, edges=[]))
    candidates, unresolved = _input_controlled_call_candidates(
        graph, function, {'input'}, entry=entry,
    )
    assert candidates == []
    assert 'could not be bound' in unresolved[0]
