"""Regression for programs where an external read returns via registered C callbacks.

Callback-slot matching is ONLY navigation. It cannot create static/runtime proof.
"""
from pathlib import Path
import asyncio

from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.agents.scenario import (
    InputActionAgent, ScenarioPlanner, _same_receiver_return_callbacks,
)
from harnesscreator.llm.base import ScriptedLLM
from harnesscreator.models import (
    ActionExample, AnalysisBundle, CallEdge, Evidence, EntryRecord,
    ExternalActionSchema, FunctionMetadata, ProofStatus, Verdict,
)


def _source(tmp_path: Path) -> GraphStore:
    (tmp_path / 'callbacks.c').write_text('''
    typedef struct conn conn;
    struct conn {
      long (*read)(conn *, void *, int);
      int (*try_read_command)(conn *);
    };
    long tcp_read(conn *c, void *out, int n) { return n; }
    int handle_get(conn *c) { return 1; }
    int process_command_ascii(conn *c) {
        if (c->read && c->try_read_command) {
            return handle_get(c);
        }
        return 0;
    }
    int try_read_command_ascii(conn *c) {
        return process_command_ascii(c);
    }
    int try_read_network(conn *c) {
        char buf[128];
        return c->read(c, buf, 128) > 0;
    }
    int drive_machine(conn *c) {
        if (try_read_network(c)) {
            return c->try_read_command(c);
        }
        return 0;
    }
    void conn_new(conn *c) {
        c->read = tcp_read;
        c->try_read_command = try_read_command_ascii;
    }
    typedef struct other { long (*read)(void *); } other;
    long unrelated_reader(void *x) { return 0; }
    long unrelated_user(other *x) { return x->read(x); }
    void unrelated_registration(other *x) { x->read = unrelated_reader; }
    ''')
    return GraphStore(StaticAnalyzer(tmp_path).index())


def _field_return_source(tmp_path: Path, *, same_receiver: bool) -> GraphStore:
    invocation = 'c->handler(c)' if same_receiver else 'other->handler(other)'
    (tmp_path / 'field_return.c').write_text(f'''
    #include <unistd.h>
    typedef struct conn conn;
    struct conn {{ char buf[8]; int (*handler)(conn *); }};
    int parse_input(conn *c) {{ return c->buf[0] == 'X'; }}
    int acquire(conn *c, int fd) {{
        return read(fd, c->buf, sizeof(c->buf));
    }}
    int drive(conn *c, conn *other, int fd) {{
        int n = acquire(c, fd);
        if (n > 0) return {invocation};
        return 0;
    }}
    void register_handler(conn *c) {{ c->handler = parse_input; }}
    ''')
    return GraphStore(StaticAnalyzer(tmp_path).index())


def test_callback_registration_is_selectable_without_becoming_proof(tmp_path):
    graph = _source(tmp_path)
    by_name = {item.name: item for item in graph.bundle.functions.values()}
    root = by_name['tcp_read']
    registrations = graph.callback_registration_candidates([root.function_id])
    assert [item['function_id'] for item in registrations] == [
        by_name['conn_new'].function_id,
    ]
    assert all(
        connection['relation'] == 'callback_registration_candidate'
        and connection['proof_policy'].startswith('navigation only')
        for item in registrations for connection in item['connections']
    )
    agent = InputActionAgent(ScriptedLLM([]), graph)
    choices = agent._choices([root.function_id], [], EntryRecord(
        entry_id='callback-entry', candidate_id='callback-entry',
        status=Verdict.VERIFIED, entry_function_id=root.function_id,
        source_api='read', channel_kind='network_tcp', attacker_control='client',
        provenance_path=[], consumer_hints=[], evidence=[], unknowns=[],
        verifier_confidence=0.9, entry_line=root.start_line,
        first_acquisition_confirmed=True,
    ), focus_function_id=root.function_id)
    assert by_name['conn_new'].function_id in {
        item['function_id'] for item in choices
    }


def test_comment_and_literal_callback_spellings_do_not_create_leads(tmp_path):
    (tmp_path / 'callbacks.cc').write_text('''
    struct conn { int (*read)(conn *); };
    int tcp_read(conn *) { return 1; }
    void setup(conn *c) {
      // c->read = tcp_read;
      const char *example = "c->read = tcp_read;";
      const char *raw = R"tag(c->read = tcp_read;)tag";
    }
    int drive(conn *c) {
      /* c->read(c); */
      return 0;
    }
    ''', encoding='utf-8')
    graph = GraphStore(StaticAnalyzer(tmp_path).index())
    target = next(item for item in graph.bundle.functions.values()
                  if item.name == 'tcp_read')
    assert graph.callback_slot_candidates([target.function_id]) == []
    assert graph.callback_registration_candidates([target.function_id]) == []


def test_field_read_return_callback_is_navigation_only(tmp_path):
    graph = _field_return_source(tmp_path, same_receiver=True)
    by_name = {item.name: item for item in graph.bundle.functions.values()}
    read_site = by_name['acquire']
    entry_line = read_site.start_line + next(
        offset for offset, line in enumerate(read_site.source.splitlines())
        if 'read(' in line
    )
    entry = EntryRecord(
        entry_id='field-return', candidate_id='field-return-candidate',
        status=Verdict.VERIFIED, entry_function_id=read_site.function_id,
        source_api='read', channel_kind='network_tcp',
        attacker_control='socket client', provenance_path=[],
        consumer_hints=[], evidence=[], unknowns=[],
        verifier_confidence=0.9, entry_line=entry_line,
        first_acquisition_confirmed=True,
    )
    assert _same_receiver_return_callbacks(
        graph, entry, by_name['drive'],
    ) == [by_name['parse_input'].function_id]

    parser = by_name['parse_input']
    citation = {
        'kind': 'source', 'function_id': parser.function_id,
        'line': parser.start_line, 'detail': 'reads the session buffer',
    }
    llm = ScriptedLLM([
        {
            'actions': [], 'context_complete': False,
            'requested_function_ids': [by_name['drive'].function_id],
            'rationale': 'inspect read caller',
        },
        {
            'actions': [], 'context_complete': False,
            'requested_function_ids': [parser.function_id],
            'rationale': 'inspect callback',
        },
        {
            'actions': [{
                'name': 'parse request', 'description': 'read session input',
                'dispatcher_function_id': parser.function_id,
                'handler_function_id': parser.function_id,
                'discriminator': 'X', 'fields': [],
                'examples': [{
                    'data_hex': '58', 'bindings': [], 'rationale': 'trial',
                    'origin': 'source_candidate', 'evidence': [citation],
                }],
                'success_markers_hex': [], 'failure_markers_hex': [],
                'success_evidence': [citation], 'failure_evidence': [],
                'response_bindings': [], 'evidence': [citation],
                'unknowns': [], 'confidence': 0.9,
            }],
            'context_complete': True,
            'requested_function_ids': [], 'rationale': 'candidate found',
        },
    ])
    agent = InputActionAgent(llm, graph)
    actions, _seeds = asyncio.run(agent._run_entry(entry))
    opened = [call['payload']['current_function']['name'] for call in llm.calls]
    assert opened == ['acquire', 'drive', 'parse_input']
    assert len(actions) == 1
    assert actions[0].status is ProofStatus.POSSIBLE
    assert any('input-value flow' in item for item in actions[0].unknowns)

    limited = InputActionAgent(ScriptedLLM([{
        'actions': [], 'context_complete': False,
        'requested_function_ids': [by_name['drive'].function_id],
        'rationale': 'inspect caller',
    }, {
        'actions': [], 'context_complete': True,
        'requested_function_ids': [], 'rationale': 'callback not opened',
    }]), graph, budget=2)
    asyncio.run(limited._run_entry(entry))
    assert any(
        parser.function_id in obligation
        and 'uninspected' in obligation
        for obligation in limited.inventory_obligations
    )


def test_field_read_return_callback_rejects_other_receiver(tmp_path):
    graph = _field_return_source(tmp_path, same_receiver=False)
    by_name = {item.name: item for item in graph.bundle.functions.values()}
    read_site = by_name['acquire']
    entry_line = read_site.start_line + next(
        offset for offset, line in enumerate(read_site.source.splitlines())
        if 'read(' in line
    )
    entry = EntryRecord(
        entry_id='field-return-other', candidate_id='field-return-candidate',
        status=Verdict.VERIFIED, entry_function_id=read_site.function_id,
        source_api='read', channel_kind='network_tcp',
        attacker_control='socket client', provenance_path=[],
        consumer_hints=[], evidence=[], unknowns=[],
        verifier_confidence=0.9, entry_line=entry_line,
        first_acquisition_confirmed=True,
    )
    assert _same_receiver_return_callbacks(graph, entry, by_name['drive']) == []


def test_multiple_read_callers_keep_source_supported_callback_route(tmp_path):
    graph = _field_return_source(tmp_path, same_receiver=True)
    source = tmp_path / 'field_return.c'
    source.write_text(source.read_text() + '''
    int unrelated_caller(conn *c, conn *other, int fd) {
        int n = acquire(c, fd);
        if (n > 0) return other->handler(other);
        return 0;
    }
    ''')
    graph = GraphStore(StaticAnalyzer(tmp_path).index())
    by_name = {item.name: item for item in graph.bundle.functions.values()}
    read_site = by_name['acquire']
    entry_line = read_site.start_line + next(
        offset for offset, line in enumerate(read_site.source.splitlines())
        if 'read(' in line
    )
    entry = EntryRecord(
        entry_id='multiple-field-callers', candidate_id='field-candidate',
        status=Verdict.VERIFIED, entry_function_id=read_site.function_id,
        source_api='read', channel_kind='network_tcp',
        attacker_control='socket client', provenance_path=[],
        consumer_hints=[], evidence=[], unknowns=[],
        verifier_confidence=0.9, entry_line=entry_line,
        first_acquisition_confirmed=True,
    )
    assert _same_receiver_return_callbacks(
        graph, entry, by_name['unrelated_caller'],
    ) == []
    llm = ScriptedLLM([{
        'actions': [], 'context_complete': False,
        'requested_function_ids': [by_name['drive'].function_id],
        'rationale': 'inspect read caller',
    }, {
        'actions': [], 'context_complete': False,
        'requested_function_ids': [by_name['parse_input'].function_id],
        'rationale': 'inspect callback',
    }, {
        'actions': [], 'context_complete': True,
        'requested_function_ids': [], 'rationale': 'done',
    }])
    agent = InputActionAgent(llm, graph)
    asyncio.run(agent._run_entry(entry))
    opened = [call['payload']['current_function']['name'] for call in llm.calls]
    assert opened == ['acquire', 'drive', 'parse_input']
    assert any(
        by_name['unrelated_caller'].function_id in obligation
        and 'unresolved' in obligation
        for obligation in agent.inventory_obligations
    )


def test_read_error_callback_is_not_forced_as_input_consumer(tmp_path):
    (tmp_path / 'error_callback.c').write_text('''
    #include <unistd.h>
    typedef struct conn conn;
    struct conn { void (*closed)(conn *); };
    void on_closed(conn *c) { (void)c; }
    void configure(conn *c) { c->closed = on_closed; }
    int acquire(int fd, conn *c) {
        char input[8];
        int n = read(fd, input, sizeof(input));
        if (n == 0) c->closed(c);
        return n;
    }
    ''')
    graph = GraphStore(StaticAnalyzer(tmp_path).index())
    by_name = {item.name: item for item in graph.bundle.functions.values()}
    root = by_name['acquire']
    entry_line = root.start_line + next(
        offset for offset, line in enumerate(root.source.splitlines())
        if 'read(' in line
    )
    entry = EntryRecord(
        entry_id='error-callback', candidate_id='error-candidate',
        status=Verdict.VERIFIED, entry_function_id=root.function_id,
        source_api='read', channel_kind='network_tcp',
        attacker_control='socket client', provenance_path=[],
        consumer_hints=[], evidence=[], unknowns=[],
        verifier_confidence=0.9, entry_line=entry_line,
        first_acquisition_confirmed=True,
    )
    llm = ScriptedLLM([{
        'actions': [], 'context_complete': True,
        'requested_function_ids': [], 'rationale': 'no consumer yet',
    }])
    agent = InputActionAgent(llm, graph)
    asyncio.run(agent._run_entry(entry))
    assert [
        call['payload']['current_function']['name'] for call in llm.calls
    ] == ['acquire']
    # EOF/error handling is keyed by read's return value, not by acquired
    # bytes. It is available in the source graph, but it is not an automatic
    # input-value consumer in the focused Action frontier.
    assert by_name['on_closed'].function_id not in {
        item['function_id'] for item in llm.calls[0]['payload']['frontier']
    }
    assert any(
        'no external Action reconstructed' in item
        for item in agent.inventory_obligations
    )


def test_callback_navigation_discovers_return_then_parse_without_forging_static_proof(tmp_path):
    graph = _source(tmp_path)
    by_name = {f.name: f.function_id for f in graph.bundle.functions.values()}
    src = by_name['tcp_read']
    tgt = by_name['process_command_ascii']
    assert not graph.causal_path_from_entry(
        src, tgt, opened_function_ids=graph.bundle.functions,
    )
    path = graph.callback_navigation_path(src, tgt)
    assert path[0] == src and path[-1] == tgt
    names = [graph.get(identifier).name for identifier in path]
    assert 'try_read_network' in names
    assert 'drive_machine' in names
    assert 'try_read_command_ascii' in names
    assert any(
        edge.get('relation') == 'callback_candidate_caller'
        for candidate in graph.callback_slot_candidates([src])
        for edge in candidate['connections']
    )
    # Ambiguous callback identity must NOT introduce authoritative call edges.
    assert not any(
        edge.caller_id == by_name['try_read_network'] and edge.callee_id == src
        for edge in graph.bundle.edges
    )


def test_callback_slots_are_type_scoped_when_type_is_known(tmp_path):
    graph = _source(tmp_path)
    by_name = {f.name: f.function_id for f in graph.bundle.functions.values()}
    candidates = graph.callback_slot_candidates([by_name['tcp_read']])
    assert by_name['unrelated_user'] not in {x['function_id'] for x in candidates}


def test_completed_read_wrapper_opens_source_callback_invoker(tmp_path):
    graph = _source(tmp_path)
    by_name = {function.name: function for function in graph.bundle.functions.values()}
    root = by_name['tcp_read']
    invoker = by_name['try_read_network']
    entry = EntryRecord(
        entry_id='callback-read', candidate_id='callback-candidate',
        status=Verdict.VERIFIED, entry_function_id=root.function_id,
        source_api='read', channel_kind='network_tcp',
        attacker_control='socket client', provenance_path=[],
        consumer_hints=[], evidence=[Evidence(
            'source', root.function_id, root.file, root.start_line,
            'callback receives external bytes',
        )], unknowns=[], verifier_confidence=0.9,
        entry_line=root.start_line, first_acquisition_confirmed=True,
    )
    llm = ScriptedLLM([{
        'actions': [], 'context_complete': False,
        'requested_function_ids': [invoker.function_id],
        'rationale': 'inspect callback invoker',
    }, {
        'actions': [], 'context_complete': True,
        'requested_function_ids': [], 'rationale': 'no action established',
    }])
    agent = InputActionAgent(llm, graph, budget=10)
    actions, _seeds = asyncio.run(agent._run_entry(entry))

    assert actions == []
    assert not agent.infrastructure_failures
    assert len(llm.calls) == 2
    assert llm.calls[1]['payload']['current_function']['function_id'] == invoker.function_id


def test_callback_registration_prefers_unique_definition_in_same_translation_unit(tmp_path):
    (tmp_path / 'server.c').write_text('''
    typedef struct conn conn;
    struct conn { long (*read)(conn *, void *, int); };
    long tcp_read(conn *c, void *buf, int n) { return n; }
    void register_reader(conn *c) { c->read = tcp_read; }
    long receive_one(conn *c, void *buf) { return c->read(c, buf, 1); }
    ''')
    (tmp_path / 'testapp.c').write_text('''
    struct conn { long (*read)(void *, void *, int); };
    long tcp_read(void *c, void *buf, int n) { return n; }
    ''')
    graph = GraphStore(StaticAnalyzer(tmp_path).index())
    server_reader = next(
        function for function in graph.bundle.functions.values()
        if function.name == 'tcp_read' and function.file == 'server.c'
    )
    test_reader = next(
        function for function in graph.bundle.functions.values()
        if function.name == 'tcp_read' and function.file == 'testapp.c'
    )
    receive = next(
        function for function in graph.bundle.functions.values()
        if function.name == 'receive_one'
    )

    server_candidates = graph.callback_slot_candidates([server_reader.function_id])
    test_candidates = graph.callback_slot_candidates([test_reader.function_id])
    assert receive.function_id in {item['function_id'] for item in server_candidates}
    assert receive.function_id not in {item['function_id'] for item in test_candidates}
    assert not any(
        edge.caller_id == receive.function_id
        and edge.callee_id == server_reader.function_id
        for edge in graph.bundle.edges
    )


def test_callback_navigation_keeps_library_to_executable_handoff(tmp_path):
    (tmp_path / 'CMakeLists.txt').write_text('''
    add_library(callbacks cb.c)
    add_executable(server server.c)
    target_link_libraries(server callbacks)
    ''')
    (tmp_path / 'cb.c').write_text('''
    typedef struct conn conn;
    struct conn { long (*read)(conn *, void *, int); };
    long tcp_read(conn *c, void *buf, int n) { return n; }
    void register_reader(conn *c) { c->read = tcp_read; }
    ''')
    (tmp_path / 'server.c').write_text('''
    typedef struct conn conn;
    struct conn { long (*read)(conn *, void *, int); };
    long receive_one(conn *c, void *buf) { return c->read(c, buf, 1); }
    ''')
    graph = GraphStore(StaticAnalyzer(tmp_path).index())
    reader = next(
        function for function in graph.bundle.functions.values()
        if function.name == 'tcp_read'
    )
    receive = next(
        function for function in graph.bundle.functions.values()
        if function.name == 'receive_one'
    )
    assert reader.build_targets == ['callbacks']
    assert receive.build_targets == ['server']
    assert receive.function_id in {
        item['function_id']
        for item in graph.callback_slot_candidates([reader.function_id])
    }
    assert graph.callback_navigation_path(
        reader.function_id, receive.function_id
    ) == [reader.function_id, receive.function_id]


def test_callback_navigation_has_no_unjustified_default_depth_cutoff():
    names = ['reader', *[f'return_{i}' for i in range(20)],
             *[f'forward_{i}' for i in range(20)], 'handler']
    functions = [
        FunctionMetadata.create(
            name=name, signature=f'void {name}(void)', file='daemon.c',
            start_line=index + 1, end_line=index + 1,
            source=f'void {name}(void) {{}}',
        )
        for index, name in enumerate(names)
    ]
    ids = {function.name: function.function_id for function in functions}
    edges = [
        CallEdge(f'up-{index}', ids[f'return_{index}'],
                 ids['reader' if index == 0 else f'return_{index - 1}'],
                 line=index + 1)
        for index in range(20)
    ]
    edges.extend([
        CallEdge('handoff', ids['return_19'], ids['forward_0'], line=21),
        *[
            CallEdge(f'down-{index}', ids[f'forward_{index}'],
                     ids['handler' if index == 19 else f'forward_{index + 1}'],
                     line=index + 22)
            for index in range(20)
        ],
    ])
    graph = GraphStore(AnalysisBundle(
        functions={function.function_id: function for function in functions},
        edges=edges,
    ))

    path = graph.callback_navigation_path(ids['reader'], ids['handler'])
    assert len(path) == 42
    assert path[0] == ids['reader']
    assert path[-1] == ids['handler']


def test_possible_source_action_without_oracle_still_gets_exploratory_candidate():
    evidence = [Evidence('source', 'reader', 'app.c', 15, 'opened parser')]
    action = ExternalActionSchema(
        action_id='read-action', entry_id='read-entry', name='command',
        description='normal action',
        dispatcher_function_id='reader', handler_function_id='reader',
        discriminator='command', channel_kind='file', fields=[],
        examples=[ActionExample(b'hello'.hex(), {})],
        success_markers_hex=[], failure_markers_hex=[], evidence=evidence,
        inspected_function_ids=['reader'], status=ProofStatus.POSSIBLE,
        confidence=0.75, source_api='fread', entry_function_id='reader',
    )
    planned = ScenarioPlanner().exploratory_candidates([action], [])
    assert len(planned) == 1
    assert planned[0].steps[0].request_hex == b'hello'.hex()


def test_input_action_opens_hint_callback_route_without_branch_jobs(tmp_path):
    graph = _source(tmp_path)
    by_name = {f.name: f.function_id for f in graph.bundle.functions.values()}
    root = graph.get(by_name['tcp_read'])
    dispatcher = graph.get(by_name['process_command_ascii'])
    entry = EntryRecord(
        entry_id='entry-read', candidate_id='candidate', status=Verdict.VERIFIED,
        entry_function_id=root.function_id, source_api='read',
        channel_kind='network_tcp', attacker_control='socket client',
        provenance_path=[], consumer_hints=[dispatcher.function_id],
        evidence=[Evidence('source', root.function_id, root.file, root.start_line,
                           'reads external input')], unknowns=[],
        verifier_confidence=0.95, entry_line=root.start_line,
        first_acquisition_confirmed=True,
    )
    agent = InputActionAgent(
        ScriptedLLM([]), graph, budget=12,
    )
    candidate_path = agent._candidate_entry_path(entry)
    assert candidate_path[0] == root.function_id
    assert candidate_path[-1] == dispatcher.function_id
    assert len(candidate_path) >= 4

    responses = []
    for index, identifier in enumerate(candidate_path):
        function = graph.get(identifier)
        selected = identifier == dispatcher.function_id
        responses.append({
            'actions': [],
            'context_complete': selected,
            'requested_function_ids': (
                [candidate_path[index + 1]]
                if index + 1 < len(candidate_path) else []
            ),
            'rationale': 'source navigation',
            'branch_disposition': 'ACTION' if selected else 'UNRESOLVED',
            'branch_disposition_evidence': (
                [{'kind': 'source', 'function_id': identifier,
                  'line': function.start_line, 'detail': 'source router'}]
                if selected else []
            ),
        })
    agent.llm = ScriptedLLM(responses)
    direct_actions, operation_seeds = asyncio.run(agent._run_entry(entry))
    assert direct_actions == []
    assert operation_seeds == [], 'syntax branches are not semantic Action jobs'
    assert not agent.infrastructure_failures
    assert any('no external Action reconstructed' in item
               for item in agent.inventory_obligations)


def test_callback_path_alone_cannot_prove_action(tmp_path):
    graph = _source(tmp_path)
    by_name = {f.name: f.function_id for f in graph.bundle.functions.values()}
    root = graph.get(by_name['tcp_read'])
    dispatcher = graph.get(by_name['process_command_ascii'])
    handler = graph.get(by_name['handle_get'])
    entry = EntryRecord(
        entry_id='e', candidate_id='c', status=Verdict.VERIFIED,
        entry_function_id=root.function_id, source_api='read', channel_kind='network_tcp',
        attacker_control='remote', provenance_path=[], consumer_hints=[],
        evidence=[Evidence('source',root.function_id,root.file,root.start_line,'read')],
        unknowns=[], verifier_confidence=1.0, entry_line=root.start_line,
        first_acquisition_confirmed=True,
    )
    agent = InputActionAgent(ScriptedLLM([]), graph)
    example_evidence = [
        {'kind': 'source', 'function_id': handler.function_id,
         'line': handler.start_line, 'detail': 'concrete bytes'}
    ]
    raw = {
        'dispatcher_function_id': dispatcher.function_id,
        'handler_function_id': handler.function_id,
        'name': 'get', 'description': 'request', 'discriminator': 'get',
        'evidence': [
            {'kind': 'source', 'function_id': dispatcher.function_id,
             'line': dispatcher.start_line, 'detail': 'selected get'},
            *example_evidence,
        ],
        'success_evidence': example_evidence,
        'success_markers_hex': [b'OK'.hex()],
        'failure_markers_hex': [],
        'examples': [{'data_hex': b'get k\r\n'.hex(), 'bindings': {},
                      'rationale': 'raw bytes', 'origin': 'product_source',
                      'evidence': example_evidence}],
        'confidence': 1.0,
        'unknowns': [],
    }
    opened = list(graph.bundle.functions)
    checked = agent._validate_actions(entry, [raw], opened, [], context_complete=True)
    assert len(checked) == 1
    assert checked[0].status is ProofStatus.POSSIBLE
    assert any('does not establish Entry' in u for u in checked[0].unknowns)


def test_source_only_selection_allows_unproven_causality_not_unopened_functions():
    from harnesscreator.orchestrator import _source_draft_action_is_supported
    from dataclasses import replace
    dispatcher, handler = 'dispatcher', 'handler'
    evidence = [
        Evidence('source', dispatcher, 'src.c', 7, 'source-located branch'),
        Evidence('source', handler, 'src.c', 12, 'source-located handler'),
    ]
    action = ExternalActionSchema(
        action_id='get', entry_id='entry', name='GET', description='get',
        dispatcher_function_id=dispatcher, handler_function_id=handler,
        discriminator='get', channel_kind='tcp', fields=[],
        examples=[ActionExample(b'get k\r\n'.hex(), {})],
        success_markers_hex=[], failure_markers_hex=[], evidence=evidence,
        inspected_function_ids=[dispatcher, handler], status=ProofStatus.POSSIBLE,
        entry_function_id='acquire',
        entry_probe_evidence=[Evidence('entry', 'acquire', 'src.c', 3, 'read')],
    )
    assert _source_draft_action_is_supported(action)
    assert not _source_draft_action_is_supported(replace(action, entry_probe_evidence=[]))
    assert not _source_draft_action_is_supported(replace(
        action, entry_probe_evidence=[Evidence('entry', 'acquire', 'src.c', None, 'read')],
    ))
    assert not _source_draft_action_is_supported(replace(action, evidence=evidence[:1]))
    assert not _source_draft_action_is_supported(replace(
        action, evidence=[replace(evidence[0], line=None), evidence[1]],
    ))
    assert not _source_draft_action_is_supported(replace(
        action, evidence=[evidence[0], replace(evidence[1], line=None)],
    ))
    assert not _source_draft_action_is_supported(replace(action, examples=[]))
    assert not _source_draft_action_is_supported(replace(action, status=ProofStatus.REFUTED))


def test_missing_branch_probe_does_not_block_exploratory_replay(tmp_path):
    from dataclasses import replace
    from harnesscreator.models import ProjectSpec, ScenarioCandidate, ScenarioStep
    from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier
    graph = _source(tmp_path)
    by_name = {f.name: f.function_id for f in graph.bundle.functions.values()}
    target_id = by_name['process_command_ascii']
    entry_id = by_name['tcp_read']
    evidence = [Evidence('source', target_id, graph.get(target_id).file,
                         graph.get(target_id).start_line, 'handler body')]
    action = ExternalActionSchema(
        action_id='get', entry_id='e', name='get', description='get',
        dispatcher_function_id=target_id, handler_function_id=target_id,
        discriminator='get', channel_kind='network_tcp', fields=[],
        examples=[ActionExample(b'get k\r\n'.hex(), {})],
        success_markers_hex=[b'END\r\n'.hex()], failure_markers_hex=[], evidence=evidence,
        inspected_function_ids=[target_id], status=ProofStatus.POSSIBLE,
        confidence=0.9, source_api='read', entry_function_id=entry_id,
        success_evidence=evidence,
    )
    step = ScenarioStep(0, action.action_id, action.entry_id,
                        action.examples[0].data_hex, {}, action.success_markers_hex)
    candidate = ScenarioCandidate('get-scenario', action.action_id, [step], ['e'], [], [])
    base = ProjectSpec(source_root=tmp_path, output_root=tmp_path / 'out',
        require_fuzz_introspector=False, svf_enabled=False,
        scenario_command=['./app'], scenario_channel='tcp', scenario_port=11999,
        scenario_attribution='gdb', scenario_exploratory_drafts=True).normalized()
    assert ScenarioRuntimeVerifier(base, [action], graph)._compatibility_error(candidate) == ''
    strict = replace(base, scenario_exploratory_drafts=False)
    assert ScenarioRuntimeVerifier(strict, [action], graph)._compatibility_error(candidate)


def test_source_only_auto_keeps_inferred_transport_in_harness_plan(tmp_path):
    from harnesscreator.models import ProjectSpec, ScenarioCandidate, ScenarioStep, ScenarioStatus
    from harnesscreator.runtime.scenario import ScenarioRuntimeVerifier
    from harnesscreator.agents.scenario_harness import build_harness_plan
    evidence = [Evidence('source', 'parser', 'p.c', 10, 'parser')]
    action = ExternalActionSchema(
        action_id='get', entry_id='entry', name='get', description='get',
        dispatcher_function_id='parser', handler_function_id='parser',
        discriminator='get', channel_kind='network_tcp', fields=[],
        examples=[ActionExample(b'get k\r\n'.hex(), {})],
        success_markers_hex=[b'END\r\n'.hex()], failure_markers_hex=[],
        evidence=evidence, inspected_function_ids=['parser'],
        status=ProofStatus.POSSIBLE, source_api='read', entry_function_id='acquire',
    )
    step = ScenarioStep(0, action.action_id, action.entry_id,
                        action.examples[0].data_hex, {}, action.success_markers_hex)
    candidate = ScenarioCandidate('scenario', action.action_id,
                                  [step], ['entry'], [], [])
    project = ProjectSpec(source_root=tmp_path, output_root=tmp_path / 'out',
                          require_fuzz_introspector=False, svf_enabled=False,
                          scenario_channel='auto', scenario_command=[]).normalized()
    witness = asyncio.run(ScenarioRuntimeVerifier(project, [action]).verify(candidate))
    assert witness.status is ScenarioStatus.UNPROVEN
    assert witness.channel == 'tcp'
    plan = build_harness_plan(witness,
        action_function_ids={action.action_id: ('acquire', 'parser')},
        allow_unproven=True)
    assert plan.boundary_contract['mode'] == 'original_input_transport'
    assert plan.boundary_contract['transport'] == 'tcp'
    assert plan.boundary_contract['status'] == 'SOURCE_ONLY_UNVERIFIED'
