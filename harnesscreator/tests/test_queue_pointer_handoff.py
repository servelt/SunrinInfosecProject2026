from harnesscreator.analysis.graph import GraphStore
from harnesscreator.models import AnalysisBundle, FunctionMetadata


def test_address_of_struct_member_enqueue_dequeue_navigation():
    producer = FunctionMetadata.create(name='producer',signature='void producer(void)',file='producer.c',start_line=1,end_line=4,source=
        'void producer(void) { mq_enqueue(&me->pending_requests, item); }')
    consumer = FunctionMetadata.create(name='consumer',signature='void consumer(void)',file='consumer.c',start_line=1,end_line=4,source=
        'void consumer(void) { item = mq_dequeue(&other->pending_requests); }')
    graph = GraphStore(AnalysisBundle({f.function_id:f for f in (producer, consumer)}, []))
    hint = graph.queue_handoff_candidates([producer.function_id])
    assert len(hint) == 1
    assert hint[0]['function_id'] == consumer.function_id
    assert hint[0]['connections'][0]['evidence_kind'] == 'lexical_navigation_only'
