import unittest
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.models import AnalysisBundle, FunctionMetadata

class QueueFrontierTests(unittest.TestCase):
    def test_typed_field_writer_is_hint_and_other_type_is_not(self):
        def fn(name, source):
            return FunctionMetadata.create(name=name, signature=name, file='x.c', start_line={'consumer':1, 'producer':10, 'unrelated':20}[name], end_line=30, source=source)
        consumer = fn('consumer', 'void consumer(void) { CQ_ITEM *item; item = cq_pop(q); use(item->sfd); }')
        producer = fn('producer', 'void producer(int fd) { CQ_ITEM *item; item->sfd = fd; cq_push(q,item); }')
        unrelated = fn('unrelated', 'void unrelated(int fd) { OTHER *item; item->sfd = fd; }')
        graph = GraphStore(AnalysisBundle({x.function_id:x for x in (consumer,producer,unrelated)}, []))
        choices = graph.shared_field_candidates([consumer.function_id])
        self.assertEqual([x['name'] for x in choices], ['producer'])
        self.assertEqual(choices[0]['connections'][0]['evidence_kind'], 'lexical_navigation_only')
        self.assertEqual(graph.frontier([consumer.function_id]), [])

if __name__ == '__main__': unittest.main()
