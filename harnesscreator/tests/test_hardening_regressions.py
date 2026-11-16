from __future__ import annotations

import unittest
from pathlib import Path

from harnesscreator.analysis.graph import GraphStore
from harnesscreator.models import AnalysisBundle, FunctionMetadata
from harnesscreator.runtime.scenario import _response_marker_matches
from harnesscreator.runtime.crash import crash_signatures_match, extract_crash_signature


class HardeningRegressions(unittest.TestCase):
    def test_status_prefix_collision_is_never_accepted(self):
        for response in (b'NOT_STORED\r\n', b'STORED_ERROR\r\n', b'STORED_MORE'):
            self.assertFalse(_response_marker_matches(response, b'STORED'))
            self.assertFalse(_response_marker_matches(response, b'STORED\r\n'))
        self.assertTrue(_response_marker_matches(b'STORED\r\n', b'STORED\r\n'))
        self.assertTrue(_response_marker_matches(b'STORED\r\n', b'STORED'))
        self.assertTrue(_response_marker_matches(b'STORED\n', b'STORED'))
        self.assertTrue(_response_marker_matches(b'OK: done\r\n', b'OK:'))

    def test_shared_caller_does_not_define_same_crash(self):
        first = extract_crash_signature(
            'ERROR: AddressSanitizer: heap-buffer-overflow\n'
            '#0 0x111 in parse_one /src/one.c:32\n'
            '#1 0x222 in dispatcher /src/server.c:99\n'
        )
        second = extract_crash_signature(
            'ERROR: AddressSanitizer: heap-buffer-overflow\n'
            '#0 0x333 in parse_two /src/two.c:28\n'
            '#1 0x444 in dispatcher /src/server.c:99\n'
        )
        same = extract_crash_signature(
            'ERROR: AddressSanitizer: heap-buffer-overflow\n'
            '#0 0x999 in parse_one /other/build/one.c:32\n'
            '#1 0xAAA in dispatcher /other/build/server.c:99\n'
        )
        self.assertFalse(crash_signatures_match(first, second))
        self.assertTrue(crash_signatures_match(first, same))

    def test_async_queue_navigation_is_never_a_call_edge(self):
        producer = FunctionMetadata.create(
            name='dispatch_conn_new', file='conn.c', start_line=1, end_line=3,
            signature='void dispatch_conn_new(void)', source=(
                'void dispatch_conn_new(void) {\n'
                '  cq_push(thread->new_conn_queue, item);\n'
                '}\n'
            ),
        )
        consumer = FunctionMetadata.create(
            name='thread_libevent_process', file='thread.c', start_line=11, end_line=13,
            signature='void thread_libevent_process(void)', source=(
                'void thread_libevent_process(void) {\n'
                '  item = cq_pop(me->new_conn_queue);\n'
                '}\n'
            ),
        )
        graph = GraphStore(AnalysisBundle(
            functions={producer.function_id: producer, consumer.function_id: consumer},
            edges=[],
        ))
        candidates = graph.queue_handoff_candidates([producer.function_id])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]['function_id'], consumer.function_id)
        self.assertEqual(candidates[0]['connections'][0]['relation'], 'queue_handoff_candidate')
        self.assertEqual(graph.shortest_path(producer.function_id, consumer.function_id), [])
        self.assertTrue(any(item['function_id'] == consumer.function_id
                            for item in graph.frontier([producer.function_id])))

    def test_same_name_unrelated_queues_do_not_merge(self):
        producer = FunctionMetadata.create(
            name='produce', file='one.c', start_line=1, end_line=2,
            signature='void produce(void)', source='void produce(void) {cq_push(ctx->read_queue, x);}',
        )
        consumer = FunctionMetadata.create(
            name='consume', file='two.c', start_line=1, end_line=2,
            signature='void consume(void)', source='void consume(void) {cq_pop(ctx->write_queue);}',
        )
        graph = GraphStore(AnalysisBundle(
            functions={producer.function_id: producer, consumer.function_id: consumer},
            edges=[],
        ))
        self.assertEqual(graph.queue_handoff_candidates([producer.function_id]), [])


if __name__ == '__main__':
    unittest.main()
