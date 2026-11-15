"""Provider-free tests for an opt-in, bounded Direction source view."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

PREP = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PREP / 'evaluation_tools'), str(PREP / 'review_tools')]

from development_direction_study import build_context  # noqa: E402
from blind3_direction_context_windows_dev import window_excerpt  # noqa: E402


def old_context(source: str) -> dict:
    rows = [
        {'function_id': 'fn-a', 'name': 'A', 'file': 'target.c', 'source': source},
        {'function_id': 'fn-b', 'name': 'B', 'file': 'target.c',
         'source': 'int B(unsigned x) { return (int)x; }'},
    ]
    files = {
        'harness/source': b'extern int A(const unsigned char*, unsigned long);\n',
        'catalog/functions.jsonl': ''.join(json.dumps(x) + '\n' for x in rows).encode(),
        'catalog/edges.jsonl': (json.dumps({
            'caller_id': 'fn-a', 'callee_id': 'fn-b'}) + '\n').encode(),
        'catalog/indirect_edges.jsonl': b'',
    }
    return build_context(files, None, source_mode='all_catalog_prefix',
                         harness_member='harness/source', anchor_ids=['fn-a'])


class DirectionWindowsTests(unittest.TestCase):
    def test_late_call_argument_is_visible_with_same_800_source_char_cap(self):
        prefix = ('int A(const unsigned char *data, unsigned long size) {\n' +
                  '  unsigned harmless_padding = 0;\n' * 30)
        suffix = '  harmless_padding += 1;\n' * 35 + '}\n'
        input_source = prefix + '  return size ? B(data[0]) : 0;\n' + suffix
        fixed_source = prefix + '  return size ? B(0) : 0;\n' + suffix
        self.assertGreater(input_source.index('B(data[0])'), 800)
        self.assertEqual(old_context(input_source), old_context(fixed_source))
        call_line = input_source[:input_source.index('B(data[0])')].count('\n') + 1
        left = window_excerpt(input_source, 1, [call_line])
        right = window_excerpt(fixed_source, 1, [call_line])
        text_left = ''.join(row[3] for row in left['source_windows'])
        text_right = ''.join(row[3] for row in right['source_windows'])
        self.assertIn('B(data[0])', text_left)
        self.assertIn('B(0)', text_right)
        self.assertNotEqual(text_left, text_right)
        self.assertLessEqual(len(text_left), 800)
        self.assertTrue(left['source_truncated'])
        self.assertTrue(left['omitted_ranges'])
        self.assertEqual(left['callsite_line_omitted'], [])

    def test_many_calls_mark_unshown_lines_and_keep_disjoint_offsets(self):
        lines = ['int A(void) {', *['  int filler = 0;' for _ in range(25)]]
        call_lines = []
        for index in range(8):
            call_lines.append(len(lines) + 1)
            lines.append(f'  B({index});')
            lines.extend(['  filler += 1;' for _ in range(12)])
        lines.append('  return 0;')
        lines.append('}')
        excerpt = window_excerpt('\n'.join(lines) + '\n', 1, call_lines)
        windows = excerpt['source_windows']
        self.assertLessEqual(sum(len(row[3]) for row in windows), 800)
        self.assertEqual(len(excerpt['callsite_line_omitted']), 4)
        self.assertTrue(all(a[1] <= b[0]
                            for a, b in zip(windows, windows[1:])))
        self.assertTrue(excerpt['source_context_incomplete'])

    def test_short_source_is_full_and_has_no_omitted_ranges(self):
        source = 'int A(void) { return B(0); }\n'
        excerpt = window_excerpt(source, 7, [7])
        self.assertEqual([row[3] for row in excerpt['source_windows']], [source])
        self.assertEqual(excerpt['omitted_ranges'], [])
        self.assertFalse(excerpt['source_truncated'])


if __name__ == '__main__':
    unittest.main()
