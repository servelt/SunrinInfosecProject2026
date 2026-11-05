from __future__ import annotations

import unittest
from harnesscreator.models import ActionExample, Evidence, InputFieldConstraint
from harnesscreator.runtime.request_ir import render_request


class RequestIRTests(unittest.TestCase):
    def setUp(self):
        self.evidence = [Evidence('source', 'parser', 'parser.c', 10, 'source-located field')]

    def field(self, name, start, width, encoding='bytes', binding='', relation='opaque'):
        return InputFieldConstraint(name, start, width, encoding, binding, relation, self.evidence)

    def test_variable_width_updates_ascii_length_and_all_following_offsets(self):
        # Original seed is a value of length three. The source-proven length
        # dependency is declarative. The renderer changes offsets itself.
        example = ActionExample(b'SET 3:abc!\n'.hex(), {'value': b'abc'.hex()})
        fields = [
            self.field('count', 4, 1, 'ascii_decimal', '', 'length_of(value)'),
            self.field('value', 6, 3, 'variable_bytes', 'value'),
        ]
        rendered = render_request(example, fields, override_bindings={'value': b'abcdefghijkl'})
        self.assertEqual(rendered.data, b'SET 12:abcdefghijkl!\n')
        self.assertEqual(rendered.offsets['value'], (7, 12))
        self.assertEqual(rendered.bindings['value'], b'abcdefghijkl')

    def test_crc32_and_unrecognized_relation_not_executed(self):
        import zlib
        data = b'ABCD\x00\x00\x00\x00'
        example = ActionExample(data.hex())
        fields = [
            self.field('payload', 0, 4, 'bytes', '', 'human description'),
            self.field('checksum', 4, 4, 'u32le', '', 'crc32_of(payload)'),
        ]
        out = render_request(example, fields)
        self.assertEqual(out.data, b'ABCD' + zlib.crc32(b'ABCD').to_bytes(4, 'little'))

    def test_missing_dependency_and_overlapping_fields_fail_closed(self):
        example = ActionExample(b'AA42'.hex())
        with self.assertRaisesRegex(ValueError, 'unknown field'):
            render_request(example, [self.field('len', 2, 2, 'ascii_decimal', '', 'length_of(missing)')])
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            render_request(example, [self.field('a', 0, 3), self.field('b', 1, 1)])

    def test_does_not_resize_fixed_width_bindings(self):
        example = ActionExample(b'GET x\n'.hex(), {'key': b'x'.hex()})
        with self.assertRaisesRegex(ValueError, 'fixed-width'):
            render_request(example, [self.field('key', 4, 1, 'bytes', 'key')],
                           override_bindings={'key': b'longer'})


if __name__ == '__main__':
    unittest.main()

# Keep these independent of ScriptedLLM: they exercise actual binary request
# rendering with source-located field rules.
class RequestIRDerivedContractTests(RequestIRTests):
    def test_unknown_derived_relation_blocks_mutated_frame(self):
        example = ActionExample(b'3:abc'.hex(), {'value': b'abc'.hex()})
        fields = [
            self.field('total', 0, 1, 'ascii_decimal', '', 'total_frame_length'),
            self.field('value', 2, 3, 'variable_bytes', 'value'),
        ]
        with self.assertRaisesRegex(ValueError, 'unsupported relation'):
            render_request(example, fields, override_bindings={'value': b'abcdefgh'})

    def test_unknown_relation_keeps_original_unmodified_input(self):
        example = ActionExample(b'3:abc'.hex(), {'value': b'abc'.hex()})
        fields = [
            self.field('total', 0, 1, 'ascii_decimal', '', 'total_frame_length'),
            self.field('value', 2, 3, 'variable_bytes', 'value'),
        ]
        self.assertEqual(render_request(example, fields).data, b'3:abc')

    def test_nested_derived_length_computes_resolved_values(self):
        example = ActionExample(b'13:abc'.hex(), {'value': b'abc'.hex()})
        # prefix2 := length_of(prefix1), prefix1 := length_of(value).
        # Existing initial seed allows 1 and 3; override needs 2 and 12.
        fields = [
            self.field('prefix2', 0, 1, 'ascii_decimal', '', 'length_of(prefix1)'),
            self.field('prefix1', 1, 1, 'ascii_decimal', '', 'length_of(value)'),
            self.field('value', 3, 3, 'variable_bytes', 'value'),
        ]
        out = render_request(example, fields, override_bindings={'value': b'abcdefghijkl'})
        self.assertEqual(out.data, b'212:abcdefghijkl')

    def test_derived_cycle_rejected(self):
        example = ActionExample(b'12'.hex())
        fields = [
            self.field('a', 0, 1, 'ascii_decimal', '', 'length_of(b)'),
            self.field('b', 1, 1, 'ascii_decimal', '', 'length_of(a)'),
        ]
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            render_request(example, fields)
