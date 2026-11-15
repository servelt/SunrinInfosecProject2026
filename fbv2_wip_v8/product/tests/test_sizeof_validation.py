from pathlib import Path
import tempfile
import unittest

from vulnerabilityanalysis.assertions import instrument_copy, validate_expression


class SizeofValidationTests(unittest.TestCase):
    def test_builtin_type_sizeof_is_accepted(self):
        validate_expression('blocksize <= ((size_t)-1) / sizeof(unsigned short)')

    def test_builtin_type_sizeof_instrumentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'sample.c'
            target = root / 'instrumented.c'
            source.write_text('#include <stddef.h>\nint f(size_t blocksize) { return (int)blocksize; }\n')
            instrument_copy(source, 2, 'blocksize <= ((size_t)-1) / sizeof(unsigned short)',
                            target, 'SIZEOF-TYPE-001')
            self.assertIn('sizeof(unsigned short)', target.read_text())

    def test_builtin_type_sizeof_with_build_preprocessing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'sample.c'
            target = root / 'instrumented.c'
            source.write_text('#include <stddef.h>\nint f(size_t blocksize) { return (int)blocksize; }\n')
            command = ['gcc', '-std=c99', '-c', str(source), '-o', str(root / 'sample.o')]
            instrument_copy(source, 2, 'blocksize <= ((size_t)-1) / sizeof(unsigned short)',
                            target, 'SIZEOF-TYPE-002', build_command=command)
            self.assertIn('sizeof(unsigned short)', target.read_text())

    def test_sizeof_value_expression_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_expression('blocksize <= ((size_t)-1) / sizeof(blocksize)')

    def test_unknown_type_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_expression('blocksize <= ((size_t)-1) / sizeof(CustomType)')

    def test_function_call_remains_rejected(self):
        with self.assertRaises(ValueError):
            validate_expression('blocksize <= malloc(4)')

    def test_nested_call_remains_rejected(self):
        with self.assertRaises(ValueError):
            validate_expression('blocksize <= sizeof(malloc(4))')

    def test_function_call_hidden_by_comment_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_expression('blocksize <= malloc/**/(4)')


if __name__ == '__main__':
    unittest.main()
