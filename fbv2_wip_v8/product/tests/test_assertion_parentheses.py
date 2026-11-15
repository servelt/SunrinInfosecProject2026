"""Focused regression for model-generated parenthesized assertions."""
import unittest

from vulnerabilityanalysis.assertions import validate_expression_source


class ParenthesizedAssertionTest(unittest.TestCase):
    def test_saved_expression_shapes(self):
        for expression in (
            "(wpos >= 0) && (wpos <= rpos) && (rpos < length)",
            "((starter - buffer) >= 0) && ((starter - buffer) < wpos)",
        ):
            with self.subTest(expression=expression):
                validate_expression_source(expression, "")

    def test_malformed_or_unsafe_expressions_stay_rejected(self):
        for expression in (
            "(wpos >= 0", "wpos >= 0)", "()", "(wpos > )",
            "(wpos >= 0) && (rpos <)", "(wpos >= 0) &&", "(helper(wpos) > 0)",
            "(wpos = 1)", "(wpos++)", "(wpos; rpos)",
        ):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                validate_expression_source(expression, "")

    def test_existing_pointer_arithmetic_guard_still_applies(self):
        with self.assertRaisesRegex(ValueError, "out-of-bounds pointer addition"):
            validate_expression_source("(cursor + n <= limit)",
                                       "const char *cursor = buffer;\n")


if __name__ == "__main__":
    unittest.main()
