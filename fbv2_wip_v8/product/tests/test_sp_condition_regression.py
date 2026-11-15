"""Regression for a source-valid SP condition that was dropped before tracing."""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulnerabilityanalysis.agents import _source_condition_check
from vulnerabilityanalysis.assertions import validate_expression


class SPConditionRegression(unittest.TestCase):
    def test_builtin_pointer_sizeof_is_side_effect_free(self):
        validate_expression("count > INT_MAX / (int)sizeof(char *)")
        with self.assertRaises(ValueError):
            validate_expression("count > sizeof(CustomType *)")
        with self.assertRaises(ValueError):
            validate_expression("count > (value *)")

    def test_available_gcc_validates_source_when_clang_is_absent(self):
        real_which = shutil.which
        gcc = real_which("gcc")
        if gcc is None:
            self.skipTest("GCC is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.c"
            source.write_text("int parse(int count) {\n  return count;\n}\n")
            resolver = lambda name: None if name == "clang" else gcc if name == "gcc" else real_which(name)
            with patch("vulnerabilityanalysis.agents.shutil.which", side_effect=resolver):
                self.assertIsNone(_source_condition_check(source, 2, "count > 0"))
                self.assertIn("condition expression invalid in target build", _source_condition_check(
                    source, 2, "missing_symbol > 0"))


if __name__ == "__main__":
    unittest.main()
