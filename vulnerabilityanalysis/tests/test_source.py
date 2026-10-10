import unittest
import tempfile
from pathlib import Path

from vulnerabilityanalysis.source import SourceRepository


ROOT = Path(__file__).resolve().parents[2]


class SourceTest(unittest.TestCase):
    def test_extracts_cpp_const_method_without_neighbor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.cpp").write_text(
                "int Parser::value() const\n{ return count; }\n"
                "int Parser::other() const\n{ return 0; }\n")
            source = SourceRepository(root, {
                "Parser::value": {"file": "target.cpp", "start_line": 1}}).open_function(
                    "Parser::value")
            self.assertIn("return count", source)
            self.assertNotIn("Parser::other", source)

    def test_extracts_cpp_constructor_initializer_list(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "target.cpp").write_text(
                "Parser::Parser(int n): count(n), valid(true)\n{ count++; }\n"
                "Parser::~Parser()\n{ count = 0; }\n")
            source = SourceRepository(root, {
                "Parser::Parser": {"file": "target.cpp", "start_line": 1}}).open_function(
                    "Parser::Parser")
            self.assertIn("count(n)", source)
            self.assertNotIn("Parser::~Parser", source)

    def test_extracts_one_real_function_without_neighbor(self):
        repo = ROOT / "harnessgenerator/harnesscreator/tests/fixtures/c_project"
        catalog = {"parse_frame": {"file": "target.c", "start_line": 8},
                   "serve_client": {"file": "target.c", "start_line": 15}}
        source = SourceRepository(repo, catalog).open_function("parse_frame")
        self.assertIn("if (size < 2)", source)
        self.assertNotIn("serve_client", source)


if __name__ == "__main__":
    unittest.main()
