"""Direct source declaration lookup used during request reconstruction."""
import tempfile
import unittest
from pathlib import Path

from harnesscreator.analysis.declarations import extract_declarations
from harnesscreator.analysis.indexer import StaticAnalyzer


class DeclarationIndexTests(unittest.TestCase):
    def test_macro_record_enum_inventory_and_qualified_lookup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.h").write_text(
                '#define NOREPLYSTR "noreply"\n'
                '#define WIDTH(x) \\\n+ ((x) + 1)\n'
                'typedef union { struct { unsigned char opcode; } request; '
                'unsigned char bytes[1]; } packet_header;\n'
                'typedef enum {\n CMD_GET = 0,\n CMD_SET = 1,\n} command;\n',
                encoding="utf-8")
            (root / "b.h").write_text('#define NOREPLYSTR "other"\n', encoding="utf-8")
            inventory = extract_declarations(root, [root / "a.h", root / "b.h"])
            self.assertEqual(len(inventory.lookup("NOREPLYSTR")), 2)
            self.assertEqual(len(inventory.lookup("a.h:NOREPLYSTR")), 1)
            (root / "b.h").write_text(
                '#define NOREPLYSTR "other"\n'
                '#undef NOREPLYSTR\n'
                '#define NOREPLYSTR "later"\n', encoding="utf-8")
            revised = extract_declarations(root, [root / "b.h"])
            self.assertEqual(len(revised.lookup("b.h:NOREPLYSTR")), 2)
            self.assertEqual(revised.lookup("b.h:3:NOREPLYSTR")[0].source,
                             '#define NOREPLYSTR "later"')
            self.assertIn("typedef union", inventory.lookup("packet_header")[0].source)
            self.assertIn("CMD_SET = 1", inventory.lookup("CMD_SET")[0].source)
            self.assertIn("((x) + 1)", inventory.lookup("WIDTH")[0].source)
            self.assertEqual([item["name"] for item in inventory.names("packet")],
                             ["packet_header"])

    def test_static_analysis_keeps_inventory_in_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "server.c").write_text(
                '#define NOREPLYSTR "noreply"\n'
                'typedef struct { unsigned char opcode; } packet_header;\n'
                'int handle(void) { return sizeof(packet_header); }\n',
                encoding="utf-8")
            analysis = StaticAnalyzer(root).index()
            names = {item.name for item in analysis.declarations}
            self.assertTrue({"NOREPLYSTR", "packet_header"} <= names)
            self.assertEqual(analysis.completeness["source_declaration_count"],
                             len(analysis.declarations))


if __name__ == "__main__":
    unittest.main()
