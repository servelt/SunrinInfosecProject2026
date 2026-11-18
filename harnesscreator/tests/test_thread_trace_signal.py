"""The thread trace is written when the traced program is stopped with SIGTERM."""

import os
import shutil
import signal
import subprocess
import time
import unittest
from pathlib import Path
import tempfile

from harnesscreator.contexts.thread_trace import SymbolTable, read_trace

HOOK = Path(__file__).resolve().parents[1] / "src" / "harnesscreator" / "contexts" / "thread_trace_hook.c"
PROGRAM = """
#include <unistd.h>
void handle_request(void) { }
int main(void) { handle_request(); for (;;) pause(); }
"""


@unittest.skipUnless(shutil.which("gcc"), "gcc is required")
class SignalDumpTests(unittest.TestCase):
    def test_sigterm_leaves_a_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "p.c").write_text(PROGRAM)
            subprocess.run(["gcc", "-c", "-o", str(tmp / "hook.o"), str(HOOK)], check=True)
            subprocess.run(["gcc", "-O0", "-g", "-finstrument-functions", "-o", str(tmp / "p"), str(tmp / "p.c"),
                            str(tmp / "hook.o")], check=True)
            trace = tmp / "trace.txt"
            process = subprocess.Popen([str(tmp / "p")], env={**os.environ, "HC_THREAD_TRACE": str(trace)})
            time.sleep(0.3)
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=5), -signal.SIGTERM)    # it still dies of SIGTERM
            threads = read_trace(trace, SymbolTable(tmp / "p"))
            self.assertTrue(any("handle_request" in names for names in threads.values()))
