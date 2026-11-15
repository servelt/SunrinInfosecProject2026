"""Provider-free proof that the pinned emitter actually launches its target."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


EMITTER = Path(__file__).parents[1] / "devtools" / "md4c_uaf_trace_emitter.py"


def test_emitter_executes_target_and_binds_target_receipt(tmp_path):
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"provider-free-md4c-input")
    target = tmp_path / "instrumented-target"
    marker = tmp_path / "target-ran"
    target.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\n"
        f"open({str(marker)!r},'wb').write(b'yes')\n"
        "trace={'kind':'FBV2_UAF_RAW_TRACE_V1',"
        "'evaluation_id':os.environ['FBV2_EVALUATION_ID'],"
        "'input_sha256':os.environ['FBV2_INPUT_SHA256'],'events':[]}\n"
        "with open(os.environ['FBV2_TRACE_PATH'],'x') as stream:\n"
        " json.dump(trace,stream,separators=(',',':'),sort_keys=True)\n"
        " stream.flush(); os.fsync(stream.fileno())\n"
        "sys.stderr.write('synthetic target stderr\\n')\n"
        "raise SystemExit(1)\n")
    target.chmod(0o700)
    trace_path = tmp_path / "target-trace.json"
    env = {
        "PATH": os.environ.get("PATH", ""),
        "FBV2_BINARY_SHA256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "FBV2_INPUT_SHA256":
            hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "FBV2_EVALUATION_ID": "eval-emitter-1",
        "FBV2_TRACE_PATH": str(trace_path),
    }
    done = subprocess.run(
        [sys.executable, str(EMITTER), str(target), str(input_path),
         str(trace_path)], cwd=tmp_path, env=env, capture_output=True,
        check=False)
    assert done.returncode == 1
    assert marker.read_bytes() == b"yes"
    assert done.stderr == b"synthetic target stderr\n"
    raw = json.loads(done.stdout)
    target_receipt = raw["target_execution"]
    assert target_receipt["binary_path"] == str(target)
    assert target_receipt["input_path"] == str(input_path)
    assert target_receipt["returncode"] == 1
    assert target_receipt["stderr_sha256"] == hashlib.sha256(
        done.stderr).hexdigest()
