"""Read-only build preflight for the md4c causal instrumentation patch."""

from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).parents[1]
MD4C_REPO = Path(
    "/home/dawne/work/SunrinInfosecProject2026/fbv2_md4c_workspace/repo")
PATCH = ROOT / "devtools" / "md4c_uaf_trace_source.patch"
HEADER = ROOT / "devtools" / "md4c_uaf_trace_hooks.h"


def test_md4c_instrumentation_patch_applies_and_parses_as_c(tmp_path):
    assert MD4C_REPO.joinpath("src/md4c.c").is_file()
    assert shutil.which("patch") and shutil.which("cc")
    copied = tmp_path / "repo"
    shutil.copytree(MD4C_REPO, copied, symlinks=True)
    shutil.copy2(HEADER, copied / "src" / HEADER.name)
    applied = subprocess.run(
        ["patch", "-s", "-d", str(copied), "-p1", "-i", str(PATCH)],
        capture_output=True, text=True, check=False)
    assert applied.returncode == 0, applied.stderr
    compiled = subprocess.run([
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-DFBV2_UAF_CAUSAL_TRACE=1", f"-I{copied / 'src'}",
        "-fsyntax-only", str(copied / "src" / "md4c.c"),
    ], capture_output=True, text=True, check=False)
    assert compiled.returncode == 0, compiled.stderr
