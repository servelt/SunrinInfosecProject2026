"""Commit invariants as tagged assertions and rebuild the harness (Code Augur §4.2, §4.3, §5).

Each invariant phi_N becomes one inserted line before its source line:

    do { fba_phi_reach(N); [fba_phi_dist(N, (__int128)(L) - (__int128)(R));] if (!(E)) fba_phi_violate(N); } while (0);

The runtime (appended to a copy of the harness) exports libFuzzer extra counters,
16 slots per invariant as in Code Augur's C/C++ backend: one for reachability, one
for tripping and 14 logarithmic distance buckets.  The first violation of an
invariant aborts (so the fuzzer saves the input for triage); invariants listed in
FBA_PHI_CONTINUE only report and continue, so the fuzzer can keep exploring past
an already-triaged violation.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

MAX_PHI = 512

RUNTIME = r"""

/* ---- fbaugur invariant runtime (Code Augur style falsification) ---- */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define FBA_MAX_PHI %(max_phi)d
__attribute__((used, section("__libfuzzer_extra_counters")))
static uint8_t fba_extra_counters[FBA_MAX_PHI * 16];
static int fba_mode_loaded;
static int fba_trace;
static char fba_continue[8192];
static unsigned char fba_reported[FBA_MAX_PHI];
static void fba_load_mode(void) {
    if (fba_mode_loaded) return;
    const char *list = getenv("FBA_PHI_CONTINUE");
    if (list) snprintf(fba_continue, sizeof fba_continue, ",%%s,", list);
    fba_trace = getenv("FBA_PHI_TRACE") != NULL;
    fba_mode_loaded = 1;
}
void fba_phi_reach(unsigned id) {
    if (id >= FBA_MAX_PHI) return;
    fba_extra_counters[id * 16] = 1;
    fba_load_mode();
    /* Printed on EVERY pass under trace, not once: this call happens immediately before the
       assertion's expression is evaluated, so when the expression itself faults (a NULL
       dereference written by the recorder) the last marker in the log names the assertion.
       Nothing else identifies it -- a bare SEGV carries no UBSan line, and a build without
       llvm-symbolizer has no file or line in its frames either.  Trace is only on while
       probing a new build, so the volume is bounded. */
    if (fba_trace) { fba_reported[id] |= 1; fprintf(stderr, "FBA_PHI_REACHED:%%u\n", id); fflush(stderr); }
}
void fba_phi_dist(unsigned id, __int128 d) {
    if (id >= FBA_MAX_PHI) return;
    unsigned bucket = 0;
    if (d < 0) d = -d;
    while (d && bucket < 13) { bucket++; d >>= 1; }
    fba_extra_counters[id * 16 + 2 + bucket] = 1;
}
__attribute__((noinline)) void fba_phi_violate(unsigned id) {
    char key[32];
    if (id >= FBA_MAX_PHI) return;
    fba_extra_counters[id * 16 + 1] = 1;
    fba_load_mode();
    fprintf(stderr, "FBA_PHI_VIOLATION:%%u\n", id);
    snprintf(key, sizeof key, ",%%u,", id);
    if (!strstr(fba_continue, key)) abort();
}
""" % {"max_phi": MAX_PHI}

PROTOTYPES_C = "void fba_phi_reach(unsigned); void fba_phi_dist(unsigned, __int128); void fba_phi_violate(unsigned);"
PROTOTYPES_CXX = 'extern "C" { ' + PROTOTYPES_C + " }"

_FORBIDDEN_START = re.compile(r"^\s*(else\b|case\b|default\s*:|}|#|\w+\s*:(?!:))")
_ALLOWED_CALLS = {"sizeof", "offsetof", "__builtin_offsetof", "_Alignof", "__alignof__", "defined"}


@dataclasses.dataclass
class Invariant:
    num: int
    file: str          # relative to the source root
    line: int          # insert before this original line
    expression: str
    distance: bool = True

    def snippet(self) -> str:
        parts = [f"fba_phi_reach({self.num});"]
        operands = split_comparison(self.expression)
        if self.distance and operands:
            left, _, right = operands
            parts.append(f"fba_phi_dist({self.num}, (__int128)({left}) - (__int128)({right}));")
        parts.append(f"if (!({self.expression})) fba_phi_violate({self.num});")
        return "do { " + " ".join(parts) + f" }} while (0); /* fba-phi {self.num} */\n"


def split_comparison(expression: str) -> tuple[str, str, str] | None:
    """Split `L op R` at its single top-level comparison; None when not a simple comparison."""
    depth, positions = 0, []
    text = expression.strip()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0:
            two = text[i:i + 2]
            if two in ("&&", "||"):
                return None
            if ch == "?":
                return None
            if two in ("<=", ">=", "==", "!="):
                if text[i:i + 3] in ("<<=", ">>="):
                    return None
                positions.append((i, two))
                i += 2
                continue
            if ch in "<>" and text[i:i + 2] not in ("<<", ">>") and text[i - 1:i + 1] not in ("<<", ">>", "->"):
                positions.append((i, ch))
        i += 1
    if len(positions) != 1:
        return None
    pos, op = positions[0]
    left, right = text[:pos].strip(), text[pos + len(op):].strip()
    return (left, op, right) if left and right else None


def lexical_problems(expression: str, function_like_macros: set[str]) -> list[str]:
    problems = []
    masked = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', expression)
    if re.search(r"(?<![=!<>])=(?!=)", masked):
        problems.append("contains an assignment")
    if "++" in masked or "--" in masked:
        problems.append("contains an increment or decrement")
    for name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", masked):
        if name not in _ALLOWED_CALLS and name not in function_like_macros:
            problems.append(f"calls `{name}(...)`, which is not a known side-effect-free macro")
    if not masked.strip():
        problems.append("is empty")
    return problems


def function_like_macros(source_root: Path) -> set[str]:
    names: set[str] = set()
    for path in list(source_root.glob("*.h")) + list(source_root.glob("*.c")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names.update(re.findall(r"^\s*#\s*define\s+([A-Za-z_]\w*)\(", text, re.M))
    return names


_CONTROL_WITH_PARENS = {"if", "for", "while", "switch"}
_LINE_COMMENT = re.compile(r"//.*$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/")


def _code_of(text: str) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub(" ", text)).strip()


def unbraced_body_of(lines: list[str], line: int) -> tuple[str, int] | None:
    """(keyword, line) of the control statement whose only, unbraced statement is `line`.

    Inserting a statement in front of such a line makes the inserted statement the body and
    leaves the original one outside the condition.  tinyproxy's hsearch.c, line 120:
        if ((!e->item.key && ...) ||
            (e->hash==hash && STRCMP(e->item.key, key)==0))
                break;
    An assertion inserted before `break;` turned it into an unconditional break: every lookup
    stopped at the first slot, the header map broke, and the program faulted far away -- after
    which two innocent assertions were withdrawn as "unsafe".  The same holds for an opening
    brace on its own line after `if (...)`.
    """
    k = line - 2
    while k >= 0:
        code = _code_of(lines[k])
        if code and not code.startswith(("#", "*", "/*")):
            break
        k -= 1
    if k < 0:
        return None
    code = _code_of(lines[k])
    last_word = re.search(r"(\w+)$", code)
    if last_word and last_word.group(1) in ("else", "do"):
        return last_word.group(1), k + 1
    if not code.endswith(")"):
        return None
    depth, row, col = 0, k, len(code) - 1
    text = code
    while row >= 0:
        while col >= 0:
            ch = text[col]
            if ch == ")":
                depth += 1
            elif ch == "(":
                depth -= 1
                if depth == 0:
                    before = re.search(r"(\w+)\s*$", text[:col])
                    if before and before.group(1) in _CONTROL_WITH_PARENS:
                        return before.group(1), row + 1
                    return None
            col -= 1
        row -= 1
        if row < 0 or k - row > 40:
            return None
        text = _code_of(lines[row])
        col = len(text) - 1
    return None


def location_problems(lines: list[str], line: int) -> list[str]:
    if not 1 <= line <= len(lines):
        return [f"line {line} is outside the file ({len(lines)} lines)"]
    text = lines[line - 1]
    if not text.strip():
        return [f"line {line} is blank; choose the line of the statement itself"]
    if _FORBIDDEN_START.match(text):
        return [f"line {line} (`{text.strip()[:80]}`) does not start a statement (else/case/label/brace/preprocessor)"]
    owner = unbraced_body_of(lines, line)
    if owner is not None:
        keyword, at = owner
        return [f"line {line} (`{text.strip()[:80]}`) is the only statement of the `{keyword}` on line {at}, which "
                f"has no braces; an assertion inserted there would become that statement and push line {line} "
                f"out of the `{keyword}`, changing what the program does. Put it on line {at} (before the "
                f"`{keyword}`) or inside a braced block"]
    return []


def instrument_text(text: str, invariants: list[Invariant], cxx: bool) -> tuple[str, dict[int, int]]:
    """Insert snippets; returns new text and a map new_line -> phi num."""
    lines = text.splitlines(keepends=True)
    by_line: dict[int, list[Invariant]] = {}
    for inv in invariants:
        by_line.setdefault(inv.line, []).append(inv)
    out = [(PROTOTYPES_CXX if cxx else PROTOTYPES_C) + "\n"]
    line_map: dict[int, int] = {}
    for number, line in enumerate(lines, start=1):
        for inv in by_line.get(number, []):
            out.append(inv.snippet())
            line_map[len(out)] = inv.num
        out.append(line)
    return "".join(out), line_map


@dataclasses.dataclass
class BuildResult:
    ok: bool
    binary: Path | None
    error: str
    failing: list[int]        # phi nums blamed for a compile error
    # instrumented file (as the compiler names it) -> {line in that file: phi num}.
    # A sanitizer report from P' names a line of the instrumented copy, so this is
    # what turns "SEGV at ftpserv.c:1684" into "invariant phi 16 is unsafe".
    line_map: dict[str, dict[int, int]] = dataclasses.field(default_factory=dict)


class InvariantBuilder:
    """Builds P' for one harness: a source copy with all given invariants inserted."""

    def __init__(self, *, source_root: Path, harness_source: Path, build_plan: Path | None, work_dir: Path,
                 harnesscreator_src: Path, python: str, extra_cflags: str = "",
                 sanitizer: str = "address+undefined", compile_database: Path | None = None):
        self.source_root = source_root
        self.harness_source = harness_source
        self.work_dir = work_dir
        self.harnesscreator_src = harnesscreator_src
        self.python = python or sys.executable
        self.plan: dict[str, Any] = {}
        if build_plan and build_plan.is_file():
            self.plan = json.loads(build_plan.read_text(encoding="utf-8"))
        self.extra_cflags = extra_cflags
        self.sanitizer = sanitizer
        self.compile_database = compile_database
        self.macros = function_like_macros(source_root)
        self.base = work_dir / "src-base"

    # -- source copy -----------------------------------------------------------
    def ensure_base(self) -> None:
        if (self.base / ".fba-complete").is_file():
            return
        if self.base.exists():
            shutil.rmtree(self.base)
        self.base.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cp", "-a", str(self.source_root), str(self.base)], check=True)
        for pattern in ("*.o", "*.gcda", "*.gcno"):
            for path in self.base.rglob(pattern):
                path.unlink(missing_ok=True)
        (self.base / ".fba-complete").write_text("ok\n")

    def _relocated_database(self, src: Path, root: Path) -> Path | None:
        """The project's compile database, rewritten to point at the instrumented copy.

        The rebuild compiles a copy of the source tree, so every path into the original source
        root is moved to the copy and everything else -- defines, include order, language
        standard -- is kept as the project builds it.  Without this the rebuild had no flags at
        all: tinyproxy's sources need -DHAVE_CONFIG_H to read config.h, every rebuild failed with
        "use of undeclared identifier 'PACKAGE'", and no invariant and no MemorySanitizer build
        ever ran.  LightFTP compiles without any define, which is why it never showed.
        """
        if self.compile_database is None or not Path(self.compile_database).is_file():
            return None
        original = str(self.source_root.resolve())
        copy = str(src.resolve())

        def move(value):
            if isinstance(value, str):
                return copy + value[len(original):] if value.startswith(original) else \
                    value.replace("=" + original, "=" + copy).replace("-I" + original, "-I" + copy)
            if isinstance(value, list):
                return [move(item) for item in value]
            return value

        entries = json.loads(Path(self.compile_database).read_text(encoding="utf-8"))
        relocated = [{key: move(value) for key, value in entry.items()} for entry in entries]
        path = root / "compile_commands.json"
        path.write_text(json.dumps(relocated, indent=1), encoding="utf-8")
        return path

    def compile_command(self, rel_file: str) -> list[str] | None:
        target = str((self.source_root / rel_file).resolve())
        for argv in self.plan.get("compile_commands", []):
            if "-c" in argv and argv[argv.index("-c") + 1] == target:
                return list(argv)
        return None

    # -- checks ------------------------------------------------------------------
    def precheck(self, file: str, line: int, expression: str) -> list[str]:
        path = self.source_root / file
        if not path.resolve().is_relative_to(self.source_root.resolve()) or not path.is_file():
            return [f"file `{file}` is not a source file under the source root"]
        if self.compile_command(file) is None:
            return [f"`{file}` is not compiled into the harness (pick a .c file of the program)"]
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return location_problems(lines, line) + [f"the expression {p}" for p in lexical_problems(expression, self.macros)]

    def syntax_check(self, inv: Invariant, scratch: Path) -> tuple[str | None, bool]:
        """(error or None, distance_kept).  Retries without the distance probe on failure."""
        argv = self.compile_command(inv.file)
        if argv is None:
            return f"`{inv.file}` is not compiled into the harness", inv.distance
        original = (self.source_root / inv.file).read_text(encoding="utf-8", errors="replace")
        scratch.mkdir(parents=True, exist_ok=True)
        attempts = [inv.distance, False] if inv.distance else [False]
        error = None
        for distance in attempts:
            candidate = dataclasses.replace(inv, distance=distance)
            text, line_map = instrument_text(original, [candidate], inv.file.endswith((".cc", ".cpp", ".cxx")))
            copy = scratch / Path(inv.file).name
            copy.write_text(text, encoding="utf-8")
            check = list(argv)
            i = check.index("-c")
            check[i:i + 2] = ["-fsyntax-only", str(copy)]
            if "-o" in check:
                j = check.index("-o")
                del check[j:j + 2]
            check += ["-Wtautological-compare", "-Wtautological-constant-out-of-range-compare",
                      "-Wtype-limits", "-Wno-error"]
            proc = subprocess.run(check, capture_output=True, text=True, cwd=str(self.source_root), timeout=120)
            inserted = next(iter(line_map))
            ours = [l for l in proc.stderr.splitlines() if re.match(rf"^{re.escape(str(copy))}:{inserted}:\d+: ", l)]
            if proc.returncode == 0:
                always = [l for l in ours if "always true" in l or "always false" in l]
                if always:
                    return ("the comparison is decided by the operand types (compiler: "
                            + always[0].split(": ", 2)[-1] + "); it can never be falsified"), distance
                return None, distance
            error = "\n".join(l for l in proc.stderr.splitlines() if "error" in l)[:3000] or proc.stderr[-3000:]
            error = error.replace(str(copy), inv.file)
        return error, False

    # -- full build -----------------------------------------------------------------
    def build(self, version: int, invariants: list[Invariant], log) -> BuildResult:
        self.ensure_base()
        root = self.work_dir / f"v{version}"
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
        src = root / "src"
        # Hard-link copy: cheap per version, and each instrumented file is unlinked
        # before being rewritten so the shared base copy stays untouched.
        subprocess.run(["cp", "-al", str(self.base), str(src)], check=True)
        line_maps: dict[str, dict[int, int]] = {}
        by_file: dict[str, list[Invariant]] = {}
        for inv in invariants:
            by_file.setdefault(inv.file, []).append(inv)
        for rel, items in by_file.items():
            path = src / rel
            original = path.read_text(encoding="utf-8", errors="replace")
            text, line_maps[rel] = instrument_text(original, items, rel.endswith((".cc", ".cpp", ".cxx")))
            path.unlink()
            path.write_text(text, encoding="utf-8")
        harness = root / self.harness_source.name
        harness.write_text(self.harness_source.read_text(encoding="utf-8") + RUNTIME, encoding="utf-8")
        (root / "invariants.json").write_text(json.dumps([dataclasses.asdict(i) for i in invariants], indent=2))
        # -fno-inline keeps per-function coverage comparable; a project may need more
        # (for example -fcommon for pre-C99-tentative-definition sources).
        env = dict(os.environ, PYTHONPATH=str(self.harnesscreator_src),
                   HARNESSCREATOR_NATIVE_EXTRA_CFLAGS=("-fno-inline " + self.extra_cflags).strip(),
                   HARNESSCREATOR_NATIVE_SANITIZER=self.sanitizer)
        argv = [self.python, "-m", "harnesscreator.runtime.native_build", "--source-root", str(src),
                "--harness", str(harness), "--output", str(root / "out")]
        database = self._relocated_database(src, root)
        if database is not None:
            argv += ["--compile-database", str(database)]
        proc = subprocess.run(argv,
                              capture_output=True, text=True, env=env, timeout=1800)
        output = proc.stdout + proc.stderr
        (root / "build.log").write_text(output)
        binary = root / "out" / "hc-native-fuzzer"
        # Keyed by the absolute path the compiler and the sanitizers print.
        absolute_maps = {str(src / rel): mapping for rel, mapping in line_maps.items()}
        (root / "line-map.json").write_text(
            json.dumps({path: {str(k): v for k, v in mapping.items()}
                        for path, mapping in absolute_maps.items()}, indent=2), encoding="utf-8")
        if proc.returncode == 0 and binary.is_file():
            return BuildResult(True, binary, "", [], absolute_maps)
        failing = set()
        for rel, mapping in line_maps.items():
            name = re.escape(str((src / rel)))
            for match in re.finditer(rf"{name}:(\d+):\d+: error", output):
                line = int(match.group(1))
                if line in mapping:
                    failing.add(mapping[line])
        return BuildResult(False, None, output[-6000:], sorted(failing), absolute_maps)
