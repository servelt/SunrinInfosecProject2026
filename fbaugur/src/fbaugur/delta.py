"""Delta scan input: which functions a diff changes, and how far each is from the harness.

A port of FuzzingBrain V2's `analysis/diff_parser.py` (`parse_diff`, `get_all_changes`):
parse a unified diff, take the changed lines on the new side of each source file, map them to
the functions that contain them, and attach static reachability.  As in FBv2's current logic,
unreachable functions are kept and only marked: static analysis misses calls made through
function pointers, so the delta SP generator is told to analyse them anyway and the PoV decides.

Two differences from FBv2, both because there is no FBv2 Analysis Server here:
- Functions and their line spans come from the HarnessCreator run (Project), and reachability
  is a breadth-first search over its static call graph from the harness driver.
- A diff's paths are relative to its repository root, which need not be the analysed source
  root (LightFTP: `Source/Other/ftpserv.c` in the repository, `ftpserv.c` in the source root),
  so a diff file is matched to a program file by the longest common path suffix.

Changed lines are the added lines, plus, for a hunk that only deletes, the new-side line where
the deletion happened -- FBv2 counts the whole new range of a hunk, which marks unchanged context
lines as changed.
"""

from __future__ import annotations

import dataclasses
import re
from collections import deque
from pathlib import Path
from typing import Any, Callable

SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclasses.dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str]

    def changed_new_lines(self) -> list[int]:
        changed, number, deletion_only = [], self.new_start, True
        for line in self.lines:
            if line.startswith("+"):
                changed.append(number)
                number += 1
                deletion_only = False
            elif line.startswith("-"):
                continue
            elif line.startswith("\\"):
                continue                                   # "\ No newline at end of file"
            else:
                number += 1
        if deletion_only and any(line.startswith("-") for line in self.lines):
            changed.append(self.deletion_anchor())
        return changed

    def deletion_anchor(self) -> int:
        number = self.new_start
        for line in self.lines:
            if line.startswith("-"):
                return number
            if not line.startswith(("+", "\\")):
                number += 1
        return number

    def new_side(self) -> list[str]:
        """The hunk's lines as they read in the new file: context and added lines, in order."""
        return [line[1:] for line in self.lines if line[:1] in (" ", "+")]

    def text(self) -> str:
        return (f"@@ -{self.old_start},{self.old_count} +{self.new_start},{self.new_count} @@\n"
                + "\n".join(self.lines))


@dataclasses.dataclass
class FileDiff:
    old_path: str
    new_path: str
    hunks: list[Hunk] = dataclasses.field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False
    is_binary: bool = False

    @property
    def path(self) -> str:
        return self.old_path if self.is_deleted else self.new_path


@dataclasses.dataclass
class FunctionChange:
    function: str
    file: str                      # path relative to the analysed source root
    diff_file: str                 # path as the diff names it
    start_line: int
    end_line: int
    changed_lines: list[int]
    excerpt: str
    static_reachable: bool
    distance: int | None

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _strip_prefix(path: str) -> str:
    return path[2:] if path.startswith(("a/", "b/")) else path


def parse_diff(text: str) -> list[FileDiff]:
    """Unified diff (git or plain `diff -u`) -> per-file hunks.

    Hunk bodies are consumed by their line counts, so a removed line that itself starts with
    "-- " (shown as "--- ...") or an added "++ " line is never mistaken for a file header.
    """
    files: list[FileDiff] = []
    current: FileDiff | None = None
    hunk: Hunk | None = None
    old_left = new_left = 0
    pending_old: str | None = None
    for raw in text.splitlines():
        if hunk is not None and (old_left > 0 or new_left > 0):
            tag = raw[:1]
            if tag == "\\":
                hunk.lines.append(raw)
                continue
            if tag in (" ", ""):
                old_left -= 1
                new_left -= 1
            elif tag == "-":
                old_left -= 1
            elif tag == "+":
                new_left -= 1
            else:                       # malformed counts: stop the hunk here
                hunk, old_left, new_left = None, 0, 0
            if hunk is not None:
                hunk.lines.append(raw if raw else " ")
                continue
        if raw.startswith("\\") and hunk is not None:
            hunk.lines.append(raw)
            continue
        if raw.startswith("diff --git "):
            match = re.match(r"diff --git (\S+) (\S+)", raw)
            current = FileDiff(_strip_prefix(match.group(1)), _strip_prefix(match.group(2))) if match else None
            if current:
                files.append(current)
            hunk, pending_old = None, None
            continue
        if current is not None and (raw.startswith("Binary files") or raw.startswith("GIT binary patch")):
            current.is_binary = True
            continue
        if current is not None and raw.startswith("new file mode"):
            current.is_new = True
            continue
        if current is not None and raw.startswith("deleted file mode"):
            current.is_deleted = True
            continue
        if raw.startswith("--- "):
            pending_old = raw[4:].split("\t")[0].strip()
            continue
        if raw.startswith("+++ ") and pending_old is not None:
            new = raw[4:].split("\t")[0].strip()
            if current is None or current.hunks:              # plain `diff -u`, or the next file
                current = FileDiff(_strip_prefix(pending_old), _strip_prefix(new))
                files.append(current)
            if pending_old == "/dev/null":
                current.is_new = True
            if new == "/dev/null":
                current.is_deleted = True
            pending_old, hunk = None, None
            continue
        match = _HUNK.match(raw)
        if match and current is not None:
            hunk = Hunk(int(match.group(1)), int(match.group(2) or 1),
                        int(match.group(3)), int(match.group(4) or 1), [])
            old_left, new_left = hunk.old_count, hunk.new_count
            current.hunks.append(hunk)
    return files


def anchor_offset(hunk: Hunk, source: list[str]) -> int | None:
    """How far the hunk's new-side lines sit from where its header says, in the analysed file.

    A diff made against another revision than the one analysed carries line numbers of that
    revision.  The tinyproxy test diff (CVE-2023-49606's fix, reversed) was cut from the 2024
    tree: it names lines 782 and 807, which are 778 and 803 in the analysed 1.11.1.  The function
    mapping survived, but the crash frame `remove_connection_headers reqs.c:803` no longer stood
    on a changed line, and the crash would have been related to the diff as "stack" instead of
    "line".  The new-side text is searched for in the analysed file, as `patch` does: 0 when it is
    where the header says, the shift when it is elsewhere (nearest match wins), None when the
    text is not in the file at all.
    """
    want = [line.rstrip() for line in hunk.new_side()]
    if not want:
        return None
    have = [line.rstrip() for line in source]
    best: int | None = None
    for start in range(0, len(have) - len(want) + 1):
        if have[start:start + len(want)] == want:
            offset = (start + 1) - hunk.new_start
            if best is None or abs(offset) < abs(best):
                best = offset
                if offset == 0:
                    break
    return best


def match_source_file(diff_path: str, program_files: list[str]) -> str | None:
    """The program file with the longest common path suffix (at least the file name)."""
    parts = Path(diff_path).parts
    best, best_len = None, 0
    for candidate in program_files:
        cparts = Path(candidate).parts
        common = 0
        while common < min(len(parts), len(cparts)) and parts[-1 - common] == cparts[-1 - common]:
            common += 1
        if common > best_len:
            best, best_len = candidate, common
    return best


def delta_relation(frames: list[dict[str, Any]], changes: list[dict[str, Any]]) -> str:
    """How a crash stack relates to the diff: "line", "fault", "stack" or "none".

    line   a frame stands on a line the diff changed
    fault  the innermost program frame -- where the fault happens -- is in a changed function
    stack  a changed function is only further down the stack
    none   no frame is in a changed function

    Both simpler rules were wrong on LightFTP.  Changed *lines*: the injected CVE changes a
    declaration (`_text[512]`, line 383) and faults at the strcat on line 435, so the true finding
    never stands on a changed line.  Changed *functions anywhere on the stack*: the command
    dispatcher ftp_client_thread was changed by the real 7ea0a8f diff and is on nearly every
    stack, so two bugs older than that diff counted as in it.  The fault frame separates them.
    """
    lines = {(Path(c["file"]).name, line) for c in changes for line in c["changed_lines"]}
    names = {c["function"] for c in changes}
    for frame in frames:
        file, line = frame.get("file"), frame.get("line")
        if file and line and (Path(str(file)).name, int(line)) in lines:
            return "line"
    if frames and str(frames[0].get("function") or "") in names:
        return "fault"
    if any(str(f.get("function") or "") in names for f in frames[1:]):
        return "stack"
    return "none"


def call_distances(callees: dict[str, Any], roots: list[str]) -> dict[str, int]:
    """Shortest static call depth from any root (the harness driver and interpreters)."""
    distance: dict[str, int] = {}
    queue: deque[str] = deque()
    for root in roots:
        if root and root not in distance:
            distance[root] = 0
            queue.append(root)
    while queue:
        name = queue.popleft()
        for callee in callees.get(name, ()):
            if callee not in distance:
                distance[callee] = distance[name] + 1
                queue.append(callee)
    return distance


def changed_functions(diff_text: str, functions: dict[str, list[dict[str, Any]]],
                      callees: dict[str, Any], roots: list[str],
                      read_source: Callable[[str], list[str] | None] | None = None,
                      ) -> tuple[list[FunctionChange], dict[str, Any]]:
    """All functions the diff changes (reachable or not), reachable first then by distance.

    `functions` is index.json's map: name -> [{file, start, end, ...}].  With `read_source`
    (analysed-source path -> its lines), each hunk is re-anchored to where its text actually is
    in the analysed file, so changed line numbers are the analysed program's own.
    """
    by_file: dict[str, list[tuple[str, int, int]]] = {}
    for name, items in functions.items():
        for item in items:
            by_file.setdefault(item["file"], []).append((name, int(item["start"]), int(item["end"])))
    distances = call_distances(callees, roots)
    report: dict[str, Any] = {"files": [], "unmatched_files": [], "skipped_files": []}
    changes: list[FunctionChange] = []
    for file_diff in parse_diff(diff_text):
        path = file_diff.path
        if file_diff.is_binary or Path(path).suffix.lower() not in SOURCE_SUFFIXES:
            report["skipped_files"].append(path)
            continue
        if file_diff.is_deleted or not file_diff.hunks:
            report["skipped_files"].append(path)
            continue
        source = match_source_file(path, list(by_file))
        if source is None:
            report["unmatched_files"].append(path)
            continue
        lines = read_source(source) if read_source else None
        offsets: list[int | None] = []
        changed_set: set[int] = set()
        for hunk in file_diff.hunks:
            offset = anchor_offset(hunk, lines) if lines is not None else 0
            offsets.append(offset)
            changed_set.update(line + (offset or 0) for line in hunk.changed_new_lines())
        changed = sorted(changed_set)
        entry = {"diff_file": path, "source_file": source, "changed_lines": len(changed)}
        if lines is not None:
            entry["line_offsets"] = offsets
            entry["unmatched_hunks"] = sum(1 for o in offsets if o is None)
        report["files"].append(entry)
        for name, start, end in by_file[source]:
            inside = [line for line in changed if start <= line <= end]
            if not inside:
                continue
            excerpt = "\n".join(h.text() for h in file_diff.hunks
                                if not (h.new_start + h.new_count < start or h.new_start > end))
            changes.append(FunctionChange(
                function=name, file=source, diff_file=path, start_line=start, end_line=end,
                changed_lines=inside, excerpt=excerpt, static_reachable=name in distances,
                distance=distances.get(name)))
    changes.sort(key=lambda c: (not c.static_reachable, c.distance if c.distance is not None else 999, c.function))
    report["changed_functions"] = len(changes)
    report["static_reachable"] = sum(1 for c in changes if c.static_reachable)
    return changes, report
