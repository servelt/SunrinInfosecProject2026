"""What a scan is doing right now, read from what the pipeline already writes.

Nothing here talks to the running pipeline.  Stage 1 (HarnessCreator) is read from the pipeline
log and from HarnessCreator's own structured event file (`debug/agent-events.jsonl`) and result
files; stage 2 from each context's `state.db`, where every agent run is inserted as "running"
when it starts.  The web page polls this.

Agent ids:  HARNESS CREATE      eg ev cg ig hg hv
            VULNERABILITY RES.  tm dr spg spv pov inv fz ct val adv
Statuses:   done | run | wait | fail
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any
from . import labels

HC_AGENTS = ("eg", "ev", "cg", "ig", "hg", "hv")
VR_AGENTS = ("tm", "dr", "spg", "spv", "pov", "inv", "fz", "ct", "val", "adv")

# Stage-1 log milestones before the first LLM agent, and how far along the bar each one is.
# The share before 0.5 belongs to target preparation (clone, configure, builds).
PREP_MARKS = [
    ("[stage 1] harness generation", 0.55, "정적 분석 준비"),
    ("static analysis preflight started", 0.62, "호출 그래프"),
    ("Fuzz Introspector cache hit", 0.66, "호출 그래프"),
    ("static analysis preflight completed", 0.78, "간접 호출 점검"),
    ("indirect-call preflight completed", 0.83, "외부 근거 확인"),
    ("upstream evidence preflight completed", 0.87, "함수 색인"),
    ("static analysis completed", 0.95, "Entry Generator 준비"),
]
TS = re.compile(r"^\[(\d\d:\d\d:\d\d)\]\s*")


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def read_log(path: Path | None) -> list[str]:
    if not path or not Path(path).is_file():
        return []
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def strip_ts(line: str) -> str:
    line = TS.sub("", line)
    return TS.sub("", line.strip())


def pipeline_dir_of(lines: list[str]) -> Path | None:
    for line in lines[:20]:
        m = re.search(r"pipeline directory: (\S+)", line)
        if m:
            return Path(m.group(1))
    return None


def hc_run_of(lines: list[str], pipeline_dir: Path | None) -> Path | None:
    """The HarnessCreator run directory.

    Not from HarnessCreator's own "started; artifacts=<path>" line: the pipeline relays those
    lines cut at 220 characters, and a long path came through as ".../runs/202", so the page
    showed Entry Generator as not started after it had finished.  The pipeline's own lines are
    not cut, and the run directory is always under <pipeline>/harness.
    """
    for line in lines:
        m = re.search(r"\[stage 1\] skipped; reusing (\S+)", line)
        if m and Path(m.group(1)).is_dir():
            return Path(m.group(1))
    if pipeline_dir and (pipeline_dir / "harness").is_dir():
        runs = sorted(p for p in (pipeline_dir / "harness").iterdir() if (p / "project.json").is_file())
        if runs:
            return runs[-1]
    for line in lines:
        m = re.search(r"started; artifacts=(\S+)", line)
        if m and (Path(m.group(1)) / "project.json").is_file():
            return Path(m.group(1))
    return None


def scan_dirs_of(lines: list[str], pipeline_dir: Path | None) -> list[Path]:
    if not pipeline_dir or not pipeline_dir.is_dir():
        return []
    order = []
    for line in lines:
        m = re.search(r"\[stage 2\] scan \d+/\d+: (ctx-[0-9a-f]+)", line)
        if m:
            order.append(m.group(1))
    found = [p for p in pipeline_dir.glob("scan*") if (p / "state.db").is_file()]
    rank = {f"scan-{ctx}": i for i, ctx in enumerate(order)}
    return sorted(found, key=lambda p: (rank.get(p.name, 99), p.stat().st_mtime))


def _db(path: Path) -> sqlite3.Connection | None:
    db = path / "state.db"
    if not db.is_file():
        return None
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _q(conn, sql: str, *args) -> list[dict[str, Any]]:
    try:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    except sqlite3.Error:
        return []


def _json(value) -> Any:
    if not value:
        return {}
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return {}


def row(a: str, b: str = "", c: str = "", tag: str = "") -> dict[str, str]:
    return {"a": str(a), "b": str(b), "c": str(c), "t": tag}


# ----------------------------------------------------------------------------------- prep bar
def prep_progress(lines: list[str], session: dict[str, Any]) -> tuple[float, str, bool]:
    """(fraction, label, finished) for the bar shown before the first LLM agent starts."""
    if any("entry generation started" in l or "[stage 1] skipped" in l or "[stage 2]" in l for l in lines):
        return 1.0, "Entry Generator 시작", True
    value, label = session.get("prep_progress", 0.0), session.get("prep_label", "준비 중")
    for marker, fraction, text in PREP_MARKS:
        if any(marker in l for l in lines):
            value, label = max(value, fraction), text
    # Long silent steps (Fuzz Introspector on a large tree took 11+ minutes on redis) say what runs.
    started = next((l for l in lines if "Fuzz Introspector automatic analysis started" in l), "")
    if started and not any("Fuzz Introspector automatic analysis completed" in l or "Fuzz Introspector cache hit" in l
                           or "automatic Fuzz Introspector analysis failed" in l for l in lines):
        files = re.search(r"files=(\d+)", started)
        waited = next((m for m in (re.search(r"no output for (\d+)s", l) for l in reversed(lines[-5:])) if m), None)
        label = "정적 분석: Fuzz Introspector" + (f" · 파일 {files.group(1)}개" if files else "") + \
                (f" · {int(waited.group(1)) // 60}분 경과" if waited else "")
    return value, label, False


# ----------------------------------------------------------------------------------- stage 1
def _phase_state(lines: list[str], start: str, end: str) -> str:
    started = any(start in l for l in lines)
    ended = any(end in l for l in lines)
    return "done" if ended else "run" if started else "wait"


def _workflow_step(lines: list[str], number: str) -> str:
    """'2' (normal inputs) or '3' (harness): run while the latest such step has no 'finished'."""
    state = "wait"
    for line in lines:
        m = re.search(r"\[WORKFLOW\] " + number + r"\.(\d+) .*: (started|finished)", line)
        if m:
            state = "run" if m.group(2) == "started" else "done"
    return state


def stage1(lines: list[str], hc: Path | None, alive: bool) -> dict[str, Any]:
    finished = any(re.search(r"\[stage 1\] (finished|skipped)", l) or "[stage 2]" in l for l in lines)
    events = _rows(hc / "debug" / "agent-events.jsonl") if hc else []
    fn_names: dict[str, str] = {}
    if hc and (hc / "analysis" / "functions.jsonl").is_file():
        for r in _rows(hc / "analysis" / "functions.jsonl"):
            fn_names[r["function_id"]] = r.get("name", r["function_id"])
    st = {
        "eg": "done" if any(e.get("agent") == "entry_generator" and e.get("event") == "completed" for e in events)
        or any("entry generation completed" in l for l in lines)
        else "run" if any(e.get("agent") == "entry_generator" for e in events) or any("entry generation started" in l for l in lines)
        else "wait",
        "ev": _phase_state(lines, "entry generation started", "entry verification completed: "),
        "cg": _phase_state(lines, "[WORKFLOW] 1 input contexts", "locate interpreters): finished"),
        "ig": _workflow_step(lines, "2"),
        "hg": _workflow_step(lines, "3"),
        "hv": _workflow_step(lines, "3"),
    }
    if st["ev"] == "run" and not any(e.get("agent") == "entry_verifier" for e in events):
        st["ev"] = "wait" if st["eg"] != "done" else "run"
    # Harness step: generating until the newest attempt has a built binary, then verifying.
    if st["hg"] == "run" and hc:
        attempts = sorted(hc.glob("context-harnesses/*/attempt-*"), key=lambda p: p.stat().st_mtime)
        built = attempts and any(attempts[-1].glob("build/hc-native-fuzzer"))
        st["hg"], st["hv"] = ("done", "run") if built else ("run", "wait")
    elif st["hg"] == "done" and any("context-harness:" in l and ": BUILT" in l for l in lines):
        st["hv"] = "done"
    if finished:
        st = {k: ("done" if v != "fail" else v) for k, v in st.items()}
    if not alive:
        st = {k: ("wait" if v == "run" else v) for k, v in st.items()} if not finished else st

    details: dict[str, dict[str, Any]] = {k: {"rows": []} for k in HC_AGENTS}
    if not hc:
        return {"status": st, "details": details}
    # Entries and contexts are shown as code + a short Korean label (labels.py), not file:line.
    from . import labels
    fn_files: dict[str, str] = {}
    for r in _rows(hc / "analysis" / "functions.jsonl"):
        fn_files[r["function_id"]] = r.get("file", "")
    try:
        source_root = Path(json.loads((hc / "project.json").read_text(encoding="utf-8"))["source_root"])
    except (OSError, ValueError, KeyError):
        source_root = None
    file_cache: dict[str, list[str]] = {}

    def code_at(function_id: str, line: Any) -> str:
        rel = fn_files.get(function_id or "", "")
        if not source_root or not rel or not line:
            return ""
        if rel not in file_cache:
            try:
                file_cache[rel] = (source_root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                file_cache[rel] = []
        text = file_cache[rel]
        return text[int(line) - 1].strip()[:140] if 0 < int(line) <= len(text) else ""

    cands = _rows(hc / "entries" / "candidates.jsonl")
    if not cands:
        # HarnessCreator writes entries/candidates.jsonl only when the Entry stage ends; until then
        # the deduplicated candidates are in the Verifier's candidate_started events.
        seen: set[str] = set()
        for e in events:
            c = e.get("candidate") if e.get("event") == "candidate_started" else None
            if isinstance(c, dict) and c.get("candidate_id") and c["candidate_id"] not in seen:
                seen.add(c["candidate_id"])
                cands.append(c)
    verified = _rows(hc / "entries" / "verified.jsonl")
    rejected = _rows(hc / "entries" / "rejected.jsonl")
    unresolved = _rows(hc / "entries" / "unresolved.jsonl")
    contexts = _rows(hc / "contexts" / "contexts.jsonl")
    to_label = {}
    for c in cands:
        to_label[c["candidate_id"]] = {"id": c["candidate_id"], "line": code_at(c.get("function_id"), c.get("line")),
                                       "function": fn_names.get(c.get("function_id"), ""), "api": c.get("source_api", ""),
                                       "channel": c.get("boundary_subject", "")}
    for r in verified + rejected + unresolved:
        cid = r.get("candidate_id") or r.get("entry_id")
        to_label.setdefault(cid, {"id": cid, "line": code_at(r.get("entry_function_id"), r.get("entry_line")),
                                  "function": fn_names.get(r.get("entry_function_id"), ""), "api": r.get("source_api", ""),
                                  "channel": (r.get("channel_kind") or "")[:200]})
    ctx_items = [{"id": c["context_id"], "driver": c.get("driver_function"), "deliveries": c.get("deliveries"),
                  "resource": c.get("resource_kind"),
                  "entries": [{"code": code_at(e.get("entry_function_id"), e.get("entry_line")),
                               "function": e.get("entry_function"), "channel": (e.get("channel_kind") or "")[:160]}
                              for e in c.get("entries", [])],
                  "interpreters": [str(f.get("name") if isinstance(f, dict) else f) for f in (c.get("interpreter_functions") or [])][:8],
                  "notes": str(c.get("notes") or "")[:300]} for c in contexts]
    harness_items = []
    for status_file in sorted(hc.glob("context-harnesses/*/status.json")):
        data = _json(status_file.read_text(encoding="utf-8", errors="replace"))
        attempts = data.get("attempts") or []
        if not attempts:
            continue
        source = status_file.parent / f"attempt-{len(attempts)}" / "fuzz_target.c"
        try:
            code = source.read_text(encoding="utf-8", errors="replace")[:7000]
        except OSError:
            continue
        name = status_file.parent.name
        ctx = name.rsplit("-", 1)[0]
        harness_items.append({"key": labels.harness_key(name, len(attempts)), "id": name,
                              "context": labels.load(hc).get(labels.ctx_key(ctx), {}) or ctx,
                              "shape": attempts[-1].get("shape", ""), "source": code})
    labels.ensure(hc, [v for v in to_label.values() if v["line"] or v["function"]], ctx_items, harness_items)
    lab = labels.load(hc)

    def entry_row(cid: str, tag_text: str = "", tag: str = "") -> dict[str, str]:
        item, label = to_label.get(cid, {}), lab.get(cid, {})
        return row(label.get("code") or item.get("line") or item.get("function", "?"),
                   label.get("summary") or "설명 만드는 중…", tag_text, tag)

    # Entry Generator
    batches = [e for e in events if e.get("agent") == "entry_generator" and e.get("event") == "batch_decision"]
    details["eg"] = {"summary": f"입력 지점 후보 {len(cands)}개" if cands else "", "layout": "list",
                     "now": f"LLM 배치 {len(batches)}개 처리 · 함수를 훑는 중",
                     "rows": [entry_row(c["candidate_id"]) for c in cands]}
    # Entry Verifier
    verdicts = [e for e in events if e.get("event") == "final_verdict"]
    current = [e for e in events if e.get("event") == "candidate_started"
               and not any(v.get("candidate_id") and v.get("candidate_id") in json.dumps(e) for v in verdicts)]
    ev_rows = [entry_row(r.get("candidate_id") or r.get("entry_id"), "검증", "ok") for r in verified]
    ev_rows += [entry_row(r.get("candidate_id") or r.get("entry_id"), "기각", "no") for r in rejected]
    ev_rows += [entry_row(r.get("candidate_id") or r.get("entry_id"), "미해결", "warn") for r in unresolved]
    if not ev_rows:
        ev_rows = [entry_row(e.get("candidate_id", ""), (e.get("final_status") or "").lower(),
                             "ok" if e.get("final_status") == "VERIFIED" else "no") for e in verdicts]
    details["ev"] = {"summary": f"검증 {len(verified)} · 기각 {len(rejected)} · 미해결 {len(unresolved)}" if (verified or rejected) else
                     f"판정 {len(verdicts)}개", "layout": "list",
                     "now": ("확인 중 · " + current[-1].get("message", "").replace("verify ", "")) if current else f"판정 {len(verdicts)}개 완료",
                     "rows": ev_rows}
    # Context Grouping: adopted (a harness is built for it), dropped, or unresolved (chosen, no harness)
    built = set(re.findall(r"(ctx-[0-9a-f]+)/\w+", " ".join(l for l in lines if "[WORKFLOW] selected:" in l)))
    built |= set(re.findall(r"'(ctx-[0-9a-f]+)'", " ".join(l for l in lines if "[stage 1] built harnesses:" in l)))
    failed = set()
    for status_file in hc.glob("context-harnesses/*/status.json"):
        data = _json(status_file.read_text(encoding="utf-8", errors="replace"))
        if data.get("attempts") and not any(a.get("built") for a in data["attempts"]):
            failed.add(status_file.parent.name.rsplit("-", 1)[0])
    cg_rows = []
    for c in contexts:
        cid, label = c["context_id"], lab.get(labels.ctx_key(c["context_id"]), {})
        state, tag = ("미해결", "warn") if cid in failed else ("채택", "ok") if cid in built else ("드롭", "no")
        cg_rows.append(row(label.get("name") or c.get("driver_function") or cid,
                           label.get("description") or "설명 만드는 중…", state, tag))
    cg_rows.sort(key=lambda r: {"채택": 0, "미해결": 1, "드롭": 2}[r["c"]])
    details["cg"] = {"summary": f"문맥 {len(contexts)}개 · 채택 {sum(1 for r in cg_rows if r['c'] == '채택')}" if contexts else "",
                     "layout": "groups", "now": "Entry를 입력 흐름별로 묶는 중", "rows": cg_rows}
    # Input Generator
    seeds = _rows(hc / "seeds" / "results.jsonl")
    purpose = {c["seed_id"]: c for c in _rows(hc / "seeds" / "candidates.jsonl")}
    new = [s for s in seeds if s.get("status") == "ACCEPTED_NEW"]
    last_seed = next((l for l in reversed(lines) if "[SEED]" in l), "")
    m = re.search(r"(seed-[0-9a-f]+) (\w+): (.*)$", last_seed)
    now_bytes = ""
    if m and m.group(1) in purpose:
        msgs = purpose[m.group(1)].get("messages_hex") or []
        try:
            now_bytes = bytes.fromhex(msgs[0])[:600].decode("latin-1").replace("\r\n", "\u21b5\n") if msgs else ""
        except ValueError:
            now_bytes = ""
    # Input Generator: one section per adopted context, in the order the workflow runs them
    steps: dict[str, dict[str, Any]] = {}
    for l in lines:
        w = re.search(r"\[WORKFLOW\] 2\.(\d+) normal inputs for (ctx-[0-9a-f]+).*?: (started|finished)", l)
        if w:
            steps.setdefault(w.group(2), {"n": int(w.group(1))})["state"] = w.group(3)
    order = sorted(steps, key=lambda c: steps[c]["n"]) + sorted(c for c in built if c not in steps)
    by_ctx: dict[str, list[dict[str, Any]]] = {}
    for s in seeds:
        by_ctx.setdefault(s.get("context_id", ""), []).append(s)

    def first_line(seed_id: str) -> str:
        msgs = purpose.get(seed_id, {}).get("messages_hex") or []
        try:
            text = bytes.fromhex(msgs[0]).decode("latin-1") if msgs else ""
        except ValueError:
            return seed_id[:13]
        line = text.split("\n", 1)[0].strip()
        return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in line)[:90] or seed_id[:13]

    def seed_row(s: dict[str, Any]) -> dict[str, str]:
        status = s.get("status", "")
        if status == "ACCEPTED_NEW":
            text, tag_text, tag = (f"새 함수 {len(s.get('new_target_function_ids') or [])}개 · 새 줄 {s.get('new_target_lines', 0)}",
                                   "채택", "ok")
        elif status == "ACCEPTED_REDUNDANT":
            text, tag_text, tag = "이미 다른 시드가 지난 코드만 지남", "중복", "no"
        elif status.startswith("REJECTED"):
            text, tag_text, tag = "이 문맥의 대상 함수에 닿지 못함", "거절", "no"
        else:
            text, tag_text, tag = (s.get("reason") or status)[:80], "실패", "warn"
        return row(first_line(s.get("seed_id", "")), text, tag_text, tag)

    sections = []
    current_ctx = ""
    for cid in order:
        state = steps.get(cid, {}).get("state")
        rows_ = by_ctx.get(cid, [])
        rows_ = sorted(rows_, key=lambda s: s.get("status") != "ACCEPTED_NEW")
        accepted = sum(1 for s in rows_ if s.get("status") == "ACCEPTED_NEW")
        if state == "started":
            current_ctx = cid
        label = lab.get(labels.ctx_key(cid), {})
        sections.append({"title": label.get("name") or cid, "desc": label.get("description") or "",
                         "state": {"finished": "완료", "started": "진행 중"}.get(state, "대기"),
                         "tag": {"finished": "ok", "started": "warn"}.get(state, "no"),
                         "count": f"시드 {len(rows_)}개 · 채택 {accepted}" if rows_ else "",
                         "rows": [seed_row(s) for s in rows_]})
    now_name = (lab.get(labels.ctx_key(current_ctx), {}).get("name") or current_ctx) if current_ctx else ""
    details["ig"] = {"summary": f"문맥 {len(order)}개 · 시드 {len(seeds)}개 · 채택 {len(new)}개" if seeds else "",
                     "now": (f"'{now_name}' 문맥의 시드를 만드는 중" + (f" · {m.group(1)} → {m.group(2)}" if m else "")) if now_name
                            else (strip_ts(last_seed)[:120] or "시드 생성 중"),
                     "bytes": now_bytes, "layout": "sections", "sections": sections, "rows": []}
    # Harness Generator / Verifier
    hrows, vrows = [], []
    for status_file in sorted(hc.glob("context-harnesses/*/status.json")):
        data = _json(status_file.read_text(encoding="utf-8", errors="replace"))
        attempts = data.get("attempts") or []
        last = attempts[-1] if attempts else {}
        name = status_file.parent.name
        hl = lab.get(labels.harness_key(name, len(attempts)), {})
        title = hl.get("name") or (lab.get(labels.ctx_key(name.rsplit("-", 1)[0]), {}).get("name", "") + " 하네스").strip() or name
        hrows.append(row(title, hl.get("description") or "설명 만드는 중…",
                         f"시도 {len(attempts)}회 · {last.get('executions_per_second', '—')} exec/s", "ok" if last.get("built") else "warn"))
        verdict = str(data.get("status") or data.get("verdict") or last.get("status") or "")
        # Stage 2 fuzzes every context whose harness binary was built (pipeline.built_harnesses),
        # whatever the verifier's status, so "built" is what adoption means here.
        built_any = any(a.get("built") for a in attempts)
        if built_any:
            vrows.append(row(title, "", "채택", "ok"))
        elif attempts:
            why = {"STATIC_FAILED": "하네스 코드가 정적 검사(금지된 호출·형식)를 통과하지 못함",
                   "REVIEW_FAILED": "독립 리뷰에서 하네스가 문맥의 입력을 제대로 넣지 않는다고 판정",
                   "BUILD_FAILED": "하네스가 컴파일·링크되지 않음",
                   "BUILT_REPLAY_FAILED": "빌드는 됐지만 시드를 넣으면 하네스가 먼저 죽음",
                   "RUN_FAILED": "하네스 실행 자체가 실패"}.get(verdict, "")
            detail = (last.get("reason") or "").strip().splitlines()[0][:80] if last.get("reason") else ""
            vrows.append(row(title, f"시도 {len(attempts)}회 모두 실패 · " + (why or detail or verdict), "드롭", "no"))
    running_ctx = next((re.search(r"(ctx-[0-9a-f]+)", l).group(1) for l in reversed(lines) if "[WORKFLOW] 3." in l and "started" in l), "")
    details["hg"] = {"summary": f"하네스 {len(hrows)}개" if hrows else "", "layout": "groups", "now": f"'{lab.get(labels.ctx_key(running_ctx), {}).get('name') or running_ctx}' 문맥의 하네스를 만드는 중", "rows": hrows}
    details["hv"] = {"summary": f"채택 {sum(1 for r in vrows if r['c'] == '채택')} · 드롭 {sum(1 for r in vrows if r['c'] == '드롭')}" if vrows else "", "layout": "groups", "now": f"'{lab.get(labels.ctx_key(running_ctx), {}).get('name') or running_ctx}' 하네스를 원본과 비교 중", "rows": vrows}
    return {"status": st, "details": details}


# ----------------------------------------------------------------------------------- stage 2
def stage2(lines: list[str], scans: list[Path], alive: bool) -> dict[str, Any]:
    st = {k: "wait" for k in VR_AGENTS}
    details: dict[str, dict[str, Any]] = {k: {"rows": []} for k in VR_AGENTS}
    if not scans:
        return {"status": st, "details": details, "context": ""}
    scan = scans[-1]
    total = len({m.group(2) for l in lines for m in [re.search(r"\[stage 2\] scan (\d+)/(\d+)", l)] if m}) and \
        max(int(m.group(2)) for l in lines for m in [re.search(r"\[stage 2\] scan (\d+)/(\d+)", l)] if m)
    context = f"문맥 {len(scans)}/{total or len(scans)} · {scan.name.replace('scan-', '')}"
    conn = _db(scan)
    if conn is None:
        return {"status": st, "details": details, "context": context}
    try:
        finished = (scan / "summary.json").is_file()
        live = alive and not finished
        running = _q(conn, "SELECT role, subject FROM agent_runs WHERE status='running'") if live else []
        roles = {r["role"]: r["subject"] for r in running}
        drained = any("analysis lanes drained" in l for l in lines[-400:]) and live
        all_sps = _q(conn, "SELECT sp_id, worker_id, function_name, vuln_type, description, status, verification_notes, merged_into FROM sps ORDER BY created_at")
        sps = [s for s in all_sps if not s.get("merged_into")]
        merged_count = len(all_sps) - len(sps)
        invs = _q(conn, "SELECT phi_num, file, line, expression, security_property, rationale, status, last_error FROM invariants ORDER BY phi_num")
        crashes = _q(conn, "SELECT crash_id, status, crash_type, signature, details, report_path FROM crashes")
        pool_open = _q(conn, "SELECT COUNT(*) AS n FROM pool WHERE status IN ('pending','analysing')")
        building = _q(conn, "SELECT version FROM builds WHERE status='building'")
        builds = _q(conn, "SELECT version, status FROM builds ORDER BY version")
        directions = _q(conn, "SELECT direction_id, name, risk_level, risk_reason FROM directions")
        tm = _q(conn, "SELECT body FROM threat_model")
        stats = _q(conn, "SELECT key, value FROM meta WHERE key LIKE 'fuzz_stats_%'")

        def state(running_now: bool, any_done: bool) -> str:
            return "run" if running_now else "done" if any_done else "wait"

        open_pool = (pool_open[0]["n"] if pool_open else 0) > 0
        st["tm"] = state("threat_model" in roles, bool(tm))
        st["dr"] = state("direction" in roles, bool(directions))
        st["spg"] = state(bool({"sp_generator", "delta_sp_generator"} & roles.keys()) or (live and open_pool and not drained), bool(sps))
        verifying = any(s["status"] in ("pending_verify", "verifying") for s in sps)
        st["spv"] = state("sp_verifier" in roles or (live and verifying), any(s["status"] not in ("pending_verify", "verifying") for s in sps))
        pov_open = any(s["status"] in ("verified", "pending_pov", "pov_running", "generating_pov") for s in sps)
        st["pov"] = state("pov" in roles or (live and pov_open), any(s["status"].startswith("pov_") for s in sps))
        st["inv"] = state(bool({"invariant_recorder", "refine", "triage"} & roles.keys()) or bool(building) or (live and bool(invs)), bool(invs))
        st["fz"] = state(live and any("global fuzzer on" in l for l in lines[-2000:]), finished)
        pending = [c for c in crashes if c["status"] in ("pending", "confirming")]
        st["ct"] = state(bool(pending), bool(crashes))
        validated = [c for c in crashes if _json(c["details"]).get("validation")]
        st["val"] = state("vuln_validator" in roles, bool(validated))
        st["adv"] = state("report" in roles, any(c["report_path"] for c in crashes))

        def subject(role: str) -> str:
            return roles.get(role, "") or ""

        details["tm"] = {"summary": "공격 표면 정리 완료" if tm else "", "now": "공격 표면을 정리하는 중", "rows": []}
        labels.ensure_directions(scan, [{"id": d["direction_id"], "name": d["name"], "risk_reason": (d["risk_reason"] or "")[:600]}
                                        for d in directions])
        dlab = labels.load(scan)
        rank = {"high": 0, "medium": 1, "low": 2}
        risk_tag = {"high": "hi", "medium": "warn", "low": "ok"}
        dir_rows = []
        for d in sorted(directions, key=lambda d: (rank.get((d["risk_level"] or "").lower(), 3), d["name"])):
            level = (d["risk_level"] or "").lower()
            got = dlab.get(labels.direction_key(d["direction_id"]), {})
            dir_rows.append(row(got.get("name") or d["name"][:60], got.get("description") or "설명 만드는 중…",
                                level.upper(), risk_tag.get(level, "")))
        details["dr"] = {"summary": f"위험 영역 {len(directions)}개", "now": "코드를 위험 영역으로 나누는 중",
                         "layout": "groups", "rows": dir_rows}
        by_worker = {}
        for s in sps:
            by_worker[s["worker_id"]] = by_worker.get(s["worker_id"], 0) + 1
        short = lambda w: "MSan" if w.endswith("msan") else "ASan"
        labels.ensure_scan_items(scan, "sp", [
            {"id": s["sp_id"], "function": s["function_name"], "vuln_type": s["vuln_type"],
             "description": (s["description"] or "")[:700], "status": s["status"],
             "verification_notes": (s["verification_notes"] or "")[:500] if s["status"] == "rejected" else ""} for s in sps])
        labels.ensure_scan_items(scan, "inv", [
            {"id": i["phi_num"], "expression": i["expression"], "security_property": (i["security_property"] or "")[:300],
             "rationale": (i["rationale"] or "")[:300], "status": i["status"],
             "last_error": (i["last_error"] or "")[:300]} for i in invs])
        slab = labels.load(scan)

        def sp_label(s: dict[str, Any]) -> dict[str, str]:
            return slab.get(labels.item_key("sp", s["sp_id"]), {})

        details["spg"] = {"summary": f"의심 지점 {len(sps)} · " + " · ".join(f"{short(w)} {n}" for w, n in by_worker.items())
                                     + (f" · 중복 합침 {merged_count}" if merged_count else ""),
                          "now": f"분석 중 · {subject('sp_generator') or subject('delta_sp_generator')}", "layout": "groups",
                          "rows": [row(sp_label(s).get("name") or s["vuln_type"][:50],
                                       sp_label(s).get("description") or "설명 만드는 중…", short(s["worker_id"]))
                                   for s in sps[::-1]]}
        rejected = [s for s in sps if s["status"] == "rejected"]
        passed = [s for s in sps if s["status"].startswith("pov_") or s["status"] in ("verified", "pending_pov")]
        waiting = [s for s in sps if s["status"] in ("pending_verify", "verifying")]
        details["spv"] = {"summary": f"채택 {len(passed)} · 드롭 {len(rejected)}" + (f" · 확인 대기 {len(waiting)}" if waiting else ""),
                          "now": f"확인 중 · {subject('sp_verifier')}", "layout": "groups",
                          "rows": [row(sp_label(s).get("name") or s["vuln_type"][:50], "", "채택", "ok") for s in passed[::-1]]
                                  + [row(sp_label(s).get("name") or s["vuln_type"][:50],
                                         sp_label(s).get("reason") or "이유 정리 중…", "드롭", "no") for s in rejected[::-1]]}
        povs = [s for s in sps if s["status"].startswith("pov_")]
        details["pov"] = {"summary": f"크래시 입력 {sum(1 for s in povs if s['status'] == 'pov_generated')} · 실패 {sum(1 for s in povs if s['status'] == 'pov_failed')}",
                          "now": f"시험 중 · {subject('pov')}",
                          "rows": [row(s["function_name"], s["vuln_type"][:60], "성공" if s["status"] == "pov_generated" else "실패",
                                       "ok" if s["status"] == "pov_generated" else "no") for s in povs[-6:][::-1]]}
        active = [i for i in invs if i["status"] in ("built", "pending_build", "lead")]
        withdrawn = [i for i in invs if i["status"].startswith("withdrawn")]
        blocked = [i for i in invs if i["status"] == "build_blocked"]
        latest = builds[-1]["version"] if builds else None

        def inv_row(i: dict[str, Any], state: str, tag: str) -> dict[str, str]:
            got = slab.get(labels.item_key("inv", str(i["phi_num"])), {})
            text = got.get("description") or "설명 만드는 중…"
            if state != "활성":
                text = got.get("reason") or text
            return row(got.get("name") or i["expression"][:60], text, state, tag)

        details["inv"] = {"summary": f"활성 {len(active)} · 빌드 막힘 {len(blocked)} · 철회 {len(withdrawn)} · 빌드 {len(builds)}회",
                          "now": (f"빌드 v{building[-1]['version']} 만드는 중" if building else f"빌드 v{latest} 위에서 퍼징 중" if latest else "조건을 기록하는 중"),
                          "layout": "groups",
                          "rows": [inv_row(i, "활성", "ok") for i in active[::-1]]
                                  + [inv_row(i, "빌드 막힘", "warn") for i in blocked[::-1]]
                                  + [inv_row(i, "철회", "no") for i in withdrawn[::-1]]}
        fz_rows = []
        for s in stats:
            data = _json(s["value"])
            fz_rows.append(row(s["key"].replace("fuzz_stats_", ""), f"코퍼스 {data.get('corpus', '?')} · 실행 {data.get('executed_units', '?')}",
                               f"커버리지 {data.get('coverage', '?')}"))
        details["fz"] = {"summary": "퍼징 종료" if finished else "", "now": "Worker 퍼저 실행 중", "rows": fz_rows}
        counts: dict[str, int] = {}
        for c in crashes:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        finals = [c for c in crashes if c["status"] in ("confirmed", "validated", "reported", "not_vulnerability", "needs_review")]
        details["ct"] = {"summary": f"{len(crashes)}건 → 확정 {len(finals)}",
                         "now": f"새 크래시 {len(pending)}건 재생 중",
                         "rows": [row(k, "", str(v)) for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]}
        val_rows = []
        for c in validated:
            v = _json(c["details"])["validation"]
            tag = "hi" if v.get("verdict") == "VULNERABILITY" and (v.get("cvss_score") or 0) >= 7 else \
                "mid" if v.get("verdict") == "VULNERABILITY" else "warn" if v.get("verdict") == "NEEDS_REVIEW" else "no"
            val_rows.append(row(c["crash_type"] or c["crash_id"], (c["signature"] or "")[:60],
                                f"{v.get('verdict', '').replace('_', ' ').lower()} {v.get('cvss_score', '')}", tag))
        details["val"] = {"summary": f"판정 {len(validated)}건", "now": f"판정 중 · {subject('vuln_validator')}", "rows": val_rows}
        details["adv"] = {"summary": f"보고서 {sum(1 for c in crashes if c['report_path'])}건", "now": f"작성 중 · {subject('report')}",
                          "rows": [row(Path(c["report_path"]).name, c["crash_type"] or "", "") for c in crashes if c["report_path"]]}
    finally:
        conn.close()
    return {"status": st, "details": details, "context": context}


def outputs(scans: list[Path]) -> list[dict[str, Any]]:
    out = []
    for scan in scans:
        conn = _db(scan)
        if conn is None:
            continue
        try:
            for c in _q(conn, "SELECT crash_id, status, crash_type, signature, details, report_path FROM crashes "
                              "WHERE status IN ('reported','validated','needs_review','not_vulnerability')"):
                v = _json(c["details"]).get("validation") or {}
                title = ""
                if c["report_path"] and Path(c["report_path"]).is_file():
                    title = Path(c["report_path"]).read_text(encoding="utf-8", errors="replace").splitlines()[0].lstrip("# ")
                out.append({"crash_id": c["crash_id"], "context": scan.name.replace("scan-", ""), "type": c["crash_type"],
                            "signature": c["signature"], "verdict": v.get("verdict", ""), "score": v.get("cvss_score"),
                            "severity": v.get("severity", ""), "title": title or c["signature"], "path": c["report_path"] or "",
                            "conditional": v.get("conditional_impact", "")})
        finally:
            conn.close()
    order = {"VULNERABILITY": 0, "NEEDS_REVIEW": 1, "NOT_A_VULNERABILITY": 2}
    out.sort(key=lambda o: (order.get(o["verdict"], 3), -(o["score"] or 0)))
    return out


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:   # a zombie is not alive
        return "Z" not in Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0]
    except OSError:
        return True


def session_status(session: dict[str, Any]) -> dict[str, Any]:
    labels.CURRENT.set(session.get("provider") or "claude")
    lines = read_log(Path(session["log"])) if session.get("log") else []
    pipeline_dir = Path(session["pipeline_dir"]) if session.get("pipeline_dir") else pipeline_dir_of(lines)
    alive = pid_alive(session.get("pid")) if session.get("pid") else \
        bool(session.get("log")) and Path(session["log"]).is_file() and time.time() - Path(session["log"]).stat().st_mtime < 120
    hc = hc_run_of(lines, pipeline_dir)
    scans = scan_dirs_of(lines, pipeline_dir)
    progress, label, prep_done = prep_progress(lines, session)
    state = session.get("state", "")
    if state == "failed":
        phase = "failed"
    elif not prep_done and (alive or state in ("preparing", "starting")):
        phase = "prep"
    elif pipeline_dir and (pipeline_dir / "summary.json").is_file():
        phase = "done"
    elif alive or state in ("preparing", "starting"):
        phase = "run"
    else:
        phase = "stopped"
    s1 = stage1(lines, hc, alive)
    s2 = stage2(lines, scans, alive)
    return {"id": session["id"], "name": session.get("name", ""), "rev": session.get("rev", ""), "mode": session.get("mode", "Full"),
            "when": session.get("when", ""), "phase": phase, "error": session.get("error", ""),
            "prep": {"progress": progress, "label": label}, "context": s2.get("context", ""),
            "status": {**s1["status"], **s2["status"]}, "details": {**s1["details"], **s2["details"]},
            "outputs": outputs(scans), "pipeline_dir": str(pipeline_dir or "")}
