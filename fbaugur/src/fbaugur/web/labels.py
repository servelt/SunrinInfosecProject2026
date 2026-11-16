"""Short Korean labels for the page: an entry's code line and what comes in there, a context's
name and what it covers.

HarnessCreator's own agents are not asked for these: changing their output schema would change
stage 1 itself.  Instead one small model call per batch, made by the web server, turns the
records stage 1 already wrote into display labels, and the answer is kept next to them in
`<harnesscreator run>/occulta-labels.json` so each item is labelled once.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
from pathlib import Path
from typing import Any

MODEL = "claude-haiku-5-5"
_busy: set[str] = set()
_lock = threading.Lock()

ENTRY_PROMPT = """아래는 C 프로그램에서 외부 입력이 처음 들어오는 지점(Entry) 후보들이다. 각 항목마다 화면에 보여줄
라벨을 만들어라.

- code: 입력을 받는 그 코드 한 줄. 주어진 줄에서 호출 부분만 남겨 짧게 (예: recv(fd, buf, len, MSG_PEEK)).
  argv 처럼 함수 인자로 들어오는 경우는 main(int argc, char **argv) 처럼 쓴다.
- summary: 무엇이 어디서 들어오는지 한국어 한 구절, 25자 이내 (예: "TCP 연결로 들어오는 요청 바이트").
  파일 이름, 줄 번호, 함수 이름은 쓰지 마라.

JSON 배열만 출력하라: [{"id": "...", "code": "...", "summary": "..."}]

항목:
"""

CONTEXT_VERSION = "2"        # bump when CONTEXT_PROMPT changes: old labels are then made again
CONTEXT_PROMPT = """아래는 프로그램의 입력 지점들을 같은 입력 흐름끼리 묶은 문맥(context)들이다. 각 문맥마다 화면에
보여줄 라벨을 만들어라. 설명의 중심은 "외부 입력이 어디서, 무엇으로 처음 들어와 데이터가 시작되는가"다.

- name: 이 입력 흐름의 이름, 한국어 15자 이내 (예: "HTTP 요청 처리", "설정 파일 읽기").
- description: 한국어 두 문장, 합쳐 90자 이내.
  첫 문장: 어떤 통로(TCP 연결, 파일, 명령줄 인자 …)로 무엇(요청 줄, 패킷 바디, 설정 한 줄 …)을 받아오는지.
  둘째 문장: 그 데이터가 외부 입력의 시작이 되어 어디로 넘어가는지.
  예: "TCP 연결로 들어온 요청의 바디 데이터를 버퍼로 받아온다. 이 바이트가 외부 입력의 시작이 되어 요청 처리로 넘어간다."
  파일 이름과 줄 번호는 쓰지 마라. 함수 이름은 꼭 필요할 때 하나만.

JSON 배열만 출력하라: [{"id": "...", "name": "...", "description": "..."}]

문맥 (entries 의 code 가 입력을 받는 코드 줄이다):
"""


HARNESS_VERSION = "2"
HARNESS_PROMPT = """아래는 퍼징 하네스(fuzz_target.c) 들이다. 각 하네스마다 화면에 보여줄 라벨을 만들어라.
설명의 중심은 "퍼저가 만든 바이트를 이 하네스가 프로그램의 어디로, 어떻게 넣는가"다.

- name: 하네스 이름, 한국어 15자 이내. 무엇을 어디로 넣는지가 드러나게 (형식 예: "DNS 질의 패킷 주입", "이미지 파일 디코딩").
- description: 한국어 두 문장, 합쳐 90자 이내.
  첫 문장: 하네스가 프로그램을 어떻게 띄우고 바이트를 어떤 통로로 넣는지 (형식 예: "서버를 스레드로 띄우고 UDP 포트로 퍼저 바이트를 질의 패킷으로 보낸다.").
  둘째 문장: 그 바이트가 어떤 코드를 지나게 되는지.
  파일 이름과 줄 번호는 쓰지 마라. 코드에 없는 동작을 지어내지 마라.

JSON 배열만 출력하라: [{"id": "...", "name": "...", "description": "..."}]

하네스 (context 는 이 하네스가 맡은 입력 흐름, source 는 하네스 코드):
"""


def harness_key(name: str, attempt: int) -> str:
    return f"{name}@h{HARNESS_VERSION}:{attempt}"


def ctx_key(context_id: str) -> str:
    return f"{context_id}@ctx{CONTEXT_VERSION}"


def _cache_path(hc: Path) -> Path:
    return Path(hc) / "occulta-labels.json"


def load(hc: Path) -> dict[str, dict[str, str]]:
    path = _cache_path(hc)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _ask(prompt: str, claude: str) -> list[dict[str, Any]]:
    proc = subprocess.run([claude, "-p", "--model", MODEL, "--output-format", "json", "--tools", "",
                           "--disable-slash-commands", "--max-turns", "1"],
                          input=prompt, capture_output=True, text=True, timeout=240)
    try:
        text = json.loads(proc.stdout).get("result", "")
    except ValueError:
        text = proc.stdout
    match = re.search(r"\[.*\]", text, re.S)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except ValueError:
        return []
    return [d for d in data if isinstance(d, dict) and d.get("id")]


def ensure(hc: Path, entries: list[dict[str, Any]], contexts: list[dict[str, Any]],
           harnesses: list[dict[str, Any]] | None = None, claude: str = "claude") -> None:
    """Label whatever has no label yet, in a background thread (one at a time per run)."""
    have = load(hc)
    todo_e = [e for e in entries if e["id"] not in have]
    todo_c = [c for c in contexts if ctx_key(c["id"]) not in have]
    todo_h = [h for h in harnesses or [] if h["key"] not in have]
    key = str(hc)
    if not todo_e and not todo_c and not todo_h:
        return
    with _lock:
        if key in _busy:
            return
        _busy.add(key)

    def work():
        try:
            found: dict[str, dict[str, str]] = {}
            for i in range(0, len(todo_e), 40):
                batch = todo_e[i:i + 40]
                for item in _ask(ENTRY_PROMPT + json.dumps(batch, ensure_ascii=False, indent=1), claude):
                    found[str(item["id"])] = {"code": str(item.get("code", ""))[:120], "summary": str(item.get("summary", ""))[:60]}
            if todo_c:
                for item in _ask(CONTEXT_PROMPT + json.dumps(todo_c, ensure_ascii=False, indent=1), claude):
                    found[ctx_key(str(item["id"]))] = {"name": str(item.get("name", ""))[:40],
                                              "description": str(item.get("description", ""))[:200]}
            for h in todo_h:
                item = {k: v for k, v in h.items() if k != "key"}
                for answer in _ask(HARNESS_PROMPT + json.dumps([item], ensure_ascii=False, indent=1), claude)[:1]:
                    found[h["key"]] = {"name": str(answer.get("name", ""))[:40],
                                       "description": str(answer.get("description", ""))[:200]}
            if found:
                current = load(hc)
                current.update(found)
                path = _cache_path(hc)
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(current, ensure_ascii=False, indent=1), encoding="utf-8")
                tmp.replace(path)
        finally:
            with _lock:
                _busy.discard(key)

    threading.Thread(target=work, daemon=True).start()


DIRECTION_VERSION = "1"
DIRECTION_PROMPT = """아래는 취약점 분석 에이전트가 하네스가 닿는 코드를 기능별로 나눈 영역(direction)들이다.
name 과 risk_reason 은 영어로 되어 있다. 각 영역마다 화면에 보여줄 한국어 라벨을 만들어라.

- name: 이 영역이 하는 기능, 한국어 20자 이내 (형식 예: "응답 헤더 파싱", "압축 블록 해제").
- description: 한국어 한두 문장, 합쳐 90자 이내. 이 영역이 무슨 일을 하는지와 왜 위험한지(risk_reason 의 핵심).
  함수 이름은 꼭 필요할 때 하나만. risk_reason 에 없는 위험을 지어내지 마라.

JSON 배열만 출력하라: [{"id": "...", "name": "...", "description": "..."}]

영역:
"""


def direction_key(direction_id: str) -> str:
    return f"{direction_id}@dir{DIRECTION_VERSION}"


def ensure_directions(scan: Path, directions: list[dict[str, Any]], claude: str = "claude") -> None:
    """Korean labels for one scan's directions, kept in `<scan>/occulta-labels.json`."""
    have = load(scan)
    todo = [d for d in directions if direction_key(d["id"]) not in have]
    key = str(scan)
    if not todo:
        return
    with _lock:
        if key in _busy:
            return
        _busy.add(key)

    def work():
        try:
            found = {}
            for item in _ask(DIRECTION_PROMPT + json.dumps(todo, ensure_ascii=False, indent=1), claude):
                found[direction_key(str(item["id"]))] = {"name": str(item.get("name", ""))[:40],
                                                         "description": str(item.get("description", ""))[:200]}
            if found:
                current = load(scan)
                current.update(found)
                path = _cache_path(scan)
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps(current, ensure_ascii=False, indent=1), encoding="utf-8")
                tmp.replace(path)
        finally:
            with _lock:
                _busy.discard(key)

    threading.Thread(target=work, daemon=True).start()


SCAN_PROMPTS = {
    "sp": ("1", """아래는 취약점 분석 에이전트가 찾은 의심 지점(SP)들이다. 원문은 영어다. 각 항목마다 한국어 라벨을 만들어라.

- name: 의심하는 버그를 한국어 20자 이내로 (형식 예: "청크 길이 정수 오버플로", "헤더 삭제 중 해제 후 사용").
- description: 한국어 한두 문장, 합쳐 90자 이내. 어떤 입력이 어떤 코드에서 무엇을 잘못 만드는지. description 에 없는 내용은 지어내지 마라.
- reason: verification_notes 가 있고 status 가 rejected 이면, 기각한 이유를 한국어 한 문장 60자 이내로. 아니면 빈 문자열.

JSON 배열만 출력하라: [{"id": "...", "name": "...", "description": "...", "reason": "..."}]

항목:
"""),
    "inv": ("1", """아래는 취약점 분석 에이전트가 코드에 넣은 불변 조건(invariant)들이다. 각 조건은 그 줄에서 항상 참이어야 하는
식이고, 깨지면 버그 신호로 쓴다. 각 항목마다 한국어 라벨을 만들어라.

- name: 무엇을 검사하는지 한국어 20자 이내 (형식 예: "버퍼 길이가 용량 이하", "해제된 노드 재사용 금지").
- description: 한국어 한 문장 70자 이내. 이 조건이 지키려는 보안 성질(security_property, rationale 참고).
- reason: status 가 withdrawn 으로 시작하거나 build_blocked 이면 last_error 를 한국어 한 문장 60자 이내로 요약. 아니면 빈 문자열.

JSON 배열만 출력하라: [{"id": "...", "name": "...", "description": "...", "reason": "..."}]

항목:
"""),
}


def item_key(kind: str, item_id: str) -> str:
    return f"{item_id}@{kind}{SCAN_PROMPTS[kind][0]}"


def ensure_scan_items(scan: Path, kind: str, items: list[dict[str, Any]], claude: str = "claude") -> None:
    have = load(scan)
    todo = [i for i in items if item_key(kind, str(i["id"])) not in have]
    key = f"{scan}#{kind}"
    if not todo:
        return
    with _lock:
        if key in _busy:
            return
        _busy.add(key)

    def work():
        try:
            for start in range(0, len(todo), 25):
                found = {}
                for got in _ask(SCAN_PROMPTS[kind][1] + json.dumps(todo[start:start + 25], ensure_ascii=False, indent=1), claude):
                    found[item_key(kind, str(got["id"]))] = {"name": str(got.get("name", ""))[:40],
                                                             "description": str(got.get("description", ""))[:200],
                                                             "reason": str(got.get("reason", ""))[:120]}
                if found:
                    with _lock:
                        current = load(scan)
                        current.update(found)
                        path = _cache_path(scan)
                        tmp = path.with_suffix(f".{kind}.tmp")
                        tmp.write_text(json.dumps(current, ensure_ascii=False, indent=1), encoding="utf-8")
                        tmp.replace(path)
        finally:
            with _lock:
                _busy.discard(key)

    threading.Thread(target=work, daemon=True).start()
