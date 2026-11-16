"""`occulta`: the local web console.

    occulta [--port 7860] [--runs-root DIR] [--no-browser]

Serves one page (static/index.html) and a small JSON API:
    GET  /api/sessions                  sidebar: every session, newest first
    GET  /api/sessions/<id>             one session's phase, prep bar, agent statuses and details
    POST /api/scan                      {repo, branch, mode, commit, hours} -> a new session
    POST /api/sessions/<id>/stop
    GET  /api/commits?repo=&branch=     commits for the Delta picker
    GET  /api/file?session=<id>&path=   an advisory or report inside that session's pipeline directory
Standard library only.  Binds to 127.0.0.1.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .sessions import Sessions
from .status import session_status

STATIC = Path(__file__).resolve().parent / "static"
PACKAGE_ROOT = Path(__file__).resolve().parents[2]          # .../src
REPO_ROOT = PACKAGE_ROOT.parent
APP_ROOT = REPO_ROOT.parent                                   # the installed checkout (bin/, VERSION)
_version_cache: dict = {}


def version_info() -> dict:
    """Installed release and the newest release tag on GitHub (checked at most once a minute)."""
    def git(*args: str, timeout: int = 20) -> str:
        out = subprocess.run(["git", "-C", str(APP_ROOT), *args], capture_output=True, text=True, timeout=timeout)
        return out.stdout.strip() if out.returncode == 0 else ""
    try:
        version = (APP_ROOT / "VERSION").read_text().strip()
    except OSError:
        version = "dev"
    current = git("describe", "--tags", "--always") or version
    # Checked again at most once a minute: every page load asks, and the page asks again every
    # few minutes, so a new release shows up without restarting the server.
    if time.time() - _version_cache.get("at", 0) > 60:
        latest = ""
        try:
            branch = git("config", "occulta.branch") or "main"
            fetched = subprocess.run(["git", "-C", str(APP_ROOT), "fetch", "--quiet", "--tags", "origin",
                                      f"+refs/heads/{branch}:refs/remotes/origin/{branch}"],
                                     capture_output=True, text=True, timeout=60)
            _version_cache["error"] = "" if fetched.returncode == 0 else (fetched.stderr.strip()[-200:] or "git fetch failed")
            tags = git("tag", "--list", "v*", "--merged", f"origin/{branch}").split()
            def key(tag: str):
                return tuple(int(p) if p.isdigit() else 0 for p in tag.lstrip("v").split("."))
            latest = max(tags, key=key) if tags else ""
        except (OSError, subprocess.SubprocessError):
            pass
        _version_cache.update(at=time.time(), latest=latest)
    latest = _version_cache.get("latest", "")
    head_tag = git("describe", "--tags", "--exact-match")
    return {"version": version, "current": current, "latest": latest, "check_error": _version_cache.get("error", ""),
            "update": bool(latest) and latest != head_tag and (APP_ROOT / ".git").exists()}


def _handler(sessions: Sessions):
    class Handler(BaseHTTPRequestHandler):
        server_version = "occulta"

        def log_message(self, fmt, *args):     # quiet
            return

        def _send(self, code: int, body: bytes, kind: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, code: int = 200) -> None:
            self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def _error(self, code: int, message: str) -> None:
            self._json({"error": message}, code)

        def do_GET(self):
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            try:
                if url.path in ("/", "/index.html"):
                    return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
                if url.path == "/api/version":
                    return self._json(version_info())
                if url.path == "/api/sessions":
                    items = []
                    for s in sessions.all():
                        items.append({"id": s["id"], "name": s.get("name", ""), "rev": s.get("rev", ""),
                                      "mode": s.get("mode", "Full"), "when": s.get("when", ""),
                                      "phase": sessions.light_phase(s)})
                    return self._json({"sessions": items, "profiles": sessions.profiles()})
                if url.path.startswith("/api/sessions/"):
                    sid = url.path.split("/")[3]
                    session = sessions.load(sid)
                    if not session:
                        return self._error(404, "no such session")
                    return self._json(session_status(session))
                if url.path == "/api/commits":
                    return self._json({"commits": sessions.commits(q.get("repo", ""), q.get("branch", ""))})
                if url.path == "/api/file":
                    session = sessions.load(q.get("session", "")) or {}
                    root = Path(session.get("pipeline_dir") or "/nonexistent").resolve()
                    path = Path(q.get("path", "")).resolve()
                    if root not in path.parents or not path.is_file():
                        return self._error(403, "outside this session")
                    return self._send(200, path.read_bytes(), "text/plain; charset=utf-8")
                return self._error(404, "not found")
            except Exception as exc:
                return self._error(500, str(exc))

        def do_POST(self):
            url = urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._error(400, "bad json")
            try:
                if url.path == "/api/scan":
                    hours = str(body.get("hours", "")).strip()
                    if not hours.lstrip("-").isdigit() or not (int(hours) == -1 or int(hours) > 0):
                        return self._error(400, "시간 제한은 양의 정수, 또는 -1(제한 없음)")
                    if not str(body.get("repo", "")).strip():
                        return self._error(400, "저장소를 입력해")
                    if body.get("mode") == "delta" and not body.get("commit"):
                        return self._error(400, "Delta Scan 은 커밋을 골라야 해")
                    provider = str(body.get("provider") or "claude")
                    if provider not in ("claude", "codex", "ollama"):
                        return self._error(400, "provider 는 claude, codex, ollama 중 하나")
                    models = {str(k): str(v).strip() for k, v in (body.get("models") or {}).items() if str(v).strip()}
                    s = sessions.start(body["repo"], str(body.get("branch") or ""), body.get("mode", "full"),
                                       body.get("commit", ""), int(hours), provider=provider, models=models)
                    return self._json({"id": s["id"]})
                if url.path == "/api/update":
                    out = subprocess.run(["bash", str(APP_ROOT / "bin" / "occulta-update")], capture_output=True, text=True,
                                         timeout=900)
                    if out.returncode != 0:
                        return self._error(409 if out.returncode == 2 else 500, (out.stdout + out.stderr).strip()[-600:])
                    self._json({"ok": True, "log": out.stdout[-2000:]})
                    # The new code is loaded by starting this server again in the same process slot.
                    threading.Timer(1.0, lambda: os.execv(sys.executable, [sys.executable, "-m", "fbaugur.web",
                                                                           "--no-browser", *sys.argv[1:]])).start()
                    return None
                if url.path.startswith("/api/sessions/") and url.path.endswith("/delete"):
                    return self._json({"result": sessions.delete(url.path.split("/")[3])})
                if url.path.startswith("/api/sessions/") and url.path.endswith("/hours"):
                    raw = str(body.get("hours", "")).strip()
                    if not re.fullmatch(r"-?\d+", raw) or (int(raw) != -1 and int(raw) <= 0):
                        return self._error(400, "시간은 양의 정수, 제한 없음은 -1")
                    return self._json(sessions.set_hours(url.path.split("/")[3], int(raw)))
                if url.path.startswith("/api/sessions/") and url.path.endswith("/stop"):
                    sessions.stop(url.path.split("/")[3])
                    return self._json({"ok": True})
                return self._error(404, "not found")
            except Exception as exc:
                return self._error(500, str(exc))

    return Handler


def _open_browser(url: str) -> None:
    """From WSL the Windows browser reaches localhost; elsewhere use the default browser."""
    if shutil.which("cmd.exe"):
        subprocess.Popen(["cmd.exe", "/c", "start", "", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         cwd="/mnt/c" if os.path.isdir("/mnt/c") else None)
    elif shutil.which("wslview"):
        subprocess.Popen(["wslview", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        webbrowser.open(url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="occulta", description="Occulta web console")
    parser.add_argument("--port", type=int, default=int(os.environ.get("OCCULTA_PORT", 7860)))
    parser.add_argument("--home", type=Path, default=Path(os.environ.get("OCCULTA_HOME", Path.home() / ".occulta")))
    parser.add_argument("--runs-root", type=Path, default=Path(os.environ.get("OCCULTA_RUNS", str(Path.home() / ".occulta" / "cli-runs"))),
                        help="where earlier pipeline runs (and their .log files) are, shown in the sidebar")
    parser.add_argument("--targets", type=Path, default=REPO_ROOT / "targets", help="target profiles")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    sessions = Sessions(args.home, args.runs_root, PACKAGE_ROOT, args.targets, args.python)
    httpd = None
    for port in range(args.port, args.port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", port), _handler(sessions))
            break
        except OSError:
            continue
    if httpd is None:
        print(f"occulta: no free port from {args.port}", file=sys.stderr)
        return 1
    url = f"http://localhost:{httpd.server_address[1]}"
    print(f"Occulta  {url}   (Ctrl+C to quit; scans keep running)", flush=True)
    if not args.no_browser:
        threading.Timer(0.5, _open_browser, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
