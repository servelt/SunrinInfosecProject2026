"""Occulta sessions: scans started from the web page, and earlier runs found on disk.

A session started here lives in OCCULTA_HOME/sessions/<id>/:
    session.json   what was asked and where it stands (state, pid, prep progress, error)
    work/          the clone (work/source) and everything the target profile builds
    pipeline.log   the pipeline's log, the same text the CLI prints
    runs/          the pipeline directory

Preparing an arbitrary repository is not automated: a target profile (targets/<name>/) says how
to configure and build it for analysis and how the pipeline should start it.  A repository with
no profile fails at preparation with that reason, instead of a half-made scan.
"""

from __future__ import annotations

import contextlib
import shutil
import json
import os
import re
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from .. import proctrack
from .status import pid_alive, pipeline_dir_of, read_log

UNLIMITED_HOURS = 720.0       # "-1": run until stopped


def normalise_repo(repo: str) -> str:
    """Display/key form: host/owner/name, whatever form the link was typed in."""
    repo = repo.strip().rstrip("/")
    repo = re.sub(r"\.git$", "", repo)
    repo = re.sub(r"^git@([^:]+):", r"\1/", repo)
    repo = re.sub(r"^(?:https?|git|ssh)://(?:[^@/]+@)?", "", repo)
    repo = re.sub(r"^www\.", "", repo)
    return repo


def clone_url(repo: str) -> str:
    """The link as typed when it names a scheme (http://, https://, ssh://, git@), else https://."""
    raw = repo.strip().rstrip("/")
    if re.match(r"^(?:https?|git|ssh)://", raw) or re.match(r"^[^/@\s]+@[^:]+:", raw):
        return raw
    return "https://" + normalise_repo(raw)


class Sessions:
    def __init__(self, home: Path, runs_root: Path | None, package_root: Path, targets: Path, python: str):
        self.home = Path(home)
        (self.home / "sessions").mkdir(parents=True, exist_ok=True)
        self.runs_root = Path(runs_root) if runs_root else None
        self.package_root = Path(package_root)       # .../fbaugur/src
        self.targets = Path(targets)
        self.python = python
        self.lock = threading.Lock()
        self._log_map: dict[str, str] = {}
        self._log_map_at = 0.0

    # ------------------------------------------------------------------ records
    def _path(self, sid: str) -> Path:
        return self.home / "sessions" / sid / "session.json"

    def load(self, sid: str) -> dict[str, Any] | None:
        path = self._path(sid)
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
        return self._discovered().get(sid)

    def save(self, session: dict[str, Any]) -> None:
        with self.lock:
            path = self._path(session["id"])
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(session, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(path)

    def update(self, sid: str, **values) -> dict[str, Any]:
        session = self.load(sid) or {"id": sid}
        session.update(values)
        self.save(session)
        return session

    # ------------------------------------------------------------------ earlier runs on disk
    def _logs_by_pipeline(self) -> dict[str, str]:
        if not self.runs_root or time.time() - self._log_map_at < 30:
            return self._log_map
        found = {}
        for log in self.runs_root.glob("*.log"):
            try:
                head = log.read_text(encoding="utf-8", errors="replace")[:600].splitlines()
            except OSError:
                continue
            directory = pipeline_dir_of(head)
            if directory:
                found[str(directory)] = str(log)
        self._log_map, self._log_map_at = found, time.time()
        return found

    def _discovered(self) -> dict[str, dict[str, Any]]:
        if not self.runs_root or not self.runs_root.is_dir():
            return {}
        own = {str(Path(s.get("pipeline_dir", ""))) for s in self._own()}
        logs = self._logs_by_pipeline()
        out = {}
        for directory in sorted(self.runs_root.glob("*-pipeline")):
            if str(directory) in own or not any(directory.glob("scan*")) and not (directory / "harness").is_dir():
                continue
            log = logs.get(str(directory), "")
            if not log:
                continue
            name, rev, mode = directory.name, "", "Full"
            for project in directory.glob("harness/*/project.json"):
                name = json.loads(project.read_text(encoding="utf-8")).get("name") or name
            for cfg in directory.glob("scan*/config.json"):
                data = json.loads(cfg.read_text(encoding="utf-8"))
                rev = data.get("product_version") or rev
                if data.get("diff_path"):
                    mode = "Delta"
            if name == directory.name:
                lines = read_log(Path(log))
                m = next((re.search(r"--name (\S+)", l) for l in lines[:6] if "--name" in l), None)
                name = m.group(1) if m else name
                skipped = next((re.search(r"reusing (\S+)", l) for l in lines[:12] if "reusing" in l), None)
                if skipped and (Path(skipped.group(1)) / "project.json").is_file():
                    name = json.loads((Path(skipped.group(1)) / "project.json").read_text()).get("name") or name
            stamp = directory.name.split("-")
            when = f"{stamp[0][4:6]}/{stamp[0][6:8]} {stamp[1][:2]}:{stamp[1][2:4]}" if len(stamp) > 2 else ""
            out[directory.name] = {"id": directory.name, "name": name, "rev": rev, "mode": mode, "when": when,
                                   "log": log, "pipeline_dir": str(directory), "state": "found",
                                   "created": directory.stat().st_mtime}
        return out

    def _own(self) -> list[dict[str, Any]]:
        out = []
        for path in (self.home / "sessions").glob("*/session.json"):
            try:
                out.append(json.loads(path.read_text(encoding="utf-8")))
            except ValueError:
                continue
        return out

    def _hidden(self) -> set[str]:
        try:
            return set(json.loads((self.home / "hidden.json").read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return set()

    def delete(self, sid: str) -> str:
        """A session started here is stopped and its directory removed.  A run found on disk
        (not started by Occulta) is only hidden from the list: its files belong to that run."""
        if not re.fullmatch(r"[A-Za-z0-9._-]+", sid):
            raise ValueError("bad session id")
        own = self.home / "sessions" / sid
        if (own / "session.json").is_file():
            proctrack.cancel(sid)
            session = self.load(sid) or {}
            pid = session.get("pid")
            if pid and pid_alive(pid):
                with contextlib.suppress(OSError):
                    os.killpg(pid, signal.SIGTERM)
                for _ in range(50):
                    if not pid_alive(pid):
                        break
                    time.sleep(0.1)
                with contextlib.suppress(OSError):
                    if pid_alive(pid):
                        os.killpg(pid, signal.SIGKILL)
            shutil.rmtree(own, ignore_errors=True)
            return "deleted"
        with self.lock:
            hidden = self._hidden() | {sid}
            (self.home / "hidden.json").write_text(json.dumps(sorted(hidden)), encoding="utf-8")
        return "hidden"

    def all(self) -> list[dict[str, Any]]:
        hidden = self._hidden()
        sessions = [s for s in self._own() + list(self._discovered().values()) if s.get("id") not in hidden]
        for s in sessions:
            if not s.get("pipeline_dir") and s.get("log"):
                directory = pipeline_dir_of(read_log(Path(s["log"]))[:20])
                if directory:
                    s["pipeline_dir"] = str(directory)
                    if s.get("state") != "found":
                        self.update(s["id"], pipeline_dir=str(directory))
        return sorted(sessions, key=lambda s: -s.get("created", 0))

    def light_phase(self, s: dict[str, Any]) -> str:
        if s.get("state") == "failed":
            return "failed"
        if s.get("state") in ("preparing", "starting"):
            return "prep"
        directory = Path(s["pipeline_dir"]) if s.get("pipeline_dir") else None
        if directory and (directory / "summary.json").is_file():
            return "done"
        if s.get("pid"):
            return "run" if pid_alive(s["pid"]) else "stopped"
        log = Path(s["log"]) if s.get("log") else None
        return "run" if log and log.is_file() and time.time() - log.stat().st_mtime < 120 else "stopped"

    # ------------------------------------------------------------------ profiles
    @property
    def auto_targets(self) -> Path:
        """Profiles the preparation agent produced and Occulta verified (autoprep.save_profile)."""
        return self.home / "targets"

    def profile_for(self, repo: str) -> tuple[Path, dict[str, Any]] | None:
        key = normalise_repo(repo).lower()
        for path in sorted(self.targets.glob("*/profile.json")) + sorted(self.auto_targets.glob("*/profile.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            if any(normalise_repo(r).lower() == key for r in data.get("repos", [])):
                return path.parent, data
        return None

    def profiles(self) -> list[str]:
        return [json.loads(p.read_text())["repos"][0] for p in sorted(self.targets.glob("*/profile.json"))]

    # ------------------------------------------------------------------ git
    def commits(self, repo: str, branch: str, limit: int = 40, query: str = "") -> list[dict[str, str]]:
        """Commits of a branch, newest first, from a blob-less mirror kept under OCCULTA_HOME.

        Without `query` the newest `limit`.  With one, older history is searched instead: a hash
        (prefix) of any commit, or words in the message (case-insensitive), newest first.
        """
        key = re.sub(r"[^A-Za-z0-9._-]", "_", normalise_repo(repo))
        mirror = self.home / "mirrors" / key
        url = clone_url(repo)
        if not mirror.is_dir():
            mirror.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "clone", "--bare", "--filter=blob:none", url, str(mirror)], check=True,
                           capture_output=True, timeout=300)
        elif not query:      # a search reuses the mirror the list just fetched, so typing stays fast
            subprocess.run(["git", "-C", str(mirror), "fetch", "--prune", "origin", "+refs/heads/*:refs/heads/*",
                            "+refs/tags/*:refs/tags/*"], capture_output=True, timeout=300)
        ref = branch or "HEAD"
        fmt = ["--format=%h%x1f%ad%x1f%s", "--date=short"]
        rows: list[str] = []
        query = query.strip()
        if query and re.fullmatch(r"[0-9a-fA-F]{4,40}", query):
            found = subprocess.run(["git", "-C", str(mirror), "log", "-1", *fmt, query, "--"],
                                   capture_output=True, text=True, timeout=60)
            if found.returncode == 0:
                rows += found.stdout.splitlines()
        if query:
            out = subprocess.run(["git", "-C", str(mirror), "log", f"--max-count={limit}", *fmt, "-i",
                                  "--fixed-strings", f"--grep={query}", ref],
                                 capture_output=True, text=True, timeout=120)
        else:
            out = subprocess.run(["git", "-C", str(mirror), "log", f"--max-count={limit}", *fmt, ref],
                                 capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise ValueError(out.stderr.strip()[-300:] or f"no such branch or tag: {ref}")
        rows += out.stdout.splitlines()
        seen, result = set(), []
        for line in rows:
            if line and line.split("\x1f")[0] not in seen:
                seen.add(line.split("\x1f")[0])
                result.append(dict(zip(("hash", "date", "msg"), line.split("\x1f"))))
        return result

    # ------------------------------------------------------------------ start / stop
    def start(self, repo: str, branch: str, mode: str, commit: str, hours: int, *, provider: str = "claude",
              models: dict[str, str] | None = None) -> dict[str, Any]:
        repo_n = normalise_repo(repo)
        sid = time.strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(2).hex()
        session = {"id": sid, "repo": repo_n, "url": clone_url(repo), "provider": provider, "models": dict(models or {}), "branch": branch.strip(), "mode": "Delta" if mode == "delta" else "Full",
                   "commit": commit, "hours": hours, "name": repo_n.split("/")[-1],
                   "rev": (commit if mode == "delta" else branch.strip() or "기본 브랜치"), "when": time.strftime("%m/%d %H:%M"),
                   "created": time.time(), "state": "preparing", "prep_progress": 0.02, "prep_label": "저장소 받기",
                   "log": str(self.home / "sessions" / sid / "pipeline.log"), "pid": None, "error": ""}
        self.save(session)
        threading.Thread(target=self._run, args=(sid,), daemon=True).start()
        return session

    def stop(self, sid: str) -> None:
        proctrack.cancel(sid)              # clone / prepare.sh / preparation agent, before any pipeline
        session = self.load(sid) or {}
        pid = session.get("pid")
        if pid and pid_alive(pid):
            try:
                os.killpg(pid, signal.SIGTERM)
            except OSError:
                pass
        if session.get("state") in ("preparing", "starting"):
            self.update(sid, state="failed", error="사용자가 멈춤")
        else:
            self.update(sid, state="stopped")

    def set_hours(self, sid: str, hours: int) -> dict[str, Any]:
        """Change the time limit of a session, also while it runs (the pipeline re-reads its deadline file)."""
        from .. import deadline as live
        session = self.load(sid) or {}
        if not session:
            raise ValueError("no such session")
        start = float(session.get("created") or time.time())
        end = start + (UNLIMITED_HOURS if hours == -1 else float(hours)) * 3600
        session = self.update(sid, hours=hours)
        target = Path(session["pipeline_dir"]) / "deadline" if session.get("pipeline_dir") else None
        if target is not None and target.parent.is_dir():
            live.write(target, end)
        return {"hours": hours, "ends_at": None if hours == -1 else end}

    def _auto_prepare(self, sid: str, session: dict[str, Any], work: Path, hc_root: Path) -> tuple[Path, dict[str, Any]]:
        """No profile for this repository: an agent writes one in WORK/profile, Occulta checks it."""
        from ..autoprep import AutoPrep, default_model, save_profile
        provider = session.get("provider") or "claude"
        name = re.sub(r"[^A-Za-z0-9._-]", "_", session["repo"].split("/")[-1]).lower() or "target"
        self._log(sid, f"[autoprep] no profile for {session['repo']}: the preparation agent works it out")
        self.update(sid, prep_progress=0.15, prep_label="자동 준비: 빌드 방법 찾는 중")
        steps = {"n": 0}

        def progress(label: str) -> None:
            steps["n"] += 1
            self.update(sid, prep_progress=min(0.48, 0.15 + 0.004 * steps["n"]), prep_label="자동 준비: " + label)

        prep = AutoPrep(work, repo=session["repo"], name=name, provider=provider, key=sid,
                        model=default_model(provider, session.get("models")), python=self.python, hc=hc_root,
                        emit=lambda m: self._log(sid, m), progress=progress)
        ok, problems, summary = prep.run()
        if not ok:
            raise RuntimeError("자동 준비가 실패함: " + " / ".join(p[:200] for p in problems[:3]))
        dest = save_profile(work, self.auto_targets, name)
        self._log(sid, f"[autoprep] profile verified and kept in {dest}")
        self.update(sid, prep_progress=0.5, prep_label="자동 준비 완료")
        return dest, json.loads((dest / "profile.json").read_text(encoding="utf-8"))

    def _log(self, sid: str, text: str) -> None:
        with open(self.home / "sessions" / sid / "pipeline.log", "a", encoding="utf-8") as handle:
            handle.write(time.strftime("[%H:%M:%S] ") + text + "\n")

    def _run(self, sid: str) -> None:
        session = self.load(sid)
        root = self.home / "sessions" / sid
        work = root / "work"
        try:
            found = self.profile_for(session["repo"])
            self._log(sid, f"occulta: {session['repo']} @ {session['rev']} ({session['mode']})")
            url = session.get("url") or clone_url(session["repo"])
            self._log(sid, f"clone {url}")
            cloned = proctrack.run(sid, ["git", "clone", "--filter=blob:none", "--no-checkout", url, str(work / "source")],
                                   text=True, timeout=600)
            if cloned.returncode != 0:
                raise RuntimeError(f"clone 실패: {cloned.stderr.strip()[-300:]}")
            branch = session.get("branch") or ""
            if not branch:            # no branch typed: the repository's default branch (main, master, ...)
                head = proctrack.run(sid, ["git", "-C", str(work / "source"), "symbolic-ref", "--short", "HEAD"],
                                     text=True, timeout=30)
                branch = head.stdout.strip() or "HEAD"
                self.update(sid, branch=branch, **({} if session["mode"] == "Delta" else {"rev": branch}))
            target = session["commit"] if session["mode"] == "Delta" else branch
            checkout = proctrack.run(sid, ["git", "-C", str(work / "source"), "checkout", "--quiet", target],
                                     text=True, timeout=300)
            if checkout.returncode != 0:
                raise RuntimeError(f"'{target}' 를 체크아웃하지 못함: {checkout.stderr.strip()[-200:]}")
            if session["mode"] == "Delta":
                diff = proctrack.run(sid, ["git", "-C", str(work / "source"), "diff", f"{target}^", target],
                                     text=True, timeout=120)
                (work / "delta.diff").write_text(diff.stdout, encoding="utf-8")
            self.update(sid, prep_progress=0.12, prep_label="대상 준비")
            hc_root = self.package_root.parent.parent / "harnesscreator"
            if not (hc_root / "src" / "harnesscreator").is_dir():
                hc_root = Path(os.environ.get("HARNESSCREATOR", hc_root))
            prepared = False
            if found is None:
                found = self._auto_prepare(sid, session, work, hc_root)
                prepared = True       # the check already ran prepare.sh on this WORK
            profile_dir, profile = found
            env = dict(os.environ, WORK=str(work), PROFILE=str(profile_dir), PY=self.python, HC=str(hc_root))
            if not prepared:
                proc = proctrack.spawn(sid, ["bash", str(profile_dir / profile["prepare"])], cwd=str(work), env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                steps = 0
                for line in proc.stdout:
                    line = line.rstrip()
                    self._log(sid, "  " + line)
                    m = re.match(r"\[prep\] (.+)", line)
                    if m:
                        steps += 1
                        self.update(sid, prep_progress=min(0.5, 0.12 + 0.1 * steps), prep_label=m.group(1))
                proctrack.forget(sid, proc)
                if proctrack.cancelled(sid):
                    raise proctrack.Cancelled("사용자가 멈춤")
                if proc.wait() != 0:
                    raise RuntimeError(f"대상 준비가 실패함 (exit {proc.returncode}); {work}/*.log 확인")
            session = self.load(sid) or session          # the limit may have been changed during preparation
            if int(session["hours"]) == -1:
                hours = UNLIMITED_HOURS
            else:   # counted from when the scan was started, like a limit changed later (set_hours)
                hours = max(0.1, (float(session.get("created") or time.time()) + float(session["hours"]) * 3600
                                  - time.time()) / 3600)
            args = [self.python, "-m", "fbaugur.cli", "pipeline", str(work / "source"), "--name", profile["name"],
                    "--output", str(root / "runs"), "--python", self.python, "--max-hours", str(hours),
                    "--product-version", session["rev"]]
            # The scan's time limit governs stage 1 (half of it); a stage-1 cap written into a profile
            # (earlier auto-prepared profiles copied "--harness-max-minutes 55" from the example) would
            # cut harness generation off whatever limit the scan was started with.
            extra = [a.replace("{WORK}", str(work)) for a in profile.get("pipeline_args", [])]
            for i, a in enumerate(extra):
                if a == "--harness-max-minutes":
                    del extra[i:i + 2]
                    break
            args += extra
            if session["mode"] == "Delta":
                args += ["--diff", str(work / "delta.diff")]
            args += ["--provider", session.get("provider") or "claude"]
            for tier, model in sorted((session.get("models") or {}).items()):
                if tier in ("1", "2", "3"):
                    args += [f"--model-t{tier}", model]
            if proctrack.cancelled(sid):
                raise proctrack.Cancelled("사용자가 멈춤")
            self.update(sid, prep_progress=0.52, prep_label="정적 분석 준비", state="starting")
            log = open(root / "pipeline.log", "a", encoding="utf-8")
            pipeline = subprocess.Popen(args, cwd=str(self.package_root.parent), stdout=log, stderr=subprocess.STDOUT,
                                        env=dict(os.environ, PYTHONPATH=str(self.package_root)), start_new_session=True)
            self.update(sid, pid=pipeline.pid, state="running")
        except proctrack.Cancelled:
            if (self.home / "sessions" / sid).is_dir():
                self._log(sid, "stopped by the user during preparation")
                self.update(sid, state="failed", error="사용자가 멈춤")
        except Exception as exc:          # every failure ends up on the page, with its reason
            if proctrack.cancelled(sid):
                return
            self._log(sid, f"failed: {exc}")
            self.update(sid, state="failed", error=str(exc))
