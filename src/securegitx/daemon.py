"""
SecureGitX background daemon — advisory only.

Watches the repository for staging changes and sensitive untracked files.
On change: runs a background scan and writes structured results to the local cache.
Queues .gitignore suggestions for user approval; never applies them automatically.

The daemon NEVER:
  - stages or commits files
  - modifies .gitignore or any repository file without user approval
  - replaces the pre-commit hook as the enforcement point
  - fetches remote code at runtime

Local state lives in .securegitx/ which is always in .gitignore.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path

_LOG = logging.getLogger("securegitx.daemon")

_DEFAULT_INTERVAL: float = 2.0

_STATE_DIR = ".securegitx"
_PID_FILE = "daemon.pid"
_LOG_FILE = "logs/daemon.log"
_CACHE_FILE = "cache/scan_result.json"
_SUGGESTIONS_FILE = "cache/gitignore_suggestions.json"


class DaemonError(Exception):
    pass


# State-dir helpers


def _state(root: Path) -> Path:
    return root / _STATE_DIR


def _ensure_dirs(root: Path) -> None:
    state = _state(root)
    (state / "cache").mkdir(parents=True, exist_ok=True)
    (state / "logs").mkdir(parents=True, exist_ok=True)


def _pid_path(root: Path) -> Path:
    return _state(root) / _PID_FILE


def _cache_path(root: Path) -> Path:
    return _state(root) / _CACHE_FILE


def _suggestions_path(root: Path) -> Path:
    return _state(root) / _SUGGESTIONS_FILE


def _write_pid(root: Path) -> None:
    _pid_path(root).write_text(str(os.getpid()), encoding="utf-8")


def _clear_pid(root: Path) -> None:
    _pid_path(root).unlink(missing_ok=True)


def _read_pid(root: Path) -> int | None:
    path = _pid_path(root)
    if not path.exists():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def is_running(root: Path) -> bool:
    """Return True if a daemon process for this repo is alive."""
    pid = _read_pid(root)
    if pid is None:
        return False
    try:
        os.kill(pid, 0)  # signal 0 = check existence only
        return True
    except (ProcessLookupError, PermissionError):
        _clear_pid(root)
        return False


# Daemon class


class SecureGitXDaemon:
    """
    Thread-based polling watcher.

    Polls .git/index mtime to detect staging changes.
    Also scans for newly created untracked files matching sensitive patterns.
    """

    def __init__(self, root: Path, interval: float = _DEFAULT_INTERVAL) -> None:
        self._root = root
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._index = root / ".git" / "index"
        self._last_mtime: float = 0.0
        self._project_type = "generic"

    # Public

    def start(self) -> None:
        if is_running(self._root):
            raise DaemonError("Daemon already running for this repository")

        _ensure_dirs(self._root)
        self._configure_logging()
        self._detect_project()

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._watch_loop,
            name="securegitx-daemon",
            daemon=True,
        )
        self._thread.start()
        _write_pid(self._root)
        _LOG.info(
            "Started (pid=%d, interval=%.1fs, project=%s)",
            os.getpid(),
            self._interval,
            self._project_type,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self._interval * 2)
        _clear_pid(self._root)
        _LOG.info("Stopped")

    def join(self) -> None:
        """Block until the watch loop exits (use for foreground mode)."""
        if self._thread:
            self._thread.join()

    # Internal — setup

    def _configure_logging(self) -> None:
        log_path = _state(self._root) / "logs" / "daemon.log"
        if not _LOG.handlers:
            handler = logging.FileHandler(log_path, encoding="utf-8")
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)-8s %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S",
                )
            )
            _LOG.addHandler(handler)
            _LOG.setLevel(logging.INFO)

    def _detect_project(self) -> None:
        try:
            from securegitx.project_detect import detect

            info = detect(self._root)
            self._project_type = info.type
            _LOG.info(
                "Project type: %s (confidence=%s, markers=%s)",
                info.type,
                info.confidence,
                info.markers,
            )
        except Exception as exc:
            _LOG.warning("Project detection failed: %s", exc)

    # Internal — watch loop

    def _watch_loop(self) -> None:
        _LOG.info("Watch loop running (polling every %.1fs)", self._interval)
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:
                _LOG.error("Tick error: %s", exc)
            self._stop.wait(self._interval)
        _LOG.info("Watch loop exited")

    def _tick(self) -> None:
        mtime = self._index_mtime()
        if mtime is not None and mtime != self._last_mtime:
            self._last_mtime = mtime
            _LOG.info("git index changed — running background scan")
            self._run_scan()

        # Always check for sensitive untracked files each tick
        self._check_untracked_sensitive()

    def _index_mtime(self) -> float | None:
        try:
            return self._index.stat().st_mtime
        except FileNotFoundError:
            return None

    # Internal — scan

    def _run_scan(self) -> None:
        try:
            from securegitx import gitops, scanner
            from securegitx.config import load_config
            from securegitx.rules import load_rules, load_allowlist

            config = load_config(cwd=self._root)
            rules = load_rules()
            allowlist = load_allowlist()

            staged = gitops.staged_files(cwd=self._root)
            diff = gitops.staged_diff(cwd=self._root)

            findings = scanner.scan_filenames(staged, rules, allowlist)
            findings += scanner.scan_diff(
                diff, rules, allowlist, config.entropy_threshold
            )

            self._write_cache(staged, findings)

            if findings:
                _LOG.warning(
                    "%d finding(s) in staged files — commit will be blocked",
                    len(findings),
                )
                for f in findings:
                    _LOG.warning("  [%s] %s line %d", f.rule_id, f.file, f.line_number)
            else:
                _LOG.info("Staged files clean (%d file(s))", len(staged))

        except Exception as exc:
            _LOG.error("Background scan failed: %s", exc)

    def _check_untracked_sensitive(self) -> None:
        """
        Scan untracked files for sensitive filename patterns.
        Queues .gitignore suggestions; never modifies files directly.
        """
        try:
            from securegitx.rules import load_rules, load_allowlist
            from securegitx import scanner

            result = subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=self._root,
                capture_output=True,
                text=True,
            )
            untracked = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            if not untracked:
                return

            rules = load_rules()
            allowlist = load_allowlist()
            sensitive = scanner.scan_filenames(untracked, rules, allowlist)

            for finding in sensitive:
                _LOG.warning(
                    "Sensitive untracked file: %s [%s]", finding.file, finding.rule_id
                )
                self._queue_suggestion(finding.file)

        except Exception as exc:
            _LOG.debug("Untracked file check failed: %s", exc)

    def _queue_suggestion(self, filepath: str) -> None:
        """Add a .gitignore suggestion to the queue without applying it."""
        path = _suggestions_path(self._root)
        suggestions: list[str] = []

        if path.exists():
            try:
                suggestions = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        if filepath not in suggestions:
            suggestions.append(filepath)
            path.write_text(json.dumps(suggestions, indent=2), encoding="utf-8")
            _LOG.info("Queued .gitignore suggestion: %s", filepath)

    def _write_cache(self, staged: list[str], findings: list) -> None:
        cache = {
            "timestamp": time.time(),
            "staged_count": len(staged),
            "staged_files": staged,
            "finding_count": len(findings),
            "clean": len(findings) == 0,
            "findings": [f.as_dict() for f in findings],
        }
        try:
            _cache_path(self._root).write_text(
                json.dumps(cache, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            _LOG.error("Failed to write cache: %s", exc)


# CLI-facing functions (called from _cmd_daemon in cli.py)


def start(root: Path, interval: float = _DEFAULT_INTERVAL) -> str:
    """Start the daemon in the foreground. Use & or nohup for background."""
    if is_running(root):
        return f"Daemon already running (pid={_read_pid(root)})"
    daemon = SecureGitXDaemon(root, interval=interval)
    daemon.start()
    return f"Daemon started (pid={os.getpid()}) — watching {root}"


def stop(root: Path) -> str:
    """Send SIGTERM to the running daemon."""
    pid = _read_pid(root)
    if pid is None or not is_running(root):
        _clear_pid(root)
        return "No daemon running"
    try:
        import signal

        os.kill(pid, signal.SIGTERM)
        _clear_pid(root)
        return f"Daemon stopped (pid={pid})"
    except (ProcessLookupError, PermissionError) as exc:
        raise DaemonError(f"Could not stop daemon (pid={pid}): {exc}") from exc


def status(root: Path) -> str:
    """Return a human-readable daemon status string."""
    pid = _read_pid(root)
    running = is_running(root)

    if not running:
        return "Daemon: not running"

    lines = [f"Daemon: running (pid={pid})"]

    cache = _cache_path(root)
    if cache.exists():
        try:
            data = json.loads(cache.read_text(encoding="utf-8"))
            age = time.time() - data.get("timestamp", 0)
            staged = data.get("staged_count", 0)
            clean = data.get("clean", True)
            n_finds = data.get("finding_count", 0)
            lines.append(f"Last scan: {age:.0f}s ago — {staged} staged file(s)")
            lines.append(
                "Findings: none"
                if clean
                else f"Findings: {n_finds} (commit will be blocked)"
            )
        except (json.JSONDecodeError, OSError):
            lines.append("Cache: unreadable")

    suggestions = read_suggestions(root)
    if suggestions:
        lines.append(f"Pending .gitignore suggestions: {len(suggestions)}")
        lines.append("  Run: securegitx init --apply-suggestions  to apply")

    return "\n".join(lines)


# .gitignore suggestion queue


def read_suggestions(root: Path) -> list[str]:
    """Return pending .gitignore suggestions from the daemon cache."""
    path = _suggestions_path(root)
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def apply_suggestions(root: Path, project_type: str) -> str:
    """
    Write queued .gitignore suggestions into the managed section and clear the queue.
    Must be called explicitly by the user — never called automatically.
    """
    suggestions = read_suggestions(root)
    if not suggestions:
        return "No pending .gitignore suggestions"

    from securegitx.gitignore_builder import ensure_gitignore

    msg = ensure_gitignore(root, project_type, extra_entries=suggestions)

    _suggestions_path(root).write_text("[]", encoding="utf-8")
    return f"{msg} — {len(suggestions)} suggestion(s) applied"
