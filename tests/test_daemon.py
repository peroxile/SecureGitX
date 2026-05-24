from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from securegitx import daemon
from securegitx.scanner import Finding


@pytest.fixture(autouse=True)
def clear_daemon_logger():
    handlers = list(daemon._LOG.handlers)
    for handler in handlers:
        daemon._LOG.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass
    yield
    handlers = list(daemon._LOG.handlers)
    for handler in handlers:
        daemon._LOG.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass


@pytest.fixture()
def repo_root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    return root


def make_finding(
    rule_id: str = "SGX101",
    rule_name: str = "ssh_private_key",
    severity: str = "critical",
    file: str = "secrets/id_rsa",
    line_number: int = 1,
    matched_text: str = "id_rsa",
    reason: str = "Sensitive filename",
    remediation: str = "Move this file out of the repository.",
    confidence: str = "high",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        file=file,
        line_number=line_number,
        matched_text=matched_text,
        reason=reason,
        remediation=remediation,
        confidence=confidence,
    )


def test_state_paths_and_pid_helpers(repo_root: Path):
    assert daemon._state(repo_root) == repo_root / ".securegitx"
    assert daemon._pid_path(repo_root) == repo_root / ".securegitx" / "daemon.pid"
    assert (
        daemon._cache_path(repo_root)
        == repo_root / ".securegitx" / "cache" / "scan_result.json"
    )
    assert (
        daemon._suggestions_path(repo_root)
        == repo_root / ".securegitx" / "cache" / "gitignore_suggestions.json"
    )

    daemon._ensure_dirs(repo_root)
    assert (repo_root / ".securegitx" / "cache").is_dir()
    assert (repo_root / ".securegitx" / "logs").is_dir()

    daemon._write_pid(repo_root)
    assert daemon._read_pid(repo_root) == os.getpid()

    daemon._clear_pid(repo_root)
    assert daemon._read_pid(repo_root) is None


def test_is_running_true_and_stale_pid_cleared(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
):
    daemon._ensure_dirs(repo_root)
    daemon._pid_path(repo_root).write_text("12345", encoding="utf-8")

    monkeypatch.setattr(daemon.os, "kill", lambda pid, sig: None)
    assert daemon.is_running(repo_root) is True

    daemon._pid_path(repo_root).write_text("99999", encoding="utf-8")

    def raise_missing(pid, sig):
        raise ProcessLookupError()

    monkeypatch.setattr(daemon.os, "kill", raise_missing)
    assert daemon.is_running(repo_root) is False
    assert not daemon._pid_path(repo_root).exists()


def test_start_returns_already_running_when_pid_exists(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(daemon, "is_running", lambda root: True)
    monkeypatch.setattr(daemon, "_read_pid", lambda root: 4321)

    msg = daemon.start(repo_root)
    assert "already running" in msg
    assert "4321" in msg


def test_start_spawns_worker_and_waits_until_running(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list[tuple] = []

    class FakeProc:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))
            self._pid = 777

        def poll(self):
            return None

    running = iter([False, True])

    def fake_is_running(root):
        return next(running)

    monkeypatch.setattr(daemon, "is_running", fake_is_running)
    monkeypatch.setattr(daemon.subprocess, "Popen", FakeProc)

    msg = daemon.start(repo_root, interval=0.1)
    assert "Daemon started" in msg or "Daemon starting" in msg
    assert calls
    assert (repo_root / ".securegitx" / "cache").is_dir()
    assert (repo_root / ".securegitx" / "logs").is_dir()


def test_stop_when_no_daemon_running(repo_root: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(daemon, "_read_pid", lambda root: None)
    monkeypatch.setattr(daemon, "is_running", lambda root: False)
    assert daemon.stop(repo_root) == "No daemon running"


def test_stop_running_daemon(repo_root: Path, monkeypatch: pytest.MonkeyPatch):
    daemon._ensure_dirs(repo_root)
    daemon._write_pid(repo_root)

    calls: list[tuple[int, int]] = []

    def fake_kill(pid, sig):
        calls.append((pid, sig))

    running = iter([True, False])

    monkeypatch.setattr(daemon, "_read_pid", lambda root: 2468)
    monkeypatch.setattr(daemon, "is_running", lambda root: next(running))
    monkeypatch.setattr(daemon.os, "kill", fake_kill)
    monkeypatch.setattr(daemon.time, "sleep", lambda x: None)

    msg = daemon.stop(repo_root)
    assert "Daemon stopped" in msg
    assert calls
    assert not daemon._pid_path(repo_root).exists()


def test_status_not_running(repo_root: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(daemon, "is_running", lambda root: False)
    monkeypatch.setattr(daemon, "_read_pid", lambda root: None)
    assert daemon.status(repo_root) == "Daemon: not running"


def test_status_reports_cache_and_suggestions(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
):
    daemon._ensure_dirs(repo_root)
    daemon._pid_path(repo_root).write_text("555", encoding="utf-8")

    cache = {
        "timestamp": daemon.time.time() - 10,
        "staged_count": 2,
        "finding_count": 1,
        "clean": False,
        "staged_files": ["a.txt", "b.txt"],
        "findings": [make_finding().as_dict()],
    }
    daemon._cache_path(repo_root).write_text(json.dumps(cache), encoding="utf-8")
    daemon._suggestions_path(repo_root).write_text(
        json.dumps(["secrets/"]), encoding="utf-8"
    )

    monkeypatch.setattr(daemon, "is_running", lambda root: True)
    monkeypatch.setattr(daemon, "_read_pid", lambda root: 555)

    output = daemon.status(repo_root)
    assert "running" in output
    assert "Last scan" in output
    assert "Findings: 1" in output
    assert "Pending .gitignore suggestions: 1" in output


def test_read_suggestions_handles_invalid_json(repo_root: Path):
    daemon._ensure_dirs(repo_root)
    daemon._suggestions_path(repo_root).write_text("{not valid json", encoding="utf-8")
    assert daemon.read_suggestions(repo_root) == []


def test_queue_suggestion_deduplicates(repo_root: Path):
    daemon._ensure_dirs(repo_root)

    d = daemon.SecureGitXDaemon(repo_root)
    d._queue_suggestion("secrets.env")

    data = json.loads(daemon._suggestions_path(repo_root).read_text(encoding="utf-8"))
    assert data == ["secrets.env"]


def test_write_cache_records_findings(repo_root: Path):
    daemon._ensure_dirs(repo_root)
    findings = [make_finding()]
    daemon.SecureGitXDaemon(repo_root)._write_cache(["a.txt"], findings)

    cache = json.loads(daemon._cache_path(repo_root).read_text(encoding="utf-8"))
    assert cache["staged_count"] == 1
    assert cache["finding_count"] == 1
    assert cache["clean"] is False
    assert cache["staged_files"] == ["a.txt"]
    assert len(cache["findings"]) == 1


def test_run_scan_writes_cache(repo_root: Path, monkeypatch: pytest.MonkeyPatch):
    d = daemon.SecureGitXDaemon(repo_root)

    class FakeConfig:
        entropy_threshold = 4.5

    monkeypatch.setattr("securegitx.config.load_config", lambda cwd=None: FakeConfig())
    monkeypatch.setattr("securegitx.rules.load_rules", lambda: ["rules"])
    monkeypatch.setattr("securegitx.rules.load_allowlist", lambda: ["allow"])
    monkeypatch.setattr("securegitx.gitops.staged_files", lambda cwd=None: ["a.txt"])
    monkeypatch.setattr("securegitx.gitops.staged_diff", lambda cwd=None: "diff")
    monkeypatch.setattr(
        "securegitx.scanner.scan_filenames",
        lambda staged, rules, allowlist: [
            make_finding(file="a.txt", matched_text="id_rsa")
        ],
    )
    monkeypatch.setattr(
        "securegitx.scanner.scan_diff",
        lambda diff, rules, allowlist, threshold: [
            make_finding(file="a.txt", matched_text="secret")
        ],
    )

    d._run_scan()

    cache = json.loads(daemon._cache_path(repo_root).read_text(encoding="utf-8"))
    assert cache["staged_count"] == 1
    assert cache["finding_count"] == 2
    assert cache["clean"] is False


def test_check_untracked_sensitive_queues_suggestion(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
):
    d = daemon.SecureGitXDaemon(repo_root)

    monkeypatch.setattr(
        daemon.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="secrets/api.key\n", returncode=0
        ),
    )
    monkeypatch.setattr("securegitx.rules.load_rules", lambda: ["rules"])
    monkeypatch.setattr("securegitx.rules.load_allowlist", lambda: ["allow"])
    monkeypatch.setattr(
        "securegitx.scanner.scan_filenames",
        lambda untracked, rules, allowlist: [
            make_finding(file="secrets/api.key", rule_id="SGX104")
        ],
    )

    d._check_untracked_sensitive()

    suggestions = json.loads(
        daemon._suggestions_path(repo_root).read_text(encoding="utf-8")
    )
    assert suggestions == ["secrets/api.key"]


def test_apply_suggestions_calls_gitignore_build(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
):
    daemon._ensure_dirs(repo_root)
    daemon._suggestions_path(repo_root).write_text(
        json.dumps(["secrets.env"]), encoding="utf-8"
    )

    called = {}

    def fake_ensure_gitignore(root, project_type, extra_entries=None):
        called["root"] = root
        called["project_type"] = project_type
        called["extra_entries"] = extra_entries
        return "updated"

    monkeypatch.setattr(
        "securegitx.gitignore_build.ensure_gitignore", fake_ensure_gitignore
    )

    msg = daemon.apply_suggestions(repo_root, "python")
    assert "applied" in msg
    assert called["root"] == repo_root
    assert called["project_type"] == "python"
    assert called["extra_entries"] == ["secrets.env"]
    assert daemon._suggestions_path(repo_root).read_text(encoding="utf-8") == "[]"
