"""Tests for hooks.py — uses a temp directory to simulate a git repo."""
import stat
from pathlib import Path

import pytest

from securegitx.hooks import install, uninstall, status, HookError, _MARKER


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """Create a minimal fake git repo structure."""
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    return tmp_path


def test_install_creates_hook(fake_repo):
    install(fake_repo)
    hook = fake_repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert _MARKER in hook.read_text()


def test_installed_hook_is_executable(fake_repo):
    install(fake_repo)
    hook = fake_repo / ".git" / "hooks" / "pre-commit"
    mode = hook.stat().st_mode
    assert mode & stat.S_IXUSR


def test_install_twice_is_idempotent(fake_repo):
    msg1 = install(fake_repo)
    msg2 = install(fake_repo)
    assert "no change" in msg2.lower() or "already" in msg2.lower()


def test_install_backs_up_existing_hook(fake_repo):
    existing = fake_repo / ".git" / "hooks" / "pre-commit"
    existing.write_text("#!/bin/sh\necho old hook\n")
    existing.chmod(0o755)
    install(fake_repo)
    backups = list((fake_repo / ".git" / "hooks").glob("pre-commit.backup.*"))
    assert len(backups) == 1
    assert "old hook" in backups[0].read_text()


def test_uninstall_removes_hook(fake_repo):
    install(fake_repo)
    uninstall(fake_repo)
    hook = fake_repo / ".git" / "hooks" / "pre-commit"
    assert not hook.exists()


def test_uninstall_restores_backup(fake_repo):
    existing = fake_repo / ".git" / "hooks" / "pre-commit"
    existing.write_text("#!/bin/sh\necho original\n")
    existing.chmod(0o755)
    install(fake_repo)
    uninstall(fake_repo)
    assert existing.exists()
    assert "original" in existing.read_text()


def test_uninstall_no_hook_returns_message(fake_repo):
    msg = uninstall(fake_repo)
    assert "nothing" in msg.lower() or "no pre-commit" in msg.lower()


def test_uninstall_unmanaged_hook_raises(fake_repo):
    hook = fake_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho third party\n")
    hook.chmod(0o755)
    with pytest.raises(HookError):
        uninstall(fake_repo)


def test_dry_run_install_does_not_create_file(fake_repo):
    install(fake_repo, dry_run=True)
    hook = fake_repo / ".git" / "hooks" / "pre-commit"
    assert not hook.exists()


def test_dry_run_uninstall_does_not_remove_file(fake_repo):
    install(fake_repo)
    uninstall(fake_repo, dry_run=True)
    hook = fake_repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()


def test_status_not_installed(fake_repo):
    assert status(fake_repo) == "not installed"


def test_status_managed(fake_repo):
    install(fake_repo)
    assert "managed" in status(fake_repo)


def test_status_unmanaged(fake_repo):
    hook = fake_repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho other\n")
    assert "unmanaged" in status(fake_repo)