"""
Hook installation and removal.
Manages .git/hooks/pre-commit only. No scanning logic.
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

_MARKER = "# managed-by: securegitx"

_HOOK_TEMPLATE = """\
#!/usr/bin/env sh
{marker}
# Installed: {timestamp}
# Remove with: securegitx hook uninstall

securegitx scan --staged
exit $?
"""


class HookError(Exception):
    pass


def _hooks_dir(repo_root: Path) -> Path:
    return repo_root / ".git" / "hooks"


def _hook_path(repo_root: Path) -> Path:
    return _hooks_dir(repo_root) / "pre-commit"


def _is_managed(hook: Path) -> bool:
    try:
        return _MARKER in hook.read_text()
    except OSError:
        return False


def install(repo_root: Path, force: bool = False, dry_run: bool = False) -> str:
    """
    Install the pre-commit hook.
    Returns a message describing what happened.
    """
    hooks_dir = _hooks_dir(repo_root)
    if not hooks_dir.exists():
        raise HookError(f"Hooks directory not found: {hooks_dir}")

    hook = _hook_path(repo_root)

    if hook.exists():
        if _is_managed(hook):
            return "Hook already installed and managed by SecureGitX — no change"
        # Back up the existing unmanaged hook
        backup = hook.with_suffix(f".backup.{_timestamp()}")
        if not dry_run:
            shutil.copy2(hook, backup)
        msg = f"Backed up existing hook to {backup.name}"
    else:
        msg = "No existing hook"

    content = _HOOK_TEMPLATE.format(marker=_MARKER, timestamp=_iso_now())
    if not dry_run:
        hook.write_text(content)
        hook.chmod(0o755)

    action = "[dry-run] would install" if dry_run else "Installed"
    return f"{msg}\n{action} SecureGitX pre-commit hook at {hook}"


def uninstall(repo_root: Path, dry_run: bool = False) -> str:
    hook = _hook_path(repo_root)

    if not hook.exists():
        return "No pre-commit hook found — nothing to remove"

    if not _is_managed(hook):
        raise HookError(
            "Pre-commit hook exists but was not installed by SecureGitX.\n"
            "Remove it manually or use --force."
        )

    # Restore backup if present, else delete
    backups = sorted(_hooks_dir(repo_root).glob("pre-commit.backup.*"))
    if backups:
        latest = backups[-1]
        if not dry_run:
            shutil.copy2(latest, hook)
            latest.unlink()
        action = "[dry-run] would restore" if dry_run else "Restored"
        return f"{action} previous hook from {latest.name}"
    else:
        if not dry_run:
            hook.unlink()
        action = "[dry-run] would remove" if dry_run else "Removed"
        return f"{action} SecureGitX pre-commit hook"


def status(repo_root: Path) -> str:
    hook = _hook_path(repo_root)
    if not hook.exists():
        return "not installed"
    if _is_managed(hook):
        return "installed (managed)"
    return "installed (unmanaged — not by SecureGitX)"


def _timestamp() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _iso_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")