"""Tests for securegitx.cli."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from securegitx.cli import (
    EXIT_BLOCKED,
    EXIT_CLEAN,
    EXIT_GIT,
    EXIT_RULES,
    EXIT_USAGE,
    _build_parser,
    _cmd_commit,
    _cmd_hook,
    _cmd_init,
    _cmd_rules,
    _cmd_scan,
    _git_branch,
    _git_cfg,
    _show_auth_phase,
    main,
)

# Helpers


def _scan_args(**kwargs) -> argparse.Namespace:
    defaults = dict(
        config=None, format=None, fail_on=None, quiet=False, staged=False, tracked=False
    )
    return argparse.Namespace(**{**defaults, **kwargs})


def _hook_args(cmd: str | None = None, force: bool = False, dry_run: bool = False):
    return argparse.Namespace(hook_command=cmd, force=force, dry_run=dry_run)


def _init_args(no_gitignore: bool = False) -> argparse.Namespace:
    return argparse.Namespace(no_gitignore=no_gitignore)


def _rules_args(cmd: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(rules_command=cmd)


def _mock_config(format="text", fail_on="high", entropy_threshold=4.5) -> MagicMock:
    cfg = MagicMock()
    cfg.format = format
    cfg.fail_on = fail_on
    cfg.entropy_threshold = entropy_threshold
    return cfg


# Silence all terminal output in tests
@pytest.fixture(autouse=True)
def silence_terminal(monkeypatch):
    monkeypatch.setattr("securegitx.cli.T", MagicMock())


# _git_cfg


def test_git_cfg_returns_value():
    with patch("subprocess.check_output", return_value="main\n"):
        assert _git_cfg("user.name") == "main"


def test_git_cfg_returns_empty_on_error():
    with patch(
        "subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "git")
    ):
        assert _git_cfg("user.name") == ""


# _git_branch


def test_git_branch_returns_branch():
    with patch("subprocess.check_output", return_value="main\n"):
        assert _git_branch() == "main"


def test_git_branch_returns_detached_head_on_empty():
    with patch("subprocess.check_output", return_value=""):
        assert _git_branch() == "detached HEAD"


def test_git_branch_returns_unknown_on_error():
    with patch(
        "subprocess.check_output", side_effect=subprocess.CalledProcessError(1, "git")
    ):
        assert _git_branch() == "unknown"


# _show_auth_phase


def test_show_auth_phase_with_full_identity():
    with (
        patch(
            "securegitx.cli._git_cfg",
            side_effect=["Alice", "alice@users.noreply.github.com"],
        ),
        patch("securegitx.cli._git_branch", return_value="main"),
    ):
        _show_auth_phase()  # must not raise


def test_show_auth_phase_missing_name():
    with (
        patch("securegitx.cli._git_cfg", side_effect=["", "alice@example.com"]),
        patch("securegitx.cli._git_branch", return_value="main"),
    ):
        _show_auth_phase()


def test_show_auth_phase_missing_email():
    with (
        patch("securegitx.cli._git_cfg", side_effect=["Alice", ""]),
        patch("securegitx.cli._git_branch", return_value="main"),
    ):
        _show_auth_phase()


def test_show_auth_phase_detached_head():
    with (
        patch("securegitx.cli._git_cfg", side_effect=["Alice", "alice@example.com"]),
        patch("securegitx.cli._git_branch", return_value="detached HEAD"),
    ):
        _show_auth_phase()


def test_show_auth_phase_non_noreply_email():
    with (
        patch("securegitx.cli._git_cfg", side_effect=["Alice", "alice@company.com"]),
        patch("securegitx.cli._git_branch", return_value="main"),
    ):
        _show_auth_phase()


# _build_parser


def test_build_parser_scan_subcommand():
    parser = _build_parser()
    args = parser.parse_args(["scan", "--staged"])
    assert args.command == "scan"
    assert args.staged is True


def test_build_parser_scan_tracked():
    parser = _build_parser()
    args = parser.parse_args(["scan", "--tracked"])
    assert args.tracked is True


def test_build_parser_hook_install():
    parser = _build_parser()
    args = parser.parse_args(["hook", "install"])
    assert args.command == "hook"
    assert args.hook_command == "install"


def test_build_parser_hook_install_force():
    parser = _build_parser()
    args = parser.parse_args(["hook", "install", "--force"])
    assert args.force is True


def test_build_parser_hook_status():
    parser = _build_parser()
    args = parser.parse_args(["hook", "status"])
    assert args.hook_command == "status"


def test_build_parser_init():
    parser = _build_parser()
    args = parser.parse_args(["init"])
    assert args.command == "init"
    assert args.no_gitignore is False


def test_build_parser_init_no_gitignore():
    parser = _build_parser()
    args = parser.parse_args(["init", "--no-gitignore"])
    assert args.no_gitignore is True


def test_build_parser_rules_validate():
    parser = _build_parser()
    args = parser.parse_args(["rules", "validate"])
    assert args.command == "rules"
    assert args.rules_command == "validate"


def test_build_parser_scan_format_json():
    parser = _build_parser()
    args = parser.parse_args(["scan", "--format", "json"])
    assert args.format == "json"


def test_build_parser_scan_quiet():
    parser = _build_parser()
    args = parser.parse_args(["scan", "--quiet"])
    assert args.quiet is True


# _cmd_scan


def test_cmd_scan_config_error():
    from securegitx.config import ConfigError

    with patch("securegitx.config.load_config", side_effect=ConfigError("bad")):
        result = _cmd_scan(_scan_args())
    assert result == EXIT_USAGE


def test_cmd_scan_rules_error():
    from securegitx.rules import RuleLoadError

    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", side_effect=RuleLoadError("bad")),
    ):
        result = _cmd_scan(_scan_args())
    assert result == EXIT_RULES


def test_cmd_scan_not_git_repo():
    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=False),
    ):
        result = _cmd_scan(_scan_args())
    assert result == EXIT_GIT


def test_cmd_scan_staged_no_files():
    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=[]),
    ):
        result = _cmd_scan(_scan_args(quiet=True))
    assert result == EXIT_CLEAN


def test_cmd_scan_staged_no_findings():
    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=["src/main.py"]),
        patch("securegitx.gitops.staged_diff", return_value=""),
        patch("securegitx.scanner.scan_filenames", return_value=[]),
        patch("securegitx.scanner.scan_diff", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=False),
        patch("securegitx.report.format_text"),
    ):
        result = _cmd_scan(_scan_args(quiet=True))
    assert result == EXIT_CLEAN


def test_cmd_scan_staged_blocked():
    finding = MagicMock()
    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=["src/main.py"]),
        patch("securegitx.gitops.staged_diff", return_value=""),
        patch("securegitx.scanner.scan_filenames", return_value=[finding]),
        patch("securegitx.scanner.scan_diff", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=True),
        patch("securegitx.report.format_text"),
    ):
        result = _cmd_scan(_scan_args(quiet=True))
    assert result == EXIT_BLOCKED


def test_cmd_scan_json_format():
    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=["src/main.py"]),
        patch("securegitx.gitops.staged_diff", return_value=""),
        patch("securegitx.scanner.scan_filenames", return_value=[]),
        patch("securegitx.scanner.scan_diff", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=False),
        patch("securegitx.report.format_json") as mock_json,
    ):
        result = _cmd_scan(_scan_args(format="json"))
    assert result == EXIT_CLEAN
    mock_json.assert_called_once()


def test_cmd_scan_tracked_mode():
    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.tracked_files", return_value=["README.md"]),
        patch("securegitx.gitops.read_tracked_file", return_value="content"),
        patch("securegitx.scanner.scan_filenames", return_value=[]),
        patch("securegitx.scanner.scan_file_content", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=False),
        patch("securegitx.report.format_text"),
    ):
        result = _cmd_scan(_scan_args(tracked=True, quiet=True))
    assert result == EXIT_CLEAN


def test_cmd_scan_tracked_read_error_skipped():
    from securegitx.gitops import GitError

    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.tracked_files", return_value=["f.py"]),
        patch("securegitx.gitops.read_tracked_file", side_effect=GitError("gone")),
        patch("securegitx.scanner.scan_filenames", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=False),
        patch("securegitx.report.format_text"),
    ):
        result = _cmd_scan(_scan_args(tracked=True, quiet=True))
    assert result == EXIT_CLEAN


def test_cmd_scan_git_error_propagates():
    from securegitx.gitops import GitError

    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", side_effect=GitError("oops")),
    ):
        result = _cmd_scan(_scan_args(quiet=True))
    assert result == EXIT_GIT


def test_cmd_scan_staged_no_files_not_quiet_prints():
    with (
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=[]),
        patch("builtins.print") as mock_print,
    ):
        result = _cmd_scan(_scan_args(format="json"))  # json → not verbose, not quiet
    assert result == EXIT_CLEAN


# _cmd_commit


def test_cmd_commit_config_error():
    from securegitx.config import ConfigError

    with (
        patch("securegitx.cli._git_cfg", return_value=""),
        patch("securegitx.cli._git_branch", return_value="main"),
        patch("securegitx.config.load_config", side_effect=ConfigError("bad")),
    ):
        result = _cmd_commit("feat: test")
    assert result == EXIT_USAGE


def test_cmd_commit_rules_error():
    from securegitx.rules import RuleLoadError

    with (
        patch("securegitx.cli._git_cfg", return_value=""),
        patch("securegitx.cli._git_branch", return_value="main"),
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", side_effect=RuleLoadError("bad")),
    ):
        result = _cmd_commit("feat: test")
    assert result == EXIT_RULES


def test_cmd_commit_not_git_repo():
    with (
        patch("securegitx.cli._git_cfg", return_value=""),
        patch("securegitx.cli._git_branch", return_value="main"),
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=False),
    ):
        result = _cmd_commit("feat: test")
    assert result == EXIT_GIT


def test_cmd_commit_no_staged_files():
    with (
        patch("securegitx.cli._git_cfg", return_value=""),
        patch("securegitx.cli._git_branch", return_value="main"),
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=[]),
    ):
        result = _cmd_commit("feat: test")
    assert result == EXIT_CLEAN


def test_cmd_commit_blocked():
    finding = MagicMock()
    with (
        patch("securegitx.cli._git_cfg", return_value=""),
        patch("securegitx.cli._git_branch", return_value="main"),
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=["f.py"]),
        patch("securegitx.gitops.staged_diff", return_value=""),
        patch("securegitx.scanner.scan_filenames", return_value=[finding]),
        patch("securegitx.scanner.scan_diff", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=True),
        patch("securegitx.report.format_text"),
    ):
        result = _cmd_commit("feat: test")
    assert result == EXIT_BLOCKED


def test_cmd_commit_success():
    with (
        patch("securegitx.cli._git_cfg", return_value="Alice"),
        patch("securegitx.cli._git_branch", return_value="main"),
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=["f.py"]),
        patch("securegitx.gitops.staged_diff", return_value=""),
        patch("securegitx.scanner.scan_filenames", return_value=[]),
        patch("securegitx.scanner.scan_diff", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=False),
        patch("securegitx.report.format_text"),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0)
        result = _cmd_commit("feat: add feature")
    assert result == EXIT_CLEAN


def test_cmd_commit_git_commit_fails():
    with (
        patch("securegitx.cli._git_cfg", return_value="Alice"),
        patch("securegitx.cli._git_branch", return_value="main"),
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=["f.py"]),
        patch("securegitx.gitops.staged_diff", return_value=""),
        patch("securegitx.scanner.scan_filenames", return_value=[]),
        patch("securegitx.scanner.scan_diff", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=False),
        patch("securegitx.report.format_text"),
        patch(
            "subprocess.run", side_effect=subprocess.CalledProcessError(1, "git commit")
        ),
    ):
        result = _cmd_commit("feat: add feature")
    assert result == EXIT_GIT


def test_cmd_commit_low_findings_not_blocked():
    finding = MagicMock()
    with (
        patch("securegitx.cli._git_cfg", return_value="Alice"),
        patch("securegitx.cli._git_branch", return_value="main"),
        patch("securegitx.config.load_config", return_value=_mock_config()),
        patch("securegitx.rules.load_rules", return_value=[]),
        patch("securegitx.rules.load_allowlist", return_value=[]),
        patch("securegitx.gitops.is_git_repo", return_value=True),
        patch("securegitx.gitops.staged_files", return_value=["f.py"]),
        patch("securegitx.gitops.staged_diff", return_value=""),
        patch("securegitx.scanner.scan_filenames", return_value=[finding]),
        patch("securegitx.scanner.scan_diff", return_value=[]),
        patch("securegitx.report.exceeds_threshold", return_value=False),
        patch("securegitx.report.format_text") as mock_fmt,
        patch("subprocess.run"),
    ):
        result = _cmd_commit("feat: add feature")
    assert result == EXIT_CLEAN
    mock_fmt.assert_called_once()  # prints findings even when not blocked


# _cmd_hook


def test_cmd_hook_install():
    with (
        patch("securegitx.gitops.repo_root", return_value=Path("/repo")),
        patch("securegitx.hooks.install", return_value="Hook installed"),
    ):
        result = _cmd_hook(_hook_args("install"))
    assert result == EXIT_CLEAN


def test_cmd_hook_install_hook_error():
    from securegitx.hooks import HookError

    with (
        patch("securegitx.gitops.repo_root", return_value=Path("/repo")),
        patch("securegitx.hooks.install", side_effect=HookError("already exists")),
    ):
        result = _cmd_hook(_hook_args("install"))
    assert result == EXIT_USAGE


def test_cmd_hook_uninstall():
    with (
        patch("securegitx.gitops.repo_root", return_value=Path("/repo")),
        patch("securegitx.hooks.uninstall", return_value="Hook removed"),
    ):
        result = _cmd_hook(_hook_args("uninstall"))
    assert result == EXIT_CLEAN


def test_cmd_hook_uninstall_hook_error():
    from securegitx.hooks import HookError

    with (
        patch("securegitx.gitops.repo_root", return_value=Path("/repo")),
        patch("securegitx.hooks.uninstall", side_effect=HookError("not managed")),
    ):
        result = _cmd_hook(_hook_args("uninstall"))
    assert result == EXIT_USAGE


def test_cmd_hook_status():
    with (
        patch("securegitx.gitops.repo_root", return_value=Path("/repo")),
        patch("securegitx.hooks.status", return_value="Managed"),
    ):
        result = _cmd_hook(_hook_args("status"))
    assert result == EXIT_CLEAN


def test_cmd_hook_no_subcommand():
    with patch("securegitx.gitops.repo_root", return_value=Path("/repo")):
        result = _cmd_hook(_hook_args(None))
    assert result == EXIT_USAGE


def test_cmd_hook_git_error():
    from securegitx.gitops import GitError

    with patch("securegitx.gitops.repo_root", side_effect=GitError("not a repo")):
        result = _cmd_hook(_hook_args("install"))
    assert result == EXIT_GIT


# _cmd_init


def test_cmd_init_creates_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = _cmd_init(_init_args())
    assert result == EXIT_CLEAN
    assert (tmp_path / ".securegitx.toml").exists()


def test_cmd_init_config_already_exists(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".securegitx.toml").write_text("existing = true\n")
    result = _cmd_init(_init_args())
    assert result == EXIT_CLEAN
    assert (tmp_path / ".securegitx.toml").read_text() == "existing = true\n"


def test_cmd_init_creates_gitignore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = _cmd_init(_init_args())
    assert result == EXIT_CLEAN
    assert (tmp_path / ".gitignore").exists()
    assert ".securegitx.toml" in (tmp_path / ".gitignore").read_text()


def test_cmd_init_no_gitignore_flag(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = _cmd_init(_init_args(no_gitignore=True))
    assert result == EXIT_CLEAN
    assert not (tmp_path / ".gitignore").exists()


def test_cmd_init_appends_to_existing_gitignore(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitignore").write_text("__pycache__/\n")
    result = _cmd_init(_init_args())
    assert result == EXIT_CLEAN
    content = (tmp_path / ".gitignore").read_text()
    assert ".securegitx.toml" in content
    assert "__pycache__/" in content


def test_cmd_init_does_not_duplicate_gitignore_entry(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitignore").write_text(".securegitx.toml\n")
    _cmd_init(_init_args())
    content = (tmp_path / ".gitignore").read_text()
    assert content.count(".securegitx.toml") == 1


def test_cmd_init_config_content(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _cmd_init(_init_args())
    content = (tmp_path / ".securegitx.toml").read_text()
    assert "entropy_threshold" in content
    assert "fail_on" in content
    assert "format" in content


# _cmd_rules


def test_cmd_rules_validate():
    rule = MagicMock()
    with patch("securegitx.rules.load_rules", return_value=[rule, rule]):
        result = _cmd_rules(_rules_args("validate"))
    assert result == EXIT_CLEAN


def test_cmd_rules_list(capsys):
    rule = MagicMock()
    rule.id = "T001"
    rule.severity = "high"
    rule.type = "content"
    rule.name = "test_rule"
    with patch("securegitx.rules.load_rules", return_value=[rule]):
        result = _cmd_rules(_rules_args("list"))
    assert result == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "T001" in out
    assert "high" in out


def test_cmd_rules_no_subcommand():
    with patch("securegitx.rules.load_rules", return_value=[]):
        result = _cmd_rules(_rules_args(None))
    assert result == EXIT_USAGE


def test_cmd_rules_load_error():
    from securegitx.rules import RuleLoadError

    with patch("securegitx.rules.load_rules", side_effect=RuleLoadError("bad")):
        result = _cmd_rules(_rules_args("validate"))
    assert result == EXIT_RULES


# main


def test_main_no_args_exits_usage():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == EXIT_USAGE


def test_main_routes_scan():
    with (
        patch("securegitx.cli._cmd_scan", return_value=EXIT_CLEAN) as mock_scan,
        pytest.raises(SystemExit),
    ):
        main(["scan", "--quiet"])
    mock_scan.assert_called_once()


def test_main_routes_hook():
    with (
        patch("securegitx.cli._cmd_hook", return_value=EXIT_CLEAN) as mock_hook,
        pytest.raises(SystemExit),
    ):
        main(["hook", "status"])
    mock_hook.assert_called_once()


def test_main_routes_init():
    with (
        patch("securegitx.cli._cmd_init", return_value=EXIT_CLEAN) as mock_init,
        pytest.raises(SystemExit),
    ):
        main(["init"])
    mock_init.assert_called_once()


def test_main_routes_rules():
    with (
        patch("securegitx.cli._cmd_rules", return_value=EXIT_CLEAN) as mock_rules,
        pytest.raises(SystemExit),
    ):
        main(["rules", "validate"])
    mock_rules.assert_called_once()


def test_main_bare_commit_message():
    with (
        patch("securegitx.cli._cmd_commit", return_value=EXIT_CLEAN) as mock_commit,
        pytest.raises(SystemExit),
    ):
        main(["feat: add feature"])
    mock_commit.assert_called_once_with("feat: add feature")


def test_main_bare_commit_multiword():
    with (
        patch("securegitx.cli._cmd_commit", return_value=EXIT_CLEAN) as mock_commit,
        pytest.raises(SystemExit),
    ):
        main(["feat:", "add", "feature"])
    mock_commit.assert_called_once_with("feat: add feature")


def test_main_exits_with_handler_return_code():
    with (
        patch("securegitx.cli._cmd_scan", return_value=EXIT_BLOCKED),
        pytest.raises(SystemExit) as exc,
    ):
        main(["scan", "--quiet"])
    assert exc.value.code == EXIT_BLOCKED
