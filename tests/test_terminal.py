from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

import securegitx.terminal as terminal


class FakeShutil:
    def __init__(self, func):
        self.get_terminal_size = func


def reload_terminal(monkeypatch: pytest.MonkeyPatch, tty: bool, lang: str = ""):
    monkeypatch.setattr(terminal.sys.stdout, "isatty", lambda: tty, raising=False)
    monkeypatch.setenv("LANG", lang)
    monkeypatch.delenv("LC_ALL", raising=False)
    return importlib.reload(terminal)


def test_non_tty_uses_ascii(monkeypatch: pytest.MonkeyPatch):
    mod = reload_terminal(monkeypatch, tty=False, lang="en_US.UTF-8")

    assert mod.OK == "[OK]"
    assert mod.WARN == "[WARN]"
    assert mod.ERR == "[ERR]"
    assert mod.INFO == "[INFO]"
    assert mod.STEP == ">"
    assert mod.RED == ""
    assert mod.NC == ""


def test_unicode_tty_uses_unicode_symbols(monkeypatch: pytest.MonkeyPatch):
    mod = reload_terminal(monkeypatch, tty=True, lang="en_US.UTF-8")

    assert mod.OK == "✓"
    assert mod.WARN == "⚠"
    assert mod.ERR == "✗"
    assert mod.INFO == "ℹ"
    assert mod.STEP == "▶"
    assert mod.RED != ""
    assert mod.NC != ""


def test_separator_prints_line(capsys):
    terminal.separator()
    out = capsys.readouterr().out
    assert terminal.SEP in out


def test_log_success_writes_stdout(capsys):
    terminal.log_success("done")
    out = capsys.readouterr().out
    assert "done" in out


def test_log_info_writes_stdout(capsys):
    terminal.log_info("hello")
    out = capsys.readouterr().out
    assert "hello" in out


def test_log_warning_writes_stdout(capsys):
    terminal.log_warning("warn")
    out = capsys.readouterr().out
    assert "warn" in out


def test_log_error_writes_stderr(capsys):
    terminal.log_error("bad")
    err = capsys.readouterr().err
    assert "bad" in err


def test_log_step_writes_stdout(capsys):
    terminal.log_step("step")
    out = capsys.readouterr().out
    assert "step" in out


def test_term_width_uses_fallback_on_error(monkeypatch: pytest.MonkeyPatch):
    def raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(terminal, "shutil", FakeShutil(raise_error))
    assert terminal._term_width() == 80


def test_term_width_uses_terminal_size(monkeypatch: pytest.MonkeyPatch):
    def fake_get_terminal_size(*_args, **_kwargs):
        return SimpleNamespace(columns=120)

    monkeypatch.setattr(terminal, "shutil", FakeShutil(fake_get_terminal_size))
    assert terminal._term_width() == 120


def test_show_banner_non_tty_is_noop(monkeypatch: pytest.MonkeyPatch, capsys):
    mod = reload_terminal(monkeypatch, tty=False, lang="en_US.UTF-8")
    mod.show_banner("v1.2.0")
    out = capsys.readouterr().out
    assert out == ""


def test_show_banner_unicode_full(monkeypatch: pytest.MonkeyPatch, capsys):
    mod = reload_terminal(monkeypatch, tty=True, lang="en_US.UTF-8")
    monkeypatch.setattr(
        mod,
        "shutil",
        FakeShutil(lambda *_args, **_kwargs: SimpleNamespace(columns=100)),
    )

    mod.show_banner("v1.2.0")
    out = capsys.readouterr().out

    assert "SecureGitX" in out
    assert "Auth" in out
    assert "Scan" in out
    assert "Secure Commit" in out
    assert "██████" in out
    assert "███████╗███████╗" in out


def test_show_banner_unicode_boundary_uses_compact(
    monkeypatch: pytest.MonkeyPatch, capsys
):
    mod = reload_terminal(monkeypatch, tty=True, lang="en_US.UTF-8")
    monkeypatch.setattr(
        mod,
        "shutil",
        FakeShutil(lambda *_args, **_kwargs: SimpleNamespace(columns=79)),
    )

    mod.show_banner("v1.2.0")
    out = capsys.readouterr().out

    assert "SecureGitX" in out
    assert "Auth" in out
    assert "Scan" in out
    assert "Secure Commit" in out
    assert "███████╗ ██████╗" in out
    assert "███████╗███████╗" not in out
