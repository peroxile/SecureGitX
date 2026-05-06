"""Tests for config.py."""
import os
import tempfile
from pathlib import Path

import pytest

from securegitx.config import load_config, Config, ConfigError


def _write_toml(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def test_defaults_when_no_file():
    cfg = load_config(explicit_path=None, cwd=Path("/tmp"))
    assert isinstance(cfg, Config)
    assert cfg.entropy_threshold == 4.5
    assert cfg.fail_on == "high"


def test_explicit_config_loaded():
    p = _write_toml('entropy_threshold = 3.5\nfail_on = "critical"\n')
    try:
        cfg = load_config(explicit_path=p)
        assert cfg.entropy_threshold == 3.5
        assert cfg.fail_on == "critical"
    finally:
        p.unlink()


def test_missing_explicit_config_raises():
    with pytest.raises(ConfigError, match="not found"):
        load_config(explicit_path=Path("/nonexistent/config.toml"))


def test_unknown_key_does_not_raise(capsys):
    p = _write_toml('unknown_key = "value"\n')
    try:
        cfg = load_config(explicit_path=p)  # should not raise
        out = capsys.readouterr().out
        assert "unknown_key" in out
    finally:
        p.unlink()


def test_wrong_type_raises():
    p = _write_toml("entropy_threshold = \"not_a_float\"\n")
    try:
        with pytest.raises(ConfigError, match="expects float"):
            load_config(explicit_path=p)
    finally:
        p.unlink()


def test_env_override(monkeypatch):
    monkeypatch.setenv("SGX_FAIL_ON", "critical")
    monkeypatch.setenv("SGX_FORMAT", "json")
    cfg = load_config(explicit_path=None, cwd=Path("/tmp"))
    assert cfg.fail_on == "critical"
    assert cfg.format == "json"


def test_env_bad_value_raises(monkeypatch):
    monkeypatch.setenv("SGX_ENTROPY_THRESHOLD", "not_a_number")
    with pytest.raises(ConfigError):
        load_config(explicit_path=None, cwd=Path("/tmp"))