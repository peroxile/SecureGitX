"""
Config loading — merges defaults, file config, and environment overrides.
Never executes code from config.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-reuse-defined]


CONFIG_FILENAME = ".securegitx.toml"

_ALLOWED_KEYS = {
    "enforce_safe_email",
    "auto_gitignore",
    "entropy_threshold",
    "exclude_dirs",
    "rules_path",
    "allowlist_path",
    "log_level",
    "format",
    "fail_on",
}


@dataclass
class Config:
    enforce_safe_email: bool = True
    auto_gitignore: bool = True
    entropy_threshold: float = 4.5
    exclude_dirs: list[str] = field(default_factory=lambda: [
        ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
    ])
    rules_path: str = ""       # empty = use bundled rules
    allowlist_path: str = ""   # empty = use bundled allowlist
    log_level: str = "info"
    format: str = "text"       # "text" | "json"
    fail_on: str = "high"      # "low" | "medium" | "high" | "critical"


class ConfigError(Exception):
    pass


def _find_config_file(start: Path) -> Path | None:
    """Walk up from `start` looking for .securegitx.toml."""
    current = start.resolve()
    for parent in [current, *current.parents]:
        candidate = parent / CONFIG_FILENAME
        if candidate.exists():
            return candidate
    return None


def _load_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text())
    except Exception as e:
        raise ConfigError(f"Failed to parse config at {path}: {e}")


def _apply_dict(config: Config, data: dict, source: str) -> None:
    """Apply a flat dict onto a Config, warning on unknown keys."""
    for key, value in data.items():
        if key not in _ALLOWED_KEYS:
            # Warn but don't abort — unknown keys are ignored
            print(f"[securegitx] Warning: unknown config key '{key}' in {source}", flush=True)
            continue
        if not hasattr(config, key):
            continue
        expected = type(getattr(config, key))
        if not isinstance(value, expected):
            raise ConfigError(
                f"Config key '{key}' expects {expected.__name__}, got {type(value).__name__}"
            )
        setattr(config, key, value)


def _apply_env(config: Config) -> None:
    """Override config from SGX_* environment variables."""
    mapping = {
        "SGX_ENTROPY_THRESHOLD": ("entropy_threshold", float),
        "SGX_LOG_LEVEL":         ("log_level", str),
        "SGX_FORMAT":            ("format", str),
        "SGX_FAIL_ON":           ("fail_on", str),
        "SGX_RULES_PATH":        ("rules_path", str),
        "SGX_ALLOWLIST_PATH":    ("allowlist_path", str),
    }
    for env_key, (attr, cast) in mapping.items():
        val = os.environ.get(env_key)
        if val is not None:
            try:
                setattr(config, attr, cast(val))
            except (ValueError, TypeError) as e:
                raise ConfigError(f"Invalid env var {env_key}={val!r}: {e}")


def load_config(
    explicit_path: Path | None = None,
    cwd: Path | None = None,
) -> Config:
    """
    Load config in priority order:
      1. explicit --config path
      2. repo-local .securegitx.toml (walked up from cwd)
      3. built-in defaults
    Then overlay SGX_* env vars.
    """
    config = Config()

    if explicit_path is not None:
        if not explicit_path.exists():
            raise ConfigError(f"Config file not found: {explicit_path}")
        data = _load_toml(explicit_path)
        _apply_dict(config, data, str(explicit_path))
    else:
        search_root = cwd or Path.cwd()
        found = _find_config_file(search_root)
        if found:
            data = _load_toml(found)
            _apply_dict(config, data, str(found))

    _apply_env(config)
    return config