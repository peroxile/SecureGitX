"""Tests for securegitx.rules_update."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from securegitx.rules_update import (
    DEFAULT_SOURCE_URL,
    UpdateError,
    UpdateResult,
    _is_newer,
    _parse_version,
    _validate_entries,
    check,
    rollback,
    rule_version,
    update,
)

# Fixtures

_RULE_V1 = {
    "version": "1.0.0",
    "rules": [
        {
            "id": "SGX001",
            "name": "test_rule",
            "severity": "high",
            "type": "content",
            "pattern": r"\bsecret\b",
            "description": "Test rule",
            "remediation": "Remove the secret",
        }
    ],
}

_RULE_V2 = {**_RULE_V1, "version": "2.0.0"}
_RULE_V2["rules"] = _RULE_V1["rules"] + [
    {
        "id": "SGX002",
        "name": "another_rule",
        "severity": "critical",
        "type": "filename",
        "pattern": r"\.env$",
        "description": "Env file",
        "remediation": "Add to .gitignore",
    }
]


def _as_bytes(data: dict) -> bytes:
    return json.dumps(data).encode("utf-8")


def _checksum(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _patch_rules_dir(tmp_path: Path, monkeypatch):
    """Redirect _RULES_DIR and related paths to tmp_path."""
    monkeypatch.setattr("securegitx.rules_update._RULES_DIR", tmp_path)
    monkeypatch.setattr("securegitx.rules_update._RULES_FILE", tmp_path / "rules.json")
    monkeypatch.setattr(
        "securegitx.rules_update._BACKUP_FILE", tmp_path / "rules.json.bak"
    )
    monkeypatch.setattr(
        "securegitx.rules_update._META_FILE", tmp_path / "rules.json.meta"
    )


def _write_current(tmp_path: Path, data: dict = _RULE_V1) -> None:
    (tmp_path / "rules.json").write_text(json.dumps(data), encoding="utf-8")


# _parse_version


def test_parse_version_simple():
    assert _parse_version("1.2.3") == (1, 2, 3)


def test_parse_version_zero():
    assert _parse_version("0.0.0") == (0, 0, 0)


def test_parse_version_unknown():
    assert _parse_version("unknown") == (0,)


def test_parse_version_partial():
    assert _parse_version("1.2") == (1, 2)


# _is_newer


def test_is_newer_greater():
    assert _is_newer("2.0.0", "1.0.0") is True


def test_is_newer_equal():
    assert _is_newer("1.0.0", "1.0.0") is False


def test_is_newer_lesser():
    assert _is_newer("1.0.0", "2.0.0") is False


def test_is_newer_minor_bump():
    assert _is_newer("1.1.0", "1.0.0") is True


def test_is_newer_unknown_remote():
    assert _is_newer("unknown", "1.0.0") is True


def test_is_newer_both_unknown():
    assert _is_newer("unknown", "unknown") is False


# _validate_entries


def test_validate_entries_valid():
    _validate_entries(_RULE_V1["rules"], "test")  # must not raise


def test_validate_entries_missing_field():
    bad = [{"id": "X", "name": "x"}]  # missing severity, type, pattern
    with pytest.raises(UpdateError, match="missing fields"):
        _validate_entries(bad, "test")


def test_validate_entries_invalid_regex():
    bad = [
        {
            "id": "X",
            "name": "x",
            "severity": "high",
            "type": "content",
            "pattern": "[invalid",
        }
    ]
    with pytest.raises(UpdateError, match="invalid regex"):
        _validate_entries(bad, "test")


def test_validate_entries_non_dict():
    with pytest.raises(UpdateError, match="not an object"):
        _validate_entries(["not a dict"], "test")


def test_validate_entries_empty_list():
    _validate_entries([], "test")  # empty is valid


# rule_version


def test_rule_version_reads_version_field(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)
    assert rule_version() == "1.0.0"


def test_rule_version_unknown_when_missing(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    # No rules.json written
    assert rule_version() == "unknown"


def test_rule_version_unknown_when_no_version_field(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    (tmp_path / "rules.json").write_text(json.dumps({"rules": []}), encoding="utf-8")
    assert rule_version() == "unknown"


def test_rule_version_bare_array(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    (tmp_path / "rules.json").write_text(json.dumps([]), encoding="utf-8")
    assert rule_version() == "unknown"


# update — happy path


def _mock_fetch(content: bytes, checksum_url_content: bytes | None = None):
    """Return a _fetch mock that returns content, or raises for checksum URL."""

    def _fetch(url: str) -> bytes:
        if url.endswith(".sha256"):
            if checksum_url_content is None:
                raise UpdateError("No checksum file")
            return checksum_url_content
        return content

    return _fetch


def test_update_installs_newer_version(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    remote = _as_bytes(_RULE_V2)
    monkeypatch.setattr("securegitx.rules_update._fetch", _mock_fetch(remote))

    result = update(verify_checksum=False)
    assert result.previous_version == "1.0.0"
    assert result.new_version == "2.0.0"
    assert result.rule_count == 2
    assert not result.skipped


def test_update_creates_backup(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )

    update(verify_checksum=False)
    assert (tmp_path / "rules.json.bak").exists()


def test_update_writes_new_rules(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )

    update(verify_checksum=False)
    data = json.loads((tmp_path / "rules.json").read_text())
    assert data["version"] == "2.0.0"


def test_update_writes_meta(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )

    update(verify_checksum=False)
    meta = json.loads((tmp_path / "rules.json.meta").read_text())
    assert meta["version"] == "2.0.0"
    assert meta["previous_version"] == "1.0.0"
    assert meta["rule_count"] == 2
    assert "updated_at" in meta
    assert "checksum" in meta


def test_update_with_valid_checksum(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    remote = _as_bytes(_RULE_V2)
    digest = _checksum(remote)
    monkeypatch.setattr(
        "securegitx.rules_update._fetch",
        _mock_fetch(remote, checksum_url_content=digest.encode()),
    )

    result = update(verify_checksum=True)
    assert not result.skipped


# update — skip cases


def test_update_skips_same_version(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)  # 1.0.0

    monkeypatch.setattr(
        "securegitx.rules_update._fetch",
        _mock_fetch(_as_bytes(_RULE_V1)),  # same version
    )

    result = update(verify_checksum=False)
    assert result.skipped
    assert "up to date" in result.skip_reason.lower()


def test_update_skips_older_version(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V2)  # 2.0.0

    monkeypatch.setattr(
        "securegitx.rules_update._fetch",
        _mock_fetch(_as_bytes(_RULE_V1)),  # 1.0.0 — older
    )

    result = update(verify_checksum=False)
    assert result.skipped


def test_update_force_installs_older(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V2)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch",
        _mock_fetch(_as_bytes(_RULE_V1)),
    )

    result = update(verify_checksum=False, force=True)
    assert not result.skipped
    assert result.new_version == "1.0.0"


def test_update_dry_run_writes_nothing(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)
    original = (tmp_path / "rules.json").read_text()

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )

    result = update(verify_checksum=False, dry_run=True)
    assert result.skipped
    assert "dry-run" in result.skip_reason
    assert (tmp_path / "rules.json").read_text() == original
    assert not (tmp_path / "rules.json.bak").exists()


# update — error cases


def test_update_checksum_mismatch_raises(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    remote = _as_bytes(_RULE_V2)
    wrong_digest = "a" * 64  # wrong checksum
    monkeypatch.setattr(
        "securegitx.rules_update._fetch",
        _mock_fetch(remote, checksum_url_content=wrong_digest.encode()),
    )

    with pytest.raises(UpdateError, match="Checksum mismatch"):
        update(verify_checksum=True)


def test_update_invalid_json_raises(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch",
        _mock_fetch(b"{not valid json{{"),
    )

    with pytest.raises(UpdateError, match="valid JSON"):
        update(verify_checksum=False)


def test_update_invalid_rule_pattern_raises(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    bad_data = {
        "version": "9.0.0",
        "rules": [
            {
                "id": "BAD",
                "name": "bad",
                "severity": "high",
                "type": "content",
                "pattern": "[invalid",
            }
        ],
    }
    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(bad_data))
    )

    with pytest.raises(UpdateError, match="invalid regex"):
        update(verify_checksum=False)


def test_update_network_error_raises(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    def _fail(url: str) -> bytes:
        raise UpdateError("Network error")

    monkeypatch.setattr("securegitx.rules_update._fetch", _fail)

    with pytest.raises(UpdateError, match="Network error"):
        update(verify_checksum=False)


def test_update_does_not_corrupt_on_failure(tmp_path, monkeypatch):
    """On validation failure the existing rules.json must be untouched."""
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)
    original = (tmp_path / "rules.json").read_text()

    bad_data = {"version": "9.0.0", "rules": [{"id": "X"}]}  # missing fields
    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(bad_data))
    )

    with pytest.raises(UpdateError):
        update(verify_checksum=False)

    assert (tmp_path / "rules.json").read_text() == original
    assert not (tmp_path / "rules.json.bak").exists()


# rollback


def test_rollback_restores_backup(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )
    update(verify_checksum=False)

    assert json.loads((tmp_path / "rules.json").read_text())["version"] == "2.0.0"
    rollback()
    assert json.loads((tmp_path / "rules.json").read_text())["version"] == "1.0.0"


def test_rollback_removes_backup(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )
    update(verify_checksum=False)
    rollback()

    assert not (tmp_path / "rules.json.bak").exists()


def test_rollback_removes_meta(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )
    update(verify_checksum=False)
    rollback()

    assert not (tmp_path / "rules.json.meta").exists()


def test_rollback_raises_without_backup(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    with pytest.raises(UpdateError, match="No backup"):
        rollback()


# check


def test_check_shows_update_available(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )
    result = check()
    assert "update available" in result


def test_check_shows_up_to_date(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V2)

    monkeypatch.setattr(
        "securegitx.rules_update._fetch", _mock_fetch(_as_bytes(_RULE_V2))
    )
    result = check()
    assert "up to date" in result


def test_check_handles_network_error_gracefully(tmp_path, monkeypatch):
    _patch_rules_dir(tmp_path, monkeypatch)
    _write_current(tmp_path, _RULE_V1)

    def _fail(url: str) -> bytes:
        raise UpdateError("Network error fetching")

    monkeypatch.setattr("securegitx.rules_update._fetch", _fail)
    result = check()
    assert "failed" in result.lower()
