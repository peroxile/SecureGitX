from __future__ import annotations

import json
from pathlib import Path

import pytest

from securegitx import rules


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture()
def rules_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "rules"
    root.mkdir()
    monkeypatch.setattr(rules, "_RULES_DIR", root)
    return root


def test_unwrap_list_accepts_bare_array(rules_dir: Path):
    data = [{"id": "SGX001"}]
    assert rules._unwrap_list(data, ("rules",), rules_dir / "rules.json") == data


def test_unwrap_list_accepts_wrapped_object(rules_dir: Path):
    data = {"version": "1.0.0", "rules": [{"id": "SGX001"}]}
    assert (
        rules._unwrap_list(data, ("rules",), rules_dir / "rules.json") == data["rules"]
    )


def test_unwrap_list_rejects_wrong_inner_type(rules_dir: Path):
    with pytest.raises(rules.RuleLoadError, match="must be an array"):
        rules._unwrap_list({"rules": "bad"}, ("rules",), rules_dir / "rules.json")


def test_unwrap_list_rejects_missing_key(rules_dir: Path):
    with pytest.raises(rules.RuleLoadError, match="none of the expected keys"):
        rules._unwrap_list({"version": "1.0.0"}, ("rules",), rules_dir / "rules.json")


def test_unwrap_list_rejects_non_list_non_object(rules_dir: Path):
    with pytest.raises(rules.RuleLoadError, match="must be a JSON array or object"):
        rules._unwrap_list("bad", ("rules",), rules_dir / "rules.json")


def test_load_rules_accepts_wrapped_object(rules_dir: Path):
    write_json(
        rules_dir / "rules.json",
        {
            "version": "1.0.0",
            "rules": [
                {
                    "id": "SGX001",
                    "name": "aws_key",
                    "severity": "critical",
                    "type": "content",
                    "pattern": r"AKIA[0-9A-Z]{16}",
                    "description": "AWS access key",
                    "remediation": "Rotate the key.",
                }
            ],
        },
    )

    loaded = rules.load_rules()

    assert len(loaded) == 1
    r = loaded[0]
    assert r.id == "SGX001"
    assert r.name == "aws_key"
    assert r.severity == "critical"
    assert r.type == "content"
    assert r.pattern == r"AKIA[0-9A-Z]{16}"
    assert r.description == "AWS access key"
    assert r.remediation == "Rotate the key."
    assert r.compiled().pattern == r"AKIA[0-9A-Z]{16}"


def test_load_rules_accepts_bare_array(rules_dir: Path):
    write_json(
        rules_dir / "rules.json",
        [
            {
                "id": "SGX002",
                "name": "private_key_file",
                "severity": "high",
                "type": "filename",
                "pattern": r"(?i)\.pem$",
            }
        ],
    )

    loaded = rules.load_rules()

    assert len(loaded) == 1
    assert loaded[0].id == "SGX002"
    assert loaded[0].type == "filename"


def test_load_rules_missing_file_raises(rules_dir: Path):
    with pytest.raises(rules.RuleLoadError, match="rules.json not found"):
        rules.load_rules()


def test_load_rules_invalid_json_raises(rules_dir: Path):
    (rules_dir / "rules.json").write_text("{not json", encoding="utf-8")

    with pytest.raises(rules.RuleLoadError, match="invalid JSON"):
        rules.load_rules()


def test_load_rules_invalid_regex_raises(rules_dir: Path):
    write_json(
        rules_dir / "rules.json",
        [
            {
                "id": "SGX003",
                "name": "bad_regex",
                "severity": "medium",
                "type": "content",
                "pattern": "[unclosed",
            }
        ],
    )

    with pytest.raises(rules.RuleLoadError, match="invalid pattern"):
        rules.load_rules()


def test_load_rules_missing_required_field_raises(rules_dir: Path):
    write_json(
        rules_dir / "rules.json",
        [
            {
                "name": "missing_id",
                "severity": "high",
                "type": "content",
                "pattern": r".+",
            }
        ],
    )

    with pytest.raises(rules.RuleLoadError, match="missing required field"):
        rules.load_rules()


def test_load_allowlist_missing_file_returns_empty(rules_dir: Path):
    assert rules.load_allowlist() == []


def test_load_allowlist_accepts_wrapped_object(rules_dir: Path):
    write_json(
        rules_dir / "allowlist.json",
        {
            "allowlist": [
                {
                    "rule_id": "SGX001",
                    "path": "tests/*",
                    "value": "example",
                    "comment": "test fixture",
                }
            ]
        },
    )

    loaded = rules.load_allowlist()

    assert len(loaded) == 1
    entry = loaded[0]
    assert entry.rule_id == "SGX001"
    assert entry.path == "tests/*"
    assert entry.value == "example"
    assert entry.comment == "test fixture"


def test_load_allowlist_accepts_entries_key(rules_dir: Path):
    write_json(
        rules_dir / "allowlist.json",
        {
            "entries": [
                {
                    "rule_id": "*",
                    "path": "*",
                    "value": "placeholder",
                    "comment": "generic exception",
                }
            ]
        },
    )

    loaded = rules.load_allowlist()

    assert len(loaded) == 1
    assert loaded[0].rule_id == "*"


def test_load_allowlist_accepts_bare_array(rules_dir: Path):
    write_json(
        rules_dir / "allowlist.json",
        [
            {
                "rule_id": "SGX002",
                "path": "docs/*",
                "value": "*",
                "comment": "docs example",
            }
        ],
    )

    loaded = rules.load_allowlist()

    assert len(loaded) == 1
    assert loaded[0].path == "docs/*"


def test_load_allowlist_invalid_json_raises(rules_dir: Path):
    (rules_dir / "allowlist.json").write_text("{not json", encoding="utf-8")

    with pytest.raises(rules.RuleLoadError, match="invalid JSON"):
        rules.load_allowlist()


def test_load_allowlist_missing_required_field_raises(rules_dir: Path):
    write_json(
        rules_dir / "allowlist.json",
        [
            {
                "path": "tests/*",
                "value": "example",
            }
        ],
    )

    with pytest.raises(rules.RuleLoadError, match="missing required field"):
        rules.load_allowlist()


def test_is_allowlisted_matches_any_rule_any_path_any_value():
    allowlist = [rules.AllowEntry(rule_id="*", path="*", value="*")]
    assert (
        rules.is_allowlisted("secret-value", "src/app.py", "SGX001", allowlist) is True
    )


def test_is_allowlisted_matches_specific_rule_and_path_and_value():
    allowlist = [
        rules.AllowEntry(
            rule_id="SGX001", path="tests/*", value="example", comment="test"
        )
    ]
    assert (
        rules.is_allowlisted(
            "my example token", "tests/test_rules.py", "SGX001", allowlist
        )
        is True
    )
    assert (
        rules.is_allowlisted("my example token", "src/app.py", "SGX001", allowlist)
        is False
    )
    assert (
        rules.is_allowlisted(
            "my example token", "tests/test_rules.py", "SGX002", allowlist
        )
        is False
    )


def test_is_allowlisted_uses_substring_matching():
    allowlist = [rules.AllowEntry(rule_id="SGX001", path="*", value="needle")]
    assert (
        rules.is_allowlisted(
            "haystack-with-needle-inside", "src/app.py", "SGX001", allowlist
        )
        is True
    )
    assert rules.is_allowlisted("haystack", "src/app.py", "SGX001", allowlist) is False


def test_rule_compiled_is_cached():
    rule = rules.Rule(
        id="SGX001",
        name="test",
        severity="high",
        type="content",
        pattern=r"foo",
    )

    first = rule.compiled()
    second = rule.compiled()

    assert first is second
    assert first.pattern == "foo"
