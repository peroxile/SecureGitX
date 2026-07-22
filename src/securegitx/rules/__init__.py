"""
Rule and allowlist types, loaders, and allowlist matching.

rules.json  — bare array OR {"version": ..., "rules": [...]} object (required)
allowlist.json — bare array OR {"allowlist": [...]} object           (optional)

Public API:
  Rule, AllowEntry, RuleLoadError
  load_rules()          → list[Rule]
  load_allowlist()      → list[AllowEntry]
  is_allowlisted(...)   → bool
  rule_version()        → str
  validate_rules_data() → list[Rule]   (used by updater before install)
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_RULES_DIR = Path(__file__).parent


class RuleLoadError(Exception):
    pass


# Data types

@dataclass
class Rule:
    id: str
    name: str
    severity: str
    type: str  # "filename" | "content"
    pattern: str
    description: str = ""
    remediation: str = ""
    _compiled: Optional[re.Pattern] = field(
        default=None, repr=False, compare=False, init=False
    )

    def compiled(self) -> re.Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern)
        return self._compiled


@dataclass
class AllowEntry:
    rule_id: str
    path: str = "*"
    value: str = "*"
    comment: str = ""


# Allowlist matching

def is_allowlisted(
    value: str,
    filename: str,
    rule_id: str,
    allowlist: list[AllowEntry],
) -> bool:
    for entry in allowlist:
        rule_match = entry.rule_id == "*" or entry.rule_id == rule_id
        path_match = entry.path == "*" or fnmatch.fnmatch(filename, entry.path)
        value_match = entry.value == "*" or entry.value in value
        if rule_match and path_match and value_match:
            return True
    return False


# Internal helpers

def _unwrap_list(data: object, list_keys: tuple[str, ...], path: Path) -> list:
    """Accept a bare array or a wrapper object with one of list_keys."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in list_keys:
            if key in data:
                value = data[key]
                if not isinstance(value, list):
                    raise RuleLoadError(
                        f"{path.name} '{key}' value must be an array, "
                        f"got {type(value).__name__}"
                    )
                return value
        raise RuleLoadError(
            f"{path.name} is an object but has none of the expected keys: {list_keys}"
        )
    raise RuleLoadError(
        f"{path.name} must be a JSON array or object, got {type(data).__name__}"
    )


def _build_rules(entries: list, source_label: str) -> list[Rule]:
    """Parse a list of raw dicts into Rule objects, compiling each pattern."""
    rules: list[Rule] = []
    for i, entry in enumerate(entries):
        try:
            rule = Rule(
                id=entry["id"],
                name=entry["name"],
                severity=entry["severity"],
                type=entry["type"],
                pattern=entry["pattern"],
                description=entry.get("description", ""),
                remediation=entry.get("remediation", ""),
            )
            rule.compiled()  # validate regex at load time
            rules.append(rule)
        except KeyError as exc:
            raise RuleLoadError(
                f"Rule #{i} in {source_label} missing required field: {exc}"
            )
        except re.error as exc:
            raise RuleLoadError(
                f"Rule {entry.get('id', f'#{i}')} in {source_label} "
                f"has invalid pattern: {exc}"
            )
    return rules


# Public loaders

def load_rules() -> list[Rule]:
    """Load and validate rules from the bundled rules.json."""
    path = _RULES_DIR / "rules.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuleLoadError(f"rules.json not found: {path}")
    except json.JSONDecodeError as exc:
        raise RuleLoadError(f"rules.json invalid JSON: {exc}")

    entries = _unwrap_list(data, ("rules",), path)
    return _build_rules(entries, "rules.json")


def load_allowlist() -> list[AllowEntry]:
    """Load suppression entries from allowlist.json. Returns [] if file absent."""
    path = _RULES_DIR / "allowlist.json"
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleLoadError(f"allowlist.json invalid JSON: {exc}")

    entries_data = _unwrap_list(data, ("allowlist", "entries"), path)
    entries: list[AllowEntry] = []
    for i, entry in enumerate(entries_data):
        try:
            entries.append(
                AllowEntry(
                    rule_id=entry["rule_id"],
                    path=entry.get("path", "*"),
                    value=entry.get("value", "*"),
                    comment=entry.get("comment", ""),
                )
            )
        except KeyError as exc:
            raise RuleLoadError(f"Allowlist entry #{i} missing required field: {exc}")
    return entries


def rule_version(_rules_dir: Path | None = None) -> str:
    """
    Return the 'version' field from rules.json.

    Returns 'unknown' if rules.json is a bare array or lacks a version field.
    Raises RuleLoadError if the file is missing or contains invalid JSON.
    """
    path = (_rules_dir or _RULES_DIR) / "rules.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuleLoadError(f"rules.json not found: {path}")
    except json.JSONDecodeError as exc:
        raise RuleLoadError(f"rules.json invalid JSON: {exc}")

    if isinstance(data, dict):
        version = data.get("version")
        if version is not None:
            return str(version)

    return "unknown"  # bare array format or version field absent


def validate_rules_data(data: object, source: str = "<remote>") -> list[Rule]:
    """
    Validate raw parsed JSON as a rules bundle and return Rule objects.

    Called by the updater to validate downloaded content before it is
    written to disk. Raises RuleLoadError on any structural problem.

    Args:
        data:   Parsed JSON (dict or list).
        source: Label used in error messages (e.g. a URL or filename).
    """
    entries = _unwrap_list(data, ("rules",), Path(source))
    return _build_rules(entries, source)
