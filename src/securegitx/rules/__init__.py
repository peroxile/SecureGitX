"""
Rule and allowlist types, loaders, and allowlist matching.

rules.json  — bare array OR {"version": ..., "rules": [...]} object (required)
allowlist.json — bare array OR {"allowlist": [...]} object           (optional)

Rule fields:
  id          str   unique identifier, e.g. "SGX001"
  name        str   short slug
  severity    str   "low" | "medium" | "high" | "critical"
  type        str   "filename" | "content"
  pattern     str   Python regex
  description str   human-readable explanation  (optional)
  remediation str   fix guidance                (optional)

AllowEntry fields:
  rule_id  str  rule id to suppress; "*" matches any rule
  path     str  file path glob;      "*" matches any path   (optional, default "*")
  value    str  substring match;     "*" matches any value  (optional, default "*")
  comment  str  reason for suppression                      (optional)
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
    rule_id: str  # rule id to suppress, or "*" for any
    path: str = "*"  # file path glob, or "*" for any
    value: str = "*"  # substring to match against value, or "*" for any
    comment: str = ""


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


def _unwrap_list(data: object, list_keys: tuple[str, ...], path: Path) -> list:
    """Accept a bare array or an object whose value under any of list_keys is the array."""
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
            f"{path.name} is an object but has none of the expected keys: "
            f"{list_keys}"
        )
    raise RuleLoadError(
        f"{path.name} must be a JSON array or object, got {type(data).__name__}"
    )


def load_rules() -> list[Rule]:
    path = _RULES_DIR / "rules.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuleLoadError(f"rules.json not found: {path}")
    except json.JSONDecodeError as exc:
        raise RuleLoadError(f"rules.json invalid JSON: {exc}")

    entries = _unwrap_list(data, ("rules",), path)

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
            raise RuleLoadError(f"Rule #{i} missing required field: {exc}")
        except re.error as exc:
            raise RuleLoadError(
                f"Rule {entry.get('id', f'#{i}')} has invalid pattern: {exc}"
            )

    return rules


def load_allowlist() -> list[AllowEntry]:
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
