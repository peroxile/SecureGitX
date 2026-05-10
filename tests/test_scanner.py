"""Tests for securegitx.scanner."""

from __future__ import annotations

import pytest

from securegitx.rules import AllowEntry, Rule
from securegitx.scanner import (
    Finding,
    _is_high_entropy,
    _redact,
    _shannon_entropy,
    scan_diff,
    scan_file_content,
    scan_filenames,
)

# Helpers


def _rule(
    id="T001",
    name="test",
    pattern="secret",
    type="content",
    severity="high",
    description="",
    remediation="fix it",
) -> Rule:
    return Rule(
        id=id,
        name=name,
        severity=severity,
        type=type,
        pattern=pattern,
        description=description,
        remediation=remediation,
    )


def _fname_rule(id="F001", pattern=r"\.env$", severity="high") -> Rule:
    return Rule(
        id=id, name="env_file", severity=severity, type="filename", pattern=pattern
    )


# _redact


def test_redact_long_value():
    assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA***"


def test_redact_short_value():
    assert _redact("abc") == "***"


def test_redact_exactly_at_keep():
    # len == keep triggers the <= branch → masked entirely
    assert _redact("abcd") == "***"


def test_redact_one_over_keep():
    assert _redact("abcde") == "abcd***"


def test_redact_custom_keep():
    assert _redact("SECRETVALUE", keep=2) == "SE***"


# _shannon_entropy


def test_entropy_empty():
    assert _shannon_entropy("") == 0.0


def test_entropy_uniform_chars():
    assert _shannon_entropy("aaaa") == 0.0


def test_entropy_two_chars():
    e = _shannon_entropy("abababab")
    assert abs(e - 1.0) < 0.01


def test_entropy_high_random():
    e = _shannon_entropy("aB3kL9mN2xQpR7vW")
    assert e > 3.0


# _is_high_entropy


def test_high_entropy_short_token_false():
    assert not _is_high_entropy("short", 4.5)


def test_high_entropy_low_entropy_false():
    assert not _is_high_entropy("a" * 25, 4.5)


def test_high_entropy_high_entropy_true():
    token = "aB3kL9mN2xQpR7vWzY1cD4eF6gH8iJ0"
    assert _is_high_entropy(token, 3.0)


def test_high_entropy_threshold_respected():
    token = "aB3kL9mN2xQpR7vWzY1cD4eF6gH8iJ0"
    assert not _is_high_entropy(token, 9.0)  # unreachable threshold


# Finding.as_dict


def test_finding_as_dict_redacts_matched_text():
    f = Finding(
        rule_id="T001",
        rule_name="test",
        severity="high",
        file="f.py",
        line_number=1,
        matched_text="secretVALUE",
        reason="matched",
        remediation="fix",
    )
    d = f.as_dict()
    assert d["matched_text"] == "secr***"
    assert d["rule_id"] == "T001"
    assert d["file"] == "f.py"
    assert d["line_number"] == 1


def test_finding_default_confidence():
    f = Finding(
        rule_id="T001",
        rule_name="test",
        severity="high",
        file="f.py",
        line_number=1,
        matched_text="x",
        reason="r",
        remediation="r",
    )
    assert f.confidence == "high"


# scan_filenames


def test_scan_filenames_match():
    rule = _fname_rule(pattern=r"\.env$")
    findings = scan_filenames([".env"], [rule], [])
    assert len(findings) == 1
    assert findings[0].rule_id == "F001"
    assert findings[0].file == ".env"
    assert findings[0].line_number == 0


def test_scan_filenames_no_match():
    rule = _fname_rule(pattern=r"\.env$")
    assert scan_filenames(["main.py"], [rule], []) == []


def test_scan_filenames_skips_content_rules():
    rule = _rule(type="content")
    assert scan_filenames([".env"], [rule], []) == []


def test_scan_filenames_allowlisted():
    rule = _fname_rule(pattern=r"\.env$")
    al = [AllowEntry(rule_id="F001", path=".env")]
    assert scan_filenames([".env"], [rule], al) == []


def test_scan_filenames_multiple_files_one_match():
    rule = _fname_rule(pattern=r"\.env$")
    findings = scan_filenames([".env", "main.py"], [rule], [])
    assert len(findings) == 1


def test_scan_filenames_remediation_set():
    rule = Rule(
        id="F001",
        name="env",
        severity="high",
        type="filename",
        pattern=r"\.env$",
        remediation="Add to .gitignore",
    )
    findings = scan_filenames([".env"], [rule], [])
    assert findings[0].remediation == "Add to .gitignore"


def test_scan_filenames_empty_input():
    rule = _fname_rule()
    assert scan_filenames([], [rule], []) == []


def test_scan_filenames_no_rules():
    assert scan_filenames([".env"], [], []) == []


# scan_diff

_CLEAN_DIFF = """\
diff --git a/main.py b/main.py
--- a/main.py
+++ b/main.py
@@ -1,3 +1,3 @@
 def hello():
-    pass
+    return "hello"
"""

_DIRTY_DIFF = """\
diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,2 +1,3 @@
 import os
+API_KEY = "secret_value_here"
 print("ok")
"""


def test_scan_diff_clean():
    assert scan_diff(_CLEAN_DIFF, [_rule(pattern="secret")], [], 4.5) == []


def test_scan_diff_detects_secret():
    findings = scan_diff(_DIRTY_DIFF, [_rule(pattern="secret")], [], 4.5)
    assert len(findings) == 1
    assert findings[0].file == "config.py"
    assert findings[0].rule_id == "T001"


def test_scan_diff_skips_removed_lines():
    diff = (
        "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n"
        "-secret = 'removed'\n"
        "+something_clean = 'added'\n"
    )
    assert scan_diff(diff, [_rule(pattern="secret")], [], 4.5) == []


def test_scan_diff_correct_line_number():
    diff = (
        "--- a/f.py\n+++ b/f.py\n@@ -1,3 +1,3 @@\n"
        " line1\n"
        " line2\n"
        "+secret = 'value'\n"
    )
    findings = scan_diff(diff, [_rule(pattern="secret")], [], 4.5)
    assert findings[0].line_number == 3


def test_scan_diff_deduplicates_same_match():
    diff = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n+secret = secret\n"
    # "secret" matches twice at same positions but matched text is the same
    findings = scan_diff(diff, [_rule(pattern="secret")], [], 4.5)
    assert len(findings) == 1


def test_scan_diff_allowlist_suppresses():
    al = [AllowEntry(rule_id="T001", value="secret")]
    assert scan_diff(_DIRTY_DIFF, [_rule(pattern="secret")], al, 4.5) == []


def test_scan_diff_skips_filename_rules():
    rule = _fname_rule(pattern="secret")
    assert scan_diff(_DIRTY_DIFF, [rule], [], 4.5) == []


def test_scan_diff_empty_string():
    assert scan_diff("", [_rule(pattern="secret")], [], 4.5) == []


def test_scan_diff_hunk_line_tracking():
    diff = (
        "--- a/f.py\n+++ b/f.py\n@@ -10,3 +10,4 @@\n"
        " context\n"
        " context\n"
        "+secret_key = 'value'\n"
    )
    findings = scan_diff(diff, [_rule(pattern="secret")], [], 4.5)
    assert findings[0].line_number == 12  # 10 + 2 context lines


def test_scan_diff_multiple_files():
    # Use filenames that don't start with 'b' to avoid lstrip("b/") stripping too much
    diff = (
        "--- a/main.py\n+++ b/main.py\n@@ -1 +1 @@\n+secret1\n"
        "--- a/utils.py\n+++ b/utils.py\n@@ -1 +1 @@\n+secret2\n"
    )
    findings = scan_diff(diff, [_rule(pattern="secret")], [], 4.5)
    files = {f.file for f in findings}
    assert "main.py" in files
    assert "utils.py" in files


# scan_file_content


def test_scan_file_content_match():
    rule = _rule(pattern="password")
    findings = scan_file_content(
        "line1\npassword = 'hunter2'\nline3", "config.py", [rule], [], 4.5
    )
    assert len(findings) == 1
    assert findings[0].line_number == 2
    assert findings[0].file == "config.py"


def test_scan_file_content_no_match():
    rule = _rule(pattern="password")
    assert scan_file_content("just normal code\n", "main.py", [rule], [], 4.5) == []


def test_scan_file_content_multiple_matches():
    rule = _rule(pattern="secret")
    findings = scan_file_content("secret1\nnormal\nsecret2\n", "f.py", [rule], [], 4.5)
    assert len(findings) == 2
    assert findings[0].line_number == 1
    assert findings[1].line_number == 3


def test_scan_file_content_allowlisted():
    rule = _rule(pattern="EXAMPLE")
    al = [AllowEntry(rule_id="T001", value="EXAMPLE")]
    assert (
        scan_file_content("key = AKIAIOSFODNN7EXAMPLE\n", "f.py", [rule], al, 4.5) == []
    )


def test_scan_file_content_skips_filename_rules():
    rule = _fname_rule(pattern="secret")
    assert scan_file_content("secret\n", "f.py", [rule], [], 4.5) == []


def test_scan_file_content_empty():
    assert scan_file_content("", "f.py", [_rule()], [], 4.5) == []
