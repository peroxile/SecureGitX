"""Tests for report.py — text output, JSON output, threshold logic."""
import io
import json

import pytest

from securegitx.scanner import Finding
from securegitx.report import format_text, format_json, exceeds_threshold


def _finding(severity="critical", rule_id="SGX003", confidence="high"):
    return Finding(
        rule_id=rule_id,
        rule_name="test_rule",
        severity=severity,
        file="config.py",
        line_number=5,
        matched_text="AKIA1234567890ABCDEF",
        reason="Test reason",
        remediation="Test remediation",
        confidence=confidence,
    )


#  Text format

def test_text_clean_output():
    buf = io.StringIO()
    format_text([], stream=buf)
    assert "No secrets detected" in buf.getvalue()


def test_text_shows_rule_id():
    buf = io.StringIO()
    format_text([_finding()], stream=buf)
    assert "SGX003" in buf.getvalue()


def test_text_shows_filename():
    buf = io.StringIO()
    format_text([_finding()], stream=buf)
    assert "config.py" in buf.getvalue()


def test_text_shows_line_number():
    buf = io.StringIO()
    format_text([_finding()], stream=buf)
    assert ":5" in buf.getvalue()


def test_text_redacts_matched_value():
    buf = io.StringIO()
    format_text([_finding()], stream=buf)
    out = buf.getvalue()
    # Should show first 4 chars then ***
    assert "AKIA***" in out
    # Should NOT show the full value
    assert "AKIA1234567890ABCDEF" not in out


def test_text_shows_remediation():
    buf = io.StringIO()
    format_text([_finding()], stream=buf)
    assert "Test remediation" in buf.getvalue()


def test_text_shows_confidence_when_low():
    buf = io.StringIO()
    format_text([_finding(confidence="low")], stream=buf)
    assert "low" in buf.getvalue()


def test_text_hides_confidence_when_high():
    buf = io.StringIO()
    format_text([_finding(confidence="high")], stream=buf)
    assert "Conf" not in buf.getvalue()


def test_text_summary_count():
    findings = [_finding("critical"), _finding("high"), _finding("high")]
    buf = io.StringIO()
    format_text(findings, stream=buf)
    assert "3 finding(s)" in buf.getvalue()


def test_text_sorts_by_severity():
    findings = [_finding("low"), _finding("critical"), _finding("medium")]
    buf = io.StringIO()
    format_text(findings, stream=buf)
    out = buf.getvalue()
    # Critical should appear before low
    assert out.index("CRITICAL") < out.index("LOW")


def test_text_no_remediation_flag():
    buf = io.StringIO()
    format_text([_finding()], stream=buf, show_remediation=False)
    assert "Test remediation" not in buf.getvalue()


#  JSON format

def test_json_output_is_valid():
    buf = io.StringIO()
    format_json([_finding()], stream=buf)
    data = json.loads(buf.getvalue())
    assert "findings" in data
    assert "summary" in data


def test_json_finding_fields():
    buf = io.StringIO()
    format_json([_finding()], stream=buf)
    data = json.loads(buf.getvalue())
    f = data["findings"][0]
    required = {"rule_id", "rule_name", "severity", "file",
                "line_number", "matched_text", "reason", "remediation", "confidence"}
    assert required <= f.keys()


def test_json_matched_text_is_redacted():
    buf = io.StringIO()
    format_json([_finding()], stream=buf)
    data = json.loads(buf.getvalue())
    assert data["findings"][0]["matched_text"] == "AKIA***"


def test_json_summary_counts():
    findings = [_finding("critical"), _finding("critical"), _finding("high")]
    buf = io.StringIO()
    format_json(findings, stream=buf)
    data = json.loads(buf.getvalue())
    assert data["summary"]["total"] == 3
    assert data["summary"]["by_severity"]["critical"] == 2
    assert data["summary"]["by_severity"]["high"] == 1


def test_json_empty_findings():
    buf = io.StringIO()
    format_json([], stream=buf)
    data = json.loads(buf.getvalue())
    assert data["findings"] == []
    assert data["summary"]["total"] == 0


#  Threshold logic

@pytest.mark.parametrize("severity,fail_on,expected", [
    ("critical", "high",     True),   # critical >= high threshold
    ("high",     "high",     True),   # exact match
    ("medium",   "high",     False),  # below threshold
    ("low",      "high",     False),
    ("critical", "critical", True),
    ("high",     "critical", False),  # high is below critical threshold
    ("critical", "low",      True),   # everything exceeds low
    ("low",      "low",      True),
])
def test_exceeds_threshold(severity, fail_on, expected):
    findings = [_finding(severity=severity)]
    assert exceeds_threshold(findings, fail_on) == expected


def test_exceeds_threshold_empty():
    assert not exceeds_threshold([], "high")


def test_exceeds_threshold_mixed_severities():
    findings = [_finding("low"), _finding("medium"), _finding("critical")]
    assert exceeds_threshold(findings, "high")
    assert not exceeds_threshold(findings, "high") is False