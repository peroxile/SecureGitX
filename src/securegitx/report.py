"""
Report formatting — text and JSON output.
No scanning logic here. Pure presentation.
"""
from __future__ import annotations

import json
import sys
from typing import TextIO

from securegitx.scanner import Finding

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_ICONS = {
    "critical": "✖",
    "high":     "✖",
    "medium":   "⚠",
    "low":      "ℹ",
}


# Terminal colors — only when writing to a real TTY
def _supports_color(stream: TextIO) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def _color(text: str, code: str, stream: TextIO) -> str:
    if not _supports_color(stream):
        return text
    return f"\033[{code}m{text}\033[0m"


_SEV_COLORS = {
    "critical": "31",  # red
    "high":     "31",
    "medium":   "33",  # yellow
    "low":      "36",  # cyan
}


def _redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


def format_text(
    findings: list[Finding],
    stream: TextIO = sys.stdout,
    show_remediation: bool = True,
) -> None:
    if not findings:
        _print_clean(stream)
        return

    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
    counts: dict[str, int] = {}

    stream.write("\n")
    for f in sorted_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        icon = _SEVERITY_ICONS.get(f.severity, "?")
        sev = _color(f.severity.upper(), _SEV_COLORS.get(f.severity, "0"), stream)
        stream.write(f"  {icon} [{sev}] {f.rule_name} ({f.rule_id})\n")
        stream.write(f"    File : {f.file}")
        if f.line_number:
            stream.write(f":{f.line_number}")
        stream.write("\n")
        stream.write(f"    Match: {_redact(f.matched_text)}\n")
        stream.write(f"    Why  : {f.reason}\n")
        if show_remediation and f.remediation:
            stream.write(f"    Fix  : {f.remediation}\n")
        if f.confidence != "high":
            stream.write(f"    Conf : {f.confidence}\n")
        stream.write("\n")

    _print_summary(counts, stream)


def _print_clean(stream: TextIO) -> None:
    ok = _color("✔", "32", stream)
    stream.write(f"\n  {ok} No secrets detected\n\n")


def _print_summary(counts: dict[str, int], stream: TextIO) -> None:
    total = sum(counts.values())
    stream.write("  " + "─" * 48 + "\n")
    stream.write(f"  {total} finding(s): ")
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        if sev in counts:
            c = _color(f"{counts[sev]} {sev}", _SEV_COLORS[sev], stream)
            parts.append(c)
    stream.write(", ".join(parts) + "\n\n")


def format_json(findings: list[Finding], stream: TextIO = sys.stdout) -> None:
    payload = {
        "findings": [f.as_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "by_severity": _count_by_severity(findings),
        },
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def exceeds_threshold(findings: list[Finding], fail_on: str) -> bool:
    """Return True if any finding is at or above the fail_on severity."""
    order = _SEVERITY_ORDER
    threshold = order.get(fail_on, 1)
    return any(order.get(f.severity, 9) <= threshold for f in findings)