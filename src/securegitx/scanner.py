"""
Scanner — applies rules to filenames and diff content, returns findings.

Inputs:  filenames (list[str]) and/or diff lines (list[str])
Output:  list[Finding]

No Git operations here. No IO. Pure logic.
"""
from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field
from typing import Optional

from securegitx.rules import AllowEntry, Rule, is_allowlisted

# Characters common in encoded secrets
_B64_CHARS = set(string.ascii_letters + string.digits + "+/=")
_HEX_CHARS = set(string.hexdigits)

# Minimum token length before entropy check is meaningful
_ENTROPY_MIN_LEN = 20


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    file: str
    line_number: int          # 0 for filename matches
    matched_text: str
    reason: str
    remediation: str
    confidence: str = "high"  # "high" | "medium" | "low"

    def as_dict(self) -> dict:
        return {
            "rule_id":      self.rule_id,
            "rule_name":    self.rule_name,
            "severity":     self.severity,
            "file":         self.file,
            "line_number":  self.line_number,
            "matched_text": _redact(self.matched_text),
            "reason":       self.reason,
            "remediation":  self.remediation,
            "confidence":   self.confidence,
        }


def _redact(value: str, keep: int = 4) -> str:
    """Show only the first `keep` characters; mask the rest."""
    if len(value) <= keep:
        return "***"
    return value[:keep] + "***"


def _shannon_entropy(token: str) -> float:
    """Shannon entropy of a string. Higher = more random = more likely a secret."""
    if not token:
        return 0.0
    freq = {}
    for ch in token:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_high_entropy(token: str, threshold: float) -> bool:
    if len(token) < _ENTROPY_MIN_LEN:
        return False
    charset = set(token)
    if charset <= _HEX_CHARS or charset <= _B64_CHARS:
        return _shannon_entropy(token) >= threshold
    return False


#  Filename scanning

def scan_filenames(
    filenames: list[str],
    rules: list[Rule],
    allowlist: list[AllowEntry],
) -> list[Finding]:
    filename_rules = [r for r in rules if r.type == "filename"]
    findings: list[Finding] = []

    for filename in filenames:
        for rule in filename_rules:
            pattern = rule.compiled()
            if not pattern.search(filename):
                continue
            if is_allowlisted(filename, filename, rule.id, allowlist):
                continue
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                file=filename,
                line_number=0,
                matched_text=filename,
                reason=rule.description or f"Filename matches sensitive pattern: {rule.name}",
                remediation=rule.remediation,
            ))

    return findings


#  Diff content scanning

def scan_diff(
    diff_text: str,
    rules: list[Rule],
    allowlist: list[AllowEntry],
    entropy_threshold: float = 4.5,
) -> list[Finding]:
    """
    Scan a unified diff for secret content.
    Only inspects added lines (lines starting with '+', excluding '+++').
    """
    content_rules = [r for r in rules if r.type == "content"]
    findings: list[Finding] = []
    seen: set[tuple] = set()  # dedup by (rule_id, file, line_no, matched)

    current_file = ""
    line_number = 0

    for raw_line in diff_text.splitlines():
        # Track which file we're in
        if raw_line.startswith("+++ "):
            current_file = raw_line[4:].lstrip("b/").strip()
            line_number = 0
            continue

        if raw_line.startswith("@@ "):
            # Extract starting line number from hunk header: @@ -a,b +c,d @@
            m = re.search(r"\+(\d+)", raw_line)
            line_number = int(m.group(1)) - 1 if m else 0
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            line_number += 1
            line_content = raw_line[1:]  # strip the leading '+'
            _scan_line(
                line_content, line_number, current_file,
                content_rules, allowlist, entropy_threshold,
                findings, seen,
            )
        elif not raw_line.startswith("-"):
            line_number += 1

    return findings


def scan_file_content(
    content: str,
    filename: str,
    rules: list[Rule],
    allowlist: list[AllowEntry],
    entropy_threshold: float = 4.5,
) -> list[Finding]:
    """Scan a complete file's content (for tracked-file audit mode)."""
    content_rules = [r for r in rules if r.type == "content"]
    findings: list[Finding] = []
    seen: set[tuple] = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        _scan_line(
            line, line_number, filename,
            content_rules, allowlist, entropy_threshold,
            findings, seen,
        )

    return findings


def _scan_line(
    line: str,
    line_number: int,
    filename: str,
    rules: list[Rule],
    allowlist: list[AllowEntry],
    entropy_threshold: float,
    findings: list[Finding],
    seen: set,
) -> None:
    for rule in rules:
        pattern = rule.compiled()
        for match in pattern.finditer(line):
            matched = match.group(0)
            key = (rule.id, filename, line_number, matched)
            if key in seen:
                continue
            seen.add(key)
            if is_allowlisted(matched, filename, rule.id, allowlist):
                continue
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                file=filename,
                line_number=line_number,
                matched_text=matched,
                reason=rule.description or f"Matched rule: {rule.name}",
                remediation=rule.remediation,
            ))

    # Entropy heuristic — runs after rule matching, secondary signal only
    _entropy_scan_line(line, line_number, filename, allowlist,
                       entropy_threshold, findings, seen)


def _entropy_scan_line(
    line: str,
    line_number: int,
    filename: str,
    allowlist: list[AllowEntry],
    threshold: float,
    findings: list[Finding],
    seen: set,
) -> None:
    """Flag long high-entropy tokens not already caught by a named rule."""
    # Tokenise on common delimiters
    tokens = re.split(r'[\s\'"=:,(){}\[\]<>|&;`]', line)
    for token in tokens:
        if len(token) < _ENTROPY_MIN_LEN:
            continue
        if not _is_high_entropy(token, threshold):
            continue
        # Only flag if no named rule already caught it on this line
        already_found = any(
            f.file == filename and f.line_number == line_number
            for f in findings
        )
        if already_found:
            continue
        key = ("SGX_ENTROPY", filename, line_number, token)
        if key in seen:
            continue
        seen.add(key)
        if is_allowlisted(token, filename, "SGX_ENTROPY", allowlist):
            continue
        findings.append(Finding(
            rule_id="SGX_ENTROPY",
            rule_name="high_entropy_token",
            severity="medium",
            file=filename,
            line_number=line_number,
            matched_text=token,
            reason=f"High-entropy token (entropy={_shannon_entropy(token):.2f})",
            remediation="Review this token. If it is a secret, move it to environment variables.",
            confidence="low",
        ))