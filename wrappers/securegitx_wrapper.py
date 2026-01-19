#!/usr/bin/env python3
import sys
import re
import math
import json
import os

# Load allowlist and rules from JSON
script_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(script_dir, 'allowlist.json'), 'r') as f:
    ALLOWLIST_DATA = json.load(f)
ALLOWLIST = ALLOWLIST_DATA['allowlist']

with open(os.path.join(script_dir, 'rules.json'), 'r') as f:
    RULES_DATA = json.load(f)
# Compile patterns with names for better reporting
SECRET_PATTERNS = {name: re.compile(pattern) for name, pattern in RULES_DATA['patterns'].items()}

ENTROPY_THRESHOLD = 4.5
CODE_INDICATORS = [
    '=', ':', 'import', 'def ', 'class ', 'for ', 'if ', 're.compile',
    '|', '$', 'git ', 'python3 ', './', 'bash', 'sh '
]

# Skip code-like lines for entropy


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def is_allowed(line: str) -> bool:
    return any(word in line.lower() for word in ALLOWLIST)


def is_code_like(line: str) -> bool:
    return any(indicator in line for indicator in CODE_INDICATORS)


def detect_secret(line: str) -> str:
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(line):
            return f"Matched pattern: {name}"
    # Skip entropy for short or code-like lines
    if len(line) > 20 and not is_code_like(line):
        ent = shannon_entropy(line)
        if ent >= ENTROPY_THRESHOLD:
            return f"High entropy string (entropy: {ent:.2f})"
    return ""


def main() -> int:
    detections = []
    current_file = "unknown"
    diff_line_num = 0  # Track line number in the diff for reference

    for raw in sys.stdin:
        diff_line_num += 1
        if raw.startswith('+++ b/'):
            current_file = raw.split('+++ b/')[1].strip()
            continue
        if not raw.startswith('+'):
            continue
        line = raw[1:].strip()
        if not line or is_allowed(line):
            continue
        reason = detect_secret(line)
        if reason:
            detections.append({
                'file': current_file,
                'diff_line': diff_line_num,
                'content': line[:100] + '...' if len(line) > 100 else line,  # Truncate long lines
                'reason': reason
            })

    if detections:
        print("Sensitive content detected:")
        for det in detections:
            print(f"- File: {det['file']}, Diff line: {det['diff_line']}")
            print(f"  Content: {det['content']}")
            print(f"  Reason: {det['reason']}")
            print()
        return len(detections)
    return 0


if __name__ == "__main__":
    sys.exit(main())
