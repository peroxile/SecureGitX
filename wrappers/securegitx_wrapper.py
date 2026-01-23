#!/usr/bin/env python3
import sys
import re
import math
import json
import os

# ---------- Load config ----------
script_dir = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(script_dir, "allowlist.json"), "r") as f:
    ALLOWLIST = json.load(f)["allowlist"]

with open(os.path.join(script_dir, "rules.json"), "r") as f:
    RULES = json.load(f)["patterns"]

SECRET_PATTERNS = {
    name: re.compile(pattern)
    for name, pattern in RULES.items()
}

# ---------- Constants ----------
ENTROPY_THRESHOLD = 4.5
TOKEN_REGEX = re.compile(r"[A-Za-z0-9+/=_@.-]{20,}")

# ---------- Helpers ----------


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


def is_allowed(token: str) -> bool:
    token_l = token.lower()
    return any(a in token_l for a in ALLOWLIST)


def detect_secret(line: str) -> str:
    # 1. Deterministic pattern match (strong signal)
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(line):
            return f"Matched pattern: {name}"

    # 2. Token-based entropy fallback (weak signal)
    for token in TOKEN_REGEX.findall(line):
        if is_allowed(token):
            continue
        ent = shannon_entropy(token)
        if ent >= ENTROPY_THRESHOLD:
            return f"High entropy token (entropy: {ent:.2f})"

    return ""


# ---------- Main ----------
def main() -> int:
    detections = []
    current_file = "unknown"
    diff_line_num = 0

    for raw in sys.stdin:
        diff_line_num += 1

        if raw.startswith("+++ b/"):
            current_file = raw.split("+++ b/")[1].strip()
            continue

        if not raw.startswith("+") or raw.startswith("+++"):
            continue

        line = raw[1:].strip()
        if not line:
            continue

        reason = detect_secret(line)
        if reason:
            detections.append({
                "file": current_file,
                "diff_line": diff_line_num,
                "content": line[:100] + ("..." if len(line) > 100 else ""),
                "reason": reason
            })

    if detections:
        print("Sensitive content detected:")
        for d in detections:
            print(f"- File: {d['file']}, Diff line: {d['diff_line']}")
            print(f"  Content: {d['content']}")
            print(f"  Reason: {d['reason']}")
            print()
        return len(detections)

    return 0


if __name__ == "__main__":
    sys.exit(main())
