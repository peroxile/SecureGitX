#!/usr/bin/env python3

import sys
import re
import math


# Simple rules
SECRET_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),            # AWS Access Key
    re.compile(r'sk_live_[0-9a-zA-Z]{24}'),     # Stripe
    re.compile(r'ghp_[0-9a-zA-Z]{36}'),         # Github token
]

ALLOWLIST = [
    "example",
    "test",
    "dummy"
]

ENTROPY_THRESHOLD = 4.5


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


def is_secret(line: str) -> bool:
    for pattern in SECRET_PATTERNS:
        if pattern.search(line):
            return True
    return shannon_entropy(line) >= ENTROPY_THRESHOLD


def main() -> int:
    diff = sys.stdin.read()
    for raw in diff.splitlines():
        if not raw.startswith('+'):
            continue
        if raw.startswith('+++'):
            continue

        line = raw[1:].strip()

        if not line or is_allowed(line):
            continue

        if is_secret(line):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
