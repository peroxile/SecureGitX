![Diagram](assets/SecureGitX.png)

<div align="center">

**Stop secrets before they leave your machine.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![CI](https://github.com/peroxile/SecureGitX/actions/workflows/ci.yml/badge.svg)](https://github.com/peroxile/SecureGitX/actions)

</div>

---

SecureGitX is a local first pre-commit secret scanner. It inspects your staged changes before every `git commit` and blocks the commit if it finds API keys, tokens, credentials, or sensitive filenames.

---

## Install

```sh
pip install git+https://github.com/peroxile/SecureGitX.git
```

Or clone and install locally:

```sh
git clone https://github.com/peroxile/SecureGitX.git
cd SecureGitX
pip install -e ".[dev]"
```

Requires Python 3.10+.

---

## Quick start

```sh
# 1. Set up your repo (creates config, installs hook, generates .gitignore)
securegitx init
securegitx hook install

# 2. Work normally — the hook fires automatically on every commit
git add src/
git commit -m "feat: add login"

# Or use SecureGitX directly to scan and commit in one step
securegitx "feat: add login"
```

From this point, any commit containing a secret is blocked with a clear message showing the file, line, rule matched, and what to do next.

![Sample output](assets/demo.png)

---

## How it works

```
git commit
    │
    ▼
pre-commit hook
    │
    ├── scan staged filenames   → block on sensitive filename patterns
    ├── scan staged diff        → block on secret content patterns
    ├── entropy check           → block on high-entropy tokens
    │
    ├── findings above threshold?
    │       YES → print findings, exit 1 (commit blocked)
    │       NO  → exit 0 (commit proceeds)
```

The hook is the enforcement edge. Nothing else blocks commits — not the daemon, not the CLI scan command. The invariant is local and unconditional.

## What it detects

API keys, tokens, credentials, and sensitive filenames across 13 named rules — AWS, GitHub, Stripe, Google OAuth, JWTs, Slack tokens, Firebase keys, PEM headers, database URLs, SSH keys, and `.env` files. An entropy heuristic catches secrets that named rules miss.

## Configuration

Running `securegitx init` creates `.securegitx.toml`. Set `fail_on` to control which severity level blocks commits. Use the `allowlist` table to suppress false positives.
