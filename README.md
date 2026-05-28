![Diagram](assets/SecureGitX.png)

<div align="center">

**Stop secrets before they leave your machine.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![CI](https://github.com/peroxile/SecureGitX/actions/workflows/ci.yml/badge.svg)](https://github.com/peroxile/SecureGitX/actions)

</div>

---

SecureGitX is a local pre-commit secret scanner. It inspects your staged changes before every `git commit` and blocks the commit if it finds API keys, tokens, credentials, or sensitive filenames.

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

---

## Commands

### Scan

```sh
# Scan staged changes (used automatically by the hook)
securegitx scan --staged

# Audit all tracked files
securegitx scan --tracked

# Output as JSON (for CI or scripting)
securegitx scan --staged --format json

# Set severity threshold for this run
securegitx scan --tracked --fail-on critical

# Suppress output (exit code only)
securegitx scan --staged --quiet
```

### Direct commit

```sh
# Equivalent to: scan staged → if clean → git commit -m "..."
securegitx "feat: your commit message"
```

Useful if you prefer a single command over `git add` + `git commit`.

### Hook

```sh
securegitx hook install       # install pre-commit hook (backs up any existing hook)
securegitx hook uninstall     # remove hook (restores backup if one exists)
securegitx hook status        # check whether the hook is installed and managed
```

The hook calls `securegitx scan --staged` and exits with its result. You can always bypass it with `git commit --no-verify` when needed.

### Init

```sh
securegitx init               # create .securegitx.toml with defaults
securegitx init --no-gitignore  # skip .gitignore generation
```

`init` detects your project type, writes a project-aware `.gitignore`, and adds `.securegitx.toml` to it so your config is never committed.

### Rules

```sh
securegitx rules list         # show all loaded rules with ID, severity, type, name
securegitx rules validate     # verify rules.json is valid and all patterns compile
securegitx rules list         # list loaded rules
securegitx rules updated      # fetch  rules 
seuregitx rules rollback      # rollback updated rules
```

### Daemon

The daemon is an optional background watcher. It is off by default and must be started explicitly.

```sh
securegitx daemon start               # start watcher (runs in background)
securegitx daemon stop                # stop the running daemon
securegitx daemon status              # show status and last scan result
```

The daemon watches your git index for staging changes and scans in the background. When it finds a newly created untracked file that matches a sensitive pattern, it queues a `.gitignore` suggestion — it never modifies files on its own.

To apply queued suggestions:

```sh
securegitx init   # re-running init picks up daemon suggestions
```

---

## Configuration

Running `securegitx init` creates `.securegitx.toml` in your repo root:

```toml
enforce_safe_email = true
auto_gitignore     = true
entropy_threshold  = 4.5
fail_on            = "high"
format             = "text"
```

| Field | Default | Description |
|---|---|---|
| `enforce_safe_email` | `true` | Warn when git user email is not a GitHub no-reply address |
| `auto_gitignore` | `true` | Generate and maintain a SecureGitX section in `.gitignore` |
| `entropy_threshold` | `4.5` | Shannon entropy threshold for flagging high-entropy tokens |
| `fail_on` | `"high"` | Block commits with findings at or above this severity: `low` · `medium` · `high` · `critical` |
| `format` | `"text"` | Output format: `text` or `json` |

Environment variable overrides (useful in CI):

```sh
SGX_FAIL_ON=critical securegitx scan --tracked
SGX_FORMAT=json      securegitx scan --staged
```

The config file is never executed. Unknown keys are ignored with a warning.

---

## What it detects

### Content rules

| ID | Rule | Severity | Example pattern |
|---|---|---|---|
| SGX001 | Database URL with credentials | critical | `postgres://user:pass@host` |
| SGX002 | Generic database URL | critical | `sqlserver://user:pass@host` |
| SGX003 | AWS access key ID | critical | `AKIA...` (20 chars) |
| SGX004 | AWS secret access key | critical | near `aws_secret_access_key =` |
| SGX005 | GitHub token | critical | `ghp_`, `gho_`, `github_pat_` |
| SGX006 | Stripe key | critical | `sk_live_`, `sk_test_`, `rk_live_` |
| SGX007 | AI provider key | high | `sk-live-`, `sk-prod-`, `ai-key-` |
| SGX008 | JWT token | high | `eyJ...` three-part base64 |
| SGX009 | Slack bot token | high | `xoxb-` |
| SGX010 | Slack user token | high | `xoxp-` |
| SGX011 | Firebase server key | high | `AAAA...` 140+ chars |
| SGX012 | PEM private key header | critical | `-----BEGIN RSA PRIVATE KEY-----` |
| SGX013 | Google OAuth client secret | critical | `0GOCSPX-` |

### Filename rules

| ID | Rule | Severity | Examples |
|---|---|---|---|
| SGX101 | SSH private key file | critical | `id_rsa`, `id_ed25519` |
| SGX102 | PEM / key file | critical | `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| SGX103 | Environment file | high | `.env`, `.env.local`, `.env.production` |
| SGX104 | Secrets directory | high | `secrets/`, `credentials/`, `private/` |

### Entropy heuristic

In addition to named rules, SecureGitX flags long tokens (20+ characters) with high Shannon entropy that no named rule caught. These are marked with confidence `low` and severity `medium` — they indicate something worth reviewing, not a guaranteed secret.

### Allowlist

To suppress a false positive, add an entry to `.securegitx.toml`:

```toml
[[allowlist]]
rule_id = "SGX008"
path    = "tests/*"
value   = "eyJhbGciOiJIUzI1NiJ9"
comment = "test fixture JWT — not a real token"
```

| Field | Description |
|---|---|
| `rule_id` | Rule to suppress, or `"*"` for any rule |
| `path` | File glob to match, or `"*"` for any path |
| `value` | Substring of the matched value, or `"*"` for any value |
| `comment` | Why this suppression is safe (required for review) |

---

## .gitignore generation

`securegitx init` detects your project type from manifest files and generates a selective `.gitignore`. It manages its own clearly-marked section and never touches content you wrote:

```
# >>> SecureGitX managed — do not edit this block manually
# SecureGitX local state
.securegitx/
.securegitx.toml

# Security — credentials and keys
*.env
*.pem
*.key
...

# Python
__pycache__/
.venv/
...
# <<< SecureGitX
```

Detection order:

| Markers found | Detected type |
|---|---|
| `pyproject.toml`, `requirements.txt`, `setup.py` | Python |
| `package.json`, `tsconfig.json` | Node |
| `go.mod` | Go |
| `Cargo.toml` | Rust |
| `pom.xml`, `build.gradle` | Java |
| `composer.json` | PHP |
| None of the above | Generic (conservative) |

Only patterns relevant to the detected type are added. A Python project does not get `node_modules/`. A Node project does not get `__pycache__/`.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings at or above the threshold |
| `1` | Blocked — findings found above threshold |
| `2` | Usage or config error |
| `3` | Git error (not a repo, detached HEAD, git not found) |
| `4` | Rule validation error |

---

## Local state

The daemon and init command write to `.securegitx/` in your repo root. This directory is always added to `.gitignore` and never committed.

```
.securegitx/
├── cache/
│   ├── scan_result.json        ← last background scan result
│   └── gitignore_suggestions.json  ← pending suggestions from daemon
├── logs/
│   └── daemon.log              ← structured daemon log
└── daemon.pid                  ← daemon process ID
```

---

## Development

```sh
make install    # install with dev dependencies
make test       # run tests
make coverage   # tests with coverage report
make rules      # validate and list rules
```

Rules live in `src/securegitx/rules/rules.json`. See [docs/rules-format.md](docs/rules-format.md) for the format reference and guidance on writing new rules.

To contribute a rule, follow the format guide and open a pull request. Include at least two `examples` and two `non_examples` so the pattern can be verified without real credentials.

---

## Architecture

```
src/securegitx/
├── cli.py              command dispatcher — no scanning logic
├── scanner.py          filename, content, diff, entropy checks
├── rules/
│   ├── __init__.py     Rule + AllowEntry types, loaders
│   ├── rules.json      rule definitions
│   └── allowlist.json  suppression entries
├── gitops.py           git subprocess calls — no rule logic
├── hooks.py            hook install / uninstall / status
├── config.py           TOML loader — never executes config
├── report.py           text and JSON output formatters
├── terminal.py         color, icons, banner
├── project_detect.py   evidence-based project type detection
├── gitignore_builder.py  selective managed-section generator
└── daemon.py           advisory background file watcher
```

The hook is the only enforcement point. The daemon, CLI scan, and gitignore builder are advisory — they inform and suggest, but the commit gate lives entirely in the pre-commit hook path.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).