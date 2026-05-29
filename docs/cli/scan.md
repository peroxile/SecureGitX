---
title: scan
category: cli
order: 1
summary: Scan staged or tracked files for secrets, sensitive filenames, and high-entropy tokens.
related: docs/cli/hook,docs/cli/init
---

# scan

Inspect staged changes or all tracked files for secrets before they leave your machine.

## Usage

```sh
securegitx scan --staged
securegitx scan --tracked
```

## Options

| Option | Description |
|---|---|
| `--staged` | Scan staged diff only — used automatically by the pre-commit hook |
| `--tracked` | Audit all tracked files in the working tree |
| `--format text\|json` | Output format. Defaults to config value (`text`) |
| `--fail-on low\|medium\|high\|critical` | Override severity threshold for this run only |
| `--quiet` | Suppress output; report via exit code only |

## Examples

```sh
# Default: scan what's staged right now
securegitx scan --staged

# Full audit, JSON output, only fail on critical
securegitx scan --tracked --format json --fail-on critical

# Scripting: exit code only
securegitx scan --staged --quiet && git commit -m "..."
```

## Environment overrides

```sh
SGX_FAIL_ON=critical securegitx scan --tracked
SGX_FORMAT=json      securegitx scan --staged
```

Environment variables override both config and CLI flags.

## Notes

The hook calls `securegitx scan --staged` automatically. You only need to call `scan` directly when auditing outside of a commit workflow — CI pipelines, manual checks, scripting.