---
title: exit codes
category: develop
order: 3
summary: Complete reference for SecureGitX exit codes used by the hook, scan command, and all subcommands.
related: docs/cli/scan,docs/cli/hook
---

# exit codes

All SecureGitX commands exit with a consistent set of codes. Use these for scripting, CI integration, and hook behavior.

## Code reference

| Code | Constant       | Meaning                                                                |
| ---- | -------------- | ---------------------------------------------------------------------- |
| `0`  | `EXIT_CLEAN`   | Clean — no findings at or above the configured threshold               |
| `1`  | `EXIT_BLOCKED` | Blocked — one or more findings at or above threshold                   |
| `2`  | `EXIT_USAGE`   | Usage or configuration error                                           |
| `3`  | `EXIT_GIT`     | Git error: not a repository, detached HEAD, or git not found           |
| `4`  | `EXIT_RULES`   | Rule validation error: invalid schema or pattern that fails to compile |

## In the hook

The pre-commit hook exits with the result of `securegitx scan --staged`. Git interprets:

- Exit `0` → commit proceeds.
- Exit non-zero → commit is blocked.

Exit `1` (findings found) and exit `2`/`3`/`4` (errors) all block the commit, but for different reasons. In normal operation you should only see `0` and `1`.

## In CI

```sh
securegitx scan --tracked --format json
echo "Exit: $?"
```

Use `--fail-on critical` to only fail on critical findings and treat lower severities as informational:

```sh
securegitx scan --tracked --fail-on critical
# exits 0 if only medium/high findings exist
# exits 1 if any critical finding exists
```

## Scripting

```sh
securegitx scan --staged --quiet
STATUS=$?

case $STATUS in
  0) echo "Clean" ;;
  1) echo "Secrets found — commit blocked" ;;
  2) echo "Config error" ;;
  3) echo "Git error" ;;
  4) echo "Rules error" ;;
esac
```
