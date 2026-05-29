---
title: direct commit
category: cli
order: 7
summary: Scan staged changes and commit in one step if clean.
related: docs/cli/scan,docs/cli/hook
---

# direct commit

A shorthand that combines scanning and committing into one command.

## Usage

```sh
securegitx "your commit message"
```

## What it does

Equivalent to:

```sh
securegitx scan --staged && git commit -m "your commit message"
```

If the scan finds findings at or above the configured threshold, the commit is blocked and the findings are printed. If the scan is clean, `git commit` runs immediately.

## When to use it

Useful when you want a single command instead of the `git add` + `git commit` two-step. The pre-commit hook provides the same guarantee automatically — this is a convenience alias, not an additional enforcement layer.

## Notes

- This does **not** replace the hook. If you use direct commit without the hook installed, and something bypasses the scan (e.g., `git commit` called directly), there is no backstop.
- Always run `securegitx hook install` as part of repo setup. Use direct commit as a workflow shorthand on top of that.