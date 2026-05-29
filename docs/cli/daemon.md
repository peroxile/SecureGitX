---
title: daemon
category: cli
order: 5
summary: Optional background watcher that monitors the git index and queues .gitignore suggestions.
related: docs/cli/init,docs/develop/architecture
---

# daemon

An optional background process that watches your git index for staging changes.

The daemon is **off by default**. It must be started explicitly.

## Commands

```sh
securegitx daemon start   # start the watcher (runs in background)
securegitx daemon stop    # stop the running daemon
securegitx daemon status  # show status and last scan result
```

## What the daemon does

- Watches the git index for newly staged or created untracked files.
- When it detects a file matching a sensitive filename pattern, it queues a `.gitignore` suggestion.
- It **never modifies files on its own** — all suggestions are advisory.

## Applying suggestions

Queued `.gitignore` suggestions are picked up when you re-run `init`:

```sh
securegitx init
```

This is the only way to apply daemon suggestions to your `.gitignore`.

## Local state

The daemon writes to `.securegitx/` in your repo root:

```
.securegitx/
├── cache/
│   ├── scan_result.json           ← last background scan result
│   └── gitignore_suggestions.json ← pending suggestions
├── logs/
│   └── daemon.log                 ← structured log
└── daemon.pid                     ← process ID
```

This directory is always excluded from commits.

## Notes

The daemon is not required for secret scanning. The pre-commit hook provides the enforcement guarantee independently. The daemon is a convenience layer for teams that want proactive `.gitignore` maintenance.