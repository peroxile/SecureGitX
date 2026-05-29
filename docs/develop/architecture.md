---
title: architecture
category: develop
order: 1
summary: Module layout, enforcement model, and design invariants.
related: docs/develop/development,docs/develop/exitcodes
---

# architecture

## Module layout

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

## Enforcement model

The hook is the **only enforcement point**. This is a deliberate design invariant.

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

The daemon, CLI scan, and gitignore builder are advisory — they inform and suggest, but do not block. The commit gate lives entirely in the pre-commit hook path.

## Separation of concerns

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing and command dispatch only. No logic. |
| `scanner.py` | All detection logic: patterns, entropy, allowlist filtering. |
| `gitops.py` | All git subprocess calls. No rule logic. |
| `config.py` | TOML loading and validation. Never executes user config. |
| `report.py` | Formatting only. No detection logic. |
| `daemon.py` | File watching only. Never modifies files. |

## Adding a scanner pass

New detection passes (e.g., a new check type) should be added to `scanner.py` and follow the existing contract: take a list of files or diff hunks, return a list of `Finding` objects. The hook calls scanner passes in order and aggregates findings before making the block/allow decision.