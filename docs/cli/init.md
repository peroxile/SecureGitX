---
title: init
category: cli
order: 3
summary: Set up SecureGitX in a repository — creates config, installs the hook, and generates a .gitignore.
related: docs/cli/hook,docs/cli/scan
---

# init

Bootstrap SecureGitX in the current repository. Run this once after installing.

## Usage

```sh
securegitx init
securegitx init --no-gitignore
```

## What init does

1. Creates `.securegitx.toml` in the repo root with default configuration.
2. Detects your project type from manifest files and generates a project-aware `.gitignore`.
3. Adds `.securegitx.toml` and `.securegitx/` to `.gitignore` so config and local state are never committed.
4. Picks up any queued suggestions from the daemon (if it has been running).

## Flags

| Flag | Description |
|---|---|
| `--no-gitignore` | Skip `.gitignore` generation entirely |

## Project type detection

`init` inspects the repo root for manifest files and selects a template accordingly:

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

## .gitignore managed section

`init` manages its own clearly marked section. It never touches content outside that block:

```
# >>> SecureGitX managed — do not edit this block manually
.securegitx/
.securegitx.toml
*.env
*.pem
*.key
...
# <<< SecureGitX
```

Re-running `init` updates only this section.