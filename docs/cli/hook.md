---
title: hook
category: cli
order: 2
summary: Install, uninstall, and inspect the pre-commit hook that enforces scanning on every commit.
related: docs/cli/scan,docs/develop/architecture
---

# hook

Manage the pre-commit hook that fires `securegitx scan --staged` before every `git commit`.

## Commands

```sh
securegitx hook install    # install the pre-commit hook
securegitx hook uninstall  # remove the hook (restores backup if one existed)
securegitx hook status     # check whether the hook is installed and managed by SecureGitX
```

## hook install

Writes the hook script to `.git/hooks/pre-commit`. If a hook already exists at that path, it is backed up to `.git/hooks/pre-commit.sgx-backup` before being replaced.

The installed hook:

```sh
#!/usr/bin/env sh
securegitx scan --staged
```

## hook uninstall

Removes the managed hook. If a backup exists at `.git/hooks/pre-commit.sgx-backup`, it is restored automatically.

## hook status

Prints whether the hook exists, whether it is managed by SecureGitX, and whether a backup is present.

## Bypassing the hook

```sh
git commit --no-verify -m "message"
```

Use sparingly. `--no-verify` skips all hooks, not just SecureGitX. Any bypassed commits should be reviewed before pushing.

## Notes

The hook is the only enforcement point. Nothing else blocks commits — not the daemon, not the CLI scan command. The invariant is local and unconditional.