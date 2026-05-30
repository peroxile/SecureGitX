---
title: rules
category: cli
order: 4
summary: List, validate, update, and roll back the detection rules used by the scanner.
related: docs/default/rules-format,docs/cli/scan
---

# rules

Manage the detection rule set that drives the scanner.

## Commands

```sh
securegitx rules list      # show all loaded rules: ID, severity, type, name
securegitx rules validate  # verify rules.json is valid and all patterns compile
securegitx rules updated   # fetch the latest rules from upstream
securegitx rules rollback  # revert to the previous rules version
```

## rules list

Prints a table of all currently active rules. Columns: `ID`, `name`, `type` (`content` or `filename`), `severity`.

```
SGX001  Database URL with credentials   content   critical
SGX002  Generic database URL            content   critical
SGX003  AWS access key ID               content   critical
...
```

## rules validate

Loads `rules.json`, checks schema validity, and compiles every regex pattern. Exits non-zero if any pattern fails to compile or if required fields are missing.

Run this after editing rules locally before committing.

## rules updated

Fetches the latest `rules.json` from the upstream distribution. The current file is backed up before replacement.

## rules rollback

Restores the backup created by `rules updated`. Only one level of rollback is supported.

## Rule structure

Rules live in `src/securegitx/rules/rules.json`. See the [Rules Format](/docs/default/rules-format) reference for the full schema.

Each rule requires at least two `examples` (strings that should match) and two `non_examples` (strings that must not match) for verification.