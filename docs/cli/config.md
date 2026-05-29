---
title: config
category: cli
order: 6
summary: Configure SecureGitX via .securegitx.toml and environment variable overrides.
related: docs/cli/init,docs/cli/scan
---

# config

SecureGitX reads configuration from `.securegitx.toml` in the repo root. Running `securegitx init` creates this file with defaults.

## Fields

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
| `auto_gitignore` | `true` | Generate and maintain the SecureGitX section in `.gitignore` |
| `entropy_threshold` | `4.5` | Shannon entropy threshold for flagging high-entropy tokens |
| `fail_on` | `"high"` | Block commits at or above this severity: `low` · `medium` · `high` · `critical` |
| `format` | `"text"` | Output format: `text` or `json` |

## Environment variable overrides

| Variable | Equivalent field |
|---|---|
| `SGX_FAIL_ON` | `fail_on` |
| `SGX_FORMAT` | `format` |

Environment variables take precedence over the config file and CLI flags. Useful for CI without modifying the committed config.

```sh
SGX_FAIL_ON=critical securegitx scan --tracked
```

## Allowlist

False positives can be suppressed in the same config file:

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
| `comment` | Required — reason this suppression is safe |

## Security

The config file is **never executed**. Unknown keys are ignored with a warning. No shell expansion or dynamic evaluation occurs.