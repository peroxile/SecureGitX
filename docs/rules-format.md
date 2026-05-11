# SecureGitX Rules Format

Rules live in `rules/rules.json`. The file is validated against `rules/schema.json` on load.

## Bundle structure

```json
{
  "version": "1.0.0",
  "rules": [ ... ]
}
```

`version` follows semantic versioning. Increment the minor version when adding rules, patch for fixes, major for breaking schema changes.

---

## Rule fields

| Field | Required | Type | Description |
|---|---|---|---|
| `id` | yes | string | Stable identifier. Format: `SGX` + 3 digits. Content rules: `SGX001`–`SGX099`. Filename rules: `SGX101`–`SGX199`. |
| `name` | yes | string | Snake_case short name. Used in output and allowlist references. |
| `pattern` | yes | string | Python `re` regex. See matching semantics below. |
| `type` | yes | `"filename"` or `"content"` | Determines which scanner stage applies the rule. |
| `severity` | yes | `"low"`, `"medium"`, `"high"`, `"critical"` | Controls exit code threshold. |
| `description` | no | string | One sentence explaining what the rule detects and why. |
| `tags` | no | array of strings | Categories: `aws`, `database`, `token`, `private-key`, etc. |
| `enabled` | no | boolean | Defaults to `true`. Set `false` to disable without deleting. |
| `case_sensitive` | no | boolean | Defaults to `false`. Set `true` for patterns where case matters (e.g. AWS key prefix). |
| `examples` | no | array of strings | Strings the pattern must match. Used in tests. |
| `non_examples` | no | array of strings | Strings the pattern must not match. Used in tests. |
| `remediation` | no | string | Shown to the user when a finding is reported. |

---

## Matching semantics

- **Filename rules** (`"type": "filename"`) — applied via `re.search()` against the full file path as returned by `git ls-files` or `git diff --name-only`. Paths use forward slashes regardless of OS.
- **Content rules** (`"type": "content"`) — applied via `re.search()` against each added line in a diff, or each line of a file in audit mode.

`re.search()` is used, not `re.fullmatch()`. Anchor with `^` or `$` when you need full-string matching.

---

## Filename matching examples

Match only `id_rsa` and similar at any path depth:
```
(^|/)id_(rsa|dsa|ecdsa|ed25519)$
```

Match `.env` but not `.env.example`:
```
\.env(?!\.(example|sample|template|dist|test))(?:\.[a-z]+)?$
```

Match files in a `secrets/` directory anywhere in the tree:
```
^(secrets?|private|credentials?|creds)/
```

---

## Writing content rules

### Be specific about prefix shape

Prefer:
```
AKIA[0-9A-Z]{16}
```
Over:
```
[A-Z0-9]{20}
```

The second form matches too many things. Anchor on a known prefix whenever possible.

### Use non-capturing groups for alternation

```
(?:postgres|mysql|redis)://[^:@\s"']+:[^@\s"']{3,}@
```

### Set `case_sensitive: true` for patterns where prefix case is fixed

AWS keys, GitHub tokens, Stripe keys — these have fixed-case prefixes. Setting `case_sensitive: true` avoids matching lowercased variable names that happen to contain the pattern.

### Avoid catastrophic backtracking

Patterns like `(.+)+` or `(a+)+` applied to long lines can cause exponential backtracking. Prefer character classes with explicit exclusions over greedy wildcards.

Bad:
```
password=(.+)@
```

Good:
```
password=[^@\s"']{3,}@
```

---

## Allowlist format

Allowlist entries live in `rules/allowlist.json`.

```json
{
  "version": "1.0.0",
  "entries": [
    {
      "id": "AL001",
      "description": "AWS documentation placeholder key",
      "type": "exact",
      "value": "AKIAIOSFODNN7EXAMPLE",
      "rule_id": "SGX003"
    }
  ]
}
```

### Entry types

| Type | Behavior |
|---|---|
| `exact` | Full string equality |
| `substring` | `value in matched_text` |
| `regex` | `re.search(value, matched_text)` |
| `path_prefix` | `file_path.startswith(value)` |

### `rule_id` scoping

- Set `rule_id` to a specific rule ID to limit the allowlist entry to that rule only.
- Set `rule_id` to `null` to suppress all rules for the given condition (e.g. a path prefix that contains intentional test secrets).

---

## Adding a new rule: checklist

1. Pick the next available ID in the correct range.
2. Write the pattern. Test it manually with Python `re.search()`.
3. Add at least two `examples` and at least one `non_example`.
4. Verify the `test_rules.py` parametrized tests cover the new ID.
5. Run `securegitx rules validate` to confirm the schema passes.
6. Run the full test suite.

---

## ID ranges

| Range | Purpose |
|---|---|
| `SGX001`–`SGX099` | Content pattern rules |
| `SGX100`–`SGX199` | Filename pattern rules |
| `SGX_ENTROPY` | Reserved — internal entropy heuristic (not in rules.json) |