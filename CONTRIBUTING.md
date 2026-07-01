# Contributing to SecureGitX

Thank you for considering contributing to **SecureGitX**!  
We welcome pull requests, bug reports, and feature ideas.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Philosophy](#philosophy)
- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Architectural Boundaries](#architectural-boundaries)
- [Rule Contributions](#rule-contributions)
- [Good Rule Properities](#good-rule-properties)
- [Commit Message Convention](#commit-message-convention)
- [Security Reports](#security-reports)
- [Pull Request Guidelines](#pull-request-guidelines)

---

## Philosophy

SecureGitX is built around a few strict invariants:

- Secret scanning must remain local-only
- The pre-commit hook is the only enforcement edge
- Scanning logic must remain deterministic and testable
- Rules must be data-driven, not hardcoded into CLI logic
- Config must never execute code
- Git operations must stay isolated from scanning logic
- Advisory systems (daemon, gitignore generation) must never mutate repositories implicitly

---

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).  
Be kind, respectful, and assume best intentions.

---

## How Can I Contribute?

Contributions are welcome in the following areas:

- Secret detection rules
- False-positive reduction
- Entropy heuristics
- Git hook reliability
- Performance improvements
- Cross-platform compatibility
- Documentation
- Type safety improvements
- Test coverage
- Daemon reliability
- `.gitignore` templates
- Project type detection
- CLI UX improvements


---

## Development Setup


Clone the repository:

```bash
git clone https://github.com/peroxile/SecureGitX.git
cd SecureGitX
````

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install development dependencies:

```bash
pip install -e ".[dev]"
```
---

## Architectural Boundaries

### scanner.py

Pure scanning logic only.

Must not:

* invoke git
* perform file IO
* mutate repositories
* print to terminal

### gitops.py

Git subprocess wrapper layer only.

Must not:

* contain scan logic
* parse rules
* apply enforcement policy

### report.py

Presentation layer only.

Must not:

* perform scanning
* mutate findings
* invoke git

### hooks.py

Hook installation/removal only.

Must not:

* implement scan logic
* parse diffs
* contain enforcement policy

### config.py

Configuration loading only.

Must never:

* execute arbitrary code
* import user modules
* dynamically evaluate config

### daemon.py

Advisory background system only.

Must never:

* block commits
* mutate tracked files automatically
* become an enforcement dependency

---

## Running Tests

Run the full suite:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=securegitx
```

Run static analysis:

```bash
ruff check .
```

Run type checking:

```bash
pyright
```

All checks should pass before opening a pull request.

---

## Rule Contributions

Rules live in:

```text
src/securegitx/rules/rules.json
```

Every new rule should include:

* unique `id`
* clear `name`
* realistic `description`
* precise regex pattern
* remediation guidance
* examples
* non_examples

Avoid broad regexes that create excessive false positives.

## Good Rule Properties

* deterministic
* low false-positive rate
* narrowly scoped
* provider-aware when possible
* testable without real credentials

---

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org):

```
feat: add support for .env.local files
fix: correct python detection when only pyproject.toml exists
refactor: simplify project type detection
perf: speed up staged file scanning 
test: improve staged secret detection test
docs: update CONTRIBUTING.md
chore: bump version to 1.3.1
```

---

## Pull Request Guidelines

Before opening a PR:

* Ensure tests pass
* Ensure no real secrets exist in commits
* Ensure type checks pass
* Ensure lint checks pass
* Keep PRs focused and minimal
* Explain security implications for detection changes
* Add documentation for behavioral changes

Large architectural changes should be discussed in an issue first.

---

## Security Reports

Report security issues privately through GitHub Security Advisories:

[GitHub Security Advisories](https://github.com/peroxile/SecureGitX/security/advisories)
