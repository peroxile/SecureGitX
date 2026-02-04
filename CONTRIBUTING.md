# Contributing to SecureGitX

Thank you for considering contributing to **SecureGitX**!  
We welcome pull requests, bug reports, and feature ideas.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Making Changes](#making-changes)
- [Commit Message Convention](#commit-message-convention)
- [Pull Request Guidelines](#pull-request-guidelines)

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).  
Be kind, respectful, and assume best intentions.

## How Can I Contribute?

- Report bugs or security issues
- Suggest new scan patterns / project types
- Improve documentation
- Add or improve tests
- Fix typos or enhance UX
- Port to other shells (fish, zsh, etc.)

## Development Setup

```bash
git clone https://github.com/peroxile/SecureGitX.git
cd SecureGitX
```

### Install Bats (for running tests) — one time only

```bash
git clone https://github.com/bats-core/bats-core.git /tmp/bats
/tmp/bats/install.sh /usr/local
```

## Running Tests

```bash
# Run the entire test suite
tools/bats-core/bin/bats tests

# Run only one file
tools/bats-core/bin/bats tests/test_scan.bats
```

All tests must pass before we merge any PR.

## Making Changes

1. Fork & clone the repo
2. Create a feature branch:
   ```bash
   git checkout -b feat/add-awesome-feature
   ```
3. Make your changes
4. Add/update tests if possible
5. Run the test suite locally
6. Commit with a clear message (see below)
7. Open a Pull Request

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

## Pull Request Guidelines

- [ ] Tests pass (`bats tests`)
- [ ] No sensitive real secrets are committed
- [ ] Changes are clearly described in the PR
- [ ] PR title follows the conventional commit style

## Questions / Ideas?

Just open an issue or ping @peroxile in any PR.

Let's build! 
