# Contributing to SecureGitX

Thank you for considering contributing to **SecureGitX**!  

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Commit Message Convention](#commit-message-convention)

---

---

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).  

---

## How Can I Contribute?

Contributions are welcome in the following areas:

- Performance improvements
- Cross-platform compatibility
- Documentation
- `.gitignore` templates


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


## Running Tests

Run the full suite:

```bash
pytest
```

---

## Commit Message Convention

This project use [Conventional Commits](https://www.conventionalcommits.org):

