# CLAUDE.md

This file provides guidance for AI assistants working with this repository.

## Project Overview

**Demo-project** is a Python project in early development. The repository is initialized with a Python-oriented `.gitignore` but does not yet contain application code, a build system, or a test suite.

## Repository Structure

```
Demo-project/
├── .gitignore       # Python project gitignore (comprehensive)
├── README.md        # Project description
└── CLAUDE.md        # This file
```

## Tech Stack

- **Language**: Python
- **Package manager**: Not yet configured (`.gitignore` covers pip, poetry, pdm, uv, pipenv, pixi)
- **Testing**: Not yet configured (`.gitignore` covers pytest, tox, nox, coverage)
- **Linting**: Not yet configured (`.gitignore` covers ruff, mypy, pyre, pytype)
- **Documentation**: Not yet configured (`.gitignore` covers Sphinx, mkdocs)

## Development Workflows

No build system, test runner, or linting tools are configured yet. When these are added, update this section with the relevant commands.

<!-- Example (uncomment/replace when tools are set up):
### Setup
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Testing
```bash
pytest
```

### Linting & Formatting
```bash
ruff check .
ruff format .
```

### Type Checking
```bash
mypy .
```
-->

## Conventions for AI Assistants

### General

- Read existing code before proposing changes.
- Keep changes minimal and focused on the task at hand.
- Do not add features, refactoring, or "improvements" beyond what is requested.
- Avoid introducing security vulnerabilities (command injection, XSS, SQL injection, etc.).

### Python Style (when code is added)

- Follow PEP 8 conventions.
- Use type hints for function signatures.
- Prefer f-strings for string formatting.
- Use `pathlib.Path` over `os.path` for file system operations.
- Write docstrings for public functions and classes.

### Git

- Write clear, concise commit messages describing the "why" not just the "what".
- Keep commits focused on a single logical change.
- Never commit secrets, credentials, or `.env` files.

### Testing (when a test suite is added)

- Place tests alongside source code or in a `tests/` directory.
- Name test files `test_*.py` and test functions `test_*`.
- Run the full test suite before pushing changes.

## Key Files

| File | Purpose |
|------|---------|
| `.gitignore` | Excludes Python bytecode, virtual envs, IDE artifacts, build outputs |
| `README.md` | Project description |
| `CLAUDE.md` | AI assistant guidance (this file) |
