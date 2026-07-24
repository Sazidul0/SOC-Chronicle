# Contributing to soc-chronicle

First off, thank you for considering contributing to `soc-chronicle`. It's people like you that make open-source software such a great community!

## Development Setup

1. Fork the repo and clone it locally.
2. Install the development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
3. Set up pre-commit hooks. We require this to ensure code quality and security checks pass before commits:
   ```bash
   pre-commit install
   ```

## Workflow

1. Create a new branch (`git checkout -b feature-or-bugfix-name`).
2. Make your changes.
3. Add tests to cover your changes.
4. Run the test suite:
   ```bash
   pytest
   ```
5. Ensure pre-commit checks pass:
   ```bash
   pre-commit run --all-files
   ```
6. Commit your changes and push to your fork.
7. Submit a Pull Request.

## Coding Standards

- We use `ruff` for formatting and linting.
- We use `mypy` for static type checking. All code must be strictly typed.
- We use `bandit` to ensure no insecure coding patterns are introduced.
