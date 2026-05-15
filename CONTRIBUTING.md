# Contributing to mcpwarden

Thanks for your interest in improving mcpwarden.

## Development setup

```bash
git clone https://github.com/SoumilBhandari/mcpwarden
cd mcpwarden
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Before opening a pull request

Run the same checks CI runs:

```bash
ruff check .
ruff format --check .
mypy
pytest
```

All four must pass. CI runs them on Python 3.11, 3.12, and 3.13.

## Guidelines

- Keep changes focused — one concern per pull request.
- Add or update tests for any behavior change.
- Record user-facing changes in `CHANGELOG.md` under `## [Unreleased]`.
- mcpwarden is built milestone by milestone; check the roadmap in `README.md`
  before starting larger work so efforts do not collide.
