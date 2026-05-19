# Contributing to Bastion

Thanks for your interest in improving Bastion! Contributions of all kinds are
welcome — code, tests, docs, examples, and bug reports.

## Where to start

- Browse [open issues](https://github.com/SoumilBhandari/Bastion/issues),
  especially those labeled
  [`good first issue`](https://github.com/SoumilBhandari/Bastion/labels/good%20first%20issue).
- Found a bug or have an idea?
  [Open an issue](https://github.com/SoumilBhandari/Bastion/issues/new/choose).
- For larger work, check the roadmap in `README.md` and comment on (or open) the
  relevant issue first, so efforts don't collide.

## Development setup

```bash
git clone https://github.com/SoumilBhandari/Bastion
cd Bastion
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

All four must pass — CI runs them on Python 3.11, 3.12, and 3.13.

## Guidelines

- Keep changes focused — one concern per pull request.
- Add or update tests for any behavior change.
- Record user-facing changes in `CHANGELOG.md` under `## [Unreleased]`.

## Code of Conduct & security

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).
To report a security vulnerability, see [SECURITY.md](SECURITY.md).
