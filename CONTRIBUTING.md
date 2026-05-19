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

## How changes get in

Bastion keeps two long-lived branches:

- **`dev`** — the integration branch. All contributions land here first, and it's
  the repository's default branch, so pull requests target it automatically.
- **`main`** — the stable branch. It only moves when `dev` is merged into it, and
  releases are tagged from `main`.

You don't need write access to this repository to contribute — you work from your
own fork:

1. **Fork** the repo with the *Fork* button on GitHub. That gives you a personal
   copy you can push to.
2. **Clone your fork** and create a branch off `dev`:

   ```bash
   git clone https://github.com/<your-username>/Bastion
   cd Bastion
   git checkout dev
   git checkout -b short-description-of-change
   ```

3. Make your changes, commit them, and **push the branch to your fork**.
4. **Open a pull request** targeting this repo's `dev` branch. CI runs on it
   automatically, and a maintainer reviews from there.

Once it's merged into `dev`, your change ships to `main` with the next release.

## Development setup

Once you've forked and cloned (see above), set up the environment:

```bash
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
