# Changelog

All notable changes to Bastion are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Resource reads and prompt fetches are now governed and audited. Previously the
  middleware only mediated `tools/call`, so `resources/read` and `prompts/get`
  bypassed permissions and the audit log entirely — under a default-deny policy
  an agent could still read a resource, completely unlogged. They now run the
  permission check (default-deny denies them) and are recorded with a new audit
  `kind` field (`tool` / `resource` / `prompt`).
- Guards now inspect structured arguments. A block guard matching a string
  command was evaded by passing an argv array (e.g. `["rm", "-rf", "/"]`); guards
  now test each scalar leaf and a space-joined command-line form of list and dict
  values.

## [1.0.1] - 2026-05-29

### Fixed

- `bastion --version` / `bastion version` reported a stale hardcoded `0.1.0`;
  the version now derives from installed package metadata so it tracks
  `pyproject.toml` and can't drift.
- Guard rules with an invalid regex `pattern` or JSONPath `arg` are now caught
  by `bastion validate` with a clear message, instead of passing validation and
  crashing at `bastion run`.
- A corrupt or hand-edited budget checkpoint no longer crashes gateway startup:
  an unreadable file starts fresh and individual malformed entries are skipped.
- `.gitignore` now covers the budget checkpoint (`bastion-budgets.json`).

### Security

- `bastion dashboard` and the HTTP gateway now warn when bound to a non-loopback
  host, since neither is authenticated.
- Added `docs/security.md` documenting the operational security model (secrets
  in the audit log, unauthenticated surfaces, operator-trusted guard regexes).

## [1.0.0] - 2026-05-25

### Added

- `examples/full/`: a runnable example showing every policy feature together —
  permissions, rate limits, budgets, argument guards — with audit and cost on.

### Changed

- README polished for the 1.0 release: PyPI / CI / Python / license badges,
  links into `docs/configuration.md` and `examples/`, milestones fully marked
  complete.
- PyPI Development Status classifier graduated from `3 - Alpha` to
  `5 - Production/Stable`.

## [0.4.0] - 2026-05-25

### Added

- New CLI commands powered by an audit-log reader:
  - `bastion logs` — show past audit records with optional `--tool` glob,
    `--outcome` filter, and `-n/--limit` for the last N records.
  - `bastion stats` — summarise the audit log: total calls, outcomes, top tools.
  - `bastion tail` — follow the audit log, streaming new records as they're
    recorded (Ctrl+C to exit).
  - `bastion init` — scaffold a starter `bastion.yaml` (refuses to overwrite
    unless `--force`).
- `docs/configuration.md`: a full reference for every `bastion.yaml` section.
- `examples/permissions/`: a runnable example showing the per-tool allow/deny
  pattern (most-specific glob wins) with audit enabled.
- CI now also runs on Windows (Python 3.12) alongside the Ubuntu 3.11/3.12/3.13
  matrix.

## [0.3.0] - 2026-05-25

### Added

- Argument guards: a `policy.guards` config section with regex-on-JSONPath
  rules that operate on tool-call arguments. Each rule has a `name`, a glob
  `match` for which tools it applies to (defaults to `*`), a JSONPath `arg`,
  a regex `pattern`, and an `action` of either `block` (raise a policy denial
  before the upstream sees the call, recorded as `denied` in the audit log
  with the rule name in `error`) or `redact` (replace the matched value with
  `***` in the audit log only, leaving the actual call unchanged).

## [0.2.0] - 2026-05-19

### Added

- Rate limiting: a `policy.rate_limits` config section with per-rule token
  buckets. Each rule has a `name`, a `scope` (`global` or `per_tool`), a
  `max_per_minute` cap, and an optional `burst`. Calls past a rule's budget
  are blocked before reaching the upstream and recorded in the audit log
  with `outcome: denied` and the rule name in `error`.
- Budgets: a `policy.budgets` config section with per-rule fixed-window
  counters. Each rule has a `name`, a `scope` (`global` or `per_tool`), a
  `per` window (`minute`, `hour`, or `day`), and at least one of
  `max_calls` or `max_cost`. Calls past a budget are blocked and recorded
  the same way as rate-limit denials. Counters are persisted to
  `policy.budget_checkpoint` (default `bastion-budgets.json`) so caps
  survive a restart; set the path to `null` to disable.
- Cost model: a new top-level `cost` config section with `default_per_call`
  and a `per_tool` map of overrides. The resolved cost is what budget rules
  with a `max_cost` charge against.

## [0.1.0] - 2026-05-19

### Added

- Project skeleton: packaging (`pyproject.toml`), Apache-2.0 license, CI.
- YAML configuration schema and loader covering the `gateway` and `upstreams`
  sections, with friendly validation errors.
- Gateway that proxies and aggregates one or more upstream MCP servers over
  stdio and HTTP transports.
- CLI: `bastion run`, `bastion validate`, `bastion dashboard`, `bastion version`, and root `--version` flag.
- Audit logging: every tool call through the gateway is recorded to a JSON
  Lines file. New optional `audit` config section (`enabled`, `path`,
  `log_arguments`).
- Local web dashboard (`bastion dashboard`): a browser view of the audit log
  with live tool-call history and summary stats.
- Permissions: a `policy` config section with per-tool allow/deny rules
  (glob-matched; the most specific rule wins). Denied calls are blocked before
  reaching the upstream and recorded in the audit log with a `denied` outcome.
- PEP 561 `py.typed` marker, so downstream type checkers pick up Bastion's
  shipped type hints.
