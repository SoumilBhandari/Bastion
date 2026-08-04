# Changelog

All notable changes to Bastion are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — robustness pass

A second round of testing, prompted by a Windows-only CI failure, against
platforms, corrupt inputs and hostile values. Each of these was reproduced
before being fixed.

- **`bastion doctor` and `bastion explain` crashed on Windows** whenever their
  output was piped, redirected or captured — which is always, in CI. They print
  `✓`, and cp1252 has no representation for it, so they died with
  `UnicodeEncodeError` partway through. Glyphs are now chosen against what the
  stream can encode, and the stream degrades rather than raising. Reproducible
  anywhere with `PYTHONIOENCODING=cp1252`.
- **An audit-write failure turned a completed call into a reported failure.**
  The write runs in a `finally`, so a full disk replaced whatever the call was
  about to return — after the side effect had already happened. An agent told a
  call failed retries it. Failures now leave the outcome alone and are reported
  on stderr.
- **A tool called with `1e999` wrote bare `Infinity`** into the log, which is
  not JSON and permanently broke the dashboard API.
- **One byte of invalid UTF-8 took down `logs`, `stats`, `verify`, `doctor` and
  the dashboard**, contradicting the reader's own promise of tolerance.
- **The dashboard could not see tampering in records it had already read**, and
  re-read the whole log on every 1.5-second poll. Reading is incremental now;
  verification re-reads everything on a five-second throttle.
- **An ambiguous permission rule failed open.** Two equally specific rules that
  disagreed were resolved by which was written first, so a config that both
  allowed and denied the same pattern allowed the call. Ties now resolve to
  `deny`, and a config that contradicts itself outright is rejected.
- **A self-referential YAML alias** exhausted the stack instead of being
  reported as a malformed config.
- **A budget checkpoint claiming negative spend** was restored as-is, handing
  back budget that had been spent.
- **`bastion init` into a new directory** printed a traceback; a config path
  that was a directory or a device node was reported as "not found".
- The audit log is written with fixed line endings, so its bytes are identical
  on every platform and its own size accounting is right.

### Changed

- `bastion doctor` now also fails on a permission, guard or response-guard rule
  that matches none of the tools the upstreams actually advertise, and flags a
  `max_cost` budget that can never be reached because every call costs zero.
- Guards: the reference and examples now steer toward `$..name` over `$.name`,
  because the top-level form silently protects nothing when a tool nests its
  arguments.

### Added

- **Tamper-evident audit log.** Each record carries the hash of the record
  before it, so altering, reordering, or deleting one breaks every link after
  it. `bastion verify` walks the chain and names the first record that does not
  hold, with `--include-rotated` to check rotated generations as one sequence.
  This detects tampering rather than preventing it — the head hash it prints is
  the value to anchor somewhere an attacker cannot reach.
- **Response inspection.** Results are now examined on the way back to the
  agent. Credentials in output are masked before they enter the model's context
  (`policy.responses.redact_secrets`, with `allow_secrets_from` for tools whose
  job is returning secrets). Text matching prompt-injection heuristics is
  flagged in the audit log and prefixed with a caution naming it untrusted data
  (`detect_injection`, defaulting to `warn` rather than `block`, because these
  are heuristics and a document *about* prompt injection will trip them).
  Operator-supplied `responses.guards` can redact or block on their own regex.
- **Tool-definition pinning.** Definitions are fingerprinted on first sight and
  compared on every listing after, so a server that changes a tool's description
  after you approved it is noticed. `bastion pin` shows what changed with the
  pinned and current text side by side; `--approve` accepts it. Under
  `policy.pinning.on_change: block` a drifted tool is quarantined — hidden from
  listings and refused on call.
- **Built-in credential redaction** in the audit log (`audit.redact_secrets`),
  covering AWS, GitHub, Slack, Stripe, Google, Anthropic/OpenAI-style keys,
  JWTs, private-key blocks, `Authorization` headers, and credentials embedded in
  URLs. Arguments whose *name* looks sensitive are masked whole.
- **Environment interpolation** in the config: `${VAR}`, `${VAR:-default}`, and
  `$${VAR}` to escape. A `.env` beside the config is read too, which matters
  over stdio where the MCP client controls the process environment.
- **Call timeouts** (`timeouts.default_seconds`, default 120s, with `per_tool`
  overrides). A wedged upstream previously hung the agent indefinitely.
- **Policy-filtered listings.** Denied tools, resources, resource templates, and
  prompts are removed from listings (`policy.hide_denied`), so an agent is never
  offered something it cannot use.
- **Audit log rotation** (`audit.max_bytes`, `audit.keep`) and optional
  `audit.fsync`. The chain continues across a rotation.
- **`bastion explain <tool>`** — traces every policy layer for a call, not just
  the first to refuse, including guards against `--args`, rate-limit headroom,
  budget state, resolved cost and timeout, and listing visibility. Read-only.
- **`bastion doctor`** — connects to each upstream, verifies the audit chain,
  and reviews the config for settings that are legal but usually unintended.
- **Benchmarks** (`benchmarks/bench_gateway.py`). On an M4 Max the full stack
  adds ~0.33 ms to a ~2.4 ms call.
- Audit records gained `cost` (what the call was actually charged, `null` if it
  never ran) and `flags` (response-guard findings), both surfaced in
  `bastion logs`, `bastion tail`, and the dashboard.
- `examples/hardened/` — a default-deny containment config, and an index of the
  examples.

### Fixed

The following were found by an adversarial review of this branch, and are worth
listing individually because each one made a documented guarantee weaker than it
read.

- **The hash chain could be laundered.** Stripping `hash` and `prev` from the
  leading records let an attacker rewrite any prefix of the log: the rest still
  chained to each other, `verify` reported OK, and the head hash was unchanged,
  so even anchoring the head off-box did not catch it. Unchained records
  followed by a chain that does not open at genesis are now a break.
- **Deleting records from the front of the log verified clean.** Rotation is the
  only legitimate reason a chain starts mid-stream; `verify` and `doctor` now
  fail when it does and nothing was rotated.
- **A record larger than 256 KiB restarted the chain at genesis.** Arguments are
  logged by default and unbounded, so one call carrying a large document made
  every later verification report tampering that never happened. Restarting in
  the gap between a rotation and the next write did the same.
- **Cancelled calls were recorded as successes.** `asyncio.CancelledError`
  derives from `BaseException` and slipped past the audit middleware, so every
  in-flight call at client disconnect was hash-chained into the log as `ok`.
- **Response scanning skipped embedded resources** — the ordinary way MCP
  servers return file contents and fetched pages — so credentials and injection
  payloads in them reached the agent unredacted and unlogged. The injection
  caution also never reached `structured_content`, which is what `result.data`
  returns, and operator `redact` guards never applied there either.
- **`^system:` only matched at the very start of a result**, because the pattern
  is line-anchored but was compiled without `MULTILINE`.
- **The hidden-comment check amplified CPU ~64×** on attacker-chosen output: 100
  KB of bare `<!--` cost 529 ms against 8 ms for prose.
- **Upstream text reached Rich unescaped**, so a tool error containing an
  unmatched tag crashed `bastion logs` and `bastion tail`, and a well-formed one
  could paint styled text into the operator's terminal.
- **Three examples and `bastion init` shipped rules that could never match**,
  using the `<upstream>_<tool>` form against a single upstream, where names pass
  through unprefixed. `examples/hardened/` allowlisted nothing and left the agent
  with no tools; `examples/permissions/` allowed the writes its own comment said
  it blocked. `bastion doctor` now fails on any rule matching no advertised tool.
- **A pin quarantine was never released**, so an upstream that shipped a bad tool
  description and reverted it left that tool unreachable until restart.
- **`audit.fsync` was inert**, and the test covering it asserted only that a line
  had been written — equally true without fsync. Several other tests could not
  fail either; they now can.
- A non-ASCII dashboard token returned 500 instead of 401; a zero or negative
  per-tool timeout was accepted; re-pinning reset a tool's `first_seen`.

- **Failed tool calls were audited as successful.** An upstream tool that raises
  does not propagate an exception through the proxy; FastMCP marshals the
  failure into a result with `is_error=True`. The audit middleware only
  inspected exceptions, so every failed call was recorded with outcome `ok` and
  no error.
- **Config paths were resolved against the working directory**, so
  `bastion run --config ~/mcp/bastion.yaml` wrote the audit log and budget
  checkpoint into whatever directory it happened to be launched from. They now
  read as relative to the config file that declares them.
- **`bastion tail` stopped following after a rotation.** It tracked a byte
  offset, so once the log rotated it seeked past the end of the new, smaller
  file and silently followed nothing.
- **Oversized values bypassed the scanners entirely.** Text past the size cap
  was skipped rather than scanned, so padding a response hid a credential or a
  prompt injection completely. It is now scanned up to the limit.
- The error boundary now covers resource reads and prompt fetches, which reach
  the same upstreams over the same transports; previously only tool calls were
  wrapped, so a transport failure on either leaked a raw traceback to the agent.
- The audit writer keeps its file handle open and flushes each record, instead
  of reopening the file per record.

### Security

- **The dashboard is gated on a per-session token**, printed in the URL at
  startup. It serves the complete audit log — every argument the agent passed —
  and previously did so to anything that could reach the port. `--no-token`
  opts out for use behind an authenticating proxy.

### Changed

- The dashboard reads the log incrementally instead of re-parsing it in full on
  every poll, and shows response-guard findings, spend, filters, and a banner
  when the hash chain does not verify.
- CI runs on macOS alongside Linux and Windows, measures coverage (94%, gated at
  90%), and smoke-runs the benchmark.

## [1.0.2] - 2026-05-29

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
