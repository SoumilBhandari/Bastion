# Configuration reference

Bastion reads a single YAML file. The path is, in order of precedence,
the `--config` flag, the `BASTION_CONFIG` environment variable, or
`./bastion.yaml`. The only required section is `upstreams`; everything
else is optional with sensible defaults.

```yaml
gateway:    {}     # how the gateway listens (optional)
upstreams:  {}     # the MCP servers Bastion proxies (required, ≥ 1 entry)
audit:      {}     # audit logging (optional)
cost:       {}     # per-call cost model (optional)
timeouts:   {}     # how long to wait on an upstream (optional)
policy:     {}     # permissions, guards, limits, budgets, responses, pinning (optional)
```

Validate a file without running the gateway with `bastion validate
--config path/to/bastion.yaml`, and check it against the live upstreams with
`bastion doctor`. See `examples/` for runnable configurations.

## Paths are relative to the config file

Every path in the config — `audit.path`, `policy.budget_checkpoint`,
`policy.pinning.path` — is resolved against the directory holding the config
file, not the process working directory. `bastion run --config ~/mcp/bastion.yaml`
writes its audit log next to that config no matter where it was launched from.
Absolute paths are used as given.

## Environment variables

Any string value may reference the environment:

| Form | Meaning |
|---|---|
| `${VAR}` | required — startup fails if it is not set |
| `${VAR:-fallback}` | uses `fallback` when `VAR` is unset or empty |
| `$${VAR}` | a literal `${VAR}`, not a reference |

```yaml
upstreams:
  github:
    url: https://api.githubcopilot.com/mcp/
    headers:
      Authorization: Bearer ${GITHUB_TOKEN}
```

Substitution runs over the parsed document rather than the raw text, so a value
containing `:` or a newline cannot alter the file's structure. Every unresolved
variable is reported at once, each with its location in the file.

A `.env` file beside the config is also read, with the real process environment
taking precedence. This matters over stdio: the MCP client that launches
`bastion run` controls the child's environment, so without the file there is
often no way to hand the gateway a secret at all. Keep `.env` out of version
control.

## `gateway`

How Bastion itself listens for the connecting agent.

| Key | Type | Default | Notes |
|---|---|---|---|
| `transport` | `stdio` \| `http` | `stdio` | |
| `host` | string | `127.0.0.1` | only used by `http` |
| `port` | int (1-65535) | `8765` | only used by `http` |

## `upstreams`

A map of name → upstream MCP server. **At least one entry is required.**
Each upstream is either a **stdio** subprocess (provide `command`) or an
**HTTP** endpoint (provide `url`).

Stdio upstream:

| Key | Type | Notes |
|---|---|---|
| `command` | string | the executable to launch |
| `args` | list[string] | command-line arguments |
| `env` | map[string, string] | extra environment variables |

HTTP upstream:

| Key | Type | Notes |
|---|---|---|
| `url` | string | the HTTP endpoint |
| `headers` | map[string, string] | extra request headers |

Upstream names must start with a letter and contain only letters, digits,
and underscores.

With more than one upstream, tool names are namespaced as
`<upstream>_<tool>` to prevent collisions. With a single upstream, tool
names pass through unchanged.

## `audit`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | |
| `path` | path | `bastion-audit.jsonl` | JSON-Lines file |
| `log_arguments` | bool | `true` | set to `false` to omit args from records |
| `redact_secrets` | bool | `true` | mask recognized credentials in logged arguments |
| `hash_chain` | bool | `true` | link each record to the previous, making edits detectable |
| `fsync` | bool | `false` | force each record to physical disk before the call proceeds |
| `max_bytes` | int ≥ 1 \| null | `100000000` | rotate past this size; `null` never rotates |
| `keep` | int ≥ 0 | `5` | rotated generations to keep (`audit.jsonl.1`, `.2`, …) |

Every governed operation — a tool call, resource read, or prompt fetch —
produces one JSON record per line:

| Field | Notes |
|---|---|
| `call_id` | unique per operation |
| `timestamp` | ISO 8601 UTC |
| `kind` | `tool` / `resource` / `prompt` / `pin` |
| `tool` | the tool name, resource URI, or prompt name |
| `arguments` | after redaction; `null` when `log_arguments` is off |
| `outcome` | `ok` / `error` / `denied` / `cancelled` |
| `duration_ms` | |
| `error` | the reason, on non-`ok` outcomes |
| | `cancelled` means the client went away or aborted the request before it finished |
| `cost` | what the call was charged; `null` if it never ran |
| `flags` | response-guard findings, e.g. `injection:instruction-override` |
| `prev`, `hash` | the hash chain, when `hash_chain` is on |

### Durability

Records are flushed as they are written, so a crashed gateway still leaves a
complete log up to its last call. `fsync: true` additionally forces each record
out to the physical disk, which survives the machine losing power at the cost of
a real disk round trip per call.

### Tamper evidence

With `hash_chain` on, each record carries the hash of the record before it, so
altering, reordering, or deleting any record breaks every link after it.
`bastion verify` walks the chain and names the first record that does not hold;
`--include-rotated` checks rotated generations as one sequence.

This detects tampering rather than preventing it — see
[`security.md`](security.md#the-audit-log-is-tamper-evident-not-tamper-proof).

## `timeouts`

How long the gateway waits on an upstream before giving up. Without a cap a
wedged upstream hangs the agent indefinitely, with no error to react to.

| Key | Type | Default | Notes |
|---|---|---|---|
| `default_seconds` | float > 0 \| null | `120.0` | `null` waits forever |
| `per_tool` | map[string, float] | `{}` | per-tool overrides (exact names) |

```yaml
timeouts:
  default_seconds: 60
  per_tool:
    run_test_suite: 900
```

A timeout surfaces to the agent as an attributable error and is recorded in the
audit log, so an upstream that stalls repeatedly becomes visible. Timing out
cancels the in-flight request; a well-behaved upstream unwinds, one that does
not may keep working on a result nobody is waiting for.

## `cost`

The per-call cost model used by budget rules with a `max_cost` cap. Costs
are unit-agnostic — treat them as whatever currency you want to cap.

| Key | Type | Default | Notes |
|---|---|---|---|
| `default_per_call` | float ≥ 0 | `0.0` | fallback for tools not in `per_tool` |
| `per_tool` | map[string, float] | `{}` | per-tool overrides |

```yaml
cost:
  default_per_call: 0.0
  per_tool:
    search_web: 0.01
    expensive_llm_call: 0.10
```

## `policy`

The policy section bundles every rule the gateway enforces. On the way out,
checks run in this order and the first denial short-circuits the rest:

1. `permissions` — allow/deny on the tool name.
2. `guards` — regex/JSONPath checks on the arguments.
3. `rate_limits` — token-bucket caps.
4. `budgets` — windowed call-count and/or cost caps.

On the way back, `responses` inspects the result. Separately, `pinning` watches
tool *definitions* for changes.

Use `bastion explain <tool>` to see every layer's verdict for a specific call
rather than reasoning through the file.

### `default`, `permissions`, and `hide_denied`

| Key | Type | Default |
|---|---|---|
| `default` | `allow` \| `deny` | `allow` |
| `permissions` | list[PermissionRule] | `[]` |
| `hide_denied` | bool | `true` |

With `hide_denied` on, denied entries are removed from the tool, resource,
resource-template, and prompt listings, so the agent is never offered something
it cannot use — which otherwise costs a wasted turn, and under a default-deny
allowlist burns context on every tool it is forbidden to call. Filtering is
presentation only: the call-time check still refuses a client that calls a
hidden name directly. Set it to `false` to leave listings untouched.

Each `PermissionRule`:

| Key | Type | Notes |
|---|---|---|
| `tool` | tool glob | e.g. `files_*`, `files_delete_*`, `*` |
| `action` | `allow` \| `deny` | |

When several rules match a tool, the most specific glob (most literal
characters) wins; ties break by definition order. When no rule matches,
`default` applies.

```yaml
policy:
  default: allow
  permissions:
    - { tool: "files_read_*",   action: allow }
    - { tool: "files_delete_*", action: deny  }
```

### `rate_limits`

Per-rule token-bucket rate limits. Each rule maintains its own bucket(s).

| Key | Type | Default | Notes |
|---|---|---|---|
| `name` | string | — | shown in denial reasons |
| `scope` | `global` \| `per_tool` | `global` | bucket granularity |
| `max_per_minute` | int ≥ 1 | — | the long-term throughput |
| `burst` | int ≥ 1 \| null | = `max_per_minute` | the bucket's burst capacity |

`global` shares one bucket across every call; `per_tool` keeps a separate
bucket per distinct tool name.

```yaml
policy:
  rate_limits:
    - { name: global-cap, scope: global,   max_per_minute: 120, burst: 30 }
    - { name: per-tool,   scope: per_tool, max_per_minute: 60 }
```

### `budgets` and `budget_checkpoint`

Per-rule fixed-window counters: call-count and/or cost caps. The window
resets at the boundary (UTC midnight for `day`, the top of the hour for
`hour`, the top of the minute for `minute`).

| Key | Type | Default | Notes |
|---|---|---|---|
| `name` | string | — | shown in denial reasons |
| `scope` | `global` \| `per_tool` | `global` | counter granularity |
| `per` | `minute` \| `hour` \| `day` | — | window size |
| `max_calls` | int ≥ 1 \| null | null | optional call-count cap |
| `max_cost` | float > 0 \| null | null | optional cost cap (uses `cost` model) |

**At least one of `max_calls` or `max_cost` is required.**

`policy.budget_checkpoint` is a path (default `bastion-budgets.json`).
Counters are persisted to it on every reserve, so caps survive a restart.
Set to `null` to disable persistence.

```yaml
cost:
  per_tool: { search_web: 0.01 }

policy:
  budgets:
    - { name: daily-spend, scope: global, per: day,  max_cost:  5.00 }
    - { name: hourly-cap,  scope: global, per: hour, max_calls: 1000 }
  budget_checkpoint: ./bastion-budgets.json
```

### `guards`

Per-argument rules: a regex tested against the value at a JSONPath into
the call's arguments.

| Key | Type | Default | Notes |
|---|---|---|---|
| `name` | string | — | shown in denial reasons |
| `match` | tool glob | `*` | which tools the guard applies to |
| `type` | `regex` | `regex` | reserved for future expansion |
| `arg` | JSONPath | — | e.g. `$.command`, `$.headers.Authorization` |
| `pattern` | regex | — | matched (via `re.search`) against the value at `arg` |
| `action` | `block` \| `redact` | `block` | block raises a denial; redact masks the value in the audit log only |

A `block` guard raises a policy denial before the upstream sees the call;
the denial is recorded with the rule name in `error`. A `redact` guard
replaces the matched value with `***` in the audit log — the actual
upstream call is unchanged.

```yaml
policy:
  guards:
    - name: no-rm-rf
      match: "shell_*"
      arg: "$.command"
      pattern: 'rm\s+-rf'
      action: block
    - name: redact-bearer
      arg: "$.headers.Authorization"
      pattern: '^Bearer '
      action: redact
```

### `responses`

Argument guards protect the world from the agent; these protect the agent from
the world. Applied to tool results on the way back.

| Key | Type | Default | Notes |
|---|---|---|---|
| `redact_secrets` | bool | `true` | mask credentials a tool returned, before the model sees them |
| `allow_secrets_from` | list[tool glob] | `[]` | tools exempt from the above |
| `detect_injection` | `off` \| `warn` \| `block` | `warn` | what to do about suspected prompt injection |
| `guards` | list[ResponseGuardRule] | `[]` | your own regex rules on result text |

Each `ResponseGuardRule`:

| Key | Type | Default | Notes |
|---|---|---|---|
| `name` | string | — | shown in denial reasons and audit flags |
| `match` | tool glob | `*` | which tools the rule applies to |
| `pattern` | regex | — | matched against the result text |
| `action` | `block` \| `redact` | `redact` | block withholds the result; redact masks the match |

```yaml
policy:
  responses:
    redact_secrets: true
    allow_secrets_from: ["vault_*"]     # a tool whose job *is* returning secrets
    detect_injection: warn
    guards:
      - { name: no-internal-hostnames, pattern: '\.internal\.corp\b', action: redact }
```

**Injection detection.** `warn` records the finding in the record's `flags` and
prefixes the result with a caution naming it untrusted data — the original text
still reaches the agent. `block` withholds the result entirely and records the
call as `denied`. `off` disables the check.

The default is `warn` rather than `block` deliberately: these are heuristics, an
attacker who knows them can phrase around them, and a document *about* prompt
injection will trip them. Findings appear in `bastion logs`, `bastion tail`, and
the dashboard.

### `pinning`

An MCP server writes its own tool descriptions, and the agent reads them as
instructions — so a server you approved once can serve different text later. See
[`security.md`](security.md#tool-definitions-are-trust-on-first-use).

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | |
| `path` | path | `bastion-pins.json` | where fingerprints are stored |
| `on_change` | `warn` \| `block` | `warn` | what to do when a definition drifts |

Definitions are fingerprinted on first sight — name, title, description, input
and output schema, annotations, taken from the MCP wire form the agent receives
— and compared on every listing after. Cosmetic fields such as icons are
excluded, so churn there does not raise alarms nobody will keep reading.

`warn` records the drift in the audit log with `kind: pin`. `block` also
quarantines the tool: dropped from listings and refused on call, so a client
working from a listing it cached earlier still cannot reach it.

Drift never silently re-pins itself. Review it with `bastion pin`, which shows
the pinned and current descriptions side by side, and accept it with
`bastion pin --approve`.

```yaml
policy:
  pinning:
    enabled: true
    path: ./bastion-pins.json
    on_change: block
```

## See also

- [`security.md`](security.md) — operational security notes (secrets in the
  audit log, unauthenticated surfaces, guard patterns).
- `examples/` — runnable starter configurations.
- `CHANGELOG.md` — what landed in each release.
- `CONTRIBUTING.md` — how to propose changes.
