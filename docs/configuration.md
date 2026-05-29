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
policy:     {}     # permissions, rate limits, budgets, guards (optional)
```

Validate a file without running the gateway with `bastion validate
--config path/to/bastion.yaml`. See `examples/` for runnable configurations.

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

Every governed operation — a tool call, resource read, or prompt fetch —
produces one JSON record per line with these fields: `call_id`, `timestamp`
(ISO 8601 UTC), `kind` (`tool` / `resource` / `prompt`), `tool` (the tool name,
resource URI, or prompt name), `arguments`, `outcome` (`ok` / `error` /
`denied`), `duration_ms`, and `error` (the reason on non-`ok` outcomes).

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

The policy section bundles every rule the gateway enforces on a tool call.
Checks run in this order, and the first denial short-circuits the rest:

1. `permissions` — allow/deny on the tool name.
2. `guards` — regex/JSONPath checks on the arguments.
3. `rate_limits` — token-bucket caps.
4. `budgets` — windowed call-count and/or cost caps.

### `default` and `permissions`

| Key | Type | Default |
|---|---|---|
| `default` | `allow` \| `deny` | `allow` |
| `permissions` | list[PermissionRule] | `[]` |

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

## See also

- [`security.md`](security.md) — operational security notes (secrets in the
  audit log, unauthenticated surfaces, guard patterns).
- `examples/` — runnable starter configurations.
- `CHANGELOG.md` — what landed in each release.
- `CONTRIBUTING.md` — how to propose changes.
