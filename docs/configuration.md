# Configuration reference

Bastion reads configuration from `bastion.yaml`. The `upstreams` section is
required; `gateway`, `audit`, and `policy` are optional and use the defaults
shown below.

```yaml
gateway:
  transport: stdio
  host: 127.0.0.1
  port: 8765

upstreams:
  files:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "."]

  search:
    url: https://search.example.com/mcp
    headers:
      Authorization: Bearer ${SEARCH_TOKEN}

audit:
  enabled: true
  path: bastion-audit.jsonl
  log_arguments: true

policy:
  default: allow
  permissions:
    - tool: "files_read_*"
      action: allow
    - tool: "files_delete_*"
      action: deny
```

## `gateway`

Controls how the Bastion gateway listens for the agent that connects to it.

| Field | Default | Description |
| --- | --- | --- |
| `transport` | `stdio` | Gateway transport. Use `stdio` when your agent launches `bastion run`; use `http` to run a local HTTP endpoint. |
| `host` | `127.0.0.1` | Bind address for the HTTP gateway. Ignored by `stdio`. |
| `port` | `8765` | Port for the HTTP gateway. Must be between `1` and `65535`. Ignored by `stdio`. |

## `upstreams`

Defines the MCP servers that Bastion proxies. This section is required and must
contain at least one upstream. Each key is the upstream name; it must start with
a letter and contain only letters, digits, and underscores.

Each upstream must set exactly one of `command` or `url`:

### Stdio upstreams

Use `command` for a local MCP server that Bastion starts over stdio.

```yaml
upstreams:
  files:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "."]
    env:
      NODE_ENV: production
```

| Field | Default | Description |
| --- | --- | --- |
| `command` | required | Executable to launch. |
| `args` | `[]` | Command-line arguments passed to `command`. |
| `env` | `{}` | Environment variables for the upstream process. |
| `transport` | inferred as `stdio` | Optional explicit transport. If set, it must be `stdio`. |

### HTTP upstreams

Use `url` for an MCP server that is already reachable over HTTP.

```yaml
upstreams:
  search:
    url: https://search.example.com/mcp
    headers:
      Authorization: Bearer ${SEARCH_TOKEN}
```

| Field | Default | Description |
| --- | --- | --- |
| `url` | required | HTTP MCP endpoint to proxy. |
| `headers` | `{}` | Headers sent to the upstream server. |
| `transport` | inferred as `http` | Optional explicit transport. If set, it must be `http`. |

`args` and `env` are valid only with `command`. `headers` is valid only with
`url`. With one upstream, Bastion keeps tool names unchanged. With multiple
upstreams, tools are namespaced by upstream key, such as `files_read_file`.

## `audit`

Controls Bastion's JSON Lines audit log. When enabled, Bastion writes one JSON
object per tool call, including denied and failed calls.

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Whether to write audit records. |
| `path` | `bastion-audit.jsonl` | File path for the JSON Lines audit log. Parent directories are created as needed. |
| `log_arguments` | `true` | Whether audit records include tool arguments. Set to `false` to avoid storing request details. |

## `policy`

Controls allow/deny decisions for every tool call.

| Field | Default | Description |
| --- | --- | --- |
| `default` | `allow` | Action used when no permission rule matches. Must be `allow` or `deny`. |
| `permissions` | `[]` | Ordered list of tool rules. Each rule has `tool` and `action`. |

Permission `tool` values are glob patterns matched against tool names. When more
than one rule matches, the most specific matching rule wins.

```yaml
policy:
  default: deny
  permissions:
    - tool: "files_read_*"
      action: allow
    - tool: "search_*"
      action: allow
    - tool: "files_delete_*"
      action: deny
```

A denied call is blocked before it reaches the upstream and is still recorded in
the audit log when auditing is enabled.
