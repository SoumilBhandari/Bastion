# Bastion

**A local-first control plane for your AI agent's tools.** Bastion is a gateway
that sits between an AI agent (Claude Code, Cursor, Claude Desktop, …) and the
MCP servers it uses — capping spend, rate-limiting, enforcing per-action
permissions, and auditing every tool call.

> **Status: early development.** Bastion is being built in the open, milestone
> by milestone. Today it proxies your MCP servers, writes a full audit log of
> every tool call, and enforces per-tool **permissions**; rate limits, budgets,
> and argument guards land over the next milestones — see the [roadmap](#roadmap).

## Why

[Model Context Protocol](https://modelcontextprotocol.io) won — every major AI
vendor ships it and there are 17,000+ MCP servers. But agents call those servers
with **no spend caps, no rate limits, no permissions, and no audit trail**. A
looping agent can burn real money in minutes, and you have no record of what it
did.

Bastion is the missing control layer. One config file, one command, no cloud,
no database.

## How it works

Your agent points at Bastion instead of at its MCP servers directly. Bastion is
both an MCP server (to the agent) and an MCP client (to the real "upstream"
servers). It aggregates your upstreams behind one endpoint and enforces rules on
every `tools/call`:

```
  AI agent  ──MCP──▶  Bastion  ──MCP──▶  upstream server A
                      (policy +          upstream server B
                       audit)            upstream server C
```

## Install

```bash
pip install bastion-mcp
```

This installs the `bastion` command. To run it without installing globally,
use [uv](https://github.com/astral-sh/uv):

```bash
uvx --from bastion-mcp bastion --help
```

To hack on Bastion itself, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quickstart

Create `bastion.yaml`:

```yaml
upstreams:
  files:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
```

Validate it:

```bash
bastion validate
```

Point your agent at the gateway — e.g. for Claude Code:

```bash
claude mcp add --transport stdio bastion -- bastion run --config ./bastion.yaml
```

Your agent now reaches the filesystem server *through* Bastion. With a single
upstream, tools keep their original names; configure several and Bastion
namespaces each tool by its upstream key (`files_read_file`, `search_query`, …)
so they never collide.

## Configuration

`bastion.yaml` — `upstreams` is required; everything else is optional.

```yaml
gateway:
  transport: stdio          # stdio | http

upstreams:                  # each key names an upstream MCP server
  files:
    command: npx            # `command` ⇒ stdio upstream
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
  search:
    url: https://search.example.com/mcp   # `url` ⇒ http upstream

audit:                      # every tool call is logged here (JSON Lines)
  enabled: true
  path: ./bastion-audit.jsonl

policy:                     # per-tool allow/deny (most-specific rule wins)
  default: allow
  permissions:
    - { tool: "files_read_*",   action: allow }
    - { tool: "files_delete_*", action: deny  }
```

A denied call is blocked before it reaches the upstream and recorded in the
audit log. The `cost` section (budgets) is documented as it lands — see the
roadmap below.

## Dashboard

`bastion dashboard` serves a local web view of the audit log — every tool call,
live, with arguments, outcomes, and timings:

```bash
bastion dashboard --config bastion.yaml   # then open http://127.0.0.1:8787
```

## Roadmap

Bastion is built in milestones; each adds one capability. The first PyPI release
comes early — right after permissions — and every milestone after ships a release.

- [x] **M0** — multi-upstream proxy (stdio + HTTP), config schema, CLI
- [x] **M1** — audit log: every tool call recorded to JSONL
- [x] **M2** — permissions: per-tool allow/deny rules
- [ ] **M3** — first PyPI release (`pip install bastion`)
- [ ] **M4** — rate limiting: per-tool / per-client / global token buckets
- [ ] **M5** — budgets: call-count and cost caps that survive restarts
- [ ] **M6** — argument guards: block dangerous tool arguments
- [ ] **M7** — live log viewer (`bastion tail`) and CLI polish
- [ ] **M8** — docs, examples, `v1.0.0`

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE)
