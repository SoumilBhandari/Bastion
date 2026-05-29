# Bastion

[![PyPI](https://img.shields.io/pypi/v/bastion-mcp)](https://pypi.org/project/bastion-mcp/)
[![CI](https://github.com/SoumilBhandari/Bastion/actions/workflows/ci.yml/badge.svg)](https://github.com/SoumilBhandari/Bastion/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/bastion-mcp)](https://pypi.org/project/bastion-mcp/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**A local-first control plane for your AI agent's tools.** Bastion is a gateway
that sits between an AI agent (Claude Code, Cursor, Claude Desktop, …) and the
MCP servers it uses — capping spend, rate-limiting, enforcing per-tool
permissions, redacting or blocking dangerous arguments, and auditing every call.

One config file, one command, no cloud, no database.

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

`bastion.yaml` — `upstreams` is required; everything else is optional. A
small example with permissions and audit:

```yaml
upstreams:
  files:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]

audit:
  enabled: true
  path: ./bastion-audit.jsonl

policy:
  default: allow
  permissions:
    - { tool: "files_read_*",   action: allow }
    - { tool: "files_delete_*", action: deny  }
```

A denied call is blocked before reaching the upstream and recorded in the
audit log. Rate limits, budgets (call-count and cost), and argument guards
(block or redact) layer onto the same `policy` section.

See **[`docs/configuration.md`](docs/configuration.md)** for the full reference
of every section, **[`docs/security.md`](docs/security.md)** for the security
model (secrets in the audit log, unauthenticated surfaces), and
**[`examples/`](examples/)** for runnable starter configurations.

## Dashboard

`bastion dashboard` serves a local web view of the audit log — every tool call,
live, with arguments, outcomes, and timings:

```bash
bastion dashboard --config bastion.yaml   # then open http://127.0.0.1:8787
```

## Milestones

Bastion shipped one feature per release, milestone by milestone:

- [x] **M0** — multi-upstream proxy (stdio + HTTP), config schema, CLI
- [x] **M1** — audit log: every tool call recorded to JSONL
- [x] **M2** — permissions: per-tool allow/deny rules
- [x] **M3** — first PyPI release (`pip install bastion-mcp`)
- [x] **M4** — rate limiting: per-tool and global token buckets
- [x] **M5** — budgets: call-count and cost caps with on-disk checkpoint
- [x] **M6** — argument guards: regex-on-JSONPath, block or redact
- [x] **M7** — live log viewer (`bastion tail/logs/stats/init`) + Windows CI
- [x] **M8** — docs, examples, `v1.0.0` 🎉

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE)
