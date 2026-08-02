# Examples

Four runnable configurations, from smallest to strictest. Each is a complete
`bastion.yaml` — pass it with `--config` and it works as written.

| | What it shows |
| --- | --- |
| [`minimal/`](minimal/bastion.yaml) | The least you can write: one upstream, nothing else |
| [`permissions/`](permissions/bastion.yaml) | Per-tool allow/deny rules, and how the most-specific glob wins |
| [`full/`](full/bastion.yaml) | Every section, annotated — the one to read to see what exists |
| [`hardened/`](hardened/bastion.yaml) | Default-deny containment for an upstream you do not trust |

```bash
bastion validate --config examples/full/bastion.yaml
bastion run      --config examples/full/bastion.yaml
```

They all point at `@modelcontextprotocol/server-filesystem` via `npx`, so they
need Node available. Swap in your own upstream — the policy sections do not care
what is behind them.

Two things worth doing before running any of these against a real agent:

```bash
bastion doctor --config examples/full/bastion.yaml   # reachable? config sane?
bastion pin --approve --config examples/full/bastion.yaml   # baseline the tool definitions
```

Full reference in [`docs/configuration.md`](../docs/configuration.md); what each
defence is actually worth is in [`docs/security.md`](../docs/security.md).
