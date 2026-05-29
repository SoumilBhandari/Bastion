# Security considerations

Bastion is local-first and trusts its own configuration file (written by the
operator). Within that model, a few things are worth knowing.

## The audit log records arguments in plaintext

With `audit.log_arguments: true` (the default), every tool call's arguments are
written to the audit log as-is. If your tools receive secrets (API keys, tokens,
passwords), those values land in `bastion-audit.jsonl`. To avoid that:

- Set `audit.log_arguments: false` to omit arguments entirely, or
- Add `redact` guards that mask matching values in the log — the underlying call
  to the upstream is unchanged. For example, redact bearer tokens:

  ```yaml
  policy:
    guards:
      - name: redact-bearer
        arg: "$.headers.Authorization"
        pattern: "^Bearer "
        action: redact
  ```

Treat the audit log itself as sensitive: it records what your agent did and may
contain whatever it passed to its tools.

## The dashboard and HTTP gateway are unauthenticated

`bastion dashboard` and the HTTP gateway transport bind to `127.0.0.1` by
default, reachable only from the local machine. Binding either to a non-loopback
address (e.g. `--host 0.0.0.0`) exposes it to the network with **no built-in
authentication** — the dashboard would serve your raw audit log, and the gateway
would let any client drive your agent's upstream tools. Bastion prints a warning
when you do this. Keep these surfaces on loopback, or place an authenticating
reverse proxy in front.

## Guard patterns are operator-trusted

Guard `pattern` regexes come from your config and run (via Python's `re`) against
tool arguments. A pathological pattern combined with attacker-influenced argument
values could backtrack slowly. Since the config is authored by the operator, keep
guard patterns simple and anchored.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
