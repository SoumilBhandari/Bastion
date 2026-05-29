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

## Matching is case-sensitive

Permission globs, guard `match` globs, and guard `pattern` regexes are
case-sensitive. A rule for `files_delete_*` won't match `Files_Delete_x`, and a
pattern `rm` won't match `RM`. (MCP tool dispatch is itself case-sensitive, so a
mis-cased name fails as an unknown tool rather than slipping past a deny rule —
but match your rules to the exact names the upstream exposes, and use `(?i)` in a
guard pattern where case shouldn't matter.) Guards also inspect structured
arguments: a list value is matched element-by-element and as a space-joined
command line, so an argv array like `["rm", "-rf", "/"]` can't smuggle a command
past a string pattern.

## Budgets reset on fixed windows

Budget windows are fixed (calendar minute/hour/day in UTC), not sliding. Near a
boundary an agent can spend up to a full window's budget just before the reset
and again just after — roughly 2× over a short span. Size caps with that in
mind, or use a shorter window for tighter control.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
