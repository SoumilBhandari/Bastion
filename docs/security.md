# Security model

Bastion trusts two things: the config file, which the operator writes, and the
machine it runs on. Everything else — the upstreams, their tool descriptions,
and everything they return — is treated as untrusted.

This page is about what that does and does not buy you. Several of Bastion's
defences are heuristics, and a heuristic you mistake for a guarantee is worse
than no defence at all.

## What Bastion is not

It is not a sandbox. A tool that can delete files can still delete files;
Bastion decides whether the call is allowed and writes down that it happened. If
an agent must not be able to do something at all, do not give it a tool that
can.

It is not an authentication layer. Anything that can reach the gateway can drive
it (see below).

It does not make an untrustworthy MCP server safe. It narrows what that server
can be asked to do, notices when it changes, and records what it did.

## The audit log is tamper-evident, not tamper-proof

With `audit.hash_chain` on (the default) each record carries the hash of the
record before it, so altering, reordering, or removing any record breaks every
link after it and `bastion verify` will say so.

An attacker who can write to the file can also rewrite it from scratch and
produce a chain that verifies. What defeats that is a copy of the newest hash
somewhere they cannot reach — `bastion verify` prints it as `head:`. Store it on
another host, in a ticket, anywhere out of reach, and compare.

Other limits worth knowing:

- The log records what Bastion saw. It cannot record what an agent did through a
  path that bypasses the gateway.
- With `audit.fsync` off (the default), a record is flushed but not forced to
  disk, so an abrupt power loss can lose the last few records. A crash of the
  gateway process alone loses nothing.
- Rotation discards the oldest generation. Set `audit.max_bytes: null` to keep
  everything, and archive it yourself.

## The audit log is sensitive

It records what your agent did and, unless `audit.log_arguments` is off,
everything it passed. `audit.redact_secrets` masks recognized credentials before
they are written, but redaction is pattern-based and not exhaustive — a bespoke
internal token format needs its own `redact` guard. Treat the file as
confidential.

## Credential detection is best-effort

Detectors are anchored on the token shapes real issuers use (`AKIA…`, `ghp_…`,
`sk-ant-…`, `Bearer …`, and so on) rather than guessing from entropy, because a
false positive silently destroys evidence in an audit log. The consequence is
that anything not shaped like a known credential is not detected: an internal
API key that looks like a UUID, a password in a field named something unusual.

Argument names that look sensitive (`password`, `api_key`, `token`, …) are
redacted whole, which catches values no pattern would.

## Prompt-injection detection is heuristic

`policy.responses.detect_injection` looks for text engineered to steer the
agent. It will miss payloads phrased outside its patterns — an attacker who
reads `bastion/policy/injection.py` can write around it — and it will flag
innocent text that discusses prompt injection.

Under the default `warn`, a finding annotates the result and lands in the audit
log; the text still reaches the agent, prefixed with a caution naming it
untrusted data. Under `block` the result is withheld entirely, which is stronger
and also breaks legitimate work more often.

Do not treat a clean scan as evidence that a result is safe. Its value is
raising the cost of the easy attacks and making the suspicious ones visible in
the log.

## Walking stops at a nesting limit

Arguments come from the agent and results come from upstreams, so both are
shaped by something other than you. A value nested a few thousand levels deep —
which an upstream can simply return — exhausted the interpreter stack in every
recursive walk Bastion does over them: redaction, serialisation, and the
flattening that feeds the scanners.

Walks now stop at 100 levels and replace anything deeper with a conspicuous
marker, so nothing slips through a walk that was supposed to inspect it. Real
arguments and results are nowhere near that deep; if you see the marker in an
audit log, that subtree was never examined.

## Scanning stops at a size limit

Both scanners examine at most `SCAN_LIMIT` characters (1 MB) of a value, because
scanning is linear — roughly 0.09 ms per kilobyte — and an unbounded result would
let one enormous response stall the gateway. Content past that point is neither scanned nor redacted, so an
attacker who controls the size of a response can push a payload out of range.
Where results are routinely large, weigh that against turning detection off
rather than assuming coverage you do not have.

## Tool definitions are trust-on-first-use

`policy.pinning` fingerprints each tool's definition the first time it is seen
and reports drift after that. It defends against the change *after* you looked —
the server that was fine when you approved it and is not any more. It does not
help if the server was already hostile at the moment it was first pinned. Review
what a new upstream advertises before you point an agent at it.

Under `on_change: warn` (the default) a drifted tool is still served, with the
drift recorded. Use `block` where an unreviewed change should stop work.

## The dashboard and HTTP gateway

`bastion dashboard` binds to `127.0.0.1` and mints a per-session access token,
printed in the URL at startup. Without it the dashboard would serve your
complete audit log to anything that could reach the port. `--no-token` disables
that check and should only be used behind a proxy that authenticates.

The HTTP gateway transport has **no authentication at all**. Anything that can
reach it can drive your agent's upstream tools. Keep it on loopback, or put an
authenticating reverse proxy in front. Bastion warns when either is bound to a
non-loopback address.

## Guard patterns are operator-trusted

Guard `pattern` regexes come from your config and run against tool arguments and
results. A pathological pattern combined with attacker-influenced values could
backtrack badly. Keep them simple and anchored. (Bastion's own built-in patterns
are all linear-time by construction, since those run against attacker-controlled
text by definition.)

## Matching is case-sensitive

Permission globs, guard `match` globs, and guard `pattern` regexes are
case-sensitive. A rule for `files_delete_*` does not match `Files_Delete_x`, and
a pattern `rm` does not match `RM`. MCP tool dispatch is itself case-sensitive,
so a mis-cased name fails as an unknown tool rather than slipping past a deny
rule — but match your rules to the exact names the upstream exposes, and use
`(?i)` in a guard pattern where case should not matter.

Guards inspect structured arguments, not just strings: a list value is matched
element by element and as a space-joined command line, so an argv array like
`["rm", "-rf", "/"]` cannot smuggle a command past a string pattern.

## Budgets reset on fixed windows

Budget windows are calendar minutes, hours, or days in UTC — not sliding. Near a
boundary an agent can spend a full window's budget just before the reset and
again just after, roughly 2× over a short span. Size caps with that in mind, or
use a shorter window.

## Timeouts cancel, they do not stop

A call that exceeds `timeouts.default_seconds` is cancelled and reported as an
error. A well-behaved upstream notices and unwinds. One that does not may keep
working — and if the work had a side effect, that side effect may still happen
even though the agent was told the call failed.

## Checking your own configuration

`bastion doctor` reviews a config for settings that are legal but usually not
intended: default-allow with no rules, no limits at all, hash chaining off,
pinning off, timeouts disabled, an unauthenticated non-loopback bind.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
