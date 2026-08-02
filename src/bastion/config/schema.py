"""Pydantic models describing the Bastion configuration file."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from jsonpath_ng import parse as parse_jsonpath
from pydantic import BaseModel, ConfigDict, Field, model_validator

UPSTREAM_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")

Transport = Literal["stdio", "http"]
Action = Literal["allow", "deny"]


class Upstream(BaseModel):
    """One upstream MCP server that the gateway proxies to.

    Exactly one of ``command`` (a local server launched over stdio) or ``url``
    (a remote HTTP server) must be set; ``transport`` is inferred from whichever
    is present.
    """

    model_config = ConfigDict(extra="forbid")

    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    transport: Transport | None = None

    @model_validator(mode="after")
    def _resolve_transport(self) -> Upstream:
        has_command = self.command is not None
        has_url = self.url is not None
        if has_command and has_url:
            raise ValueError("set either 'command' or 'url', not both")
        if not has_command and not has_url:
            raise ValueError("must set either 'command' (stdio) or 'url' (http)")

        inferred: Transport = "stdio" if has_command else "http"
        if self.transport is not None and self.transport != inferred:
            raise ValueError(
                f"transport '{self.transport}' conflicts with this upstream (expected '{inferred}')"
            )
        self.transport = inferred

        if inferred == "http" and (self.args or self.env):
            raise ValueError("'args' and 'env' apply only to stdio upstreams ('command')")
        if inferred == "stdio" and self.headers:
            raise ValueError("'headers' applies only to http upstreams ('url')")
        return self


class GatewaySettings(BaseModel):
    """How the gateway itself listens for the connecting agent."""

    model_config = ConfigDict(extra="forbid")

    transport: Transport = "stdio"
    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1, le=65535)


class AuditConfig(BaseModel):
    """Whether, where, and how durably the gateway writes its audit log.

    ``redact_secrets`` masks recognized credentials in logged arguments, so the
    audit log does not quietly become a plaintext credential file.
    ``hash_chain`` links each record to the one before it, so edits to the log
    are detectable. ``fsync`` forces each record to physical disk before the
    call proceeds — correct across a power loss, but it costs a disk round trip
    per call. ``max_bytes``/``keep`` bound how much history is kept on disk.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    path: Path = Path("bastion-audit.jsonl")
    log_arguments: bool = True
    redact_secrets: bool = True
    hash_chain: bool = True
    fsync: bool = False
    max_bytes: int | None = Field(default=100_000_000, ge=1)
    keep: int = Field(default=5, ge=0)


class CostConfig(BaseModel):
    """Per-call cost model used by budget rules.

    Costs are unit-agnostic (typically US dollars). The cost charged for a
    given tool call is ``per_tool[name]`` if the tool is listed; otherwise
    ``default_per_call``.
    """

    model_config = ConfigDict(extra="forbid")

    default_per_call: float = Field(default=0.0, ge=0.0)
    per_tool: dict[str, float] = Field(default_factory=dict)


class TimeoutConfig(BaseModel):
    """How long the gateway waits on an upstream before giving up.

    Without a cap a wedged upstream — a server that accepted the request and
    then stopped answering — hangs the agent indefinitely, with no error to
    react to and no way out but killing the client. The timeout applies only
    to the upstream call itself, not to policy evaluation.

    Tools listed in ``per_tool`` use their own limit; everything else uses
    ``default_seconds``. Set ``default_seconds`` to ``null`` to wait forever.
    """

    model_config = ConfigDict(extra="forbid")

    default_seconds: float | None = Field(default=120.0, gt=0.0)
    per_tool: dict[str, float] = Field(default_factory=dict)

    def for_tool(self, tool: str) -> float | None:
        return self.per_tool.get(tool, self.default_seconds)


class PermissionRule(BaseModel):
    """An allow/deny rule matching tool names by glob (e.g. ``files_*``)."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1)
    action: Action


class RateLimitRule(BaseModel):
    """A rate-limit rule applied to tool calls.

    Each rule maintains a token bucket. ``scope`` chooses bucket granularity:
    ``global`` shares one bucket across all calls; ``per_tool`` keeps a
    separate bucket per distinct tool name.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    scope: Literal["global", "per_tool"] = "global"
    max_per_minute: int = Field(ge=1)
    burst: int | None = Field(default=None, ge=1)


class BudgetRule(BaseModel):
    """A budget rule with a fixed time window.

    Either ``max_calls`` or ``max_cost`` (or both) must be set. The window
    resets at the boundary: UTC midnight for ``day``, the top of the hour for
    ``hour``, the top of the minute for ``minute``. ``scope`` chooses whether
    one counter is shared across all calls (``global``) or kept per tool
    (``per_tool``).
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    scope: Literal["global", "per_tool"] = "global"
    per: Literal["minute", "hour", "day"]
    max_calls: int | None = Field(default=None, ge=1)
    max_cost: float | None = Field(default=None, gt=0.0)

    @model_validator(mode="after")
    def _at_least_one_cap(self) -> BudgetRule:
        if self.max_calls is None and self.max_cost is None:
            raise ValueError("budget rule must set max_calls or max_cost (or both)")
        return self


class GuardRule(BaseModel):
    """A guard rule applied to a tool call's arguments.

    Each rule has a glob ``match`` for which tools it applies to, a JSONPath
    ``arg`` pointing into the arguments dict, and a regex ``pattern`` tested
    against the value(s) at that path. ``action`` decides what happens on a
    match: ``block`` raises a policy denial; ``redact`` replaces the matched
    value with ``***`` in the audit log only (the underlying call is unchanged).
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    match: str = "*"
    type: Literal["regex"] = "regex"
    arg: str = Field(min_length=1)
    pattern: str = Field(min_length=1)
    action: Literal["block", "redact"] = "block"

    @model_validator(mode="after")
    def _validate_pattern_and_arg(self) -> GuardRule:
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"invalid 'pattern' regex: {exc}") from exc
        try:
            parse_jsonpath(self.arg)
        except Exception as exc:  # jsonpath_ng raises its own parser errors
            raise ValueError(f"invalid 'arg' JSONPath: {exc}") from exc
        return self


class ResponseGuardRule(BaseModel):
    """A guard rule applied to an upstream's result text.

    ``match`` is a glob over tool names, ``pattern`` a regex tested against the
    result. ``block`` refuses the result outright; ``redact`` masks the matched
    span before the agent sees it.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    match: str = "*"
    pattern: str = Field(min_length=1)
    action: Literal["block", "redact"] = "redact"

    @model_validator(mode="after")
    def _validate_pattern(self) -> ResponseGuardRule:
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"invalid 'pattern' regex: {exc}") from exc
        return self


class ResponseConfig(BaseModel):
    """What the gateway does with results on the way back to the agent.

    Argument guards protect the world from the agent; these protect the agent
    from the world. ``redact_secrets`` masks credentials a tool returned, so a
    leaked key never reaches the model's context at all. Some tools return
    credentials because that is their whole job — a vault or password-manager
    server — so list those in ``allow_secrets_from`` (globs over tool names) to
    let their results through intact.

    ``detect_injection`` looks for text engineered to steer the agent — the
    payload usually arriving not from the MCP server but from whatever it
    fetched: a web page, an issue comment, a filename. ``warn`` (the default)
    flags it in the audit log and prefixes the result with a caution telling
    the model to treat it as data; ``block`` refuses the result; ``off``
    disables the check. The default is deliberately not ``block``: these are
    heuristics, and a document *about* prompt injection will trip them.
    """

    model_config = ConfigDict(extra="forbid")

    redact_secrets: bool = True
    allow_secrets_from: list[str] = Field(default_factory=list)
    detect_injection: Literal["off", "warn", "block"] = "warn"
    guards: list[ResponseGuardRule] = Field(default_factory=list)


class PolicyConfig(BaseModel):
    """Policy enforced on every tool call.

    Permission rules are matched against tool names by glob; when several match
    a tool, the most specific wins. When none match, ``default`` applies.

    ``hide_denied`` also removes denied entries from ``tools/list`` and the
    resource and prompt listings, so the agent is never offered something it
    cannot use. Turn it off to leave listings untouched and let the agent
    discover the denial by being refused.
    """

    model_config = ConfigDict(extra="forbid")

    default: Action = "allow"
    hide_denied: bool = True
    permissions: list[PermissionRule] = Field(default_factory=list)
    rate_limits: list[RateLimitRule] = Field(default_factory=list)
    budgets: list[BudgetRule] = Field(default_factory=list)
    budget_checkpoint: Path | None = Path("bastion-budgets.json")
    guards: list[GuardRule] = Field(default_factory=list)
    responses: ResponseConfig = Field(default_factory=ResponseConfig)


class BastionConfig(BaseModel):
    """The top-level Bastion configuration."""

    model_config = ConfigDict(extra="forbid")

    gateway: GatewaySettings = Field(default_factory=GatewaySettings)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    cost: CostConfig = Field(default_factory=CostConfig)
    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    upstreams: dict[str, Upstream] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_upstream_names(self) -> BastionConfig:
        for name in self.upstreams:
            if not UPSTREAM_NAME_PATTERN.match(name):
                raise ValueError(
                    f"upstream name '{name}' is invalid: start with a letter and use "
                    "only letters, digits, and underscores"
                )
        return self
