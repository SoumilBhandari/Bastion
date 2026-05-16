"""Pydantic models describing the Bastion configuration file."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

UPSTREAM_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")

Transport = Literal["stdio", "http"]


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
    """Whether and where the gateway writes its audit log."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    path: Path = Path("bastion-audit.jsonl")
    log_arguments: bool = True


class BastionConfig(BaseModel):
    """The top-level Bastion configuration."""

    model_config = ConfigDict(extra="forbid")

    gateway: GatewaySettings = Field(default_factory=GatewaySettings)
    audit: AuditConfig = Field(default_factory=AuditConfig)
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
