"""Configuration loading and validation for Bastion."""

from bastion.config.loader import (
    CONFIG_ENV_VAR,
    DEFAULT_CONFIG_NAME,
    ConfigError,
    find_config,
    load_config,
)
from bastion.config.schema import (
    Action,
    AuditConfig,
    BastionConfig,
    GatewaySettings,
    PermissionRule,
    PolicyConfig,
    Transport,
    Upstream,
)

__all__ = [
    "CONFIG_ENV_VAR",
    "DEFAULT_CONFIG_NAME",
    "Action",
    "AuditConfig",
    "BastionConfig",
    "ConfigError",
    "GatewaySettings",
    "PermissionRule",
    "PolicyConfig",
    "Transport",
    "Upstream",
    "find_config",
    "load_config",
]
