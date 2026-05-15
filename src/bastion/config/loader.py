"""Locating, reading, and validating the Bastion configuration file."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import ValidationError

from bastion.config.schema import BastionConfig

DEFAULT_CONFIG_NAME = "bastion.yaml"
CONFIG_ENV_VAR = "BASTION_CONFIG"


class ConfigError(Exception):
    """Raised when the configuration cannot be located, parsed, or validated."""


def find_config(explicit: Path | None = None) -> Path:
    """Locate the config file.

    Resolution order: an explicit ``--config`` path, then ``$BASTION_CONFIG``,
    then ``./bastion.yaml``. Raises :class:`ConfigError` if the chosen source
    points at a file that does not exist.
    """
    if explicit is not None:
        if explicit.is_file():
            return explicit
        raise ConfigError(f"config file not found: {explicit}")

    env_value = os.environ.get(CONFIG_ENV_VAR)
    if env_value:
        env_path = Path(env_value)
        if env_path.is_file():
            return env_path
        raise ConfigError(f"config file not found: {env_path} (from ${CONFIG_ENV_VAR})")

    default = Path.cwd() / DEFAULT_CONFIG_NAME
    if default.is_file():
        return default
    raise ConfigError(f"no config file found at {default}. Create one, or pass --config <path>.")


def load_config(path: Path) -> BastionConfig:
    """Read and validate the config file at ``path``."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {path} is not valid YAML: {exc}") from exc

    if raw is None:
        raise ConfigError(f"config file {path} is empty")
    if not isinstance(raw, dict):
        raise ConfigError(
            f"config file {path} must contain a YAML mapping at the top level, "
            f"got {type(raw).__name__}"
        )

    try:
        return BastionConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(path, exc)) from exc


def _format_validation_error(path: Path, exc: ValidationError) -> str:
    lines = [f"config file {path} is invalid:"]
    for err in exc.errors():
        location = ".".join(str(part) for part in err["loc"]) or "(top level)"
        lines.append(f"  - {location}: {err['msg']}")
    return "\n".join(lines)
