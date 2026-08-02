"""Environment-variable interpolation for the configuration file.

Secrets do not belong in ``bastion.yaml``. Any string value in the config may
reference the environment with ``${VAR}`` (required) or ``${VAR:-default}``
(optional, falling back when unset or empty); ``$${VAR}`` escapes to a literal
``${VAR}``.

Substitution happens on the *parsed* values, never on the raw YAML text, so a
variable whose value contains ``:`` or a newline cannot alter the document's
structure.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ENV_FILE_NAME = ".env"

_REFERENCE = re.compile(
    r"""
    \$(?P<escape>\$)?          # a doubled $ escapes the reference
    \{
      (?P<name>[A-Za-z_][A-Za-z0-9_]*)
      (?: :- (?P<default>[^}]*) )?
    \}
    """,
    re.VERBOSE,
)

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


class EnvError(Exception):
    """Raised when the config references environment variables that are not set."""


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a ``.env`` file into a mapping.

    Understands ``KEY=value``, an optional ``export`` prefix, ``#`` comments,
    and single- or double-quoted values. Lines that do not parse are ignored
    rather than treated as fatal, so a stray note in the file is harmless.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}

    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if match is None:
            continue
        key, value = match.group(1), match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].strip()
        values[key] = value
    return values


def build_environment(config_dir: Path, process_env: Mapping[str, str]) -> dict[str, str]:
    """Merge a ``.env`` beside the config with the real process environment.

    The process environment wins, so an explicitly exported variable always
    overrides the file. The file exists because an MCP client that launches
    ``bastion run`` over stdio controls the child's environment — without it
    there is often no way to get a secret to the gateway at all.
    """
    merged = read_env_file(config_dir / ENV_FILE_NAME)
    merged.update(process_env)
    return merged


def interpolate(value: Any, env: Mapping[str, str]) -> Any:
    """Expand environment references throughout a parsed config document.

    Recurses through mappings and sequences, substituting in string values.
    Mapping keys are left alone. Raises :class:`EnvError` listing every
    unresolved variable at once, rather than failing on the first.
    """
    missing: list[str] = []
    result = _walk(value, env, "", missing)
    if missing:
        joined = "\n".join(f"  - {entry}" for entry in missing)
        raise EnvError(
            f"config references environment variables that are not set:\n{joined}\n"
            f"Set them in the environment, put them in a {ENV_FILE_NAME} file beside "
            "the config, or give them a default with ${VAR:-fallback}."
        )
    return result


def _walk(value: Any, env: Mapping[str, str], location: str, missing: list[str]) -> Any:
    if isinstance(value, str):
        return _expand(value, env, location or "(top level)", missing)
    if isinstance(value, dict):
        return {key: _walk(item, env, _join(location, key), missing) for key, item in value.items()}
    if isinstance(value, list):
        return [_walk(item, env, f"{location}[{i}]", missing) for i, item in enumerate(value)]
    return value


def _join(location: str, key: Any) -> str:
    return f"{location}.{key}" if location else str(key)


def _expand(text: str, env: Mapping[str, str], location: str, missing: list[str]) -> str:
    def replace(match: re.Match[str]) -> str:
        if match.group("escape"):
            return match.group(0)[1:]
        name, default = match.group("name"), match.group("default")
        resolved = env.get(name)
        if default is not None:
            return resolved if resolved else default
        if resolved is None:
            missing.append(f"${{{name}}} at {location}")
            return ""
        return resolved

    return _REFERENCE.sub(replace, text)
