"""The configuration file: the addresses that are never blocked and the optional measures."""

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from torrent_tracker_blocker.measures import NO_MEASURES, ConfigError, Measures, Scope

# Sections and the options each of them accepts.
SECTIONS = {
    "signatures": ("scope",),
    "connection_limit": ("scope", "max_connections"),
}


@dataclass(frozen=True)
class Config:
    """Everything the configuration file can set; what it leaves out stays at its default."""

    # Addresses, ranges and lists of them (local files or https:// URLs) that never get a blocking rule.
    whitelist: tuple[str, ...] = ()
    measures: Measures = NO_MEASURES


DEFAULTS = Config()


def _whitelist(document: dict[str, Any]) -> tuple[str, ...]:
    entries: object = document.get("whitelist", [])

    if isinstance(entries, list):
        items = cast("list[object]", entries)
        whitelist = tuple(item for item in items if isinstance(item, str) and item.strip())

        if len(whitelist) == len(items):
            return whitelist

    raise ConfigError(f"whitelist must be a list of addresses, ranges, files or https:// URLs, not {entries!r}")


def _scope(section: dict[str, Any], name: str) -> Scope:
    value = section.get("scope", Scope.OFF.value)

    if not isinstance(value, str) or value not in list(Scope):
        raise ConfigError(f'scope in [{name}] must be "off", "forward" or "all", not {value!r}')

    return Scope(value)


def _parse(document: dict[str, Any]) -> Config:
    sections = {name: section for name, section in document.items() if name != "whitelist"}

    for name, section in sections.items():
        # A typo must not silently leave a measure off.
        if name not in SECTIONS:
            raise ConfigError(f"unknown section or option {name!r}")

        if not isinstance(section, dict):
            raise ConfigError(f"{name!r} must be a section: [{name}]")

        unknown = set(cast("dict[str, object]", section)) - set(SECTIONS[name])

        if unknown:
            raise ConfigError(f"unknown option {min(unknown)!r} in [{name}]")

    signatures = sections.get("signatures", {})
    connection_limit = sections.get("connection_limit", {})

    return Config(
        whitelist=_whitelist(document),
        measures=Measures(
            signatures=_scope(signatures, "signatures"),
            connection_limit=_scope(connection_limit, "connection_limit"),
            max_connections=connection_limit.get("max_connections"),
        ),
    )


def load_config(path: Path) -> Config:
    """Read the configuration from a TOML file."""
    try:
        with path.open("rb") as file:
            return _parse(tomllib.load(file))

    # Covers invalid TOML, text that is not UTF-8 and our own ConfigError.
    except ValueError as error:
        raise ConfigError(f"{path}: {error}") from error
