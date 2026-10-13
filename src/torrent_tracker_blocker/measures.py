"""Optional blocking measures.

Unlike the tracker rules they can also drop legitimate traffic, so each one
stays off until it is asked for.
"""

from dataclasses import dataclass
from enum import StrEnum

# The largest number iptables accepts for a connection limit.
MAX_CONNECTIONS_CEILING = 2**32 - 1


class ConfigError(ValueError):
    """A setting has a value that cannot be used."""


class Scope(StrEnum):
    """Which traffic a measure applies to."""

    OFF = "off"
    # Only what the host forwards for others, such as the clients of a VPN server.
    FORWARD = "forward"
    # Forwarded traffic and the traffic of the host itself.
    ALL = "all"


def _is_usable_limit(value: object) -> bool:
    # bool is an int in Python, but "max_connections = true" is a mistake.
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= MAX_CONNECTIONS_CEILING


@dataclass(frozen=True)
class Measures:
    """What to do on top of blocking the listed trackers; invalid values are rejected."""

    # Drop packets that carry an unencrypted BitTorrent, DHT or tracker request.
    signatures: Scope = Scope.OFF
    # Drop the new connections of an address that has more than max_connections open.
    connection_limit: Scope = Scope.OFF
    # No default: the right number depends on what the clients do, so whoever enables the limit sets it.
    max_connections: int | None = None

    def __post_init__(self) -> None:
        if self.max_connections is None:
            if self.connection_limit is not Scope.OFF:
                raise ConfigError(
                    "connection_limit needs max_connections: how many connections one address may have open"
                )

        # Checked at run time: the value may come straight from a configuration file.
        elif not _is_usable_limit(self.max_connections):
            raise ConfigError(
                f"max_connections must be a whole number from 1 to {MAX_CONNECTIONS_CEILING}, "
                f"not {self.max_connections!r}"
            )


NO_MEASURES = Measures()
