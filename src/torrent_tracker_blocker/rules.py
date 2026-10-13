"""Tracker blocking rule and its CSV representation (``protocol,port,ip``)."""

import csv
import ipaddress
import os
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from pathlib import Path

PROTOCOLS = ("tcp", "udp")
MAX_PORT = 65535
CSV_COLUMNS = 3

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Ranges that only become blockable when the operator explicitly asks for it.
PRIVATE_NETWORKS: tuple[IpNetwork, ...] = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
# IPv6 ranges that carry an IPv4 address inside: a rule for one of them would
# reach an IPv4 host that none of the checks below has looked at.
IPV4_EMBEDDING_NETWORKS = tuple(
    ipaddress.IPv6Network(network)
    for network in ("::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16")
)


class InvalidRuleError(ValueError):
    """A rule that must not be loaded into the firewall."""


def is_blockable_ip(ip: str, allow_private: bool = False) -> bool:
    """Only public unicast IPv4 and IPv6 addresses may be blocked by default.

    Dead trackers often resolve to loopback or private addresses; dropping
    traffic to those would break the host or its local network. Private
    ranges are opt-in; loopback, link-local, multicast and reserved addresses
    are never blockable.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv6Address) and (
        # A zone identifier is free text and has no place in a firewall rule.
        address.scope_id is not None or any(address in network for network in IPV4_EMBEDDING_NETWORKS)
    ):
        return False

    if address.is_global and not address.is_multicast:
        return True

    return allow_private and any(address in network for network in PRIVATE_NETWORKS)


@dataclass(frozen=True)
class TrackerRule:
    """A tracker address and port to drop traffic for; invalid values are rejected."""

    protocol: str
    port: int
    ip: str

    def __post_init__(self) -> None:
        if self.protocol not in PROTOCOLS:
            raise InvalidRuleError(f"unsupported protocol {self.protocol!r}")

        if not 1 <= self.port <= MAX_PORT:
            raise InvalidRuleError(f"port {self.port} is out of range")

        # Only the canonical spelling, so that equal addresses always make equal rules.
        if not is_blockable_ip(self.ip, allow_private=True) or self.ip != str(ipaddress.ip_address(self.ip)):
            raise InvalidRuleError(f"{self.ip!r} is not a blockable IP address")

    @property
    def ip_version(self) -> int:
        """4 or 6."""
        return ipaddress.ip_address(self.ip).version


def without_excluded(rules: Iterable[TrackerRule], networks: Collection[IpNetwork]) -> list[TrackerRule]:
    """Drop the rules whose address belongs to one of the networks."""
    return [rule for rule in rules if not any(ipaddress.ip_address(rule.ip) in network for network in networks)]


def read_rules(path: Path, allow_private: bool = False) -> list[TrackerRule]:
    """Load unique rules from a CSV file, failing on the first invalid row."""
    rules: list[TrackerRule] = []

    with path.open(newline="") as file:
        for line_number, row in enumerate(csv.reader(file), start=1):
            if not row:
                continue

            try:
                if len(row) != CSV_COLUMNS:
                    raise InvalidRuleError("expected protocol,port,ip")

                protocol, port, ip = row
                ip = str(ipaddress.ip_address(ip))

                if not is_blockable_ip(ip, allow_private):
                    raise InvalidRuleError(f"{ip!r} is not a public IP address")

                rules.append(TrackerRule(protocol, int(port), ip))

            except ValueError as error:
                raise InvalidRuleError(f"{path}:{line_number}: {error}") from error

    return list(dict.fromkeys(rules))


def write_rules(path: Path, rules: Iterable[TrackerRule]) -> None:
    """Replace the file in one step: a failed or interrupted write leaves it as it was."""
    # In the same directory, because a rename is only atomic within one file system.
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")

    try:
        with temporary.open("w", newline="") as file:
            writer = csv.writer(file, lineterminator="\n")
            writer.writerows((rule.protocol, rule.port, rule.ip) for rule in rules)
            file.flush()
            os.fsync(file.fileno())

        temporary.replace(path)

    finally:
        temporary.unlink(missing_ok=True)
