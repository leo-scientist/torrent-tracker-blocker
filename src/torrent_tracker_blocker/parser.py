"""Turn a list of tracker announce URLs into blocking rules."""

import ipaddress
import logging
import socket
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlsplit

from torrent_tracker_blocker.rules import TrackerRule, is_blockable_ip

logger = logging.getLogger(__name__)

# URL scheme -> (transport protocol, default port)
SCHEMES = {
    "http": ("tcp", 80),
    "https": ("tcp", 443),
    "udp": ("udp", 80),
}
RESOLVER_THREADS = 32

Resolver = Callable[[str], Sequence[str]]


@dataclass(frozen=True)
class Endpoint:
    """Where a tracker listens, as written in its announce URL."""

    protocol: str
    host: str
    port: int


def parse_line(line: str) -> Endpoint | None:
    """Return the endpoint of a tracker URL, or None if the line is not one."""
    try:
        url = urlsplit(line.strip())
        port = url.port
    except ValueError:
        return None
    scheme = SCHEMES.get(url.scheme)
    if scheme is None or not url.hostname:
        return None
    protocol, default_port = scheme
    return Endpoint(protocol, url.hostname, port or default_port)


def resolve_host(host: str) -> list[str]:
    """Return every IPv4 and IPv6 address of a host; empty if it does not resolve."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []

    return list(dict.fromkeys(str(sockaddr[0]) for *_, sockaddr in results))


def build_rules(
    lines: Iterable[str], resolve: Resolver = resolve_host, allow_private: bool = False
) -> list[TrackerRule]:
    """Parse tracker URLs and resolve them into unique rules, keeping input order."""
    endpoints: list[Endpoint] = []

    for line in lines:
        if not line.strip():
            continue

        endpoint = parse_line(line)
        if endpoint is None:
            logger.warning("Skipping unsupported line: %s", line.strip())
            continue

        endpoints.append(endpoint)

    hosts = list(dict.fromkeys(endpoint.host for endpoint in endpoints))

    with ThreadPoolExecutor(max_workers=RESOLVER_THREADS) as pool:
        resolved = dict(zip(hosts, pool.map(resolve, hosts), strict=True))

    blockable: dict[str, list[str]] = {}

    for host, ips in resolved.items():
        # Canonical spelling, whatever the resolver returned.
        blockable[host] = [str(ipaddress.ip_address(ip)) for ip in ips if is_blockable_ip(ip, allow_private)]
        skipped = sorted(ip for ip in set(ips) if not is_blockable_ip(ip, allow_private))

        if not ips:
            logger.warning("Skipping %s: does not resolve", host)

        elif skipped:
            logger.warning("Skipping unblockable addresses of %s: %s", host, ", ".join(skipped))

    rules = [
        TrackerRule(endpoint.protocol, endpoint.port, ip) for endpoint in endpoints for ip in blockable[endpoint.host]
    ]
    return list(dict.fromkeys(rules))
