"""Read tracker and exclusion lists from local files or HTTPS URLs."""

import http.client
import ipaddress
import urllib.request
from pathlib import Path

from torrent_tracker_blocker.rules import IpNetwork

MAX_SOURCE_BYTES = 1_000_000
FETCH_TIMEOUT_SECONDS = 30
HTTPS_PREFIX = "https://"
# Sites behind Cloudflare answer 403 to the default urllib user agent.
USER_AGENT = "torrent-tracker-blocker"


class SourceError(Exception):
    """A tracker or exclusion list could not be read or is invalid."""


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
    # urlopen() is typed as returning Any; for https:// it returns an HTTPResponse.
    response: http.client.HTTPResponse

    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
            if not response.url.startswith(HTTPS_PREFIX):
                raise SourceError(f"{url}: redirected to insecure {response.url}")

            return response.read(MAX_SOURCE_BYTES + 1)

    except (OSError, http.client.HTTPException) as error:
        raise SourceError(f"{url}: {error}") from error


def read_source(source: str) -> list[str]:
    """Return the lines of a local file or of an https:// URL.

    The lists end up as firewall rules, so remote ones are only accepted over
    a connection that cannot be tampered with.
    """
    if source.startswith(HTTPS_PREFIX):
        content = _fetch(source)
    elif "://" in source:
        raise SourceError(f"{source}: only https:// URLs and local files are supported")
    else:
        try:
            content = Path(source).read_bytes()
        except OSError as error:
            raise SourceError(f"{source}: {error.strerror}") from error

    if len(content) > MAX_SOURCE_BYTES:
        raise SourceError(f"{source}: larger than {MAX_SOURCE_BYTES} bytes")

    try:
        return content.decode().splitlines()
    except UnicodeDecodeError as error:
        raise SourceError(f"{source}: not a UTF-8 text file") from error


def read_networks(source: str) -> list[IpNetwork]:
    """Read IPv4 and IPv6 addresses or CIDR ranges, one per line; ``#`` starts a comment."""
    networks: list[IpNetwork] = []

    for line_number, line in enumerate(read_source(source), start=1):
        entry = line.split("#", 1)[0].strip()

        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as error:
            # A typo must not silently leave an address unprotected.
            raise SourceError(f"{source}:{line_number}: {error}") from error

    return networks
