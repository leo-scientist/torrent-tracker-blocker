import logging
import socket
import urllib.request
from collections.abc import Iterator
from typing import NoReturn

import pytest


@pytest.fixture(autouse=True)
def reset_log_level() -> Iterator[None]:
    """Keep the package log level set by the CLI from leaking into other tests."""
    yield
    logging.getLogger("torrent_tracker_blocker").setLevel(logging.NOTSET)


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any real download: unit tests must never use the network."""

    def urlopen(request: urllib.request.Request, timeout: float | None = None) -> NoReturn:
        raise AssertionError(f"unexpected download of {request.full_url}")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)


AddrInfo = tuple[socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int]]


@pytest.fixture
def dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """Resolve host names from the returned table instead of asking the real DNS."""
    hosts: dict[str, list[str]] = {}

    def getaddrinfo(host: str, *args: object, **kwargs: object) -> list[AddrInfo]:
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in hosts[host]
        ]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return hosts
