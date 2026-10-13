import logging
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
