import ipaddress
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Self

import pytest

from torrent_tracker_blocker import sources
from torrent_tracker_blocker.sources import SourceError, read_networks, read_source

URL = "https://lists.example.com/trackers.txt"


class FakeResponse:
    def __init__(self, body: bytes, url: str = URL) -> None:
        self.body = body
        self.url = url

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def read(self, size: int) -> bytes:
        return self.body[:size]


class Remote:
    def __init__(self) -> None:
        self.response: FakeResponse | Exception = FakeResponse(b"")
        self.requests: list[urllib.request.Request] = []


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Remote:
    """Serve ``remote.response`` for every request and record the requests."""
    remote = Remote()

    def urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        remote.requests.append(request)
        if isinstance(remote.response, Exception):
            raise remote.response
        return remote.response

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return remote


def test_read_source_reads_a_local_file(tmp_path: Path) -> None:
    path = tmp_path / "trackers.txt"
    path.write_text("udp://tracker.example.com:6969/announce\n\nhttp://tracker.example.com/\n")

    assert read_source(str(path)) == [
        "udp://tracker.example.com:6969/announce",
        "",
        "http://tracker.example.com/",
    ]


def test_read_source_downloads_an_https_url(remote: Remote) -> None:
    remote.response = FakeResponse(b"udp://tracker.example.com:6969/announce\n")

    assert read_source(URL) == ["udp://tracker.example.com:6969/announce"]
    assert remote.requests[0].full_url == URL
    assert remote.requests[0].get_header("User-agent") == "torrent-tracker-blocker"


@pytest.mark.parametrize(
    "source",
    [
        "http://lists.example.com/trackers.txt",
        "ftp://lists.example.com/trackers.txt",
        "file:///etc/passwd",
        "HTTPS://lists.example.com/trackers.txt",
    ],
)
def test_read_source_rejects_other_url_schemes(remote: Remote, source: str) -> None:
    with pytest.raises(SourceError, match="only https:// URLs and local files"):
        read_source(source)
    assert remote.requests == []


def test_read_source_rejects_a_redirect_to_plain_http(remote: Remote) -> None:
    remote.response = FakeResponse(b"udp://tracker.example.com/\n", url="http://evil.example.com/")

    with pytest.raises(SourceError, match="redirected to insecure http://evil.example.com/"):
        read_source(URL)


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.HTTPError(URL, 403, "Forbidden", Message(), None),
        urllib.error.URLError("certificate verify failed"),
        TimeoutError("timed out"),
    ],
)
def test_read_source_reports_download_failures(remote: Remote, error: Exception) -> None:
    remote.response = error

    with pytest.raises(SourceError, match=r"^https://lists\.example\.com/trackers\.txt: "):
        read_source(URL)


def test_read_source_rejects_an_oversized_download(remote: Remote, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sources, "MAX_SOURCE_BYTES", 10)
    remote.response = FakeResponse(b"x" * 11)

    with pytest.raises(SourceError, match="larger than 10 bytes"):
        read_source(URL)


def test_read_source_rejects_an_oversized_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sources, "MAX_SOURCE_BYTES", 10)
    path = tmp_path / "trackers.txt"
    path.write_bytes(b"x" * 11)

    with pytest.raises(SourceError, match="larger than 10 bytes"):
        read_source(str(path))


def test_read_source_rejects_binary_content(remote: Remote) -> None:
    remote.response = FakeResponse(b"\xff\xfe\x00")

    with pytest.raises(SourceError, match="not a UTF-8 text file"):
        read_source(URL)


def test_read_source_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match=r"missing\.txt: No such file or directory"):
        read_source(str(tmp_path / "missing.txt"))


def test_read_networks(tmp_path: Path) -> None:
    path = tmp_path / "exclude.txt"
    path.write_text("# Cloudflare\n104.16.0.0/13\n\n  8.8.8.8  # DNS\n198.41.128.7/17\n")

    assert read_networks(str(path)) == [
        ipaddress.IPv4Network("104.16.0.0/13"),
        ipaddress.IPv4Network("8.8.8.8/32"),
        ipaddress.IPv4Network("198.41.128.0/17"),
    ]


@pytest.mark.parametrize("entry", ["example.com", "8.8.8", "8.8.8.8/33", "2400:cb00::/32"])
def test_read_networks_reports_the_invalid_line(tmp_path: Path, entry: str) -> None:
    path = tmp_path / "exclude.txt"
    path.write_text(f"8.8.8.8\n{entry}\n")

    with pytest.raises(SourceError, match=r"exclude\.txt:2: "):
        read_networks(str(path))
