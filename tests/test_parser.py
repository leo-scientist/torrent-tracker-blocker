import socket
from typing import NoReturn

import pytest

from torrent_tracker_blocker.parser import Endpoint, build_rules, parse_line, resolve_host
from torrent_tracker_blocker.rules import TrackerRule

DNS = {
    "tracker.example.com": ["46.4.13.97"],
    "multi.example.com": ["46.4.13.97", "5.79.209.57"],
    "sinkholed.example.com": ["127.0.0.11"],
    "mixed.example.com": ["10.0.0.1", "5.79.209.57"],
    "dual.example.com": ["2A01:4F8:C17:8F74:0:0:0:2", "46.4.13.97"],
    "local6.example.com": ["::1", "fe80::1%eth0", "fd00::5", "::ffff:8.8.8.8", "64:ff9b::808:808"],
}


def fake_resolve(host: str) -> list[str]:
    return DNS.get(host, [host] if host[0].isdigit() else [])


@pytest.mark.parametrize(
    ("line", "endpoint"),
    [
        (
            "http://tracker.example.com:6969/announce\n",
            Endpoint("tcp", "tracker.example.com", 6969),
        ),
        ("http://tracker.example.com/announce.php", Endpoint("tcp", "tracker.example.com", 80)),
        ("https://tracker.example.com/announce", Endpoint("tcp", "tracker.example.com", 443)),
        ("udp://tracker.example.com/", Endpoint("udp", "tracker.example.com", 80)),
        (
            "  udp://Tracker.Example.com:2710/announce  ",
            Endpoint("udp", "tracker.example.com", 2710),
        ),
        ("http://80.246.243.18:6969/announce", Endpoint("tcp", "80.246.243.18", 6969)),
        ("udp://[2A01:4F8::1]:6969/announce", Endpoint("udp", "2a01:4f8::1", 6969)),
        ("https://[2a01:4f8::1]/announce", Endpoint("tcp", "2a01:4f8::1", 443)),
    ],
)
def test_parse_line(line: str, endpoint: Endpoint) -> None:
    assert parse_line(line) == endpoint


@pytest.mark.parametrize(
    "line",
    [
        "tracker.example.com:6969",
        "tracker.example.com",
        "ftp://tracker.example.com/",
        "http://tracker.example.com:port/announce",
        "http://tracker.example.com:99999/announce",
        "http:///announce",
        "http://[::1/announce",
    ],
)
def test_parse_line_rejects_unsupported_lines(line: str) -> None:
    assert parse_line(line) is None


def test_build_rules_keeps_order_and_drops_duplicates() -> None:
    lines = [
        "udp://tracker.example.com:2710/announce\n",
        "\n",
        "http://tracker.example.com/announce\n",
        "udp://tracker.example.com:2710/other\n",
        "http://46.4.13.97:80/announce",
    ]

    assert build_rules(lines, fake_resolve) == [
        TrackerRule("udp", 2710, "46.4.13.97"),
        TrackerRule("tcp", 80, "46.4.13.97"),
    ]


def test_build_rules_blocks_every_address_of_a_host() -> None:
    assert build_rules(["http://multi.example.com:6969/announce"], fake_resolve) == [
        TrackerRule("tcp", 6969, "46.4.13.97"),
        TrackerRule("tcp", 6969, "5.79.209.57"),
    ]


def test_build_rules_blocks_ipv6_addresses_in_canonical_spelling() -> None:
    lines = [
        "udp://dual.example.com:6969/announce",
        "udp://[2a01:4f8:c17:8f74:0:0:0:2]:6969/announce",
        "http://[2a01:4f8:c17:8f74::3]/announce",
    ]

    assert build_rules(lines, fake_resolve) == [
        TrackerRule("udp", 6969, "2a01:4f8:c17:8f74::2"),
        TrackerRule("udp", 6969, "46.4.13.97"),
        TrackerRule("tcp", 80, "2a01:4f8:c17:8f74::3"),
    ]


def test_build_rules_skips_local_ipv6_addresses(caplog: pytest.LogCaptureFixture) -> None:
    lines = ["udp://local6.example.com:6969/announce"]

    assert build_rules(lines, fake_resolve) == []
    assert (
        "Skipping unblockable addresses of local6.example.com: "
        "64:ff9b::808:808, ::1, ::ffff:8.8.8.8, fd00::5, fe80::1%eth0" in caplog.text
    )
    assert build_rules(lines, fake_resolve, allow_private=True) == [TrackerRule("udp", 6969, "fd00::5")]


def test_build_rules_skips_what_cannot_be_blocked(caplog: pytest.LogCaptureFixture) -> None:
    lines = [
        "not a tracker",
        "http://unresolved.example.com/announce",
        "http://sinkholed.example.com/announce",
        "http://127.0.0.1:6969/announce",
        "http://mixed.example.com/announce",
    ]

    assert build_rules(lines, fake_resolve) == [TrackerRule("tcp", 80, "5.79.209.57")]
    assert "Skipping unsupported line: not a tracker" in caplog.text
    assert "Skipping unresolved.example.com: does not resolve" in caplog.text
    assert "Skipping unblockable addresses of sinkholed.example.com: 127.0.0.11" in caplog.text
    assert "Skipping unblockable addresses of mixed.example.com: 10.0.0.1" in caplog.text


def test_build_rules_allow_private_admits_private_ranges_only() -> None:
    lines = [
        "http://mixed.example.com/announce",
        "http://sinkholed.example.com/announce",
        "udp://192.168.1.1:6969/announce",
        "udp://169.254.169.254:6969/announce",
    ]

    assert build_rules(lines, fake_resolve, allow_private=True) == [
        TrackerRule("tcp", 80, "10.0.0.1"),
        TrackerRule("tcp", 80, "5.79.209.57"),
        TrackerRule("udp", 6969, "192.168.1.1"),
    ]


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "127.1",
        "2130706433",
        "0x7f.0.0.1",
        "[::1]",
        "[0:0:0:0:0:0:0:1]",
        "[::ffff:127.0.0.1]",
        "[::ffff:7f00:1]",
        "[64:ff9b::7f00:1]",
        "[2002:7f00:1::1]",
        "[fe80::1]",
    ],
)
def test_build_rules_cannot_be_tricked_into_blocking_loopback(host: str) -> None:
    # No fake resolver: these spellings of 127.0.0.1 go through the real one.
    assert build_rules([f"http://{host}:22/announce"]) == []
    assert build_rules([f"http://{host}:22/announce"], allow_private=True) == []


def test_build_rules_never_reads_an_octal_address_as_loopback() -> None:
    # The C library decides: glibc reads the first octet as octal (127), macOS as decimal (177).
    assert build_rules(["http://0177.0.0.1:22/announce"]) in ([], [TrackerRule("tcp", 22, "177.0.0.1")])


def test_resolve_host_returns_a_literal_address_without_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", pytest.fail)

    assert resolve_host("46.4.13.97") == ["46.4.13.97"]
    assert resolve_host("2A01:4F8:C17:8F74:0:0:0:2") == ["2a01:4f8:c17:8f74::2"]


def test_resolve_host_returns_all_addresses_of_both_versions(dns: dict[str, list[str]]) -> None:
    dns["dual.example.com"] = ["2a01:4f8:c17:8f74::2", "46.4.13.97", "5.79.209.57", "46.4.13.97"]

    assert resolve_host("dual.example.com") == ["2a01:4f8:c17:8f74::2", "46.4.13.97", "5.79.209.57"]


@pytest.mark.parametrize("error", [socket.gaierror("not found"), UnicodeError("label too long")])
def test_resolve_host_returns_nothing_on_failure(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def fail(host: str, *args: object, **kwargs: object) -> NoReturn:
        raise error

    monkeypatch.setattr(socket, "getaddrinfo", fail)

    assert resolve_host("dead.example.com") == []
