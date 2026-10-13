import ipaddress
from collections.abc import Iterator
from pathlib import Path

import pytest

from torrent_tracker_blocker.rules import (
    InvalidRuleError,
    TrackerRule,
    is_blockable_ip,
    read_rules,
    without_excluded,
    write_rules,
)


@pytest.mark.parametrize("ip", ["46.4.13.97", "1.1.1.1"])
def test_public_addresses_are_blockable(ip: str) -> None:
    assert is_blockable_ip(ip)


@pytest.mark.parametrize(
    "ip",
    [
        "0.0.0.0",  # noqa: S104
        "0.1.2.3",
        "10.0.0.1",
        "10.255.255.255",
        "100.64.0.1",
        "100.127.255.255",
        "127.0.0.1",
        "127.0.0.11",
        "127.255.255.254",
        "169.254.1.1",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "192.168.255.255",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.250",
        "240.0.0.1",
        "255.255.255.255",
        "127.1",
        "2130706433",
        "0x7f.0.0.1",
        "0177.0.0.1",
        "::ffff:127.0.0.1",
        " 46.4.13.97",
        "::1",
        "1",
        "tracker.example.com",
        "",
    ],
)
def test_other_addresses_are_not_blockable(ip: str) -> None:
    assert not is_blockable_ip(ip)


PRIVATE = [
    "10.0.0.1",
    "10.255.255.255",
    "100.64.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
]
NEVER_BLOCKABLE = [
    "0.0.0.0",  # noqa: S104
    "127.0.0.1",
    "127.0.0.11",
    "169.254.169.254",
    "192.0.2.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "127.1",
    "localhost",
]


@pytest.mark.parametrize("ip", PRIVATE)
def test_private_addresses_are_blockable_only_on_request(ip: str) -> None:
    assert not is_blockable_ip(ip)
    assert is_blockable_ip(ip, allow_private=True)


@pytest.mark.parametrize("ip", NEVER_BLOCKABLE)
def test_local_addresses_are_never_blockable(ip: str) -> None:
    assert not is_blockable_ip(ip, allow_private=True)


@pytest.mark.parametrize(
    ("protocol", "port", "ip"),
    [
        ("http", 80, "46.4.13.97"),
        ("tcp", 0, "46.4.13.97"),
        ("tcp", 65536, "46.4.13.97"),
        ("tcp", 80, "127.0.0.11"),
        ("tcp", 80, "169.254.169.254"),
        ("tcp", 80, "46.4.13.97\n-A INPUT -j ACCEPT"),
    ],
)
def test_invalid_rule_is_rejected(protocol: str, port: int, ip: str) -> None:
    with pytest.raises(InvalidRuleError):
        TrackerRule(protocol, port, ip)


def test_without_excluded() -> None:
    rules = [
        TrackerRule("tcp", 443, "104.16.1.1"),
        TrackerRule("udp", 6969, "46.4.13.97"),
        TrackerRule("udp", 53, "8.8.8.8"),
    ]
    networks = [ipaddress.IPv4Network("104.16.0.0/13"), ipaddress.IPv4Network("8.8.8.8/32")]

    assert without_excluded(rules, networks) == [TrackerRule("udp", 6969, "46.4.13.97")]
    assert without_excluded(rules, []) == rules


def test_csv_round_trip(tmp_path: Path) -> None:
    rules = [TrackerRule("tcp", 6969, "46.4.109.148"), TrackerRule("udp", 80, "185.217.0.76")]
    path = tmp_path / "trackers.csv"

    write_rules(path, rules)

    assert path.read_text() == "tcp,6969,46.4.109.148\nudp,80,185.217.0.76\n"
    assert read_rules(path) == rules


def test_write_rules_keeps_the_previous_file_when_writing_fails(tmp_path: Path) -> None:
    path = tmp_path / "trackers.csv"
    path.write_text("tcp,80,46.4.13.97\n")

    def failing_rules() -> Iterator[TrackerRule]:
        yield TrackerRule("udp", 80, "185.217.0.76")
        raise OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        write_rules(path, failing_rules())

    assert path.read_text() == "tcp,80,46.4.13.97\n"
    assert list(tmp_path.iterdir()) == [path]


def test_read_rules_drops_duplicates_and_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "trackers.csv"
    path.write_text("tcp,80,46.4.13.97\n\ntcp,80,46.4.13.97\nudp,80,46.4.13.97\n")

    assert read_rules(path) == [
        TrackerRule("tcp", 80, "46.4.13.97"),
        TrackerRule("udp", 80, "46.4.13.97"),
    ]


@pytest.mark.parametrize(
    "row",
    [
        "tcp,80",
        "tcp,eighty,46.4.13.97",
        "http,80,46.4.13.97",
        "tcp,80,127.0.0.1",
        "tcp,80,46.4.13.97,x",
    ],
)
def test_read_rules_reports_the_invalid_line(tmp_path: Path, row: str) -> None:
    path = tmp_path / "trackers.csv"
    path.write_text(f"tcp,80,46.4.13.97\n{row}\n")

    with pytest.raises(InvalidRuleError, match=r"trackers\.csv:2: "):
        read_rules(path)


def test_read_rules_accepts_private_addresses_only_on_request(tmp_path: Path) -> None:
    path = tmp_path / "trackers.csv"
    path.write_text("tcp,80,46.4.13.97\ntcp,8080,10.10.0.5\n")

    with pytest.raises(InvalidRuleError, match=r"trackers\.csv:2: '10\.10\.0\.5' is not a public"):
        read_rules(path)
    assert read_rules(path, allow_private=True) == [
        TrackerRule("tcp", 80, "46.4.13.97"),
        TrackerRule("tcp", 8080, "10.10.0.5"),
    ]


@pytest.mark.parametrize("ip", NEVER_BLOCKABLE)
def test_read_rules_never_accepts_local_addresses(tmp_path: Path, ip: str) -> None:
    path = tmp_path / "trackers.csv"
    path.write_text(f"tcp,80,{ip}\n")

    with pytest.raises(InvalidRuleError):
        read_rules(path, allow_private=True)
