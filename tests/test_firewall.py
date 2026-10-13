import subprocess
from typing import NoReturn

import pytest

from torrent_tracker_blocker import firewall
from torrent_tracker_blocker.firewall import (
    ChainStatus,
    FirewallError,
    build_apply_script,
    build_remove_script,
    parse_status,
)
from torrent_tracker_blocker.rules import TrackerRule

RULES = [TrackerRule("tcp", 6969, "46.4.109.148"), TrackerRule("udp", 80, "185.217.0.76")]

CLEAN = """\
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A FORWARD -i tun0 -j ACCEPT
"""

INSTALLED = """\
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-N vpn-forward
-N vpn-input
-N vpn-output
-N vpn-input-extra
-A INPUT -j vpn-input
-A INPUT -m comment --comment "-j vpn-input" -j vpn-input-extra
-A FORWARD -i tun0 -j ACCEPT
-A FORWARD -m comment --comment "torrent trackers" -j vpn-forward
-A FORWARD -j vpn-forward
-A OUTPUT -j vpn-output
-A vpn-input -s 1.2.3.4/32 -p tcp -m tcp --sport 80 -j DROP
"""


def test_apply_script_on_a_clean_firewall() -> None:
    assert (
        build_apply_script(CLEAN, "vpn", RULES)
        == """\
*filter
:vpn-input - [0:0]
:vpn-output - [0:0]
:vpn-forward - [0:0]
-A vpn-input -m addrtype --src-type LOCAL -j RETURN
-A vpn-output -m addrtype --dst-type LOCAL -j RETURN
-A vpn-input -s 46.4.109.148/32 -p tcp -m tcp --sport 6969 -j DROP
-A vpn-input -s 185.217.0.76/32 -p udp -m udp --sport 80 -j DROP
-A vpn-output -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -j DROP
-A vpn-output -d 185.217.0.76/32 -p udp -m udp --dport 80 -j DROP
-A vpn-forward -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -j DROP
-A vpn-forward -d 185.217.0.76/32 -p udp -m udp --dport 80 -j DROP
-I INPUT 1 -j vpn-input
-I OUTPUT 1 -j vpn-output
-I FORWARD 1 -j vpn-forward
COMMIT
"""
    )


def test_apply_script_replaces_only_its_own_jumps() -> None:
    script = build_apply_script(INSTALLED, "vpn", RULES)

    assert [line for line in script.splitlines() if line.startswith("-D")] == [
        "-D INPUT -j vpn-input",
        '-D FORWARD -m comment --comment "torrent trackers" -j vpn-forward',
        "-D FORWARD -j vpn-forward",
        "-D OUTPUT -j vpn-output",
    ]
    assert "1.2.3.4" not in script


def test_apply_script_guards_local_addresses_before_any_drop() -> None:
    lines = build_apply_script(CLEAN, "vpn", RULES).splitlines()
    first_drop = next(index for index, line in enumerate(lines) if line.endswith("-j DROP"))

    assert lines.index("-A vpn-input -m addrtype --src-type LOCAL -j RETURN") < first_drop
    assert lines.index("-A vpn-output -m addrtype --dst-type LOCAL -j RETURN") < first_drop


VERBOSE = """\
-P INPUT ACCEPT -c 0 0
-P FORWARD ACCEPT -c 0 0
-P OUTPUT ACCEPT -c 0 0
-N vpn-forward
-N vpn-input
-N vpn-output
-N vpn-output-extra
-A INPUT -c 12 900 -j vpn-input
-A OUTPUT -c 9 500 -j vpn-output
-A OUTPUT -c 0 0 -j vpn-output-extra
-A vpn-forward -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -c 4 240 -j DROP
-A vpn-input -m addrtype --src-type LOCAL -c 7 420 -j RETURN
-A vpn-input -s 46.4.109.148/32 -p tcp -m tcp --sport 6969 -c 0 0 -j DROP
-A vpn-output -m addrtype --dst-type LOCAL -c 2 120 -j RETURN
-A vpn-output -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -c 3 87 -j DROP
-A vpn-output -d 185.217.0.76/32 -p udp -m udp --dport 80 -c 5 145 -j DROP
-A vpn-output-extra -d 1.2.3.4/32 -c 100 100 -j DROP
"""


def test_parse_status() -> None:
    assert parse_status(VERBOSE, "vpn") == [
        ChainStatus("vpn-input", rules=1, dropped_packets=0, is_active=True),
        ChainStatus("vpn-output", rules=2, dropped_packets=8, is_active=True),
        # The chain exists but FORWARD does not jump to it.
        ChainStatus("vpn-forward", rules=1, dropped_packets=4, is_active=False),
    ]


def test_parse_status_when_nothing_is_installed() -> None:
    assert parse_status("-P INPUT ACCEPT -c 0 0\n", "vpn") == []
    assert parse_status(VERBOSE, "other") == []


def test_remove_script() -> None:
    assert (
        build_remove_script(INSTALLED, "vpn")
        == """\
*filter
-D INPUT -j vpn-input
-D FORWARD -m comment --comment "torrent trackers" -j vpn-forward
-D FORWARD -j vpn-forward
-D OUTPUT -j vpn-output
-F vpn-input
-X vpn-input
-F vpn-output
-X vpn-output
-F vpn-forward
-X vpn-forward
COMMIT
"""
    )


def test_remove_script_is_empty_when_nothing_is_installed() -> None:
    assert build_remove_script(CLEAN, "vpn") is None


@pytest.mark.parametrize("prefix", ["", "a" * 21, "vpn chain", "vpn\n-A INPUT -j ACCEPT", "vpn;x"])
def test_invalid_chain_prefix_is_rejected(prefix: str) -> None:
    with pytest.raises(FirewallError, match="invalid chain name"):
        build_apply_script(CLEAN, prefix, RULES)
    with pytest.raises(FirewallError, match="invalid chain name"):
        build_remove_script(CLEAN, prefix)


def test_longest_chain_name_fits_the_iptables_limit() -> None:
    assert len(firewall.chain_name("a" * 20, "FORWARD")) == 28


def test_missing_iptables_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(*args: object, **kwargs: object) -> NoReturn:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", run)

    with pytest.raises(FirewallError, match="is iptables installed"):
        firewall.apply_rules("vpn", RULES)


def test_iptables_failure_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], **kwargs: object) -> NoReturn:
        raise subprocess.CalledProcessError(4, command, stderr="Permission denied (you must be root)\n")

    monkeypatch.setattr(subprocess, "run", run)

    with pytest.raises(FirewallError, match="iptables failed: Permission denied"):
        firewall.remove_rules("vpn")
