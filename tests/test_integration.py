"""Tests against a real iptables.

They rewrite the firewall of the machine they run on, so they only run when
explicitly enabled: see scripts/integration-test.sh.
"""

import os
import socket
import subprocess
from collections.abc import Iterator

import pytest

from torrent_tracker_blocker.firewall import ChainStatus, apply_rules, chain_statuses, remove_rules
from torrent_tracker_blocker.rules import TrackerRule

pytestmark = pytest.mark.skipif(
    os.environ.get("TRACKER_BLOCKER_INTEGRATION") != "1",
    reason="set TRACKER_BLOCKER_INTEGRATION=1 to run against a real iptables",
)

PREFIX = "tb-test"
RULES = [TrackerRule("tcp", 6969, "46.4.109.148"), TrackerRule("udp", 80, "185.217.0.76")]
IPV6_RULE = TrackerRule("udp", 6969, "2a01:4f8:c17:8f74::2")


def run(*command: str) -> list[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout.splitlines()


def iptables(*args: str) -> list[str]:
    return run("iptables", "-w", *args)


def ip6tables(*args: str) -> list[str]:
    return run("ip6tables", "-w", *args)


@pytest.fixture(autouse=True)
def firewall() -> Iterator[None]:
    # A typical VPN gateway: traffic is accepted before any appended rule is reached.
    iptables("-A", "FORWARD", "-j", "ACCEPT")
    # A foreign chain whose name merely contains our prefix must be left alone.
    iptables("-N", f"x-{PREFIX}-input")
    iptables("-A", "INPUT", "-j", f"x-{PREFIX}-input")
    yield
    remove_rules(PREFIX)
    iptables("-D", "INPUT", "-j", f"x-{PREFIX}-input")
    iptables("-X", f"x-{PREFIX}-input")
    iptables("-D", "FORWARD", "-j", "ACCEPT")


def test_apply_installs_rules_ahead_of_existing_ones() -> None:
    apply_rules(PREFIX, RULES)

    assert iptables("-S", "FORWARD")[1:] == [
        f"-A FORWARD -j {PREFIX}-forward",
        "-A FORWARD -j ACCEPT",
    ]
    assert iptables("-S", "OUTPUT")[1:] == [f"-A OUTPUT -j {PREFIX}-output"]
    assert iptables("-S", f"{PREFIX}-input")[1:] == [
        f"-A {PREFIX}-input -m addrtype --src-type LOCAL -j RETURN",
        f"-A {PREFIX}-input -s 46.4.109.148/32 -p tcp -m tcp --sport 6969 -j DROP",
        f"-A {PREFIX}-input -s 185.217.0.76/32 -p udp -m udp --sport 80 -j DROP",
    ]
    assert iptables("-S", f"{PREFIX}-forward")[1:] == [
        f"-A {PREFIX}-forward -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -j DROP",
        f"-A {PREFIX}-forward -d 185.217.0.76/32 -p udp -m udp --dport 80 -j DROP",
    ]


def test_apply_twice_replaces_the_previous_rules() -> None:
    apply_rules(PREFIX, RULES)
    apply_rules(PREFIX, RULES[:1])

    assert iptables("-S", "INPUT")[1:] == [
        f"-A INPUT -j {PREFIX}-input",
        f"-A INPUT -j x-{PREFIX}-input",
    ]
    assert iptables("-S", f"{PREFIX}-output")[1:] == [
        f"-A {PREFIX}-output -m addrtype --dst-type LOCAL -j RETURN",
        f"-A {PREFIX}-output -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -j DROP",
    ]


def test_traffic_to_a_tracker_is_dropped() -> None:
    tracker = RULES[1]
    apply_rules(PREFIX, RULES)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        # The kernel reports a packet dropped in OUTPUT as EPERM.
        with pytest.raises(PermissionError):
            client.sendto(b"announce", (tracker.ip, tracker.port))
        client.sendto(b"announce", (tracker.ip, tracker.port + 1))


def test_status_counts_dropped_packets() -> None:
    tracker = RULES[1]
    assert chain_statuses(PREFIX) == []
    apply_rules(PREFIX, RULES)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        for _ in range(3):
            with pytest.raises(PermissionError):
                client.sendto(b"announce", (tracker.ip, tracker.port))

    assert chain_statuses(PREFIX) == [
        ChainStatus(4, f"{PREFIX}-input", rules=2, dropped_packets=0, is_active=True),
        ChainStatus(4, f"{PREFIX}-output", rules=2, dropped_packets=3, is_active=True),
        ChainStatus(4, f"{PREFIX}-forward", rules=2, dropped_packets=0, is_active=True),
        ChainStatus(6, f"{PREFIX}-input", rules=0, dropped_packets=0, is_active=True),
        ChainStatus(6, f"{PREFIX}-output", rules=0, dropped_packets=0, is_active=True),
        ChainStatus(6, f"{PREFIX}-forward", rules=0, dropped_packets=0, is_active=True),
    ]
    iptables("-D", "FORWARD", "-j", f"{PREFIX}-forward")
    assert chain_statuses(PREFIX)[2].is_active is False


def test_traffic_to_an_own_address_is_never_dropped() -> None:
    # Somebody slipped one of this host's public addresses into the block list.
    own = RULES[0]
    subprocess.run(["ip", "addr", "add", f"{own.ip}/32", "dev", "lo"], check=True)
    try:
        apply_rules(PREFIX, RULES)

        with socket.create_server((own.ip, own.port)):
            socket.create_connection((own.ip, own.port), timeout=3).close()
    finally:
        subprocess.run(["ip", "addr", "del", f"{own.ip}/32", "dev", "lo"], check=True)


def test_apply_installs_ipv6_rules_in_ip6tables_only() -> None:
    apply_rules(PREFIX, [*RULES, IPV6_RULE])

    assert ip6tables("-S", "FORWARD")[1:] == [f"-A FORWARD -j {PREFIX}-forward"]
    assert ip6tables("-S", f"{PREFIX}-input")[1:] == [
        f"-A {PREFIX}-input -m addrtype --src-type LOCAL -j RETURN",
        f"-A {PREFIX}-input -s {IPV6_RULE.ip}/128 -p udp -m udp --sport 6969 -j DROP",
    ]
    assert ip6tables("-S", f"{PREFIX}-output")[1:] == [
        f"-A {PREFIX}-output -m addrtype --dst-type LOCAL -j RETURN",
        f"-A {PREFIX}-output -d {IPV6_RULE.ip}/128 -p udp -m udp --dport 6969 -j DROP",
    ]
    assert ip6tables("-S", f"{PREFIX}-forward")[1:] == [
        f"-A {PREFIX}-forward -d {IPV6_RULE.ip}/128 -p udp -m udp --dport 6969 -j DROP",
    ]
    assert not any(IPV6_RULE.ip in line for line in iptables("-S"))
    assert not any("46.4.109.148" in line for line in ip6tables("-S"))


def test_apply_without_ipv6_rules_empties_the_ipv6_chains() -> None:
    apply_rules(PREFIX, [*RULES, IPV6_RULE])
    apply_rules(PREFIX, RULES)

    assert ip6tables("-S", f"{PREFIX}-forward")[1:] == []
    assert chain_statuses(PREFIX)[5] == ChainStatus(6, f"{PREFIX}-forward", rules=0, dropped_packets=0, is_active=True)


def test_ipv6_traffic_to_a_tracker_is_dropped() -> None:
    # Give the tracker a route, so that packets to it reach the firewall at all.
    run("ip", "-6", "route", "add", f"{IPV6_RULE.ip}/128", "dev", "lo")
    try:
        apply_rules(PREFIX, [*RULES, IPV6_RULE])

        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
            with pytest.raises(PermissionError):
                client.sendto(b"announce", (IPV6_RULE.ip, IPV6_RULE.port))
            client.sendto(b"announce", (IPV6_RULE.ip, IPV6_RULE.port + 1))

        assert chain_statuses(PREFIX)[4].dropped_packets == 1
    finally:
        run("ip", "-6", "route", "del", f"{IPV6_RULE.ip}/128", "dev", "lo")


def test_ipv6_traffic_to_an_own_address_is_never_dropped() -> None:
    own = TrackerRule("tcp", 6969, "2a01:4f8:c17:8f74::3")
    run("ip", "-6", "addr", "add", f"{own.ip}/128", "dev", "lo", "nodad")
    try:
        apply_rules(PREFIX, [*RULES, own])

        with socket.create_server((own.ip, own.port), family=socket.AF_INET6):
            socket.create_connection((own.ip, own.port), timeout=3).close()
    finally:
        run("ip", "-6", "addr", "del", f"{own.ip}/128", "dev", "lo")


def test_remove_restores_the_original_firewall() -> None:
    before = iptables("-S"), ip6tables("-S")
    apply_rules(PREFIX, [*RULES, IPV6_RULE])

    assert remove_rules(PREFIX) is True
    assert (iptables("-S"), ip6tables("-S")) == before
    assert remove_rules(PREFIX) is False
