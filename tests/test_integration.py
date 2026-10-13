"""Tests against a real iptables.

They rewrite the firewall of the machine they run on, so they only run when
explicitly enabled: see scripts/integration-test.sh.
"""

import os
import socket
import struct
import subprocess
from collections.abc import Iterator
from itertools import product

import pytest

from torrent_tracker_blocker.firewall import ChainStatus, apply_rules, chain_statuses, remove_rules
from torrent_tracker_blocker.measures import NO_MEASURES, Measures, Scope
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


SCOPE_COMBINATIONS = list(product(Scope, Scope))
IP_VERSIONS = [4, 6]
# Documentation ranges: routable, but nobody answers there.
REMOTE = {4: "192.0.2.1", 6: "2001:db8::1"}
LOOPBACK = {4: "127.0.0.1", 6: "::1"}
INTERFACE = "tb-test0"
SOCKET_FAMILY = {4: socket.AF_INET, 6: socket.AF_INET6}
HOST_PREFIX_LENGTH = {4: 32, 6: 128}
# The measure rules as iptables prints them back.
SIGNATURES = [
    '-m string --hex-string "|13426974546f7272656e742070726f746f636f6c|" --algo kmp --to 128',
    '-p udp -m string --string "d1:ad2:id20:" --algo kmp --to 64',
    '-p udp -m string --hex-string "|000004172710198000000000|" --algo kmp --to 64',
    '-p tcp -m string --string "info_hash=" --algo kmp --to 512',
]
SIGNATURE_CHAINS = {Scope.OFF: [], Scope.FORWARD: ["forward"], Scope.ALL: ["input", "output", "forward"]}
CONNECTION_LIMIT_CHAINS = {Scope.OFF: [], Scope.FORWARD: ["forward"], Scope.ALL: ["output", "forward"]}

HANDSHAKE = b"\x13BitTorrent protocol" + bytes(48)
UTP_HEADER = bytes(20)
DHT_QUERY = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
TRACKER_CONNECT = bytes.fromhex("0000041727101980" + "00000000" + "12345678")
ANNOUNCE = b"GET /announce?info_hash=%124Vx%9A&peer_id=-TR4000-000000000000&port=51413 HTTP/1.1\r\n\r\n"


def listing(ip_version: int, *args: str) -> list[str]:
    return iptables(*args) if ip_version == 4 else ip6tables(*args)


def is_dropped(client: socket.socket, packet: bytes, address: tuple[str, int]) -> bool:
    # The kernel reports a packet dropped in OUTPUT as EPERM.
    try:
        client.sendto(packet, address)
    except PermissionError:
        return True
    return False


def udp_is_dropped(ip_version: int, payload: bytes, port: int = 6881, host: str | None = None) -> bool:
    with socket.socket(SOCKET_FAMILY[ip_version], socket.SOCK_DGRAM) as client:
        return is_dropped(client, payload, (host or REMOTE[ip_version], port))


def tcp_is_dropped(ip_version: int, payload: bytes) -> bool:
    """Send a hand-made TCP segment: a real connection needs somebody to answer the handshake."""
    header = struct.pack("!HHIIBBHHH", 40000, 6881, 1, 1, 5 << 4, 0x18, 65535, 0, 0)
    with socket.socket(SOCKET_FAMILY[ip_version], socket.SOCK_RAW, socket.IPPROTO_TCP) as client:
        return is_dropped(client, header + payload, (REMOTE[ip_version], 0))


@pytest.fixture
def ipv6_route() -> Iterator[None]:
    """Give the IPv6 documentation range a route, so that packets to it reach the firewall at all.

    Through an interface of its own: packets routed to the loopback come back in, which
    confuses the connection tracking that the connection limit counts with.
    """
    run("ip", "link", "add", INTERFACE, "type", "dummy")
    try:
        run("ip", "link", "set", INTERFACE, "up")
        run("ip", "-6", "addr", "add", "2001:db8:ffff::1/64", "dev", INTERFACE, "nodad")
        run("ip", "-6", "route", "add", "2001:db8::/32", "dev", INTERFACE)
        yield
    finally:
        run("ip", "link", "del", INTERFACE)


def expected_chain(ip_version: int, builtin: str, rules: list[TrackerRule], measures: Measures) -> list[str]:
    chain = f"{PREFIX}-{builtin}"
    lines = []
    if builtin == "input":
        lines.append(f"-A {chain} -m addrtype --src-type LOCAL -j RETURN")
    if builtin == "output":
        lines.append(f"-A {chain} -m addrtype --dst-type LOCAL -j RETURN")

    address, port = ("-s", "--sport") if builtin == "input" else ("-d", "--dport")
    lines += [
        f"-A {chain} {address} {rule.ip}/{HOST_PREFIX_LENGTH[ip_version]}"
        f" -p {rule.protocol} -m {rule.protocol} {port} {rule.port} -j DROP"
        for rule in rules
        if rule.ip_version == ip_version
    ]

    if builtin in SIGNATURE_CHAINS[measures.signatures]:
        lines += [f"-A {chain} {signature} -j DROP" for signature in SIGNATURES]
    if builtin in CONNECTION_LIMIT_CHAINS[measures.connection_limit]:
        lines.append(
            f"-A {chain} -m conntrack --ctstate NEW -m connlimit --connlimit-above {measures.max_connections}"
            f" --connlimit-mask {HOST_PREFIX_LENGTH[ip_version]} --connlimit-saddr -j DROP"
        )

    return lines


@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
def test_every_combination_of_measures_installs_exactly_its_rules(signatures: Scope, connection_limit: Scope) -> None:
    before = iptables("-S"), ip6tables("-S")
    rules = [*RULES, IPV6_RULE]
    measures = Measures(signatures, connection_limit, max_connections=37)

    # Whatever was configured before must leave no trace.
    apply_rules(PREFIX, rules, Measures(Scope.ALL, Scope.ALL, max_connections=7))
    apply_rules(PREFIX, rules, measures)

    for ip_version in IP_VERSIONS:
        for builtin in ("input", "output", "forward"):
            assert listing(ip_version, "-S", f"{PREFIX}-{builtin}")[1:] == expected_chain(
                ip_version, builtin, rules, measures
            )

    assert chain_statuses(PREFIX) == [
        ChainStatus(
            ip_version,
            f"{PREFIX}-{builtin}",
            rules=sum(rule.ip_version == ip_version for rule in rules),
            dropped_packets=0,
            is_active=True,
            signature_drops=0 if builtin in SIGNATURE_CHAINS[signatures] else None,
            connection_limit_drops=0 if builtin in CONNECTION_LIMIT_CHAINS[connection_limit] else None,
        )
        for ip_version in IP_VERSIONS
        for builtin in ("input", "output", "forward")
    ]

    assert remove_rules(PREFIX) is True
    assert (iptables("-S"), ip6tables("-S")) == before


@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
@pytest.mark.parametrize("ip_version", IP_VERSIONS)
def test_every_combination_of_measures_treats_the_traffic_of_the_host_as_configured(
    ipv6_route: None, ip_version: int, signatures: Scope, connection_limit: Scope
) -> None:
    measures = Measures(signatures, connection_limit, max_connections=3)

    apply_rules(PREFIX, RULES, measures)
    assert udp_is_dropped(ip_version, DHT_QUERY) is (signatures is Scope.ALL)
    assert udp_is_dropped(ip_version, b"not a torrent", port=6999) is False

    # Applying again starts counting the connections afresh.
    apply_rules(PREFIX, RULES, measures)
    connections = [udp_is_dropped(ip_version, b"hello", port) for port in range(7000, 7008)]

    is_limited = connection_limit is Scope.ALL
    assert connections == [False] * 3 + [is_limited] * 5


@pytest.mark.parametrize("ip_version", IP_VERSIONS)
def test_signatures_drop_every_kind_of_bittorrent_packet(ipv6_route: None, ip_version: int) -> None:
    apply_rules(PREFIX, RULES, Measures(signatures=Scope.ALL))

    assert udp_is_dropped(ip_version, DHT_QUERY)
    assert udp_is_dropped(ip_version, TRACKER_CONNECT)
    assert udp_is_dropped(ip_version, UTP_HEADER + HANDSHAKE)
    assert tcp_is_dropped(ip_version, HANDSHAKE)
    assert tcp_is_dropped(ip_version, ANNOUNCE)

    output = chain_statuses(PREFIX)[1 if ip_version == 4 else 4]
    assert (output.ip_version, output.name) == (ip_version, f"{PREFIX}-output")
    assert output.signature_drops == 5
    assert output.dropped_packets == 0


@pytest.mark.parametrize("ip_version", IP_VERSIONS)
def test_signatures_let_other_traffic_through(ipv6_route: None, ip_version: int) -> None:
    apply_rules(PREFIX, RULES, Measures(signatures=Scope.ALL))

    assert not udp_is_dropped(ip_version, b"\x00" * 16)
    assert not udp_is_dropped(ip_version, b"d1:rd2:id20:abcdefghij0123456789e1:t2:aa1:y1:re")
    assert not tcp_is_dropped(ip_version, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert not tcp_is_dropped(ip_version, bytes(64))
    # Only the start of a packet is searched: this is not what a DHT query looks like.
    assert not udp_is_dropped(ip_version, b"x" * 100 + DHT_QUERY)
    assert chain_statuses(PREFIX)[1 if ip_version == 4 else 4].signature_drops == 0


@pytest.mark.parametrize("ip_version", IP_VERSIONS)
@pytest.mark.parametrize("scope", [Scope.OFF, Scope.FORWARD])
def test_signatures_outside_their_scope_leave_the_host_alone(ipv6_route: None, ip_version: int, scope: Scope) -> None:
    apply_rules(PREFIX, RULES, Measures(signatures=scope))

    assert not udp_is_dropped(ip_version, DHT_QUERY)
    assert not udp_is_dropped(ip_version, TRACKER_CONNECT)
    assert not udp_is_dropped(ip_version, UTP_HEADER + HANDSHAKE)
    assert not tcp_is_dropped(ip_version, HANDSHAKE)
    assert not tcp_is_dropped(ip_version, ANNOUNCE)


@pytest.mark.parametrize("ip_version", IP_VERSIONS)
def test_measures_never_apply_to_the_own_addresses_of_the_host(ip_version: int) -> None:
    apply_rules(PREFIX, RULES, Measures(Scope.ALL, Scope.ALL, max_connections=1))

    assert not udp_is_dropped(ip_version, DHT_QUERY, host=LOOPBACK[ip_version])
    assert [udp_is_dropped(ip_version, b"hello", port, LOOPBACK[ip_version]) for port in range(7000, 7005)] == [
        False
    ] * 5


@pytest.mark.parametrize("ip_version", IP_VERSIONS)
@pytest.mark.parametrize("max_connections", [1, 2, 5])
def test_the_connection_limit_is_exact(ipv6_route: None, ip_version: int, max_connections: int) -> None:
    apply_rules(PREFIX, RULES, Measures(connection_limit=Scope.ALL, max_connections=max_connections))

    connections = [udp_is_dropped(ip_version, b"hello", port) for port in range(7000, 7008)]

    assert connections == [False] * max_connections + [True] * (8 - max_connections)
    output = chain_statuses(PREFIX)[1 if ip_version == 4 else 4]
    assert output.connection_limit_drops == 8 - max_connections


def test_tracker_rules_keep_working_next_to_the_measures() -> None:
    tracker = RULES[1]
    apply_rules(PREFIX, RULES, Measures(Scope.ALL, Scope.ALL, max_connections=100))

    assert udp_is_dropped(4, b"announce", tracker.port, tracker.ip)
    assert not udp_is_dropped(4, b"announce", tracker.port + 1, tracker.ip)

    output = chain_statuses(PREFIX)[1]
    assert (output.dropped_packets, output.signature_drops, output.connection_limit_drops) == (1, 0, 0)


@pytest.mark.parametrize("max_connections", [1, 4294967295])
@pytest.mark.parametrize("ip_version", IP_VERSIONS)
def test_the_smallest_and_the_largest_connection_limit_can_be_installed(ip_version: int, max_connections: int) -> None:
    apply_rules(PREFIX, RULES, Measures(connection_limit=Scope.ALL, max_connections=max_connections))

    assert any(
        f"--connlimit-above {max_connections} " in line for line in listing(ip_version, "-S", f"{PREFIX}-forward")
    )


def test_measures_are_removed_by_applying_without_them() -> None:
    apply_rules(PREFIX, RULES, Measures(Scope.ALL, Scope.ALL, max_connections=5))
    apply_rules(PREFIX, RULES, NO_MEASURES)

    for ip_version in IP_VERSIONS:
        assert not any("string" in line or "connlimit" in line for line in listing(ip_version, "-S"))
