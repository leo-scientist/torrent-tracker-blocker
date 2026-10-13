import shutil
import subprocess
from itertools import product
from pathlib import Path
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
from torrent_tracker_blocker.measures import Measures, Scope
from torrent_tracker_blocker.rules import TrackerRule

RULES = [TrackerRule("tcp", 6969, "46.4.109.148"), TrackerRule("udp", 80, "185.217.0.76")]
IPV6_RULES = [TrackerRule("udp", 6969, "2a01:4f8:c17:8f74::2")]

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


def test_apply_script_for_ipv6_rules() -> None:
    script = build_apply_script(CLEAN, "vpn", IPV6_RULES)

    assert [line for line in script.splitlines() if line.endswith("-j DROP")] == [
        "-A vpn-input -s 2a01:4f8:c17:8f74::2/128 -p udp -m udp --sport 6969 -j DROP",
        "-A vpn-output -d 2a01:4f8:c17:8f74::2/128 -p udp -m udp --dport 6969 -j DROP",
        "-A vpn-forward -d 2a01:4f8:c17:8f74::2/128 -p udp -m udp --dport 6969 -j DROP",
    ]
    assert "-A vpn-output -m addrtype --dst-type LOCAL -j RETURN" in script


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
    assert parse_status(VERBOSE, "vpn", 4) == [
        ChainStatus(4, "vpn-input", rules=1, dropped_packets=0, is_active=True),
        ChainStatus(4, "vpn-output", rules=2, dropped_packets=8, is_active=True),
        # The chain exists but FORWARD does not jump to it.
        ChainStatus(4, "vpn-forward", rules=1, dropped_packets=4, is_active=False),
    ]


def test_parse_status_when_nothing_is_installed() -> None:
    assert parse_status("-P INPUT ACCEPT -c 0 0\n", "vpn", 4) == []
    assert parse_status(VERBOSE, "other", 6) == []


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


Commands = list[tuple[list[str], str | None]]


@pytest.fixture
def commands(monkeypatch: pytest.MonkeyPatch) -> Commands:
    """Record every firewall command with its input; listings report an untouched firewall."""
    calls: Commands = []

    def run(command: list[str], input: str | None = None, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, input))
        return subprocess.CompletedProcess(command, 0, stdout=INSTALLED if "-S" in command else "", stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


@pytest.fixture
def ipv6_stack(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Pretend the host has ip6tables and an IPv6 stack; return the file that marks the stack."""
    stack = tmp_path / "if_inet6"
    stack.touch()
    monkeypatch.setattr(shutil, "which", lambda command: f"/usr/sbin/{command}")
    monkeypatch.setattr(firewall, "IPV6_STACK", stack)
    return stack


def test_apply_rules_updates_each_ip_version_with_its_own_rules(commands: Commands, ipv6_stack: Path) -> None:
    firewall.apply_rules("vpn", [*RULES, *IPV6_RULES])

    assert [command for command, _ in commands] == [
        ["iptables", "-w", "-S"],
        ["ip6tables", "-w", "-S"],
        ["iptables-restore", "-w", "--noflush"],
        ["ip6tables-restore", "-w", "--noflush"],
    ]
    ipv4_script, ipv6_script = commands[2][1], commands[3][1]
    assert ipv4_script is not None and ipv6_script is not None
    assert "46.4.109.148/32" in ipv4_script and "2a01:4f8" not in ipv4_script
    assert "2a01:4f8:c17:8f74::2/128" in ipv6_script and "46.4.109.148" not in ipv6_script


def test_apply_rules_clears_ipv6_chains_when_no_ipv6_rules_are_left(commands: Commands, ipv6_stack: Path) -> None:
    firewall.apply_rules("vpn", RULES)

    command, ipv6_script = commands[3]
    assert command[0] == "ip6tables-restore"
    assert ipv6_script is not None
    assert ":vpn-output - [0:0]" in ipv6_script
    assert "DROP" not in ipv6_script


def test_apply_rules_skips_ipv6_without_ip6tables(
    commands: Commands, ipv6_stack: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(shutil, "which", lambda command: None)

    firewall.apply_rules("vpn", [*RULES, *IPV6_RULES])

    assert [command[0] for command, _ in commands] == ["iptables", "iptables-restore"]
    assert "IPv6 trackers are not blocked: ip6tables is not installed" in caplog.text
    assert firewall.managed_families() == [firewall.IPV4]


def test_apply_rules_skips_ipv6_without_a_kernel_ipv6_stack(
    commands: Commands, ipv6_stack: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ipv6_stack.unlink()

    firewall.apply_rules("vpn", [*RULES, *IPV6_RULES])

    assert [command[0] for command, _ in commands] == ["iptables", "iptables-restore"]
    assert "IPv6 trackers are not blocked: the kernel has no IPv6 support" in caplog.text


def test_apply_rules_is_silent_about_ipv6_when_there_is_nothing_to_block(
    commands: Commands, ipv6_stack: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ipv6_stack.unlink()

    firewall.apply_rules("vpn", RULES)

    assert caplog.text == ""


def test_remove_rules_covers_both_ip_versions(commands: Commands, ipv6_stack: Path) -> None:
    assert firewall.remove_rules("vpn") is True
    assert [command[0] for command, _ in commands] == ["iptables", "ip6tables", "iptables-restore", "ip6tables-restore"]

    commands.clear()
    assert firewall.remove_rules("other") is False
    assert [command[0] for command, _ in commands] == ["iptables", "ip6tables"]


def test_chain_statuses_cover_both_ip_versions(monkeypatch: pytest.MonkeyPatch, ipv6_stack: Path) -> None:
    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout=VERBOSE if command[0] == "iptables" else "", stderr="")

    monkeypatch.setattr(subprocess, "run", run)

    assert [(status.ip_version, status.name) for status in firewall.chain_statuses("vpn")] == [
        (4, "vpn-input"),
        (4, "vpn-output"),
        (4, "vpn-forward"),
    ]


SCOPE_COMBINATIONS = list(product(Scope, Scope))
# The chains that each measure must add its rules to, per scope.
SIGNATURE_CHAINS = {
    Scope.OFF: [],
    Scope.FORWARD: ["vpn-forward"],
    Scope.ALL: ["vpn-input", "vpn-output", "vpn-forward"],
}
CONNECTION_LIMIT_CHAINS = {
    Scope.OFF: [],
    Scope.FORWARD: ["vpn-forward"],
    Scope.ALL: ["vpn-output", "vpn-forward"],
}
SIGNATURES = [
    '-m string --hex-string "|13|BitTorrent protocol" --algo kmp --to 128',
    '-p udp -m string --string "d1:ad2:id20:" --algo kmp --to 64',
    '-p udp -m string --hex-string "|000004172710198000000000|" --algo kmp --to 64',
    '-p tcp -m string --string "info_hash=" --algo kmp --to 512',
]


def signature_commands(scope: Scope) -> list[str]:
    return [f"-A {chain} {signature} -j DROP" for chain in SIGNATURE_CHAINS[scope] for signature in SIGNATURES]


def connection_limit_commands(scope: Scope, max_connections: int) -> list[str]:
    return [
        f"-A {chain} -m conntrack --ctstate NEW -m connlimit --connlimit-above {max_connections} --connlimit-saddr"
        " -j DROP"
        for chain in CONNECTION_LIMIT_CHAINS[scope]
    ]


def test_apply_script_with_every_measure() -> None:
    measures = Measures(signatures=Scope.ALL, connection_limit=Scope.ALL, max_connections=150)

    assert (
        build_apply_script(CLEAN, "vpn", RULES[:1], measures)
        == """\
*filter
:vpn-input - [0:0]
:vpn-output - [0:0]
:vpn-forward - [0:0]
-A vpn-input -m addrtype --src-type LOCAL -j RETURN
-A vpn-output -m addrtype --dst-type LOCAL -j RETURN
-A vpn-input -s 46.4.109.148/32 -p tcp -m tcp --sport 6969 -j DROP
-A vpn-output -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -j DROP
-A vpn-forward -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -j DROP
-A vpn-input -m string --hex-string "|13|BitTorrent protocol" --algo kmp --to 128 -j DROP
-A vpn-input -p udp -m string --string "d1:ad2:id20:" --algo kmp --to 64 -j DROP
-A vpn-input -p udp -m string --hex-string "|000004172710198000000000|" --algo kmp --to 64 -j DROP
-A vpn-input -p tcp -m string --string "info_hash=" --algo kmp --to 512 -j DROP
-A vpn-output -m string --hex-string "|13|BitTorrent protocol" --algo kmp --to 128 -j DROP
-A vpn-output -p udp -m string --string "d1:ad2:id20:" --algo kmp --to 64 -j DROP
-A vpn-output -p udp -m string --hex-string "|000004172710198000000000|" --algo kmp --to 64 -j DROP
-A vpn-output -p tcp -m string --string "info_hash=" --algo kmp --to 512 -j DROP
-A vpn-forward -m string --hex-string "|13|BitTorrent protocol" --algo kmp --to 128 -j DROP
-A vpn-forward -p udp -m string --string "d1:ad2:id20:" --algo kmp --to 64 -j DROP
-A vpn-forward -p udp -m string --hex-string "|000004172710198000000000|" --algo kmp --to 64 -j DROP
-A vpn-forward -p tcp -m string --string "info_hash=" --algo kmp --to 512 -j DROP
-A vpn-output -m conntrack --ctstate NEW -m connlimit --connlimit-above 150 --connlimit-saddr -j DROP
-A vpn-forward -m conntrack --ctstate NEW -m connlimit --connlimit-above 150 --connlimit-saddr -j DROP
-I INPUT 1 -j vpn-input
-I OUTPUT 1 -j vpn-output
-I FORWARD 1 -j vpn-forward
COMMIT
"""
    )


def test_apply_script_without_measures_is_the_default() -> None:
    assert build_apply_script(CLEAN, "vpn", RULES, Measures()) == build_apply_script(CLEAN, "vpn", RULES)


@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
@pytest.mark.parametrize("rules", [RULES, IPV6_RULES, []], ids=["ipv4", "ipv6", "no-rules"])
@pytest.mark.parametrize("current_rules", [CLEAN, INSTALLED], ids=["clean", "installed"])
def test_apply_script_puts_each_measure_into_the_chains_of_its_scope(
    signatures: Scope, connection_limit: Scope, rules: list[TrackerRule], current_rules: str
) -> None:
    measures = Measures(signatures, connection_limit, max_connections=37)

    lines = build_apply_script(current_rules, "vpn", rules, measures).splitlines()

    expected = [*signature_commands(signatures), *connection_limit_commands(connection_limit, 37)]
    assert [line for line in lines if "-m string" in line or "-m connlimit" in line] == expected
    # Everything else is exactly what is installed without any measure.
    assert [line for line in lines if line not in expected] == build_apply_script(
        current_rules, "vpn", rules
    ).splitlines()


@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
def test_apply_script_orders_measures_after_the_guards_and_the_tracker_rules(
    signatures: Scope, connection_limit: Scope
) -> None:
    lines = build_apply_script(CLEAN, "vpn", RULES, Measures(signatures, connection_limit, 37)).splitlines()
    measure_lines = [index for index, line in enumerate(lines) if "-m string" in line or "-m connlimit" in line]
    tracker_lines = [index for index, line in enumerate(lines) if "port" in line]
    guards = [index for index, line in enumerate(lines) if line.endswith("-j RETURN")]
    jumps = [index for index, line in enumerate(lines) if line.startswith("-I")]

    assert len(guards) == 2 and len(jumps) == 3
    assert all(max(guards) < index < min(jumps) for index in measure_lines)
    assert all(max(tracker_lines) < index for index in measure_lines)


@pytest.mark.parametrize("signatures", Scope)
def test_apply_script_has_no_trace_of_a_connection_limit_that_is_off(signatures: Scope) -> None:
    script = build_apply_script(CLEAN, "vpn", RULES, Measures(signatures))

    assert "connlimit" not in script
    assert "None" not in script


@pytest.mark.parametrize("max_connections", [1, 200, 4294967295])
def test_apply_script_uses_the_configured_connection_limit(max_connections: int) -> None:
    script = build_apply_script(
        CLEAN, "vpn", RULES, Measures(connection_limit=Scope.FORWARD, max_connections=max_connections)
    )

    assert connection_limit_commands(Scope.FORWARD, max_connections) == [
        line for line in script.splitlines() if "connlimit" in line
    ]


def as_listing(script: str, packets: int) -> str:
    """What ``iptables -v -S`` prints once the script is applied and every rule has matched some packets."""
    listing = []
    for line in script.splitlines():
        if line.startswith(":"):
            listing.append(f"-N {line[1:].split()[0]}")
        elif line.startswith("-A"):
            match, _, target = line.rpartition(" -j ")
            listing.append(f"{match} -c {packets} {packets * 60} -j {target}")
        elif line.startswith("-I"):
            _, builtin, _, _, chain = line.split()
            listing.append(f"-A {builtin} -c 0 0 -j {chain}")
    return "\n".join(listing) + "\n"


@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
@pytest.mark.parametrize("rules", [RULES, IPV6_RULES, []], ids=["ipv4", "ipv6", "no-rules"])
def test_parse_status_tells_the_measures_apart_in_every_combination(
    signatures: Scope, connection_limit: Scope, rules: list[TrackerRule]
) -> None:
    script = build_apply_script(CLEAN, "vpn", rules, Measures(signatures, connection_limit, max_connections=37))

    assert parse_status(as_listing(script, packets=5), "vpn", 4) == [
        ChainStatus(
            4,
            chain,
            rules=len(rules),
            dropped_packets=5 * len(rules),
            is_active=True,
            signature_drops=5 * len(SIGNATURES) if chain in SIGNATURE_CHAINS[signatures] else None,
            connection_limit_drops=5 if chain in CONNECTION_LIMIT_CHAINS[connection_limit] else None,
        )
        for chain in ["vpn-input", "vpn-output", "vpn-forward"]
    ]


# As printed by a real iptables: the hex string is normalised and the default mask is spelled out.
VERBOSE_WITH_MEASURES = """\
-P FORWARD ACCEPT -c 0 0
-N vpn-forward
-N vpn-output
-A FORWARD -c 900 54000 -j vpn-forward
-A OUTPUT -c 30 1800 -j vpn-output
-A vpn-forward -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -c 4 240 -j DROP
-A vpn-forward -m string --hex-string "|13426974546f7272656e742070726f746f636f6c|" --algo kmp --to 128 -c 7 868 -j DROP
-A vpn-forward -p udp -m string --string "d1:ad2:id20:" --algo kmp --to 64 -c 20 1680 -j DROP
-A vpn-forward -p udp -m string --hex-string "|000004172710198000000000|" --algo kmp --to 64 -c 3 132 -j DROP
-A vpn-forward -p tcp -m string --string "info_hash=" --algo kmp --to 512 -c 0 0 -j DROP
-A vpn-forward -m conntrack --ctstate NEW -m connlimit --connlimit-above 200 --connlimit-mask 32 --connlimit-saddr -c 11 660 -j DROP
-A vpn-output -m addrtype --dst-type LOCAL -c 2 120 -j RETURN
-A vpn-output -d 46.4.109.148/32 -p tcp -m tcp --dport 6969 -c 1 60 -j DROP
"""  # noqa: E501


def test_parse_status_counts_what_each_measure_dropped() -> None:
    assert parse_status(VERBOSE_WITH_MEASURES, "vpn", 4) == [
        ChainStatus(4, "vpn-output", rules=1, dropped_packets=1, is_active=True),
        ChainStatus(
            4,
            "vpn-forward",
            rules=1,
            dropped_packets=4,
            is_active=True,
            signature_drops=30,
            connection_limit_drops=11,
        ),
    ]


@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
def test_apply_rules_installs_the_measures_for_both_ip_versions(
    commands: Commands, ipv6_stack: Path, signatures: Scope, connection_limit: Scope
) -> None:
    firewall.apply_rules("vpn", [*RULES, *IPV6_RULES], Measures(signatures, connection_limit, max_connections=37))

    expected = [*signature_commands(signatures), *connection_limit_commands(connection_limit, 37)]
    for command, script in commands[2:]:
        assert command[0] in ("iptables-restore", "ip6tables-restore")
        assert script is not None
        assert [line for line in script.splitlines() if "-m string" in line or "-m connlimit" in line] == expected


def test_apply_rules_installs_no_measure_by_default(commands: Commands, ipv6_stack: Path) -> None:
    firewall.apply_rules("vpn", RULES)

    assert not any("string" in (script or "") or "connlimit" in (script or "") for _, script in commands)
