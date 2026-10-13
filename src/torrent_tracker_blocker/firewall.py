"""Sync tracker rules into dedicated iptables and ip6tables chains.

Every change to one IP version is one ``iptables-restore --noflush``
transaction: its firewall ends up either fully updated or untouched, and rules
outside our chains are never modified.
"""

import ipaddress
import logging
import re
import shlex
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from torrent_tracker_blocker.rules import TrackerRule

logger = logging.getLogger(__name__)

BUILTIN_CHAINS = ("INPUT", "OUTPUT", "FORWARD")
# iptables limits chain names to 28 characters; the longest suffix is "-forward".
CHAIN_PREFIX_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,20}")
JUMP_FLAGS = ("-j", "-g")
# Present whenever the kernel has an IPv6 stack, even if no interface uses it.
IPV6_STACK = Path("/proc/net/if_inet6")


class FirewallError(Exception):
    """The firewall could not be read or changed."""


@dataclass(frozen=True)
class Family:
    """An IP version and the tools that manage its firewall."""

    ip_version: int
    command: str
    restore_command: str


IPV4 = Family(4, "iptables", "iptables-restore")
IPV6 = Family(6, "ip6tables", "ip6tables-restore")


@dataclass(frozen=True)
class ChainStatus:
    """State of one of our chains as reported by iptables."""

    ip_version: int
    name: str
    rules: int
    dropped_packets: int
    # False when nothing jumps to the chain from its built-in chain, so it sees no traffic.
    is_active: bool


def chain_name(prefix: str, builtin: str) -> str:
    """Return the name of our chain that a built-in chain jumps to."""
    return f"{prefix}-{builtin.lower()}"


def _own_chains(prefix: str) -> list[str]:
    if not CHAIN_PREFIX_PATTERN.fullmatch(prefix):
        raise FirewallError(f"invalid chain name {prefix!r}: use 1-20 letters, digits, '_', '.' or '-'")
    return [chain_name(prefix, builtin) for builtin in BUILTIN_CHAINS]


def _drop_command(builtin: str, chain: str, rule: TrackerRule) -> str:
    # INPUT sees packets coming from the tracker; OUTPUT/FORWARD see packets going to it.
    address, port = ("-s", "--sport") if builtin == "INPUT" else ("-d", "--dport")
    host = f"{rule.ip}/{ipaddress.ip_address(rule.ip).max_prefixlen}"
    return f"-A {chain} {address} {host} -p {rule.protocol} -m {rule.protocol} {port} {rule.port} -j DROP"


def _jumps_to(line: str, chains: Sequence[str]) -> bool:
    tokens = shlex.split(line)
    return tokens[:1] == ["-A"] and any(flag in JUMP_FLAGS and target in chains for flag, target in pairwise(tokens))


def _delete_jumps(current_rules: str, chains: Sequence[str]) -> list[str]:
    """Commands deleting every existing rule that jumps to one of our chains."""
    return ["-D" + line.removeprefix("-A") for line in current_rules.splitlines() if _jumps_to(line, chains)]


def build_apply_script(current_rules: str, prefix: str, rules: Sequence[TrackerRule]) -> str:
    """Build iptables-restore input that replaces our chains with the given rules.

    ``current_rules`` is the output of ``iptables -S``. The same script works
    for ip6tables when the rules are IPv6 ones.
    """
    chains = _own_chains(prefix)
    lines = ["*filter"]
    # Declaring a chain creates it, or flushes it if it already exists.
    lines += [f":{chain} - [0:0]" for chain in chains]
    lines += _delete_jumps(current_rules, chains)
    # Whatever the rule file says, never drop traffic between this host and its own addresses.
    lines += [
        f"-A {chain_name(prefix, 'INPUT')} -m addrtype --src-type LOCAL -j RETURN",
        f"-A {chain_name(prefix, 'OUTPUT')} -m addrtype --dst-type LOCAL -j RETURN",
    ]

    for builtin, chain in zip(BUILTIN_CHAINS, chains, strict=True):
        lines += [_drop_command(builtin, chain, rule) for rule in rules]

    # Jumps go first so that earlier ACCEPT rules cannot bypass the block list.
    lines += [f"-I {builtin} 1 -j {chain}" for builtin, chain in zip(BUILTIN_CHAINS, chains, strict=True)]
    lines.append("COMMIT")

    return "\n".join(lines) + "\n"


def build_remove_script(current_rules: str, prefix: str) -> str | None:
    """Build iptables-restore input that removes our chains; None if nothing is installed."""
    chains = _own_chains(prefix)
    declared = current_rules.splitlines()
    existing = [chain for chain in chains if f"-N {chain}" in declared]
    commands = _delete_jumps(current_rules, chains)

    for chain in existing:
        commands += [f"-F {chain}", f"-X {chain}"]

    if not commands:
        return None

    return "\n".join(["*filter", *commands, "COMMIT"]) + "\n"


def parse_status(verbose_rules: str, prefix: str, ip_version: int) -> list[ChainStatus]:
    """Describe our installed chains from the output of ``iptables -v -S``."""
    lines = [shlex.split(line) for line in verbose_rules.splitlines()]
    statuses: list[ChainStatus] = []

    for builtin, chain in zip(BUILTIN_CHAINS, _own_chains(prefix), strict=True):
        if ["-N", chain] not in lines:
            continue

        drops = [tokens for tokens in lines if tokens[:2] == ["-A", chain] and tokens[-1] == "DROP"]
        statuses.append(
            ChainStatus(
                ip_version=ip_version,
                name=chain,
                rules=len(drops),
                # Counters are printed as "-c PACKETS BYTES".
                dropped_packets=sum(int(tokens[tokens.index("-c") + 1]) for tokens in drops),
                is_active=any(tokens[:2] == ["-A", builtin] and tokens[-2:] == ["-j", chain] for tokens in lines),
            )
        )

    return statuses


def _run(command: list[str], stdin: str | None = None) -> str:
    try:
        result = subprocess.run(command, input=stdin, capture_output=True, text=True, check=True)
    except FileNotFoundError as error:
        raise FirewallError(f"{command[0]} not found: is iptables installed?") from error
    except subprocess.CalledProcessError as error:
        raise FirewallError(f"{command[0]} failed: {error.stderr.strip()}") from error
    return result.stdout


def _ipv6_unavailable_reason() -> str | None:
    if shutil.which(IPV6.command) is None:
        return f"{IPV6.command} is not installed"

    if not IPV6_STACK.exists():
        return "the kernel has no IPv6 support"

    return None


def managed_families() -> list[Family]:
    """Return the IP versions whose firewall can be managed on this host."""
    return [IPV4] if _ipv6_unavailable_reason() else [IPV4, IPV6]


def _current_rules(family: Family) -> str:
    return _run([family.command, "-w", "-S"])


def _restore(family: Family, script: str) -> None:
    _run([family.restore_command, "-w", "--noflush"], stdin=script)


def apply_rules(prefix: str, rules: Sequence[TrackerRule]) -> None:
    """Replace any previously applied rules with the given ones.

    IPv4 and IPv6 are separate transactions, applied in that order.
    """
    families = managed_families()
    reason = _ipv6_unavailable_reason()

    if reason and any(rule.ip_version == IPV6.ip_version for rule in rules):
        logger.warning("IPv6 trackers are not blocked: %s", reason)

    # Read and build everything first, so that a failure there changes nothing.
    scripts = [
        build_apply_script(
            _current_rules(family), prefix, [rule for rule in rules if rule.ip_version == family.ip_version]
        )
        for family in families
    ]

    for family, script in zip(families, scripts, strict=True):
        _restore(family, script)


def remove_rules(prefix: str) -> bool:
    """Remove our chains and jumps; return False if there was nothing to remove."""
    families = managed_families()
    scripts = [build_remove_script(_current_rules(family), prefix) for family in families]

    for family, script in zip(families, scripts, strict=True):
        if script is not None:
            _restore(family, script)

    return any(script is not None for script in scripts)


def chain_statuses(prefix: str) -> list[ChainStatus]:
    """Status of each installed chain; empty if nothing is installed."""
    return [
        status
        for family in managed_families()
        for status in parse_status(_run([family.command, "-w", "-v", "-S"]), prefix, family.ip_version)
    ]
