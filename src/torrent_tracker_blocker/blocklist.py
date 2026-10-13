"""Build the rule file from tracker lists and load it into the firewall."""

import ipaddress
import logging
from collections.abc import Sequence
from pathlib import Path

from torrent_tracker_blocker.firewall import apply_rules
from torrent_tracker_blocker.measures import NO_MEASURES, Measures
from torrent_tracker_blocker.parser import build_rules
from torrent_tracker_blocker.rules import IpNetwork, TrackerRule, read_rules, without_excluded, write_rules
from torrent_tracker_blocker.sources import HTTPS_PREFIX, read_networks, read_source

logger = logging.getLogger(__name__)


def _download_rules(sources: Sequence[str], allow_private: bool) -> list[TrackerRule]:
    rules: list[TrackerRule] = []
    for source in sources:
        # A remote list is never trusted to name private addresses.
        is_local = not source.startswith(HTTPS_PREFIX)
        rules += build_rules(read_source(source), allow_private=allow_private and is_local)
    return list(dict.fromkeys(rules))


def _whitelisted_networks(whitelist: Sequence[str]) -> list[IpNetwork]:
    """Resolve the whitelist: an entry is an address or a range itself, or a list of them to read."""
    networks: list[IpNetwork] = []

    for entry in whitelist:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            networks += read_networks(entry)

    return networks


def refresh_rule_file(
    output: Path,
    sources: Sequence[str],
    *,
    whitelist: Sequence[str] = (),
    merge: bool = False,
    allow_private: bool = False,
) -> bool:
    """Write a fresh rule file; False if there is nothing to block."""
    networks = _whitelisted_networks(whitelist)
    rules = without_excluded(_download_rules(sources, allow_private), networks)

    if not rules:
        # Never replace a working list with an empty one, e.g. when DNS is down.
        logger.error("No blockable trackers found; %s not written", output)
        return False

    if merge and output.exists():
        previous = without_excluded(read_rules(output, allow_private), networks)
        rules = list(dict.fromkeys([*previous, *rules]))

    output.parent.mkdir(parents=True, exist_ok=True)
    write_rules(output, rules)
    logger.info("Wrote %d rules to %s", len(rules), output)

    return True


def load_rule_file(path: Path, chain: str, allow_private: bool = False, measures: Measures = NO_MEASURES) -> bool:
    """Replace the firewall rules with those from a rule file and the measures; False if it has no rules."""
    rules = read_rules(path, allow_private)
    if not rules:
        logger.error("No rules found in %s; firewall not changed", path)
        return False

    apply_rules(chain, rules, measures)
    logger.info("Applied %d rules to chains %s-*", len(rules), chain)

    return True
