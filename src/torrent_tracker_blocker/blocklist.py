"""Build the rule file from tracker lists and load it into the firewall."""

import logging
from collections.abc import Sequence
from pathlib import Path

from torrent_tracker_blocker.firewall import apply_rules
from torrent_tracker_blocker.parser import build_rules
from torrent_tracker_blocker.rules import TrackerRule, read_rules, without_excluded, write_rules
from torrent_tracker_blocker.sources import HTTPS_PREFIX, read_networks, read_source

logger = logging.getLogger(__name__)

# Cloudflare addresses are shared with a huge number of unrelated sites.
CLOUDFLARE_RANGES = "https://www.cloudflare.com/ips-v4"


def _download_rules(sources: Sequence[str], allow_private: bool) -> list[TrackerRule]:
    rules: list[TrackerRule] = []
    for source in sources:
        # A remote list is never trusted to name private addresses.
        is_local = not source.startswith(HTTPS_PREFIX)
        rules += build_rules(read_source(source), allow_private=allow_private and is_local)
    return list(dict.fromkeys(rules))


def refresh_rule_file(
    output: Path,
    sources: Sequence[str],
    *,
    excludes: Sequence[str] = (),
    block_cloudflare: bool = False,
    merge: bool = False,
    allow_private: bool = False,
) -> bool:
    """Write a fresh rule file; False if there is nothing to block."""
    exclude_sources = excludes if block_cloudflare else [CLOUDFLARE_RANGES, *excludes]
    networks = [network for source in exclude_sources for network in read_networks(source)]
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


def load_rule_file(path: Path, chain: str, allow_private: bool = False) -> bool:
    """Replace the firewall rules with those from a rule file; False if it has none."""
    rules = read_rules(path, allow_private)
    if not rules:
        logger.error("No rules found in %s; firewall not changed", path)
        return False

    apply_rules(chain, rules)
    logger.info("Applied %d rules to chains %s-*", len(rules), chain)

    return True
