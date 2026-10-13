"""Command line interface."""

import argparse
import logging
from collections.abc import Callable, Sequence
from pathlib import Path

from torrent_tracker_blocker.blocklist import load_rule_file, refresh_rule_file
from torrent_tracker_blocker.firewall import (
    BUILTIN_CHAINS,
    FirewallError,
    chain_statuses,
    managed_families,
    remove_rules,
)
from torrent_tracker_blocker.rules import InvalidRuleError
from torrent_tracker_blocker.sources import SourceError

logger = logging.getLogger(__name__)

DEFAULT_CHAIN = "tracker-blocker"
DEFAULT_OUTPUT = Path("trackers.csv")
# Where `update` keeps the rules, so that they can be restored at boot.
STATE_FILE = Path("/var/lib/torrent-tracker-blocker/trackers.csv")
# Public lists of working trackers, refreshed at least daily.
DEFAULT_SOURCES = (
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
    "https://newtrackon.com/api/live",
)

Handler = Callable[[argparse.Namespace], int]


def _refresh(args: argparse.Namespace) -> bool:
    return refresh_rule_file(
        args.output,
        args.input or DEFAULT_SOURCES,
        excludes=args.exclude,
        block_cloudflare=args.block_cloudflare,
        merge=args.merge,
        allow_private=args.allow_private,
    )


def _load(path: Path, args: argparse.Namespace) -> int:
    return 0 if load_rule_file(path, args.chain, args.allow_private) else 1


def _parse(args: argparse.Namespace) -> int:
    return 0 if _refresh(args) else 1


def _apply(args: argparse.Namespace) -> int:
    return _load(args.input, args)


def _update(args: argparse.Namespace) -> int:
    if not _refresh(args):
        return 1
    return _load(args.output, args)


def _remove(args: argparse.Namespace) -> int:
    if remove_rules(args.chain):
        logger.info("Removed chains %s-*", args.chain)
    else:
        logger.info("Nothing to remove for chains %s-*", args.chain)
    return 0


def _status(args: argparse.Namespace) -> int:
    statuses = chain_statuses(args.chain)
    if not statuses:
        print(f"Not installed: no {args.chain}-* chains")
        return 1

    for status in statuses:
        note = "" if status.is_active else " (inactive: nothing jumps to this chain)"
        print(
            f"IPv{status.ip_version} {status.name}: {status.rules} rules, "
            f"{status.dropped_packets} packets dropped{note}"
        )

    expected_chains = len(BUILTIN_CHAINS) * len(managed_families())
    is_complete = len(statuses) == expected_chains and all(s.is_active for s in statuses)

    return 0 if is_complete else 1


def _add_refresh_arguments(parser: argparse.ArgumentParser, default_output: Path) -> None:
    parser.add_argument(
        "-i",
        "--input",
        action="append",
        metavar="SOURCE",
        help="file or https:// URL with tracker URLs; repeatable "
        "(default: the ngosang/trackerslist and newTrackon public lists)",
    )

    parser.add_argument(
        "-x",
        "--exclude",
        action="append",
        default=[],
        metavar="SOURCE",
        help="file or https:// URL with IP addresses/CIDR ranges to never block; repeatable",
    )

    parser.add_argument(
        "--block-cloudflare",
        action="store_true",
        help="also block trackers behind Cloudflare; their addresses are shared with "
        "unrelated sites, so those are excluded by default",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=default_output,
        help=f"CSV file to write (default: {default_output})",
    )

    parser.add_argument(
        "-m",
        "--merge",
        action="store_true",
        help="add the new rules to the existing output file instead of replacing it",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tracker-blocker", description="Block BitTorrent trackers with iptables")
    commands = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-q", "--quiet", action="store_true", help="only print errors")

    chain = argparse.ArgumentParser(add_help=False)
    chain.add_argument(
        "-c",
        "--chain",
        default=DEFAULT_CHAIN,
        help=f"prefix of the iptables chains (default: {DEFAULT_CHAIN})",
    )

    private = argparse.ArgumentParser(add_help=False)
    private.add_argument(
        "--allow-private",
        action="store_true",
        help="accept private addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) "
        "from local files; never from downloaded lists",
    )

    update = commands.add_parser(
        "update",
        parents=[common, chain, private],
        help="download the tracker lists and load them into iptables",
    )
    _add_refresh_arguments(update, STATE_FILE)
    update.set_defaults(handler=_update)

    parse = commands.add_parser(
        "parse",
        parents=[common, private],
        help="download the tracker lists and resolve them into a CSV of rules",
    )
    _add_refresh_arguments(parse, DEFAULT_OUTPUT)
    parse.set_defaults(handler=_parse)

    apply = commands.add_parser(
        "apply",
        parents=[common, chain, private],
        help="replace the iptables rules with those from a CSV",
    )
    apply.add_argument("-i", "--input", type=Path, required=True, help="CSV file with rules")
    apply.set_defaults(handler=_apply)

    remove = commands.add_parser("remove", parents=[common, chain], help="remove the iptables rules")
    remove.set_defaults(handler=_remove)

    status = commands.add_parser(
        "status", parents=[common, chain], help="show the installed rules and what they dropped"
    )
    status.set_defaults(handler=_status)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface and return the exit code."""
    args = _build_parser().parse_args(argv)
    logging.basicConfig(format="%(levelname)s: %(message)s")
    logging.getLogger(__package__).setLevel(logging.ERROR if args.quiet else logging.INFO)
    handler: Handler = args.handler

    try:
        return handler(args)
    except (InvalidRuleError, SourceError, FirewallError, OSError) as error:
        logger.error("%s", error)
        return 1
