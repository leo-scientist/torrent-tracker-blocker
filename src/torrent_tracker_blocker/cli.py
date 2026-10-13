"""Command line interface."""

import argparse
import logging
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from torrent_tracker_blocker.blocklist import load_rule_file, refresh_rule_file
from torrent_tracker_blocker.config import DEFAULTS, Config, load_config
from torrent_tracker_blocker.firewall import (
    BUILTIN_CHAINS,
    ChainStatus,
    FirewallError,
    chain_statuses,
    managed_families,
    remove_rules,
)
from torrent_tracker_blocker.measures import (
    ConfigError,
    Measures,
    Scope,
)
from torrent_tracker_blocker.rules import InvalidRuleError
from torrent_tracker_blocker.sources import SourceError

logger = logging.getLogger(__name__)

DEFAULT_CHAIN = "tracker-blocker"
DEFAULT_OUTPUT = Path("trackers.csv")
# Where `update` keeps the rules, so that they can be restored at boot.
STATE_FILE = Path("/var/lib/torrent-tracker-blocker/trackers.csv")
# Read when it exists, so that `update` and the restore at boot use the same settings.
DEFAULT_CONFIG = Path("/etc/torrent-tracker-blocker/config.toml")
# Command line options that override a measure setting of the configuration file.
MEASURE_OPTIONS = ("signatures", "connection_limit", "max_connections")
# Public lists of working trackers, refreshed at least daily.
DEFAULT_SOURCES = (
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
    "https://newtrackon.com/api/live",
)

Handler = Callable[[argparse.Namespace], int]


def _refresh(args: argparse.Namespace, config: Config) -> bool:
    return refresh_rule_file(
        args.output,
        args.input or DEFAULT_SOURCES,
        whitelist=config.whitelist,
        merge=args.merge,
        allow_private=args.allow_private,
    )


def _config(args: argparse.Namespace) -> Config:
    """The configuration file, each setting overridden by its command line option when that is given."""
    path: Path | None = args.config
    if path is None and DEFAULT_CONFIG.exists():
        path = DEFAULT_CONFIG

    config = load_config(path) if path else DEFAULTS
    # Not every command has every option: `parse` takes no measures and `apply` no whitelist.
    measures = {option: value for option in MEASURE_OPTIONS if (value := getattr(args, option, None)) is not None}
    whitelist: list[str] | None = getattr(args, "whitelist", None)

    return Config(
        whitelist=config.whitelist if whitelist is None else tuple(whitelist),
        measures=replace(config.measures, **measures),
    )


def _load(path: Path, args: argparse.Namespace, measures: Measures) -> int:
    return 0 if load_rule_file(path, args.chain, args.allow_private, measures) else 1


def _parse(args: argparse.Namespace) -> int:
    return 0 if _refresh(args, _config(args)) else 1


def _apply(args: argparse.Namespace) -> int:
    return _load(args.input, args, _config(args).measures)


def _update(args: argparse.Namespace) -> int:
    # Before anything is downloaded: an invalid configuration must not leave a new rule file behind.
    config = _config(args)
    if not _refresh(args, config):
        return 1
    return _load(args.output, args, config.measures)


def _remove(args: argparse.Namespace) -> int:
    if remove_rules(args.chain):
        logger.info("Removed chains %s-*", args.chain)
    else:
        logger.info("Nothing to remove for chains %s-*", args.chain)
    return 0


def _measure_drops(status: ChainStatus) -> str:
    measures = (
        (status.signature_drops, "by signatures"),
        (status.connection_limit_drops, "by the connection limit"),
    )
    return "".join(f", {dropped} more {label}" for dropped, label in measures if dropped is not None)


def _status(args: argparse.Namespace) -> int:
    statuses = chain_statuses(args.chain)
    if not statuses:
        print(f"Not installed: no {args.chain}-* chains")
        return 1

    for status in statuses:
        note = "" if status.is_active else " (inactive: nothing jumps to this chain)"
        print(
            f"IPv{status.ip_version} {status.name}: {status.rules} rules, "
            f"{status.dropped_packets} packets dropped{_measure_drops(status)}{note}"
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
        "-w",
        "--whitelist",
        action="extend",
        nargs="*",
        metavar="ADDRESSES",
        help="what never to block: an IP address, a CIDR range, or a file or https:// URL listing them; "
        "repeatable, and without a value nothing is whitelisted. Replaces the whitelist of the "
        "configuration file (default: the address ranges of Cloudflare, which unrelated sites share)",
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
    parser = argparse.ArgumentParser(
        prog="tracker-blocker",
        description="Block BitTorrent trackers and, optionally, other BitTorrent traffic with iptables",
    )
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

    config = argparse.ArgumentParser(add_help=False)
    config.add_argument(
        "--config",
        type=Path,
        metavar="FILE",
        help=f"TOML file with the whitelist and the optional measures (default: {DEFAULT_CONFIG}, if it exists)",
    )

    measures = argparse.ArgumentParser(add_help=False)
    measures.add_argument(
        "--signatures",
        type=Scope,
        choices=list(Scope),
        help="drop unencrypted BitTorrent, DHT and tracker packets: in forwarded traffic or in all of it, "
        "the traffic of this host included; overrides the configuration file",
    )
    measures.add_argument(
        "--connection-limit",
        type=Scope,
        choices=list(Scope),
        help="drop the new connections of an address that has more than --max-connections open: "
        "forwarded ones or all, those opened by this host included; overrides the configuration file",
    )
    measures.add_argument(
        "--max-connections",
        type=int,
        metavar="N",
        help="connections that one address may have open; required with a connection limit, unless the "
        "configuration file sets it, which this option overrides",
    )

    update = commands.add_parser(
        "update",
        parents=[common, chain, private, config, measures],
        help="download the tracker lists and load them into iptables",
    )
    _add_refresh_arguments(update, STATE_FILE)
    update.set_defaults(handler=_update)

    parse = commands.add_parser(
        "parse",
        parents=[common, private, config],
        help="download the tracker lists and resolve them into a CSV of rules",
    )
    _add_refresh_arguments(parse, DEFAULT_OUTPUT)
    parse.set_defaults(handler=_parse)

    apply = commands.add_parser(
        "apply",
        parents=[common, chain, private, config, measures],
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
    except (InvalidRuleError, ConfigError, SourceError, FirewallError, OSError) as error:
        logger.error("%s", error)
        return 1
