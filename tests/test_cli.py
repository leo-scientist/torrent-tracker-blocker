import logging
from itertools import product
from pathlib import Path
from typing import NoReturn

import pytest

from torrent_tracker_blocker import blocklist, cli, sources
from torrent_tracker_blocker.config import DEFAULT_WHITELIST
from torrent_tracker_blocker.firewall import IPV4, IPV6, ChainStatus, Family, FirewallError
from torrent_tracker_blocker.measures import NO_MEASURES, Measures, Scope
from torrent_tracker_blocker.rules import TrackerRule
from torrent_tracker_blocker.sources import SourceError

REMOTE_LIST = "https://lists.example.com/trackers.txt"

Documents = dict[str, bytes | Exception]
Applied = list[tuple[str, list[TrackerRule]]]


@pytest.fixture(autouse=True)
def dns(dns: dict[str, list[str]]) -> dict[str, list[str]]:
    dns.update(
        {
            "tracker.example.com": ["46.4.13.97"],
            "other.example.com": ["5.79.209.57"],
            "cdn.example.com": ["104.16.1.1"],
            "retracker.local": ["10.10.0.5"],
            "dual.example.com": ["5.79.209.57", "2a01:4f8:c17:8f74::2"],
            "cdn6.example.com": ["2606:4700::6810:101"],
        }
    )
    return dns


@pytest.fixture(autouse=True)
def remote(monkeypatch: pytest.MonkeyPatch) -> Documents:
    """Serve downloadable documents by URL; an Exception value makes the download fail."""
    cloudflare_ipv4, cloudflare_ipv6 = DEFAULT_WHITELIST
    documents: Documents = {cloudflare_ipv4: b"104.16.0.0/13\n", cloudflare_ipv6: b"2606:4700::/32\n"}

    def fetch(url: str) -> bytes:
        document = documents[url]
        if isinstance(document, Exception):
            raise document
        return document

    monkeypatch.setattr(sources, "_fetch", fetch)
    return documents


@pytest.fixture
def workdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture(autouse=True)
def default_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep the configuration of the machine out of the tests; the returned file does not exist."""
    path = tmp_path / "etc" / "config.toml"
    path.parent.mkdir()
    monkeypatch.setattr(cli, "DEFAULT_CONFIG", path)
    return path


@pytest.fixture
def applied_measures() -> list[Measures]:
    """The measures of every firewall update recorded by ``applied``."""
    return []


@pytest.fixture
def applied(monkeypatch: pytest.MonkeyPatch, applied_measures: list[Measures]) -> Applied:
    calls: Applied = []

    def apply_rules(chain: str, rules: list[TrackerRule], measures: Measures) -> None:
        calls.append((chain, rules))
        applied_measures.append(measures)

    monkeypatch.setattr(blocklist, "apply_rules", apply_rules)
    return calls


def test_parse_writes_csv(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n\nudp://tracker.example.com/\n")

    assert cli.main(["parse", "-i", "trackers.txt", "-o", "out/rules.csv"]) == 0
    assert (workdir / "out/rules.csv").read_text() == "tcp,6969,46.4.13.97\nudp,80,46.4.13.97\n"


def test_parse_combines_several_sources(workdir: Path, remote: Documents) -> None:
    remote[REMOTE_LIST] = b"udp://other.example.com:1337/announce\n"
    (workdir / "a.txt").write_text("http://tracker.example.com:6969/announce\n")
    (workdir / "b.txt").write_text("http://tracker.example.com:6969/announce\n")

    assert cli.main(["parse", "-i", "a.txt", "-i", REMOTE_LIST, "-i", "b.txt"]) == 0
    assert (workdir / "trackers.csv").read_text() == "tcp,6969,46.4.13.97\nudp,1337,5.79.209.57\n"


def test_parse_downloads_the_public_lists_by_default(workdir: Path, remote: Documents) -> None:
    for source in cli.DEFAULT_SOURCES:
        assert source.startswith("https://")
        remote[source] = b"udp://tracker.example.com:6969/announce\n"

    assert cli.main(["parse"]) == 0
    assert (workdir / "trackers.csv").read_text() == "udp,6969,46.4.13.97\n"


def test_parse_replaces_the_previous_rules_by_default(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")
    (workdir / "trackers.csv").write_text("udp,1337,5.79.209.57\n")

    assert cli.main(["parse", "-i", "trackers.txt"]) == 0
    assert (workdir / "trackers.csv").read_text() == "tcp,6969,46.4.13.97\n"


def test_parse_merge_adds_to_the_previous_rules(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text(
        "http://tracker.example.com:6969/announce\nudp://other.example.com:1337/announce\n"
    )
    (workdir / "trackers.csv").write_text("udp,1337,5.79.209.57\ntcp,80,141.8.224.239\n")

    assert cli.main(["parse", "-i", "trackers.txt", "--merge"]) == 0
    assert (workdir / "trackers.csv").read_text() == (
        "udp,1337,5.79.209.57\ntcp,80,141.8.224.239\ntcp,6969,46.4.13.97\n"
    )


def test_parse_merge_without_previous_rules(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")

    assert cli.main(["parse", "-i", "trackers.txt", "--merge"]) == 0
    assert (workdir / "trackers.csv").read_text() == "tcp,6969,46.4.13.97\n"


def test_parse_merge_refuses_a_corrupt_previous_file(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")
    (workdir / "trackers.csv").write_text("tcp,22,127.0.0.1\n")

    assert cli.main(["parse", "-i", "trackers.txt", "--merge"]) == 1
    assert (workdir / "trackers.csv").read_text() == "tcp,22,127.0.0.1\n"


def test_parse_whitelists_cloudflare_by_default(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text(
        "https://cdn.example.com/announce\nhttp://tracker.example.com:6969/announce\n"
    )

    assert cli.main(["parse", "-i", "trackers.txt"]) == 0
    assert (workdir / "trackers.csv").read_text() == "tcp,6969,46.4.13.97\n"


def test_parse_with_an_empty_whitelist_blocks_cloudflare_too(workdir: Path, remote: Documents) -> None:
    for url in DEFAULT_WHITELIST:
        del remote[url]  # must not even be downloaded
    (workdir / "trackers.txt").write_text(
        "https://cdn.example.com/announce\nhttps://cdn6.example.com/announce\n"
        "http://tracker.example.com:6969/announce\n"
    )

    assert cli.main(["parse", "-i", "trackers.txt", "--whitelist"]) == 0
    assert (workdir / "trackers.csv").read_text() == (
        "tcp,443,104.16.1.1\ntcp,443,2606:4700::6810:101\ntcp,6969,46.4.13.97\n"
    )


def test_parse_writes_ipv6_rules(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text(
        "udp://dual.example.com:6969/announce\n"
        "https://cdn6.example.com/announce\n"
        "udp://[2A01:4F8:C17:8F74:0:0:0:3]:1337/announce\n"
        "http://[2a01:4f8:c17:8f74::4]/announce\n"
    )
    (workdir / "own.txt").write_text("2a01:4f8:c17:8f74::4/127  # ours\n")

    assert cli.main(["parse", "-i", "trackers.txt", "-w", "own.txt", *DEFAULT_WHITELIST]) == 0
    assert (workdir / "trackers.csv").read_text() == (
        "udp,6969,5.79.209.57\nudp,6969,2a01:4f8:c17:8f74::2\nudp,1337,2a01:4f8:c17:8f74::3\n"
    )


def test_parse_whitelist_covers_previous_rules(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text(
        "https://cdn.example.com/announce\nhttp://tracker.example.com:6969/announce\n"
    )
    (workdir / "own.txt").write_text("5.79.209.57  # monitoring\n")
    (workdir / "trackers.csv").write_text("udp,1337,5.79.209.57\ntcp,443,104.17.2.2\n")

    assert cli.main(["parse", "-i", "trackers.txt", "-w", "own.txt", *DEFAULT_WHITELIST, "--merge"]) == 0
    assert (workdir / "trackers.csv").read_text() == "tcp,6969,46.4.13.97\n"


@pytest.mark.parametrize("merge", [[], ["--merge"]])
def test_parse_keeps_existing_output_when_nothing_resolves(
    workdir: Path, dns: dict[str, list[str]], merge: list[str]
) -> None:
    dns["tracker.example.com"] = []
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")
    (workdir / "trackers.csv").write_text("tcp,80,46.4.13.97\n")

    assert cli.main(["parse", "-i", "trackers.txt", *merge]) == 1
    assert (workdir / "trackers.csv").read_text() == "tcp,80,46.4.13.97\n"


def test_parse_keeps_existing_output_when_everything_is_whitelisted(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")
    (workdir / "whitelist.txt").write_text("46.4.0.0/16\n")
    (workdir / "trackers.csv").write_text("tcp,80,5.79.209.57\n")

    assert cli.main(["parse", "-i", "trackers.txt", "-w", "whitelist.txt"]) == 1
    assert (workdir / "trackers.csv").read_text() == "tcp,80,5.79.209.57\n"


@pytest.mark.parametrize("failing", [REMOTE_LIST, *DEFAULT_WHITELIST])
def test_parse_keeps_existing_output_when_a_download_fails(
    workdir: Path, remote: Documents, caplog: pytest.LogCaptureFixture, failing: str
) -> None:
    remote[REMOTE_LIST] = b"http://tracker.example.com:6969/announce\n"
    remote[failing] = SourceError(f"{failing}: HTTP Error 503: Service Unavailable")
    (workdir / "trackers.csv").write_text("tcp,80,5.79.209.57\n")

    assert cli.main(["parse", "-i", REMOTE_LIST]) == 1
    assert (workdir / "trackers.csv").read_text() == "tcp,80,5.79.209.57\n"
    assert "HTTP Error 503" in caplog.text


def test_parse_fails_on_an_invalid_whitelist(workdir: Path, caplog: pytest.LogCaptureFixture) -> None:
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")
    (workdir / "whitelist.txt").write_text("104.16.0.0/33\n")

    assert cli.main(["parse", "-i", "trackers.txt", "-w", "whitelist.txt"]) == 1
    assert "whitelist.txt:1" in caplog.text
    assert not (workdir / "trackers.csv").exists()


LOCAL_ADDRESSES = (
    "http://tracker.example.com:22/announce\n"
    "http://127.0.0.1:22/announce\n"
    "http://localhost:22/announce\n"
    "udp://169.254.169.254:80/announce\n"
    "http://retracker.local/announce\n"
    "udp://192.168.1.1:53/announce\n"
    "http://[::1]:22/announce\n"
    "udp://[fe80::1]:6969/announce\n"
    "udp://[::ffff:8.8.8.8]:53/announce\n"
    "udp://[64:ff9b::808:808]:53/announce\n"
    "udp://[fd00::5]:6969/announce\n"
)


def test_parse_never_writes_local_addresses(workdir: Path, dns: dict[str, list[str]]) -> None:
    dns["tracker.example.com"] = [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "::1",
        "fe80::1%eth0",
        "fd00::9",
        "46.4.13.97",
    ]
    dns["localhost"] = ["127.0.0.1"]
    (workdir / "trackers.txt").write_text(LOCAL_ADDRESSES)

    assert cli.main(["parse", "-i", "trackers.txt"]) == 0
    assert (workdir / "trackers.csv").read_text() == "tcp,22,46.4.13.97\n"


def test_parse_allow_private_accepts_private_ranges_from_local_files_only(
    workdir: Path, dns: dict[str, list[str]], remote: Documents
) -> None:
    dns["localhost"] = ["127.0.0.1"]
    remote[REMOTE_LIST] = b"udp://10.9.9.9:6969/announce\nhttp://retracker.local:8080/announce\n"
    (workdir / "trackers.txt").write_text(LOCAL_ADDRESSES)

    args = ["parse", "-i", "trackers.txt", "-i", REMOTE_LIST, "--allow-private"]
    assert cli.main(args) == 0
    assert (workdir / "trackers.csv").read_text() == (
        "tcp,22,46.4.13.97\ntcp,80,10.10.0.5\nudp,53,192.168.1.1\nudp,6969,fd00::5\n"
    )


def test_parse_reports_missing_input(workdir: Path, caplog: pytest.LogCaptureFixture) -> None:
    assert cli.main(["parse", "-i", "missing.txt"]) == 1
    assert "missing.txt" in caplog.text


def test_apply_loads_rules_into_the_chain(workdir: Path, applied: Applied) -> None:
    (workdir / "trackers.csv").write_text("tcp,6969,46.4.13.97\n")

    assert cli.main(["apply", "-i", "trackers.csv", "-c", "vpn"]) == 0
    assert applied == [("vpn", [TrackerRule("tcp", 6969, "46.4.13.97")])]


@pytest.mark.parametrize(
    ("content", "options"),
    [
        ("", []),
        ("tcp,6969,127.0.0.1\n", []),
        ("tcp,6969,46.4.13.97\ntcp,22,10.0.0.1\n", []),
        ("tcp,22,192.168.1.1\n", []),
        ("tcp,22,127.0.0.1\n", ["--allow-private"]),
        ("tcp,22,169.254.169.254\n", ["--allow-private"]),
        ("udp,53,fd00::5\n", []),
        ("tcp,22,::1\n", ["--allow-private"]),
        ("udp,53,fe80::1\n", ["--allow-private"]),
        ("udp,53,::ffff:8.8.8.8\n", ["--allow-private"]),
    ],
)
def test_apply_does_not_touch_the_firewall_without_valid_rules(
    workdir: Path, applied: Applied, content: str, options: list[str]
) -> None:
    (workdir / "trackers.csv").write_text(content)

    assert cli.main(["apply", "-i", "trackers.csv", *options]) == 1
    assert applied == []


def test_apply_allow_private_accepts_private_ranges(workdir: Path, applied: Applied) -> None:
    (workdir / "trackers.csv").write_text("tcp,80,10.10.0.5\nudp,6969,fd00::5\n")

    assert cli.main(["apply", "-i", "trackers.csv", "--allow-private"]) == 0
    assert applied == [("tracker-blocker", [TrackerRule("tcp", 80, "10.10.0.5"), TrackerRule("udp", 6969, "fd00::5")])]


def test_apply_loads_ipv6_rules_in_any_spelling(workdir: Path, applied: Applied) -> None:
    (workdir / "trackers.csv").write_text("udp,6969,2A01:4F8:C17:8F74:0:0:0:2\nudp,6969,2a01:4f8:c17:8f74::2\n")

    assert cli.main(["apply", "-i", "trackers.csv"]) == 0
    assert applied == [("tracker-blocker", [TrackerRule("udp", 6969, "2a01:4f8:c17:8f74::2")])]


def test_update_downloads_and_applies(workdir: Path, applied: Applied, remote: Documents) -> None:
    remote[REMOTE_LIST] = b"udp://tracker.example.com:6969/announce\n"

    assert cli.main(["update", "-i", REMOTE_LIST, "-o", "state/trackers.csv"]) == 0
    assert (workdir / "state/trackers.csv").read_text() == "udp,6969,46.4.13.97\n"
    assert applied == [("tracker-blocker", [TrackerRule("udp", 6969, "46.4.13.97")])]


def test_update_keeps_the_firewall_when_the_download_fails(workdir: Path, applied: Applied, remote: Documents) -> None:
    remote[REMOTE_LIST] = SourceError(f"{REMOTE_LIST}: timed out")

    assert cli.main(["update", "-i", REMOTE_LIST, "-o", "trackers.csv", "-c", "vpn"]) == 1
    assert applied == []
    assert not (workdir / "trackers.csv").exists()


def test_update_stores_the_rules_where_they_survive_a_reboot() -> None:
    args = cli._build_parser().parse_args(["update"])

    assert args.output == cli.STATE_FILE
    assert args.output.is_absolute()


def test_quiet_only_reports_errors(workdir: Path, caplog: pytest.LogCaptureFixture) -> None:
    (workdir / "trackers.txt").write_text("not a tracker\nhttp://tracker.example.com/announce\n")

    assert cli.main(["parse", "-i", "trackers.txt", "--quiet"]) == 0
    assert caplog.records == []

    assert cli.main(["parse", "-i", "missing.txt", "--quiet"]) == 1
    assert [record.levelno for record in caplog.records] == [logging.ERROR]


def test_remove_uses_the_default_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    removed: list[str] = []

    def remove(chain: str) -> bool:
        removed.append(chain)
        return True

    monkeypatch.setattr(cli, "remove_rules", remove)

    assert cli.main(["remove"]) == 0
    assert removed == ["tracker-blocker"]


def chains(ip_version: int, dropped: int = 0, forward_is_active: bool = True) -> list[ChainStatus]:
    return [
        ChainStatus(ip_version, "vpn-input", rules=87, dropped_packets=0, is_active=True),
        ChainStatus(ip_version, "vpn-output", rules=87, dropped_packets=dropped, is_active=True),
        ChainStatus(ip_version, "vpn-forward", rules=87, dropped_packets=0, is_active=forward_is_active),
    ]


@pytest.fixture
def firewall_state(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[ChainStatus] | list[Family]]:
    """What `status` sees: the installed chains and the IP versions this host manages."""
    state: dict[str, list[ChainStatus] | list[Family]] = {"chains": [], "families": [IPV4, IPV6]}
    monkeypatch.setattr(cli, "chain_statuses", lambda chain: state["chains"])
    monkeypatch.setattr(cli, "managed_families", lambda: state["families"])
    return state


def test_status_reports_each_chain(
    firewall_state: dict[str, list[ChainStatus] | list[Family]], capsys: pytest.CaptureFixture[str]
) -> None:
    firewall_state["chains"] = [*chains(4, dropped=12), *chains(6, dropped=340)]

    assert cli.main(["status", "-c", "vpn"]) == 0
    assert capsys.readouterr().out == (
        "IPv4 vpn-input: 87 rules, 0 packets dropped\n"
        "IPv4 vpn-output: 87 rules, 12 packets dropped\n"
        "IPv4 vpn-forward: 87 rules, 0 packets dropped\n"
        "IPv6 vpn-input: 87 rules, 0 packets dropped\n"
        "IPv6 vpn-output: 87 rules, 340 packets dropped\n"
        "IPv6 vpn-forward: 87 rules, 0 packets dropped\n"
    )


def test_status_fails_when_nothing_is_installed(
    firewall_state: dict[str, list[ChainStatus] | list[Family]], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["status"]) == 1
    assert capsys.readouterr().out == "Not installed: no tracker-blocker-* chains\n"


def test_status_fails_when_a_chain_sees_no_traffic(
    firewall_state: dict[str, list[ChainStatus] | list[Family]], capsys: pytest.CaptureFixture[str]
) -> None:
    firewall_state["chains"] = [*chains(4), *chains(6, forward_is_active=False)]

    assert cli.main(["status", "-c", "vpn"]) == 1
    assert "IPv6 vpn-forward: 87 rules, 0 packets dropped (inactive" in capsys.readouterr().out


def test_status_fails_when_ipv6_is_not_covered(firewall_state: dict[str, list[ChainStatus] | list[Family]]) -> None:
    firewall_state["chains"] = chains(4)

    assert cli.main(["status", "-c", "vpn"]) == 1


def test_status_succeeds_with_ipv4_only_on_a_host_without_ipv6(
    firewall_state: dict[str, list[ChainStatus] | list[Family]],
) -> None:
    firewall_state["chains"] = chains(4)
    firewall_state["families"] = [IPV4]

    assert cli.main(["status", "-c", "vpn"]) == 0


def test_firewall_errors_exit_with_failure(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    def fail(chain: str) -> NoReturn:
        raise FirewallError("iptables failed: Permission denied")

    monkeypatch.setattr(cli, "remove_rules", fail)

    assert cli.main(["remove"]) == 1
    assert "Permission denied" in caplog.text


SCOPE_COMBINATIONS = list(product(Scope, Scope))
# A command that updates the firewall, with a rule file to load or a tracker list to download.
FIREWALL_COMMANDS = {
    "apply": ["apply", "-i", "trackers.csv"],
    "update": ["update", "-i", "trackers.txt", "-o", "state.csv"],
}


@pytest.fixture
def blocklist_files(workdir: Path) -> Path:
    (workdir / "trackers.csv").write_text("tcp,6969,46.4.13.97\n")
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")
    return workdir


def write_config(path: Path, signatures: Scope, connection_limit: Scope, max_connections: int) -> Path:
    path.write_text(
        f'[signatures]\nscope = "{signatures}"\n'
        f'[connection_limit]\nscope = "{connection_limit}"\nmax_connections = {max_connections}\n'
    )
    return path


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
def test_no_measure_is_applied_without_configuration(
    blocklist_files: Path, applied: Applied, applied_measures: list[Measures], command: str
) -> None:
    assert cli.main(FIREWALL_COMMANDS[command]) == 0
    assert applied_measures == [NO_MEASURES]


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
def test_measures_come_from_the_configuration_file(
    blocklist_files: Path,
    applied: Applied,
    applied_measures: list[Measures],
    command: str,
    signatures: Scope,
    connection_limit: Scope,
) -> None:
    config = write_config(blocklist_files / "config.toml", signatures, connection_limit, 37)

    assert cli.main([*FIREWALL_COMMANDS[command], "--config", str(config)]) == 0
    assert applied_measures == [Measures(signatures, connection_limit, 37)]
    assert applied == [("tracker-blocker", [TrackerRule("tcp", 6969, "46.4.13.97")])]


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
def test_the_default_configuration_file_is_used_when_it_exists(
    blocklist_files: Path,
    default_config: Path,
    applied: Applied,
    applied_measures: list[Measures],
    command: str,
    signatures: Scope,
    connection_limit: Scope,
) -> None:
    write_config(default_config, signatures, connection_limit, 37)

    assert cli.main(FIREWALL_COMMANDS[command]) == 0
    assert applied_measures == [Measures(signatures, connection_limit, 37)]


def test_an_explicit_configuration_file_replaces_the_default_one(
    blocklist_files: Path, default_config: Path, applied: Applied, applied_measures: list[Measures]
) -> None:
    write_config(default_config, Scope.ALL, Scope.ALL, 5)
    config = blocklist_files / "config.toml"
    config.write_text('[signatures]\nscope = "forward"\n')

    assert cli.main(["apply", "-i", "trackers.csv", "--config", str(config)]) == 0
    assert applied_measures == [Measures(signatures=Scope.FORWARD)]


@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
@pytest.mark.parametrize("max_connections", [None, 1, 4294967295])
def test_measures_can_be_set_on_the_command_line_alone(
    blocklist_files: Path,
    applied: Applied,
    applied_measures: list[Measures],
    signatures: Scope,
    connection_limit: Scope,
    max_connections: int | None,
) -> None:
    options = ["--signatures", signatures, "--connection-limit", connection_limit]
    if max_connections is not None:
        options += ["--max-connections", str(max_connections)]

    # A connection limit has no default number: it must be given together with the limit.
    if max_connections is None and connection_limit is not Scope.OFF:
        assert cli.main(["apply", "-i", "trackers.csv", *options]) == 1
        assert applied == []
        return

    assert cli.main(["apply", "-i", "trackers.csv", *options]) == 0
    assert applied_measures == [Measures(signatures, connection_limit, max_connections)]


@pytest.mark.parametrize(("configured_signatures", "configured_limit"), SCOPE_COMBINATIONS)
@pytest.mark.parametrize(("signatures", "connection_limit"), list(product([None, *Scope], [None, *Scope])))
@pytest.mark.parametrize("max_connections", [None, 5])
def test_each_command_line_option_overrides_only_its_own_setting(
    blocklist_files: Path,
    default_config: Path,
    applied: Applied,
    applied_measures: list[Measures],
    configured_signatures: Scope,
    configured_limit: Scope,
    signatures: Scope | None,
    connection_limit: Scope | None,
    max_connections: int | None,
) -> None:
    write_config(default_config, configured_signatures, configured_limit, 37)
    options: list[str] = []
    if signatures is not None:
        options += ["--signatures", signatures]
    if connection_limit is not None:
        options += ["--connection-limit", connection_limit]
    if max_connections is not None:
        options += ["--max-connections", str(max_connections)]

    assert cli.main(["apply", "-i", "trackers.csv", *options]) == 0
    assert applied_measures == [
        Measures(
            signatures=signatures or configured_signatures,
            connection_limit=connection_limit or configured_limit,
            max_connections=max_connections or 37,
        )
    ]


INVALID_CONFIGS = [
    '[connection_limit]\nscope = "forward"\n',
    '[signatures]\nscope = "everything"\n',
    "[connection_limit]\nmax_connections = 0\n",
    "[trackers]\nmerge = true\n",
    "[signatures\n",
]


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
@pytest.mark.parametrize("content", INVALID_CONFIGS)
@pytest.mark.parametrize("is_default", [True, False])
def test_an_invalid_configuration_changes_nothing(
    blocklist_files: Path,
    default_config: Path,
    applied: Applied,
    caplog: pytest.LogCaptureFixture,
    command: str,
    content: str,
    is_default: bool,
) -> None:
    config = default_config if is_default else blocklist_files / "config.toml"
    config.write_text(content)
    options = [] if is_default else ["--config", str(config)]

    assert cli.main([*FIREWALL_COMMANDS[command], *options]) == 1
    assert applied == []
    assert not (blocklist_files / "state.csv").exists()
    assert str(config) in caplog.text


@pytest.mark.parametrize("content", INVALID_CONFIGS)
def test_parse_writes_nothing_with_an_invalid_configuration(
    blocklist_files: Path, default_config: Path, caplog: pytest.LogCaptureFixture, content: str
) -> None:
    default_config.write_text(content)

    assert cli.main(["parse", "-i", "trackers.txt", "-o", "state.csv"]) == 1
    assert not (blocklist_files / "state.csv").exists()
    assert str(default_config) in caplog.text


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
def test_a_missing_explicit_configuration_file_changes_nothing(
    blocklist_files: Path, applied: Applied, caplog: pytest.LogCaptureFixture, command: str
) -> None:
    assert cli.main([*FIREWALL_COMMANDS[command], "--config", "missing.toml"]) == 1
    assert applied == []
    assert not (blocklist_files / "state.csv").exists()
    assert "missing.toml" in caplog.text


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
@pytest.mark.parametrize("max_connections", ["0", "-1", "4294967296"])
def test_an_unusable_connection_limit_changes_nothing(
    blocklist_files: Path, applied: Applied, caplog: pytest.LogCaptureFixture, command: str, max_connections: str
) -> None:
    assert cli.main([*FIREWALL_COMMANDS[command], "--max-connections", max_connections]) == 1
    assert applied == []
    assert not (blocklist_files / "state.csv").exists()
    assert "max_connections must be a whole number" in caplog.text


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
@pytest.mark.parametrize(
    "options",
    [
        ["--signatures", "everything"],
        ["--signatures", "ALL"],
        ["--connection-limit", "on"],
        ["--connection-limit"],
        ["--max-connections", "many"],
        ["--max-connections", "1.5"],
    ],
)
def test_an_unknown_measure_option_value_is_a_usage_error(
    blocklist_files: Path, applied: Applied, command: str, options: list[str]
) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main([*FIREWALL_COMMANDS[command], *options])

    assert error.value.code == 2
    assert applied == []


@pytest.mark.parametrize("command", ["parse", "remove", "status"])
@pytest.mark.parametrize("option", ["--signatures", "--connection-limit", "--max-connections"])
def test_commands_that_do_not_update_the_firewall_take_no_measure_options(command: str, option: str) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main([command, option, "all"])

    assert error.value.code == 2


def test_update_applies_the_measures_to_the_refreshed_rules(
    blocklist_files: Path, applied: Applied, applied_measures: list[Measures]
) -> None:
    options = ["--signatures", "all", "--connection-limit", "forward", "--max-connections", "50", "-c", "vpn"]

    assert cli.main(["update", "-i", "trackers.txt", "-o", "state.csv", *options]) == 0
    assert (blocklist_files / "state.csv").read_text() == "tcp,6969,46.4.13.97\n"
    assert applied == [("vpn", [TrackerRule("tcp", 6969, "46.4.13.97")])]
    assert applied_measures == [Measures(Scope.ALL, Scope.FORWARD, 50)]


@pytest.mark.parametrize(
    ("signature_drops", "connection_limit_drops", "line"),
    [
        (None, None, "IPv4 vpn-forward: 87 rules, 3 packets dropped\n"),
        (40, None, "IPv4 vpn-forward: 87 rules, 3 packets dropped, 40 more by signatures\n"),
        (None, 0, "IPv4 vpn-forward: 87 rules, 3 packets dropped, 0 more by the connection limit\n"),
        (
            0,
            15,
            "IPv4 vpn-forward: 87 rules, 3 packets dropped, 0 more by signatures, 15 more by the connection limit\n",
        ),
    ],
)
def test_status_reports_what_each_installed_measure_dropped(
    firewall_state: dict[str, list[ChainStatus] | list[Family]],
    capsys: pytest.CaptureFixture[str],
    signature_drops: int | None,
    connection_limit_drops: int | None,
    line: str,
) -> None:
    firewall_state["chains"] = [
        ChainStatus(
            4,
            "vpn-forward",
            rules=87,
            dropped_packets=3,
            is_active=True,
            signature_drops=signature_drops,
            connection_limit_drops=connection_limit_drops,
        )
    ]

    cli.main(["status", "-c", "vpn"])

    assert capsys.readouterr().out == line


def test_status_puts_the_inactive_note_after_the_measures(
    firewall_state: dict[str, list[ChainStatus] | list[Family]], capsys: pytest.CaptureFixture[str]
) -> None:
    firewall_state["chains"] = [
        ChainStatus(4, "vpn-forward", rules=1, dropped_packets=0, is_active=False, signature_drops=2)
    ]

    cli.main(["status", "-c", "vpn"])

    assert capsys.readouterr().out == (
        "IPv4 vpn-forward: 1 rules, 0 packets dropped, 2 more by signatures (inactive: nothing jumps to this chain)\n"
    )


REMOTE_WHITELIST = "https://ranges.example.com/ips.txt"
TRACKERS = (
    "https://cdn.example.com/announce\n"
    "https://cdn6.example.com/announce\n"
    "http://tracker.example.com:6969/announce\n"
    "udp://dual.example.com:1337/announce\n"
)
CDN, CDN6 = "tcp,443,104.16.1.1\n", "tcp,443,2606:4700::6810:101\n"
TRACKER = "tcp,6969,46.4.13.97\n"
DUAL, DUAL6 = "udp,1337,5.79.209.57\n", "udp,1337,2a01:4f8:c17:8f74::2\n"
# Whitelist entries of every kind, and the rules that are left with them.
WHITELISTS: dict[str, tuple[list[str], str]] = {
    "empty": ([], CDN + CDN6 + TRACKER + DUAL + DUAL6),
    "address": (["46.4.13.97"], CDN + CDN6 + DUAL + DUAL6),
    "ipv6-address": (["2a01:4f8:c17:8f74::2"], CDN + CDN6 + TRACKER + DUAL),
    "ranges": (["5.79.0.0/16", "2a01:4f8::/32"], CDN + CDN6 + TRACKER),
    "address-with-host-bits": (["5.79.209.57/16"], CDN + CDN6 + TRACKER + DUAL6),
    "file": (["own.txt"], CDN + DUAL + DUAL6),
    "url": ([REMOTE_WHITELIST], CDN6 + TRACKER + DUAL + DUAL6),
    "provider": (list(DEFAULT_WHITELIST), TRACKER + DUAL + DUAL6),
    "everything-together": (["46.4.13.97", "own.txt", REMOTE_WHITELIST, "2a01:4f8::/32"], DUAL),
}


@pytest.fixture
def whitelisting(workdir: Path, remote: Documents) -> Path:
    """A tracker list with trackers of every kind, and whitelists to read from a file and from a URL."""
    (workdir / "trackers.txt").write_text(TRACKERS)
    (workdir / "own.txt").write_text("46.4.13.97\n2606:4700::/32  # a provider\n")
    remote[REMOTE_WHITELIST] = b"104.16.0.0/13\n"
    return workdir


def toml_whitelist(entries: list[str]) -> str:
    return "whitelist = [" + ", ".join(f'"{entry}"' for entry in entries) + "]\n"


@pytest.mark.parametrize("command", ["parse", "update"])
def test_the_default_whitelist_is_cloudflare(whitelisting: Path, applied: Applied, command: str) -> None:
    assert cli.main([command, "-i", "trackers.txt", "-o", "rules.csv"]) == 0
    assert (whitelisting / "rules.csv").read_text() == TRACKER + DUAL + DUAL6


@pytest.mark.parametrize("command", ["parse", "update"])
@pytest.mark.parametrize("whitelist", WHITELISTS)
@pytest.mark.parametrize("source", ["explicit-config", "default-config", "command-line"])
def test_every_kind_of_whitelist_entry_keeps_its_addresses_unblocked(
    whitelisting: Path, default_config: Path, applied: Applied, command: str, whitelist: str, source: str
) -> None:
    entries, rules = WHITELISTS[whitelist]
    options: list[str] = []
    if source == "command-line":
        options = ["--whitelist", *entries]
    else:
        config = default_config if source == "default-config" else whitelisting / "config.toml"
        config.write_text(toml_whitelist(entries))
        options = [] if source == "default-config" else ["--config", str(config)]

    assert cli.main([command, "-i", "trackers.txt", "-o", "rules.csv", *options]) == 0
    assert (whitelisting / "rules.csv").read_text() == rules


def test_whitelist_options_can_be_repeated_and_take_several_values(whitelisting: Path) -> None:
    options = ["-w", "46.4.13.97", "own.txt", "--whitelist", REMOTE_WHITELIST, "-w", "2a01:4f8::/32"]

    assert cli.main(["parse", "-i", "trackers.txt", *options]) == 0
    assert (whitelisting / "trackers.csv").read_text() == DUAL


@pytest.mark.parametrize("configured", WHITELISTS)
@pytest.mark.parametrize("given", WHITELISTS)
def test_the_whitelist_option_replaces_the_configured_whitelist(
    whitelisting: Path, default_config: Path, configured: str, given: str
) -> None:
    default_config.write_text(toml_whitelist(WHITELISTS[configured][0]))
    entries, rules = WHITELISTS[given]

    assert cli.main(["parse", "-i", "trackers.txt", "--whitelist", *entries]) == 0
    assert (whitelisting / "trackers.csv").read_text() == rules


def test_an_empty_whitelist_downloads_no_provider_list(whitelisting: Path, remote: Documents) -> None:
    for url in DEFAULT_WHITELIST:
        del remote[url]
    (whitelisting / "config.toml").write_text("whitelist = []\n")

    assert cli.main(["parse", "-i", "trackers.txt", "--config", "config.toml"]) == 0
    assert (whitelisting / "trackers.csv").read_text() == CDN + CDN6 + TRACKER + DUAL + DUAL6


@pytest.mark.parametrize("whitelist", WHITELISTS)
@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
def test_update_combines_any_whitelist_with_any_measures(
    whitelisting: Path,
    default_config: Path,
    applied: Applied,
    applied_measures: list[Measures],
    whitelist: str,
    signatures: Scope,
    connection_limit: Scope,
) -> None:
    entries, rules = WHITELISTS[whitelist]
    default_config.write_text(
        toml_whitelist(entries)
        + f'[signatures]\nscope = "{signatures}"\n'
        + f'[connection_limit]\nscope = "{connection_limit}"\nmax_connections = 37\n'
    )

    assert cli.main(["update", "-i", "trackers.txt", "-o", "rules.csv"]) == 0
    assert (whitelisting / "rules.csv").read_text() == rules
    assert applied_measures == [Measures(signatures, connection_limit, 37)]
    assert [len(loaded) for _, loaded in applied] == [rules.count("\n")]


@pytest.mark.parametrize("command", ["parse", "update"])
@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ("missing.txt", "missing.txt"),
        ("8.8.8", "8.8.8"),
        ("10.0.0.0/33", "10.0.0.0/33"),
        ("bad.txt", "bad.txt:2"),
        ("https://ranges.example.com/down.txt", "timed out"),
        ("http://ranges.example.com/ips.txt", "only https:// URLs and local files"),
    ],
)
@pytest.mark.parametrize("source", ["config", "command-line"])
def test_an_unusable_whitelist_entry_changes_nothing(
    whitelisting: Path,
    remote: Documents,
    applied: Applied,
    caplog: pytest.LogCaptureFixture,
    command: str,
    entry: str,
    message: str,
    source: str,
) -> None:
    (whitelisting / "bad.txt").write_text("46.4.13.97\nnot an address\n")
    remote["https://ranges.example.com/down.txt"] = SourceError("https://ranges.example.com/down.txt: timed out")
    (whitelisting / "rules.csv").write_text("tcp,80,5.79.209.57\n")
    (whitelisting / "config.toml").write_text(toml_whitelist(["46.4.13.97", entry]))
    options = ["--config", "config.toml"] if source == "config" else ["-w", "46.4.13.97", entry]

    assert cli.main([command, "-i", "trackers.txt", "-o", "rules.csv", *options]) == 1
    assert (whitelisting / "rules.csv").read_text() == "tcp,80,5.79.209.57\n"
    assert applied == []
    assert message in caplog.text


def test_apply_loads_the_rule_file_as_it_is_whatever_the_whitelist(
    whitelisting: Path, default_config: Path, remote: Documents, applied: Applied
) -> None:
    # Nothing is downloaded at boot: the whitelist was applied when the rule file was written.
    remote.clear()
    default_config.write_text(toml_whitelist(["46.4.13.97", "missing.txt", *DEFAULT_WHITELIST]))
    (whitelisting / "rules.csv").write_text(CDN + TRACKER)

    assert cli.main(["apply", "-i", "rules.csv"]) == 0
    assert applied == [
        ("tracker-blocker", [TrackerRule("tcp", 443, "104.16.1.1"), TrackerRule("tcp", 6969, "46.4.13.97")])
    ]


@pytest.mark.parametrize("command", ["apply", "remove", "status"])
def test_commands_that_do_not_write_the_rule_file_take_no_whitelist(command: str) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main([command, "--whitelist", "46.4.13.97"])

    assert error.value.code == 2


@pytest.mark.parametrize("option", ["-x", "--exclude", "--block-cloudflare"])
def test_the_provider_specific_options_are_gone(option: str) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["parse", option])

    assert error.value.code == 2


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
@pytest.mark.parametrize("connection_limit", [Scope.FORWARD, Scope.ALL])
def test_a_connection_limit_without_a_number_changes_nothing(
    blocklist_files: Path, applied: Applied, caplog: pytest.LogCaptureFixture, command: str, connection_limit: Scope
) -> None:
    assert cli.main([*FIREWALL_COMMANDS[command], "--connection-limit", connection_limit]) == 1
    assert applied == []
    assert not (blocklist_files / "state.csv").exists()
    assert "connection_limit needs max_connections" in caplog.text


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
@pytest.mark.parametrize("connection_limit", [Scope.FORWARD, Scope.ALL])
def test_the_number_for_a_connection_limit_can_come_from_the_configuration_file(
    blocklist_files: Path,
    default_config: Path,
    applied: Applied,
    applied_measures: list[Measures],
    command: str,
    connection_limit: Scope,
) -> None:
    default_config.write_text("[connection_limit]\nmax_connections = 120\n")

    assert cli.main([*FIREWALL_COMMANDS[command], "--connection-limit", connection_limit]) == 0
    assert applied_measures == [Measures(connection_limit=connection_limit, max_connections=120)]


@pytest.mark.parametrize("command", FIREWALL_COMMANDS)
def test_the_number_alone_does_not_enable_the_connection_limit(
    blocklist_files: Path, applied: Applied, applied_measures: list[Measures], command: str
) -> None:
    assert cli.main([*FIREWALL_COMMANDS[command], "--max-connections", "120"]) == 0
    assert applied_measures == [Measures(max_connections=120)]
