import logging
import socket
from pathlib import Path
from typing import NoReturn

import pytest

from torrent_tracker_blocker import blocklist, cli, sources
from torrent_tracker_blocker.firewall import ChainStatus, FirewallError
from torrent_tracker_blocker.rules import TrackerRule
from torrent_tracker_blocker.sources import SourceError

REMOTE_LIST = "https://lists.example.com/trackers.txt"

Documents = dict[str, bytes | Exception]
Applied = list[tuple[str, list[TrackerRule]]]


@pytest.fixture(autouse=True)
def dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    hosts = {
        "tracker.example.com": ["46.4.13.97"],
        "other.example.com": ["5.79.209.57"],
        "cdn.example.com": ["104.16.1.1"],
        "retracker.local": ["10.10.0.5"],
    }
    monkeypatch.setattr(socket, "gethostbyname_ex", lambda host: (host, [], hosts[host]))
    return hosts


@pytest.fixture(autouse=True)
def remote(monkeypatch: pytest.MonkeyPatch) -> Documents:
    """Serve downloadable documents by URL; an Exception value makes the download fail."""
    documents: Documents = {blocklist.CLOUDFLARE_RANGES: b"104.16.0.0/13\n"}

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


@pytest.fixture
def applied(monkeypatch: pytest.MonkeyPatch) -> Applied:
    calls: Applied = []
    monkeypatch.setattr(blocklist, "apply_rules", lambda chain, rules: calls.append((chain, rules)))
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


def test_parse_excludes_cloudflare_by_default(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text(
        "https://cdn.example.com/announce\nhttp://tracker.example.com:6969/announce\n"
    )

    assert cli.main(["parse", "-i", "trackers.txt"]) == 0
    assert (workdir / "trackers.csv").read_text() == "tcp,6969,46.4.13.97\n"


def test_parse_can_block_cloudflare(workdir: Path, remote: Documents) -> None:
    del remote[blocklist.CLOUDFLARE_RANGES]  # must not even be downloaded
    (workdir / "trackers.txt").write_text(
        "https://cdn.example.com/announce\nhttp://tracker.example.com:6969/announce\n"
    )

    assert cli.main(["parse", "-i", "trackers.txt", "--block-cloudflare"]) == 0
    assert (workdir / "trackers.csv").read_text() == "tcp,443,104.16.1.1\ntcp,6969,46.4.13.97\n"


def test_parse_exclusions_add_to_the_default_and_cover_previous_rules(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text(
        "https://cdn.example.com/announce\nhttp://tracker.example.com:6969/announce\n"
    )
    (workdir / "own.txt").write_text("5.79.209.57  # monitoring\n")
    (workdir / "trackers.csv").write_text("udp,1337,5.79.209.57\ntcp,443,104.17.2.2\n")

    assert cli.main(["parse", "-i", "trackers.txt", "-x", "own.txt", "--merge"]) == 0
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


def test_parse_keeps_existing_output_when_everything_is_excluded(workdir: Path) -> None:
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")
    (workdir / "exclude.txt").write_text("46.4.0.0/16\n")
    (workdir / "trackers.csv").write_text("tcp,80,5.79.209.57\n")

    assert cli.main(["parse", "-i", "trackers.txt", "-x", "exclude.txt"]) == 1
    assert (workdir / "trackers.csv").read_text() == "tcp,80,5.79.209.57\n"


@pytest.mark.parametrize("failing", [REMOTE_LIST, blocklist.CLOUDFLARE_RANGES])
def test_parse_keeps_existing_output_when_a_download_fails(
    workdir: Path, remote: Documents, caplog: pytest.LogCaptureFixture, failing: str
) -> None:
    remote[REMOTE_LIST] = b"http://tracker.example.com:6969/announce\n"
    remote[failing] = SourceError(f"{failing}: HTTP Error 503: Service Unavailable")
    (workdir / "trackers.csv").write_text("tcp,80,5.79.209.57\n")

    assert cli.main(["parse", "-i", REMOTE_LIST]) == 1
    assert (workdir / "trackers.csv").read_text() == "tcp,80,5.79.209.57\n"
    assert "HTTP Error 503" in caplog.text


def test_parse_fails_on_an_invalid_exclusion_list(workdir: Path, caplog: pytest.LogCaptureFixture) -> None:
    (workdir / "trackers.txt").write_text("http://tracker.example.com:6969/announce\n")
    (workdir / "exclude.txt").write_text("104.16.0.0/33\n")

    assert cli.main(["parse", "-i", "trackers.txt", "-x", "exclude.txt"]) == 1
    assert "exclude.txt:1" in caplog.text
    assert not (workdir / "trackers.csv").exists()


LOCAL_ADDRESSES = (
    "http://tracker.example.com:22/announce\n"
    "http://127.0.0.1:22/announce\n"
    "http://localhost:22/announce\n"
    "udp://169.254.169.254:80/announce\n"
    "http://retracker.local/announce\n"
    "udp://192.168.1.1:53/announce\n"
)


def test_parse_never_writes_local_addresses(workdir: Path, dns: dict[str, list[str]]) -> None:
    dns["tracker.example.com"] = ["127.0.0.1", "10.0.0.5", "192.168.1.1", "46.4.13.97"]
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
    assert (workdir / "trackers.csv").read_text() == ("tcp,22,46.4.13.97\ntcp,80,10.10.0.5\nudp,53,192.168.1.1\n")


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
    ],
)
def test_apply_does_not_touch_the_firewall_without_valid_rules(
    workdir: Path, applied: Applied, content: str, options: list[str]
) -> None:
    (workdir / "trackers.csv").write_text(content)

    assert cli.main(["apply", "-i", "trackers.csv", *options]) == 1
    assert applied == []


def test_apply_allow_private_accepts_private_ranges(workdir: Path, applied: Applied) -> None:
    (workdir / "trackers.csv").write_text("tcp,80,10.10.0.5\n")

    assert cli.main(["apply", "-i", "trackers.csv", "--allow-private"]) == 0
    assert applied == [("tracker-blocker", [TrackerRule("tcp", 80, "10.10.0.5")])]


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


def test_status_reports_each_chain(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    statuses = [
        ChainStatus("vpn-input", rules=87, dropped_packets=0, is_active=True),
        ChainStatus("vpn-output", rules=87, dropped_packets=12, is_active=True),
        ChainStatus("vpn-forward", rules=87, dropped_packets=340, is_active=True),
    ]
    monkeypatch.setattr(cli, "chain_statuses", lambda chain: statuses)

    assert cli.main(["status", "-c", "vpn"]) == 0
    assert capsys.readouterr().out == (
        "vpn-input: 87 rules, 0 packets dropped\n"
        "vpn-output: 87 rules, 12 packets dropped\n"
        "vpn-forward: 87 rules, 340 packets dropped\n"
    )


def test_status_fails_when_nothing_is_installed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "chain_statuses", lambda chain: [])

    assert cli.main(["status"]) == 1
    assert capsys.readouterr().out == "Not installed: no tracker-blocker-* chains\n"


def test_status_fails_when_a_chain_sees_no_traffic(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    statuses = [
        ChainStatus("vpn-input", rules=87, dropped_packets=0, is_active=True),
        ChainStatus("vpn-output", rules=87, dropped_packets=0, is_active=True),
        ChainStatus("vpn-forward", rules=87, dropped_packets=0, is_active=False),
    ]
    monkeypatch.setattr(cli, "chain_statuses", lambda chain: statuses)

    assert cli.main(["status", "-c", "vpn"]) == 1
    assert "vpn-forward: 87 rules, 0 packets dropped (inactive" in capsys.readouterr().out


def test_firewall_errors_exit_with_failure(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    def fail(chain: str) -> NoReturn:
        raise FirewallError("iptables failed: Permission denied")

    monkeypatch.setattr(cli, "remove_rules", fail)

    assert cli.main(["remove"]) == 1
    assert "Permission denied" in caplog.text
