from itertools import product
from pathlib import Path

import pytest

from torrent_tracker_blocker.config import DEFAULTS, Config, load_config
from torrent_tracker_blocker.measures import MAX_CONNECTIONS_CEILING, NO_MEASURES, ConfigError, Measures, Scope

SCOPE_COMBINATIONS = list(product(Scope, Scope))
# How the whitelist can be written in the file, and what that means.
WHITELISTS = {
    "": (),
    "whitelist = []\n": (),
    'whitelist = ["10.8.0.5"]\n': ("10.8.0.5",),
    'whitelist = ["https://example.com/ranges.txt", "/etc/own.txt", "2001:db8::/32"]\n': (
        "https://example.com/ranges.txt",
        "/etc/own.txt",
        "2001:db8::/32",
    ),
}


def write_config(tmp_path: Path, content: str | bytes) -> Path:
    path = tmp_path / "config.toml"
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    return path


def test_defaults_whitelist_nothing_and_enable_no_measure() -> None:
    assert Config() == DEFAULTS
    assert DEFAULTS.measures == NO_MEASURES
    assert DEFAULTS.whitelist == ()


@pytest.mark.parametrize(("signatures", "connection_limit"), SCOPE_COMBINATIONS)
@pytest.mark.parametrize("max_connections", [1, 37, MAX_CONNECTIONS_CEILING])
@pytest.mark.parametrize("whitelist", WHITELISTS)
def test_load_config_reads_every_combination(
    tmp_path: Path, signatures: Scope, connection_limit: Scope, max_connections: int, whitelist: str
) -> None:
    path = write_config(
        tmp_path,
        f'{whitelist}\n[signatures]\nscope = "{signatures}"\n\n'
        f'[connection_limit]\nscope = "{connection_limit}"\nmax_connections = {max_connections}\n',
    )

    assert load_config(path) == Config(
        whitelist=WHITELISTS[whitelist], measures=Measures(signatures, connection_limit, max_connections)
    )


@pytest.mark.parametrize(
    ("content", "measures"),
    [
        ("", NO_MEASURES),
        ("# nothing is enabled\n", NO_MEASURES),
        ("[signatures]\n", NO_MEASURES),
        ("[connection_limit]\n", NO_MEASURES),
        ('[signatures]\nscope = "forward"\n', Measures(signatures=Scope.FORWARD)),
        ('[connection_limit]\nscope = "off"\n', NO_MEASURES),
        ('[connection_limit]\nscope = "all"\nmax_connections = 5\n', Measures(Scope.OFF, Scope.ALL, 5)),
        ("[connection_limit]\nmax_connections = 50\n", Measures(max_connections=50)),
        ('connection_limit = { scope = "forward", max_connections = 9 }\n', Measures(Scope.OFF, Scope.FORWARD, 9)),
    ],
)
def test_load_config_leaves_what_is_not_configured_at_its_default(
    tmp_path: Path, content: str, measures: Measures
) -> None:
    assert load_config(write_config(tmp_path, content)) == Config(measures=measures)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('scope = "all"\n', "unknown section or option 'scope'"),
        ('whitelists = ["10.8.0.5"]\n', "unknown section or option 'whitelists'"),
        ('[signature]\nscope = "all"\n', "unknown section or option 'signature'"),
        ("[trackers]\nmerge = true\n", "unknown section or option 'trackers'"),
        ('signatures = "all"\n', r"'signatures' must be a section: \[signatures\]"),
        ("connection_limit = 200\n", r"'connection_limit' must be a section"),
        ('[signatures]\nscop = "all"\n', r"unknown option 'scop' in \[signatures\]"),
        ("[signatures]\nmax_connections = 5\n", r"unknown option 'max_connections' in \[signatures\]"),
        ('[signatures]\nwhitelist = ["10.8.0.5"]\n', r"unknown option 'whitelist' in \[signatures\]"),
        ("[connection_limit]\nmax = 5\n", r"unknown option 'max' in \[connection_limit\]"),
        ('[signatures]\nscope = "everything"\n', r"scope in \[signatures\] must be .* not 'everything'"),
        ('[signatures]\nscope = "ALL"\n', r"scope in \[signatures\] must be .* not 'ALL'"),
        ('[signatures]\nscope = ""\n', r"scope in \[signatures\] must be .* not ''"),
        ("[signatures]\nscope = true\n", r"scope in \[signatures\] must be .* not True"),
        ("[signatures]\nscope = 1\n", r"scope in \[signatures\] must be .* not 1"),
        ('[signatures]\nscope = ["all"]\n', r"scope in \[signatures\] must be"),
        ('[connection_limit]\nscope = "on"\n', r"scope in \[connection_limit\] must be .* not 'on'"),
        ('[connection_limit]\nscope = "forward"\n', "connection_limit needs max_connections"),
        ('[connection_limit]\nscope = "all"\n', "connection_limit needs max_connections"),
        (
            "[connection_limit]\nmax_connections = 0\n",
            "max_connections must be a whole number from 1 to 4294967295, not 0",
        ),
        ("[connection_limit]\nmax_connections = -5\n", "max_connections must be .* not -5"),
        ("[connection_limit]\nmax_connections = 4294967296\n", "max_connections must be .* not 4294967296"),
        ('[connection_limit]\nmax_connections = "200"\n', "max_connections must be .* not '200'"),
        ("[connection_limit]\nmax_connections = 1.5\n", "max_connections must be .* not 1.5"),
        ("[connection_limit]\nmax_connections = true\n", "max_connections must be .* not True"),
        ('whitelist = "10.8.0.5"\n', "whitelist must be a list of .* not '10.8.0.5'"),
        ("whitelist = true\n", "whitelist must be a list of .* not True"),
        ("whitelist = [1, 2]\n", "whitelist must be a list of"),
        ('whitelist = ["10.8.0.5", ""]\n', "whitelist must be a list of"),
        ('whitelist = ["  "]\n', "whitelist must be a list of"),
        ('whitelist = [["10.8.0.5"]]\n', "whitelist must be a list of"),
        ("[whitelist]\naddresses = []\n", "whitelist must be a list of"),
        ("[signatures\n", "config.toml: "),
        ('[signatures]\nscope = "all"\nscope = "off"\n', "config.toml: "),
        (b'[signatures]\nscope = "\xff"\n', "config.toml: "),
    ],
)
def test_load_config_rejects_an_invalid_file(tmp_path: Path, content: str | bytes, message: str) -> None:
    path = write_config(tmp_path, content)

    with pytest.raises(ConfigError, match=message) as error:
        load_config(path)
    assert str(error.value).startswith(f"{path}: ")


def test_load_config_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.toml")
