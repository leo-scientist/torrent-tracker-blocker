import pytest

from torrent_tracker_blocker.measures import (
    MAX_CONNECTIONS_CEILING,
    NO_MEASURES,
    ConfigError,
    Measures,
    Scope,
)


def test_every_measure_is_off_by_default() -> None:
    assert Measures(Scope.OFF, Scope.OFF, None) == NO_MEASURES
    assert Measures() == NO_MEASURES


@pytest.mark.parametrize("max_connections", [1, 2, 200, MAX_CONNECTIONS_CEILING])
@pytest.mark.parametrize("connection_limit", Scope)
def test_measures_accept_every_usable_limit(connection_limit: Scope, max_connections: int) -> None:
    measures = Measures(connection_limit=connection_limit, max_connections=max_connections)

    assert measures.max_connections == max_connections


@pytest.mark.parametrize("max_connections", [0, -1, MAX_CONNECTIONS_CEILING + 1, True, False, 1.5, "200"])
@pytest.mark.parametrize("connection_limit", Scope)
def test_measures_reject_an_unusable_limit(connection_limit: Scope, max_connections: object) -> None:
    with pytest.raises(ConfigError, match="max_connections must be a whole number"):
        Measures(connection_limit=connection_limit, max_connections=max_connections)  # type: ignore[arg-type]


@pytest.mark.parametrize("signatures", Scope)
@pytest.mark.parametrize("connection_limit", [Scope.FORWARD, Scope.ALL])
def test_a_connection_limit_has_no_default_number(signatures: Scope, connection_limit: Scope) -> None:
    with pytest.raises(ConfigError, match="connection_limit needs max_connections"):
        Measures(signatures, connection_limit)


@pytest.mark.parametrize("signatures", Scope)
def test_no_number_is_needed_while_the_connection_limit_is_off(signatures: Scope) -> None:
    assert Measures(signatures).max_connections is None


def test_scopes_are_spelled_as_in_the_configuration_file() -> None:
    assert [str(scope) for scope in Scope] == ["off", "forward", "all"]
