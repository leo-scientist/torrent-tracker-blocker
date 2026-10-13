#!/bin/sh
# Install the package and run the whole test suite, including
# tests/test_integration.py, against real iptables (nft and legacy backends)
# on every supported Python. Everything runs inside throwaway containers, so
# the host firewall is never touched.
#
# Usage: scripts/integration-test.sh [PYTHON_VERSION...]
set -eu

cd "$(dirname "$0")/.."

[ $# -gt 0 ] || set -- 3.11 3.12 3.13 3.14

for python in "$@"; do
    echo "=== Python $python"
    docker run --rm --cap-add NET_ADMIN -v "$PWD:/src:ro" -w /src \
        -e TRACKER_BLOCKER_INTEGRATION=1 -e PYTHONDONTWRITEBYTECODE=1 \
        "python:$python-slim" sh -euc '
            apt-get update -qq
            apt-get install -y -qq iptables iproute2 >/dev/null
            pip install -q --root-user-action=ignore --disable-pip-version-check /src pytest
            for backend in nft legacy; do
                update-alternatives --set iptables "/usr/sbin/iptables-$backend" >/dev/null
                iptables --version
                pytest -q -p no:cacheprovider -W error
            done
        '
done
