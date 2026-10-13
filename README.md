# torrent-tracker-blocker

Blocks BitTorrent trackers on a Linux host or gateway (for example a VPN server)
with iptables, over both IPv4 and IPv6.

It downloads public lists of working trackers, resolves them to IP addresses
and loads `DROP` rules for them into dedicated iptables and ip6tables chains. A systemd timer
keeps the list current. The command is called `tracker-blocker`.

Optional [additional measures](#additional-measures) also drop the BitTorrent
traffic that no tracker list covers, such as DHT and connections between
peers.

## Quick start

On the Linux host, as a user with `sudo` (Debian/Ubuntu also need the
`python3-venv` package):

```sh
git clone https://github.com/leo-scientist/torrent-tracker-blocker
cd torrent-tracker-blocker

# Install into /opt and put the command on everyone's PATH
sudo python3 -m venv /opt/torrent-tracker-blocker
sudo /opt/torrent-tracker-blocker/bin/pip install .
sudo ln -s /opt/torrent-tracker-blocker/bin/tracker-blocker /usr/local/bin/

# Block the trackers now
sudo tracker-blocker update

# Refresh the list daily and restore the rules after a reboot
sudo cp systemd/tracker-blocker-* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tracker-blocker-update.timer tracker-blocker-restore.service
```

Check that it works with `sudo tracker-blocker status`; undo everything with
`sudo tracker-blocker remove`.

This blocks every listed tracker and nothing else. Some trackers share
their address with unrelated sites, which then become unreachable as well:
see [Whitelist](#whitelist) for how to spare them. To block more than
trackers, see [Additional measures](#additional-measures).

## Limitations

Read these before relying on the tool:

- **Trackers only, unless you ask for more.** Clients can still find peers
  through DHT, PEX and trackers that are not on the lists. The
  [additional measures](#additional-measures) close part of that gap, but
  encrypted BitTorrent traffic stays invisible to them. All of this makes
  torrenting harder, not impossible.
- **Shared addresses are blocked too.** About one in seven of the listed
  trackers sits behind a content delivery network such as Cloudflare, on an
  address that a huge number of unrelated sites share. Blocking it cuts those
  sites off on the same port. Nothing is spared by default: put the address
  ranges of such providers on the [whitelist](#whitelist) if that matters to
  you.
- **Third-party lists.** The lists decide what gets blocked. See
  [Safety](#safety) for what they can and cannot do to the host.

## Requirements

- Python 3.11 - 3.14 (no third-party packages)
- Linux with `iptables` and `iptables-restore` 1.6.2+ and root privileges for
  everything except `parse`. Both the nft and the legacy backend work.
- `ip6tables` for IPv6. If it is not installed, or the kernel has no IPv6
  support, only IPv4 trackers are blocked and `update` says so in a warning.
- For the [additional measures](#additional-measures), the `string`,
  `connlimit` and `conntrack` matches of iptables, which stock distribution
  kernels provide. If one is missing, `update` fails and changes nothing.

On distributions that use nftables, `iptables` is the `iptables-nft` front
end: the rules are stored in nftables (`table ip filter` and
`table ip6 filter`) and work alongside a native nftables rule set or
firewalld. Reloading a rule set that starts with `flush ruleset` removes them;
run `tracker-blocker update` again afterwards.

Without `sudo` rights for a system-wide installation, `uv tool install .` or
`pipx install .` also work; `sudo` then needs the full path:
`sudo "$(command -v tracker-blocker)" update`.

## Commands

| Command | What it does |
|---|---|
| `update` | Downloads the lists, writes the rule file and loads it into iptables. |
| `status` | Shows the installed rules and how many packets they dropped. |
| `remove` | Deletes the chains and the jumps to them. |
| `parse` | Only downloads the lists and writes the rule file. Needs neither root nor iptables. |
| `apply` | Only loads an existing rule file into iptables. |

Every command accepts `-q`/`--quiet` to print errors only, and all but `parse`
accept `-c`/`--chain CHAIN` to use chains other than `tracker-blocker-*`.

### update

```sh
sudo tracker-blocker update [-i SOURCE]... [-w [ADDRESSES ...]] [--allow-private]
                             [--merge] [-o OUTPUT] [-c CHAIN] [--config FILE]
                             [--signatures SCOPE] [--connection-limit SCOPE]
                             [--max-connections N]
```

| Option | Meaning |
|---|---|
| `-i`, `--input SOURCE` | List of tracker URLs: a local file or an `https://` URL. Repeatable. |
| `-w`, `--whitelist [ADDRESSES ...]` | Addresses that must never be blocked, see [Whitelist](#whitelist). Repeatable. |
| `--allow-private` | Accept private addresses from local files, see [Safety](#safety). |
| `-m`, `--merge` | Add the new rules to the existing rule file instead of replacing it. |
| `-o`, `--output OUTPUT` | Rule file to write (default `/var/lib/torrent-tracker-blocker/trackers.csv`). |
| `--config FILE` | [Configuration file](#configuration) to read instead of the default one. |
| `--signatures`, `--connection-limit`, `--max-connections` | See [Additional measures](#additional-measures). |

**Sources.** Without `-i` two public lists are used, both refreshed at least
daily:

- <https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt>
- <https://newtrackon.com/api/live>

A tracker list has one URL per line; `http`, `https` and `udp` URLs are
supported, and a missing port defaults to 80 (443 for `https`). Every IPv4
and IPv6 address of a host becomes a rule. Lines that cannot be parsed, hosts that do
not resolve and addresses that must not be blocked are skipped with a warning.
To add your own trackers, pass the public lists and your file together:
`-i https://... -i /etc/torrent-tracker-blocker/trackers.txt`.

**Replace or merge.** By default the rule file is replaced, so trackers that
moved or died are unblocked on the next run. With `--merge` the previous rules
are kept and the new ones added. Merging survives lists and DNS that fluctuate
between runs, but nothing is ever removed: stale addresses pile up and
eventually block whoever owns them next. Delete the file from time to time if
you use it.

**Failures.** If a list cannot be downloaded, the whitelist or the
configuration is invalid, or nothing can be blocked (for example because DNS
is down), the command fails and leaves both the rule file and the firewall as
they were.

### status

```console
$ sudo tracker-blocker status
IPv4 tracker-blocker-input: 80 rules, 0 packets dropped
IPv4 tracker-blocker-output: 80 rules, 12 packets dropped
IPv4 tracker-blocker-forward: 80 rules, 340 packets dropped
IPv6 tracker-blocker-input: 32 rules, 0 packets dropped
IPv6 tracker-blocker-output: 32 rules, 0 packets dropped
IPv6 tracker-blocker-forward: 32 rules, 57 packets dropped
```

The exit code is 0 only if all chains are installed and receive traffic: three
for IPv4 and, where IPv6 is available, three for IPv6.

A chain with [additional measures](#additional-measures) also shows what each
of them dropped:

```
IPv4 tracker-blocker-forward: 80 rules, 340 packets dropped, 1200 more by signatures, 15 more by the connection limit
```

### parse and apply

`update` is `parse` followed by `apply`. Run them separately to build the rule
file on another machine or to inspect it before it reaches the firewall:

```sh
tracker-blocker parse [-i SOURCE]... [-w [ADDRESSES ...]] [--allow-private] [--merge]
                      [-o trackers.csv] [--config FILE]
sudo tracker-blocker apply -i trackers.csv [--allow-private] [-c CHAIN] [--config FILE]
                           [--signatures SCOPE] [--connection-limit SCOPE]
                           [--max-connections N]
```

The whitelist belongs to `parse`: it decides what gets into the rule file. The
additional measures belong to `apply`: they are firewall rules of their own.

`apply` creates the chains `CHAIN-input`, `CHAIN-output` and `CHAIN-forward`
in both iptables and ip6tables, fills them with `DROP` rules for the trackers
and for the enabled measures, and jumps to them
from the top of `INPUT`, `OUTPUT` and `FORWARD`, so existing `ACCEPT` rules
cannot bypass the block list.

Running it again replaces the previous rules. Each IP version is changed in a
single `iptables-restore` transaction: an invalid rule file or an iptables
error leaves its firewall exactly as it was, and rules outside these chains
are never touched. IPv4 is applied first; if the IPv6 transaction then fails,
the command reports the error and IPv6 keeps its previous rules.

## Configuration

Settings that the daily update and the restore at boot must share live in
`/etc/torrent-tracker-blocker/config.toml`, which `update`, `parse` and
`apply` read. The file is optional, and whatever it leaves out keeps its
default:

```toml
# Addresses that never get a blocking rule: here the ranges that Cloudflare
# publishes, a list of your own and a single server.
whitelist = [
    "https://www.cloudflare.com/ips-v4",
    "https://www.cloudflare.com/ips-v6",
    "/etc/torrent-tracker-blocker/whitelist.txt",
    "203.0.113.7",
]

[signatures]
scope = "forward"

[connection_limit]
scope = "forward"
max_connections = 200
```

| Setting | Command line | Values | Default |
|---|---|---|---|
| `whitelist` | `-w`, `--whitelist` | Addresses, ranges, files and URLs, see [Whitelist](#whitelist). | Empty |
| `scope` in `[signatures]` | `--signatures` | `"off"`, `"forward"` or `"all"`, see [Additional measures](#additional-measures). | `"off"` |
| `scope` in `[connection_limit]` | `--connection-limit` | `"off"`, `"forward"` or `"all"`. | `"off"` |
| `max_connections` in `[connection_limit]` | `--max-connections` | A whole number from 1 to 4294967295. | None: it must be set once the limit is on. |

To create the file and put it into effect:

```sh
sudo mkdir -p /etc/torrent-tracker-blocker
sudoedit /etc/torrent-tracker-blocker/config.toml
sudo tracker-blocker update
```

How the file is read:

- `--config FILE` reads another file instead of the default one.
- A command line option overrides the setting of the same name.
- `whitelist` has to stand above the first `[section]`. That is how TOML
  works: below a section header it would belong to that section, and is
  rejected there.
- The file has to be valid on its own. A connection limit that is enabled in
  it needs its `max_connections` there too, even if you pass the number on
  the command line.
- An unknown option or a value that cannot be used fails the command before
  anything is downloaded or changed. The restore at boot reads the same file,
  so run `update` after every edit to see that it is accepted.

### Whitelist

Addresses on the whitelist never get a blocking rule, whatever the tracker
lists say. An entry is one of:

- an IPv4 or IPv6 address, such as `203.0.113.7`;
- a CIDR range, such as `198.51.100.0/24` or `2001:db8::/32`;
- a list of them: a local file or an `https://` URL with one address or range
  per line, where `#` starts a comment. Give files by their full path: a
  relative one is looked up in the directory the command runs in, which under
  systemd is `/`.

The lists are read again on every `update`, so a provider that changes its
ranges is followed automatically. If one of them cannot be read, the update
fails and the previous rules stay.

The whitelist is empty by default: no provider is built in, and what to spare
is your decision. Two kinds of addresses are worth putting on it:

- **The ranges of content delivery networks.** They serve a huge number of
  unrelated sites from the same addresses, so a rule for a tracker behind one
  makes every site on that address and port unreachable. Many providers
  publish their ranges in the format above; Cloudflare, for example, at
  <https://www.cloudflare.com/ips-v4> and <https://www.cloudflare.com/ips-v6>.
  A provider that publishes them in another format needs a file of your own.
- **The servers the host depends on**, such as DNS resolvers, monitoring and
  your own services, so that no list can ever block them.

`-w`/`--whitelist` sets the whitelist from the command line. It replaces the
configured one, and without a value it whitelists nothing.

The whitelist is applied when the rule file is written, so `apply` loads a
rule file as it is. It only decides which addresses get a tracker rule: the
additional measures recognise BitTorrent by what a packet contains, not by
where it goes.

## Additional measures

Blocking the listed trackers never touches other traffic. The measures below
also catch what the lists miss, but each of them can hit legitimate traffic
too, so they are off until you enable them.

| Measure | What it drops | What it costs |
|---|---|---|
| `signatures` | Unencrypted BitTorrent packets, wherever they go: peer handshakes (TCP and uTP), DHT queries, connection requests to UDP trackers and announces to HTTP trackers. | The start of every packet is searched, which takes CPU time on a busy gateway. Another program's packet that happens to begin with the same bytes is dropped as well. Encrypted peer connections and HTTPS trackers are not seen. |
| `connection_limit` | New connections of an address that already has more than `max_connections` open, counting every protocol together. | It slows torrents down instead of blocking them, and it slows down everything else that opens many connections at once: several devices behind one address, download managers, crawlers. |

Each measure has a `scope`:

| Scope | Traffic it applies to |
|---|---|
| `off` | None; the default. |
| `forward` | Only what the host forwards for others, such as the clients of a VPN server. The host's own traffic is left alone. |
| `all` | Forwarded traffic and the host itself: signatures in the packets it sends and receives, the limit for the connections it opens. Connections that others open to the host are never limited, so a server running on it keeps its clients. |

Details worth knowing:

- The connection limit is per source address and only refuses new
  connections: the ones that are already established keep working.
- `max_connections` has no default, because the right number depends on what
  your clients do: a browser keeps a few dozen connections open, a torrent
  client hundreds. Enabling the limit without it is an error.
- Traffic between the host and its own addresses is exempt from every measure.
- The measures cover IPv4 and IPv6 alike.
- `status` shows what each measure dropped, which helps to see whether it
  earns its cost before and after you enable it.

On the command line: `--signatures SCOPE`, `--connection-limit SCOPE` and
`--max-connections N`, accepted by `update` and `apply`.

## Automatic updates

The units in [`systemd/`](systemd) are installed in the quick start:

| Unit | Purpose |
|---|---|
| `tracker-blocker-update.timer` | Runs `tracker-blocker update --quiet` once a day. |
| `tracker-blocker-restore.service` | Loads the saved rule file at boot, because iptables rules do not survive a reboot. |

Both units read the [configuration file](#configuration), so the whitelist
and the additional measures are set there. For the other options, for example
a tracker list of your own, override the command with
`sudo systemctl edit tracker-blocker-update.service`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/tracker-blocker update --quiet -i /etc/torrent-tracker-blocker/trackers.txt
```

Failed runs show up in `systemctl --failed` and
`journalctl -u tracker-blocker-update.service`.

Without systemd, use root's crontab instead:

```cron
0 4 * * * /usr/local/bin/tracker-blocker update --quiet
@reboot /usr/local/bin/tracker-blocker apply --quiet -i /var/lib/torrent-tracker-blocker/trackers.csv
```

## Safety

The block list comes from third parties, so it is treated as hostile input.

What a list can never do:

- **Block local networks.** Only public unicast addresses can become a rule.
  Loopback, private (10/8, 172.16/12, 192.168/16, fc00::/7), link-local,
  CGNAT, multicast and reserved ranges are rejected, however they are spelled
  (`localhost`, `127.1`, `2130706433`, `::ffff:127.0.0.1`, a host name
  resolving to them). `parse` skips such entries; `apply` refuses a rule file
  that contains one.
- **Smuggle an IPv4 address inside an IPv6 one.** IPv6 addresses that embed an
  IPv4 address (IPv4-mapped, NAT64, 6to4, Teredo) are rejected, and so is any
  IPv6 address with a zone identifier. The price: on an IPv6-only host that
  reaches IPv4 through NAT64, IPv4-only trackers are not blocked.
- **Cut the host off from itself.** The chains start with a rule that returns
  early for traffic between the host and its own addresses, public ones
  included. The kernel decides what is local, so this holds for addresses
  added later.
- **Be tampered with in transit.** Remote lists are only read over HTTPS, and
  a redirect to plain HTTP is rejected.
- **Leave the firewall half-configured.** See `apply`.

What a list can still do: block any *other* public address and port. A hostile
entry such as `udp://8.8.8.8:53` would block that DNS resolver for the host
and for forwarded clients. Put the addresses the host depends on (DNS
resolvers, monitoring, your own services) on the [whitelist](#whitelist), and
only add sources you trust.

**Whitelists.** A whitelist can only take addresses off the block list, never
add to it. The worst a downloaded one can do is to name so much that fewer
trackers are blocked; if it names everything, `update` fails and keeps the
previous rules. Like the tracker lists, remote whitelists are only read over
HTTPS.

**The configuration file** is yours and is trusted as it is. Keep it writable
by root only: whoever can edit it can switch the blocking off.

**Blocking private addresses on purpose.** A tracker inside your own network,
such as an ISP's `retracker.local`, has a private address. To block it, list
it in a local file and pass `--allow-private` to `update` (or to both `parse`
and `apply`). The option admits the private and CGNAT ranges (10/8, 172.16/12,
192.168/16, 100.64/10, fc00::/7) from local files only: downloaded lists can never add
them, and loopback, link-local and the host's own addresses stay unblockable.

## Rule file format

A CSV without a header, one rule per line:

```
tcp,6969,46.4.109.148
udp,80,185.217.0.76
udp,6969,2a01:4f8:c17:8f74::2
```

| Column   | Value                          |
|----------|--------------------------------|
| protocol | `tcp` or `udp`                 |
| port     | tracker port, 1-65535          |
| ip       | public IPv4 or IPv6 address    |

`apply` rejects the whole file if any row is invalid.

## Development

```sh
uv sync                        # create .venv with the dev tools
uv run pytest                  # unit tests
uv run ruff check              # lint
uv run ruff format             # format
uv run mypy                    # type check (strict)
./scripts/integration-test.sh  # test against real iptables and ip6tables inside Docker
```

The integration tests rewrite the firewall of the machine they run on, so they
are skipped unless `TRACKER_BLOCKER_INTEGRATION=1` is set; the script sets it
inside a throwaway container.

```
src/torrent_tracker_blocker/
├── cli.py        command line interface
├── blocklist.py  build the rule file and load it into the firewall
├── config.py     the configuration file: whitelist and measures
├── measures.py   optional measures and their scopes
├── sources.py    read lists from files and https:// URLs
├── parser.py     tracker URLs -> rules (DNS resolution)
├── rules.py      rule model, validation and CSV I/O
└── firewall.py   iptables-restore scripts and chain status
systemd/          units for daily updates and restoring rules at boot
```

## License

[MIT](LICENSE)
