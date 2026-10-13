# torrent-tracker-blocker

Blocks BitTorrent trackers on a Linux host or gateway (for example a VPN server)
with iptables.

It downloads public lists of working trackers, resolves them to IP addresses
and loads `DROP` rules for them into dedicated iptables chains. A systemd timer
keeps the list current. The command is called `tracker-blocker`.

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

## Limitations

Read these before relying on the tool:

- **Trackers only.** Clients can still find peers through DHT, PEX and
  trackers that are not on the lists. This makes torrenting harder, not
  impossible.
- **IPv4 only.** IPv6 addresses are neither resolved nor blocked. About half
  of the listed trackers are also reachable over IPv6.
- **Trackers behind Cloudflare stay reachable.** Their addresses are shared
  with a huge number of unrelated sites, so they are excluded by default; see
  `--block-cloudflare`. That is about one in seven of the listed trackers.
- **Third-party lists.** The lists decide what gets blocked. See
  [Safety](#safety) for what they can and cannot do to the host.

## Requirements

- Python 3.11 - 3.14 (no third-party packages)
- Linux with `iptables` and `iptables-restore` 1.6.2+ and root privileges for
  everything except `parse`. Both the nft and the legacy backend work.

On distributions that use nftables, `iptables` is the `iptables-nft` front
end: the rules are stored in nftables (`table ip filter`) and work alongside a
native nftables rule set or firewalld. Reloading a rule set that starts with
`flush ruleset` removes them; run `tracker-blocker update` again afterwards.

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
sudo tracker-blocker update [-i SOURCE]... [-x SOURCE]... [--block-cloudflare]
                             [--allow-private] [--merge] [-o OUTPUT] [-c CHAIN]
```

| Option | Meaning |
|---|---|
| `-i`, `--input SOURCE` | List of tracker URLs: a local file or an `https://` URL. Repeatable. |
| `-x`, `--exclude SOURCE` | Addresses that must never be blocked: a local file or an `https://` URL. Repeatable. |
| `--block-cloudflare` | Do not exclude Cloudflare's addresses. |
| `--allow-private` | Accept private addresses from local files, see [Safety](#safety). |
| `-m`, `--merge` | Add the new rules to the existing rule file instead of replacing it. |
| `-o`, `--output OUTPUT` | Rule file to write (default `/var/lib/torrent-tracker-blocker/trackers.csv`). |

**Sources.** Without `-i` two public lists are used, both refreshed at least
daily:

- <https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt>
- <https://newtrackon.com/api/live>

A tracker list has one URL per line; `http`, `https` and `udp` URLs are
supported, and a missing port defaults to 80 (443 for `https`). Every IPv4
address of a host becomes a rule. Lines that cannot be parsed, hosts that do
not resolve and addresses that must not be blocked are skipped with a warning.
To add your own trackers, pass the public lists and your file together:
`-i https://... -i /etc/torrent-tracker-blocker/trackers.txt`.

**Exclusions.** An exclusion list has one IPv4 address or CIDR range per line;
`#` starts a comment. Lists given with `-x` are used in addition to
Cloudflare's published ranges (<https://www.cloudflare.com/ips-v4>), which are
always excluded unless `--block-cloudflare` is given. With that option every
unrelated site on the same Cloudflare address and port becomes unreachable too.

**Replace or merge.** By default the rule file is replaced, so trackers that
moved or died are unblocked on the next run. With `--merge` the previous rules
are kept and the new ones added. Merging survives lists and DNS that fluctuate
between runs, but nothing is ever removed: stale addresses pile up and
eventually block whoever owns them next. Delete the file from time to time if
you use it.

**Failures.** If a list cannot be downloaded, an exclusion list is invalid or
nothing can be blocked (for example because DNS is down), the command fails
and leaves both the rule file and the firewall as they were.

### status

```console
$ sudo tracker-blocker status
tracker-blocker-input: 87 rules, 0 packets dropped
tracker-blocker-output: 87 rules, 12 packets dropped
tracker-blocker-forward: 87 rules, 340 packets dropped
```

The exit code is 0 only if all three chains are installed and receive traffic.

### parse and apply

`update` is `parse` followed by `apply`. Run them separately to build the rule
file on another machine or to inspect it before it reaches the firewall:

```sh
tracker-blocker parse [the options of update, except -c] [-o trackers.csv]
sudo tracker-blocker apply -i trackers.csv [--allow-private] [-c CHAIN]
```

`apply` creates the chains `CHAIN-input`, `CHAIN-output` and `CHAIN-forward`,
fills them with `DROP` rules and jumps to them from the top of `INPUT`,
`OUTPUT` and `FORWARD`, so existing `ACCEPT` rules cannot bypass the block
list.

Running it again replaces the previous rules. The whole change is a single
`iptables-restore` transaction: an invalid rule file or an iptables error
leaves the firewall exactly as it was, and rules outside these chains are
never touched.

## Automatic updates

The units in [`systemd/`](systemd) are installed in the quick start:

| Unit | Purpose |
|---|---|
| `tracker-blocker-update.timer` | Runs `tracker-blocker update --quiet` once a day. |
| `tracker-blocker-restore.service` | Loads the saved rule file at boot, because iptables rules do not survive a reboot. |

To change the options, for example to add an exclusion list, override the
command with `sudo systemctl edit tracker-blocker-update.service`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/tracker-blocker update --quiet -x /etc/torrent-tracker-blocker/exclude.txt
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

- **Block local networks.** Only public unicast IPv4 addresses can become a
  rule. Loopback, private (10/8, 172.16/12, 192.168/16), link-local, CGNAT,
  multicast and reserved ranges are rejected, however they are spelled
  (`localhost`, `127.1`, `2130706433`, a host name resolving to them). `parse`
  skips such entries; `apply` refuses a rule file that contains one.
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
resolvers, monitoring, your own services) into an exclusion list, and only add
sources you trust.

**Blocking private addresses on purpose.** A tracker inside your own network,
such as an ISP's `retracker.local`, has a private address. To block it, list
it in a local file and pass `--allow-private` to `update` (or to both `parse`
and `apply`). The option admits the private and CGNAT ranges (10/8, 172.16/12,
192.168/16, 100.64/10) from local files only: downloaded lists can never add
them, and loopback, link-local and the host's own addresses stay unblockable.

## Rule file format

A CSV without a header, one rule per line:

```
tcp,6969,46.4.109.148
udp,80,185.217.0.76
```

| Column   | Value                      |
|----------|----------------------------|
| protocol | `tcp` or `udp`             |
| port     | tracker port, 1-65535      |
| ip       | public IPv4 address        |

`apply` rejects the whole file if any row is invalid.

## Development

```sh
uv sync                        # create .venv with the dev tools
uv run pytest                  # unit tests
uv run ruff check              # lint
uv run ruff format             # format
uv run mypy                    # type check (strict)
./scripts/integration-test.sh  # test against real iptables inside Docker
```

The integration tests rewrite the firewall of the machine they run on, so they
are skipped unless `TRACKER_BLOCKER_INTEGRATION=1` is set; the script sets it
inside a throwaway container.

```
src/torrent_tracker_blocker/
├── cli.py        command line interface
├── blocklist.py  build the rule file and load it into the firewall
├── sources.py    read lists from files and https:// URLs
├── parser.py     tracker URLs -> rules (DNS resolution)
├── rules.py      rule model, validation and CSV I/O
└── firewall.py   iptables-restore scripts and chain status
systemd/          units for daily updates and restoring rules at boot
```

## License

[MIT](LICENSE)
