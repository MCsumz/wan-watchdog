# WAN watchdog

A small Linux service that notices when the internet goes down, records the evidence, and reboots
a ZTE 5G router through its own web API when the router has stopped routing.

One Python file, standard library only, run by systemd. It's tested with a **ZTE MC8830**, and it
may work with other ZTE routers whose web UI uses the same `zwrt_web` ubus API (untested).

## Why

My 5G router sometimes keeps its connection to the mobile network but stops passing traffic.
Every device loses the internet. Restarting the local DNS server doesn't help; only a router reboot
does. The router's own log shows nothing, and the signal stays good.

- **17 Nov 2026, about 17:30 to 17:55:** every lookup from the gateway timed out while the router
  stayed reachable on the LAN. A router reboot fixed it within seconds. Smaller bursts came before
  that, on 16 and 17 Nov.
- **19 Nov 2026, 18:30 to 18:52:** the watchdog logged seven short outages of 30 to 90 s. New TCP
  connections to 1.1.1.1 and 8.8.8.8 still opened, but the lookups failed, and the router showed 5G
  SA with 3 or 4 bars. The ISP also intercepts plain UDP port 53 traffic, so at first this looked
  like its DNS faltering, and the local resolver was moved to encrypted DNS (DoH/DoT).
- **20 Nov 2026, 19:20 and 22:24:** two more outages of over 4 minutes, this time with encrypted
  DNS. Connections still opened but no data came through (`outage: stalled`). The router's own log
  shows the radio link up all along (same cell, normal signal). A data disconnect and reconnect in
  the router's web UI did not help; only a full reboot, which also re-registers with the network,
  brought the internet back.

Every hang so far started in the evening, between about 17:30 and 22:30. Whether the cause is the
router or an overloaded cell is still open; the watchdog's log is the evidence for either.

## What it does

Every 30 seconds it checks the internet directly, past any local DNS server:

- **DNS:** a query for a fresh random name over DoH (`https://1.1.1.1/dns-query`) and DoT
  (`tls://9.9.9.9`). The name is random so that no cache, and no interceptor, can answer it from
  memory. NXDOMAIN is the expected answer.
- **TCP:** a connection to 1.1.1.1:443 and 8.8.8.8:443.

The DNS check is a full encrypted exchange, so it also proves that data flows; the TCP check only
proves that a connection opens. If either check fails on every target, the internet is down, and
the event says which way: `stalled` (connections open, no data gets through) or `offline` (not even
a connection opens). Each change is written as a JSON line
to `/var/lib/wan-watchdog/events.jsonl` and to the journal, together with the router's radio state
(read from its status API, no login needed):

```json
{"at": "2026-11-20T19:20:07+0100", "event": "down", "outage": "stalled", "probes": {"dns": false, "tcp": true}, "router_reachable": true, "netinfo": {"network_type": "SA", "signalbar": "3", "wan_active_band": "n78", "network_provider": "<ISP>", "nr5g_cell_id": "<cell>", "nr5g_pci": "<pci>", "domain_stat": "PS_ONLY", "lock_nr_cell": ""}}
{"at": "2026-11-20T19:25:30+0100", "event": "up", "down_seconds": 330, "reboots": 1}
```

`probes_changed` records when an outage changes between `stalled` and `offline`, and `up` records
how long it lasted.

### When it reboots the router

After **2 minutes down**, it logs in to the router's web API the way the router's own UI does
(SHA-256 of SHA-256(password) + salt) and calls `zwrt_mc.device.manager.device_reboot`. It only
does that when all of these hold:

- the router itself still answers on the LAN, so a dead router or cable isn't rebooted blindly
- at least 30 minutes have passed since the last reboot
- there have been at most 3 reboots in 6 hours
- no login was rejected in the last 6 hours, which keeps it well clear of the router's 5-try
  lockout

Each skipped reboot is logged with its reason (`cooldown`, `too_many_reboots`,
`router_unreachable`, `login_failed_recently`, `no_password_file`, `auto_reboot_off`), once per
reason and outage rather than every 30 s.

A real reboot during testing logged `down` at 18:21:34 and `up` at 18:22:10: the internet was back
about a minute after the request.

## Install

On the Linux machine that should watch the router (it needs Python 3 and systemd):

```sh
curl -L https://github.com/MCsumz/wan-watchdog/archive/refs/tags/v1.1.0.tar.gz | tar -xz
cd wan-watchdog-1.1.0
sudo sh install.sh
```

(Or `git clone` the repo for the latest `main`; [releases](https://github.com/MCsumz/wan-watchdog/releases) list the changes.)

The installer:

1. checks the files against `SHA256SUMS`
2. installs them to `/opt/wan-watchdog` and the unit to `/etc/systemd/system`
3. asks for the router's admin password, without echoing it, and stores it in
   `/etc/wan-watchdog/router-password` (root only, `0600`)
4. tests the login, then enables and starts the service

If the login fails, it deletes the password file and the watchdog runs **log-only**: it still
records every outage but never reboots. Run the installer again to retry.

**Settings** go in `/etc/wan-watchdog/config.json`. Every key is optional, and the installer keeps
whatever is there:

| Key | Default | Meaning |
| --- | --- | --- |
| `router` | `192.168.0.1` | The router's LAN address. Set it before installing if yours differs. |
| `interval` | `30` | Seconds between checks |
| `reboot_after` | `120` | Seconds down before a reboot |
| `cooldown` | `1800` | Minimum seconds between reboots |
| `max_reboots`, `window` | `3`, `21600` | At most this many reboots per window |
| `auto_reboot` | `true` | `false` = log only |
| `dns_targets`, `tcp_targets` | see above | What the probes check |

## Use

```sh
sudo python3 /opt/wan-watchdog/wan_watchdog.py --status        # state and the last events
sudo python3 /opt/wan-watchdog/wan_watchdog.py --check-login   # log in to the router and out again
sudo python3 /opt/wan-watchdog/wan_watchdog.py --reboot-now    # reboot the router once, now
sudo python3 /opt/wan-watchdog/wan_watchdog.py --once --dry-run
journalctl -u wan-watchdog -f
```

The unit runs hardened: `ProtectSystem=strict`, `NoNewPrivileges`, no capabilities, and only IP
and Unix sockets.

## Tests

```sh
python3 -m unittest test_wan_watchdog
```

There are 12 offline tests with a fake clock, probe and router. They cover:

- quiet while the internet is up
- a short drop is logged without a reboot
- a reboot after 2 minutes, with the stored password
- the cooldown and the limit of 3 per 6 hours
- no reboot while the router itself is unreachable
- a rejected login stops further attempts
- log-only and dry-run modes
- a missing password file
- state survives a restart
- stalls and full outages are labelled
- the login hash matches the router UI
- a fake DNS answer is rejected

It has also run on a real gateway since 17 Nov 2026:

- the probes, the router's status API, and the login check
- a simulated outage, using unreachable probe targets and `--dry-run`
- a real router reboot

## Notes

- **Your router, your risk.** Rebooting drops every connection for about a minute. The limits
  above keep it from looping, but read the code before you trust it with your network.
- **Unofficial.** This isn't affiliated with ZTE. The router API was read from the router's own
  web UI.
- **Built with AI assistance;** the integration and testing were done hands-on.

## License

[MIT](LICENSE)
