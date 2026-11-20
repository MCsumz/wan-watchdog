#!/usr/bin/env python3
"""WAN watchdog: logs internet outages and reboots a ZTE 5G router when it stops routing.

The router (tested: ZTE MC8830) sometimes stays attached to the mobile network but stops
passing traffic until it is rebooted. Every 30 s this checks the internet directly, past any
local DNS server. After 2 minutes down, with the router itself still reachable, it logs in to
the router's own web API and reboots it, at most once per 30 minutes and 3 times per 6 hours.
Python standard library only.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import socket
import ssl
import struct
import sys
import time
import urllib.request

CONFIG = Path("/etc/wan-watchdog/config.json")
PASSWORD = Path("/etc/wan-watchdog/router-password")
STATE_DIR = Path("/var/lib/wan-watchdog")
DEFAULTS = {
    "router": "192.168.0.1",
    "interval": 30,
    "reboot_after": 120,
    "cooldown": 1800,
    "max_reboots": 3,
    "window": 21600,
    "auto_reboot": True,
    "dns_targets": ["https://1.1.1.1/dns-query", "tls://9.9.9.9"],
    "tcp_targets": ["1.1.1.1", "8.8.8.8"],
}
# A rejected login leaves auto-reboot off this long, so the router's 5-try lockout is never reached.
LOGIN_BACKOFF = 21600
ANONYMOUS = "0" * 32
NETINFO_KEYS = ("network_type", "signalbar", "wan_active_band", "nr5g_pci", "nr5g_cell_id",
                "domain_stat", "network_provider", "lock_nr_cell")


class RouterError(Exception):
    pass


class LoginRejected(RouterError):
    pass


def dns_ok(server, timeout=3.0):
    """A DNS-over-HTTPS (or DNS-over-TLS) query for a random name.

    Some ISPs intercept all UDP port 53 traffic, and an interceptor can falter under
    evening load (observed: lookups failing for 30-90 s while TCP connects worked). Encrypted DNS goes
    past the interception, so the probe uses it too and never reboots the router over the
    ISP's DNS. A fresh random name has to be resolved for real; NXDOMAIN is the expected answer.
    """
    qid = random.randrange(65536)
    label = ("ww%d" % random.randrange(10 ** 9)).encode()
    name = b"".join(bytes([len(part)]) + part for part in (label, b"example", b"com")) + b"\0"
    query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)
    try:
        if server.startswith("tls://"):
            # DNS over TLS. Quad9 answers DoH only over HTTP/2, which urllib cannot speak.
            host = server[len("tls://"):]
            context = ssl.create_default_context()
            with socket.create_connection((host, 853), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as sock:
                    sock.sendall(struct.pack(">H", len(query)) + query)
                    reply = b""
                    while len(reply) < 2 or len(reply) < 2 + struct.unpack(">H", reply[:2])[0]:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        reply += chunk
                    reply = reply[2:]
        else:
            url = "%s?dns=%s" % (server, base64.urlsafe_b64encode(query).decode().rstrip("="))
            request = urllib.request.Request(url, headers={"Accept": "application/dns-message"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                reply = response.read(4096)
    except (OSError, ValueError, struct.error):
        return False
    return len(reply) >= 12 and reply[:2] == query[:2] and reply[3] & 0x0F in (0, 3)


def tcp_ok(host, port=443, timeout=3.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def outage_kind(probes):
    """'stalled': new connections still open, but no data gets through (the DNS probe is a full
    encrypted exchange). 'offline': not even a connection opens."""
    return "stalled" if probes.get("tcp") and not probes.get("dns") else "offline"


class Probe:
    def __init__(self, config):
        self.config = config

    def check(self):
        """Name lookups and plain TCP separately: either failing everywhere breaks the internet for every device."""
        return {"dns": any(dns_ok(server) for server in self.config["dns_targets"]),
                "tcp": any(tcp_ok(host) for host in self.config["tcp_targets"])}

    def router(self):
        return tcp_ok(self.config["router"], 443, 2.0)


def sha(text):
    # The router's web UI hashes with SHA-256 as upper-case hex: SHA256(SHA256(password) + salt).
    return hashlib.sha256(text.encode()).hexdigest().upper()


class Router:
    """The router's ubus JSON-RPC API, as its own web UI uses it."""

    def __init__(self, host):
        self.host = host
        # The router serves its own self-signed certificate on the LAN.
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def call(self, session, obj, method, args):
        body = json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "call",
                            "params": [session, obj, method, args]}]).encode()
        request = urllib.request.Request(
            "https://%s/ubus/?t=%d" % (self.host, int(time.time() * 1000)), body,
            {"Content-Type": "application/json", "Referer": "https://%s/" % self.host})
        try:
            with urllib.request.urlopen(request, timeout=10, context=self.context) as response:
                reply = json.load(response)
        except (OSError, ValueError) as error:
            raise RouterError("%s.%s: %s" % (obj, method, error)) from error
        entry = reply[0] if isinstance(reply, list) and reply else {}
        if "error" in entry or not isinstance(entry.get("result"), list) or entry["result"][0] != 0:
            raise RouterError("%s.%s: %s" % (obj, method, entry.get("error") or entry.get("result")))
        return entry["result"][1] if len(entry["result"]) > 1 else {}

    def netinfo(self):
        info = self.call(ANONYMOUS, "zte_nwinfo_api", "nwinfo_get_netinfo", {})
        return {key: info.get(key) for key in NETINFO_KEYS}

    def login(self, password):
        info = self.call(ANONYMOUS, "zwrt_web", "web_login_info", {})
        if str(info.get("login_fail_lock_lefttime") or "0") not in ("0", ""):
            raise LoginRejected("router login is locked for %ss" % info["login_fail_lock_lefttime"])
        reply = self.call(ANONYMOUS, "zwrt_web", "web_login",
                          {"password": sha(sha(password) + info["zte_web_sault"])})
        if str(reply.get("result")) != "0" or not reply.get("ubus_rpc_session"):
            raise LoginRejected("router rejected the password (%s tries left before lockout)" %
                                info.get("login_fail_num"))
        return reply["ubus_rpc_session"]

    def check_login(self, password):
        session = self.login(password)
        self.call(session, "zwrt_web", "web_logout", {})

    def reboot(self, password):
        session = self.login(password)
        self.call(session, "zwrt_mc.device.manager", "device_reboot", {"moduleName": "web"})


class Watchdog:
    def __init__(self, config, state_dir, probe, router, password_file, clock=time.time, dry_run=False):
        self.config = config
        self.state_path = state_dir / "state.json"
        self.events_path = state_dir / "events.jsonl"
        self.probe = probe
        self.router = router
        self.password_file = password_file
        self.clock = clock
        self.dry_run = dry_run
        self.state = load_json(self.state_path)

    def event(self, kind, **fields):
        record = dict(fields, at=time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.clock())), event=kind)
        line = json.dumps(record, sort_keys=True)
        print(line, flush=True)
        with open(self.events_path, "a") as stream:
            stream.write(line + "\n")

    def netinfo(self):
        try:
            return self.router.netinfo()
        except RouterError as error:
            return {"error": str(error)}

    def blocked(self, now):
        """Why a reboot may not happen now, or None."""
        state = self.state
        if not self.config["auto_reboot"]:
            return "auto_reboot_off"
        if not self.password_file.exists():
            return "no_password_file"
        if now - state.get("login_failed_at", 0) < LOGIN_BACKOFF:
            return "login_failed_recently"
        if not self.probe.router():
            return "router_unreachable"
        if now - state.get("last_reboot", 0) < self.config["cooldown"]:
            return "cooldown"
        recent = [at for at in state.get("reboots", []) if now - at < self.config["window"]]
        if len(recent) >= self.config["max_reboots"]:
            return "too_many_reboots"
        return None

    def tick(self):
        now = self.clock()
        state = self.state
        probes = self.probe.check()
        if all(probes.values()):
            if state.get("down_since"):
                self.event("up", down_seconds=round(now - state["down_since"]),
                           reboots=state.get("outage_reboots", 0))
                state.update(down_since=None, outage_reboots=0, last_block=None, probes=None)
                self.save()
            return
        if not state.get("down_since"):
            state.update(down_since=now, outage_reboots=0, last_block=None, probes=probes)
            self.event("down", outage=outage_kind(probes), probes=probes, router_reachable=self.probe.router(),
                       netinfo=self.netinfo())
            self.save()
            return
        if probes != state.get("probes"):
            # Shows whether connections still opened (a stall) or nothing got through at all.
            state["probes"] = probes
            self.event("probes_changed", outage=outage_kind(probes), probes=probes,
                       down_seconds=round(now - state["down_since"]))
            self.save()
        down_for = now - state["down_since"]
        if down_for < self.config["reboot_after"]:
            return
        reason = self.blocked(now)
        if reason:
            # Logged once per reason and outage, not every 30 s.
            if state.get("last_block") != reason:
                state["last_block"] = reason
                self.event("reboot_skipped", reason=reason, down_seconds=round(down_for))
                self.save()
            return
        netinfo = self.netinfo()
        try:
            if self.dry_run:
                self.event("reboot_dry_run", down_seconds=round(down_for), probes=probes, netinfo=netinfo)
            else:
                self.router.reboot(self.password_file.read_text().rstrip("\r\n"))
                self.event("reboot", down_seconds=round(down_for), probes=probes, netinfo=netinfo)
        except LoginRejected as error:
            state["login_failed_at"] = now
            self.event("reboot_failed", error=str(error), down_seconds=round(down_for))
        except (RouterError, OSError) as error:
            self.event("reboot_failed", error=str(error), down_seconds=round(down_for))
        # Failed attempts count too, so a broken router API is not hammered.
        state["last_reboot"] = now
        state["reboots"] = [at for at in state.get("reboots", []) if now - at < self.config["window"]] + [now]
        state["outage_reboots"] = state.get("outage_reboots", 0) + 1
        state["last_block"] = None
        self.save()

    def save(self):
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state))
        os.replace(tmp, self.state_path)


def load_json(path):
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def load_config(path):
    config = dict(DEFAULTS)
    config.update(load_json(path))
    return config


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--password-file", type=Path, default=PASSWORD)
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR)
    parser.add_argument("--once", action="store_true", help="run one check and exit")
    parser.add_argument("--dry-run", action="store_true", help="log a reboot instead of doing it")
    parser.add_argument("--status", action="store_true", help="show the state and the last events")
    parser.add_argument("--check-login", action="store_true", help="log in to the router and out again")
    parser.add_argument("--reboot-now", action="store_true", help="reboot the router once, now")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    router = Router(config["router"])
    if args.check_login or args.reboot_now:
        password = args.password_file.read_text().rstrip("\r\n")
        try:
            if args.reboot_now:
                router.reboot(password)
                print("Router reboot requested; it is back in about 2 minutes.")
            else:
                router.check_login(password)
                print("Router login works.")
        except RouterError as error:
            print("Router: %s" % error, file=sys.stderr)
            return 1
        return 0
    args.state_dir.mkdir(parents=True, exist_ok=True)
    if args.status:
        print(json.dumps(load_json(args.state_dir / "state.json"), indent=2))
        try:
            print("".join(open(args.state_dir / "events.jsonl").readlines()[-20:]), end="")
        except OSError:
            print("no events yet")
        return 0
    watchdog = Watchdog(config, args.state_dir, Probe(config), router, args.password_file, dry_run=args.dry_run)
    if args.once:
        watchdog.tick()
        return 0
    watchdog.event("started", auto_reboot=config["auto_reboot"], dry_run=args.dry_run,
                   reboot_after=config["reboot_after"], netinfo=watchdog.netinfo())
    while True:
        started = time.monotonic()
        try:
            watchdog.tick()
        except Exception as error:  # keep watching; systemd restarts only on a crash of the loop itself
            watchdog.event("tick_error", error="%s: %s" % (type(error).__name__, error))
        time.sleep(max(1.0, config["interval"] - (time.monotonic() - started)))


if __name__ == "__main__":
    sys.exit(main())
