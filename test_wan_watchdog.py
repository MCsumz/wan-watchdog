"""Offline checks for the WAN watchdog: outage detection, reboot rules and the router login hash."""

import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("wan_watchdog", HERE / "wan_watchdog.py")
ww = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ww)


class FakeProbe:
    def __init__(self):
        self.dns = self.tcp = True
        self.router_up = True

    @property
    def up(self):
        return self.dns and self.tcp

    @up.setter
    def up(self, value):
        self.dns = self.tcp = value

    def check(self):
        return {"dns": self.dns, "tcp": self.tcp}

    def router(self):
        return self.router_up


class FakeRouter:
    def __init__(self):
        self.reboots = []
        self.fail = None

    def netinfo(self):
        return {"network_type": "SA", "signalbar": "4"}

    def reboot(self, password):
        if self.fail:
            raise self.fail
        self.reboots.append(password)


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)
        self.password = self.dir / "router-password"
        self.password.write_text("secret\n")
        self.probe, self.router, self.clock = FakeProbe(), FakeRouter(), Clock()
        self.config = dict(ww.DEFAULTS)
        self.dog = self.make()

    def make(self, **kwargs):
        return ww.Watchdog(self.config, self.dir, self.probe, self.router, self.password, clock=self.clock, **kwargs)

    def run_for(self, seconds, step=30):
        with redirect_stdout(io.StringIO()):
            for _ in range(int(seconds // step)):
                self.dog.tick()
                self.clock.now += step

    def events(self):
        path = self.dir / "events.jsonl"
        return [json.loads(line)["event"] for line in path.read_text().splitlines()] if path.exists() else []

    def test_quiet_while_up(self):
        self.run_for(600)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.router.reboots, [])

    def test_short_drop_is_logged_without_reboot(self):
        self.probe.up = False
        self.run_for(120)
        self.probe.up = True
        self.run_for(60)
        self.assertEqual(self.events(), ["down", "up"])
        self.assertEqual(self.router.reboots, [])
        last = json.loads((self.dir / "events.jsonl").read_text().splitlines()[-1])
        self.assertEqual(last["down_seconds"], 120)

    def test_reboots_after_four_minutes_with_the_stored_password(self):
        self.probe.up = False
        self.run_for(240)
        self.assertEqual(self.router.reboots, [])
        self.run_for(30)
        self.assertEqual(self.router.reboots, ["secret"])
        self.assertEqual(self.events(), ["down", "reboot"])

    def test_cooldown_and_rate_limit(self):
        self.probe.up = False
        self.run_for(1800)  # reboot at 4 minutes, then 30 minutes of cooldown
        self.assertEqual(len(self.router.reboots), 1)
        self.assertIn("reboot_skipped", self.events())
        self.run_for(5 * 3600)  # cooldowns would allow more; the limit is 3 per 6 hours
        self.assertEqual(len(self.router.reboots), 3)
        skipped = [json.loads(line).get("reason") for line in (self.dir / "events.jsonl").read_text().splitlines()]
        self.assertIn("too_many_reboots", skipped)

    def test_no_reboot_when_router_itself_is_unreachable(self):
        self.probe.up = self.probe.router_up = False
        self.run_for(600)
        self.assertEqual(self.router.reboots, [])
        reasons = [json.loads(line).get("reason") for line in (self.dir / "events.jsonl").read_text().splitlines()]
        self.assertEqual(reasons.count("router_unreachable"), 1)  # logged once, not every 30 s

    def test_rejected_login_stops_further_attempts(self):
        self.router.fail = ww.LoginRejected("router rejected the password (4 tries left before lockout)")
        self.probe.up = False
        self.run_for(4 * 3600)
        self.assertEqual(self.events().count("reboot_failed"), 1)
        self.assertIn("login_failed_recently", (self.dir / "events.jsonl").read_text())

    def test_off_and_dry_run_never_reboot(self):
        self.config["auto_reboot"] = False
        self.probe.up = False
        self.run_for(600)
        self.assertEqual(self.router.reboots, [])
        self.assertIn("auto_reboot_off", (self.dir / "events.jsonl").read_text())
        self.config["auto_reboot"] = True
        self.dog = self.make(dry_run=True)
        self.dog.state.update(down_since=None)
        self.run_for(600)
        self.assertEqual(self.router.reboots, [])
        self.assertIn("reboot_dry_run", self.events())

    def test_missing_password_file(self):
        self.password.unlink()
        self.probe.up = False
        self.run_for(600)
        self.assertIn("no_password_file", (self.dir / "events.jsonl").read_text())

    def test_state_survives_restart(self):
        self.probe.up = False
        self.run_for(300)
        self.assertEqual(len(self.router.reboots), 1)
        self.dog = self.make()  # service restart mid-outage
        self.run_for(300)
        self.assertEqual(len(self.router.reboots), 1)

    def test_dns_only_failure_counts_as_down_and_is_labelled(self):
        self.probe.dns = False
        self.run_for(120)
        self.probe.tcp = False
        self.run_for(60)
        records = [json.loads(line) for line in (self.dir / "events.jsonl").read_text().splitlines()]
        self.assertEqual([r["event"] for r in records], ["down", "probes_changed"])
        self.assertEqual(records[0]["probes"], {"dns": False, "tcp": True})
        self.assertEqual(records[1]["probes"], {"dns": False, "tcp": False})

    def test_login_hash_matches_router_ui(self):
        # The router UI: paswordAlgorithmsCookie(paswordAlgorithmsCookie(pw) + sault), SHA-256 as upper-case hex.
        inner = hashlib.sha256(b"pw").hexdigest().upper()
        expected = hashlib.sha256((inner + "SALT").encode()).hexdigest().upper()
        self.assertEqual(ww.sha(ww.sha("pw") + "SALT"), expected)

    def test_dns_probe_rejects_garbage(self):
        self.assertFalse(ww.dns_ok("https://192.0.2.1/dns-query", timeout=0.2))  # TEST-NET, never answers
        self.assertFalse(ww.dns_ok("tls://192.0.2.1", timeout=0.2))


if __name__ == "__main__":
    unittest.main()
