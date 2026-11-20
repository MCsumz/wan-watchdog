#!/bin/sh
# Installs the WAN watchdog. Run with sudo from this folder on the Linux machine that should watch
# the router. Asks for the router admin password once (not echoed), stores it root-only, checks the
# login, and starts the service. If the login check fails, the watchdog runs in log-only mode.
#
# A router other than https://192.168.0.1: create /etc/wan-watchdog/config.json first, for example
#   {"router": "192.168.8.1"}
# The installer keeps every setting in that file and only sets "auto_reboot".
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
cd "$here"
sha256sum -c SHA256SUMS

install -d -o root -g root -m 0755 /opt/wan-watchdog
install -o root -g root -m 0755 wan_watchdog.py /opt/wan-watchdog/wan_watchdog.py
install -o root -g root -m 0644 wan-watchdog.service /etc/systemd/system/wan-watchdog.service
install -d -o root -g root -m 0700 /etc/wan-watchdog

config=/etc/wan-watchdog/config.json
router=$(/usr/bin/python3 -B -c 'import sys
sys.path.insert(0, "/opt/wan-watchdog")
from wan_watchdog import load_config
print(load_config(sys.argv[1])["router"])' "$config")

pw_file=/etc/wan-watchdog/router-password
if [ ! -s "$pw_file" ]; then
    printf 'Router admin password (https://%s): ' "$router"
    stty -echo
    IFS= read -r pw
    stty echo
    printf '\n'
    old_umask=$(umask); umask 077
    printf '%s' "$pw" > "$pw_file"
    umask "$old_umask"
    unset pw
fi
chown root:root "$pw_file"; chmod 0600 "$pw_file"

set_auto_reboot() {
    /usr/bin/python3 -B -c 'import sys, json
path, value = sys.argv[1], sys.argv[2] == "true"
try:
    with open(path) as stream:
        config = json.load(stream)
except (OSError, ValueError):
    config = {}
config = config if isinstance(config, dict) else {}
config["auto_reboot"] = value
with open(path, "w") as stream:
    stream.write(json.dumps(config, indent=2) + "\n")' "$config" "$1"
    chmod 0644 "$config"
}

if /usr/bin/python3 -B /opt/wan-watchdog/wan_watchdog.py --check-login; then
    set_auto_reboot true
    mode="auto-reboot ON"
else
    set_auto_reboot false
    rm -f "$pw_file"
    mode="LOG-ONLY (router login failed; run this installer again to retry the password)"
fi

systemctl daemon-reload
systemctl enable wan-watchdog.service >/dev/null
systemctl restart wan-watchdog.service
sleep 3
systemctl is-active --quiet wan-watchdog.service
echo "WAN watchdog installed and running: $mode."
journalctl -u wan-watchdog.service -n 3 --no-pager -o cat
