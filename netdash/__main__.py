"""python3 -m netdash {serve,user,unifi,pfsense,modem,fingerprint} ..."""
import argparse
import getpass
import json
import logging
import os

from . import auth, modem, pfsense, server, tlsverify, unifi
from .store import Store


def main(argv=None):
    p = argparse.ArgumentParser(prog="netdash")
    p.add_argument("--db", default="netdash.db")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the poller and dashboard")
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--port", type=int, default=9180)
    u = sub.add_parser("user", help="manage dashboard logins (used when NETDASH_AUTH=on)")
    u.add_argument("action", choices=("add", "passwd", "del", "list"))
    u.add_argument("name", nargs="?")
    sub.add_parser("unifi", help="test the UniFi login; list APs and weak clients")
    sub.add_parser("modem", help="show the latest modem_check readings")
    sub.add_parser("pfsense", help="test the pfSense API key; show router health, gateways and interfaces")
    fp = sub.add_parser("fingerprint", help="show the certificate fingerprints to pin (default: the pfSense and "
                                            "UniFi URLs from the environment)")
    fp.add_argument("url", nargs="*")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if a.cmd == "serve":
        server.serve(Store(a.db), a.bind, a.port)
    elif a.cmd == "user":
        manage_users(Store(a.db), a.action, a.name)
    elif a.cmd == "unifi":
        u = unifi.UniFi()
        if not u.enabled:
            raise SystemExit("set NETDASH_UNIFI_USER and NETDASH_UNIFI_PASS (or NETDASH_UNIFI_API_KEY)")
        clients, devices = u.snapshot()
        print(f"{u.url}: {len(clients)} clients, {len(devices)} devices")
        for d in devices:
            radios = ", ".join(f"{r['band']} ch {r['channel']} ({r['clients']} clients, {r['util_pct']}% busy)"
                               for r in d["radios"])
            print(f"  {d['type']:4} {d['name']:<20} {'up' if d['online'] else 'DOWN':4} {radios}")
        weak = [c for c in clients if not c["wired"] and (c["signal_dbm"] or 0) < unifi.WEAK_DBM]
        print(f"weak clients (below {unifi.WEAK_DBM} dBm): {len(weak)}")
        for c in weak:
            print(f"  {c['signal_dbm']:>4} dBm  {c['name']:<28} via {c['ap_name']} ({c['essid']})")
    elif a.cmd == "pfsense":
        pf = pfsense.PfSense()
        if not pf.enabled:
            raise SystemExit("set NETDASH_PFSENSE_URL and NETDASH_PFSENSE_KEY")
        print(json.dumps(pf.system(), indent=1))
        for g in pf.gateways():
            print(f"gateway {g['name']}: {g['status']} ({g['substatus']}), {g['delay_ms']} ms, "
                  f"{g['loss_pct']}% loss, monitoring {g['monitor_ip']}")
        ifaces = pf.interfaces()
        leases = pf.leases(ifaces)
        for i in ifaces:
            n = sum(1 for l in leases if l["iface"] == i["name"])
            print(f"  {i['name']:<12} {i['hwif']:<12} {'up' if i['up'] else 'down':4} {i['network'] or '':<18} {n} leases")
        fw = pf.firewall_log(200)
        print(f"firewall log: {len(fw)} of the newest 200 lines parsed, "
              f"{sum(1 for e in fw if e['action'] == 'block')} blocks")
    elif a.cmd == "fingerprint":
        show_fingerprints(a.url)
    elif a.cmd == "modem":
        m = modem.ModemDB()
        if not m.enabled:
            raise SystemExit(f"modem_check database not found at {m.path} (set NETDASH_MODEM_DB)")
        s = m.summary()
        print(json.dumps({k: s[k] for k in ("status", "ping", "speed", "errors_24h", "problems")}, indent=1))


def show_fingerprints(urls):
    """Print NETDASH_*_FINGERPRINT lines for the certificates the servers present now.
    Compare each with the fingerprint the device itself shows before pinning it."""
    targets = [(None, u) for u in urls] or [
        (src, os.environ.get(f"NETDASH_{src}_URL") or default)
        for src, default in (("PFSENSE", None), ("UNIFI", "https://127.0.0.1:12443"))]
    for src, url in targets:
        if not url:
            continue
        try:
            fp = tlsverify.fetch_fingerprint(url)
        except (OSError, ValueError) as e:
            print(f"# {url}: {e}")
            continue
        print(f"# {url}")
        print(f"NETDASH_{src}_FINGERPRINT={fp}" if src else fp)
    print("# Check each against the device before trusting it: pfSense shows its certificate under\n"
          "# System > Certificates; a browser shows it in the padlock's certificate details.")


def manage_users(store, action, name):
    """Run as the service's user against the live database, e.g.
    sudo -u netdash python3 -m netdash --db /var/lib/netdash/netdash.db user add alice"""
    a = auth.Auth(store)
    if action == "list":
        users = store.users()
        for u in users:
            print(f"{u['name']:<20} created {u['created']}  last login {u['last_login'] or 'never'}  "
                  f"{u['sessions']} active session(s)")
        print(f"{len(users)} user(s)" + ("" if a.enabled else "; logins are off (set NETDASH_AUTH=on)"))
        return
    if not name:
        raise SystemExit(f"user {action} needs a name")
    exists = store.get_user(name) is not None
    if action == "del":
        print(f"deleted {name} and logged them out" if store.delete_user(name) else f"no user {name}")
        return
    if action == "add" and exists:
        raise SystemExit(f"{name} already exists; use: user passwd {name}")
    if action == "passwd" and not exists:
        raise SystemExit(f"no user {name}; use: user add {name}")
    pw = getpass.getpass(f"password for {name}: ")
    if pw != getpass.getpass("again: "):
        raise SystemExit("the two passwords differ; nothing changed")
    try:
        a.set_password(name, pw)
    except ValueError as e:
        raise SystemExit(f"not changed: {e}")
    print(f"{'added' if action == 'add' else 'changed password for'} {name}"
          + ("" if action == "add" else " (their sessions were logged out)"))


if __name__ == "__main__":
    main()
