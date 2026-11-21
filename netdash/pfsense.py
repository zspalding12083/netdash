"""pfSense Plus client (pfrest REST API package, v2), stdlib only.

The router is a Netgate 3100 (32-bit ARM): pfrest warns it's unsupported there,
but the read endpoints used here work. Its interface byte counters are 32-bit
and wrap about every 100 s at full download speed, so they're polled often and
differenced modulo 2**32.

Settings (/etc/netdash.env):
    NETDASH_PFSENSE_URL   e.g. https://10.0.0.1:8443
    NETDASH_PFSENSE_KEY   API key of the read-only "netdash" user
    NETDASH_PFSENSE_FINGERPRINT / _CA / _TLS_VERIFY   certificate checking, see tlsverify.py
"""
import datetime as dt
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from . import tlsverify

WRAP = 2 ** 32
MONTHS = {m: i for i, m in enumerate(("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec").split(), 1)}


class PfSense:
    def __init__(self, env=os.environ):
        self.url = (env.get("NETDASH_PFSENSE_URL") or "").rstrip("/")
        self.key = env.get("NETDASH_PFSENSE_KEY")
        # pfSense's web GUI certificate is usually self-signed: pin it (tlsverify.py).
        https, self.tls_mode = tlsverify.https_handler(env, "PFSENSE", "pfSense")
        self.opener = urllib.request.build_opener(https)

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.key and self.key != "None")

    def get(self, path, timeout=30, **query):
        """GET /api/v2/<path> -> the "data" field."""
        url = f"{self.url}/api/v2/{path}" + (f"?{urllib.parse.urlencode(query)}" if query else "")
        req = urllib.request.Request(url, headers={"X-API-Key": self.key, "Accept": "application/json"})
        try:
            r = self.opener.open(req, timeout=timeout)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError as e:
            raise tlsverify.explain(e, "PFSENSE") from e
        with r:
            return json.load(r)["data"]

    def interfaces(self):
        return parse_interfaces(self.get("status/interfaces"))

    def gateways(self):
        return parse_gateways(self.get("status/gateways"))

    def system(self):
        return parse_system(self.get("status/system"))

    def leases(self, interfaces):
        return parse_leases(self.get("status/dhcp_server/leases"), interfaces)

    def arp(self):
        """{ip: (mac, interface description)} from pfSense's ARP table."""
        return {a["ip_address"]: ((a.get("mac_address") or "").lower(), a.get("interface"))
                for a in self.get("diagnostics/arp_table") if a.get("ip_address")}

    def rules(self):
        """{tracker id: rule description}. Needs the api-v2-firewall-rules-get privilege."""
        return {str(r.get("tracker")): r.get("descr") or "" for r in self.get("firewall/rules") if r.get("tracker")}

    def firewall_log(self, limit=1000, now=None):
        """The newest `limit` filterlog entries, parsed, oldest first."""
        return [e for e in (parse_filterlog(r.get("text", ""), now) for r in self.get("status/logs/firewall", limit=limit))
                if e]


def parse_interfaces(raw):
    out = []
    for i in raw:
        net = None
        if i.get("ipaddr") and i.get("subnet"):
            try:
                net = str(ipaddress.ip_interface(f"{i['ipaddr']}/{i['subnet']}").network)
            except ValueError:
                pass
        hwif = i.get("hwif") or ""
        out.append({
            "id": i.get("name"),                  # wan, lan, opt3 ... (pfSense's internal id)
            "name": i.get("descr") or i.get("name"),
            "hwif": hwif,
            "vlan": int(hwif.rsplit(".", 1)[1]) if "." in hwif and hwif.rsplit(".", 1)[1].isdigit() else None,
            "up": i.get("status") == "up",
            # internet-facing: has an upstream gateway (multi-WAN: wan, optN ...)
            "wan": bool(i.get("gateway")) or i.get("name") == "wan",
            "ip": i.get("ipaddr"),
            "network": net,
            "media": i.get("media"),
            # 32-bit counters, reported signed; store them unsigned
            "in_bytes": (i.get("inbytes") or 0) % WRAP,
            "out_bytes": (i.get("outbytes") or 0) % WRAP,
            "errors": (i.get("inerrs") or 0) + (i.get("outerrs") or 0),
        })
    return out


def rates(prev, cur, seconds):
    """{iface id: (in_bps, out_bps)} from two interface snapshots taken `seconds`
    apart. Deltas are taken modulo 2**32, which is right as long as fewer than
    4 GiB passed between snapshots."""
    if not prev or seconds <= 0:
        return {}
    before = {i["id"]: i for i in prev}
    out = {}
    for i in cur:
        p = before.get(i["id"])
        if p:
            out[i["id"]] = (((i["in_bytes"] - p["in_bytes"]) % WRAP) * 8 / seconds,
                            ((i["out_bytes"] - p["out_bytes"]) % WRAP) * 8 / seconds)
    return out


def parse_gateways(raw):
    return [{
        "name": g.get("name"),
        "monitor_ip": g.get("monitorip"),
        "src_ip": g.get("srcip"),
        "delay_ms": _f(g.get("delay")),
        "stddev_ms": _f(g.get("stddev")),
        "loss_pct": _f(g.get("loss")),
        "status": g.get("status"),               # online / down / ...
        "substatus": g.get("substatus"),         # none / highloss / highdelay ...
    } for g in raw]


def parse_system(raw):
    return {
        "platform": raw.get("platform"),
        "uptime": raw.get("uptime"),
        "cpu_pct": _f(raw.get("cpu_usage")),
        "mem_pct": _f(raw.get("mem_usage")),
        "disk_pct": _f(raw.get("disk_usage")),
        "temp_c": _f(raw.get("temp_c")),
        "temp_f": _f(raw.get("temp_f")),
        "load": raw.get("cpu_load_avg"),
        "cpus": raw.get("cpu_count"),
    }


def parse_leases(raw, interfaces):
    """DHCP leases with the interface worked out from the IP when pfSense leaves
    it blank (it does for most dynamic leases)."""
    nets = [(ipaddress.ip_network(i["network"]), i) for i in interfaces if i["network"]]
    by_id = {i["id"]: i for i in interfaces}
    out = []
    for l in raw:
        iface = by_id.get(l.get("if"))
        if not iface and l.get("ip"):
            try:
                ip = ipaddress.ip_address(l["ip"])
                iface = next((i for n, i in nets if ip in n), None)
            except ValueError:
                pass
        out.append({
            "ip": l.get("ip"),
            "mac": (l.get("mac") or "").lower(),
            "hostname": l.get("hostname") or None,
            "descr": l.get("descr") or None,
            "iface": iface["name"] if iface else None,
            "static": l.get("active_status") == "static",
            "online": l.get("online_status") == "active/online",
            "ends": l.get("ends") or None,
        })
    return out


def parse_filterlog(text, now=None):
    """One syslog line from pfSense's filterlog -> dict, or None for other lines.
    Format: https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html"""
    try:
        head, csv = text.split(" filterlog", 1)
        csv = csv.split(": ", 1)[1]
    except (ValueError, IndexError):
        return None
    f = csv.split(",")
    if len(f) < 9:
        return None
    now = now or dt.datetime.now()
    try:
        mon, day, hms = head.split()[:3]
        h, m, s = (int(x) for x in hms.split(":"))
        ts = dt.datetime(now.year, MONTHS[mon], int(day), h, m, s)
        if ts > now + dt.timedelta(days=1):   # December's lines read in January
            ts = ts.replace(year=now.year - 1)
    except (ValueError, KeyError):
        return None
    e = {"ts": ts.isoformat(), "rule": f[3], "hwif": f[4], "action": f[6], "dir": f[7], "ipver": f[8],
         "proto": None, "src": None, "dst": None, "sport": None, "dport": None, "tcpflags": None}
    if f[8] == "4" and len(f) > 19:
        e.update(proto=f[16].lower(), src=f[18], dst=f[19])
        if e["proto"] in ("tcp", "udp") and len(f) > 21:
            e.update(sport=_i(f[20]), dport=_i(f[21]))
        if e["proto"] == "tcp" and len(f) > 23:
            e["tcpflags"] = f[23] or None
    elif f[8] == "6" and len(f) > 16:
        e.update(proto=f[12].lower(), src=f[15], dst=f[16])
        if e["proto"] in ("tcp", "udp") and len(f) > 18:
            e.update(sport=_i(f[17]), dport=_i(f[18]))
        if e["proto"] == "tcp" and len(f) > 20:
            e["tcpflags"] = f[20] or None
    return e


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _i(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
