"""netdash's own SQLite: Wi-Fi history (UniFi doesn't keep it), every client
seen, router history, firewall events, per-device traffic, and dashboard users.
Modem data (home only) stays in modem_check's database.

Retention (/etc/netdash.env):
    NETDASH_KEEP_DAYS        samples (Wi-Fi, APs, interfaces, router, gateways); default 60
    NETDASH_FW_KEEP_DAYS     firewall events; default 14
    NETDASH_USAGE_KEEP_DAYS  per-device hourly traffic, and clients not seen for that long; default 400
"""
import datetime as dt
import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS wifi_samples (    -- each wireless client, every SAMPLE_EVERY
    ts         TEXT NOT NULL,                -- local time, ISO 8601
    mac        TEXT NOT NULL,
    ap_mac     TEXT, essid TEXT, band TEXT, channel INTEGER,
    signal_dbm INTEGER, tx_rate_mbps INTEGER, rx_rate_mbps INTEGER, satisfaction INTEGER
);
CREATE INDEX IF NOT EXISTS wifi_samples_ts ON wifi_samples(ts);
CREATE INDEX IF NOT EXISTS wifi_samples_mac ON wifi_samples(mac, ts);
CREATE TABLE IF NOT EXISTS ap_samples (      -- each AP radio, every SAMPLE_EVERY
    ts           TEXT NOT NULL,
    ap_mac       TEXT NOT NULL,
    radio        TEXT, channel INTEGER, clients INTEGER, util_pct INTEGER, satisfaction INTEGER
);
CREATE INDEX IF NOT EXISTS ap_samples_ts ON ap_samples(ts);
CREATE TABLE IF NOT EXISTS clients (         -- every client UniFi has shown us
    mac        TEXT PRIMARY KEY,
    name       TEXT, hostname TEXT, ip TEXT, network TEXT, wired INTEGER,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    last_ap    TEXT, last_essid TEXT, last_signal INTEGER
);
CREATE TABLE IF NOT EXISTS devices (         -- APs and switches, for names in history
    mac  TEXT PRIMARY KEY,
    name TEXT, type TEXT, model TEXT
);
CREATE TABLE IF NOT EXISTS host_usage (      -- bytes per client per hour, from UniFi's counters
    hour  TEXT NOT NULL,                     -- local time, 'YYYY-MM-DDTHH'
    mac   TEXT NOT NULL,
    down  INTEGER NOT NULL DEFAULT 0,        -- toward the client
    up    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, mac)
);
CREATE TABLE IF NOT EXISTS if_samples (      -- pfSense interface throughput, every pfSense poll
    ts      TEXT NOT NULL,
    iface   TEXT NOT NULL,                   -- pfSense description: WAN, LAN, IOT ...
    in_bps  REAL, out_bps REAL               -- as seen by the router: on WAN, in = download
);
CREATE INDEX IF NOT EXISTS if_samples_ts ON if_samples(ts);
CREATE TABLE IF NOT EXISTS router_samples (  -- pfSense health and WAN gateway monitor
    ts       TEXT PRIMARY KEY,
    cpu_pct  REAL, mem_pct REAL, temp_c REAL,
    gw_delay_ms REAL, gw_loss_pct REAL, gw_status TEXT
);
CREATE TABLE IF NOT EXISTS fw_events (       -- pfSense firewall log (filterlog lines)
    ts     TEXT NOT NULL,
    iface  TEXT, action TEXT, dir TEXT, ipver TEXT, proto TEXT,
    src    TEXT, dst TEXT, sport INTEGER, dport INTEGER, rule TEXT,
    tcpflags TEXT,
    what   TEXT,                             -- plain-language label (ident.describe)
    noise  INTEGER                           -- 1 = routine (discovery chatter, closed-connection leftovers)
);
CREATE INDEX IF NOT EXISTS fw_events_ts ON fw_events(ts);
CREATE TABLE IF NOT EXISTS gw_samples (      -- every pfSense gateway (multi-WAN), every pfSense poll
    ts       TEXT NOT NULL,
    name     TEXT NOT NULL,
    delay_ms REAL, loss_pct REAL, status TEXT
);
CREATE INDEX IF NOT EXISTS gw_samples_ts ON gw_samples(ts);
CREATE TABLE IF NOT EXISTS users (           -- dashboard logins (auth.py); managed with `netdash user`
    name       TEXT PRIMARY KEY,
    salt       BLOB NOT NULL,
    iterations INTEGER NOT NULL,
    hash       BLOB NOT NULL,
    created    TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,             -- sha256 of the cookie value; the cookie itself isn't stored
    user       TEXT NOT NULL,
    created    TEXT NOT NULL,
    expires    TEXT NOT NULL,
    ip         TEXT
);
-- log fetches overlap; this skips lines already stored (ICMP has no ports, and NULLs never match)
CREATE UNIQUE INDEX IF NOT EXISTS fw_events_once ON fw_events(ts, iface, action, ifnull(src, ''), ifnull(dst, ''),
    ifnull(sport, -1), ifnull(dport, -1), ifnull(proto, ''));
"""


def _now():
    return dt.datetime.now().isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str, env=os.environ):
        self.keep = dt.timedelta(days=float(env.get("NETDASH_KEEP_DAYS") or 60))
        self.fw_keep = dt.timedelta(days=float(env.get("NETDASH_FW_KEEP_DAYS") or 14))
        self.usage_keep = dt.timedelta(days=float(env.get("NETDASH_USAGE_KEEP_DAYS") or 400))
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        cols = [r[1] for r in self.db.execute("PRAGMA table_info(fw_events)")]
        for c, t in (("tcpflags", "TEXT"), ("what", "TEXT"), ("noise", "INTEGER")):
            if c not in cols:
                self.db.execute(f"ALTER TABLE fw_events ADD COLUMN {c} {t}")
        self.lock = threading.Lock()

    def seen(self, clients, devices, ts=None) -> int:
        """Update the clients and devices tables; returns how many clients are new."""
        ts = ts or _now()
        with self.lock, self.db:
            known = {m for (m,) in self.db.execute("SELECT mac FROM clients")}
            for c in clients:
                self.db.execute(
                    "INSERT INTO clients (mac, name, hostname, ip, network, wired, first_seen, last_seen, "
                    "last_ap, last_essid, last_signal) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(mac) DO UPDATE SET name = excluded.name, "
                    "hostname = coalesce(excluded.hostname, hostname), ip = coalesce(excluded.ip, ip), "
                    "network = coalesce(excluded.network, network), wired = excluded.wired, "
                    "last_seen = excluded.last_seen, last_ap = excluded.last_ap, "
                    "last_essid = coalesce(excluded.last_essid, last_essid), "
                    "last_signal = coalesce(excluded.last_signal, last_signal)",
                    (c["mac"], c["name"], c["hostname"], c["ip"], c["network"], int(c["wired"]), ts, ts,
                     c["ap_name"], c["essid"], c["signal_dbm"]))
            self.db.executemany("INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?)",
                                [(d["mac"], d["name"], d["type"], d["model"]) for d in devices])
        return len({c["mac"] for c in clients} - known)

    def sample(self, clients, devices, ts=None) -> None:
        ts = ts or _now()
        with self.lock, self.db:
            self.db.executemany(
                "INSERT INTO wifi_samples VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(ts, c["mac"], c["ap_mac"], c["essid"], c["band"], c["channel"], c["signal_dbm"],
                  c["tx_rate_mbps"], c["rx_rate_mbps"], c["satisfaction"]) for c in clients if not c["wired"]])
            self.db.executemany(
                "INSERT INTO ap_samples VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(ts, d["mac"], r["radio"], r["channel"], r["clients"], r["util_pct"], r["satisfaction"])
                 for d in devices if d["type"] == "uap" for r in d["radios"]])
            cut = (dt.datetime.now() - self.keep).isoformat(timespec="seconds")
            self.db.execute("DELETE FROM wifi_samples WHERE ts < ?", (cut,))
            self.db.execute("DELETE FROM ap_samples WHERE ts < ?", (cut,))

    def add_router(self, rates: dict, names: dict, system: dict | None, gw: dict | None, ts=None,
                   gateways=()) -> None:
        """rates {iface id: (in_bps, out_bps)}, names {iface id: description}; gw is the first
        gateway (kept in router_samples), gateways all of them (gw_samples)."""
        ts = ts or _now()
        with self.lock, self.db:
            self.db.executemany("INSERT INTO if_samples VALUES (?, ?, ?, ?)",
                                [(ts, names.get(k, k), i, o) for k, (i, o) in rates.items()])
            if system or gw:
                system, gw = system or {}, gw or {}
                self.db.execute("INSERT OR REPLACE INTO router_samples VALUES (?, ?, ?, ?, ?, ?, ?)",
                                (ts, system.get("cpu_pct"), system.get("mem_pct"), system.get("temp_c"),
                                 gw.get("delay_ms"), gw.get("loss_pct"), gw.get("status")))
            self.db.executemany("INSERT INTO gw_samples VALUES (?, ?, ?, ?, ?)",
                                [(ts, g["name"], g.get("delay_ms"), g.get("loss_pct"), g.get("status"))
                                 for g in gateways])
            cut = (dt.datetime.now() - self.keep).isoformat(timespec="seconds")
            self.db.execute("DELETE FROM if_samples WHERE ts < ?", (cut,))
            self.db.execute("DELETE FROM router_samples WHERE ts < ?", (cut,))
            self.db.execute("DELETE FROM gw_samples WHERE ts < ?", (cut,))

    FW_KEYS = ("ts", "iface", "action", "dir", "ipver", "proto", "src", "dst", "sport", "dport", "rule",
               "tcpflags", "what", "noise")

    def add_fw(self, events) -> int:
        """Insert firewall log entries, skipping ones already stored; returns how many were new."""
        with self.lock, self.db:
            before = self.db.total_changes
            self.db.executemany(f"INSERT OR IGNORE INTO fw_events ({', '.join(self.FW_KEYS)}) "
                                f"VALUES ({', '.join('?' * len(self.FW_KEYS))})",
                                [tuple(e.get(k) for k in self.FW_KEYS) for e in events])
            new = self.db.total_changes - before
            self.db.execute("DELETE FROM fw_events WHERE ts < ?",
                            ((dt.datetime.now() - self.fw_keep).isoformat(timespec="seconds"),))
        return new

    def if_history(self, since: dt.datetime):
        rows = self.db.execute("SELECT ts, iface, in_bps, out_bps FROM if_samples WHERE ts >= ? ORDER BY ts",
                               (since.isoformat(timespec="seconds"),))
        return [dict(zip(("ts", "iface", "in_bps", "out_bps"), r)) for r in rows]

    def transfer(self, since: dt.datetime | None):
        """{iface: (bytes in, bytes out)} since `since` (None = everything stored), integrating
        each sample's rate over the time since the previous sample of that interface. Gaps
        over 2 minutes (netdash or pfSense down) aren't counted, since nothing measured them."""
        rows = self.db.execute(
            "SELECT iface, sum(in_bps * dt) / 8, sum(out_bps * dt) / 8, min(ts), count(*) FROM ("
            "  SELECT iface, ts, in_bps, out_bps, "
            "    strftime('%s', ts) - strftime('%s', lag(ts) OVER (PARTITION BY iface ORDER BY ts)) AS dt "
            "  FROM if_samples WHERE ts >= ?) WHERE dt > 0 AND dt <= 120 GROUP BY iface",
            ((since.isoformat(timespec="seconds") if since else ""),))
        return {r[0]: {"in_bytes": r[1], "out_bytes": r[2], "since": r[3], "samples": r[4]} for r in rows}

    def gw_history(self, since: dt.datetime):
        rows = self.db.execute("SELECT ts, name, delay_ms, loss_pct, status FROM gw_samples WHERE ts >= ? ORDER BY ts",
                               (since.isoformat(timespec="seconds"),))
        return [dict(zip(("ts", "name", "delay_ms", "loss_pct", "status"), r)) for r in rows]

    # ---- users and sessions (auth.py) --------------------------------------
    def get_user(self, name):
        r = self.db.execute("SELECT name, salt, iterations, hash FROM users WHERE name = ?", (name,)).fetchone()
        return dict(zip(("name", "salt", "iterations", "hash"), r)) if r else None

    def set_user(self, name, salt, iterations, pw_hash) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT INTO users (name, salt, iterations, hash, created) VALUES (?, ?, ?, ?, ?) "
                            "ON CONFLICT(name) DO UPDATE SET salt = excluded.salt, iterations = excluded.iterations, "
                            "hash = excluded.hash", (name, salt, iterations, pw_hash, _now()))
            self.db.execute("DELETE FROM sessions WHERE user = ?", (name,))   # a new password logs out everywhere

    def delete_user(self, name) -> bool:
        with self.lock, self.db:
            self.db.execute("DELETE FROM sessions WHERE user = ?", (name,))
            return self.db.execute("DELETE FROM users WHERE name = ?", (name,)).rowcount > 0

    def users(self):
        return [dict(zip(("name", "created", "last_login", "sessions"), r)) for r in self.db.execute(
            "SELECT u.name, u.created, u.last_login, (SELECT count(*) FROM sessions s WHERE s.user = u.name "
            "AND s.expires > ?) FROM users u ORDER BY u.name", (_now(),))]

    def add_session(self, token_hash, user, expires, ip) -> None:
        with self.lock, self.db:
            now = _now()
            self.db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)", (token_hash, user, now, expires, ip))
            self.db.execute("UPDATE users SET last_login = ? WHERE name = ?", (now, user))
            self.db.execute("DELETE FROM sessions WHERE expires < ?", (now,))

    def session_user(self, token_hash):
        r = self.db.execute("SELECT s.user FROM sessions s JOIN users u ON u.name = s.user "
                            "WHERE s.token_hash = ? AND s.expires > ?", (token_hash, _now())).fetchone()
        return r[0] if r else None

    def delete_session(self, token_hash) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def router_history(self, since: dt.datetime):
        keys = ("ts", "cpu_pct", "mem_pct", "temp_c", "gw_delay_ms", "gw_loss_pct", "gw_status")
        return [dict(zip(keys, r)) for r in self.db.execute(
            f"SELECT {', '.join(keys)} FROM router_samples WHERE ts >= ? ORDER BY ts",
            (since.isoformat(timespec="seconds"),))]

    def unlabelled_fw(self, limit=5000):
        return [dict(zip(("rowid",) + self.FW_KEYS, r)) for r in self.db.execute(
            f"SELECT rowid, {', '.join(self.FW_KEYS)} FROM fw_events WHERE what IS NULL LIMIT ?", (limit,))]

    def tcp_without_flags(self) -> int:
        """TCP rows still waiting for flags (rows already marked "not recorded" are done)."""
        return self.db.execute("SELECT count(*) FROM fw_events WHERE proto = 'tcp' AND tcpflags IS NULL "
                               "AND ifnull(what, '') NOT LIKE '%not recorded%'").fetchone()[0]

    def set_fw_flags(self, events) -> int:
        """Fill in tcpflags (and the label that depends on them) on rows stored before flags were recorded."""
        with self.lock, self.db:
            before = self.db.total_changes
            self.db.executemany(
                "UPDATE fw_events SET tcpflags = ?, what = ?, noise = ? WHERE tcpflags IS NULL AND proto = 'tcp' "
                "AND ts = ? AND iface = ? AND src = ? AND dst = ? AND sport = ? AND dport = ?",
                [(e["tcpflags"], e["what"], e["noise"], e["ts"], e["iface"], e["src"], e["dst"], e["sport"], e["dport"])
                 for e in events if e.get("tcpflags")])
            return self.db.total_changes - before

    def mark_flagless_tcp(self) -> None:
        with self.lock, self.db:
            self.db.execute("UPDATE fw_events SET what = what || ' (TCP flags not recorded)', noise = 0 "
                            "WHERE proto = 'tcp' AND tcpflags IS NULL AND what NOT LIKE '%not recorded%'")

    def label_fw(self, labels) -> None:
        """labels: [(what, noise, rowid)]"""
        with self.lock, self.db:
            self.db.executemany("UPDATE fw_events SET what = ?, noise = ? WHERE rowid = ?", labels)

    def fw_summary(self, since: dt.datetime, limit: int = 15, hide_noise: bool = False):
        """Blocks per interface, top blocked sources and the most recent blocks."""
        s = since.isoformat(timespec="seconds")
        quiet = " AND ifnull(noise, 0) = 0" if hide_noise else ""
        per_iface = [dict(zip(("iface", "blocks", "notable", "sources"), r)) for r in self.db.execute(
            "SELECT iface, count(*), sum(ifnull(noise, 0) = 0), count(DISTINCT src) FROM fw_events "
            "WHERE action = 'block' AND ts >= ? GROUP BY iface ORDER BY 2 DESC", (s,))]
        top = [dict(zip(("iface", "src", "proto", "dport", "blocks", "last", "dst", "what", "noise", "dsts"), r))
               for r in self.db.execute(
            "SELECT iface, src, proto, dport, count(*), max(ts), max(dst), max(what), min(ifnull(noise, 0)), "
            "count(DISTINCT dst) FROM fw_events WHERE action = 'block' AND ts >= ?" + quiet +
            " GROUP BY iface, src, proto, dport ORDER BY 5 DESC LIMIT ?", (s, limit))]
        recent = [dict(zip(self.FW_KEYS, r)) for r in self.db.execute(
            f"SELECT {', '.join(self.FW_KEYS)} FROM fw_events WHERE action = 'block'" + quiet +
            " ORDER BY ts DESC LIMIT ?", (limit * 3,))]
        buckets = [dict(zip(("ts", "iface", "blocks"), r)) for r in self.db.execute(
            "SELECT substr(ts, 1, 15) || '0:00', iface, count(*) FROM fw_events "
            "WHERE action = 'block' AND ts >= ? GROUP BY 1, 2 ORDER BY 1", (s,))]
        return {"per_iface": per_iface, "top": top, "recent": recent, "buckets": buckets}

    def add_usage(self, deltas, ts=None) -> None:
        """deltas: {mac: (down bytes, up bytes)} since the previous poll."""
        hour = (ts or _now())[:13]
        with self.lock, self.db:
            self.db.executemany(
                "INSERT INTO host_usage VALUES (?, ?, ?, ?) ON CONFLICT(hour, mac) DO UPDATE SET "
                "down = down + excluded.down, up = up + excluded.up",
                [(hour, m, int(d), int(u)) for m, (d, u) in deltas.items() if d or u])
            if hour.endswith("T00"):     # once a day is plenty (runs every poll during that hour; cheap)
                cut = (dt.datetime.now() - self.usage_keep).isoformat(timespec="seconds")
                self.db.execute("DELETE FROM host_usage WHERE hour < ?", (cut[:13],))
                self.db.execute("DELETE FROM clients WHERE last_seen < ?", (cut,))

    def top_hosts(self, since: dt.datetime | None, limit: int = 10):
        rows = self.db.execute(
            "SELECT h.mac, sum(h.down), sum(h.up), min(h.hour), c.name, c.ip, c.network, c.wired, c.last_ap "
            "FROM host_usage h LEFT JOIN clients c ON c.mac = h.mac WHERE h.hour >= ? "
            "GROUP BY h.mac ORDER BY sum(h.down) + sum(h.up) DESC LIMIT ?",
            ((since.isoformat(timespec="seconds")[:13] if since else ""), limit))
        keys = ("mac", "down", "up", "first_hour", "name", "ip", "network", "wired", "ap")
        out = [dict(zip(keys, r)) for r in rows]
        first = self.db.execute("SELECT min(hour) FROM host_usage").fetchone()[0]
        return {"hosts": out, "tracking_since": first}

    def known_clients(self):
        keys = ("mac", "name", "hostname", "ip", "network", "wired", "first_seen", "last_seen",
                "last_ap", "last_essid", "last_signal")
        return [dict(zip(keys, r)) for r in self.db.execute(
            f"SELECT {', '.join(keys)} FROM clients ORDER BY last_seen DESC")]

    def device_names(self) -> dict:
        return dict(self.db.execute("SELECT mac, name FROM devices"))

    def ap_history(self, since: dt.datetime):
        """[{ts, ap_mac, clients, util_pct (busiest radio)}] per sample time and AP."""
        rows = self.db.execute(
            "SELECT ts, ap_mac, sum(clients), max(util_pct) FROM ap_samples WHERE ts >= ? "
            "GROUP BY ts, ap_mac ORDER BY ts", (since.isoformat(timespec="seconds"),))
        return [dict(zip(("ts", "ap_mac", "clients", "util_pct"), r)) for r in rows]

    def weak_history(self, since: dt.datetime, weak_dbm: int):
        rows = self.db.execute(
            "SELECT ts, count(*), sum(signal_dbm < ?), min(signal_dbm) FROM wifi_samples WHERE ts >= ? "
            "GROUP BY ts ORDER BY ts", (weak_dbm, since.isoformat(timespec="seconds")))
        return [dict(zip(("ts", "clients", "weak", "worst_dbm"), r)) for r in rows]

    def client_history(self, mac: str, since: dt.datetime):
        keys = ("ts", "ap_mac", "essid", "band", "channel", "signal_dbm", "tx_rate_mbps", "rx_rate_mbps",
                "satisfaction")
        return [dict(zip(keys, r)) for r in self.db.execute(
            f"SELECT {', '.join(keys)} FROM wifi_samples WHERE mac = ? AND ts >= ? ORDER BY ts",
            (mac.lower(), since.isoformat(timespec="seconds")))]
