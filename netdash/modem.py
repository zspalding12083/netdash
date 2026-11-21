"""Cable modem (ARRIS SB8200) data, read-only from modem_check's database
(https://github.com/zspalding12083/modem_check).

modem_check (~/modem_check on the Pi) polls the modem every 30 min and pings
every 5 min. netdash never logs in to the modem itself, so the modem's 40-entry
event log isn't filled with logins.

    NETDASH_MODEM_DB   default ~/modem_check/data/modem.db (of the user netdash runs as,
                       where modem_check's README installs it); "none" = no modem.
    NETDASH_MODEM_URL  where the page's modem_check link goes; default /modem/, modem_check's
                       dashboard served by netdash behind its login (NETDASH_MODEM_DASHBOARD, server.py)
                       Sites without a modem need nothing: the default path won't exist there.
"""
import datetime as dt
import os
import sqlite3

DEFAULT_DB = os.path.expanduser("~/modem_check/data/modem.db")
PROJECT_URL = "https://github.com/zspalding12083/modem_check"
# The same reference ranges modem_check's report uses (config.ini [ranges]).
RANGES = {"ds_power_min": -15, "ds_power_max": 15, "ds_snr_min": 33, "us_power_min": 35, "us_power_max": 51}
UPLOAD_OUTAGE_MBPS = 1.0
PING_OUTAGE_LOSS_PCT = 50
# Modem log lines that are just modem_check logging in.
NOISE = ("GUI Login Status",)


class ModemDB:
    def __init__(self, env=os.environ, path=None):
        setting = path or env.get("NETDASH_MODEM_DB")
        self.off = (setting or "").lower() == "none"
        self.explicit = bool(setting) and not self.off
        self.path = setting if self.explicit else DEFAULT_DB

    @property
    def configured(self) -> bool:
        """A modem is expected here: set explicitly, or the home default exists."""
        return not self.off and (self.explicit or os.path.exists(self.path))

    @property
    def enabled(self) -> bool:
        return self.configured and os.path.exists(self.path)

    def _db(self):
        db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def summary(self, now=None):
        """Latest modem status, channels (flagged against RANGES), last ping and
        speed test, codeword errors over the last 24 h, and recent modem log lines."""
        now = now or dt.datetime.now().astimezone()
        with self._db() as db:
            poll = db.execute("SELECT * FROM polls WHERE ok = 1 ORDER BY id DESC LIMIT 1").fetchone()
            last_try = db.execute("SELECT ts, ok, error FROM polls ORDER BY id DESC LIMIT 1").fetchone()
            ping = db.execute("SELECT * FROM pings ORDER BY id DESC LIMIT 1").fetchone()
            speed = db.execute("SELECT * FROM speedtests ORDER BY id DESC LIMIT 1").fetchone()
            ds = us = []
            errors_24h = None
            if poll:
                ds = [dict(r) for r in db.execute(
                    "SELECT kind, chid, locked, modulation, freq_hz, power_dbmv, snr_db, corrected, uncorrectable "
                    "FROM downstream WHERE poll_id = ? ORDER BY kind DESC, chid", (poll["id"],))]
                us = [dict(r) for r in db.execute(
                    "SELECT kind, chid, locked, modulation, freq_hz, width_hz, power_dbmv "
                    "FROM upstream WHERE poll_id = ? ORDER BY chid", (poll["id"],))]
                errors_24h = codeword_growth(db, poll, now - dt.timedelta(hours=24))
            events = recent_events(db, 15)
            note = db.execute("SELECT ts, text FROM notes ORDER BY ts DESC LIMIT 1").fetchone()
        for c in ds:
            c["flags"] = ds_flags(c)
        for c in us:
            c["flags"] = us_flags(c)
        out = {
            "db": self.path,
            "last_poll": dict(last_try) if last_try else None,
            "status": None, "ds": ds, "us": us, "errors_24h": errors_24h, "events": events,
            "ping": dict(ping) if ping else None,
            "speed": dict(speed) if speed else None,
            "note": dict(note) if note else None,
        }
        if poll:
            out["status"] = {k: poll[k] for k in ("ts", "cm_status", "cm_connected", "network_access",
                                                   "docsis_mode", "uptime_s", "hw_model", "sw_version")}
        out["problems"] = problems(out)
        return out

    def history(self, since: dt.datetime):
        """Time series for charts: pings, speed tests, and per-poll channel extremes."""
        s = since.isoformat(sep=" ", timespec="seconds")
        with self._db() as db:
            pings = [dict(r) for r in db.execute(
                "SELECT ts, loss_pct, rtt_avg, rtt_max, error FROM pings WHERE ts >= ? ORDER BY ts", (s,))]
            speeds = [dict(r) for r in db.execute(
                "SELECT ts, down_mbps, up_mbps, latency_ms, error FROM speedtests WHERE ts >= ? ORDER BY ts", (s,))]
            channels = [dict(r) for r in db.execute(
                "SELECT p.ts, min(d.snr_db) AS snr_min, min(d.power_dbmv) AS ds_power_min, "
                "max(d.power_dbmv) AS ds_power_max, sum(d.locked = 0) AS ds_unlocked, "
                "(SELECT max(u.power_dbmv) FROM upstream u WHERE u.poll_id = p.id) AS us_power_max, "
                "(SELECT sum(u.locked = 0) FROM upstream u WHERE u.poll_id = p.id) AS us_unlocked "
                "FROM polls p JOIN downstream d ON d.poll_id = p.id AND d.kind = 'SC-QAM' "
                "WHERE p.ok = 1 AND p.ts >= ? GROUP BY p.id ORDER BY p.ts", (s,))]
            notes = [dict(r) for r in db.execute("SELECT ts, text FROM notes WHERE ts >= ? ORDER BY ts", (s,))]
        return {"pings": pings, "speeds": speeds, "channels": channels, "notes": notes,
                "outages": outages(pings, speeds)}


def ds_flags(c):
    f = []
    if not c["locked"]:
        f.append("not locked")
    if c["power_dbmv"] is not None and not RANGES["ds_power_min"] <= c["power_dbmv"] <= RANGES["ds_power_max"]:
        f.append("power")
    if c["kind"] == "SC-QAM" and c["snr_db"] is not None and c["snr_db"] < RANGES["ds_snr_min"]:
        f.append("SNR")
    return f


def us_flags(c):
    f = []
    if not c["locked"]:
        f.append("not locked")
    if c["power_dbmv"] is not None and not RANGES["us_power_min"] <= c["power_dbmv"] <= RANGES["us_power_max"]:
        f.append("power")
    return f


def codeword_growth(db, poll, since):
    """Corrected/uncorrectable codewords added since `since`, summed over channels.
    Counters reset when the modem restarts, so a drop starts a new baseline."""
    s = since.isoformat(sep=" ", timespec="seconds")
    rows = db.execute(
        "SELECT p.id, p.ts, sum(d.corrected) AS corr, sum(d.uncorrectable) AS unc FROM polls p "
        "JOIN downstream d ON d.poll_id = p.id WHERE p.ok = 1 AND p.ts >= ? GROUP BY p.id ORDER BY p.ts",
        (s,)).fetchall()
    corr = unc = 0
    for a, b in zip(rows, rows[1:]):
        corr += b["corr"] - a["corr"] if b["corr"] >= a["corr"] else b["corr"]
        unc += b["unc"] - a["unc"] if b["unc"] >= a["unc"] else b["unc"]
    return {"since": rows[0]["ts"] if rows else None, "corrected": corr, "uncorrectable": unc,
            "polls": len(rows)}


def recent_events(db, limit):
    """Modem log lines, newest first, with the modem's clock converted to local time
    (the modem runs about 2 h behind; each poll records the difference)."""
    out = []
    for r in db.execute(
            "SELECT e.time, e.priority, e.text, p.clock_offset_s FROM events e "
            "LEFT JOIN polls p ON p.id = e.first_seen_poll ORDER BY e.time DESC LIMIT ?", (limit * 4,)):
        if r["text"].startswith(NOISE):
            continue
        local = r["time"]
        try:
            local = (dt.datetime.fromisoformat(r["time"]) + dt.timedelta(seconds=r["clock_offset_s"] or 0)).isoformat()
        except (TypeError, ValueError):
            pass
        out.append({"ts": local, "priority": r["priority"], "text": r["text"].split(";CM-MAC=")[0]})
        if len(out) == limit:
            break
    return out


MERGE_GAP = dt.timedelta(minutes=10)


def outages(pings, speeds):
    """Failing tests (ping losing PING_OUTAGE_LOSS_PCT or more, or upload below
    UPLOAD_OUTAGE_MBPS) as windows: runs of failures per test type (a passing
    test of the same type ends a run), then overlapping or close runs merged,
    as modem_check's report does. Upload-only outages leave ping passing, so
    pings must not split an upload run."""
    runs = []
    for tests, failed, kind in (
            (pings, lambda p: (p["loss_pct"] or 0) >= PING_OUTAGE_LOSS_PCT or p["error"], "ping"),
            (speeds, lambda s: s["up_mbps"] is None or s["up_mbps"] < UPLOAD_OUTAGE_MBPS, "upload")):
        cur = None
        for t in tests:
            if failed(t):
                cur = cur or {"start": t["ts"], "end": t["ts"], "tests": 0, "kinds": {kind}}
                cur["end"] = t["ts"]
                cur["tests"] += 1
            elif cur:
                runs.append(cur)
                cur = None
        if cur:
            cur["ongoing"] = True
            runs.append(cur)
    out = []
    for r in sorted(runs, key=lambda r: r["start"]):
        if out and _ts(r["start"]) - _ts(out[-1]["end"]) <= MERGE_GAP:
            o = out[-1]
            o["end"] = max(o["end"], r["end"])
            o["tests"] += r["tests"]
            o["kinds"] |= r["kinds"]
            o["ongoing"] = o.get("ongoing") or r.get("ongoing", False)
        else:
            out.append(r)
    for o in out:
        o["kinds"] = sorted(o["kinds"])
        o["ongoing"] = bool(o.get("ongoing"))
    return out


def _ts(s):
    return dt.datetime.fromisoformat(s)


def problems(s):
    """Short plain-language list of anything wrong right now."""
    p = []
    st = s["status"]
    if st and st["cm_status"] != "Operational":
        p.append(f"Modem status: {st['cm_status']}")
    if s["last_poll"] and not s["last_poll"]["ok"]:
        p.append(f"Last modem poll failed: {s['last_poll']['error']}")
    ping = s["ping"]
    if ping and ((ping["loss_pct"] or 0) >= PING_OUTAGE_LOSS_PCT or ping["error"]):
        p.append(f"Ping losing {ping['loss_pct']:.0f}%" if ping["loss_pct"] is not None else f"Ping failed: {ping['error']}")
    sp = s["speed"]
    if sp and (sp["up_mbps"] is None or sp["up_mbps"] < UPLOAD_OUTAGE_MBPS):
        p.append("Upload test failed" if sp["up_mbps"] is None else f"Upload only {sp['up_mbps']:.1f} Mbps")
    bad_ds = [c for c in s["ds"] if c["flags"]]
    if bad_ds:
        p.append(f"{len(bad_ds)} downstream channel{'s' * (len(bad_ds) > 1)} out of range")
    bad_us = [c for c in s["us"] if c["flags"]]
    if bad_us:
        p.append(f"{len(bad_us)} upstream channel{'s' * (len(bad_us) > 1)} out of range")
    return p
