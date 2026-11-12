import datetime as dt
import os
import sqlite3
import tempfile
import unittest

from netdash import modem

# modem_check's schema (the columns netdash reads)
SCHEMA = """
CREATE TABLE polls (id INTEGER PRIMARY KEY, ts TEXT, ok INTEGER, error TEXT, clock_offset_s INTEGER,
    uptime_s INTEGER, cm_status TEXT, cm_connected TEXT, network_access TEXT, docsis_mode TEXT,
    sw_version TEXT, hw_model TEXT);
CREATE TABLE downstream (poll_id INTEGER, kind TEXT, chid INTEGER, locked INTEGER, modulation TEXT,
    freq_hz INTEGER, power_dbmv REAL, snr_db REAL, unerrored INTEGER, corrected INTEGER, uncorrectable INTEGER);
CREATE TABLE upstream (poll_id INTEGER, kind TEXT, chid INTEGER, locked INTEGER, modulation TEXT,
    freq_hz INTEGER, width_hz INTEGER, power_dbmv REAL);
CREATE TABLE events (id INTEGER PRIMARY KEY, time_raw TEXT, time TEXT, priority TEXT, text TEXT,
    first_seen_poll INTEGER, first_seen_ts TEXT);
CREATE TABLE pings (id INTEGER PRIMARY KEY, ts TEXT, target TEXT, sent INTEGER, received INTEGER,
    loss_pct REAL, rtt_min REAL, rtt_avg REAL, rtt_max REAL, error TEXT, source TEXT);
CREATE TABLE speedtests (id INTEGER PRIMARY KEY, ts TEXT, server TEXT, down_mbps REAL, up_mbps REAL,
    latency_ms REAL, down_bytes INTEGER, up_bytes INTEGER, error TEXT, trigger TEXT);
CREATE TABLE notes (id INTEGER PRIMARY KEY, ts TEXT, text TEXT, added TEXT);
"""
NOW = dt.datetime(2026, 10, 17, 14, 0, tzinfo=dt.timezone(dt.timedelta(hours=-4)))


def ts(minutes_ago):
    return (NOW - dt.timedelta(minutes=minutes_ago)).isoformat(sep=" ", timespec="seconds")


class ModemTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = sqlite3.connect(self.path)
        db.executescript(SCHEMA)
        for pid, ago, corr, unc in ((1, 120, 100, 10), (2, 60, 150, 12), (3, 30, 20, 1)):  # poll 3: modem restarted
            db.execute("INSERT INTO polls VALUES (?, ?, 1, NULL, 7200, 3600, 'Operational', 'Connected', "
                       "'Allowed', 'DOCSIS 3.1', 'sw', 'SB8200v3')", (pid, ts(ago)))
            db.execute("INSERT INTO downstream VALUES (?, 'SC-QAM', 1, 1, '256QAM', 465000000, 4.0, 40.0, 0, ?, ?)",
                       (pid, corr, unc))
            db.execute("INSERT INTO downstream VALUES (?, 'SC-QAM', 2, 1, '256QAM', 471000000, 16.5, 30.0, 0, 0, 0)",
                       (pid,))
            db.execute("INSERT INTO upstream VALUES (?, 'ATDMA', 1, 1, '64QAM', 18200000, 6400000, 52.0)", (pid,))
        db.execute("INSERT INTO events VALUES (1, 'x', '2026-10-17 11:00:00', 'notice', "
                   "'GUI Login Status - Login Sucess;CM-MAC=aa', 3, 'x')")
        db.execute("INSERT INTO events VALUES (2, 'y', '2026-10-17 11:05:00', 'critical', "
                   "'No Ranging Response received - T3 time-out;CM-MAC=aa', 3, 'x')")
        # pings every 5 min; two failing ones in a row 50-45 min ago
        for i, ago in enumerate(range(90, -1, -5)):
            loss = 100.0 if ago in (50, 45) else 0.0
            db.execute("INSERT INTO pings (ts, sent, received, loss_pct, rtt_avg) VALUES (?, 10, ?, ?, 12)",
                       (ts(ago), 0 if loss else 10, loss))
        # upload fails at 55 and 40, passes at 70 and 25 (pings in between pass at 40) -> one outage
        for ago, up in ((70, 18.0), (55, 0.2), (40, None), (25, 17.0)):
            db.execute("INSERT INTO speedtests (ts, down_mbps, up_mbps) VALUES (?, 330, ?)", (ts(ago), up))
        db.commit()
        db.close()
        self.m = modem.ModemDB(path=self.path)

    def tearDown(self):
        os.unlink(self.path)

    def test_summary(self):
        s = self.m.summary(NOW)
        self.assertEqual(s["status"]["cm_status"], "Operational")
        self.assertEqual([c["flags"] for c in s["ds"]], [[], ["power", "SNR"]])
        self.assertEqual(s["us"][0]["flags"], ["power"])
        # 100->150 (+50), then a counter reset to 20 counts as 20
        self.assertEqual(s["errors_24h"]["corrected"], 70)
        self.assertEqual(s["errors_24h"]["uncorrectable"], 3)
        # login lines hidden, CM-MAC tail dropped, modem clock +2 h
        self.assertEqual(s["events"], [{"ts": "2026-10-17T13:05:00", "priority": "critical",
                                        "text": "No Ranging Response received - T3 time-out"}])
        self.assertIn("1 downstream channel out of range", s["problems"])

    def test_outages_merge_across_test_types(self):
        h = self.m.history(NOW - dt.timedelta(days=1))
        self.assertEqual(len(h["outages"]), 1)
        o = h["outages"][0]
        self.assertEqual((o["start"], o["end"]), (ts(55), ts(40)))
        self.assertEqual(o["kinds"], ["ping", "upload"])
        self.assertFalse(o["ongoing"])

    def test_ongoing_outage(self):
        o = modem.outages([], [{"ts": ts(10), "up_mbps": 0.1}])
        self.assertTrue(o[0]["ongoing"])


if __name__ == "__main__":
    unittest.main()
