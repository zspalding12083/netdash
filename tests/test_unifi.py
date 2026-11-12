import datetime as dt
import http.server
import json
import os
import tempfile
import threading
import unittest

from netdash import unifi
from netdash.store import Store

DEVICES = [
    {"mac": "AA:00:00:00:00:01", "name": "Basement AP", "type": "uap", "model": "U6LR", "state": 1, "num_sta": 2,
     "uptime": 100, "system-stats": {"cpu": "3.1", "mem": "40"},
     "radio_table_stats": [{"radio": "ng", "channel": 6, "num_sta": 1, "cu_total": 35},
                           {"radio": "na", "channel": 36, "num_sta": 1, "cu_total": 12}]},
    {"mac": "aa:00:00:00:00:02", "name": "Main Switch", "type": "usw", "model": "US8", "state": 1},
]
CLIENTS = [
    {"mac": "11:11:11:11:11:11", "hostname": "oil-gauge", "ap_mac": "aa:00:00:00:00:01", "essid": "IoT",
     "radio": "ng", "channel": 6, "signal": -84, "tx_rate": 72000, "rx_rate": 65000, "is_wired": False},
    {"mac": "22:22:22:22:22:22", "name": "Laptop", "ap_mac": "aa:00:00:00:00:01", "essid": "Home",
     "radio": "na", "channel": 36, "signal": -55, "is_wired": False},
    {"mac": "33:33:33:33:33:33", "hostname": "pi", "sw_mac": "aa:00:00:00:00:02", "is_wired": True, "signal": 0,
     "tx_bytes": 0, "wired-tx_bytes": 53000, "wired-rx_bytes": 12000, "wired-tx_bytes-r": 100},
]


class UniFiTest(unittest.TestCase):
    def test_parse(self):
        devices = unifi.parse_devices(DEVICES)
        self.assertEqual(devices[0]["mac"], "aa:00:00:00:00:01")
        self.assertEqual(devices[0]["radios"][0]["band"], "2.4 GHz")
        self.assertEqual(devices[0]["cpu_pct"], 3.1)
        clients = unifi.parse_clients(CLIENTS, DEVICES)
        self.assertEqual([c["name"] for c in clients], ["oil-gauge", "Laptop", "pi"])  # weakest first, wired last
        self.assertEqual(clients[0]["ap_name"], "Basement AP")
        self.assertEqual(clients[0]["tx_rate_mbps"], 72)
        self.assertEqual(clients[2]["ap_name"], "Main Switch")
        self.assertIsNone(clients[2]["signal_dbm"])
        self.assertEqual((clients[2]["down_bytes"], clients[2]["up_bytes"], clients[2]["down_bps"]), (53000, 12000, 800))

    def test_store(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            st = Store(path)
            devices = unifi.parse_devices(DEVICES)
            clients = unifi.parse_clients(CLIENTS, DEVICES)
            self.assertEqual(st.seen(clients, devices), 3)
            self.assertEqual(st.seen(clients, devices), 0)
            st.sample(clients, devices)
            since = dt.datetime.now() - dt.timedelta(hours=1)
            self.assertEqual(st.weak_history(since, unifi.WEAK_DBM)[0]["weak"], 1)
            self.assertEqual(st.ap_history(since)[0]["clients"], 2)
            self.assertEqual(len(st.client_history("11:11:11:11:11:11", since)), 1)
            self.assertEqual(st.device_names()["aa:00:00:00:00:02"], "Main Switch")
        finally:
            os.unlink(path)


class FakeClassic(http.server.BaseHTTPRequestHandler):
    """The classic Network application's login and stat paths, no /proxy/network."""
    logins = []

    def _json(self, status, body, cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeClassic.logins.append(self.path)
        if self.path == "/api/login" and body["password"] == "right":
            return self._json(200, {"meta": {"rc": "ok"}, "data": []}, "unifises=abc; Path=/")
        self._json(400, {"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []})

    def do_GET(self):
        if "unifises=abc" not in (self.headers.get("Cookie") or ""):
            return self._json(401, {"meta": {"rc": "error", "msg": "api.err.LoginRequired"}, "data": []})
        data = {"/api/s/default/stat/device": DEVICES, "/api/s/default/stat/sta": CLIENTS}.get(self.path)
        self._json(200 if data else 404, {"meta": {"rc": "ok"}, "data": data or []})

    def log_message(self, *a):
        pass


class ClassicTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeClassic)
        cls.url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def env(self, pw):
        return {"NETDASH_UNIFI_URL": self.url, "NETDASH_UNIFI_USER": "netdash-ro", "NETDASH_UNIFI_PASS": pw,
                "NETDASH_UNIFI_KIND": "classic"}

    def test_login_and_snapshot(self):
        FakeClassic.logins = []
        u = unifi.UniFi(self.env("right"))
        clients, devices = u.snapshot()
        self.assertEqual((len(clients), len(devices)), (3, 2))
        self.assertEqual(FakeClassic.logins, ["/api/login"])    # the session cookie is reused for stat/sta
        u.jar.clear()                                            # session expired: one re-login on 401
        u.snapshot()
        self.assertEqual(FakeClassic.logins, ["/api/login", "/api/login"])

    def test_rejected_login_backs_off(self):
        FakeClassic.logins = []
        u = unifi.UniFi(self.env("wrong"))
        with self.assertRaises(Exception):
            u.snapshot()
        with self.assertRaisesRegex(PermissionError, "api.err.Invalid"):
            u.snapshot()
        self.assertEqual(len(FakeClassic.logins), 1)             # not retried until the backoff ends


class UsageTest(unittest.TestCase):
    def test_deltas_and_reset(self):
        from netdash.server import usage_deltas
        prev = {"a": (1000, 100), "b": (5000, 500)}
        clients = [{"mac": "a", "down_bytes": 1500, "up_bytes": 150},     # +500/+50
                   {"mac": "b", "down_bytes": 300, "up_bytes": 20},       # reconnected: counters restarted
                   {"mac": "c", "down_bytes": 9999, "up_bytes": 1}]       # new: no baseline
        self.assertEqual(usage_deltas(prev, clients), {"a": (500, 50), "b": (300, 20)})

    def test_store_top_hosts(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            st = Store(path)
            st.add_usage({"a": (500, 50), "b": (10, 0)}, ts="2026-10-18T01:05:00")
            st.add_usage({"a": (500, 50)}, ts="2026-10-18T01:06:00")
            top = st.top_hosts(None)["hosts"]
            self.assertEqual([(h["mac"], h["down"], h["up"]) for h in top], [("a", 1000, 100), ("b", 10, 0)])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
