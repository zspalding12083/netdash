import http.client
import http.server
import json
import os
import tempfile
import threading
import unittest
import urllib.parse

from netdash import auth, modem, pfsense, server, unifi
from netdash.store import Store

PW = "correct horse battery"


class AuthTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.store = Store(self.path)
        self.auth = auth.Auth(self.store, {"NETDASH_AUTH": "on"})
        self.auth.set_password("alice", PW)

    def tearDown(self):
        os.unlink(self.path)

    def test_password_rules(self):
        with self.assertRaises(ValueError):
            self.auth.set_password("bob", "short")
        with self.assertRaises(ValueError):
            self.auth.set_password("longusername", "LongUserName")

    def test_login_session_logout(self):
        self.assertTrue(self.auth.enabled)
        self.assertFalse(auth.Auth(self.store, {}).enabled)        # off unless asked for
        token, why = self.auth.login("alice", PW, "10.0.0.5")
        self.assertIsNotNone(token)
        self.assertEqual(self.auth.user_for(token), "alice")
        # only the hash of the token is stored
        self.assertIsNone(self.store.db.execute("SELECT 1 FROM sessions WHERE token_hash = ?", (token,)).fetchone())
        self.auth.logout(token)
        self.assertIsNone(self.auth.user_for(token))
        self.assertIsNone(self.auth.user_for(None))

    def test_wrong_password_and_unknown_user(self):
        self.assertEqual(self.auth.login("alice", "wrong password", "10.0.0.5"), (None, "bad"))
        self.assertEqual(self.auth.login("mallory", PW, "10.0.0.6"), (None, "bad"))

    def test_lockout_per_address_and_per_user(self):
        for _ in range(auth.MAX_FAILURES):
            self.auth.login("alice", "nope nope nope", "10.0.0.7")
        # even the right password is refused while locked, from that address ...
        self.assertEqual(self.auth.login("alice", PW, "10.0.0.7"), (None, "locked"))
        # ... and for that user name from anywhere
        self.assertEqual(self.auth.login("alice", PW, "10.0.0.8"), (None, "locked"))

    def test_new_password_and_delete_end_sessions(self):
        t1, _ = self.auth.login("alice", PW, "10.0.0.5")
        self.auth.set_password("alice", PW + " 2")
        self.assertIsNone(self.auth.user_for(t1))
        t2, _ = self.auth.login("alice", PW + " 2", "10.0.0.5")
        self.assertTrue(self.store.delete_user("alice"))
        self.assertIsNone(self.auth.user_for(t2))


class HttpTest(unittest.TestCase):
    """The real handler on a local port: redirects, 401s, the login form, cookies, CSRF."""

    @classmethod
    def setUpClass(cls):
        fd, cls.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        env = {"NETDASH_AUTH": "on", "NETDASH_SITE_NAME": "Branch Office"}
        cls.store = Store(cls.path)
        cls.app = server.App(cls.store, wifi=unifi.UniFi({}), modem_db=modem.ModemDB({"NETDASH_MODEM_DB": "none"}),
                             router=pfsense.PfSense({}), env=env)
        cls.app.auth.set_password("alice", PW)
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(cls.app))
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        os.unlink(cls.path)

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": f"127.0.0.1:{self.port}", **(headers or {})}
        if body is not None:
            body = urllib.parse.urlencode(body)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, body, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def login(self, user="alice", pw=PW):
        r, _ = self.req("POST", "/login", {"user": user, "password": pw})
        cookie = r.getheader("Set-Cookie") or ""
        return r, cookie.split(";")[0]

    def test_logged_out(self):
        r, _ = self.req("GET", "/")
        self.assertEqual((r.status, r.getheader("Location")), (303, "/login"))
        r, _ = self.req("GET", "/api/summary")
        self.assertEqual(r.status, 401)
        r, body = self.req("GET", "/login")
        self.assertEqual(r.status, 200)
        self.assertIn(b"Sign in", body)
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
        r, body = self.req("GET", "/api/site")                     # public: the login page shows the name
        self.assertEqual(json.loads(body), {"site": "Branch Office", "auth": True, "logo": None})
        r, body = self.req("GET", "/brand/brand.css")              # no brand folder: an empty stylesheet ...
        self.assertEqual((r.status, body, r.getheader("Content-Type")), (200, b"", "text/css"))
        r, _ = self.req("GET", "/brand/favicon.ico")               # ... and nothing else
        self.assertEqual(r.status, 404)

    def test_login_flow(self):
        r, cookie = self.login()
        self.assertEqual((r.status, r.getheader("Location")), (303, "/"))
        self.assertIn("HttpOnly", r.getheader("Set-Cookie"))
        self.assertIn("SameSite=Strict", r.getheader("Set-Cookie"))
        r, body = self.req("GET", "/api/summary", headers={"Cookie": cookie})
        s = json.loads(body)
        self.assertEqual((r.status, s["user"], s["site"], s["internet"]), (200, "alice", "Branch Office", {"modem": False}))
        r, _ = self.req("GET", "/login", headers={"Cookie": cookie})  # already in: back to the dashboard
        self.assertEqual(r.getheader("Location"), "/")
        r, _ = self.req("POST", "/logout", {}, headers={"Cookie": cookie})
        self.assertEqual(r.getheader("Location"), "/login")
        r, _ = self.req("GET", "/api/summary", headers={"Cookie": cookie})
        self.assertEqual(r.status, 401)

    def test_bad_login_and_cross_site_post(self):
        r, cookie = self.login(pw="not the password")
        self.assertEqual((r.getheader("Location"), cookie), ("/login?e=bad", ""))
        r, _ = self.req("POST", "/login", {"user": "alice", "password": PW}, headers={"Origin": "http://evil.example"})
        self.assertEqual(r.status, 403)

    def test_static_paths_cannot_escape(self):
        _, cookie = self.login()
        r, _ = self.req("GET", "/../store.py", headers={"Cookie": cookie})
        self.assertEqual(r.status, 404)
        r, _ = self.req("GET", "/brand/../store.py")
        self.assertEqual(r.status, 404)

    def test_brand_folder(self):
        with tempfile.TemporaryDirectory() as d:
            for n, data in (("brand.css", b":root { --s1: #0081b5; }"), ("logo.png", b"\x89PNG")):
                with open(os.path.join(d, n), "wb") as f:
                    f.write(data)
            self.app.brand = d
            try:
                r, body = self.req("GET", "/api/site")             # logged out: the sign-in page shows the logo too
                self.assertEqual(json.loads(body)["logo"], "/brand/logo.png")
                r, body = self.req("GET", "/brand/brand.css")
                self.assertEqual((r.status, body), (200, b":root { --s1: #0081b5; }"))
                r, _ = self.req("GET", "/brand/logo.png")
                self.assertEqual((r.status, r.getheader("Content-Type")), (200, "image/png"))
                r, _ = self.req("GET", "/brand/index.html")        # only the brand folder, never static/
                self.assertEqual(r.status, 404)
            finally:
                self.app.brand = None


class NoModemTest(unittest.TestCase):
    def test_modem_configuration(self):
        self.assertFalse(modem.ModemDB({"NETDASH_MODEM_DB": "none"}).configured)
        missing = modem.ModemDB({"NETDASH_MODEM_DB": "/nonexistent/modem.db"})
        self.assertTrue(missing.configured)           # asked for, so a missing file is an error ...
        self.assertFalse(missing.enabled)             # ... not silently ignored

    def test_gateway_outages(self):
        rows = [{"ts": f"2026-10-19T10:0{i}:00", "name": n, "status": st, "loss_pct": loss}
                for i, (n, st, loss) in enumerate([("WAN1", "online", 0), ("WAN1", "down", 100), ("WAN2", "online", 60),
                                                   ("WAN1", "online", 0), ("WAN2", "online", 70)])]
        o = server.gateway_outages(rows)
        self.assertEqual([(x["kinds"], x["start"], x["end"], x["ongoing"]) for x in o],
                         [(["WAN1"], rows[1]["ts"], rows[1]["ts"], False),
                          (["WAN2"], rows[2]["ts"], rows[4]["ts"], True)])

    def test_wan_detection(self):
        i = {x["id"]: x for x in pfsense.parse_interfaces([
            {"name": "wan", "descr": "WAN", "hwif": "igb0", "status": "up", "gateway": "203.0.113.1"},
            {"name": "opt2", "descr": "WAN2", "hwif": "igb3", "status": "up", "gateway": "198.51.100.1"},
            {"name": "lan", "descr": "LAN", "hwif": "igb1", "status": "up", "gateway": None}])}
        self.assertEqual((i["wan"]["wan"], i["opt2"]["wan"], i["lan"]["wan"]), (True, True, False))


if __name__ == "__main__":
    unittest.main()
