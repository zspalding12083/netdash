"""Dashboard web server and the pollers, stdlib only.

Site settings (/etc/netdash.env):
    NETDASH_SITE_NAME    page title, e.g. "Branch Office"; default "Home network"
    NETDASH_TLS_CERT     serve HTTPS with this certificate (PEM) ...
    NETDASH_TLS_KEY      ... and key; strongly advised when NETDASH_AUTH is on
    NETDASH_BRAND_DIR    a folder served at /brand/: brand.css (loaded after the built-in
                         styles, so it can override the colour tokens), logo.svg or logo.png
                         (shown in the header; brand.css should give the header a background
                         it reads on), favicon.ico. Unset: the plain look
Logins: see auth.py. Modem (home only): see modem.py.
"""
import datetime as dt
import http.cookies
import http.server
import json
import logging
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse

from . import auth, ident, modem, pfsense, unifi

log = logging.getLogger("netdash")
STATIC = os.path.join(os.path.dirname(__file__), "static")
CTYPES = {"html": "text/html; charset=UTF-8", "js": "text/javascript", "css": "text/css", "svg": "image/svg+xml",
          "png": "image/png", "jpg": "image/jpeg", "ico": "image/x-icon", "woff2": "font/woff2"}
RANGES = {"day": 1, "week": 7, "month": 31, "all": 3650}
PF_RULES_EVERY = 1800    # firewall rule descriptions (tracker -> name), if the key may read them
POLL_EVERY = 60          # seconds between UniFi polls (the live view)
SAMPLE_EVERY = 300       # seconds between rows written to wifi_samples / ap_samples
PF_EVERY = 30            # pfSense interface counters: 32-bit, wrap in ~100 s at full speed
PF_SYSTEM_EVERY = 60     # status/system takes ~1.5 s on the Netgate 3100
PF_LEASES_EVERY = 300
PF_FW_EVERY = 120        # newest PF_FW_LIMIT log lines; ~4000 lines/hour here, so this overlaps
PF_FW_LIMIT = 1000
GW_BAD_LOSS = 50         # a gateway sample losing this % or more counts toward an outage (sites without a modem)
PUBLIC = {"/login", "/api/site"}   # reachable without logging in, as is /brand/ (the sign-in page uses it)
SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "same-origin"),   # "no-referrer" makes Chrome send Origin: null on form posts
    ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"),
]


class App:
    def __init__(self, store, wifi=None, modem_db=None, router=None, env=os.environ):
        self.store = store
        self.site = env.get("NETDASH_SITE_NAME") or "Home network"
        self.modem_url = env.get("NETDASH_MODEM_URL") or modem.PROJECT_URL
        self.brand = env.get("NETDASH_BRAND_DIR") or None
        self.auth = auth.Auth(store, env)
        self.unifi = wifi if wifi is not None else unifi.UniFi()
        self.modem = modem_db if modem_db is not None else modem.ModemDB()
        self.pf = router if router is not None else pfsense.PfSense()
        self.wifi = {"ts": None, "clients": [], "devices": [], "error": None}
        self.router = {"ts": None, "interfaces": [], "rates": {}, "gateways": [], "system": None,
                       "leases": [], "arp": {}, "error": None}
        self.namer = ident.Namer()
        self.rules = {}               # tracker -> description; stays empty without the privilege
        self._rules_allowed = True
        self._last_sample = 0.0
        self._counters = {}           # mac -> (down_bytes, up_bytes) at the previous UniFi poll
        self._pf_prev = None          # (monotonic time, interfaces) for rates
        self._pf_due = {"system": 0.0, "leases": 0.0, "fw": 0.0, "rules": 0.0}
        self.label_backlog()

    # ---- UniFi poller ------------------------------------------------------
    def poll_unifi(self):
        try:
            clients, devices = self.unifi.snapshot()
        except Exception as e:
            log.warning("UniFi poll failed: %s", e)
            self.wifi = {**self.wifi, "error": str(e)}
            return
        ts = dt.datetime.now().isoformat(timespec="seconds")
        new = self.store.seen(clients, devices, ts)
        self.store.add_usage(usage_deltas(self._counters, clients), ts)
        self._counters = {c["mac"]: (c["down_bytes"], c["up_bytes"]) for c in clients
                          if c["down_bytes"] is not None}
        if new and self.wifi["ts"]:
            log.info("%d new client%s seen", new, "s" * (new > 1))
        if time.monotonic() - self._last_sample >= SAMPLE_EVERY:
            self.store.sample(clients, devices, ts)
            self._last_sample = time.monotonic()
        self.wifi = {"ts": ts, "clients": clients, "devices": devices, "error": None}
        self.update_names()

    def update_names(self):
        r = self.router
        self.namer.update(r["interfaces"], r["leases"], r["arp"], self.wifi["clients"])

    def label(self, e):
        what, noise = ident.describe(e, self.namer.name(e["src"], lookup=False)["kind"],
                                     self.namer.name(e["dst"], lookup=False)["kind"])
        e["what"], e["noise"] = what, int(noise)
        return e

    def label_backlog(self):
        """Give a label to firewall rows stored before labelling existed."""
        while True:
            rows = self.store.unlabelled_fw()
            if not rows:
                return
            self.store.label_fw([(self.label(e)["what"], e["noise"], e["rowid"]) for e in rows])

    def run_poller(self):
        def loop():
            while True:
                self.poll_unifi()
                time.sleep(POLL_EVERY)
        threading.Thread(target=loop, daemon=True, name="unifi").start()

    # ---- pfSense poller ----------------------------------------------------
    def poll_pfsense(self):
        r = dict(self.router)
        try:
            now = time.monotonic()
            ifaces = self.pf.interfaces()
            prev = self._pf_prev
            r["rates"] = pfsense.rates(prev[1], ifaces, now - prev[0]) if prev else {}
            self._pf_prev = (now, ifaces)
            r["interfaces"], r["gateways"] = ifaces, self.pf.gateways()
            system = None
            if now >= self._pf_due["system"]:
                r["system"] = system = self.pf.system()
                self._pf_due["system"] = now + PF_SYSTEM_EVERY
            if now >= self._pf_due["leases"]:
                r["leases"] = self.pf.leases(ifaces)
                try:
                    r["arp"] = self.pf.arp()
                except urllib.error.HTTPError as e:
                    log.info("pfSense ARP table not readable (HTTP %s); add api-v2-diagnostics-arp-table-get", e.code)
                self._pf_due["leases"] = now + PF_LEASES_EVERY
            if self._rules_allowed and now >= self._pf_due["rules"]:
                try:
                    self.rules = self.pf.rules()
                except urllib.error.HTTPError as e:
                    self._rules_allowed = False
                    log.info("pfSense firewall rules not readable (HTTP %s); block reasons show tracker ids. "
                             "Add api-v2-firewall-rules-get to show rule names", e.code)
                self._pf_due["rules"] = now + PF_RULES_EVERY
            self.router = {**self.router, "interfaces": ifaces, "leases": r["leases"], "arp": r["arp"]}
            self.update_names()
            names = {i["id"]: i["name"] for i in ifaces}
            up = {i["id"] for i in ifaces if i["up"]}
            self.store.add_router({k: v for k, v in r["rates"].items() if k in up}, names, system,
                                  r["gateways"][0] if r["gateways"] else None, gateways=r["gateways"])
            if now >= self._pf_due["fw"]:
                by_hw = {i["hwif"]: i["name"] for i in ifaces}
                events = self.pf.firewall_log(PF_FW_LIMIT)
                for e in events:
                    e["iface"] = by_hw.get(e["hwif"], e["hwif"])
                    self.label(e)
                self.store.add_fw(events)
                self._pf_due["fw"] = now + PF_FW_EVERY
            r["ts"], r["error"] = dt.datetime.now().isoformat(timespec="seconds"), None
        except Exception as e:
            log.warning("pfSense poll failed: %s", e)
            r["error"] = str(e)
        self.router = r

    def backfill_tcp_flags(self):
        """Rows stored before TCP flags were recorded: recover the flags from pfSense's
        log (it holds a few hours), then mark whatever is older as unknown."""
        if not self.store.tcp_without_flags():
            return
        try:
            ifaces = self.pf.interfaces()
            by_hw = {i["hwif"]: i["name"] for i in ifaces}
            events = self.pf.firewall_log(limit=0, now=None)        # 0 = the whole log
            for e in events:
                e["iface"] = by_hw.get(e["hwif"], e["hwif"])
                self.label(e)
            n = self.store.set_fw_flags(events)
            self.store.mark_flagless_tcp()
            log.info("recovered TCP flags for %d stored firewall rows", n)
        except Exception as e:
            log.warning("could not backfill TCP flags: %s", e)

    def run_pf_poller(self):
        def loop():
            self.backfill_tcp_flags()
            while True:
                self.poll_pfsense()
                time.sleep(PF_EVERY)
        threading.Thread(target=loop, daemon=True, name="pfsense").start()

    def router_summary(self):
        r = self.router
        rates = r["rates"]
        ifaces = [{**i, "in_bps": rates.get(i["id"], (None, None))[0], "out_bps": rates.get(i["id"], (None, None))[1],
                   "leases": sum(1 for l in r["leases"] if l["iface"] == i["name"]),
                   "leases_online": sum(1 for l in r["leases"] if l["iface"] == i["name"] and l["online"])}
                  for i in r["interfaces"]]
        return {"enabled": self.pf.enabled, "ts": r["ts"], "error": r["error"], "interfaces": ifaces,
                "wans": [i["name"] for i in r["interfaces"] if i["wan"]],
                "gateways": r["gateways"], "system": r["system"]}

    # ---- API ---------------------------------------------------------------
    def wifi_summary(self):
        w = self.wifi
        wireless = [c for c in w["clients"] if not c["wired"]]
        per_ap = {}
        for c in wireless:
            per_ap[c["ap_mac"]] = per_ap.get(c["ap_mac"], 0) + 1
        return {
            "enabled": self.unifi.enabled, "ts": w["ts"], "error": w["error"],
            "weak_dbm": unifi.WEAK_DBM,
            "clients": w["clients"], "devices": w["devices"],
            "counts": {
                "clients": len(w["clients"]), "wireless": len(wireless),
                "weak": sum(1 for c in wireless if (c["signal_dbm"] or 0) < unifi.WEAK_DBM),
                "per_ap": per_ap,
                "aps_online": sum(1 for d in w["devices"] if d["type"] == "uap" and d["online"]),
                "aps": sum(1 for d in w["devices"] if d["type"] == "uap"),
            },
        }

    def brand_file(self, name):
        """Path of a file in the brand folder, or None."""
        fp = self.brand and os.path.join(self.brand, os.path.basename(name))
        return fp if fp and os.path.isfile(fp) else None

    def logo(self):
        return next((f"/brand/{n}" for n in ("logo.svg", "logo.png") if self.brand_file(n)), None)

    def api(self, path, query, user=None):
        now = dt.datetime.now()
        since = now - dt.timedelta(days=RANGES.get(query.get("range", "day"), 1))
        if path == "/api/site":
            return {"site": self.site, "auth": self.auth.enabled, "logo": self.logo()}
        if path == "/api/summary":
            if not self.modem.configured:
                internet = {"modem": False}
            elif self.modem.enabled:
                internet = {"modem": True, "modem_url": self.modem_url, **self.modem.summary()}
            else:
                internet = {"modem": True, "error": f"modem_check database not found at {self.modem.path}"}
            return {"generated": now.isoformat(timespec="seconds"), "site": self.site, "user": user,
                    "auth": self.auth.enabled, "internet": internet,
                    "wifi": self.wifi_summary(), "router": self.router_summary()}
        if path == "/api/internet":
            gws = self.store.gw_history(since)
            if not self.modem.configured:
                return {"modem": False, "gateways": gws, "outages": gateway_outages(gws)}
            if not self.modem.enabled:
                return {"modem": True, "error": "modem_check database not found", "gateways": gws}
            return {"modem": True, "gateways": gws, **self.modem.history(since.astimezone())}
        if path == "/api/wifi":
            return {"aps": self.store.ap_history(since), "weak": self.store.weak_history(since, unifi.WEAK_DBM),
                    "names": self.store.device_names()}
        if path == "/api/client":
            mac = query.get("mac")
            if not mac:
                raise ValueError("mac is required")
            return {"samples": self.store.client_history(mac, since), "names": self.store.device_names()}
        if path == "/api/router":
            return {"interfaces": self.store.if_history(since), "router": self.store.router_history(since)}
        if path == "/api/firewall":
            f = self.store.fw_summary(now - dt.timedelta(hours=float(query.get("hours", 1))),
                                      hide_noise=query.get("noise") == "hide")
            for row in f["top"] + f["recent"]:
                row["src_info"] = self.namer.name(row["src"])
                row["dst_info"] = self.namer.name(row["dst"])
                if row.get("rule"):
                    row["rule_name"] = self.rules.get(row["rule"])
            f["rules_known"] = bool(self.rules)
            return f
        if path == "/api/hosts":
            if query.get("range") == "now":
                live = sorted((c for c in self.wifi["clients"] if c["down_bps"] is not None),
                              key=lambda c: -((c["down_bps"] or 0) + (c["up_bps"] or 0)))[:10]
                return {"now": True, "hosts": [{k: c[k] for k in ("mac", "name", "ip", "network", "wired", "ap_name",
                                                                   "down_bps", "up_bps", "vendor")} for c in live]}
            return self.store.top_hosts(None if query.get("range") == "all" else since)
        if path == "/api/transfer":
            t = None if query.get("range") == "all" else since
            return {"since": t.isoformat(timespec="seconds") if t else None, "totals": self.store.transfer(t)}
        if path == "/api/leases":
            return self.router["leases"]
        if path == "/api/known":
            return self.store.known_clients()
        return None


def usage_deltas(prev, clients):
    """{mac: (down, up)} bytes since the previous poll. UniFi's counters restart when a
    client reconnects; a counter that went down is taken as new since the restart."""
    out = {}
    for c in clients:
        p = prev.get(c["mac"])
        if p is None or c["down_bytes"] is None:
            continue                     # first sight: no baseline yet
        d = c["down_bytes"] - p[0] if c["down_bytes"] >= p[0] else c["down_bytes"]
        u = c["up_bytes"] - p[1] if (c["up_bytes"] or 0) >= (p[1] or 0) else (c["up_bytes"] or 0)
        out[c["mac"]] = (d, u)
    return out


def gateway_outages(rows):
    """Windows when a gateway was down or losing GW_BAD_LOSS% or more, per gateway,
    in the same shape as modem.outages (start, end, tests, kinds, ongoing)."""
    out, cur = [], {}
    for r in rows:
        bad = r["status"] == "down" or (r["loss_pct"] or 0) >= GW_BAD_LOSS
        c = cur.get(r["name"])
        if bad:
            c = cur[r["name"]] = c or {"start": r["ts"], "end": r["ts"], "tests": 0, "kinds": [r["name"]]}
            c["end"] = r["ts"]
            c["tests"] += 1
        elif c:
            out.append({**c, "ongoing": False})
            del cur[r["name"]]
    out += [{**c, "ongoing": True} for c in cur.values()]
    return sorted(out, key=lambda o: o["start"])


def make_handler(app: App, tls: bool = False):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, status, body: bytes, ctype=None, headers=None):
            self.send_response(status)
            for k, v in (headers or [("Content-Type", ctype)]) + SECURITY_HEADERS:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _redirect(self, where, cookie=None):
            headers = [("Location", where), ("Cache-Control", "no-store")]
            if cookie is not None:
                headers.append(("Set-Cookie", cookie))
            self._send(303, b"", headers=headers)

        def _token(self):
            c = http.cookies.SimpleCookie()
            try:
                c.load(self.headers.get("Cookie") or "")
            except http.cookies.CookieError:
                return None
            return c[auth.COOKIE].value if auth.COOKIE in c else None

        def _user(self):
            """(allowed, user name or None)."""
            if not app.auth.enabled:
                return True, None
            user = app.auth.user_for(self._token())
            return user is not None, user

        def _cookie(self, value, max_age):
            return (f"{auth.COOKIE}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict"
                    + ("; Secure" if tls else ""))

        def _same_origin(self):
            """Refuse cross-site form posts (login CSRF); browsers send Origin on POST."""
            origin = self.headers.get("Origin")
            return not origin or urllib.parse.urlsplit(origin).netloc == self.headers.get("Host")

        def do_POST(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path not in ("/login", "/logout"):
                return self._send(404, b"not found", "text/plain")
            if not self._same_origin():
                return self._send(403, b"cross-site request refused", "text/plain")
            length = int(self.headers.get("Content-Length") or 0)
            if length > 4096:
                return self._send(413, b"too large", "text/plain")
            form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode(errors="replace")))
            ip = self.client_address[0]
            if url.path == "/logout":
                app.auth.logout(self._token())
                return self._redirect("/login", self._cookie("", 0))
            token, why = app.auth.login(form.get("user", ""), form.get("password", ""), ip)
            if not token:
                log.warning("login %s for %r from %s", "blocked (too many failures)" if why == "locked"
                            else "failed", form.get("user", "")[:64], ip)
                return self._redirect(f"/login?e={why}")
            log.info("login: %s from %s", form.get("user"), ip)
            self._redirect("/", self._cookie(token, app.auth.max_age()))

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            allowed, user = self._user()
            if not allowed and url.path not in PUBLIC and not url.path.startswith("/brand/"):
                if url.path.startswith("/api/"):
                    return self._send(401, b'{"error": "login required"}', "application/json")
                return self._redirect("/login")
            if url.path == "/login":
                if not app.auth.enabled or user:
                    return self._redirect("/")
                url = url._replace(path="/login.html")
            if url.path.startswith("/api/"):
                query = dict(urllib.parse.parse_qsl(url.query))
                try:
                    data = app.api(url.path, query, user)
                except ValueError as e:
                    return self._send(400, str(e).encode(), "text/plain")
                except Exception as e:
                    log.exception("API %s failed", url.path)
                    return self._send(500, str(e).encode(), "text/plain")
                if data is None:
                    return self._send(404, b"not found", "text/plain")
                return self._send(200, json.dumps(data, default=str).encode(), "application/json")
            name = "index.html" if url.path in ("/", "") else os.path.basename(url.path)
            ctype = CTYPES.get(name.rsplit(".", 1)[-1], "application/octet-stream")
            if url.path.startswith("/brand/"):
                fp = app.brand_file(name)
                if not fp and name == "brand.css":          # the pages always link it; no brand is no error
                    return self._send(200, b"", headers=[("Content-Type", ctype), ("Cache-Control", "no-cache")])
            else:
                fp = os.path.join(STATIC, name)
            if not fp or not os.path.isfile(fp):
                return self._send(404, b"not found", "text/plain")
            with open(fp, "rb") as f:
                # no-cache: browsers re-check, so an updated dashboard shows up after a deploy
                self._send(200, f.read(), headers=[("Content-Type", ctype), ("Cache-Control", "no-cache")])

        do_HEAD = do_GET

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.client_address[0], fmt % args)

    return Handler


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """One log line instead of a traceback for broken connections, e.g. plain HTTP
        sent to the HTTPS port, or a client that hangs up mid-handshake."""
        e = sys.exc_info()[1]
        if isinstance(e, (ssl.SSLError, ConnectionError, TimeoutError)):
            log.debug("connection from %s dropped: %s", client_address[0], e)
        else:
            super().handle_error(request, client_address)


def serve(store, bind, port, env=os.environ):
    app = App(store, env=env)
    log.info("site: %s", app.site)
    if app.brand:
        log.info("brand: %s%s", app.brand, "" if os.path.isdir(app.brand) else " (NOT FOUND: plain look)")
    log.info("modem data: %s", "none (no modem at this site)" if not app.modem.configured
             else app.modem.path if app.modem.enabled else f"NOT FOUND at {app.modem.path}")
    cert, key = env.get("NETDASH_TLS_CERT"), env.get("NETDASH_TLS_KEY")
    if app.auth.enabled:
        n = len(store.users())
        log.info("logins required (%d user%s)%s", n, "" if n == 1 else "s",
                 "" if n else "; add one with: python3 -m netdash --db <db> user add NAME")
        if not cert:
            log.warning("logins are on but HTTPS isn't: passwords cross the network unencrypted. "
                        "Set NETDASH_TLS_CERT and NETDASH_TLS_KEY")
    else:
        log.info("logins: off (anyone who can reach the port sees the dashboard)")
    log.info("UniFi: %s", f"{app.unifi.url}{' (classic controller)' if app.unifi.classic else ''} "
                          f"as {app.unifi.user or 'API key'}, {app.unifi.tls_mode}" if app.unifi.enabled
             else "off (set NETDASH_UNIFI_USER/NETDASH_UNIFI_PASS in /etc/netdash.env)")
    try:
        httpd = Server((bind, port), make_handler(app, tls=bool(cert)))
        if cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert, key)
            # handshake in the request's thread, so one stalled client can't block accept()
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    except OSError as e:
        raise SystemExit(f"can't listen on port {port}: {e.strerror}. "
                         f"Find what's using it with `sudo ss -ltnp | grep :{port}` or pick another with --port.")
    log.info("pfSense: %s", f"{app.pf.url}, {app.pf.tls_mode}" if app.pf.enabled
             else "off (set NETDASH_PFSENSE_URL/NETDASH_PFSENSE_KEY in /etc/netdash.env)")
    if app.unifi.enabled:
        app.run_poller()
    if app.pf.enabled:
        app.run_pf_poller()
    log.info("dashboard on %s://%s:%d/", "https" if cert else "http", bind, port)
    httpd.serve_forever()
