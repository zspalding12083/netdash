"""UniFi client (stdlib only), from sogdash/unifi.py, generalised to every client
and device.

Settings (/etc/netdash.env):
    NETDASH_UNIFI_URL       default https://127.0.0.1:12443 (UniFi OS Server on the Pi)
    NETDASH_UNIFI_USER      a View Only local UniFi account (e.g. netdash-ro) ...
    NETDASH_UNIFI_PASS      ... and its password
    NETDASH_UNIFI_API_KEY   or an API key instead of user/password (untested)
    NETDASH_UNIFI_SITE      default "default"
    NETDASH_UNIFI_KIND      "unifios" (default: UniFi OS console or UniFi OS Server) or
                            "classic" (the self-hosted Network application, usually port 8443)
    NETDASH_UNIFI_FINGERPRINT / _CA / _TLS_VERIFY   certificate checking, see tlsverify.py
"""
import http.cookiejar
import json
import os
import threading
import time
import urllib.error
import urllib.request

from . import tlsverify

WEAK_DBM = -80          # below this, low-power IoT clients get unreliable
LOGIN_BACKOFF = 15 * 60  # seconds before retrying a rejected login
RADIOS = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}


class UniFi:
    def __init__(self, env=os.environ):
        self.url = (env.get("NETDASH_UNIFI_URL") or "https://127.0.0.1:12443").rstrip("/")
        self.user, self.password = env.get("NETDASH_UNIFI_USER"), env.get("NETDASH_UNIFI_PASS")
        self.api_key = env.get("NETDASH_UNIFI_API_KEY")
        self.site = env.get("NETDASH_UNIFI_SITE") or "default"
        # Classic controllers have no /proxy/network prefix and log in at /api/login.
        self.classic = (env.get("NETDASH_UNIFI_KIND") or "unifios").lower() == "classic"
        # Controllers usually have self-signed certificates: pin them (tlsverify.py).
        https, self.tls_mode = tlsverify.https_handler(env, "UNIFI", "UniFi")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(https, urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None
        self._lock = threading.Lock()
        self._login_blocked_until, self._login_error = 0.0, None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key or (self.user and self.password))

    def _request(self, path, body=None, timeout=15):
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.url + path, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            r = self.opener.open(req, timeout=timeout)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError as e:
            raise tlsverify.explain(e, "UNIFI") from e
        with r:
            self.csrf = r.headers.get("X-CSRF-Token") or r.headers.get("X-Updated-Csrf-Token") or self.csrf
            return json.load(r)

    def login(self):
        """A rejected login (bad password, locked account) isn't retried for
        LOGIN_BACKOFF: retrying every poll keeps UniFi's lockout going."""
        if self.api_key:
            return
        if time.monotonic() < self._login_blocked_until:
            raise PermissionError(f"UniFi login rejected earlier ({self._login_error}); retrying later")
        try:
            self._request("/api/login" if self.classic else "/api/auth/login",
                          {"username": self.user, "password": self.password, "remember": False})
        except urllib.error.HTTPError as e:
            if e.code in (400, 401, 403):
                try:
                    body = json.load(e)
                    # UniFi OS: {"code": ...}; classic: {"meta": {"rc": "error", "msg": "api.err.Invalid"}}
                    self._login_error = body.get("code") or (body.get("meta") or {}).get("msg") or f"HTTP {e.code}"
                except ValueError:
                    self._login_error = f"HTTP {e.code}"
                self._login_blocked_until = time.monotonic() + LOGIN_BACKOFF
            raise

    def get(self, what: str):
        """GET /proxy/network/api/s/<site>/<what> (classic: /api/s/<site>/<what>) -> the "data"
        list; logs in again once on 401."""
        path = f"{'' if self.classic else '/proxy/network'}/api/s/{self.site}/{what}"
        with self._lock:
            if not self.api_key and not (self.csrf or self._logged_in()):
                self.login()
            try:
                return self._request(path).get("data", [])
            except urllib.error.HTTPError as e:
                if e.code != 401 or self.api_key:
                    raise
                self.login()
                return self._request(path).get("data", [])

    def _logged_in(self):
        """Classic controllers send no CSRF header on login, only the unifises cookie."""
        return self.classic and any(c.name == "unifises" for c in self.jar)

    def snapshot(self):
        """(clients, devices) as plain dicts, from one stat/sta + stat/device pair."""
        devices = self.get("stat/device")
        return parse_clients(self.get("stat/sta"), devices), parse_devices(devices)


def parse_devices(raw):
    out = []
    for d in raw:
        radios = [{
            "radio": r.get("radio"),
            "band": RADIOS.get(r.get("radio"), r.get("radio")),
            "channel": r.get("channel"),
            "clients": r.get("num_sta"),
            "util_pct": r.get("cu_total"),          # channel utilisation, all sources
            "satisfaction": r.get("satisfaction"),
            "tx_retries_pct": r.get("tx_retries"),
        } for r in d.get("radio_table_stats") or []]
        out.append({
            "mac": (d.get("mac") or "").lower(),
            "name": d.get("name") or d.get("model") or d.get("mac"),
            "type": d.get("type"),                  # uap, usw, ...
            "model": d.get("model"),
            "version": d.get("version"),
            "online": d.get("state") == 1,
            "uptime_s": d.get("uptime"),
            "clients": d.get("num_sta"),
            "satisfaction": d.get("satisfaction"),
            "cpu_pct": _num((d.get("system-stats") or {}).get("cpu")),
            "mem_pct": _num((d.get("system-stats") or {}).get("mem")),
            "radios": radios,
        })
    return sorted(out, key=lambda d: (d["type"] != "uap", d["name"] or ""))


def parse_clients(raw, devices=()):
    names = {(d.get("mac") or "").lower(): d.get("name") for d in devices}
    out = []
    for c in raw:
        wired = bool(c.get("is_wired"))
        ap_mac = (c.get("ap_mac") or c.get("sw_mac") or "").lower() or None
        out.append({
            "mac": (c.get("mac") or "").lower(),
            "name": c.get("name") or c.get("hostname") or c.get("oui") or c.get("mac"),
            "hostname": c.get("hostname"),
            "ip": c.get("ip"),
            "network": c.get("last_connection_network_name") or c.get("network"),
            "vendor": c.get("oui") or None,
            "wired": wired,
            "ap_mac": ap_mac,
            "ap_name": names.get(ap_mac) or c.get("last_uplink_name") or ap_mac,
            "essid": None if wired else c.get("essid"),
            "band": None if wired else RADIOS.get(c.get("radio"), c.get("radio")),
            "channel": None if wired else c.get("channel"),
            "signal_dbm": None if wired else c.get("signal"),
            "tx_rate_mbps": _rate(c.get("tx_rate")),
            "rx_rate_mbps": _rate(c.get("rx_rate")),
            "tx_retries": c.get("tx_retries"),
            "satisfaction": c.get("satisfaction"),
            "uptime_s": c.get("uptime"),
            # Byte counters since the client connected; UniFi's "tx" is toward the client.
            # Wired clients (through a UniFi switch) use the "wired-" fields instead.
            "down_bytes": c.get("wired-tx_bytes" if wired else "tx_bytes"),
            "up_bytes": c.get("wired-rx_bytes" if wired else "rx_bytes"),
            "down_bps": _bps(c.get("wired-tx_bytes-r" if wired else "tx_bytes-r")),
            "up_bps": _bps(c.get("wired-rx_bytes-r" if wired else "rx_bytes-r")),
        })
    return sorted(out, key=lambda c: (c["wired"], c["signal_dbm"] if c["signal_dbm"] is not None else 0))


def _bps(bytes_per_s):
    return bytes_per_s * 8 if isinstance(bytes_per_s, (int, float)) else None


def _rate(kbps):
    return round(kbps / 1000) if isinstance(kbps, (int, float)) else None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
