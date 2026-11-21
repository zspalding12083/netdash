"""Certificate checking for the HTTPS connections netdash makes to pfSense and
UniFi, so a device on the network can't pose as either and collect the API key
or the UniFi password.

Routers and controllers usually have self-signed certificates, which normal
verification rejects. For those, pin the certificate: netdash then accepts that
exact certificate and nothing else. Per source (PFSENSE, UNIFI), set one of:

    NETDASH_<SRC>_FINGERPRINT  SHA-256 of the device's certificate, hex, colons optional;
                               several separated by commas (e.g. old and new while
                               rotating). `python3 -m netdash fingerprint` prints them.
    NETDASH_<SRC>_CA           a CA bundle (PEM) that signed the device's certificate,
                               e.g. an organisation's internal CA
    NETDASH_<SRC>_TLS_VERIFY=off  no checking at all (logged as a warning)

With none of them, the system's trusted CAs are used, as for any website.
If a pinned device renews its certificate, polling that source stops with a
"certificate changed" error until the new fingerprint is checked and set.
"""
import hashlib
import http.client
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request


class CertificateChanged(ssl.SSLError):
    """The server's certificate isn't one of the pinned fingerprints."""


def normalize(fp: str) -> str:
    return fp.replace(":", "").replace(" ", "").strip().lower()


def pretty(fp: str) -> str:
    """AB:CD:... the way browsers and pfSense show SHA-256 fingerprints."""
    fp = normalize(fp).upper()
    return ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))


def _no_check_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _PinnedConnection(http.client.HTTPSConnection):
    pins: frozenset = frozenset()
    label = "server"

    def connect(self):
        super().connect()
        got = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
        if got not in self.pins:
            self.sock.close()
            raise CertificateChanged(
                f"{self.label} certificate changed: it is now {pretty(got)}, which isn't a pinned fingerprint. "
                f"If the device renewed its certificate, check that fingerprint on the device and set it")


class _PinnedHandler(urllib.request.HTTPSHandler):
    def __init__(self, pins, label):
        super().__init__(context=_no_check_context())
        self._conn = type("Pinned", (_PinnedConnection,), {"pins": frozenset(pins), "label": label})

    def https_open(self, req):
        return self.do_open(self._conn, req, context=self._context)


def https_handler(env, source: str, label: str):
    """(urllib HTTPSHandler, description of the mode) for source "PFSENSE" or "UNIFI"."""
    fps = [normalize(f) for f in (env.get(f"NETDASH_{source}_FINGERPRINT") or "").split(",") if f.strip()]
    ca = env.get(f"NETDASH_{source}_CA")
    off = (env.get(f"NETDASH_{source}_TLS_VERIFY") or "").lower() in ("off", "0", "no", "false")
    bad = [f for f in fps if len(f) != 64 or any(c not in "0123456789abcdef" for c in f)]
    if bad:
        raise ValueError(f"NETDASH_{source}_FINGERPRINT: {bad[0]!r} isn't a SHA-256 fingerprint (64 hex digits)")
    if fps:
        return _PinnedHandler(fps, label), f"certificate pinned ({len(fps)} fingerprint{'s' * (len(fps) > 1)})"
    if off:
        return urllib.request.HTTPSHandler(context=_no_check_context()), "NOT VERIFIED (TLS_VERIFY=off)"
    if ca:
        return urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)), f"verified against {ca}"
    return urllib.request.HTTPSHandler(context=ssl.create_default_context()), "verified against the system CAs"


def explain(e: Exception, source: str) -> Exception:
    """A clearer error for a self-signed certificate rejected by normal verification."""
    reason = getattr(e, "reason", e)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return ConnectionError(f"{reason.verify_message or reason}: the certificate isn't trusted. For a self-signed "
                               f"certificate, pin it: run `python3 -m netdash fingerprint` and set "
                               f"NETDASH_{source}_FINGERPRINT (or NETDASH_{source}_CA)")
    return e


def fetch_fingerprint(url: str, timeout: float = 10) -> str:
    """SHA-256 of the certificate the server at `url` presents right now (not verified:
    compare it with the one the device itself shows before trusting it)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https":
        raise ValueError(f"{url} isn't an https:// URL")
    with socket.create_connection((u.hostname, u.port or 443), timeout=timeout) as raw:
        with _no_check_context().wrap_socket(raw, server_hostname=u.hostname) as s:
            return pretty(hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest())
