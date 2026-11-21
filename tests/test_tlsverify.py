import hashlib
import http.server
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error

from netdash import pfsense, tlsverify, unifi


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"data": {"platform": "test", "cpu_usage": 1}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass                    # clients that refuse the certificate hang up mid-handshake; that's the point


@unittest.skipUnless(shutil.which("openssl"), "needs the openssl command to make a test certificate")
class TlsTest(unittest.TestCase):
    """A local HTTPS server with a self-signed certificate, like a router's or controller's."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cert, key = f"{cls.dir.name}/cert.pem", f"{cls.dir.name}/key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=router", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", key, "-out", cert], check=True, capture_output=True)
        cls.cert = cert
        with open(cert) as f:
            cls.fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.httpd = QuietServer(("127.0.0.1", 0), Handler)
        cls.httpd.socket = ctx.wrap_socket(cls.httpd.socket, server_side=True)
        cls.url = f"https://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.dir.cleanup()

    def pf(self, **extra):
        return pfsense.PfSense({"NETDASH_PFSENSE_URL": self.url, "NETDASH_PFSENSE_KEY": "k", **extra})

    def test_fetch_fingerprint(self):
        got = tlsverify.fetch_fingerprint(self.url)
        self.assertEqual(tlsverify.normalize(got), self.fp)
        self.assertRegex(got, r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")

    def test_pinned_certificate_is_accepted(self):
        for pin in (self.fp, tlsverify.pretty(self.fp), f"{'0' * 64}, {self.fp.upper()}"):   # any format, rotation
            pf = self.pf(NETDASH_PFSENSE_FINGERPRINT=pin)
            self.assertEqual(pf.get("status/system")["platform"], "test")
            self.assertIn("pinned", pf.tls_mode)

    def test_other_certificate_is_refused(self):
        pf = self.pf(NETDASH_PFSENSE_FINGERPRINT="ab" * 32)
        with self.assertRaises(urllib.error.URLError) as cm:
            pf.get("status/system")
        self.assertIsInstance(cm.exception.reason, tlsverify.CertificateChanged)
        self.assertIn(tlsverify.pretty(self.fp), str(cm.exception.reason))   # says what it saw

    def test_default_rejects_self_signed_with_a_hint(self):
        with self.assertRaisesRegex(ConnectionError, "NETDASH_PFSENSE_FINGERPRINT"):
            self.pf().get("status/system")

    def test_ca_file(self):
        pf = self.pf(NETDASH_PFSENSE_CA=self.cert)          # self-signed: the certificate is its own CA
        self.assertEqual(pf.get("status/system")["platform"], "test")

    def test_explicit_off(self):
        pf = self.pf(NETDASH_PFSENSE_TLS_VERIFY="off")
        self.assertEqual(pf.get("status/system")["platform"], "test")
        self.assertIn("NOT VERIFIED", pf.tls_mode)

    def test_bad_fingerprint_setting(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.pf(NETDASH_PFSENSE_FINGERPRINT="not-a-fingerprint")

    def test_unifi_uses_the_same_checking(self):
        u = unifi.UniFi({"NETDASH_UNIFI_URL": self.url, "NETDASH_UNIFI_API_KEY": "k",
                         "NETDASH_UNIFI_FINGERPRINT": "ab" * 32})
        with self.assertRaises(urllib.error.URLError) as cm:
            u.get("stat/sta")
        self.assertIsInstance(cm.exception.reason, tlsverify.CertificateChanged)
        u = unifi.UniFi({"NETDASH_UNIFI_URL": self.url, "NETDASH_UNIFI_API_KEY": "k",
                         "NETDASH_UNIFI_FINGERPRINT": self.fp})
        self.assertEqual(u._request("/anything")["data"]["platform"], "test")


if __name__ == "__main__":
    unittest.main()
