import http.server
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.request

from netdash import server


class Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


@unittest.skipUnless(shutil.which("openssl"), "needs the openssl command to make a test certificate")
class HttpsRedirectTest(unittest.TestCase):
    """HTTPS and an http:// -> https:// redirect on the same port."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cert, key = f"{cls.dir.name}/cert.pem", f"{cls.dir.name}/key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=dash", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", key, "-out", cert], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.httpd = server.Server(("127.0.0.1", 0), Hello)
        cls.httpd.tls = ctx
        cls.port = cls.httpd.server_address[1]
        cls.client = ssl.create_default_context(cafile=cert)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.dir.cleanup()

    def test_https_works(self):
        with urllib.request.urlopen(f"https://127.0.0.1:{self.port}/", context=self.client, timeout=5) as r:
            self.assertEqual(r.read(), b"ok")

    def test_plain_http_is_redirected(self):
        opener = urllib.request.build_opener(NoRedirect)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            opener.open(f"http://127.0.0.1:{self.port}/api/site?x=1", timeout=5)
        self.assertEqual(cm.exception.code, 301)
        self.assertEqual(cm.exception.headers["Location"], f"https://127.0.0.1:{self.port}/api/site?x=1")


if __name__ == "__main__":
    unittest.main()
