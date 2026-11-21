import http.server
import threading
import unittest

from netdash import server

PAGE = (b'<html><head></head><body><nav><a href="/?range=7d">7 days</a><a href="/pdf?range=7d">PDF</a>'
        b'<form method="get" action="/"></form><a href="//elsewhere/">x</a>'
        b'<img src="data:image/png;base64,AA"></nav></body></html>')


class FakeModemCheck(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/pdf"):
            body, ctype = b"%PDF-1.4", "application/pdf"
        elif self.path.startswith("/?") or self.path == "/":
            body, ctype = PAGE + self.path.encode(), "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        if ctype == "application/pdf":
            self.send_header("Content-Disposition", 'attachment; filename="r.pdf"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ModemProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeModemCheck)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_page_links_move_under_modem(self):
        status, headers, body = server.modem_page(self.base, "/modem/", "range=7d")
        self.assertEqual(status, 200)
        for want in (b'href="/modem/?range=7d"', b'href="/modem/pdf?range=7d"', b'action="/modem/"',
                     b'href="//elsewhere/"', b'src="data:image', b'href="/">', b"/?range=7d"):
            self.assertIn(want, body)
        self.assertIn(("Cache-Control", "no-store"), headers)

    def test_pdf_passes_through(self):
        status, headers, body = server.modem_page(self.base, "/modem/pdf", "range=24h")
        self.assertEqual((status, body), (200, b"%PDF-1.4"))
        self.assertIn(("Content-Disposition", 'attachment; filename="r.pdf"'), headers)

    def test_dashboard_down(self):
        status, _, body = server.modem_page("http://127.0.0.1:9", "/modem/", "", timeout=3)
        self.assertEqual(status, 502)
        self.assertIn(b"didn't answer", body)


if __name__ == "__main__":
    unittest.main()
