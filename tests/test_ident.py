import datetime as dt
import os
import tempfile
import unittest

from netdash import ident
from netdash.store import Store


class IdentTest(unittest.TestCase):
    def setUp(self):
        self.n = ident.Namer(resolve=False)
        self.n.update(
            interfaces=[{"name": "WAN", "ip": "203.0.113.30"}, {"name": "LAN", "ip": "10.0.0.1"}],
            leases=[{"ip": "10.0.0.102", "mac": "aa:bb:cc:00:00:02", "hostname": "desk", "iface": "LAN"}],
            arp={"10.0.0.111": ("00:11:22:33:44:55", "LAN")},
            clients=[{"mac": "00:11:22:33:44:55", "name": "Living Room TV", "vendor": "Roku, Inc", "ip": None}])

    def test_eui64(self):
        self.assertEqual(ident.eui64_mac("fe80::211:22ff:fe33:4455"), "00:11:22:33:44:55")
        self.assertIsNone(ident.eui64_mac("fe80::1c2d:3e4f:5a6b:7c8d"))   # privacy address
        self.assertIsNone(ident.eui64_mac("10.0.0.1"))

    def test_names(self):
        self.assertEqual(self.n.name("203.0.113.30")["name"], "pfSense (WAN)")
        self.assertEqual(self.n.name("10.0.0.102")["name"], "desk")
        self.assertEqual(self.n.name("10.0.0.111")["name"], "Living Room TV")          # via ARP
        tv = self.n.name("fe80::211:22ff:fe33:4455")                                   # via EUI-64
        self.assertEqual((tv["name"], tv["vendor"]), ("Living Room TV", "Roku, Inc"))
        self.assertIn("can't be identified", self.n.name("fe80::1c2d:3e4f:5a6b:7c8d")["name"])
        self.assertEqual(self.n.name("ff02::fb"), {"name": "mDNS group", "kind": "multicast"})
        self.assertEqual(self.n.name("ff02::1:ff07:79d1")["name"], "IPv6 neighbor discovery")
        self.assertEqual(self.n.name("8.8.4.4", lookup=False)["kind"], "internet")
        self.assertEqual(self.n._q.qsize(), 0)          # lookup=False queues no DNS
        self.n.name("8.8.4.4")
        self.assertEqual(self.n._q.qsize(), 1)

    def test_describe(self):
        d = ident.describe
        self.assertEqual(d({"proto": "udp", "dport": 5353}, "local", "multicast"), ("mDNS discovery", True))
        self.assertEqual(d({"proto": "options"}, "local", "multicast")[1], True)
        late = d({"proto": "tcp", "dport": 443, "tcpflags": "FA"}, "local", "internet")
        self.assertTrue(late[1] and "closed connection" in late[0])
        self.assertTrue(d({"proto": "tcp", "dport": 443, "tcpflags": "SA"}, "internet", "router")[1])
        self.assertEqual(d({"proto": "tcp", "dport": 22, "tcpflags": "S"}, "internet", "router"),
                         ("inbound SSH connection attempt", False))
        self.assertEqual(d({"proto": "tcp", "dport": 5155, "tcpflags": "S"}, "internet", "router"),
                         ("inbound TCP connection attempt to port 5155", False))
        self.assertEqual(d({"proto": "icmp"}, "internet", "router"), ("inbound ping", False))
        self.assertFalse(d({"proto": "tcp", "dport": 80, "tcpflags": "S"}, "local", "local")[1])


class TransferTest(unittest.TestCase):
    def test_integrates_rates_and_skips_gaps(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            st = Store(path)
            t0 = dt.datetime.now().replace(microsecond=0) - dt.timedelta(hours=1)
            # 8 Mbit/s in for three 30 s steps, then a 10-minute gap that must not count
            for k, sec in enumerate((0, 30, 60, 90, 690)):
                st.add_router({"wan": (8e6, 0.0)}, {"wan": "WAN"}, None, None,
                              ts=(t0 + dt.timedelta(seconds=sec)).isoformat())
            tot = st.transfer(t0 - dt.timedelta(minutes=1))["WAN"]
            self.assertEqual(tot["in_bytes"], 3 * 30 * 1e6)     # 1 MB/s for 90 s
            self.assertEqual(tot["out_bytes"], 0)
            self.assertIn("WAN", st.transfer(None))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
