import datetime as dt
import os
import tempfile
import unittest

from netdash import pfsense
from netdash.store import Store

# Shapes as returned by pfrest 2.10.2 on the Netgate 3100 (2026-10-17), trimmed.
IFACES = [
    {"name": "wan", "descr": "WAN", "hwif": "mvneta2", "status": "up", "ipaddr": "203.0.113.30", "subnet": 21,
     "inbytes": 927305203, "outbytes": 743748819, "inerrs": 0, "outerrs": 0},
    {"name": "lan", "descr": "LAN", "hwif": "mvneta1", "status": "up", "ipaddr": "10.0.0.1", "subnet": 24,
     "inbytes": 338649187, "outbytes": -2130051355, "inerrs": 0, "outerrs": 0},
    {"name": "opt3", "descr": "IOT", "hwif": "mvneta1.110", "status": "up", "ipaddr": "10.0.51.1", "subnet": 24,
     "inbytes": 1, "outbytes": 2, "inerrs": 0, "outerrs": 0},
    {"name": "opt1", "descr": "OPT1", "hwif": "mvneta0", "status": "down", "ipaddr": None, "subnet": None,
     "inbytes": 0, "outbytes": 0},
]
V4 = ("Oct 17 10:09:00 router filterlog[55220]: 1,6,,1000000103,mvneta2,match,block,in,4,0x0,,7,28,0,DF,"
      "6,tcp,44,198.51.100.86,203.0.113.30,51234,22,0,S,123,,1024,,mss")
V6 = ("Oct 17 10:09:01 router filterlog[55220]: 1,8,,1000000105,mvneta1.130,match,block,in,6,0x00,0x20c00,"
      "255,UDP,17,93,fe80::181a:96ee:35ef:38eb,ff02::fb,5353,5353,93")
ICMP = ("Oct 17 10:09:00 router filterlog[55220]: 1,6,,1000000103,mvneta2,match,block,in,4,0x0,,7,28,0,DF,"
        "1,icmp,44,198.51.100.86,203.0.113.30,request,34050,2724")


class PfSenseTest(unittest.TestCase):
    def test_interfaces(self):
        i = {x["id"]: x for x in pfsense.parse_interfaces(IFACES)}
        self.assertEqual(i["lan"]["out_bytes"], 2 ** 32 - 2130051355)  # signed 32-bit -> unsigned
        self.assertEqual(i["lan"]["network"], "10.0.0.0/24")
        self.assertEqual(i["opt3"]["vlan"], 110)
        self.assertIsNone(i["wan"]["vlan"])
        self.assertFalse(i["opt1"]["up"])

    def test_rates_across_wrap(self):
        prev = [{"id": "wan", "in_bytes": 2 ** 32 - 1000, "out_bytes": 50}]
        cur = [{"id": "wan", "in_bytes": 3000, "out_bytes": 150}]   # wrapped: 4000 bytes in
        self.assertEqual(pfsense.rates(prev, cur, 10), {"wan": (3200.0, 80.0)})
        self.assertEqual(pfsense.rates(None, cur, 10), {})

    def test_filterlog(self):
        now = dt.datetime(2026, 10, 17, 12)
        e = pfsense.parse_filterlog(V4, now)
        self.assertEqual((e["ts"], e["hwif"], e["action"], e["proto"], e["src"], e["dport"]),
                         ("2026-10-17T10:09:00", "mvneta2", "block", "tcp", "198.51.100.86", 22))
        e = pfsense.parse_filterlog(V6, now)
        self.assertEqual((e["ipver"], e["proto"], e["dst"], e["dport"]), ("6", "udp", "ff02::fb", 5353))
        e = pfsense.parse_filterlog(ICMP, now)
        self.assertEqual((e["proto"], e["dport"]), ("icmp", None))
        self.assertIsNone(pfsense.parse_filterlog("Oct 17 10:09:00 router newsyslog[79]: logfile turned over"))
        # A December line read in January belongs to last year
        self.assertTrue(pfsense.parse_filterlog(V4.replace("Oct 17", "Dec 31"), dt.datetime(2027, 1, 1, 0, 5))
                        ["ts"].startswith("2026-12-31"))

    def test_leases_get_interface_from_ip(self):
        ifaces = pfsense.parse_interfaces(IFACES)
        leases = pfsense.parse_leases([
            {"ip": "10.0.51.20", "mac": "AA:BB:CC:00:00:01", "if": None, "hostname": "plug", "online_status": "active/online"},
            {"ip": "10.0.0.50", "mac": "aa:bb:cc:00:00:02", "if": "lan", "active_status": "static",
             "online_status": "idle/offline"},
        ], ifaces)
        self.assertEqual([(l["iface"], l["online"], l["static"]) for l in leases],
                         [("IOT", True, False), ("LAN", False, True)])
        self.assertEqual(leases[0]["mac"], "aa:bb:cc:00:00:01")

    def test_store_firewall_dedupes(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            st = Store(path)
            now = dt.datetime.now()
            events = [pfsense.parse_filterlog(t, now) for t in (V4, V6, ICMP)]
            for e in events:
                e["ts"] = now.replace(microsecond=0).isoformat()   # recent, so pruning keeps them
                e["iface"] = {"mvneta2": "WAN"}.get(e["hwif"], "PARENTS")
            self.assertEqual(st.add_fw(events), 3)
            self.assertEqual(st.add_fw(events), 0)             # the next poll overlaps
            s = st.fw_summary(now - dt.timedelta(hours=1))
            self.assertEqual({r["iface"]: r["blocks"] for r in s["per_iface"]}, {"WAN": 2, "PARENTS": 1})
            st.add_router({"wan": (8e6, 1e6)}, {"wan": "WAN"}, {"cpu_pct": 12}, {"loss_pct": 100, "status": "down"})
            self.assertEqual(st.if_history(now - dt.timedelta(hours=1))[0]["iface"], "WAN")
            self.assertEqual(st.router_history(now - dt.timedelta(hours=1))[0]["gw_loss_pct"], 100)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
