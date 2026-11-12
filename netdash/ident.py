"""Put names on addresses in the firewall log: local devices (DHCP leases,
pfSense's ARP table, UniFi clients), IPv6 link-local addresses built from a MAC
(EUI-64), well-known multicast groups, and internet hosts (reverse DNS, cached
and looked up in the background so a page load never waits on DNS)."""
import ipaddress
import queue
import socket
import threading
import time

SERVICES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IPsec", 554: "RTSP", 587: "SMTP", 853: "DNS over TLS",
    993: "IMAPS", 1194: "OpenVPN", 1433: "MS SQL", 1900: "SSDP/UPnP", 3306: "MySQL", 3389: "Remote Desktop",
    3478: "STUN", 4500: "IPsec NAT-T", 5060: "SIP", 5353: "mDNS", 5355: "LLMNR", 5555: "Android debug",
    5900: "VNC", 6379: "Redis", 7547: "TR-069", 8080: "HTTP alt", 8443: "HTTPS alt", 8728: "MikroTik API",
    10001: "UniFi discovery", 23456: "Telnet alt", 37215: "Huawei exploit", 51820: "WireGuard",
}
MULTICAST = {
    "224.0.0.1": "all hosts", "224.0.0.22": "IGMP", "224.0.0.251": "mDNS group", "224.0.0.252": "LLMNR group",
    "239.255.255.250": "SSDP group", "255.255.255.255": "broadcast",
    "ff02::1": "all IPv6 nodes", "ff02::2": "all IPv6 routers", "ff02::16": "MLDv2 routers",
    "ff02::fb": "mDNS group", "ff02::1:3": "LLMNR group", "ff02::c": "SSDP group", "ff02::1:2": "DHCPv6 group",
}
# Local discovery protocols: devices announce themselves to the whole subnet and the
# router drops what it doesn't route. Expected, not an attack.
NOISE_PORTS = {67, 68, 137, 138, 1900, 5353, 5355, 10001}
NOISE_PROTOS = {"options", "igmp", "ipv6-icmp", "icmp6"}


def eui64_mac(ip):
    """The MAC address inside an EUI-64 IPv6 address (…xx:xxff:fexx:xxxx), or None."""
    try:
        b = ipaddress.IPv6Address(ip).packed[8:]
    except ValueError:
        return None
    if b[3:5] != b"\xff\xfe":
        return None
    mac = bytes([b[0] ^ 0x02]) + b[1:3] + b[5:8]
    return ":".join(f"{x:02x}" for x in mac)


class Namer:
    def __init__(self, resolve=True):
        self.by_ip, self.by_mac, self.router_ips = {}, {}, {}
        self.rdns = {}                      # ip -> hostname or "" (no PTR)
        self._q = queue.Queue()
        self._queued = set()
        if resolve:
            threading.Thread(target=self._resolver, daemon=True, name="rdns").start()

    def update(self, interfaces=(), leases=(), arp=None, clients=()):
        """Rebuild the lookup tables from the latest pfSense and UniFi snapshots."""
        by_mac, by_ip = {}, {}
        for c in clients:
            if c.get("mac"):
                by_mac[c["mac"]] = {"name": c.get("name"), "vendor": c.get("vendor"), "network": c.get("network")}
                if c.get("ip"):
                    by_ip[c["ip"]] = c["mac"]
        for l in leases:
            if not l.get("mac"):
                continue
            d = by_mac.setdefault(l["mac"], {})
            d["name"] = d.get("name") or l.get("descr") or l.get("hostname")
            d.setdefault("network", l.get("iface"))
            if l.get("ip"):
                by_ip.setdefault(l["ip"], l["mac"])
        for ip, (mac, iface) in (arp or {}).items():
            if mac:
                by_ip.setdefault(ip, mac)
                by_mac.setdefault(mac, {}).setdefault("network", iface)
        self.by_mac, self.by_ip = by_mac, by_ip
        self.router_ips = {i["ip"]: i["name"] for i in interfaces if i.get("ip")}

    def name(self, ip, lookup=True):
        """{"name", "kind", "mac", "vendor"}; kind is router / multicast / local / internet / unknown.
        lookup=False skips queueing a reverse-DNS lookup (for bulk labelling of log lines)."""
        if not ip:
            return {"name": None, "kind": "unknown"}
        if ip in self.router_ips:
            return {"name": f"pfSense ({self.router_ips[ip]})", "kind": "router"}
        if ip in MULTICAST:
            return {"name": MULTICAST[ip], "kind": "multicast"}
        if ip == "::":
            return {"name": "unconfigured IPv6 (address check)", "kind": "local"}
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return {"name": None, "kind": "unknown"}
        if a.is_multicast:
            if a.version == 6 and ip.startswith("ff02::1:ff"):
                return {"name": "IPv6 neighbor discovery", "kind": "multicast"}
            return {"name": "multicast", "kind": "multicast"}
        mac = self.by_ip.get(ip) or (eui64_mac(ip) if a.version == 6 else None)
        if mac or a.is_private or a.is_link_local:
            d = self.by_mac.get(mac, {}) if mac else {}
            name = d.get("name")
            if not name and a.version == 6 and a.is_link_local and not mac:
                name = "IPv6 private address (device can't be identified)"
            return {"name": name, "kind": "local", "mac": mac, "vendor": d.get("vendor"), "network": d.get("network")}
        host = self.rdns.get(ip)
        if lookup and host is None and ip not in self._queued:
            self._queued.add(ip)
            self._q.put(ip)
        return {"name": host or None, "kind": "internet"}

    def _resolver(self):
        socket.setdefaulttimeout(3)
        while True:
            ip = self._q.get()
            try:
                self.rdns[ip] = socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):
                self.rdns[ip] = ""
            if len(self.rdns) > 20000:      # keep the cache bounded
                self.rdns.clear()
                self._queued.clear()
            time.sleep(0.05)


def describe(e, src_kind, dst_kind):
    """A short plain-language label for one blocked packet, and whether it's
    routine noise (local discovery chatter, leftovers of closed connections)."""
    proto, dport, flags = e.get("proto") or "", e.get("dport"), e.get("tcpflags") or ""
    service = SERVICES.get(dport) if dport else None
    if proto in NOISE_PROTOS or dst_kind == "multicast" or (dport in NOISE_PORTS and src_kind == "local"):
        what = {5353: "mDNS discovery", 1900: "SSDP/UPnP discovery", 137: "NetBIOS name lookup",
                138: "NetBIOS browse", 67: "DHCP", 68: "DHCP", 5355: "LLMNR lookup",
                10001: "UniFi discovery"}.get(dport)
        if not what:
            what = "IPv6 multicast listener report" if proto == "options" else "local broadcast/multicast"
        return what, True
    if proto == "tcp" and flags and ("S" not in flags or "A" in flags):   # not a bare SYN: not a new connection
        return f"late {service or 'TCP'} packet of an already-closed connection ({flags})", True
    if src_kind == "internet":
        if proto == "tcp":
            return f"inbound {service or 'TCP'} connection attempt" + (f" to port {dport}" if not service and dport else ""), False
        if proto == "icmp":
            return "inbound ping", False
        return f"inbound {service or proto.upper()}" + (f" to port {dport}" if not service and dport else ""), False
    if src_kind == "local" and dst_kind == "internet":
        return f"outbound {service or proto.upper()} blocked by a rule", False
    if src_kind == "local" and dst_kind in ("local", "router"):
        return f"{service or proto.upper()} to another local device/network blocked by a rule", False
    return f"{service or proto.upper()}" + (f" port {dport}" if dport and not service else ""), False
