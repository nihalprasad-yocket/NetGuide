"""
Traffic engine: synthesizes a realistic packet timeline for the IDS to inspect.

IMPORTANT: this does NOT attack any real network. It builds packet *bytes*
in memory (identical to what would appear on a wire) and hands them to the
detection engine and/or writes them to a .pcap. It is a lab bench, not a weapon:
there is no target, no socket sending to another host, nothing leaves the process.

The timeline mixes normal background traffic with embedded attack patterns so
every detector has something to catch during the demo.
"""
import random

from . import protocols as P

GW = "192.168.1.1"
GW_MAC = "aa:bb:cc:00:00:01"
DNS = "192.168.1.1"
SERVER = "192.168.1.10"            # internal web server (victim of scans/floods)
SERVER_MAC = "aa:bb:cc:00:00:10"
ATTACKER = "192.168.1.66"
ATTACKER_MAC = "de:ad:be:ef:00:66"
SWITCH_MAC = "aa:bb:cc:ff:ff:ff"

CLIENTS = [f"192.168.1.{i}" for i in (21, 22, 23, 24, 25)]
SITES = {"example.com": "93.184.216.34", "cdn.site.net": "151.101.1.5",
         "api.service.io": "34.120.5.9", "bank.example.in": "103.21.58.10"}


def _mac_for(ip):
    return f"aa:bb:cc:00:{int(ip.split('.')[-1]):02x}:aa"


def _eth_ip(src, payload, smac=None, dmac=GW_MAC):
    return P.build_eth(dmac, smac or _mac_for(src), P.ETH_IP, payload)


class Timeline:
    def __init__(self):
        self.frames = []     # (bytes, ts)

    def add(self, frame, ts):
        self.frames.append((frame, ts))

    def extend(self, frames):
        self.frames.extend(frames)

    def sort(self):
        self.frames.sort(key=lambda x: x[1])
        return self.frames


# --------------------------------------------------------------- benign
def benign_burst(tl, t, n=6):
    """A little normal traffic so the IDS isn't only seeing attacks."""
    for _ in range(n):
        c = random.choice(CLIENTS)
        t += random.uniform(0.01, 0.06)
        kind = random.random()
        if kind < 0.4:  # DNS lookup + answer
            name = random.choice(list(SITES))
            txid = random.randint(1, 65000)
            tl.add(_eth_ip(c, P.build_dns_query(c, DNS, txid, name)), t)
            tl.add(_eth_ip(DNS, P.build_dns_response(DNS, c, txid, name, SITES[name]), smac=GW_MAC), t + 0.02)
        elif kind < 0.7:  # a proper TCP handshake to the server
            sp = random.randint(40000, 60000)
            tl.add(_eth_ip(c, P.build_tcp(c, SERVER, sp, 443, P.SYN, seq=1000)), t)
            tl.add(_eth_ip(SERVER, P.build_tcp(SERVER, c, 443, sp, P.SYN | P.ACK, seq=5000, ack=1001),
                           smac=SERVER_MAC), t + 0.01)
            tl.add(_eth_ip(c, P.build_tcp(c, SERVER, sp, 443, P.ACK, seq=1001, ack=5001)), t + 0.02)
        elif kind < 0.85:  # a ping
            tl.add(_eth_ip(c, P.build_icmp(c, GW, 8)), t)
            tl.add(_eth_ip(GW, P.build_icmp(GW, c, 0), smac=GW_MAC), t + 0.01)
        else:  # normal HTTP GET to an external site (no creds)
            tl.add(_eth_ip(c, P.build_http_get(c, SERVER, "intranet.local", "/")), t)
    return t


# --------------------------------------------------------------- attacks
def attack_port_scan(tl, t):
    """Attacker SYNs 1000 common ports on the server (nmap -sS style)."""
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521,
             3306, 3389, 5432, 5900, 8080, 8443, 6379, 27017, 9200, 11211]
    for i, p in enumerate(ports):
        tl.add(_eth_ip(ATTACKER, P.build_tcp(ATTACKER, SERVER, 55000, p, P.SYN, seq=i),
                       smac=ATTACKER_MAC), t + i * 0.02)
    return t + len(ports) * 0.02


def attack_stealth_scan(tl, t):
    """XMAS, NULL and FIN scans - crafted illegal flag combos to evade logging."""
    for i, (flags, port) in enumerate([(P.FIN | P.PSH | P.URG, 80), (0, 22), (P.FIN, 443),
                                       (P.FIN | P.PSH | P.URG, 3389)]):
        tl.add(_eth_ip(ATTACKER, P.build_tcp(ATTACKER, SERVER, 55001, port, flags, seq=i),
                       smac=ATTACKER_MAC), t + i * 0.05)
    return t + 0.3


def attack_syn_flood(tl, t):
    """80 half-open SYNs from spoofed random sources to the server's port 80."""
    for i in range(80):
        fake = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
        tl.add(_eth_ip(fake, P.build_tcp(fake, SERVER, random.randint(1024, 65000), 80, P.SYN, seq=i),
                       smac=ATTACKER_MAC), t + i * 0.01)
    return t + 0.8


def attack_arp_spoof(tl, t):
    """Attacker claims to be the gateway: gratuitous ARP replies poisoning the cache."""
    # first establish the legitimate binding (so the change is detectable)
    tl.add(P.build_eth("ff:ff:ff:ff:ff:ff", GW_MAC, P.ETH_ARP,
                       P.build_arp(2, GW_MAC, GW, "ff:ff:ff:ff:ff:ff", GW)), t)
    for i in range(10):  # attacker now says "GW is at my MAC"
        tl.add(P.build_eth("ff:ff:ff:ff:ff:ff", ATTACKER_MAC, P.ETH_ARP,
                           P.build_arp(2, ATTACKER_MAC, GW, "ff:ff:ff:ff:ff:ff", GW)), t + 0.1 + i * 0.05)
    return t + 0.8


def attack_ping_sweep(tl, t):
    """Attacker pings every host in the /24 to map live hosts."""
    for i in range(1, 25):
        tl.add(_eth_ip(ATTACKER, P.build_icmp(ATTACKER, f"192.168.1.{i}", 8),
                       smac=ATTACKER_MAC), t + i * 0.03)
    return t + 0.8


def attack_dns_spoof(tl, t):
    """A forged DNS answer races the real one: bank.example.in -> attacker IP."""
    txid = 0x4d2
    name = "bank.example.in"
    tl.add(_eth_ip(CLIENTS[0], P.build_dns_query(CLIENTS[0], DNS, txid, name)), t)
    # attacker's forged reply arrives first, pointing at a phishing server
    tl.add(_eth_ip(DNS, P.build_dns_response(DNS, CLIENTS[0], txid, name, "203.0.113.66"),
                   smac=ATTACKER_MAC), t + 0.02)
    # the real server's reply (different IP) arrives after
    tl.add(_eth_ip(DNS, P.build_dns_response(DNS, CLIENTS[0], txid, name, SITES[name]),
                   smac=GW_MAC), t + 0.08)
    return t + 0.3


def attack_plaintext_creds(tl, t):
    """A login over plain HTTP - credentials in the clear."""
    tl.add(_eth_ip(CLIENTS[1], P.build_http_get(CLIENTS[1], SERVER, "intranet.local",
                   "/admin", creds="admin:P@ssw0rd123")), t)
    return t + 0.1


# --------------------------------------------------------------- composition
DEMO = [
    ("normal traffic", None),
    ("TCP port scan", attack_port_scan),
    ("stealth scans (XMAS/NULL/FIN)", attack_stealth_scan),
    ("SYN flood (DoS)", attack_syn_flood),
    ("ARP cache poisoning (MITM)", attack_arp_spoof),
    ("ICMP ping sweep", attack_ping_sweep),
    ("DNS spoofing", attack_dns_spoof),
    ("plaintext credentials", attack_plaintext_creds),
]


def build_demo(seed=1, gap=1.2):
    """Full timeline: benign background with each attack injected in turn."""
    random.seed(seed)
    tl = Timeline()
    t = 0.0
    t = benign_burst(tl, t, 10)
    for label, fn in DEMO:
        if fn is None:
            continue
        t = benign_burst(tl, t + 0.2, 4)
        start = t + gap
        end = fn(tl, start)
        t = end
    benign_burst(tl, t + 0.3, 8)
    return tl.sort()


SCENARIOS = {name: fn for name, fn in DEMO if fn}


def build_stages(seed=1, gap=0.6):
    """Like build_demo but grouped: [(label, [(frame,ts),...]), ...] for narration."""
    random.seed(seed)
    stages = []
    t = 0.0
    tl = Timeline()
    t = benign_burst(tl, t, 10)
    stages.append(("Baseline: normal network traffic", tl.sort()))
    for label, fn in DEMO:
        if fn is None:
            continue
        tl = Timeline()
        t = benign_burst(tl, t + 0.2, 3)       # a little background noise
        end = fn(tl, t + gap)
        t = end
        stages.append((label, tl.sort()))
    return stages
