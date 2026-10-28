"""
NetGuard detection engine.

Stateful inspection of a packet stream, layer by layer. It keeps per-flow and
per-host state in sliding time windows (keyed on PACKET timestamps, so a .pcap
replays identically at any speed) and raises typed alerts.

Detections and the CN idea each one rests on:

  L2  ARP cache poisoning / MITM  - one IP's MAC binding suddenly changes, or a
                                    flood of unsolicited (gratuitous) ARP replies
  L3  Ping sweep                  - one host sends ICMP echo to many hosts (recon)
      ICMP flood                  - very high ICMP rate at one target (DoS)
  L4  TCP port scan               - one src probes many ports on one dst
      SYN flood                   - many half-open handshakes, never completed
      Stealth scans               - illegal TCP flag combos: NULL, FIN, XMAS
  L7  DNS spoofing                - two different answers for one query id, or a
                                    reply with no matching outstanding query
      Plaintext credentials       - HTTP Basic-auth / password in clear text
"""
import time
from collections import Counter, defaultdict, deque

from .protocols import ACK, FIN, PSH, RST, SYN, URG

SEV = {"critical": 3, "high": 2, "medium": 1, "info": 0}


class Alert:
    __slots__ = ("ts", "severity", "category", "layer", "src", "dst", "detail", "evidence")

    def __init__(self, ts, severity, category, layer, src, dst, detail, evidence=None):
        self.ts, self.severity, self.category, self.layer = ts, severity, category, layer
        self.src, self.dst, self.detail, self.evidence = src, dst, detail, evidence or {}

    def as_dict(self):
        return {"ts": self.ts, "severity": self.severity, "category": self.category,
                "layer": self.layer, "src": self.src, "dst": self.dst, "detail": self.detail,
                "evidence": self.evidence}


class Window:
    """Timestamps/values in a sliding time window (seconds), pruned on access."""
    def __init__(self, span):
        self.span = span
        self.items = deque()

    def add(self, ts, val=None):
        self.items.append((ts, val))

    def prune(self, now):
        while self.items and now - self.items[0][0] > self.span:
            self.items.popleft()

    def __len__(self):
        return len(self.items)

    def values(self):
        return [v for _, v in self.items]


class Engine:
    def __init__(self, cfg=None):
        c = cfg or {}
        # thresholds (tunable in the demo)
        self.scan_ports = c.get("scan_ports", 15)
        self.scan_win = c.get("scan_win", 3.0)
        self.syn_flood = c.get("syn_flood", 60)
        self.syn_win = c.get("syn_win", 3.0)
        self.sweep_hosts = c.get("sweep_hosts", 10)
        self.sweep_win = c.get("sweep_win", 3.0)
        self.icmp_flood = c.get("icmp_flood", 100)
        self.icmp_win = c.get("icmp_win", 2.0)
        self.gratuitous_arp = c.get("gratuitous_arp", 8)

        # state
        self.scan_ports_seen = defaultdict(lambda: Window(self.scan_win))   # (src,dst)->dports
        self.syn_track = defaultdict(lambda: Window(self.syn_win))          # dst->src
        self.half_open = defaultdict(set)                                   # dst-> set of flows half open
        self.sweep = defaultdict(lambda: Window(self.sweep_win))           # src-> dsts
        self.icmp_rate = defaultdict(lambda: Window(self.icmp_win))        # dst-> ts
        self.arp_table = {}                                                # ip-> mac
        self.gratuitous = defaultdict(lambda: Window(5.0))                 # mac-> ts
        self.dns_q = {}                                                     # txid-> (qname, answers)
        self.cooldown = {}                                                 # alert-key-> ts

        # live stats for the dashboard
        self.total = 0
        self.bytes = 0
        self.proto = Counter()
        self.talkers = Counter()
        self.targets = Counter()
        self.pps_window = Window(5.0)
        self.alerts = []
        self.start = None
        self.last_ts = None

    # ---------------------------------------------------------- helpers
    def _fire(self, alert, key, every=4.0):
        """De-duplicate repeated alerts for the same thing within `every` seconds."""
        last = self.cooldown.get(key)
        if last is not None and alert.ts - last < every:
            return None
        self.cooldown[key] = alert.ts
        self.alerts.append(alert)
        return alert

    # ---------------------------------------------------------- main
    def process(self, pk):
        now = pk.ts
        if self.start is None:
            self.start = now
        self.last_ts = now
        self.total += 1
        self.bytes += pk.length
        self.proto[pk.proto] += 1
        self.pps_window.add(now)
        self.pps_window.prune(now)
        fired = []
        ip = pk["ip"]
        if ip:
            self.talkers[ip["src"]] += 1
            self.targets[ip["dst"]] += 1

        if pk.has("arp"):
            fired += self._arp(pk, now)
        if pk.has("tcp"):
            fired += self._tcp(pk, now)
        if pk.has("icmp"):
            fired += self._icmp(pk, now)
        if pk.has("dns"):
            fired += self._dns(pk, now)
        if pk.has("http"):
            fired += self._http(pk, now)
        return [a for a in fired if a]

    # ---------------------------------------------------------- L2 ARP
    def _arp(self, pk, now):
        a = pk["arp"]
        out = []
        if a["op"] == 2:  # ARP reply
            ip, mac = a["spa"], a["sha"]
            known = self.arp_table.get(ip)
            if known and known != mac:
                out.append(self._fire(Alert(now, "critical", "ARP cache poisoning (MITM)", "L2",
                    mac, ip, f"{ip} moved from {known} to {mac} - attacker likely impersonating "
                    f"this host to intercept traffic", {"ip": ip, "old_mac": known, "new_mac": mac}),
                    key=("arp", ip), every=2.0))
            self.arp_table[ip] = mac
            # gratuitous / unsolicited reply storm
            g = self.gratuitous[mac]
            g.add(now)
            g.prune(now)
            if len(g) >= self.gratuitous_arp:
                out.append(self._fire(Alert(now, "high", "Gratuitous ARP flood", "L2", mac, a["spa"],
                    f"{len(g)} unsolicited ARP replies from {mac} in 5s - cache poisoning attempt",
                    {"mac": mac, "count": len(g)}), key=("garp", mac), every=4.0))
        return out

    # ---------------------------------------------------------- L4 TCP
    def _tcp(self, pk, now):
        ip, t = pk["ip"], pk["tcp"]
        src, dst = ip["src"], ip["dst"]
        f = t["flags"]
        out = []
        # stealth scans: illegal flag combinations
        bad = None
        if f == 0:
            bad = "NULL scan (no flags set)"
        elif f == FIN:
            bad = "FIN scan (FIN only)"
        elif f == (FIN | PSH | URG):
            bad = "XMAS scan (FIN+PSH+URG)"
        if bad:
            out.append(self._fire(Alert(now, "high", "Stealth port scan", "L4", src, dst,
                f"{bad} from {src} to {dst}:{t['dport']} - crafted packet to probe a port "
                f"while evading connection logs", {"flags": t["flags_str"], "dport": t["dport"]}),
                key=("stealth", src, dst), every=4.0))
        # port scan: many distinct dports, one src->dst
        if f & SYN or bad:
            w = self.scan_ports_seen[(src, dst)]
            w.add(now, t["dport"])
            w.prune(now)
            ports = set(w.values())
            if len(ports) >= self.scan_ports:
                out.append(self._fire(Alert(now, "high", "TCP port scan", "L4", src, dst,
                    f"{src} probed {len(ports)} ports on {dst} in {self.scan_win:.0f}s "
                    f"- reconnaissance sweep", {"ports": len(ports), "sample": sorted(ports)[:12]}),
                    key=("scan", src, dst), every=4.0))
        # SYN flood: half-open handshakes
        flow = (src, t["sport"], dst, t["dport"])
        if f & SYN and not f & ACK:
            self.half_open[dst].add(flow)
            w = self.syn_track[dst]
            w.add(now, src)
            w.prune(now)
            if len(w) >= self.syn_flood:
                srcs = len(set(w.values()))
                out.append(self._fire(Alert(now, "critical", "SYN flood (DoS)", "L4",
                    src if srcs == 1 else f"{srcs} sources", dst,
                    f"{len(w)} half-open SYNs to {dst}:{t['dport']} in {self.syn_win:.0f}s from "
                    f"{srcs} source(s) - connection table exhaustion attack",
                    {"syns": len(w), "sources": srcs, "half_open": len(self.half_open[dst])}),
                    key=("synflood", dst), every=3.0))
        if f & ACK and not f & SYN:  # handshake completing / data -> not half open
            self.half_open[dst].discard(flow)
        return out

    # ---------------------------------------------------------- L3 ICMP
    def _icmp(self, pk, now):
        ip, ic = pk["ip"], pk["icmp"]
        src, dst = ip["src"], ip["dst"]
        out = []
        if ic["type"] == 8:  # echo request
            w = self.sweep[src]
            w.add(now, dst)
            w.prune(now)
            hosts = set(w.values())
            if len(hosts) >= self.sweep_hosts:
                out.append(self._fire(Alert(now, "medium", "ICMP ping sweep", "L3", src, "subnet",
                    f"{src} pinged {len(hosts)} hosts in {self.sweep_win:.0f}s - mapping live hosts "
                    f"on the network", {"hosts": len(hosts)}), key=("sweep", src), every=4.0))
            r = self.icmp_rate[dst]
            r.add(now)
            r.prune(now)
            if len(r) >= self.icmp_flood:
                out.append(self._fire(Alert(now, "high", "ICMP flood (DoS)", "L3", src, dst,
                    f"{len(r)} ICMP echoes to {dst} in {self.icmp_win:.0f}s - bandwidth/ping flood",
                    {"rate": len(r)}), key=("icmpflood", dst), every=3.0))
        return out

    # ---------------------------------------------------------- L7 DNS
    def _dns(self, pk, now):
        d = pk["dns"]
        out = []
        if d["qr"] == 0:  # query
            self.dns_q[d["txid"]] = {"qname": d["qname"], "answers": None, "ts": now}
        else:             # response
            rec = self.dns_q.get(d["txid"])
            if rec is None:
                out.append(self._fire(Alert(now, "high", "DNS spoofing (unsolicited reply)", "L7",
                    pk["ip"]["src"], pk["ip"]["dst"],
                    f"DNS answer for {d['qname']} (txid {d['txid']}) with no matching query "
                    f"- forged reply racing the real server", {"qname": d["qname"], "txid": d["txid"],
                    "answers": d["answers"]}), key=("dns-unsol", d["txid"], d["qname"]), every=1.0))
            elif rec["answers"] is not None and set(rec["answers"]) != set(d["answers"]):
                out.append(self._fire(Alert(now, "critical", "DNS spoofing (answer mismatch)", "L7",
                    pk["ip"]["src"], pk["ip"]["dst"],
                    f"{d['qname']} got two different answers: {rec['answers']} vs {d['answers']} "
                    f"- cache-poisoning / redirect to attacker", {"qname": d["qname"],
                    "first": rec["answers"], "second": d["answers"]}),
                    key=("dns-mism", d["qname"]), every=1.0))
            elif rec["answers"] is None:
                rec["answers"] = d["answers"]
        return out

    # ---------------------------------------------------------- L7 HTTP
    def _http(self, pk, now):
        raw = pk["http"]["raw"]
        out = []
        low = raw.lower()
        hit = None
        if "authorization: basic" in low:
            import base64
            try:
                token = raw.split("Basic ", 1)[1].split("\r", 1)[0].strip()
                hit = "HTTP Basic auth: " + base64.b64decode(token).decode("latin-1")
            except Exception:
                hit = "HTTP Basic auth header"
        elif "password=" in low or "passwd=" in low:
            hit = "password field in clear-text HTTP body/URL"
        if hit:
            out.append(self._fire(Alert(now, "high", "Plaintext credentials", "L7",
                pk["ip"]["src"], pk["ip"]["dst"],
                f"{hit} - sent over HTTP, readable by anyone on the path (use HTTPS/TLS)",
                {"evidence": hit}), key=("creds", pk["ip"]["src"], pk["ip"]["dst"]), every=2.0))
        return out

    # ---------------------------------------------------------- stats
    def pps(self):
        self.pps_window.prune(self.last_ts or 0)
        span = min(5.0, (self.last_ts - self.start) if self.start and self.last_ts else 5.0) or 1
        return round(len(self.pps_window) / span, 1)

    def snapshot(self):
        sev_count = Counter(a.severity for a in self.alerts)
        return {
            "total": self.total, "bytes": self.bytes, "pps": self.pps(),
            "proto": dict(self.proto.most_common()),
            "talkers": self.talkers.most_common(6),
            "targets": self.targets.most_common(6),
            "alerts": [a.as_dict() for a in self.alerts[-80:]],
            "alert_counts": {k: sev_count.get(k, 0) for k in ("critical", "high", "medium", "info")},
            "arp_table": self.arp_table,
            "elapsed": round((self.last_ts - self.start), 2) if self.start and self.last_ts else 0,
        }
