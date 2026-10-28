"""
Protocol decoders and builders for NetGuard.

Everything here works on RAW BYTES exactly as they appear on the wire, in
network byte order, with real checksums. The same bytes are written to a .pcap
file that opens cleanly in Wireshark, which proves the parser is correct.

Layers covered:
  L2  Ethernet, ARP
  L3  IPv4, ICMP
  L4  TCP (with flags), UDP
  L7  DNS, a little HTTP

A parsed packet is one Packet object whose .layers dict holds each header.
"""
import socket
import struct
import time

# ------------------------------------------------------------------ helpers
ETH_IP = 0x0800
ETH_ARP = 0x0806
IP_ICMP, IP_TCP, IP_UDP = 1, 6, 17

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def ip_str(b: bytes) -> str:
    return socket.inet_ntoa(b)


def ip_bytes(s: str) -> bytes:
    return socket.inet_aton(s)


def checksum(data: bytes) -> int:
    """Standard 16-bit one's-complement Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def flags_str(f: int) -> str:
    out = [n for bit, n in ((SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"), (RST, "RST"),
                            (PSH, "PSH"), (URG, "URG")) if f & bit]
    return "/".join(out) if out else "NONE"


class Packet:
    """One decoded frame. .layers = {'eth':..,'ip':..,'tcp':..,...}, .summary one line."""
    __slots__ = ("ts", "raw", "layers", "length", "summary", "proto")

    def __init__(self, raw: bytes, ts: float = None):
        self.ts = time.time() if ts is None else ts
        self.raw = raw
        self.layers = {}
        self.length = len(raw)
        self.proto = "?"
        self.summary = ""
        self._decode()

    def __getitem__(self, k):
        return self.layers.get(k)

    def has(self, k):
        return k in self.layers

    # ------------------------------------------------------------ decode
    def _decode(self):
        try:
            self._eth()
        except (struct.error, IndexError, ValueError):
            self.proto = "MALFORMED"
            self.summary = f"malformed frame ({self.length} B)"

    def _eth(self):
        dst, src, etype = struct.unpack("!6s6sH", self.raw[:14])
        self.layers["eth"] = {"dst": mac_str(dst), "src": mac_str(src), "type": etype}
        body = self.raw[14:]
        if etype == ETH_ARP:
            self._arp(body)
        elif etype == ETH_IP:
            self._ip(body)
        else:
            self.proto = "L2"
            self.summary = f"{mac_str(src)} -> {mac_str(dst)} ethertype 0x{etype:04x}"

    def _arp(self, b):
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", b[:8])
        sha, spa, tha, tpa = struct.unpack("!6s4s6s4s", b[8:28])
        arp = {"op": op, "sha": mac_str(sha), "spa": ip_str(spa),
               "tha": mac_str(tha), "tpa": ip_str(tpa)}
        self.layers["arp"] = arp
        self.proto = "ARP"
        if op == 1:
            self.summary = f"ARP who-has {arp['tpa']}? tell {arp['spa']}"
        else:
            self.summary = f"ARP {arp['spa']} is-at {arp['sha']}"

    def _ip(self, b):
        vihl, tos, tlen, ident, frag, ttl, proto, chk = struct.unpack("!BBHHHBBH", b[:12])
        ihl = (vihl & 0x0F) * 4
        src, dst = b[12:16], b[16:20]
        ok = checksum(b[:ihl]) == 0
        ip = {"src": ip_str(src), "dst": ip_str(dst), "ttl": ttl, "proto": proto,
              "len": tlen, "id": ident, "checksum_ok": ok, "ihl": ihl}
        self.layers["ip"] = ip
        payload = b[ihl:tlen] if tlen >= ihl else b[ihl:]
        if proto == IP_TCP:
            self._tcp(payload, src, dst)
        elif proto == IP_UDP:
            self._udp(payload, src, dst)
        elif proto == IP_ICMP:
            self._icmp(payload)
        else:
            self.proto = "IP"
            self.summary = f"{ip['src']} -> {ip['dst']} ip-proto {proto}"

    def _tcp(self, b, src, dst):
        sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", b[:14])
        off = (off_flags >> 12) * 4
        flags = off_flags & 0x1FF
        win = struct.unpack("!H", b[14:16])[0]
        tcp = {"sport": sport, "dport": dport, "seq": seq, "ack": ack,
               "flags": flags, "flags_str": flags_str(flags), "win": win}
        self.layers["tcp"] = tcp
        self.proto = "TCP"
        ipl = self.layers["ip"]
        data = b[off:]
        self.summary = f"{ipl['src']}:{sport} -> {ipl['dst']}:{dport} [{tcp['flags_str']}] seq={seq}"
        if data and (data[:4] in (b"GET ", b"POST", b"HTTP", b"PUT ", b"HEAD")):
            self._http(data)

    def _udp(self, b, src, dst):
        sport, dport, ulen, chk = struct.unpack("!HHHH", b[:8])
        self.layers["udp"] = {"sport": sport, "dport": dport, "len": ulen}
        self.proto = "UDP"
        ipl = self.layers["ip"]
        self.summary = f"{ipl['src']}:{sport} -> {ipl['dst']}:{dport} UDP len={ulen}"
        if dport == 53 or sport == 53:
            try:
                self._dns(b[8:])
            except (struct.error, IndexError):
                pass

    def _icmp(self, b):
        t, code, chk, ident, seq = struct.unpack("!BBHHH", b[:8])
        self.layers["icmp"] = {"type": t, "code": code, "id": ident, "seq": seq}
        self.proto = "ICMP"
        ipl = self.layers["ip"]
        kind = {8: "echo request (ping)", 0: "echo reply", 3: "dest unreachable",
                11: "time exceeded"}.get(t, f"type {t}")
        self.summary = f"{ipl['src']} -> {ipl['dst']} ICMP {kind}"

    def _dns(self, b):
        txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", b[:12])
        off = 12
        qname, off = self._dns_name(b, off)
        dns = {"txid": txid, "qr": (flags >> 15) & 1, "qname": qname, "answers": []}
        if qd:
            off += 4  # qtype, qclass
        is_resp = dns["qr"] == 1
        for _ in range(an if is_resp else 0):
            try:
                _, off = self._dns_name(b, off)
                rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", b[off:off + 10])
                off += 10
                rdata = b[off:off + rdlen]
                off += rdlen
                if rtype == 1 and rdlen == 4:
                    dns["answers"].append(ip_str(rdata))
            except (struct.error, IndexError):
                break
        self.layers["dns"] = dns
        self.proto = "DNS"
        ipl = self.layers["ip"]
        if is_resp:
            self.summary = f"{ipl['src']} DNS resp txid={txid} {qname} -> {','.join(dns['answers']) or '-'}"
        else:
            self.summary = f"{ipl['src']} DNS query txid={txid} {qname}?"

    @staticmethod
    def _dns_name(b, off):
        parts = []
        jumped = False
        start = off
        while True:
            ln = b[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0 == 0xC0:  # compression pointer
                ptr = ((ln & 0x3F) << 8) | b[off + 1]
                if not jumped:
                    start = off + 2
                off = ptr
                jumped = True
                continue
            parts.append(b[off + 1:off + 1 + ln].decode("ascii", "replace"))
            off += 1 + ln
        return ".".join(parts), (start if jumped else off)

    def _http(self, data):
        try:
            text = data.decode("latin-1")
        except Exception:
            return
        line = text.split("\r\n", 1)[0]
        self.layers["http"] = {"line": line, "raw": text}
        self.proto = "HTTP"
        ipl = self.layers["ip"]
        self.summary = f"{ipl['src']} -> {ipl['dst']} HTTP {line[:60]}"


# =================================================================== builders
# (used by the traffic engine to synthesize real on-the-wire bytes)
def build_eth(dst_mac, src_mac, etype, payload):
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", etype) + payload


def build_arp(op, sha, spa, tha, tpa):
    return struct.pack("!HHBBH", 1, ETH_IP, 6, 4, op) + \
        mac_bytes(sha) + ip_bytes(spa) + mac_bytes(tha) + ip_bytes(tpa)


def build_ip(src, dst, proto, payload, ttl=64, ident=0):
    vihl, tos = 0x45, 0
    tlen = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", vihl, tos, tlen, ident, 0, ttl, proto, 0,
                      ip_bytes(src), ip_bytes(dst))
    chk = checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", chk) + hdr[12:]
    return hdr + payload


def _l4_checksum(src, dst, proto, l4):
    pseudo = ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, proto, len(l4))
    return checksum(pseudo + l4)


def build_tcp(src, dst, sport, dport, flags, seq=0, ack=0, win=64240, payload=b""):
    off = (5 << 12) | flags
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off, win, 0, 0)
    body = hdr + payload
    chk = _l4_checksum(src, dst, IP_TCP, body)
    body = body[:16] + struct.pack("!H", chk) + body[18:]
    return build_ip(src, dst, IP_TCP, body)


def build_udp(src, dst, sport, dport, payload):
    ulen = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, ulen, 0)
    body = hdr + payload
    chk = _l4_checksum(src, dst, IP_UDP, body) or 0xFFFF
    body = body[:6] + struct.pack("!H", chk) + body[8:]
    return build_ip(src, dst, IP_UDP, body)


def build_icmp(src, dst, typ=8, code=0, ident=1, seq=1, payload=b"netguard"):
    hdr = struct.pack("!BBHHH", typ, code, 0, ident, seq)
    chk = checksum(hdr + payload)
    hdr = hdr[:2] + struct.pack("!H", chk) + hdr[4:]
    return build_ip(src, dst, IP_ICMP, hdr + payload)


def _dns_qname(name):
    out = b""
    for part in name.split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def build_dns_query(src, dst, txid, name, sport=50000):
    q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + _dns_qname(name) + struct.pack("!HH", 1, 1)
    return build_udp(src, dst, sport, 53, q)


def build_dns_response(src, dst, txid, name, answer_ip, dport=50000):
    body = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + _dns_qname(name) + struct.pack("!HH", 1, 1)
    body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_bytes(answer_ip)
    return build_udp(src, dst, 53, dport, body)


def build_http_get(src, dst, host, path="/", sport=50001, creds=None):
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
    if creds:
        import base64
        req += "Authorization: Basic " + base64.b64encode(creds.encode()).decode() + "\r\n"
    req += "\r\n"
    return build_tcp(src, dst, sport, 80, PSH | ACK, seq=1, ack=1, payload=req.encode())
