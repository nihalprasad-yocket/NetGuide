"""
Read and write the classic libpcap (.pcap) capture format.

A .pcap written here opens in Wireshark and tcpdump unchanged, which is how we
prove our hand-built packets are real and our parser agrees with Wireshark.

File layout:
  global header (24 bytes): magic, version, tz, sigfigs, snaplen, link-type
  then per packet: ts_sec, ts_usec, incl_len, orig_len, raw bytes
Link type 1 = LINKTYPE_ETHERNET.
"""
import struct

MAGIC = 0xA1B2C3D4
GLOBAL = struct.Struct("<IHHiIII")
REC = struct.Struct("<IIII")


def write(path, packets):
    """packets: iterable of (raw_bytes, timestamp_float)."""
    with open(path, "wb") as f:
        f.write(GLOBAL.pack(MAGIC, 2, 4, 0, 0, 65535, 1))
        for raw, ts in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(REC.pack(sec, usec, len(raw), len(raw)))
            f.write(raw)


def read(path):
    """Yields (raw_bytes, timestamp_float)."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[:4])[0]
        le = magic == MAGIC
        rec = REC if le else struct.Struct(">IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            sec, usec, incl, orig = rec.unpack(h)
            data = f.read(incl)
            if len(data) < incl:
                break
            yield data, sec + usec / 1_000_000
