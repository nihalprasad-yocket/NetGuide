#!/usr/bin/env python3
"""
NetGuard - a multi-layer packet analyzer and Intrusion Detection System.

  python3 netguard.py demo              run the narrated attack demo (start here)
  python3 netguard.py demo --fast       same, quicker
  python3 netguard.py pcap <file.pcap>  analyze any capture file (even live-captured)
  python3 netguard.py live [--iface en0] sniff your own machine (needs sudo + scapy)
  python3 netguard.py web <file.pcap>   load a pcap, just serve the web dashboard

The demo invents attack traffic as packet bytes inside the program and inspects
it. It never sends anything to a real network.
"""
import argparse
import asyncio
import json
import os
import sys
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from netguard import dashboard as D          # noqa: E402
from netguard import pcapfile                # noqa: E402
from netguard import simulator as S          # noqa: E402
from netguard.engine import Engine           # noqa: E402
from netguard.protocols import Packet        # noqa: E402
from netguard.web import WebDashboard        # noqa: E402

OUT = os.path.join(HERE, "results")


def record(recent, pk):
    recent.append({"proto": pk.proto, "summary": pk.summary, "ts": pk.ts})


async def serve_web(engine, recent, port):
    try:
        web = WebDashboard(engine, recent, http_port=port)
        await web.start()
        return port
    except OSError:
        return None


ATTACK_MENU = [
    ("TCP port scan", S.attack_port_scan),
    ("Stealth scan (XMAS / NULL / FIN)", S.attack_stealth_scan),
    ("SYN flood (DoS)", S.attack_syn_flood),
    ("ARP cache poisoning (MITM)", S.attack_arp_spoof),
    ("ICMP ping sweep", S.attack_ping_sweep),
    ("DNS spoofing", S.attack_dns_spoof),
    ("Plaintext credentials over HTTP", S.attack_plaintext_creds),
]


def _frames_for(fn, n=0):
    tl = S.Timeline()
    if n:
        S.benign_burst(tl, 0.0, n)
    else:
        fn(tl, 0.0)
    return tl.sort()


async def _inject(engine, recent, frames, gap=0.012):
    before = len(engine.alerts)
    for raw, _ in frames:
        pk = Packet(raw, time.time())
        record(recent, pk)
        engine.process(pk)
        await asyncio.sleep(gap)
    return engine.alerts[before:]


async def _benign_loop(engine, recent):
    """A trickle of normal traffic so the dashboard always looks alive."""
    while True:
        for raw, _ in _frames_for(None, n=3):
            pk = Packet(raw, time.time())
            record(recent, pk)
            engine.process(pk)
            await asyncio.sleep(0.06)
        await asyncio.sleep(1.5)


async def run_monitor(web_port=8080):
    engine = Engine()
    recent = deque(maxlen=200)
    port = await serve_web(engine, recent, web_port)
    loop = asyncio.get_running_loop()
    bg = loop.create_task(_benign_loop(engine, recent))
    GRN, RED, DIM, RST = "\x1b[38;5;43m", "\x1b[1;38;5;196m", "\x1b[2m", "\x1b[0m"
    menu = (f"\n  {GRN}NetGuard is monitoring the network.{RST}  "
            f"Dashboard: http://127.0.0.1:{port}\n"
            f"  {DIM}Type a number and press Enter to launch that attack, then watch the dashboard.{RST}\n\n"
            "   1  TCP port scan\n"
            "   2  Stealth scan (XMAS / NULL / FIN)\n"
            "   3  SYN flood (DoS)\n"
            "   4  ARP cache poisoning (MITM)\n"
            "   5  ICMP ping sweep\n"
            "   6  DNS spoofing\n"
            "   7  Plaintext credentials over HTTP\n"
            "   0  quit\n")
    print(menu)
    try:
        while True:
            line = (await loop.run_in_executor(None, input, "attack> ")).strip().lower()
            if line in ("0", "q", "quit", "exit"):
                break
            if line in ("m", "menu", "help"):
                print(menu)
                continue
            if not line.isdigit() or not 1 <= int(line) <= len(ATTACK_MENU):
                print("  type a number 1-7, or 0 to quit")
                continue
            name, fn = ATTACK_MENU[int(line) - 1]
            print(f"  {RED}>> launching {name} ...{RST}")
            new = await _inject(engine, recent, _frames_for(fn))
            if new:
                for a in new:
                    print(f"  {RED}DETECTED [{a.severity}] {a.category}{RST} — {a.detail}")
            else:
                print("  (detected earlier; wait a few seconds and try again, the alert is on cooldown)")
    finally:
        bg.cancel()
    summarize(engine)
    write_report(engine, name="interactive")


async def run_demo(fast=False, seed=1, web_port=8080):
    engine = Engine()
    recent = deque(maxlen=200)
    port = await serve_web(engine, recent, web_port)
    stages = S.build_stages(seed=seed)
    speed = 0.0025 if fast else 0.006       # wall-seconds per virtual-second step unit
    print(D.HIDE + D.CLEAR, end="")
    if port:
        print(f"  Web dashboard: http://127.0.0.1:{port}   (open it alongside this terminal)\n")
        time.sleep(2.0 if not fast else 0.5)
    try:
        for i, (label, frames) in enumerate(stages):
            sys.stdout.write(D.banner(label, i, len(stages) - 1) if i else
                             D.banner(label, 0, len(stages) - 1))
            sys.stdout.flush()
            time.sleep(0.8 if not fast else 0.2)
            before = len(engine.alerts)
            t_prev = frames[0][1] if frames else 0
            for raw, ts in frames:
                pk = Packet(raw, ts)
                record(recent, pk)
                new = engine.process(pk)
                gap = max(0, ts - t_prev)
                t_prev = ts
                time.sleep(min(gap * (0.05 if fast else 0.12) + (0.004 if fast else 0.02), 0.25))
                sys.stdout.write(D.render(engine, recent, label))
                sys.stdout.flush()
            fired = engine.alerts[before:]
            # settle the stage so viewers can read the alert
            for _ in range(4 if not fast else 1):
                sys.stdout.write(D.render(engine, recent, label))
                sys.stdout.flush()
                time.sleep(0.4 if not fast else 0.1)
    finally:
        sys.stdout.write(D.SHOW)
    summarize(engine)
    write_report(engine)
    if port:
        print(f"\n  Dashboard still live at http://127.0.0.1:{port} - press Ctrl+C to exit.")
        try:
            await asyncio.Event().wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass


async def run_pcap(path, replay=False, web_port=8080):
    if not os.path.exists(path):
        print(f"  no such file: {path}")
        return
    engine = Engine()
    recent = deque(maxlen=200)
    port = await serve_web(engine, recent, web_port)
    if port:
        print(f"  Web dashboard: http://127.0.0.1:{port}\n")
    pkts = list(pcapfile.read(path))
    print(f"  analyzing {len(pkts)} packets from {os.path.basename(path)} ...\n")
    print(D.HIDE, end="")
    t_prev = pkts[0][1] if pkts else 0
    try:
        for raw, ts in pkts:
            pk = Packet(raw, ts)
            record(recent, pk)
            engine.process(pk)
            if replay:
                time.sleep(min(max(0, ts - t_prev) * 0.1, 0.2))
                t_prev = ts
                sys.stdout.write(D.render(engine, recent))
                sys.stdout.flush()
    finally:
        sys.stdout.write(D.SHOW)
    summarize(engine)
    write_report(engine, name=os.path.basename(path))
    if port:
        print(f"\n  Dashboard at http://127.0.0.1:{port} - Ctrl+C to exit.")
        try:
            await asyncio.Event().wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass


async def run_live(iface, web_port=8080):
    try:
        from scapy.all import sniff
    except ImportError:
        print("  live capture needs scapy:  pip3 install scapy   (and run with sudo)")
        return
    engine = Engine()
    recent = deque(maxlen=200)
    port = await serve_web(engine, recent, web_port)
    print(f"  sniffing {iface or 'default'} ... open http://127.0.0.1:{port}  (Ctrl+C to stop)\n")
    loop = asyncio.get_running_loop()

    def handle(frame):
        raw = bytes(frame)
        pk = Packet(raw)
        record(recent, pk)
        for a in engine.process(pk):
            print(f"  ALERT [{a.severity}] {a.category}: {a.detail}")

    def do_sniff():
        sniff(iface=iface, prn=handle, store=False)
    await loop.run_in_executor(None, do_sniff)


def summarize(engine):
    snap = engine.snapshot()
    print("\n" + "═" * 70)
    print(f"  SUMMARY  {snap['total']} packets, {snap['bytes']} bytes inspected, "
          f"{len(snap['alerts'])} alerts")
    print("  " + "─" * 66)
    cats = {}
    for a in engine.alerts:
        cats.setdefault((a.severity, a.category), 0)
        cats[(a.severity, a.category)] += 1
    order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    for (sev, cat), n in sorted(cats.items(), key=lambda x: order.get(x[0][0], 9)):
        col = D.SEV.get(sev, "")
        print(f"  {col}[{sev.upper():8}]{D.R} {cat}")
    print("═" * 70)


def write_report(engine, name="demo"):
    os.makedirs(OUT, exist_ok=True)
    snap = engine.snapshot()
    with open(os.path.join(OUT, "alerts.json"), "w") as f:
        json.dump(snap, f, indent=1)
    lines = [f"# NetGuard IDS report ({name})", "",
             f"- Packets inspected: **{snap['total']}**  ({snap['bytes']} bytes)",
             f"- Protocol mix: {snap['proto']}",
             f"- Alerts raised: **{len(snap['alerts'])}**", "",
             "| Severity | Layer | Category | Detail |", "|---|---|---|---|"]
    for a in engine.alerts:
        lines.append(f"| {a.severity} | {a.layer} | {a.category} | {a.detail} |")
    with open(os.path.join(OUT, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  report written: results/report.md  and  results/alerts.json")


def main():
    ap = argparse.ArgumentParser(description="NetGuard IDS")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="narrated attack demo")
    d.add_argument("--fast", action="store_true")
    d.add_argument("--seed", type=int, default=1)
    d.add_argument("--port", type=int, default=8080)
    p = sub.add_parser("pcap", help="analyze a .pcap file")
    p.add_argument("file")
    p.add_argument("--replay", action="store_true", help="redraw live with capture timing")
    p.add_argument("--port", type=int, default=8080)
    w = sub.add_parser("web", help="load a pcap and only serve the dashboard")
    w.add_argument("file")
    w.add_argument("--port", type=int, default=8080)
    lv = sub.add_parser("live", help="sniff your own machine (sudo + scapy)")
    lv.add_argument("--iface", default=None)
    lv.add_argument("--port", type=int, default=8080)
    m = sub.add_parser("monitor", help="interactive: you launch each attack, watch it get detected")
    m.add_argument("--port", type=int, default=8080)
    sub.add_parser("pcap-only", help="write sample.pcap and exit")
    a = ap.parse_args()
    try:
        if a.cmd == "demo":
            asyncio.run(run_demo(fast=a.fast, seed=a.seed, web_port=a.port))
        elif a.cmd == "pcap":
            asyncio.run(run_pcap(a.file, replay=a.replay, web_port=a.port))
        elif a.cmd == "web":
            asyncio.run(run_pcap(a.file, replay=False, web_port=a.port))
        elif a.cmd == "live":
            asyncio.run(run_live(a.iface, web_port=a.port))
        elif a.cmd == "monitor":
            asyncio.run(run_monitor(web_port=a.port))
        elif a.cmd == "pcap-only":
            frames = S.build_demo()
            os.makedirs(OUT, exist_ok=True)
            pcapfile.write(os.path.join(OUT, "sample.pcap"), frames)
            print(f"  wrote results/sample.pcap ({len(frames)} packets)")
    except KeyboardInterrupt:
        print(D.SHOW + "\n  stopped.")


if __name__ == "__main__":
    main()
