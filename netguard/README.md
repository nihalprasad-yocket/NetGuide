# NetGuard
### A Multi-Layer Packet Analyzer & Intrusion Detection System (IDS)

NetGuard captures network packets, decodes every protocol layer **by hand from
the raw bytes** (Ethernet → ARP / IP → ICMP / TCP / UDP → DNS / HTTP), and runs
a live **intrusion-detection engine** that catches 8 classic network attacks as
they happen. It is built entirely from the Python standard library — no external
packages needed for the demo.

**It is a network-security tool, not a website.** Everything it does is core
Computer Networks: packet headers, checksums, the TCP handshake, ARP, ICMP, DNS,
sliding-window rate analysis, and attack signatures.

---

## 1. What it detects (one attack per OSI layer)

| Layer | Attack | How NetGuard detects it | CN concept |
|---|---|---|---|
| **L2** | **ARP cache poisoning / MITM** | An IP's MAC binding suddenly changes | ARP, the ARP cache, MAC/IP mapping |
| **L2** | **Gratuitous ARP flood** | Burst of unsolicited ARP replies | ARP request/reply, broadcast |
| **L3** | **ICMP ping sweep** | One host pings many hosts (host discovery) | ICMP echo, subnetting |
| **L3** | **ICMP flood (DoS)** | Very high ICMP rate at one target | ICMP, bandwidth exhaustion |
| **L4** | **TCP port scan** | One source probes many ports (SYN scan) | TCP ports, the 3-way handshake |
| **L4** | **Stealth scans (NULL / FIN / XMAS)** | Illegal TCP flag combinations | TCP flags, the TCP state machine |
| **L4** | **SYN flood (DoS)** | Many half-open handshakes, never completed | TCP backlog, half-open connections |
| **L7** | **DNS spoofing** | Two different answers for one query ID, or an unsolicited reply | DNS protocol, query IDs, UDP |
| **L7** | **Plaintext credentials** | HTTP Basic-auth / password in clear text | HTTP, why we need TLS |

## 2. How it works

```
   ┌─────────────── packet source ───────────────┐
   │  built-in traffic engine  (the demo)         │   real .pcap file        live sniff (sudo)
   │  benign traffic + embedded attacks as bytes  │   (your own capture)     (your own machine)
   └───────────────────────┬──────────────────────┘
                           ▼
         ┌──────────── PROTOCOL DECODERS (protocols.py) ────────────┐
         │  Ethernet → ARP | IPv4 → ICMP / TCP / UDP → DNS / HTTP    │
         │  real headers, network byte order, verified checksums     │
         └───────────────────────┬──────────────────────────────────┘
                                 ▼
         ┌──────────── DETECTION ENGINE (engine.py) ────────────────┐
         │  per-flow state · TCP handshake tracking · sliding time   │
         │  windows · signatures + rate/anomaly thresholds           │
         └───────────────────────┬──────────────────────────────────┘
                                 ▼
             terminal dashboard  +  web dashboard  +  report.md / alerts.json
```

**Why the demo is safe and reliable:** the traffic engine invents the attack
packets *as bytes inside the program* and feeds them to the analyzer. Nothing is
ever sent to a real network — there is no target and no live socket. So the demo
can't fail in the viva and can't touch the college network. The exact same bytes
are written to `results/sample.pcap`, which **opens in Wireshark**, proving the
packets are real and the decoder is correct.

## 3. Run it (Mac, VS Code terminal)

Nothing to install — it uses only the Python standard library.

### Best for the viva: interactive mode (you launch each attack)
```bash
cd netguard
python3 netguard.py monitor
```
Open **http://127.0.0.1:8080** in your browser beside the terminal. NetGuard is now
monitoring, with normal traffic flowing. The terminal shows a menu — **type a number
and press Enter to launch that attack**, and watch the alert appear on the dashboard:

```
 1  TCP port scan
 2  Stealth scan (XMAS / NULL / FIN)
 3  SYN flood (DoS)
 4  ARP cache poisoning (MITM)
 5  ICMP ping sweep
 6  DNS spoofing
 7  Plaintext credentials over HTTP
 0  quit
```

So you type `1`, the terminal prints "launching TCP port scan…" then "DETECTED",
and the alert shows up on the web dashboard. This is the "perform an attack and
watch it get caught" demo. Press `0` to quit.

### Hands-off: automatic narrated demo
```bash
python3 netguard.py demo
```
Runs all 8 attacks in sequence on its own (no typing needed).

When it starts it prints a web address. **Open http://127.0.0.1:8080 in your
browser** and put it beside the terminal. The demo then walks through 8 stages,
one attack at a time:

1. Baseline normal traffic
2. TCP port scan
3. Stealth scans (XMAS / NULL / FIN)
4. SYN flood (DoS)
5. ARP cache poisoning (MITM)
6. ICMP ping sweep
7. DNS spoofing
8. Plaintext credentials

The terminal shows packets scrolling and alerts firing in red; the web dashboard
shows live stats, the protocol mix, a packet feed, top talkers, and the alert
list. At the end it writes `results/report.md` and `results/alerts.json`.

- `python3 netguard.py demo --fast` — quicker run
- Port already in use → add `--port 8090` and open that port instead

### Analyze a real capture file
```bash
python3 netguard.py pcap results/sample.pcap          # analyze instantly
python3 netguard.py pcap results/sample.pcap --replay # redraw at capture speed
```
Point it at any `.pcap` — including one you record yourself in Wireshark.

### Sniff your own machine (optional, advanced)
```bash
pip3 install scapy
sudo python3 netguard.py live --iface en0
```
Then browse the web or run `ping`/`nmap` **against your own devices on your own
hotspot** and watch NetGuard react. Only ever do this on a network you own.

## 4. Prove the packets are real — open them in Wireshark
1. Run `python3 netguard.py demo` once (it creates `results/sample.pcap`), or run
   `python3 netguard.py pcap-only`.
2. Open **Wireshark → File → Open → `results/sample.pcap`**.
3. You'll see all 243 packets fully decoded by Wireshark itself: the ARP replies,
   the SYN scan, the XMAS packet (filter `tcp.flags == 0x029`), the half-open SYN
   flood (`tcp.flags.syn==1 && tcp.flags.ack==0`), the DNS answers (`dns`), and
   the HTTP request with the `Authorization: Basic` header (`http`). This shows
   your hand-built packets are byte-for-byte valid, and that NetGuard decoded the
   same fields Wireshark does.

## 5. Computer Networks concepts in this project

- **OSI / TCP-IP layering** — the decoder walks every layer explicitly
- **Framing & encapsulation** — Ethernet frame → IP packet → TCP/UDP segment → app data
- **Addressing** — MAC addresses, IPv4 addresses, ports, the ARP MAC↔IP mapping
- **Checksums** — the Internet checksum (RFC 1071) for IP, TCP, UDP, ICMP; NetGuard verifies them
- **ARP** — request/reply, the ARP cache, and how poisoning enables man-in-the-middle
- **ICMP** — echo request/reply, ping sweeps, floods
- **TCP** — the 3-way handshake, flags (SYN/ACK/FIN/RST/PSH/URG), half-open connections, the state machine
- **UDP & DNS** — connectionless transport, DNS query IDs, caching, spoofing races
- **HTTP vs HTTPS** — why plaintext protocols leak credentials
- **Traffic analysis** — packets/sec, protocol distribution, top talkers, sliding-window rate detection
- **IDS design** — signature-based vs anomaly/threshold-based detection, alert de-duplication
- **.pcap format** — the libpcap capture file format (interoperates with Wireshark/tcpdump)

## 6. Viva questions and answers

**What is an IDS?** A system that inspects network traffic and raises alerts when
it sees patterns that match known attacks (signature-based) or abnormal rates
(anomaly-based). NetGuard does both. An IDS detects and alerts; an IPS would also
block.

**Signature vs anomaly detection?** Signature = a fixed pattern, e.g. a TCP packet
with FIN+PSH+URG set is an XMAS scan. Anomaly = a statistical threshold, e.g.
more than 15 distinct ports from one source in 3 seconds is a port scan. NetGuard
uses signatures for the stealth scans, ARP and DNS checks, and sliding-window
thresholds for the scans and floods.

**How do you detect a port scan but not normal browsing?** Normal hosts open a few
ports and complete the handshake (SYN → SYN-ACK → ACK). A scanner sends SYNs to
many different ports from one source in a short window and usually never completes
them. We count distinct destination ports per source in a 3-second sliding window.

**How is a SYN flood different from a port scan?** A port scan hits many *ports* on
one host to find open ones. A SYN flood hits one *port* with many SYNs (often from
spoofed source IPs) and never sends the final ACK, filling the server's connection
backlog so real clients can't connect. We track half-open connections per target.

**What is a XMAS scan?** A TCP packet with the FIN, PSH and URG flags all set
("lit up like a Christmas tree"). It's illegal under normal TCP, so it's used to
probe firewall/port behaviour while evading some logging. NULL (no flags) and FIN
(FIN only) scans are the same idea.

**How does ARP poisoning enable a man-in-the-middle attack?** ARP has no
authentication. An attacker broadcasts "the gateway's IP is at *my* MAC", so other
hosts send their traffic to the attacker, who forwards it on and reads/modifies it.
NetGuard keeps an IP→MAC table and alerts when a binding changes.

**How do you catch DNS spoofing?** DNS matches a reply to a query by a 16-bit
transaction ID. In a spoofing/race attack a forged reply with the same ID arrives
first with a different IP. We remember each query ID and alert if a second answer
disagrees, or if a reply arrives with no matching query.

**Why build the packets by hand instead of using a library?** To show we
understand the wire format: every header field, byte order and checksum is ours.
The proof is that Wireshark — which we didn't write — opens our `.pcap` and
decodes it correctly.

**Could this run on live traffic?** Yes — `netguard.py live` uses scapy to sniff a
real interface (needs root). We demo with synthetic traffic so it's reliable and
because running real attacks on a shared network isn't allowed.

**Limitations?** It inspects headers and cleartext only (it can't see inside
TLS); thresholds are fixed, not learned; and as an IDS it alerts but doesn't block.

## 7. Project structure
```
netguard.py              CLI: demo | pcap <file> | web <file> | live | pcap-only
netguard/protocols.py    decode + build Ethernet/ARP/IP/ICMP/TCP/UDP/DNS/HTTP, checksums
netguard/engine.py       the detection engine (signatures + sliding-window anomaly)
netguard/simulator.py    synthetic benign + attack traffic (bytes only, no real network)
netguard/pcapfile.py     read/write the libpcap .pcap format (Wireshark-compatible)
netguard/dashboard.py    live terminal dashboard (ANSI)
netguard/web.py          live web dashboard (view-only)
results/sample.pcap      243-packet capture you can open in Wireshark
results/report.md        the alerts table from the last run
results/dashboard.png    screenshot of the web dashboard
```

> Only ever run live capture or any scanning tool on a network you own, such as
> your own phone hotspot. This project needs none of that — the demo is fully
> self-contained.
