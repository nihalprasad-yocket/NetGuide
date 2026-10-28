# NetGuard IDS report (interactive)

- Packets inspected: **570**  (36604 bytes)
- Protocol mix: {'TCP': 249, 'DNS': 184, 'ICMP': 92, 'HTTP': 34, 'ARP': 11}
- Alerts raised: **3**

| Severity | Layer | Category | Detail |
|---|---|---|---|
| medium | L3 | ICMP ping sweep | 192.168.1.66 pinged 10 hosts in 3s - mapping live hosts on the network |
| critical | L2 | ARP cache poisoning (MITM) | 192.168.1.1 moved from aa:bb:cc:00:00:01 to de:ad:be:ef:00:66 - attacker likely impersonating this host to intercept traffic |
| high | L2 | Gratuitous ARP flood | 8 unsolicited ARP replies from de:ad:be:ef:00:66 in 5s - cache poisoning attempt |
