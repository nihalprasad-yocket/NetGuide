"""Terminal live dashboard (ANSI). Redraws a full frame each refresh."""
import shutil

R = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
CLEAR = "\x1b[2J\x1b[H"
HOME = "\x1b[H"
HIDE = "\x1b[?25l"
SHOW = "\x1b[?25h"

C = {"TCP": "\x1b[38;5;75m", "UDP": "\x1b[38;5;141m", "DNS": "\x1b[38;5;43m",
     "ICMP": "\x1b[38;5;221m", "ARP": "\x1b[38;5;215m", "HTTP": "\x1b[38;5;211m",
     "?": "\x1b[38;5;244m", "L2": "\x1b[38;5;244m", "MALFORMED": "\x1b[38;5;196m"}
SEV = {"critical": "\x1b[1;38;5;196m", "high": "\x1b[1;38;5;208m",
       "medium": "\x1b[1;38;5;220m", "info": "\x1b[38;5;250m"}
GREEN = "\x1b[38;5;43m"
RED = "\x1b[38;5;196m"
MUT = "\x1b[38;5;244m"


def banner(label, idx, total):
    bar = "═" * 64
    return f"\n{BOLD}\x1b[38;5;45m┌{bar}┐\n│ STAGE {idx}/{total}: {label:<54}│\n└{bar}┘{R}\n"


def alert_line(a):
    col = SEV.get(a["severity"], "")
    return (f"  {col}▶ [{a['severity'].upper():8}] {a['layer']:3} {a['category']}{R}\n"
            f"    {MUT}{a['detail']}{R}")


def render(engine, recent, stage=""):
    w = shutil.get_terminal_size((100, 40)).columns
    snap = engine.snapshot()
    out = [HOME]
    ac = snap["alert_counts"]
    head = (f"{BOLD}🛡  NetGuard IDS{R}   "
            f"packets {BOLD}{snap['total']}{R}  |  pps {BOLD}{snap['pps']}{R}  |  "
            f"alerts {RED}{len(snap['alerts'])}{R} "
            f"({RED}{ac['critical']}crit {R}{SEV['high']}{ac['high']}high{R} {SEV['medium']}{ac['medium']}med{R})")
    out.append(head + "\x1b[K\n" + MUT + "─" * min(w, 100) + R + "\n")
    # protocol mix
    protos = snap["proto"]
    tot = sum(protos.values()) or 1
    mix = "  ".join(f"{C.get(k,'')}{k} {v}{R}" for k, v in protos.items())
    out.append(f"{MUT}protocols:{R} {mix}\x1b[K\n\n")
    # recent packets
    out.append(f"{BOLD}Live packets{R}\x1b[K\n")
    for p in list(recent)[-10:]:
        col = C.get(p["proto"], "")
        out.append(f"  {col}{p['proto']:<5}{R}{MUT}{p['summary'][:w-10]}{R}\x1b[K\n")
    out.append("\x1b[K\n")
    # alerts
    out.append(f"{BOLD}{RED}Intrusion alerts{R}\x1b[K\n")
    al = snap["alerts"][-8:]
    if not al:
        out.append(f"  {GREEN}no threats detected{R}\x1b[K\n")
    for a in reversed(al):
        for ln in alert_line(a).split("\n"):
            out.append(ln + "\x1b[K\n")
    out.append("\x1b[J")
    return "".join(out)
