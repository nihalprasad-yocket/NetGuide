"""View-only web dashboard for NetGuard (live packet stats + alert feed)."""
import asyncio
import json


class WebDashboard:
    def __init__(self, engine, recent, http_port=8080, host="127.0.0.1"):
        self.engine = engine
        self.recent = recent          # deque of recent packet summaries
        self.http_port = http_port
        self.host = host

    async def start(self):
        await asyncio.start_server(self._http, self.host, self.http_port)

    async def _http(self, reader, writer):
        try:
            line = (await reader.readline()).decode(errors="replace")
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            path = line.split(" ")[1] if " " in line else "/"
            if path.startswith("/state"):
                snap = self.engine.snapshot()
                snap["recent"] = list(self.recent)[-60:]
                body = json.dumps(snap).encode()
                ctype = "application/json"
            else:
                body, ctype = HTML.encode(), "text/html; charset=utf-8"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype.encode() +
                         b"\r\nCache-Control: no-store\r\nContent-Length: " +
                         str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()


HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>NetGuard IDS</title>
<style>
:root{--bg:#0b1020;--panel:#141b2e;--line:#243049;--ink:#e7ecf5;--mut:#8696b5;--grid:#1c2640;
--crit:#ff5a5a;--high:#ffa23e;--med:#ffd34e;--ok:#3ddc97;--blue:#4d9fff;--violet:#b48bff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 "Segoe UI",system-ui,sans-serif}
header{display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid var(--line);
position:sticky;top:0;background:var(--bg);z-index:5}
header b{font-size:17px}.mut{color:var(--mut)}
.badge{padding:3px 10px;border-radius:99px;font-size:12px;font-weight:700}
.badge.red{background:#3a1420;color:var(--crit)}.badge.ok{background:#10301f;color:var(--ok)}
main{display:grid;grid-template-columns:1.3fr 1fr;gap:14px;padding:14px 20px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
h3{margin:0 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px;padding:0 20px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat .n{font-size:26px;font-weight:800;font-variant-numeric:tabular-nums}
.stat .l{color:var(--mut);font-size:12px}
.bar{height:10px;border-radius:5px;background:var(--grid);overflow:hidden;display:flex;margin:8px 0}
.bar i{display:block;height:100%}
table{width:100%;border-collapse:collapse;font-size:12.5px}
td,th{padding:5px 7px;border-bottom:1px solid var(--line);text-align:left}th{color:var(--mut)}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
#feed{max-height:420px;overflow:auto}
.al{border-left:3px solid var(--mut);padding:8px 10px;margin-bottom:8px;background:#0e1526;border-radius:0 8px 8px 0}
.al.critical{border-color:var(--crit)}.al.high{border-color:var(--high)}.al.medium{border-color:var(--med)}
.al .cat{font-weight:700}.al.critical .cat{color:var(--crit)}.al.high .cat{color:var(--high)}.al.medium .cat{color:var(--med)}
.al .d{color:var(--mut);font-size:12px;margin-top:2px}
.lyr{display:inline-block;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;background:#1b2740;color:var(--blue);margin-right:6px}
#pkts{max-height:260px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px}
.pk{padding:2px 0;color:var(--mut)}.pk b{color:var(--ink)}
.p-TCP{color:#4d9fff}.p-UDP{color:#b48bff}.p-DNS{color:#3ddc97}.p-ICMP{color:#ffd34e}.p-ARP{color:#ffa23e}.p-HTTP{color:#ff85c0}
@media(max-width:900px){main{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}
</style></head><body>
<header><b>🛡 NetGuard IDS</b><span class="mut">live packet inspection · signature + anomaly detection</span>
<span id="status" class="badge ok">monitoring</span></header>
<div class="stats">
 <div class="stat"><div class="n" id="s-pkts">0</div><div class="l">packets inspected</div></div>
 <div class="stat"><div class="n" id="s-pps">0</div><div class="l">packets / sec</div></div>
 <div class="stat"><div class="n" id="s-alerts" style="color:var(--crit)">0</div><div class="l">alerts raised</div></div>
 <div class="stat"><div class="n" id="s-data">0</div><div class="l">data inspected</div></div>
</div>
<main>
 <div>
  <div class="panel"><h3>Protocol mix (by layer)</h3><div class="bar" id="bar"></div>
   <div id="legend" class="mut" style="font-size:12px"></div></div>
  <div class="panel" style="margin-top:14px"><h3>Live packet feed</h3><div id="pkts"></div></div>
  <div class="panel" style="margin-top:14px"><h3>Top talkers</h3><table id="talkers"></table></div>
 </div>
 <div class="panel"><h3>🚨 Intrusion alerts</h3><div id="feed"><div class="mut">No threats detected yet.</div></div></div>
</main>
<script>
const PC={TCP:"#4d9fff",UDP:"#b48bff",DNS:"#3ddc97",ICMP:"#ffd34e",ARP:"#ffa23e",HTTP:"#ff85c0","?":"#55617d",L2:"#55617d"};
const esc=s=>String(s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const kb=n=>n>1048576?(n/1048576).toFixed(1)+" MB":n>1024?(n/1024).toFixed(1)+" KB":n+" B";
const $=id=>document.getElementById(id);
async function tick(){let S;try{S=await(await fetch("/state")).json();}catch(e){return;}
 $("s-pkts").textContent=S.total;$("s-pps").textContent=S.pps;$("s-data").textContent=kb(S.bytes);
 const na=S.alerts.length;$("s-alerts").textContent=na;
 const st=$("status");
 if(na){st.className="badge red";st.textContent=na+" ALERT"+(na>1?"S":"");}else{st.className="badge ok";st.textContent="monitoring";}
 const tot=Object.values(S.proto).reduce((a,b)=>a+b,0)||1;
 $("bar").innerHTML=Object.entries(S.proto).map(([k,v])=>`<i style="width:${100*v/tot}%;background:${PC[k]||"#55617d"}"></i>`).join("");
 $("legend").innerHTML=Object.entries(S.proto).map(([k,v])=>`<span style="color:${PC[k]||"#889"}">&#9632;</span> ${esc(k)} ${v}`).join(" &nbsp; ");
 $("feed").innerHTML=S.alerts.slice().reverse().map(a=>`<div class="al ${a.severity}"><span class="lyr">${a.layer}</span><span class="cat">${esc(a.category)}</span><div class="d">${esc(a.detail)}</div></div>`).join("")||'<div class="mut">No threats detected yet.</div>';
 $("pkts").innerHTML=(S.recent||[]).slice().reverse().map(p=>`<div class="pk"><b class="p-${p.proto}" style="color:${PC[p.proto]||"#889"}">${(p.proto+"    ").slice(0,4)}</b> ${esc(p.summary)}</div>`).join("");
 $("talkers").innerHTML="<tr><th>Host</th><th>packets</th></tr>"+S.talkers.map(([ip,c])=>`<tr><td class="mono">${esc(ip)}</td><td>${c}</td></tr>`).join("");
}
tick();setInterval(tick,700);
</script></body></html>"""
