#!/usr/bin/env python3
"""Pi 4 wireless sensor — local read-only dashboard (bench tool).

Serves a single self-contained page + two JSON endpoints over the MANAGEMENT LAN only.
Read-only: no control of the sensor, no writes, GET only. stdlib only (offline-safe on the Pi).
Honesty: the page labels data live / stale / unavailable; this server never fabricates — if a
source is missing it returns an explicit {"available": false}.

Config (env, or /etc/pi4-wsensor/wsensor.conf is NOT sourced here — pass via systemd):
  WSENSOR_DASH_BIND  bind address (default: auto-detect the mgmt IP, else 127.0.0.1)
  WSENSOR_DASH_PORT  default 8099
  WSENSOR_DATA_DIR   default /var/lib/pi4-wsensor
  WSENSOR_DASH_TOKEN_FILE  if the file exists, requests must send ?token=<contents> (simple gate)
Never bind to a public interface; keep it on the management LAN.
"""
from __future__ import annotations

import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DATA_DIR = os.environ.get("WSENSOR_DATA_DIR", "/var/lib/pi4-wsensor")
HEALTH = os.path.join(DATA_DIR, "health.json")
EVENTS_DIR = os.path.join(DATA_DIR, "events")
PORT = int(os.environ.get("WSENSOR_DASH_PORT", "8099"))
TOKEN_FILE = os.environ.get("WSENSOR_DASH_TOKEN_FILE", "/etc/pi4-wsensor/dashboard.token")

_cache: dict = {"events": None, "events_ts": 0}


def mgmt_ip() -> str:
    env = os.environ.get("WSENSOR_DASH_BIND")
    if env:
        return env
    # best-effort: the source IP used to reach the LAN gateway range; fall back to loopback
    for probe in ("10.200.0.1", "192.168.200.1", "10.0.0.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((probe, 9))
            ip = s.getsockname()[0]
            s.close()
            if not ip.startswith("127."):
                return ip
        except OSError:
            continue
    return "127.0.0.1"


def read_health() -> dict:
    try:
        with open(HEALTH) as fh:
            h = json.load(fh)
        h["available"] = True
        return h
    except (OSError, ValueError):
        return {"available": False}


def events_summary() -> dict:
    """Aggregate the most recent event files (bounded) into AP + recent-event views. Cached 5 s."""
    now = time.time()
    if _cache["events"] is not None and now - _cache["events_ts"] < 5:
        return _cache["events"]
    out = {"available": False, "aps": [], "recent": [], "probe_sources": 0, "files": 0}
    try:
        files = sorted(
            (os.path.join(EVENTS_DIR, f) for f in os.listdir(EVENTS_DIR) if f.endswith(".jsonl")),
            key=os.path.getmtime, reverse=True,
        )[:12]  # cap work: newest dozen ring extracts
    except OSError:
        _cache.update(events=out, events_ts=now)
        return out
    aps: dict = {}
    recent: list = []
    probe_sa: set = set()
    for fp in files:
        try:
            with open(fp) as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    k = e.get("kind")
                    if k in ("beacon", "probe_resp"):
                        b = e.get("bssid")
                        if not b:
                            continue
                        a = aps.setdefault(b, {"bssid": b, "ssid": e.get("ssid"),
                                              "security": e.get("security"), "pmf_required": e.get("pmf_required"),
                                              "pmf_capable": e.get("pmf_capable"), "channel": e.get("channel"),
                                              "dbm": e.get("dbm"), "beacons": 0})
                        a["beacons"] += 1
                        if e.get("dbm") is not None:
                            a["dbm"] = e["dbm"]
                        if e.get("ssid"):
                            a["ssid"] = e["ssid"]
                    elif k == "probe_req":
                        if e.get("sa"):
                            probe_sa.add(e["sa"])
                    elif k in ("deauth", "disassoc", "auth"):
                        if len(recent) < 50:
                            recent.append({"ts": e.get("ts"), "kind": k, "bssid": e.get("bssid"),
                                           "sa": e.get("sa"), "reason_code": e.get("reason_code"),
                                           "channel": e.get("channel")})
        except OSError:
            continue
    out = {"available": True, "files": len(files),
           "aps": sorted(aps.values(), key=lambda x: x["beacons"], reverse=True),
           "recent": sorted(recent, key=lambda x: x.get("ts") or 0, reverse=True)[:50],
           "probe_sources": len(probe_sa)}
    _cache.update(events=out, events_ts=now)
    return out


def load_token() -> str | None:
    try:
        with open(TOKEN_FILE) as fh:
            t = fh.read().strip()
            return t or None
    except OSError:
        return None


PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>Pi4 Wireless Sensor</title>
<style>
:root{--bg:#0b0f14;--card:#10161d;--bd:#223;--fg:#e6edf3;--mut:#8aa;--ok:#22c55e;--off:#f59e0b;--bad:#ef4444;--ac:#22d3ee}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif}
header{padding:14px 18px;border-bottom:1px solid var(--bd);display:flex;gap:14px;align-items:baseline;flex-wrap:wrap}
h1{font-size:16px;margin:0}.sub{color:var(--mut);font-size:12px}
main{padding:16px;display:grid;gap:16px;max-width:1100px;margin:0 auto}
.banner{padding:12px 16px;border-radius:10px;font-weight:600;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.on{background:#052e16;color:var(--ok);border:1px solid #14532d}.offb{background:#2a1a02;color:var(--off);border:1px solid #713f12}
.unb{background:#2a0a0a;color:var(--bad);border:1px solid #7f1d1d}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px}
.k{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em}.v{font-size:20px;margin-top:4px;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--bd)}
th{color:var(--mut);font-weight:500;font-size:11px;text-transform:uppercase}td{font-variant-numeric:tabular-nums}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;border:1px solid var(--bd)}
.sec-open,.sec-WEP,.sec-WPA1{color:var(--bad)} .sec-trans{color:var(--off)} .sec-wpa3{color:var(--ok)}
.fresh{font-size:12px}.live{color:var(--ok)}.stale{color:var(--off)}.un{color:var(--bad)}
h2{font-size:13px;color:var(--mut);margin:0 0 8px;text-transform:uppercase;letter-spacing:.04em}
.note{color:var(--mut);font-size:12px;line-height:1.5}
</style></head><body>
<header><h1>Pi 4 Wireless Sensor</h1><span class=sub id=host></span><span class="fresh" id=fresh></span></header>
<main>
<div id=banner class=banner>…</div>
<div class=grid id=stats></div>
<div class=card><h2>Access points observed (this capture window)</h2><div id=aps>…</div></div>
<div class=card><h2>Recent management events (deauth / disassoc / auth)</h2><div id=recent>…</div></div>
<div class=card><h2>Coverage limits</h2><div class=note id=limits>…</div></div>
<div class=note>Read-only bench view. Data is <span class=live>live</span> when the sensor is capturing,
<span class=stale>stale</span> if the last update is old, <span class=un>unavailable</span> if no sensor answers.
Never shows fabricated devices.</div>
</main>
<script>
const Q=new URLSearchParams(location.search), TOK=Q.get('token')?('?token='+encodeURIComponent(Q.get('token'))):'';
const $=id=>document.getElementById(id);
function esc(s){return (s==null?'':''+s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function secClass(s){if(!s)return'';if(s=='OPEN'||s=='WEP'||s=='WPA1')return'sec-open';if((''+s).includes('transition'))return'sec-trans';if((''+s).includes('WPA3'))return'sec-wpa3';return''}
async function tick(){
 let h,ev,ok=true;
 try{h=await (await fetch('api/health'+TOK,{cache:'no-store'})).json()}catch(e){ok=false;h={available:false}}
 try{ev=await (await fetch('api/events'+TOK,{cache:'no-store'})).json()}catch(e){ev={available:false,aps:[],recent:[]}}
 $('host').textContent=h.sensor?('· '+h.sensor+' · '+(h.freq_mhz||'?')+' MHz'):'';
 const b=$('banner');
 if(!h.available){b.className='banner unb';b.innerHTML='<span>SENSOR UNAVAILABLE — no health data</span>';$('fresh').innerHTML='<span class=un>unavailable</span>';}
 else{const age=h.ts?Math.round((Date.now()-Date.parse(h.ts))/1000):999;
  const live=h.coverage=='on'&&age<30;
  $('fresh').innerHTML=live?('<span class=live>live · '+age+'s ago</span>'):('<span class=stale>stale · '+age+'s ago</span>');
  if(h.coverage=='on'){b.className='banner on';b.innerHTML='<span>CAPTURING · '+esc(h.reason)+'</span><span>'+(h.rx_pps||0)+' pps</span>';}
  else{b.className='banner offb';b.innerHTML='<span>COVERAGE OFF · '+esc(h.reason)+'</span><span>lock: '+esc(h.lock_owner||'-')+'</span>';}
  const S=[['channel',(h.freq_mhz||'?')+'/'+(h.width_mhz||'?')],['rx pps',h.rx_pps],['drops',h.rx_dropped],
   ['stalls',h.stalls],['bounces',h.bounces],['yields',h.yields],['coverage',(h.coverage_ratio!=null?(h.coverage_ratio*100).toFixed(1)+'%':'-')],
   ['temp °C',h.temp_c],['disk %',h.disk_used_pct],['uptime',h.uptime_s!=null?Math.floor(h.uptime_s/60)+'m':'-']];
  $('stats').innerHTML=S.map(([k,v])=>'<div class=card><div class=k>'+k+'</div><div class=v>'+esc(v==null?'-':v)+'</div></div>').join('');
  $('limits').textContent=h.limits||'';
 }
 if(ev.available&&ev.aps.length){$('aps').innerHTML='<table><tr><th>BSSID</th><th>SSID</th><th>Security</th><th>PMF</th><th>ch</th><th>dBm</th><th>beacons</th></tr>'+
  ev.aps.map(a=>'<tr><td>'+esc(a.bssid)+'</td><td>'+esc(a.ssid||'(hidden)')+'</td><td class="'+secClass(a.security)+'">'+esc(a.security)+'</td><td>'+(a.pmf_required?'required':a.pmf_capable?'optional':'no')+'</td><td>'+esc(a.channel)+'</td><td>'+esc(a.dbm)+'</td><td>'+esc(a.beacons)+'</td></tr>').join('')+'</table>';}
 else $('aps').innerHTML='<div class=note>'+(ev.available?'no beacons in the current window':'events unavailable')+'</div>';
 if(ev.available&&ev.recent.length){$('recent').innerHTML='<table><tr><th>time</th><th>kind</th><th>bssid</th><th>sa</th><th>reason</th></tr>'+
  ev.recent.map(r=>'<tr><td>'+(r.ts?new Date(r.ts*1000).toLocaleTimeString():'-')+'</td><td>'+esc(r.kind)+'</td><td>'+esc(r.bssid)+'</td><td>'+esc(r.sa)+'</td><td>'+esc(r.reason_code)+'</td></tr>').join('')+'</table>';}
 else $('recent').innerHTML='<div class=note>'+(ev.available?'none observed (no deauth/disassoc bursts)':'events unavailable')+'</div>';
}
tick();setInterval(tick,5000);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "wsensor-dash"

    def _auth_ok(self) -> bool:
        tok = load_token()
        if not tok:
            return True
        q = parse_qs(urlparse(self.path).query)
        return q.get("token", [""])[0] == tok

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if not self._auth_ok():
            self._send(401, b"unauthorized\n", "text/plain")
            return
        if path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/api/health":
            self._send(200, json.dumps(read_health()).encode(), "application/json")
        elif path == "/api/events":
            self._send(200, json.dumps(events_summary()).encode(), "application/json")
        else:
            self._send(404, b"not found\n", "text/plain")

    def log_message(self, *a):  # quiet
        pass


def main() -> None:
    bind = mgmt_ip()
    httpd = ThreadingHTTPServer((bind, PORT), H)
    print(f"wsensor-dashboard on http://{bind}:{PORT} (data={DATA_DIR}, auth={'on' if load_token() else 'off'})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
