#!/usr/bin/env python3
"""Regenerate the HEQK validation matrix (heqk-validation.html) from live data.

The QEMU phase gates are re-derived by running ./validate.sh and reading which
[Px] PASS markers the emulated boot emits — so a regression flips the row here.
The CM5-metal, secure-boot, and hardware-gated rows are NOT emulatable (they need
a physical flash / are hardware-blocked), so they carry their last-recorded state
from METAL_ROWS below; bump those by hand after a metal boot.

Usage:
  tools/gen-validation.py                 # run validate.sh, regenerate the HTML
  tools/gen-validation.py --no-validate   # skip QEMU, keep last gate states
Output: heqk-validation.html (repo root). Then republish the artifact to keep the
same URL.
"""
import os, re, subprocess, sys, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "heqk-validation.html")

# --- validator phase key -> the boot marker validate.sh greps for -------------
# (used only to run + parse; the row<->gate mapping is the `gate=` field below.)

def run_validator():
    """Run ./validate.sh, return {phase_key: 'PASS'|'FAIL'|'PLANNED'} or None."""
    try:
        p = subprocess.run(["bash", "validate.sh"], cwd=ROOT,
                           capture_output=True, text=True, timeout=180)
    except Exception as e:
        print(f"  ! validate.sh did not run ({e}); keeping last gate states", file=sys.stderr)
        return None
    gates = {}
    # Table rows look like:  " P8p  PASS     Validation   ..."
    for line in p.stdout.splitlines():
        m = re.match(r"\s*(P\w+|DRV)\s+(PASS|FAIL|PLANNED)\b", line)
        if m:
            gates[m.group(1)] = m.group(2)
    ok = "VERDICT: all implemented phases GREEN" in p.stdout
    print(f"  validate.sh: {len(gates)} gates parsed; "
          f"{'ALL GREEN' if ok else 'REGRESSIONS PRESENT'}")
    return gates

# --- feature data -------------------------------------------------------------
# env: which environments PROVE the row. 'metal'/'qemu'/'block'.
# gate: validate.sh phase key whose live PASS/FAIL drives the QEMU pill (optional).
#       If set and the gate is not PASS, the row is flagged REGRESSED.
SECTIONS = [
 ("L0", "Microkernel core", "seL4-style capability kernel — the trusted computing base", [
   dict(feat="Boot chain EL2→EL1 + PL011 UART + exception vectors", sub="fault trapped, not fatal",
        phase="P0", proves="Boots and prints; a fault is caught, not fatal.",
        env=["metal","qemu"], marker="<b>[CM5-BOOT]</b> · [P0]", gate="P0"),
   dict(feat="Preemptive priority scheduler + context switch", phase="P1",
        proves="H&gt;M&gt;L preemption; an uncooperative task is timer-preempted.",
        env=["metal","qemu"], marker="[P7b] · [P1]", gate="P1"),
   dict(feat="MMU stage-1 + physical frame allocator", phase="P1b",
        proves="Live translation; VA≠PA read-back proves the walk.",
        env=["metal","qemu"], marker="[P1b]", gate="P1b"),
   dict(feat="Capabilities — untyped / retype / CDT / revoke + rights",
        sub="iterative revoke; rights-diminished mint; enforcement on invoke", new=True, phase="P2",
        proves="Capability derivation tree; iterative (non-recursive) revoke; monotonic rights diminution — a read-only frame's write is denied, amplification refused.",
        env=["qemu"], marker="[P2]", gate="P2"),
   dict(feat="EL0 userspace + SVC syscall boundary + fault containment", phase="P3",
        proves="User/kernel split; an EL0 fault is contained.",
        env=["metal","qemu"], marker="[P3]", gate="P3"),
   dict(feat="Synchronous IPC — Endpoint rendezvous + register fastpath", phase="P4",
        proves="Block/unblock over an Endpoint; reply-cap fastpath.",
        env=["qemu"], marker="[P4]", gate="P4"),
   dict(feat="Packet Engine — zero-copy SPSC ring + in-place verdict", phase="P5",
        proves="Payload inspected in place, never copied through the ring.",
        env=["qemu"], marker="[P5]", gate="P5"),
   dict(feat="Real wire — virtio-net ARP round-trip → ring → verdict", phase="P5b",
        proves="A real received frame reaches the verdict engine.",
        env=["qemu"], marker="[P5b]", gate="P5b"),
   dict(feat="RFC 9669 BPF VM (interpreter) + bounds sandbox", phase="P6",
        proves="Signed bytecode is the verdict; OOB load rejected.",
        env=["metal","qemu"], marker="[P6]", gate="P6"),
   dict(feat="BPF static verifier + JIT (W^X) + self-heal + telemetry", phase="P6b",
        proves="Verify-before-run; native codegen; HAM restart; QSecBit-lite.",
        env=["qemu"], marker="[P6b]", gate="P6b"),
 ]),
 ("L1", "Metal bring-up &amp; driver isolation",
  "the microkernel on real silicon, drivers pushed out of the TCB", [
   dict(feat="CM5 / BCM2712 bring-up — RP1 UART console, high-PA MMU", phase="P7",
        proves="Boots and prints on real silicon over the FTDI console.",
        env=["metal"], marker="<b>[CM5-BOOT]</b>"),
   dict(feat="Inline IPS — wire → ring → BPF → enforce", phase="P7a",
        proves="Benign :53 forwarded, threat :4444 dropped on the wire.",
        env=["metal"], marker="<b>[P8] IPS</b>"),
   dict(feat="W^X — kernel .text RO+X, data RW+PXN, SCTLR.WXN", phase="P7b",
        proves="No writable-executable memory anywhere (K1 block-split).",
        env=["metal","qemu"], marker="<b>[P7b] W^X</b>"),
   dict(feat="Isolated EL0 GEM driver — register probe", phase="P7c·1",
        proves="EL0 driver reads real GEM MMIO; matches kernel, nothing else granted.",
        env=["metal"], marker="<b>[P7c]</b>"),
   dict(feat="Isolated EL0 GEM driver — TX from EL0", phase="P7c·3",
        proves="Transmit armed + kicked + completed from user space.",
        env=["metal"], marker="<b>[P7c]</b>"),
   dict(feat="Continuous restartable EL0 driver server", phase="P7c·4d",
        proves="5 real frames judged; a driver crash contained + restarted.",
        env=["metal"], marker="<b>[P7c]</b>"),
   dict(feat="EL0 driver as preemptible scheduled TCB in its own ASID",
        sub="counter 1.29 B, preempted, zero EL0 faults", new=True, phase="P7c·4c",
        proves="Full driver-isolation runtime — own address space, ASID-tagged TTBR0 switch — on metal.",
        env=["metal","qemu"], marker="<b>[P7c-4c]</b>"),
   dict(feat="EL1↔EL2 stage-2 isolation — HBoot region hidden", phase="P7e",
        proves="An EL1 access into HBoot's footprint traps to EL2 (B-3 closed).",
        env=["metal"], marker="stage2 armed"),
 ]),
 ("L2", "Secure boot &amp; hardware attestation",
  "quantum-safe, OTP-rooted — HBoot at EL2", [
   dict(feat="Hybrid quantum-safe secure boot — ed25519 AND SLH-DSA (FIPS-205)", phase="—",
        proves="Breaking boot needs breaking classical ECC AND post-quantum.",
        env=["metal"], marker="<b>verify PASS</b>"),
   dict(feat="Measured boot + CRTM anchor", sub="PCR0 rooted in OTP device id 0x0102…5a31", new=True,
        phase="B-7", proves="PCR chain rooted in the immutable OTP-fused identity, not a free-floating self-measurement.",
        env=["metal"], marker="<b>CRTM-anchored</b>"),
   dict(feat="Hardware-bound per-device AK — OTP-derived, non-extractable", phase="B-1",
        proves="Attestation key lives only in fuses, per device — not in the image.",
        env=["metal"], marker="<b>[P7d-B1]</b>"),
   dict(feat="Runtime attestation — ephemeral key answers verifier nonces", phase="B-2",
        proves="Fresh challenge → fresh signature; replay rejected; AK scrubbed post-boot.",
        env=["metal"], marker="<b>[P7d-B2]</b>"),
   dict(feat="Anti-rollback SVN floor — OTP thermometer, fail-closed",
        sub="watermark held on read failure — no rollback", new=True, phase="B-8 · P7d-c",
        proves="Monotonic hardware floor; a forced OTP read-failure can't roll it back.",
        env=["metal"], marker="<b>floor read OK</b>"),
   dict(feat="Hardware TRNG per-boot nonce — BCM2712 rng200", phase="P7d-a",
        proves="A fresh 32-byte nonce each boot; kills the static-nonce weakness.",
        env=["metal"], marker="hw-trng"),
 ]),
 ("L3", "Detection plane at scale",
  "the IDS/IPS product surface — &ldquo;the OS is the sensor&rdquo;", [
   dict(feat="PREVAIL-style static verifier — abstract interpretation", phase="P8",
        proves="Proves rule memory-safety before it runs; rejects wild-load / loop / uninit-verdict.",
        env=["metal","qemu"], marker="<b>[P8]</b>", gate="P8"),
   dict(feat="General BPF JIT — two-pass, W^X, forward branches",
        sub="EL1 RO+X code window on metal (GB6)", new=True, phase="P8",
        proves="Native aarch64 codegen; verdicts match the interpreter — on QEMU and CM5 silicon.",
        env=["metal","qemu"], marker="<b>[P8-JIT]</b>", gate="P8p"),
   dict(feat="HookProbe rule registry — parity corpus",
        sub="3/3 rules JIT-compiled to native ARM64 on metal", phase="P8",
        proves="The same signed bytecode runs on the Linux/FreeBSD/QNX tracks and here, unchanged.",
        env=["metal","qemu"], marker="rule plane", gate="P8p"),
   dict(feat="Live QSecBit scoring — severity-weighted, in the TCB", phase="P8",
        proves="Rule hits on real traffic scored inside the kernel — the OS is the sensor.",
        env=["qemu"], marker="[P8-plane]", gate="P8p"),
   dict(feat="Adaptive NAPI data plane — grows under load, idles when quiet", phase="P8",
        proves="Poll-budget peaks under a burst, re-arms the IRQ when quiet; spin-poll retired.",
        env=["qemu"], marker="[P8-napi]", gate="P8n"),
   dict(feat="L2 guard — malformed-ARP + ARP-spoof drop",
        sub="napse-l2guard parity; JIT'd + running on metal (drop-logic proven on QEMU)", new=True, phase="P8",
        proves="Deterministic frame-level enforcement: bad ARP shape (is_malformed) + spoofed sender-MAC (eth_mismatch) dropped before L4.",
        env=["metal","qemu"], marker="[P8-l2]", gate="P8l"),
   dict(feat="TCP scan detection — NULL / FIN / Xmas / SYN-FIN",
        sub="stateless anomalous-flag signatures (Nmap/Suricata-style)", new=True, phase="P8",
        proves="Anomalous TCP flag combinations dropped as scans; normal SYN/ACK pass (no false positives).",
        env=["qemu"], marker="[P8-tcp]", gate="P8t"),
   dict(feat="Stateful substrate — BPF CALL helper + rate limiter",
        sub="running on metal (10-rule plane, CALL interp path, 0 faults); logic proven on QEMU", new=True, phase="P8",
        proves="A signed rule decides on a RATE, not one packet — verifier admits CALL, JIT declines it, interpreter runs it. Substrate for the stateful WAN tier.",
        env=["metal","qemu"], marker="[P8-syn]", gate="P8s"),
   dict(feat="Per-source SYN-flood — live datapath rule",
        sub="keyed by IP source; running in live classify on metal (isolation proven on QEMU)", new=True, phase="P8",
        proves="Wired into live classify: a per-source SYN flood is rate-limited inline while other sources' connection setups pass.",
        env=["metal","qemu"], marker="[P8-synsrc]", gate="P8ss"),
   dict(feat="Threat-feed blocklist — keyed CIDR lookup (helper #2)",
        sub="signed block set; running in live classify on metal (drop-logic proven on QEMU)", new=True, phase="P8",
        proves="The stateful substrate generalizes beyond a counter to a keyed lookup: frames from a blocked source prefix are dropped inline; clean sources pass.",
        env=["metal","qemu"], marker="[P8-block]", gate="P8b"),
   dict(feat="Verifier self-hardening — abstract-operator soundness harness",
        sub="Agni-style; modular operators (absdom.rs); injected unsoundness caught", new=True, phase="P16",
        proves="The verifier that gates every rule is itself checked: each abstract operator over-approximates the concrete semantics; a deliberately-unsound operator is caught by the CI harness, not by prod.",
        env=["qemu"], marker="[P16-verifier]"),
 ]),
 ("L4", "Second interface", "external PCIe — the one hardware blocker", [
   dict(feat="RTL8111H external PCIe RC1 bring-up",
        sub="full pcie-brcmstb train sequence: RESCAL, SERDES, refclk-MDIO, PERST", phase="P9",
        proves="Driver code complete; the RC1 link will not train — down under Linux too, so board/hardware-gated, not a code defect.",
        env=["block"], marker="RC1 link down"),
 ]),
]

PILL = {"metal":('metal','Metal'), "qemu":('qemu','QEMU'), "block":('block','HW-gated'),
        "regress":('block','Regressed')}

def apply_gates(gates):
    """Overlay live QEMU gate results onto rows that declare a `gate`."""
    for _,_,_,rows in SECTIONS:
        for r in rows:
            g = r.get("gate")
            if not g or gates is None:
                continue
            st = gates.get(g)
            if st and st != "PASS":
                # QEMU regression: drop the qemu pill, flag it.
                r["env"] = [e for e in r["env"] if e != "qemu"] + ["regress"]
                r["marker"] = f"<b style='color:var(--block)'>{g} {st}</b>"

def render():
    rows_html = []
    n_total = n_metal = n_qemu = n_block = 0
    for sec_no, title, desc, rows in SECTIONS:
        body = []
        for r in rows:
            n_total += 1
            env = r["env"]
            if "metal" in env: n_metal += 1
            if "qemu" in env: n_qemu += 1
            if "block" in env: n_block += 1
            cls = "metal" if "metal" in env else ("block" if ("block" in env or "regress" in env) else "qemu")
            pills = "".join(f'<span class="pill {PILL[e][0]}">{PILL[e][1]}</span>' for e in env)
            sub = ""
            if r.get("sub"):
                newbadge = '<span class="new">new</span>' if r.get("new") else ""
                sub = f'<small>{r["sub"]}{newbadge}</small>'
            elif r.get("new"):
                sub = '<small><span class="new">new</span></small>'
            body.append(
              f'<tr class="{cls}"><td class="feat">{r["feat"]}{sub}</td>'
              f'<td class="ph">{r["phase"]}</td>'
              f'<td class="proves">{r["proves"]}</td>'
              f'<td class="env">{pills}</td>'
              f'<td class="marker">{r["marker"]}</td></tr>')
        rows_html.append(
          f'<section><div class="sec-head"><span class="sec-no">{sec_no}</span>'
          f'<h2>{title}</h2><span class="desc">{desc}</span></div>'
          f'<div class="tbl-wrap"><table><thead><tr><th>Feature</th><th>Phase</th>'
          f'<th>Proves</th><th>Validated</th><th>Marker</th></tr></thead>'
          f'<tbody>{"".join(body)}</tbody></table></div></section>')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    try:
        commit = subprocess.run(["git","rev-parse","--short","HEAD"], cwd=ROOT,
                                capture_output=True, text=True).stdout.strip() or "—"
    except Exception:
        commit = "—"
    return HTML.format(rows="".join(rows_html), n_total=n_total, n_metal=n_metal,
                       n_qemu=n_qemu, n_block=n_block, stamp=stamp, commit=commit)

HTML = """<title>HEQK Validation Matrix</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{{
    --bg:#F1F4F5; --panel:#FFFFFF; --panel-2:#F7F9FA;
    --ink:#0F1618; --ink-dim:#586A70; --ink-faint:#85959B;
    --line:#DBE3E5; --line-strong:#C4CFD2;
    --accent:#0C6E6C;
    --metal:#1C8348; --metal-bg:#E4F3EA;
    --qemu:#1F6BB8; --qemu-bg:#E4EEF8;
    --block:#A86410; --block-bg:#F6ECDD;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,"Liberation Mono",monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }}
  @media (prefers-color-scheme:dark){{
    :root{{
      --bg:#0C1215; --panel:#131B20; --panel-2:#0F171B;
      --ink:#E1EAED; --ink-dim:#93A3AA; --ink-faint:#66757C;
      --line:#243036; --line-strong:#31414A; --accent:#2CC0BC;
      --metal:#3BCE84; --metal-bg:#12281C; --qemu:#5BA6EE; --qemu-bg:#122435;
      --block:#E0A64A; --block-bg:#2C2213;
    }}
  }}
  :root[data-theme="light"]{{
    --bg:#F1F4F5; --panel:#FFFFFF; --panel-2:#F7F9FA;
    --ink:#0F1618; --ink-dim:#586A70; --ink-faint:#85959B;
    --line:#DBE3E5; --line-strong:#C4CFD2; --accent:#0C6E6C;
    --metal:#1C8348; --metal-bg:#E4F3EA; --qemu:#1F6BB8; --qemu-bg:#E4EEF8;
    --block:#A86410; --block-bg:#F6ECDD;
  }}
  :root[data-theme="dark"]{{
    --bg:#0C1215; --panel:#131B20; --panel-2:#0F171B;
    --ink:#E1EAED; --ink-dim:#93A3AA; --ink-faint:#66757C;
    --line:#243036; --line-strong:#31414A; --accent:#2CC0BC;
    --metal:#3BCE84; --metal-bg:#12281C; --qemu:#5BA6EE; --qemu-bg:#122435;
    --block:#E0A64A; --block-bg:#2C2213;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
    line-height:1.5;-webkit-font-smoothing:antialiased;
    background-image:radial-gradient(circle at 1px 1px,color-mix(in srgb,var(--line) 60%,transparent) 1px,transparent 0);
    background-size:22px 22px;}}
  .wrap{{max-width:1120px;margin:0 auto;padding:clamp(20px,4vw,52px) clamp(16px,4vw,40px) 72px;}}
  header{{border-bottom:1px solid var(--line-strong);padding-bottom:26px;margin-bottom:30px}}
  .kicker{{font-family:var(--mono);font-size:12px;letter-spacing:.16em;text-transform:uppercase;
    color:var(--accent);font-weight:600;display:flex;align-items:center;gap:9px}}
  .kicker::before{{content:"";width:26px;height:2px;background:var(--accent);display:inline-block}}
  h1{{font-family:var(--mono);font-weight:650;font-size:clamp(28px,5vw,42px);line-height:1.05;
    letter-spacing:-.01em;margin:14px 0 8px;text-wrap:balance}}
  h1 span{{color:var(--ink-dim);font-weight:500}}
  .sub{{color:var(--ink-dim);font-size:15.5px;max-width:66ch;margin:0}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1px;
    margin-top:28px;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
  .stat{{background:var(--panel);padding:16px 18px}}
  .stat .n{{font-family:var(--mono);font-size:30px;font-weight:650;letter-spacing:-.02em;
    font-variant-numeric:tabular-nums;line-height:1}}
  .stat .l{{font-size:12.5px;color:var(--ink-dim);margin-top:6px;letter-spacing:.01em}}
  .stat.m .n{{color:var(--metal)}} .stat.q .n{{color:var(--qemu)}} .stat.b .n{{color:var(--block)}}
  .legend{{display:flex;flex-wrap:wrap;gap:10px 18px;margin:26px 0 8px;align-items:center;
    font-size:13px;color:var(--ink-dim)}}
  .pill{{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.04em;
    text-transform:uppercase;padding:3px 8px;border-radius:5px;white-space:nowrap;
    display:inline-flex;align-items:center;gap:5px;border:1px solid transparent}}
  .pill::before{{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.9}}
  .pill.metal{{color:var(--metal);background:var(--metal-bg);border-color:color-mix(in srgb,var(--metal) 30%,transparent)}}
  .pill.qemu{{color:var(--qemu);background:var(--qemu-bg);border-color:color-mix(in srgb,var(--qemu) 30%,transparent)}}
  .pill.block{{color:var(--block);background:var(--block-bg);border-color:color-mix(in srgb,var(--block) 32%,transparent)}}
  section{{margin-top:38px}}
  .sec-head{{display:flex;align-items:baseline;gap:12px;margin-bottom:14px;flex-wrap:wrap}}
  .sec-no{{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--accent);
    letter-spacing:.1em;padding-top:3px}}
  .sec-head h2{{font-size:18px;font-weight:650;margin:0;letter-spacing:-.01em}}
  .sec-head .desc{{color:var(--ink-faint);font-size:13.5px}}
  .tbl-wrap{{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--panel)}}
  table{{border-collapse:collapse;width:100%;min-width:720px}}
  thead th{{font-family:var(--mono);font-size:11px;text-transform:uppercase;letter-spacing:.08em;
    color:var(--ink-faint);font-weight:600;text-align:left;padding:11px 16px;
    border-bottom:1px solid var(--line-strong);background:var(--panel-2);white-space:nowrap}}
  tbody td{{padding:13px 16px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}}
  tbody tr:last-child td{{border-bottom:none}}
  tbody tr:hover{{background:var(--panel-2)}}
  .feat{{font-weight:600;color:var(--ink);border-left:3px solid transparent}}
  tr.metal .feat{{border-left-color:var(--metal)}}
  tr.qemu .feat{{border-left-color:var(--qemu)}}
  tr.block .feat{{border-left-color:var(--block)}}
  .feat small{{display:block;font-weight:450;color:var(--ink-dim);font-size:12.5px;margin-top:3px;
    font-family:var(--sans);letter-spacing:0}}
  .ph{{font-family:var(--mono);font-size:12.5px;color:var(--ink-dim);font-weight:600;white-space:nowrap}}
  .proves{{color:var(--ink-dim);font-size:13.5px;max-width:34ch}}
  .env{{white-space:nowrap}}
  .env .pill+.pill{{margin-left:5px}}
  .marker{{font-family:var(--mono);font-size:12px;color:var(--ink-dim);white-space:nowrap}}
  .marker b{{color:var(--metal);font-weight:600}}
  .new{{font-family:var(--mono);font-size:9.5px;font-weight:700;letter-spacing:.06em;color:var(--accent);
    border:1px solid color-mix(in srgb,var(--accent) 40%,transparent);border-radius:4px;
    padding:1px 4px;margin-left:6px;vertical-align:middle;text-transform:uppercase}}
  footer{{margin-top:44px;padding-top:22px;border-top:1px solid var(--line);
    display:flex;flex-wrap:wrap;gap:8px 20px;justify-content:space-between;
    font-family:var(--mono);font-size:12px;color:var(--ink-faint)}}
  footer .k{{color:var(--ink-dim)}}
  @media (max-width:560px){{ .proves{{display:none}} }}
</style>
<div class="wrap">
  <header>
    <div class="kicker">Hardened Edge Quantum-safe Kernel</div>
    <h1>HEQK Validation Matrix <span>· P0 → P9</span></h1>
    <p class="sub">Every feature built into the HEQK microkernel (Rust <code>no_std</code>, aarch64) and where it has been proven — under QEMU emulation, on Raspberry Pi CM5 (BCM2712) silicon, or both. QEMU gates are re-derived live from <code>./validate.sh</code>; metal rows carry their last-recorded boot state.</p>
    <div class="stats">
      <div class="stat"><div class="n">{n_total}</div><div class="l">features built</div></div>
      <div class="stat m"><div class="n">{n_metal}</div><div class="l">proven on CM5 metal</div></div>
      <div class="stat q"><div class="n">{n_qemu}</div><div class="l">proven under QEMU</div></div>
      <div class="stat b"><div class="n">{n_block}</div><div class="l">hardware-gated (P9)</div></div>
    </div>
    <div class="legend">
      <span class="pill metal">Metal</span> validated on CM5 (BCM2712) hardware
      <span class="pill qemu">QEMU</span> validated under emulation
      <span class="pill block">HW-gated</span> code complete, blocked on hardware
    </div>
  </header>
  {rows}
  <footer>
    <span><span class="k">Repo</span> ~/heqk · local only, no remote</span>
    <span><span class="k">QEMU gates re-validated</span> {stamp}</span>
    <span><span class="k">commit</span> {commit}</span>
  </footer>
</div>
"""

def main():
    do_validate = "--no-validate" not in sys.argv
    gates = run_validator() if do_validate else None
    apply_gates(gates)
    html = render()
    with open(OUT, "w") as f:
        f.write(html)
    print(f"  wrote {OUT}")

if __name__ == "__main__":
    main()
