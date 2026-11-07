# heqk peer review — 2026-11-06 (WAN, IPv6, policy/VLAN, Wi-Fi AP, persistence)

**Classification: PEER REVIEW** (independent read, not anchored on the author's conclusions).
**Scope:** `1de38c4^..HEAD` on `worktree-heqk-premetal-gaps` before the fixes — 21 commits, 22 files,
+4,811 lines: Wi-Fi AP data path (cyw43), WAN modes (DHCP/static/PPPoE), IPv6 over PPPoE (IPV6CP,
DHCPv6 IA_NA/IA_PD, LAN router + stateful firewall), task #26 (VLAN/QinQ sub-interfaces, management VLAN,
interface-attached ACLs + prefix-lists, metric routes, reject), task #27 (snapshot persistence), RFC 5508
ICMP-error NAT.
**Reviewers:** a security auditor (internet/LAN attack surface) and a correctness reviewer (data path,
link layer, A/B store, parsers), each given the code and the scope — not the author's view. Every finding
below was verified against the code by its reviewer (file:line + quoted code) before being fixed.
**Fixes:** commit `a1816dc` (plus `352ed65` task #27, `09b12e7` RFC 5508, `135dbe8` CI guard).

## Findings and disposition

Legend: **F+R** fixed + QEMU regression case · **F** fixed (no QEMU harness for that path; metal-pending) ·
**O** open (reason given).

| ID | Sev | Finding | Disposition |
|---|---|---|---|
| H1 | high | PPPoE `decap_ipv4/ipv6`: PPPoE length 0/1 -> `f[22..20]` panic; no dst-MAC check + promiscuous GEM -> any host on the WAN segment (SID brute-force) | **F+R** `plen >= 2` + dst MAC; `[P-pppoe]` short/not-to-us frames |
| H2 | high | mgmt ping: total length < IHL+8 -> inverted checksum slice panic; unparseable frame ALLOWED by `mgmt in` | **F** full header validation; facts()==None -> drop |
| H3 | high | `wan in` + block forged RST/ICMP for OTHER hosts' flows on a shared WAN segment | **F** policy only for frames to our MAC + WAN address |
| P1 | high* | `on_lan` copied an IPv6 MSDU > 1614 B into a 1600-B buffer (*if firmware passes such frames) | **F** bounded by `out.len()` |
| SEC-M2 | med | NAT stateful bypass: any remote reached a mapped (sequential) port | **F+R** address-dependent filtering (last 4 remotes per mapping); `[P11-dnsfwd]` |
| SEC-M4 | med | IPv6 flow recorded before policy/IDS -> blocked SYN opened a 10-min pinhole | **F+R** `commit()` after allow+IDS+send; `[P-ip6]` |
| SEC-M3 | med | ICMPv6 errors admitted to any learned LAN host | **F+R** quoted packet must be a live flow of that host; `[P-ip6]` |
| SEC-M5 | med | neighbor-table miss -> `wan in` reject of a legit reply (ADR 0023) | **F** `wan in` only on genuine no-flow. **O (part):** v6 source not bound to the station MAC (v4 has `binding_ok`); table 32 entries, no NS on miss |
| SEC-M1 / COR-M5 | med | rejected POLICY.TXT ran with NO policy (fail-open) | **F** management locked (implicit deny), forwarding unchanged. **O:** POLICY.TXT unsigned (sign like other boot artifacts) |
| COR-M1 | med | full Wi-Fi queue -> WAN drain budget 0 -> PPPoE/ARP/eth1/mgmt starved | **F** drain floor 4 |
| COR-M2 | med | WAN lease down -> end0 never read -> mgmt VLAN + failover deaf | **F** end0 drained for mgmt |
| COR-M3 | med | IPv6 not re-acquired after PPPoE re-dial (stale prefix advertised); no DHCPv6 Renew | **F** reset per dial. **O:** Renew at T1 (Digi delegates infinite lifetimes) |
| COR-M4 | med | control requests (stall kick, periodic sta_info/chanspec) discard queued uplink frames | **F (part)** periodic sta_info removed. **O:** ring for non-control frames in `bcdc_dcmd` |
| SEC-L1 | low | PADT sweep: 1:1 reflector by rotating SIDs / spoofed MAC | **F** global 1/s, only toward our AC |
| SEC-L2 | low | `wan in` rejects unrate-limited (reflection) | **F** 20/s, then drop |
| SEC-L3 | low | IPv6 to own /64, ::, ::1, v4-mapped forwarded to the ISP | **F** dropped |
| SEC-L4 / COR-L3 | low | any ARP repoints the mgmt gateway MAC | **F** replies only |
| SEC-L5 | low | IPV6CP Nak loop unbounded; zero IID accepted | **F** |
| SEC-L6 | low | untagged internet + tagged mgmt: isolation relies on the upstream switch's native-VLAN handling | **O** document; recommend tagged internet when `mgmt_vlan` is set |
| COR-L1 | low | `[STALL-DIAG]` busy-waits ~2 s in the serve loop | **O** fires only if the 100-ms kick fails for 2 s; move behind a diag feature |
| COR-L2 | low | end0 drain ended after 8 filtered frames | **F** 64 |
| COR-L4 | low | A/B store: legacy blob on a read error; re-read failure; gen wrap | **F** |
| COR-L5 | low | `route … via wan gw X` ignores the gw; v6 `wan in allow` cannot admit (firewall first) | **O** document (routes via wan use the WAN's own next hop) |
| COR-L6 | low | a bad SDPCM tag / dropped glom ends the RX burst (250-ms wait); bad tag without rxfail | **O** port brcmfmac's rxfail on a bad tag |
| COR-P1 | plaus. | JML 10240 with 2-KB RX buffers -> frames spanning descriptors | **F** JML 1536 (`enable_vlan_frames`) |
| COR-P2 | plaus. | eMMC volatile cache could reorder the commit header | **O** confirm CACHE_CTRL off or FLUSH before the header |
| COR-P3 | plaus. | `acl_eval` copies a ~1.8-KB Acl per evaluation | **O** perf, measure at 150 Mbps |
| SEC-P2 | plaus. | RFC 5508 path does not un-DNAT DNS-redirect sessions | **O** functional only |
| CI-G5 | — | (found by the gate run) PPPoE self-test literal `const PASS` tripped CI's credential guard | **F** renamed, guard unchanged (`135dbe8`) |

Checked and found sound by the reviewers (abridged): SDPCM credit math vs brcmfmac `data_ok/txctl_ok`
(window clamped to [0,0x40], 2-credit control reserve), TX_SEQ advance only on success, non-blocking
`max_dry 0` (no spin), glom bounds at 48 KB (u16 offsets safe), `sta_info` offsets, RA/DHCPv6 parsers
(checksums, option bounds), `reject4/6` (never answer RST/ICMP errors/multicast; bounded), RFC 5508 bounds,
policy parser (v6 text, host bits, ge/le, ports only for tcp/udp, whole-file rejection, route tie-break),
VLAN demux (wrong VLAN / untagged-when-tagged dropped), A/B store crash consistency at every write boundary.

## End-to-end gate run (at `a1816dc`)

| Gate | Result |
|---|---|
| `kernel/heqk/validate.sh` (QEMU: every implemented phase incl. the p15-write two-boot stage) | **exit 0, 0 failing** — incl. `[P-abstore]`, `[P-ip6]`, `[P-pppoe]`, `[P-policy]`, `[P11-dnsfwd]` with the new regressions |
| CI replay `build-heqk.yml` G2 `prod` / G3 `prod-mc` | build |
| G4 `prod,apmode` must be refused | refused ("cannot be combined with `prod`") |
| G5 no Wi-Fi credential literal in kernel source | clean |
| bench `sepdiag,p15-write` (task #27 self-tests still build) | builds |
| image factory `prod-mc` (bench keys) | **FACTORY PASS**, 8/8 in-image checks (keystore window zero + outside every partition, slot B located by heqk's own fat.rs, OWNER/WAN/POLICY.TXT located) |
| image factory AP + VLAN bench (`hboot,apmode,wifi-bigtx`) | **FACTORY PASS**, 8/8 |
| release `prod-mc` without bench keys | **refused by design** (dev signing keys; production keys under HSM custody do not exist yet) |

Everything in this review is **METAL-PENDING** except what was already proven on metal before it (AP
120–160 Mbps, PPPoE + IPv6 10/10, VLAN + mgmt isolation, route via mgmt both directions).

## Metal regression after the fixes (2026-11-06 afternoon)

| Run | Image | Result |
|---|---|---|
| task #27 A3.3 (prod-mc) | `15f5303` | boot 1 fresh, no bench write in the keystore; persisted boots=1; power-cycle; `M3 RESTORED across reboot` then `persisted: boots=2 … events=2` — **PASS** |
| AP over Digi PPPoE + IPv6 | `ea8716c` | PPPoE first try (hardened decap), IPv6 /56 + IA_NA, LAN numbered; iPhone test-ipv6.com **10/10**, no socket error; ~130 Mbps peak (55k frames/5 s); 7/7 firmware stalls kicked; no panic/exception — **PASS** |

Note (expected, COR-M1): the overload loss point moved from the GEM ring (res_err/overrun now 0) to the
Wi-Fi queue (12,604 of 510,840 = 2.5% dropped, counted) — PPPoE/ARP/eth1/mgmt can no longer starve
behind a full Wi-Fi queue. Still metal-pending: VLAN failover, IPv6 ACLs, mgmt-path fixes (H2, COR-M2).

## Follow-up block (no metal, 2026-11-06 evening) — open items closed

| Item | Commit | Proof |
|---|---|---|
| COR-M4 control requests discard station frames -> 16-frame deferred ring, delivered first by ap_poll | `9a0dc2a` | AP build; METAL-PENDING (no cyw43 QEMU harness); beat `[P11-AP3 defer]` |
| SEC-M5 IPv6 source binding: SAVI first-come-first-served (RFC 6620), NS on neighbor miss, table 64 | `9a0dc2a` | `[P-ip6]`: thief refused; evicted client gets an NS |
| task #26 DHCP on the management VLAN (`mgmt=dhcp`), + a latent boot panic (`mg.stat.unwrap()`) removed | `57883e3` | `[P-policy]` parse; AP build; bench script serves DHCP on VLAN 200 |
| COR-L5 `route … via wan gw X` honours X (ARP next-hop cache; PPPoE = AC) | `efd787b` | AP build |
| COR-L6 corrupt SDPCM tag terminated (rxfail without abort, as brcmfmac hdparse) | `efd787b` | AP build |
| COR-L1 stall snapshot never blocks the serve loop (1-s pairs only with `stalldiag`) | `efd787b` | AP build |
| COR-P2 eMMC CACHE_CTRL read + reported (driver cannot enable it; no CMD6) | `efd787b` | prod-mc build |
| COR-P3 ACL eval by reference | `efd787b` | `[P-policy]` hit counts unchanged |
| SEC-P2 ICMP error for a DNS-redirected query quotes the AP address | `65c39bd` | `[P11-dnsfwd]` |
| task #21 N3 configurable management floor (`mgmt_floor=` / mgmt subnet / reported default) | `b027c36` | `[P-policy]` |
| audit: STA supplicant verifies M3 (MIC ct-compare, ANonce, replay) before M4/key install | `c760d78` | AP + stajoin builds |
| audit: connect-scan gap (proportional establishment hold, est x 8 >= distinct) | `7281bb9` | `[P8]` legit rows unchanged, connect-scan confirmed |
| audit: RFC 1858 tiny / offset-1 TCP fragments -> malformed drop | `7281bb9` | `[P8]` both dropped, legit first fragment passes |
| COR-M3 DHCPv6 PD renewal at T1 | `df77480` | `[P-ip6]` T1/T2 parse + Renew builder |
| SEC-L6 management accepts only an 802.1Q (0x8100) tag | `4b6c977` | AP build |

Still open (design, not patchable in place): **POLICY.TXT signing** — the authority should be the operator
key (the segmentation reach-policy pattern: independent operator Ed25519 + TOFU pin, `[P19-seg-policy]`),
emitted by the AEGIS reconciler — needs an ADR; **IPv6 source key** for scan/conn-rate/shed (the source-keyed
tiers use an IPv4 u32; hashing v6 into it could land in the mgmt floor) — needs an ADR; **UI de-mock** (D3:
deployment-mode badge needs an API field, the dst column a detections schema change — UI + API together,
browser-verified); NAT random external ports (low value now that inbound requires the session's remote, SEC-M2);
SEC-L6 deployment note: prefer a tagged internet VLAN whenever `mgmt_vlan` is set.

## Second independent review (re-review of `a1816dc..ef44f5f`) — classification: PEER REVIEW

Findings on the follow-up fixes themselves, all verified against the code:

| ID | Sev | Finding | Disposition (`6785b5f`) |
|---|---|---|---|
| H1 | high | SAVI bypass: one station floods 64 sources, evicts every binding, claims a victim's address — FCFS then locks the victim out | **F+R** ≤ 8 bindings/MAC; never evict an active (< 5 min) binding of another station; full table refuses the new one; `[P-ip6]` flood |
| M1 | med | bindings not released on deauth (new private MAC refused 30 min) | **F+R** `forget_mac` on Leave; `[P-ip6]` rejoin |
| M2 | med | proportional scan hold gameable by padding stray ACKs (~1 per 8 SYNs) | **O** needs SYN-ACK evidence (bidirectional flow state); on the AP NAT path a naive version flags legit many-port clients (ADR 0023) — design item |
| M3 | med | mgmt DHCP: server pinning never applied, forged NAK drops a bound address, missing router zeroes the gateway | **F** pin, NAK only while requesting from the pinned server, keep gateway, fresh xid |
| M4 | med | `mgmt_floor=/32` rejected and failed ALL of WAN.TXT (internet untagged) | **F+R** /8../32; invalid ignored + reported, never fatal |
| L1 | low | NS unthrottled (multicast airtime storm) | **F** 1/target/s, 20/s total |
| L2 | low | WAN next-hop cache accepted unsolicited replies, never aged | **F** only the reply to our ARP; 5-min TTL |
| L3 | low | mgmt DHCP: gateway not ARPed on bind, no lease expiry, 1-s lease storm | **F** |
| P1 | plaus. | scan-hold regression band for P2P-like clients; distinct-port slot collisions | **O** tied to M2's redesign |
| P2 | plaus. | the floor is keyed on IP, not ingress interface (a spoofed floor source on WAN/eth1) | **O** needs per-interface source validation (with the floor ADR item) |
| P3 | plaus. | DNS un-DNAT too loose | **F** only when quoted dst == the redirect's resolver |
| P4 | plaus. | RFC 1858 IPv4-only | **F** RFC 7112 IPv6 first-fragment check |
| P5 | plaus. | defer-ring ordering vs direct FIFO readers (authenticator) | **O** not a regression (frames were discarded before) |

## Final end-to-end gate run (HEAD `6785b5f`)

`validate.sh` exit 0 — **84 phases PASS, 0 failing** · CI replay: `prod` + `prod-mc` build, `prod,apmode`
refused, no credential literal · bench profiles `sepdiag,p15-write`, `hboot,stajoin`, `hboot,stalldiag`
build · image factory `prod-mc` and AP + VLAN (mgmt DHCP) bench: **FACTORY PASS 8/8** each. Everything in
the follow-up block and the re-review is METAL-PENDING.

## Metal regression of the whole no-metal block (2026-11-07, img `25e5d2c`, Digi PPPoE + iPhone)

PPPoE first try, IPv6 /56 + LAN, internet; iPhone **80–110 Mbps, test-ipv6.com 10/10, no errors**.
IPv6 forwarded 108,347 out / 189,414 in, **SAVI refusals 0** (no false positive under real traffic),
neighbor misses 0, firewall no_flow 1; 12/12 firmware stalls kicked (none reached 2 s); 0 panics; PD renew
correctly idle (infinite lifetimes). Deferred-frame ring: parked 51 = delivered 51, but **ring-full 48** —
16 slots too few during a speed test -> raised to 64 (`DEFER_N`), AP build compiles; re-check next session.

## Background block (no metal, 2026-11-07) — re-review items + design ADR

| Commit | Item | What changed |
|---|---|---|
| `3c6c73c` | metal: ring-full 48 | deferred-frame ring 16 → 64 |
| `c92ed58` | re-review **P2** (partial) | uRPF-lite martian source filter on the internet sub-interface: RFC 1812 martians, our own WAN address, our inside prefixes and the mgmt floor arriving from the WAN are dropped before NAT/policy (`hal::policy::wan_martian4`, `[P-policy]`). Per-interface floor binding beyond the WAN stays an ADR item |
| `2fc7e2e` | **M2 / SEC-M1 / IPv6 tiers** | ADR 0049 **PROPOSED** (operator review): D1 POLICY.TXT signed by the operator key (not the boot key), D2 tagged v4/v6-/64 source identity, D3 scan establishment needs SYN-ACK evidence |
| `acf5087` | review Q2-H1 | responder-sim: `device_fp` = sha256(authenticated device key); a mismatching msg1 claim is refused |
| `1607ee3` | A7.7 + data handling | `[PROD hb] rx_lost` (GEM RX-ring loss), eMMC PRE_EOL/LIFE from EXT_CSD at boot, exported RA-rule (121–123) MAC-derived sources pseudonymised with an HKDF(SRK) HMAC key |
| `d0f4e95` | docs | `kernel/heqk/SECURITY.md`: an accurate heqk data-handling statement; the V1 GDPR section marked as not describing heqk. **ADR 0007 (Apache-2.0) vs LICENSING.md (AGPL-3.0) contradiction flagged, not resolved — operator decision** |
| `HEAD` | UI de-mock D3 (mode badge) | `/api/health` (authenticated) carries `mode`: `cloud-linked` only while the MSSP control-plane session is Established, else `standalone`; TopBar reads it (default kept when the field is absent). Unauthenticated health unchanged. The `dst` column still needs an evidence-schema change |

Gate run at the end of the block: `validate.sh` exit 0 (all implemented phases GREEN); `prod`, `prod-mc`,
`hboot,apmode`, `hboot,stalldiag` release builds OK. The UI change is not typechecked here (no Node on the
build box). Everything in this block is METAL-PENDING.

### Task #21 block (no metal, 2026-11-07, after the operator's "fix all gaps without rpiboot")

- **N4 wall clock on prod-mc.** prod-mc had no time source (epoch 0 → the UI showed 1970). The Mission
  Control node now runs an SNTP client (RFC 4330) on its own UDP socket: the DHCP router first, then
  162.159.200.1 / .123. A reply is accepted only from the server asked, port 123, server mode, LI≠3, stratum
  1..15, Originate == our random nonce, time ≥ 2026-01-01. The first sync moves every pre-sync row; a later
  step > 1 h is refused. `/api/health` reports `clock: ntp|unsynced`. Air-gapped: stays `unsynced` (honest).
  `[P-mc]` covers parse/refusals/row-shift/re-step refusal.
- **D1 detections survive a reboot.** Snapshot events are stamped in wall-clock ms once the clock is known
  (verdict-byte flag; this boot's earlier events converted at sync). On boot the restored ones go back into
  the UI as fixed-time rows (a clock step never moves them). A prior boot that never synced is restored as
  "time unknown" and not shown (counted in the boot line). Snapshot format unchanged. `[P-snapshot]` covers it.
- **D2 on-demand SOAR drain.** One drain body (macro) for the heartbeat and on demand (ring ≥ 1/4 full or
  250 ms): detections reach the UI within ~250 ms instead of up to 5 s, and a burst between heartbeats no
  longer overruns the 64-slot ring.
- **Bench automation.** `tools/cm5-relay.py`: 2-channel USB relay (CH340 "LCUS" serial or HID USBRelay2)
  for power-cycle and rpiboot (asserts nRPIBOOT, cycles, waits for the 0a5c:2712 ROM, releases). Refuses
  the console tty.

Gates: `validate.sh` exit 0 (84 phases PASS); `prod`, `prod-mc`, `hboot,apmode`, `hboot,stalldiag`,
`sepdiag,p15-write`, `hboot,stajoin` build. METAL-PENDING: SNTP against a real router/Internet, restore
across a power cycle, drain latency.

### Metal (2026-11-07 morning, CM5 prod-mc, fortress port 4 = 10.200.0.6)

- `7c1a0fa`: SNTP request well-formed on the wire (NTPv4 client, port 40123), server rotation correct
  (gateway → 162.159.200.123 → gateway, 16 s); fortress NAC `lan_only` dropped the public servers —
  a fortress policy, not a device fault. Synced against a LAN responder on 10.200.0.1. Detections at the
  correct wall time within ~1 s. **D1 metal-proven:** power cycle → `5 detection(s) restored`, the four
  test detections back with identical ms timestamps, unmoved by the later sync; 64/59 never-synced rows
  hidden (counted). eMMC wear PRE_EOL normal, 0–10 %. On the ISP ONT (wrong cable) rx_lost res_err read
  262143 (saturated counter, constant) — report a delta (open item).
- Found: the boot `[P8]` IPS self-test's synthetic :4444 frame (src 0.0.0.0) was recorded as a real
  detection every boot. Fixed `0cf4f3b`; **metal-proven**: `self-test events discarded: 1`, detections 0.
- `0cf4f3b` under NAC `internet_only`: **SNTP synced unaided** from the public server
  (`clock synced by SNTP`), `/api/health` `clock:"ntp"`, API sample within 2.5 s of fortress time.

### Background block 2 (no metal, 2026-11-07, operator: "agile until we need rpiboot")

| Commit | Item | What changed |
|---|---|---|
| `eadd9db` | #10 rx_lost | GEM loss counters baselined at loop entry: boot-time loss (ring unserviced during self-tests; 18-bit counters saturate at 262143) printed once, heartbeat shows runtime loss only |
| `eadd9db` | #12 mgmt queue | only ARP replies + requests for OUR management address are queued (other hosts' who-has broadcasts no longer take slots) |
| `eadd9db` | #13 dst column | `Event` carries dst IPv4 + dport (in former padding: 24 B, existing offsets unchanged; persist/export images unchanged); set per frame in `packet::classify`; `/api/detections` + Detect feed show `src → dst:port` |
| `eadd9db` | #14 P5 | the WPA2 authenticator first takes ITS EAPOL / deauth from the parked ring (others keep order) and parks other stations' frames instead of discarding them; ring moved to `hal::defer` (generic, QEMU `[P11-defer]`) |
| `eadd9db` | UI | left rail: live status pill + device-reported mode on every workspace |
| this | #17 (part) | passive LAN host inventory (256, local only) + retention facts in `/api/health`; home "My Network" / "Timeline" tiles render them on heqk ("Shield" / "Get Online" stay "No data" — no device source yet) |
| — | #11 | WAN routes with a gateway and mgmt routes already existed; the MSS ceiling (1452 PPPoE / 1460) covers mgmt egress — nothing to build. IPv6 on mgmt waits on ADR 0049 D2 |

Gates: `validate.sh` 85 PASS (new `Pdefer`; `Pmc` asserts dst + host inventory), `mc-e2e` PASS incl. browser,
all six kernel profiles build. METAL-PENDING: everything in this block.

### Metal (2026-11-07 08:33, prod-mc `07e2327`, fortress port 4)

**MC-METAL: PASS** (`tools/mc-e2e-metal.sh`, browser leg incl.). Proven on silicon: self-test hit discarded;
boot RX loss reported once (0 on this port) and heartbeat `rx_lost` 0/0; SNTP unaided; `/api/health`
`hosts_active:4` (fortress neighbour table shows 5 other LAN hosts — the passive sensor counts what reaches
its switch port), `sealed_cap:64`, `oldest_detection` set; detections carry dst
(`10.200.0.1 → 10.200.0.6:4444` / `:23`); legit operator traffic served during the attack; home renders
UNDER ATTACK 26 (pill + hero agree), STANDALONE, "4 devices", "14 detections kept · newest 64 sealed".
Cosmetic left: the orb arc stays green under attack.

### AP bench (2026-11-07 08:40–09:30) — task #26 metal backlog

**Phase A** (img `b0dc87f`, fortress port 4: VLAN 100 internet DHCP, VLAN 200 mgmt DHCP, `policy-bench.txt`):
mgmt DHCP lease 192.168.200.146 (server-pinned, bound, acks 2); internet lease 10.100.0.135 tagged; admin ping
4/4 with well-formed replies (the malformed-ping fix) and a non-admin source 0/3 (implicit deny); route
`1.0.0.1/32 via mgmt` — SYNs to 1.0.0.1:400 leave VLAN 200 SNATed to .146; **failover**: VLAN 100 down 45 s →
`wan alive=false`, traffic moved to mgmt (via-mgmt 312 → 45,368, ~5–6k pps), VLAN 100 up → back within 1 s;
operator: iPhone stayed online, speed test never stalled. Deferred ring parked = delivered (122), ring-full 0;
16/16 stalls kicked, none ≥ 2 s; mgmt queue full 0.
**Found + fixed (`7e7bc69`):** the uRPF-lite filter dropped 69 legit SYN-ACKs from the upstream LAN
(10.200.0.3/.12 :7000, AirPlay) — the compile-time default mgmt floor 10.200.0.0/24 = the upstream LAN. The
floor rule now applies only when `mgmt_floor=` is configured AND a mgmt sub-interface exists; `[P-policy]`
regression row. Verified on Phase B (martian 0).
**Phase B** (img `7e7bc69`, Digi PPPoE, `policy-v6.txt`): PPPoE AuthRejected ×8 then Open at retry 9 — the ISP
held the previous (un-PADTed) session from the morning boot; bounded retries recovered unaided.
**test-ipv6.com 10/10**; IPv6 ~107k out / ~379k in, SAVI 0, martian 0; **IPv6 ACL**: `block tcp → [2606:4700:4700::1111]:400`
hit 1 → TCP RST to the client (one SYN, no retries = the reset was accepted). Host check with the device's own
parser/matcher: that packet → `Block, Acl(0, 10)`. Drop rule (Quad9 v6 :53) not exercised (no client used it).
Port 4 restored to FTS (teardown) before Phase B.
