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
