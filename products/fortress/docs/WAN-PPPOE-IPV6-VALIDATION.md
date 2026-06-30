# Fortress Direct-Fiber WAN: PPPoE + IPv6-PD + LAN RA + RA-Guard — Validation Record

**Status:** validated live on the reference Fortress (Digi RO fiber), 2026-06-30
**Scope:** direct-fiber WAN where the ONT Ethernet is wired straight into the
Fortress WAN NIC and the ISP CPE (Kaon) is bypassed.
**Purpose:** this is the v1 record of *what was tested and what was proven*, so the
v2 rebuild can do it cleaner without re-discovering the same facts. Every claim
below is backed by a live command run during bring-up.

> v2 intent: fold all of this into a first-class, prompt-driven WAN-mode in the
> installer (DHCP vs PPPoE), with NAT/PBR/IPv6 handled as one coherent module
> instead of the layered live-built stack documented here. Until then, v1 is
> reproduced by `devices/common/wan-pppoe-setup.sh` + this doc.

---

## 1. Components

| # | Function | Live artifact | Repo source |
|---|----------|---------------|-------------|
| 1 | PPPoE client (ppp0) | `/etc/ppp/peers/ftth`, `fts-pppoe.service`, chap/pap-secrets | `wan-pppoe-setup.sh` |
| 2 | DHCPv6-PD retry client | `/etc/wide-dhcpv6/dhcp6c.conf`, `fts-dhcp6c.service`, `dhcp6c_duid` | `wan-pppoe-setup.sh` |
| 3 | LAN IPv6 RA/SLAAC | `/etc/dnsmasq.d/fts-ipv6.conf` | `wan-pppoe-setup.sh` |
| 4 | IPv6 fwd + accept_ra | `/etc/sysctl.d/99-fortress-ipv6-lan.conf` | `wan-pppoe-setup.sh` |
| 5 | PPP reconnect hook | `/etc/ppp/ip-up.d/60-fts-ipv6` | `wan-pppoe-setup.sh` |
| 6 | WAN firewall (v4+v6) | `/etc/hookprobe/wanguard.nft`, `fts-wanguard.service` | `wan-pppoe-setup.sh` |
| 7 | LAN RA-Guard | OVS OpenFlow on `FTS` | `ovs-post-setup.sh` |
| — | WAN failover / NAT on ppp0 | `wan-failover.conf` `PRIMARY_IFACE=ppp0` | `wan-failover-pbr.sh` (pre-existing) |

Secrets (PPPoE password, ISP DUID) live in `/etc/hookprobe/wan-pppoe.conf` and
`/etc` only — never committed. The repo ships `wan-pppoe.conf.example`.

---

## 2. ISP facts (Digi RO, reference site)

- **PPPoE**: untagged on the WAN NIC, MTU/MRU 1492. Public-or-CGNAT IPv4 is
  assigned **per session** (seen both `82.76.x` public and `100.102.x` CGNAT).
- **IPv6**: RA on ppp0 has M-bit set, no prefix option (addressing via DHCPv6).
  - **IA_PD `/56` delegated** (`2a02:2f05:d308:b900::/56`, infinite lifetime).
  - IA_NA `/128` WAN addr with IID = hex of the IPv4.
  - History: PD returned **zero** DHCPv6 responses 06-16/06-17 (ISP-side), then
    started answering on a 06-30 reconnect. Treat PD as **session-dependent** —
    the retry daemon (`fts-dhcp6c`) exists precisely so it auto-acquires whenever
    the ISP decides to answer.

---

## 3. Validation results (live evidence)

### 3.1 PPPoE / failover — ✅
- `ip -br addr show ppp0` → public IPv4 `82.76.168.226`, peer gw.
- `wan-failover.state`: `ACTIVE_WAN=primary`, clean failback after a carrier
  loss (enp1s0 `NO-CARRIER` → LTE → fiber restored → primary). LTE backup
  (Vodafone RO `213.233.109.137`, 35 ms) verified carrying traffic during outage.

### 3.2 IPv6-PD + LAN SLAAC — ✅
- `dhcp6c` log: `IA_PD prefix 2a02:2f05:d308:b900::/56`, then
  `add an address 2a02:2f05:d308:b900:…/64 on FTS`. `sla-len 8` correct for /56.
- Box v6: `ping6 2606:4700:4700::1111` 0% loss.
- dnsmasq RA confirmed from the **Fortress** link-local `fe80::14d8:6aff:feb3:4843`
  (length 120 = prefix + RDNSS).
- **3 LAN clients auto-configured GUAs** in the prefix (`ip -6 neigh … REACHABLE`).
- A LAN client reaching the v6 internet confirmed via conntrack (QUIC/443,
  state `ASSURED`).

### 3.3 WAN firewall (`fortress_wanguard`) — ✅ (rule + behavior verified)
- `inet` family → covers **both** v4 and v6 in one ruleset.
- `forward`/`input`: `iifname {ppp0,wwan0} ct state new → drop`; `established,related accept`.
- conntrack confirmed actively tracking IPv6 → the `ct state new` drop genuinely
  applies to inbound v6 (not just v4).
- Input drop counter observed **climbing live** on real WAN scan traffic.
- Public IPv6 = no NAT → default-deny inbound is **mandatory** and is in place.
- ⚠️ **Not yet run:** a live external-origin inbound IPv6 SYN landing on the drop
  counter — no IPv6 vantage was available (MSSP has no v6; check-host/hackertarget
  reject v6 literals / need a key). To close in v2: `curl -6 http://[<LAN-GUA>]/`
  from a phone on cellular, expect timeout.

### 3.4 RA-Guard (LAN bridge) — ✅
- **Finding:** the Apple **HomePod** ("hooksound", `10.200.0.12`,
  `40:ed:cf:82:62:6b`, OUI Apple) acts as a Thread/HomeKit border router and
  emits RAs from `fe80::104c:45a8:f14c:ecde`, even re-advertising the delegated
  prefix. Not malicious — classic Apple RA pollution — but it pollutes LAN
  clients' router/prefix state.
- **Fix:** OVS OpenFlow RA-Guard on `FTS` — allow ICMPv6 RA (134) only from the
  `LOCAL` port (dnsmasq), drop RA + Redirect (137) from all client ports.
- **Proven:** allow rule (`in_port=LOCAL`) counter incremented on the Fortress's
  own RA; drop rule counter incremented on a HomePod RA within ~1 min. dnsmasq's
  RA still floods to clients (allow-path), HomePod RA dropped at ingress.

---

## 4. NOT yet validated

- **Fresh `./install.sh` reproduction.** The setup script mirrors the verified
  live config exactly, but a full fresh install was **not** run (can't reinstall
  the production box). The installer hook is guarded by the presence of
  `/etc/hookprobe/wan-pppoe.conf`, so the default DHCP-WAN path is unaffected.
- **NAT on ppp0 in a fresh install.** `wan-pppoe-setup.sh` does **not** set up
  masquerade/PBR — that is owned by `wan-failover-pbr.sh`, which requires
  `wan-failover.conf` `PRIMARY_IFACE=ppp0`. A fresh PPPoE install must set that
  (the live box has it). v2 should unify these.
- **DUID-forcing path** in the script (`PD_DUID`) is logically equivalent to the
  live `dhcp6c_duid` but was not exercised by the script itself.

---

## 5. Reproduce on a fresh box

```bash
sudo cp products/fortress/devices/common/wan-pppoe.conf.example /etc/hookprobe/wan-pppoe.conf
sudo chmod 600 /etc/hookprobe/wan-pppoe.conf
sudo $EDITOR /etc/hookprobe/wan-pppoe.conf          # PPPoE creds, sla-len, optional DUID
sudo ./install.sh                                   # hook auto-runs wan-pppoe-setup.sh
# then ensure WAN failover treats ppp0 as primary:
sudo sed -i 's/^PRIMARY_IFACE=.*/PRIMARY_IFACE="ppp0"/' /etc/hookprobe/wan-failover.conf
sudo systemctl restart fts-wan-failover
```
Verify: `ip -br addr show ppp0`, `ip -6 addr show FTS | grep global`,
`ovs-ofctl dump-flows FTS | grep icmp_type=134`,
`nft list table inet fortress_wanguard`.

---

## 6. v2 migration checklist (do better)

- [ ] First-class installer WAN-mode prompt: `dhcp` | `pppoe` (not a side-file flag).
- [ ] One WAN module owning PPPoE + NAT + PBR + IPv6 (no split with wan-failover).
- [ ] DHCPv6-PD: handle variable delegation size (auto-derive `sla-len` from the
      granted prefix length instead of a static guess).
- [ ] IPv6 firewall: add an explicit external-origin inbound test to the install
      validator (the one gap in §3.3).
- [ ] RA-Guard + DHCPv6-Guard (drop client udp6 sport 547) as standard LAN policy,
      not WAN-specific. Consider per-port instead of LOCAL-only as port topology grows.
- [ ] Persist OVS RA-Guard flows against the dynamic SDN/autopilot flow rebuilds
      (currently re-applied by `ovs-post-setup.sh`).
