# ADR 0050 — heqk parser placement: which untrusted-input parsers run in EL1, which move to EL0

**Status:** 🟡 **Proposed — for operator review** (2026-11-07; task #21 item S3). Clauses are tagged
**[realized]**, **[partial]** or **[vision]** (the ADR 0043/0044 discipline). Nothing here moves code until ratified.

## Context

ADR 0044 D4 #6 asks for "net stack as an EL0 service". Today heqk is a microkernel-*shaped* monolith: every
parser of untrusted input runs in the kernel (EL1). Inventory at `4f62058` (lines of Rust, all EL1):

| Input | Parser | Reachable by | Rate |
|---|---|---|---|
| Every frame: Ethernet/VLAN/IPv4/IPv6/L4 headers | `net.rs` (414), `packet.rs`, verified BPF tiers | anyone on the wire | line rate |
| WAN control: PPPoE/LCP/PAP/IPCP/IPV6CP, DHCPv4, DHCPv6, RA/ND, ARP | `pppoe.rs` (1071), `uplink.rs` (1384), `ip6.rs` (315) | the ISP side + anyone on the WAN segment | low |
| LAN services: DHCP server, DNS forwarder, ICMPv6/SAVI, NAT state | `cyw43.rs` AP paths, `ip6lan.rs` (560), `nat.rs` (491) | every Wi-Fi client | per flow / low |
| Wi-Fi: SDPCM/glom, firmware events, EAPOL (WPA2 authenticator + supplicant) | `cyw43.rs` (5709) | firmware + any station in radio range | line rate (data) / low (control) |
| Mission Control: HTTP/1.1, cookies, JSON, SSE, smoltcp TCP | `http.rs` (465), `mcserve.rs` (628), smoltcp | anyone who can reach port 80 | low |
| Control plane: Noise handshake, encrypted records | `securechannel.rs` (1714), `controlplane.rs` (340) | the MSSP path / an on-path attacker | low |
| Boot config: POLICY.TXT, WAN.TXT, OWNER.TXT | `hal::policy` (933), `hal::lib` (711), `mcauth.rs` | whoever can write the boot partition | once per boot |

The EL0 substrate exists but is not yet the production path: real wasmi runs signed modules in an isolated EL0
excursion on CM5 metal (`[P-wasmi-el0-metal]`), the seL4-style IPC and per-TCB CSpaces are QEMU-proven
(`[P-r1-ipc]`, CORE-2), the GEM driver runs as an EL0 excursion. The production excursion driver is not yet on
per-TCB CSpaces (deferred), and the kernel heap is a bump allocator that never frees (`heap.rs`).

## Decision (proposed)

### D1 — Three placement classes **[vision]**

1. **Line-rate header parsing stays in EL1** — Ethernet/VLAN/IP/L4 header extraction and the verified BPF rule
   tiers. Justification: per-frame EL0 round-trips were measured at ~99.9 % of per-frame cost before NAPI
   batching (`rxprof`); these parsers are fixed-offset, bounded, allocation-free, and the rule bytecode is
   already verifier-proven (PREVAIL-style, `[P16]`). They are the TCB's job.
2. **Stateful control/application protocols move to EL0 servers** — HTTP + (future) TLS, the DHCP server, the
   DNS forwarder, PPPoE/LCP/auth, DHCPv6, the Noise control channel, the WPA2 authenticator state machine. They
   are low-rate, complex, stateful and remote-reachable — exactly where a parser bug should cost one server, not
   the kernel. Each becomes a capability-scoped EL0 server talking to the kernel over the M5.0 IPC endpoint; the
   kernel hands it frames that already PASSed the verdict and transmits what it returns (the same verdict gate
   on egress `McDev` applies today).
3. **Boot-time configuration stays in EL1, parsed once, fail-safe** — POLICY.TXT / WAN.TXT / OWNER.TXT. A
   malformed file never half-applies (realized). Its integrity is ADR 0049 D1 (operator-key signature), not
   isolation.

### D2 — TLS terminates in EL0, never in EL1 **[vision]**

HTTPS for Mission Control (task #21 S2) is built as an EL0 server with its **own freeing heap** inside its
address space. The kernel's global bump allocator stays as is (no general-purpose freeing allocator in the
TCB). This replaces the earlier plan "a freeing kernel allocator first" — the prerequisite becomes the EL0
server substrate (D4 #1) plus a per-server heap, not a kernel allocator change.

### D3 — Rules for every parser that stays in EL1 (until moved) **[partial]**

- No panicking slices on input-derived lengths (length checks before every index; the 2026-11-06 review fixed
  three remote panics of exactly this kind: PPPoE decap, mgmt ping, wan-in RST). **[realized for those]**
- Bounded loops and bounded state (every table has a cap and an eviction rule that counts). **[realized]**
- Every remote-reachable parser gets a QEMU fuzz phase in `validate.sh` (deterministic corpus + mutation, a
  fixed budget, panic = FAIL) before it ships. **[partial]** — `[P-fuzz]` (`a79b261`) covers every parser the
  QEMU build carries (frames, PPPoE, IPv6 RA/DHCPv6/LAN firewall, NAT, reject, HTTP, POLICY/WAN.TXT); 0 panics
  at 3k/target and a one-off 30k/target. The CM5-only parsers (`cyw43.rs` AP DHCP server / events / EAPOL,
  `uplink.rs` mgmt + WAN DHCP) were hand-reviewed on 2026-11-07 (every index bounded first) but are not fuzzed —
  moving them to a target-independent module (the `hal::defer` pattern) is the follow-up.

### D4 — Migration order **[vision]**

1. HTTP/TLS server (largest code, internet-adjacent once a port is forwarded; smoltcp moves with it).
2. LAN services (DHCP server + DNS forwarder) — reachable by every Wi-Fi client.
3. WAN control (PPPoE/LCP/PAP, DHCPv4/v6, RA) — reachable by the ISP side.
4. Control channel (Noise) — already authenticated after msg1; lowest exposure.
5. WPA2 authenticator — tied to the CYW43455 driver; moves with the driver (ADR 0044 D4 #7).

Each step must keep the AP throughput (≥ the 2026-11-07 metal baseline: 80–160 Mbps) and pass the separation
matrix + `mc-e2e` before the EL1 copy is deleted.

## Consequences

- The kernel TCB shrinks to header parsing + verified rules + drivers' hot paths; a bug in a control protocol
  is contained to its server and its capabilities.
- Cost: one IPC round-trip per control message (low rate — negligible) and per HTTP request; HTTP throughput is
  not a goal.
- TLS lands later than "add rustls to the kernel" would, but without a freeing allocator in the TCB.
- Until D4 lands, `kernel/heqk/SECURITY.md` and BuildPlan status must keep saying the control protocols run in
  EL1 (ADR 0044 D5 honesty floor).

## References

ADR 0043, ADR 0044 (D4 #1/#2/#6/#7, D5), ADR 0049 (D1), `docs/design/heqk-peer-review-2026-11-06.md`,
`kernel/src/heap.rs`, `kernel/src/mcserve.rs`, `[P-wasmi-el0-metal]`, `[P-r1-ipc]`.
