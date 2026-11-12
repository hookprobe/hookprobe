# ADR 0050 — heqk parser placement: which untrusted-input parsers run in EL1, which move to EL0

**Status:** ✅ **Accepted by the operator 2026-11-07** (task #21 item S3): the L3/L4 fast path and rule matching
stay in the kernel; deep parsers (TLS, DNS, HTTP, …) run in isolated EL0 servers so a parser bug or panic cannot
take down forwarding or the IPS. Clauses are tagged **[realized]**, **[partial]** or **[vision]**.

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
  at 3k/target and a one-off 30k/target. The AP DHCP server, WAN DHCP client, firmware-event
  decoder and EAPOL matcher moved to the target-independent `arch-aarch64::apparse` and are fuzzed too
  (0 panics, 3k + one-off 30k). Still hand-review-only: `uplink.rs` `mgmt_frame` / `mgmt_dhcp_step` (bound to
  MMIO-backed statics; reviewed 2026-11-07, no defect). 2026-11-10 (SEC-01 inventory): a fourth remote panic of the
  same kind was found and fixed — a PPPoE LCP Echo-Request with < 4 data bytes indexed past its end in `on_lcp`
  (reachable by anyone who can spoof the session id + AC MAC on the WAN segment); regression in the PPPoE self-test.

### D4 — Migration order **[vision]**

1. HTTP/TLS server (largest code, internet-adjacent once a port is forwarded; smoltcp moves with it).
   *Status 2026-11-10:* TLS terminates in EL0 (D2, `el0-tlshost`); the HTTP request parser now runs in that
   same EL0 server too (`CMD_HTTP_PARSE`): the kernel passes the raw bytes and rebuilds the request from a
   fixed record of offsets into its own copy (bounds + UTF-8 checks only). A fault or timeout fails that
   request closed (400) and resets the server (D5); `/api/health.http_parser` reports placement, requests,
   faults and restarts; mc-e2e asserts all of it. Still in EL1 for this step: smoltcp TCP and the route
   handlers (they consume typed fields only).
2. LAN services (DHCP server + DNS forwarder) — reachable by every Wi-Fi client.
   *Status 2026-11-10:* DNS done (step 2a). Shield's query and answer parsing runs in the new EL0 server
   `el0-lansvc` (allocation-free, own ABI `hal::lansvcabi`), placed in the GB5 window's second 2 MiB block.
   The kernel keeps every decision. A fault resets the server, and the message passes un-inspected as an
   unparseable one always did. Metal-proven: `docs/design/metal-evidence/20261110-batch54-57.md`.
   Still in EL1: the AP DHCP server's parser (arch crate), which is step 2b.
   *Status 2026-11-10 (step 2b, QEMU):* the DHCP server's client-frame parse moved to the pure `hal::dhcpwire`
   (one source for kernel and server) and runs in `el0-lansvc` (`CMD_DHCP_PARSE`); the kernel re-cleans and clamps
   the returned record; a fault = an unparseable frame (no reply, the client retries). `[P-lansvc]` parity +
   libFuzzer `dhcp_wire`. Metal pending.
3. WAN control (PPPoE/LCP/PAP, DHCPv4/v6, RA) — reachable by the ISP side.
   *Status 2026-11-10 (step 3a, QEMU):* DHCPv4 replies, Router Advertisements and DHCPv6 are parsed in
   `el0-lansvc` (`CMD_WAN_DHCP_REPLY` / `CMD_WAN_RA` / `CMD_WAN_DHCP6`) through `arch_aarch64::wanparse`; the
   sources moved to `hal` (`hal::ip6`, `hal::dhcpwire`). `parse_dhcp_reply` was split into pure `dhcp_reply_facts`
   (EL0) and `apply_reply` (the merge + server pin, kernel). Records are fixed-layout and re-clamped by the kernel.
   **Placement note:** the WAN parsers share the LAN server's address space for now (one EL0 server, no state kept
   between commands); a separate WAN server is the stricter split, deferred. Still in EL1: PPPoE discovery and
   PPP LCP/PAP/CHAP/IPCP/IPv6CP (parse fused with reply building — step 3b), WAN/mgmt ARP + ICMP, SNTP.
   *Status 2026-11-11 (step 3b, QEMU):* parse split from reply building, the walks in `el0-lansvc`
   (`hal::pppwire`): PPPoE discovery tags (`CMD_WAN_PPPOE_DISC`, libFuzzer `pppoe_disc` 3.3M runs), LCP
   Configure-Request classification (`CMD_WAN_LCP_REQ`; rejected options are copied out of the EL0 record, never
   re-read from the frame), IPCP Request / Nak / Reject (`CMD_WAN_IPCP`). `[P-pppoe]` (scripted AC, end to end) and
   `[P-lansvc]` parity pass. Still in EL1: LCP Nak/Reject from the AC, PAP/CHAP (the CHAP challenge), IPv6CP,
   WAN/mgmt ARP + ICMP, SNTP.
   *Status 2026-11-11 (step 3b-iv/v, QEMU):* CHAP Challenge, IPv6CP Configure-Request and the AC's LCP
   Configure-Nak / Configure-Reject of our request are walked in `el0-lansvc` (`CMD_WAN_CHAP`, `CMD_WAN_IP6CP`,
   `CMD_WAN_LCP_PEER`; libFuzzer `ppp_ctl`). PAP replies carry no options (code + id only, read from the fixed PPP
   header). **Operator decision 2026-11-11:** the small fixed-format reply handlers stay in the kernel — SNTP replies
   (48 B, fixed offsets, nonce-checked) and WAN / mgmt ARP + ICMP echo are fixed-offset, bounded, walk-free header
   reads (the D1.1 class); moving them would add an EL0 round trip per frame without removing a walk from the TCB.
4. Control channel (Noise) — already authenticated after msg1; lowest exposure.
   **Operator decision 2026-11-11: the device identity key stays in the kernel**, so the Noise handshake (fused
   with that key, HKDF(SRK, …)) stays in EL1. The pre-authentication input is the fail-closed `HsReasm` datagram
   reassembler (bounded, fuzzed by the kernel fuzz crate). This step is closed as "not moved, by decision".
5. WPA2 authenticator — tied to the CYW43455 driver; moves with the driver (ADR 0044 D4 #7).
   *Status 2026-11-11 (step 5a, QEMU):* the attacker-shaped part — EAPOL-Key classification of a station's M2 / M4
   (`CMD_STA_EAPOL`; the returned length is re-checked against the kernel's buffer before any copy) and the M2 RSNE
   MFP-capable walk (`CMD_STA_MFPC`) — runs in `el0-lansvc` (`hal::eapolwire`, libFuzzer `eapol_wire`, 4.35 M runs
   clean). A server fault reads as "not ours" (the station retransmits) / "not MFP-capable". The key state machine,
   MIC / PTK / GTK and the SAE engine stay with the driver (this item's rule), so their move is the driver move.
   *Status 2026-11-11 (step 5b, QEMU):* the authenticator's work on station frames runs in `el0-lansvc`
   (`hal::wpaauth`, `CMD_STA_M2` / `CMD_STA_M4`):
   - PTK derivation over the station's SNonce: PRF-SHA1 for AKM 2, KDF-SHA256 for AKM 8, checked against the `sae`
     crate's KDF;
   - the M2 MIC check, which yields the PTK only when it verifies;
   - the M4 MIC check.

   The WPA crypto (`wpa.rs` / `aes.rs`) moved from `arch-aarch64` to `hal`, re-exported so the driver call sites are
   unchanged. The kernel keeps the state machine, replay counters, M1 / M3 building and `WLC_SET_KEY`. The PMK enters
   the EL0 call for M2; this is the per-network Wi-Fi key, not the device identity key that the operator kept in the
   kernel. A server fault reads as "MIC did not verify" (the station retransmits). libFuzzer `wpa_auth`.
   **Operator decision 2026-11-11 (2A): approved with key-handling safeguards.**
   - **One controlled capability:** the PMK reaches EL0 only through `CMD_STA_M2` on the LAN-services server's IO page.
   - **Erased after use:** the kernel wipes, with volatile stores, its call buffer, the IO page's input (PMK) and its
     output (PTK). The server wipes its stack copy, its local PMK / PTK and the IO input before it exits.
   - **Never exposed:** never logged and never part of the management ABI.
   - **Tested:** `[P-lansvc]` checks that the IO page holds neither key after the call.
   *Metal 2026-11-11 (batches 62–63):* the first metal run found that the AP passes the rest of its SDPCM buffer
   (over the EL0 input window), so no M2 was recognised; fixed by trimming to the 802.1X span (f7d3b933). On W22,
   WPA3 transition 7/7 (SAE + WPA2-only stations keyed and authorized) and LAN client 18/18.
   *Status 2026-11-12 (step 5c, QEMU):* the WPA3-SAE responder's walk over a station's Authentication frame runs in
   `el0-lansvc` (`hal::saewire`, `CMD_STA_SAE`, libFuzzer `sae_wire`). Placement choice (b): the server parses and
   validates only; the per-station state machine and every SAE secret stay in the kernel's `sae` crate.
   - **Moved to EL0:** algorithm / sequence / status, group 19 check (status 77 answer), the Commit length rules,
     the trailing element walk (H2E Rejected Groups and the downgrade check), the scalar range 1 < s < r, the
     element check (x, y < p, on the curve, done without a curve library), and the Confirm format. The server
     returns one fixed 168-B record; the kernel re-checks the kind and the Rejected Groups length / content.
   - **Stays in EL1:** the fixed-offset event / 802.11 header reads (`apparse::sae_auth_body`, which trims the body
     to the event's own data length — the batch 62 lesson), the state table, PWE / PT, rand / mask, our commit,
     K / KCK / PMK / PMKID, the confirm computation and its check under the KCK, `auth_status`. The curve library
     re-validates the scalar and element (fixed 32 / 64 B) before use. The in-kernel `hal::saewire` copy runs only
     when the EL0 server is absent (D5, as 5a / 5b).
   - **Crosses the boundary:** in: an H2E-offered flag and the body the station sent (≤ 512 B, longer is refused
     whole, never truncated); out: the station's own scalar / element / Rejected Groups / send-confirm / confirm.
     No password, PWE, PT, rand, KCK or PMK, so the 2A capability is not widened. The kernel still scrubs the IO
     input and output and wipes its record copy after every call; the server wipes its copies before it exits.
   - **Fault:** rejects that attempt only — nothing is sent, the station's SAE state is forgotten (it starts again
     with a new commit). The AP's security mode never changes, so there is no fallback to WPA2.
   - **Tested:** `[P-lansvc-sae]` (mc-e2e, now built with `wpa3`) covers the Annex J.10 commit via EL0, hunting-and-
     pecking and H2E exchanges equal to the in-kernel walk, malformed commits (group, scalar = r, off-curve,
     truncated, over IN_MAX), a 3000-B receive buffer trimmed to the event length, a server fault, and an IO page
     with no PMK or passphrase. `[P-sae]` adds the walk-vs-curve-library parity.

   Metal must prove: WPA3 transition stations (SAE and WPA2-only) keyed and authorized, `cm5-wpa3-check` and
   `cm5-lan-client` green, throughput ≥ the 2026-11-07 baseline, and no REL-08b (PMKID-cache use-after-free) regression on an SAE soak.

Each step must keep the AP throughput (≥ the 2026-11-07 metal baseline: 80–160 Mbps) and pass the separation
matrix + `mc-e2e` before the EL1 copy is deleted.

### D5 — Failure policy (operator: "write it down") **[vision]**

| What fails | Effect | Why |
|---|---|---|
| An EL0 service server (HTTPS, DNS forwarder, DHCP server, PPPoE control, …) faults or panics | **That service fails closed**: its connections are dropped, the kernel restarts the server (bounded backoff, counted, reported on the heartbeat and `/api/health`). Forwarding and the IPS continue unaffected. | A broken parser must never serve wrong answers; its blast radius is one service. |
| An EL0 **deep-inspection** module (Wasm detection, L7 classifier) faults on a frame | **Verdict for that frame = observe + alert** (no drop); the module is restarted; repeated faults are an alert of their own. The in-kernel L3/L4 rules still enforce. | ADR 0023: legitimate traffic always passes — a module crash must not become a self-inflicted outage. Operators who want fail-closed choose it per interface (CLAUDE.md: "per-interface fail-open (default) / fail-closed (policy choice)"). |
| The in-kernel verdict engine itself | Unchanged: a verified-rule DROP is enforced; the kernel never "fails open" on a confirmed threat verdict. | Rule bytecode is verifier-proven; this path does not contain deep parsers. |

*Engineering note (vs the operator's "fail-closed for IPS verdicts"):* fail-closed is kept for **confirmed**
in-kernel threat verdicts; a **fault** in a deep-inspection module is observe-and-alert by default because
ADR 0023 forbids dropping legitimate traffic on anything other than a confirmed attack. Fail-closed on module
fault is available as an explicit per-interface policy.

## Consequences

- The kernel TCB shrinks to header parsing + verified rules + drivers' hot paths; a bug in a control protocol
  is contained to its server and its capabilities.
- Cost: one IPC round-trip per control message (low rate — negligible) and per HTTP request; HTTP throughput is
  not a goal.
- TLS lands later than "add rustls to the kernel" would, but without a freeing allocator in the TCB.
- Until D4 lands, `os/kernel/SECURITY.md` and BuildPlan status must keep saying the control protocols run in
  EL1 (ADR 0044 D5 honesty floor).

## References

ADR 0043, ADR 0044 (D4 #1/#2/#6/#7, D5), ADR 0049 (D1), `docs/design/heqk-peer-review-2026-11-06.md`,
`kernel/src/heap.rs`, `kernel/src/mcserve.rs`, `[P-wasmi-el0-metal]`, `[P-r1-ipc]`.
