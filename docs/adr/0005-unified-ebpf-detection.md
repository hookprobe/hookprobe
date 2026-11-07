# ADR 0005 — Unified eBPF detection across the fleet (XDP + TC-bpf, CO-RE, kernel-side conntrack)

**Status:** ✅ Accepted (2026-07-01) — Phase-B inspection architecture. Supersedes the interim
`inspect.rs` ladder that used generic XDP.
**Date:** 2026-07-01
**Deciders:** os-architect (author), code-developer, security
**Relates to:** [`Readme.md`](../architecture/Readme.md) (data plane), [ADR 0003](0003-platform-manifest-schema.md)
(capability model + `runtime: sysext`), `modules/napse-capture/` (the sysext), `crates/hookprobe-manifest/src/inspect.rs`
(the reconciler). Grounded in a 2026-07-01 deep-research pass (24 authoritative sources, 25
adversarially-verified claims; sources listed at the end).

## Context

HookProbe inspects **all** traffic ("everything is rogue") across a heterogeneous edge fleet — Pi 4/5
(`brcmfmac` Wi-Fi + `bcmgenet` Ethernet), RK3588 (`stmmac`, vendor BSP kernels), Intel N100
(`igc`/`e1000e`), and virtual (`virtio-net`, `veth`) — from an **immutable, signed bootc image with
no on-device compiler**. The interim design used a per-NIC ladder `xdp-native > xdp-generic >
software` plus a `tc-mirred` mirror feeding a userspace DPI sensor, and read `/proc/net/nf_conntrack`
in userspace for flow state. Two things are wrong/weak with that: **generic XDP is a non-production
shim**, and **userspace conntrack polling** loses the packet context and can't enforce inline.

## Decision — principles

1. **One detection core, two hooks, compiled once (CO-RE).** The detection logic lives in a single
   `.bpf.c` compiled to one CO-RE object in CI. Two thin `SEC()` wrappers attach it as **native XDP**
   (`ctx = xdp_md`) or **TC-bpf** (`ctx = __sk_buff`, `BPF_PROG_TYPE_SCHED_CLS` at `clsact`). The
   loader probes the NIC and attaches the right one. Direct-packet-access parsing is shared; only the
   ctx accessors + verdict mapping + the conntrack kfunc differ.

2. **The ladder is `xdp-native → tc-bpf → software`. Generic/skb-XDP is NOT a tier.** Generic XDP runs
   after `skb` allocation and has none of native XDP's pre-stack speed; it is discouraged in
   production. The real fallback is **TC-bpf at `clsact`** — a first-class in-kernel programmable
   hook available on virtually every NIC. The `software` floor (userspace conntrack-flow,
   `senzorium-flow`) is only for kernels that can't run our BPF (pre-5.19 / no BTF).

3. **Wi-Fi is TC-bpf, and it's clean.** `mac80211` drivers (incl. `brcmfmac`) have **no native XDP**.
   A Pi AP's `wlan0` therefore uses TC-bpf, which sees **post-802.11-decap Ethernet frames** — a
   standard Ethernet parser works. This is the primary edge case, and it is fully covered.

4. **Stateful in-kernel via `bpf_ct_lookup` (kernel ≥ 5.19).** Both XDP (`bpf_xdp_ct_lookup`) and
   TC-bpf (`bpf_skb_ct_lookup`) query `nf_conntrack` directly (kfuncs, merged 5.19, **require
   `nf_conntrack` loaded** — which we already have for NAT). Established flows fast-pass in-kernel;
   new/suspicious packets are dropped or escalated to userspace NAPSE. **This replaces the userspace
   `/proc/net/nf_conntrack` read as the primary path** (that read demotes to the pre-5.19 floor).
   ⚠️ **Baseline is kernel 5.19, not 5.18** — 5.18 lacks the ct-lookup kfuncs.

5. **Cover all round — WAN side and LAN side, both directions.** Each NIC is tagged `InspectRole`:
   - **WAN** (uplink/dongle/cellular): ingress-threat policy — RPF anti-spoof (`bpf_fib_lookup`),
     SYN-flood rate-limit, threat-feed **blocklist** (LPM-trie, hourly HYDRA sync), inbound scans;
     plus egress exfil/C2 detection.
   - **LAN/AP**: client policy — lateral movement (client↔client), rogue/compromised devices, DNS
     tunneling/entropy, per-device NAC violations.
   The same core runs on both; the role selects the ruleset. A `tc-mirred` copy of **every** NIC to
   the DPI sink guarantees full-packet inspection on both sides regardless of fast-path mode.

6. **Portability = CO-RE + BTF, with a BSP fallback.** One ELF runs across kernels: libbpf relocates
   field offsets at load time against the kernel's BTF. **What breaks it:** vendor ARM BSP kernels
   built **without `CONFIG_DEBUG_INFO_BTF`** (some RK3588). Mitigation: ship **BTFGen-minimized BTF**
   blobs (`bpftool gen min_core_btf`, BTFHub archive) inside the cosign-signed sysext, keyed by
   kernel version. Also: the kernel must have `nf_conntrack` for the ct kfuncs even with a good BTF.

7. **XDP RX-metadata hints are opportunistic, never load-bearing.** The three kfuncs
   (`rx_timestamp`/`rx_hash`/`rx_vlan_tag`, standardized in **6.3**) are implemented by only a few
   drivers (`mlx5`, `igc`, `veth`, partial `stmmac`); `bcmgenet`/`brcmfmac`/`virtio-net` mostly don't
   and **degrade gracefully** (`-EOPNOTSUPP`). Use when present; never depend on them.

8. **Escalation differs by tier.** AF_XDP (XSK) redirect is **XDP-only** (works in copy/skb mode for
   non-native NICs). A **TC-bpf** program cannot AF_XDP-redirect; it escalates via **ringbuf/perf
   events** (or `bpf_redirect` to the sink). Both tiers keep the `tc-mirred` mirror for out-of-band
   full-packet DPI. Enforcement is inline (`XDP_DROP`/`TC_ACT_SHOT`), **fail-open by default**,
   fail-closed per policy. Use `libxdp`'s dispatcher if multiple XDP programs must coexist on a NIC.

## Consequences

- `inspect.rs` `select_mode` returns `XdpNative | TcBpf | Software` (done); NICs carry an
  `InspectRole` (WAN/LAN) (done). `xdp-generic` is gone.
- `napse-capture` ships **one** CO-RE object (`napse_detect.bpf.o`) with `xdp` + `tc` wrappers +
  BTFGen blobs, compiled in CI (needs `clang`/`bpftool`/`pahole` — not on the device).
- Bootstrap must probe per-NIC `xdp_native`, kernel version (≥5.19 ⇒ `bpf_stateful`), and BTF
  presence, and write them to the manifest (`inspect.rs`'s `xdp_caps_for` / `bpf_stateful` seams).
- `senzorium-flow` (userspace conntrack) becomes the **fallback floor**, not the primary path.

## Sources (deep research 2026-07-01, adversarially verified)

- Attach modes / ladder: xdp-tools `xdp-loader(8)`; docs.ebpf.io `BPF_PROG_TYPE_XDP`; liuhangbin
  "eBPF and XDP"; Oracle "eBPF firewall with XDP"; RedHat "Get started with XDP".
- Wi-Fi / mac80211: kernel `wireless.docs.kernel.org/brcm80211`; `wireless.wiki.kernel.org/brcm80211`.
- `bpf_ct_lookup` kfuncs (5.19): LWN 881567; lore `20220708130319` + patchwork `20211019` (Maxim
  Mikityanskiy / Kumar Dwivedi); `xdp_synproxy_kern.c` selftest; docs.ebpf.io `bpf_skb_ct_lookup`.
- CO-RE / BTF / BTFGen: Facebook "BPF portability and CO-RE"; Brendan Gregg "BPF CO-RE"; AquaSec
  BTFHub + `btfgen-internals`; Inspektor-Gadget BTFGen.
- XDP RX metadata (6.3): `docs.kernel.org/networking/xdp-rx-metadata`; xdp-project drivers matrix.
- AF_XDP / libxdp: `docs.kernel.org/networking/af_xdp`; xdp-tools `libxdp` README; Suricata eBPF/XDP.

*Note: the automated synthesis stage of the research run returned stub output; this ADR was
reconstructed from the run's verified claim log + the source set above + primary-doc cross-check.*

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: HARD — reconciled by ADR 0043 D2.** This decision is **not ported**: it is re-decided onto the **RFC 9669 BPF ISA** in heqk's threat plane (`~/heqk/BPF_THREAT_PLANE.md`). The *same clang-compiled bytecode rules* run on Linux eBPF and heqk — so the detection moat survives while Linux eBPF/CO-RE/BTF/`nf_conntrack`/libbpf do not. ADR 0005's "hundreds of engineer-years" fear is about *Linux* eBPF; the clean IETF ISA avoids it. → **Phase M2 (P8 rule-parity)**.
