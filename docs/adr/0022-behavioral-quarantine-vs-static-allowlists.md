# ADR 0022 — Dynamic behavioral quarantine replaces static source allowlists

**Status:** 🟢 Accepted (2026-07-06). **Mechanism PROVEN on real hardware this session** — a
non-management source that had never been seen before was auto-detected → confirmed → quarantined →
dropped → TTL-auto-reverted on a live Pi 4, with **no pre-configured allowlist entry for it**; the
management-safety allowlist simultaneously protected the operator's own path from self-lockout. The
*positioning* (behavioral quarantine is the default access-control posture; static source-allowlists
are retired) is accepted going forward. Honest scope: this governs **network reachability**, not
authentication — key-only auth remains the front line for SSH (see D4). The interface-scope
correctness fix (D3) shipped this session; the ADR-0008 RBAC enforcement it complements is still
⬜ not built.
**Deciders:** os-architect (author), security-auditor (anti-spoof / abuse review — reuses the ADR-0018
sign-off), verification-engineer (the on-metal drop proof + Gate R re-test), release-engineer, product-
steward (Cortex traceability + the V1→V2 positioning).
**Relates to:** [ADR 0018](0018-inline-quarantine-safety.md) (the anti-spoof confirmation gate this
builds on — a source is only ever quarantined once independently confirmed, never on a spoofable
single packet), [ADR 0005](0005-unified-ebpf-detection.md) (the packet/flow analysis that *produces*
the block decision), [ADR 0008](0008-rbac-admin-operator.md) (auth/identity — the front line
behavioral quarantine is defense-in-depth *behind*), [ADR 0020](0020-adversarial-resilience-harness.md)
(the harness that regression-tests the drop), [ADR 0011](0011-product-cortex.md) (evidence graph sink;
contract C9 — AI proposes, the deterministic reconciler enforces).

## Context

### What V1 did, and how it failed
V1 (`mssp.hookprobe.com`) gates SSH with a **static nftables source-allowlist**
(`hookprobe-com/scripts/setup-vrf.sh`):

```
tcp dport 22 ip saddr { $SSH_TRUSTED_SET } ct state new accept   # else default-deny
```

`$SSH_TRUSTED_SET` is derived from `trusted_networks.py` (`10.0.0.0/8` plus specific operator ISP
`/24`s). A listed source can connect; everything else is dropped. A separate, reactive threat-intel
blocker exists (`sentinel.py`: `BLOCK_ON_ATTACK` / `_block_ip`), but **reachability is decided by the
static list.**

The list's own comment records its intrinsic failure:

> *"…so the four allowlists can't drift. That drift is what let the operator's own SSH get dropped on
> 2026-06-28."*

The allowlist was duplicated in four places, they drifted, and **the operator locked themselves out.**
This is the structural fragility of static source-allowlists: a maintenance burden that grows with the
trusted set, drift across copies, and self-lockout as the dominant failure mode. It is also *coarse* —
a trusted `/8` that contains a compromised host still passes; a legitimate new location is denied until
someone edits the list.

### What V2 has that V1 lacked at the edge
V2 runs a full local SOC on the device itself: packet-layer analysis (`napse-dpi` on the tc-mirror),
conntrack/flow analysis (`napse` wasm), and host-EDR (`execsnoop`/`fanotify` → `hookprobe-evidence`).
It already *detects* malicious behaviour (port scans, brute force, reverse shells, DGA) and, per ADR
0018, can *enforce* a confirmed drop. The question this ADR settles: **should that behavioural signal
replace the static source-allowlist as the primary reachability control?**

## Decision

### D1 — Behavioural quarantine is the default reachability control; static source-allowlists are retired
The device does its own traffic analysis and **dynamically quarantines a source on demonstrated
malicious behaviour**, rather than pre-deciding who may connect. A source is not on any list until it
*earns* a block by its own conduct; the block is applied by the deterministic reconciler (nft sets +
the tc-BPF map) and **auto-reverts on a TTL** (self-healing, no stale entries, no manual unban).

There is nothing to maintain, nothing to drift, and the granularity is per-source-behaviour rather than
per-CIDR-trust. This eliminates the entire V1 drift-and-self-lockout failure class.

### D2 — The allowlist is not deleted; its purpose inverts (access-control → anti-self-lockout)
A small allowlist survives, but its meaning flips:

| | V1 static allowlist | V2 management-safety allowlist |
|---|---|---|
| Answers | "who **may** reach SSH" | "who must **never** be auto-blocked" |
| Size | large (every trusted ISP range) | tiny (the operator's own mgmt path, e.g. `10.200.0.0/28`) |
| Default posture | deny-by-default (preventive) | allow-and-analyse (detect-then-block) |
| Dominant failure | drift → operator locked out | *cannot* lock out the operator — that is its only job |

The management-safety allowlist exists **solely** to guarantee the reconciler can never quarantine the
operator's own control path — the exact 2026-06-28 V1 bug, made structurally impossible. It is a safety
floor, not an access gate. (`scan_responder::ProtectPolicy` / the `mgmt` subnet check; a quarantine
verdict for a mgmt-path source is downgraded to `observe_only`/`allowlisted`, never enforced.)

### D3 — Enforce on every ingress interface a source can arrive on, not only its IP-class interface
(Fix shipped this session; `crates/hookprobe-manifest/src/scan_responder.rs::render_bootstrap`.) The
LAN/WAN split governs the enforcement **key** (L2-adjacent source → MAC-keyed drop, anti-spoof; routed
source → IP-keyed drop) — that stays. But the drop **rules** must fire on the *union* of ingress
interfaces, because a source's class (by IP) and its arrival interface can legitimately mismatch: a
private/CGNAT-addressed source (`100.64/10`, double-NAT) can arrive on the WAN uplink. On real hardware
this session, a confirmed private-IP scanner on the WAN interface was quarantined into
`quarantine_lan_macs` but **never dropped**, because the MAC-drop rule was scoped to the LAN interface
alone. The rules now fire on `iifname { lan, wan }` (both hooks); the sets only ever hold
CONFIRMED-quarantined identities, so widening the interface scope can never add a false drop.

### D4 — Behavioural quarantine is defense-in-depth *behind* authentication, never a replacement for it
Dynamic quarantine is **detect-then-block** (reactive): the first probe reaches the service before the
source is confirmed and dropped. V1's deny-by-default was **preventive**. Therefore, for a sensitive
service like SSH, V2 does **not** remove the need for auth — key-only SSH remains the front line (V2
release images: publickey-only, no password, root locked; the debug password/root path is build-gated
and absent from signed releases, per ADR 0008 §"OS-level enforcement"). The full posture is three
layers:

1. **Auth (front line):** key-only SSH / device-identity — a probe that reaches the service still can't
   authenticate.
2. **Behavioural quarantine (defense-in-depth):** the device's own analysis auto-blocks scanners /
   brute-forcers / confirmed-malicious sources, with TTL auto-revert.
3. **Management-safety allowlist (floor):** the operator's own path is never auto-blocked.

This deletes the fragile static *source* allowlist (layer that caused V1's lockout), keeps auth, and
adds automatic blocking the static list never provided.

### D5 — Anti-spoof confirmation is a hard precondition (inherited from ADR 0018)
Because there is no allowlist to fall back on, the *correctness* of the confirmation gate matters more,
not less: a source is quarantined **only** after it is independently confirmed (a real 3-way handshake
seen by the mirror-fed `HandshakeTracker`, **or** an ESTABLISHED conntrack flow — the mirror-independent
fallback added this session). A single spoofable packet claiming a victim's source must never populate
the enforced set — otherwise behavioural quarantine becomes a reflected-DoS primitive. This invariant
(ADR 0018) is load-bearing for this ADR and is covered by the adversarial harness (ADR 0020).

## Consequences

- **Positive:** no source-allowlist to maintain or drift; per-behaviour granularity (a bad host inside a
  "trusted" range is still blocked); self-healing via TTL; the operator cannot self-lock-out; the block
  decision is explainable from the evidence graph (which detection, what confidence, TTL) rather than an
  opaque CIDR list; works standalone with no cloud/account.
- **Negative / accepted trade-offs:** detect-then-block leaves a first-probe window (mitigated by auth,
  D4); a slow-and-low attacker under the detection threshold is not auto-blocked (mitigated by the
  harness tuning detection, ADR 0020/0014, and by auth); behavioural blocking is only as good as
  detection coverage — so **improving detection is now directly a reachability-security improvement**,
  which re-frames the detection roadmap's priority.
- **Migration from V1:** the `trusted_networks.py` static set is retired as an *access* control; any
  genuinely-needed always-reachable path (the operator's mgmt subnet) becomes a management-safety
  allowlist entry (D2), which is small and stable by construction. Reactive threat-intel blocking
  (V1's `sentinel` `_block_ip`) is subsumed by HYDRA enrichment feeding the same reconciler, not a
  separate blocker.
- **Open / not-yet-built:** the ADR-0008 RBAC/auth enforcement that is the D4 front line is still
  design-only; behavioural quarantine is defense-in-depth *behind* a front line that is itself a
  roadmap item — this ADR does not fabricate its readiness.

## Validation (2026-07-06, live Pi 4 @ 10.200.0.4)
A macvlan attacker (distinct MAC, public IP `203.0.113.99`) with no allowlist entry scanned the device:
detected (portscan) → confirmed (completed handshake + ESTABLISHED conntrack) → verdict `quarantine` →
`quarantine_wan_ips` populated → the source's traffic **dropped** on the uplink (the scan wall-clock
jumped 0.09 s → 101 s as connections timed out; ping/connect from the source failed) → `status:reverted`
after the TTL. The management path (fortress, mgmt subnet) was concurrently classified `observe_only`
and never dropped — D2 proven in the same run. The D3 interface-scope fix closes the one gap this
validation surfaced (private-IP source on the WAN interface).

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The "dynamic per-behaviour quarantine with TTL-revert, not static CIDR allowlists" posture and the management-safety floor survive; the nft-set + tc-bpf-map enforcement is re-implemented on heqk's verdict path. → **Phase M2**.
