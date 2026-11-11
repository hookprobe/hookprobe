# heqk WAN and advanced routing architecture: investigation and proposal (2026-11-11)

**Status:** investigation and proposal for operator review. Nothing here is built.
**Baseline:** `origin/main` @ `fd6fb038` (code citations). Re-checked at `ae7c304d` before commit.
**Paths:** relative to `os/kernel/` unless they start with `docs/` or `onboarding/`.
**Related ADRs (proposed in the same change):** 0060 (SMP execution model, core roles, BKL),
0061 (memory budgets and admission), 0062 (microarchitectural isolation for multi-tenant PoPs).

**Status labels:** **IMPL** implemented · **PART** partially implemented · **DESIGN** design only ·
**NONE** not implemented · **UNK** unknown, needs validation.

## 0. Operator principles that bind this design (2026-11-11)

1. **heqk is a capability-driven SASE platform.**
   - A SASE PoP is neither a separate product nor reserved for x86. Any heqk device, CM5
     included, can be provisioned as a PoP if it passes measured admission (§7).
   - "It can establish BGP" does not make a device PoP-capable.
2. **CM5 full-table IPv4/IPv6 BGP is a design target.** The default-route-only and
   selected-prefix BGP postures are also supported.
3. **The BGP RIB and protocol state live in persistent, isolated EL0 services.** Routes reach
   EL1 through a bounded route-manager interface, with validated and atomic FIB installation.
4. **No gateway-era fixed limits as architecture.** Limits like `ROUTE_MAX = 16` are replaced by
   resource-bounded, platform-configurable capacities, with hard safety ceilings and
   per-service budgets.
5. **Capacity has four separate layers:** hardware capability, available resources, the enabled
   profile, and measured sustainable capacity.
6. **Settled protocol decisions:**
   - G19 is the native overlay; IPsec/IKEv2 is the interoperability option.
   - BGP comes before OSPF.
   - EIGRP is off the committed roadmap.
   - MPLS PE/LSR waits for a named customer, but must remain possible without a separate OS.
   - Per-VRF signed bundles use delegated tenant keys.
   - Persistent scheduled EL0 services are supported.
   - Peer-triggered RTBH/FlowSpec enforcement stays excluded (ADR 0023).
   - Active/active WAN failover may drop in-flight NAT sessions.
7. **Multi-core and multi-RAM use is a core requirement** (ADR 0060/0061). Security eligibility
   is verified, never configured (ADR 0062 V0).

## 1. Current-state audit (Deliverable A)

### 1.1 Interfaces

| Finding | Status | Evidence |
|---|---|---|
| Policy interfaces are a closed enum `Lan, Eth1, Wan, Mgmt`, with `IF_N = 4` | IMPL | `hal/src/policy.rs:139-151`, `parse_if` :576-584 |
| end0 is always the WAN and eth1 is always the LAN (hard-coded topology) | IMPL | `arch-aarch64/src/uplink.rs:1-7, 26-33` |
| end0 carries at most two sub-interfaces: internet (a global `LINK` encapsulation) and management (`MGMT_VLAN`, one 802.1Q tag) | IMPL (metal) | `uplink.rs:72-103, 164` |
| QinQ encapsulation (`Encap{vlan, outer, pcp, pppoe}`), RX tag parse, IP MTU derived from the stack | IMPL | `policy.rs:952-1027`; `validate.sh` markers `[P-policy]`, `[P8-vlan]` |
| Several independent L3 sub-interfaces per port | NONE | Singleton globals at `uplink.rs:79-81` |
| VLANs on the LAN side | NONE | The LAN is one /24: `FwdCfg.inside_net: [u8;3]` (`kernel/src/apcore.rs:73`), `wan_martian4` (`policy.rs:935`) |
| Tunnel as an interface | NONE | G19 is a policy attribute (`policy.rs:261-290`) |
| The hsh spec forbids a parallel interface model | DESIGN | `docs/design/hsh-native-management-shell.md` §R2, §4.2 |

### 1.2 Routes

| Finding | Status | Evidence |
|---|---|---|
| One flat table of **16** routes `Route{dst, src, via: If, gw, metric}` | IMPL | `policy.rs:40, 217-224, 845-885` |
| Linear scan: longest destination prefix wins, `from` is a filter, then lowest metric on an interface that is up; equal metric goes to the first in the file. No ECMP. | IMPL | `Policy::route` `policy.rs:409-424` |
| One routing context; no VRF | IMPL (single) | No VRF symbol in heqk |
| A source route is a filter, not a policy stage ahead of the lookup. A more specific destination route without `from` beats a `from` route. | IMPL (semantics) | `policy.rs:414-419`; `kernel/src/main.rs:14489-14496` |
| Liveness is tracked per interface, not per next hop | IMPL | `apcore.rs:99-104`; `main.rs:3656-3658`; `kernel/src/wanhealth.rs:1-41` |
| No next-hop tracking. An unreachable `via wan gw X` blackholes traffic instead of failing over. | IMPL (gap) | `uplink.rs:1636-1667`; `apcore.rs:192-200` |
| **`via lan` / `via eth1` routes are accepted by the parser but can never be selected** | IMPL (defect) | `policy.rs:576-584` vs `apcore.rs:100-104` |
| Default and connected routes are implicit (`egress = If::Wan`) | IMPL | `apcore.rs:93` |
| The G16 health anchors `1.1.1.1` and `9.9.9.9` are fixed | IMPL | `wanhealth.rs:41` |

### 1.3 IPv4, IPv6, PPPoE, tunnel, ACLs

- **IPv4 forwarding ladder** [IMPL]: `in` ACL → route → `out` ACL → ADR 0053 hold → device policy
  → exfil → Shield → (management | G19 | WAN) plus SNAT (`apcore.rs:80-232`). **Every WAN egress is
  SNAT'd.**
- **IPv6** [PART]:
  - Routed without NAT, with a stateful firewall (`arch-aarch64/src/ip6lan.rs:1-26`).
  - **IPv6 routes are parsed and unit-tested but never consulted by forwarding.**
    `Policy::route` has exactly one dataplane caller (`apcore.rs:100`), and it handles IPv4 only.
- **PPPoE and DHCP:**
  - Session and lease state feed `wan_up`, not a RIB (`uplink.rs:452-456, 1279-1352`).
  - The control parsers have moved to EL0 `el0-lansvc`, as stateless excursions
    (`docs/adr/0050:87-118`).
- **G19 tunnel** [IMPL]:
  - One PoP; at most 8 IPv4 split prefixes; IPv4 only.
  - Evaluated after the route lookup, and only when egress is not `Mgmt` (`apcore.rs:163` vs
    `:183`). **A `route … via mgmt` silently bypasses the tunnel.**
  - The PoP responder is a **Linux service** (`onboarding/enrollment/superpop/README.md`).
- **ACLs** [IMPL]: 8 ACLs × 32 entries; prefix lists 8 × 16 (`policy.rs:35-41`). The assessment
  doc says 16 prefix lists; the code says `PL_MAX = 8`.
- **Fixed limits:**
  - NAT 4096 (`arch-aarch64/src/nat.rs:18`);
  - IPv6 neighbours 64 and flows 256 (`ip6lan.rs:17-22`);
  - 4 extra WAN next hops (`uplink.rs:1636`);
  - POLICY text 4 KiB; HQCFG1 bundle 16 KiB. The **implemented** schema 1.0 accepts only the section
    kinds wan (1), wifi (4) and policy (5). Any other kind or flag is refused (`kernel/src/cfgbundle.rs:17,
    30-32, 167-171`). The assessment plans 8 kinds; none is a routing kind
    (`docs/design/secure-config-assessment-2026-11-10.md:161-173`).

### 1.4 Execution, configuration, capability primitives

- **EL1:** forwarding, policy, NAT, IPv6 router, ARP, PPPoE/DHCP state, wanhealth, G19 Noise
  (holds the device key), smoltcp (Mission Control; `kernel/src/mcserve.rs:1-11`, "one loop"),
  cfgd and mgmtabi.
- **EL0:** stateless excursions only. `el0-lansvc`: "no state survives a command"
  (`el0-lansvc/src/main.rs:8`). hsh runs with a 50 ms budget (`kernel/src/hsh.rs`). TLS runs in
  `el0-tlshost`.
- **Microkernel primitives** [PART, QEMU]:
  - capabilities and Untyped (`kernel/src/caps.rs:1-31`);
  - a single IPC endpoint (`kernel/src/ipc.rs:1-20`);
  - the scheduler (`kernel/src/scheduler.rs:1-25`);
  - the hardened SPSC device queue (`kernel/src/devq.rs`).
- **Configuration path** [IMPL, metal]: HQCFG1 plus cfgd trial/commit/revert
  (`kernel/src/cfgd.rs:1-25`), and the management-path guard covers `route … via mgmt`
  (`cfgd.rs:42-101`).
- **Learned state:** ADR 0059 D3 says "runtime state is never written back as configuration".
  This is the anchor for keeping protocol-learned routes out of configuration.
- **Single-core and memory facts** (ADR 0060/0061):
  - hboot parks secondary cores (`hboot/src/boot.s:28-30, 166-168`);
  - the CM5 boot map covers 4 GiB (`arch-aarch64/src/mmu_cm5.rs:33`);
  - the CM5 frame pool is 128 MiB, bump-allocated (`mmu_cm5.rs:405-425`);
  - the kernel heap is 1 MiB, bump-allocated (`kernel/src/heap.rs:10`).

### 1.5 Cross-tenant hazard in today's keying

IDS and enforcement state is keyed on bare IPv4 addresses:
- `actions::ip_held(u32)` (`kernel/src/actions.rs:182`);
- NAT;
- rate limiting;
- SrcKey (ADR 0049).

Once VRFs exist, a hold on `10.0.0.5` in tenant A would hit tenant B. **Keying by (VRF, address)
must land together with VRF support.**

## 2. Standards status (Deliverable B, verified 2026-11-11 against RFC Editor JSON)

**MPLS and Segment Routing**
- RFC 3031 and 3032 (PS). 3032 is updated by 3270, 3443 (TTL), 4182, 5129, 5332, 5462 (EXP
  renamed to TC), 5586, 7274 and 9017.
- LDP: RFC 5036 (DS), updated by 6720, 6790, 7358 and 7552.
- SR-MPLS: RFC 8660 (PS); the SR architecture is RFC 8402, updated by RFC 9256.

**L3VPN**
- RFC 4364 (PS), updated by 4577, 4684 and 5462.
- Related: 4659 (IPv6 VPN), 4576 (OSPF DN bit), 6565 (OSPFv3 PE-CE).
- RFC 8277 obsoletes 3107.

**OSPF**
- RFC 2328 is IS / STD 54, updated by 5709, 6549, 6845, 6860, 7474, 8042, 9355 and 9454.
- RFC 5340 (PS) is updated by 6845, 6860, 7503, 8362 and 9454. Its authentication trailer is
  RFC 7166, which obsoletes 6506.

**BGP**
- RFC 4271 is still **DS**. It is updated by 4724, 6286, 6608, 6793, 7606, 7607, 7705, 8212, 8654,
  9072, **9687** (Send Hold Timer, 2024) and **9774** (AS_SET deprecated, 2025).
- Base companions: 4760 (DS) and 4456 (DS); communities 1997, 4360 and 8092; route refresh 2918 and
  7313; ADD-PATH 7911.
- **RFC 8203 is obsoleted by RFC 9003.** Route leaks: RFC 9234.
- **Origin validation:** RFC 6811 is updated by 8481 and 8893. RFC 9324 updates 8481. RTR v1 is
  RFC 8210, which updates 6810.

**EIGRP**
- RFC 7868 is **Informational**, with 13 verified errata.

**BFD**
- RFC 5880 is updated by 7419, 7880, 8562 and 9747. Related: 5881, 5882, 5883, 5884 (updated by
  7726), 7130 and 9468.
- The 2026 authentication work (9985, 9986) and stability work (9978) are **Experimental**.

**VRRP and IS-IS**
- **VRRP:** RFC 9568 obsoletes RFC 5798.
- **IS-IS:** ISO/IEC 10589, plus RFC 1195, 5305 and 5308.

**Not re-verified:** RFC 5925 (TCP-AO), 5082 (GTSM), 7510 (MPLS-in-UDP), 8475 (conditional RAs),
7296 (IKEv2), 4303 (ESP), 9370, 6413, 7747, and the IKEv2 ML-KEM document.

### 2.1 Capability priorities

| Capability | Value for HookProbe | Priority |
|---|---|---|
| Logical interfaces, ingress demux, hierarchical FIB with VRF ids | Enables everything else | R1 |
| ribd and the FIB install ring | Required for any dynamic protocol | R2 |
| Multi-WAN, ECMP, PBR, IPv6 multihoming without NAT66, SQM shaping, BFD-lite | Highest value for SME | R3 |
| Multiple VRFs, leaks, tenant bundles, (VRF, address) keyed state | MSSP and PoP | R4 |
| eBGP: default-only → selective → full table | PoP, multi-site, cloud on-ramps | R5 |
| G19 PoP on heqk, IPsec/IKEv2 | PoP | R6 (parallel with R5) |
| iBGP/RR, communities, RPKI ROV | PoP federation | R7 |
| OSPFv2/v3 | Enterprise IGP integration | R9 |
| MP-BGP VPN / PE | Named customer only | R10 |
| MPLS label-stack *decode* for the IDS (observe only) | Fits the SOC mission | R4 |
| EIGRP, IS-IS, MPLS LSR | — | Not on the roadmap |

**An MPLS CE needs no MPLS:** an RFC 4364 CE is label-unaware.

## 3. Target architecture (Deliverable C)

```
 MANAGEMENT: Mission Control · hsh · AI Copilot (proposes diffs only) → mgmtabi → cfgd (single writer;
             HQCFG owner bundle + per-VRF tenant bundles + digest-referenced policy objects; trial/commit/revert)
 CP cores, EL0 persistent services (own ASID, own freeing heap, Untyped memory grant, CPU budget):
   bgpd (own TCP + TCP-AO; GTSM)   ikev2d   g19-pop (session control)   rtrc (RPKI)   bfd-ctl
        └── RouteProposal{instance badge, vrf, prefix, next hop, attribute handle} ──► ribd (per-VRF RIB;
            import/export policy; best path; recursion; ECMP/NHG; explicit redistribution and leaks)
 ribd ── FibOps on a shared-memory ring (Frame cap, Notification doorbell, quota) ──► EL1 FIB installer
 EL1: re-validates each op (VRF owns the NH interface? within quota? protected prefix?) → applies with
      A1/A2/A3 atomicity
 DP cores, EL1 run-to-completion per flow shard:
   RX → demux (port, S/C tag, PPPoE session, G19 sid, ESP SPI, [future label]) → logical interface → VRF
      → packet::verdict (IDS) → ACL in → [PBR] → FIB(vrf) → NHG (keyed ECMP hash) → NH → ACL out
      → NAT(vrf, egress) → encapsulation (VLAN / PPPoE / G19 / ESP / [future MPLS]) → TX
   Punt path: per-protocol and per-peer rate limits; one SPSC ring per DP core per service
 Safe FIB: connected + management + signed static routes, built by cfgd in EL1; used if ribd fails
```

### 3.1 Route lifecycle

1. **Punt.** The packet passes `packet::verdict`, then the punt classifier: a `PuntCap` matches
   (VRF, protocol, peer, TTL 255 for GTSM). It is rate-limited and placed on a ring.
2. **Parse in EL0.** A bounded, fuzzed parser handles the message; authentication is checked
   (TCP-AO, RFC 7474, RFC 7166).
3. **Propose.** The service sends a `RouteProposal` over a badged endpoint. The service cannot
   claim another instance or VRF.
4. **Select in ribd.** Import policy runs (eBGP has no default accept, per RFC 8212). Then quota,
   AD, best path, recursion (depth ≤ 4), NHG construction, and explicit redistribution.
5. **Install.** ribd writes FibOps. The installer validates them and applies them with:
   - **A1 per prefix:** a single-word atomic update.
   - **A2 per NHG:** atomic replacement, which gives prefix-independent failover.
   - **A3 per transaction:** shadow copy and swap, scoped to one VRF. Used for configuration
     changes and the initial table load.
6. **Record.** Telemetry and evidence-graph entries are written (`Route`, `RoutingNeighbor`,
   `RouteChange`). RPKI-invalid routes, leaks and surprise more-specifics become **observe-only**
   detections.
7. **On a service fault.** The last published FIB stays in place. Routes from the failed instance
   are marked stale and withdrawn after a bounded timer, falling back to the safe FIB.
   Recovery uses route refresh or graceful restart.

### 3.2 Configuration authority vs runtime state

- **Authority:** only signed configuration creates interfaces, VRF bindings, static routes,
  protocol instances, peers, key references, policies, leaks and quotas.
- **Runtime state:** learned routes, adjacencies and BFD state are never written to configuration
  (ADR 0059 D3).
- **Protocol services** cannot create a peer, a VRF or a leak, and cannot exceed a quota.

### 3.3 Designed for full tables

- **FIB layout per VRF, chosen by size:**
  - **DIR-24-8 style for large IPv4 tables.** Arithmetic, not measured: 2^24 × 2 B ≈ 32 MiB, plus
    512 B per /24 that has more-specifics. At most two memory reads per lookup.
  - **Compressed multibit trie** for IPv6 and small tenant VRFs.
  - **Node pools are sized at boot from the budgets** (ADR 0061), never from the kernel heap.
- **BGP postures:**
  - **default-only:** import policy accepts only 0/0.
  - **selective:** full RIB, partial FIB. A more-specific is suppressed only when it resolves to
    the same NHG as its covering installed route, so forwarding is unchanged.
  - **full:** full RIB and full FIB.
- **bgpd memory levers:** interned, reference-counted attributes; Adj-RIB-In storage is optional
  (route refresh replaces soft-reconfiguration inbound); update groups.
- **RIB memory model:** `P × (k_pfx + paths × k_path) + A_distinct × k_attr`. The coefficients are
  measured (§7), never assumed.

### 3.4 Tunnels

- **G19 on heqk:**
  - Port the `superpop` responder.
  - Session control runs in a persistent EL0 service. Seal/open runs in EL1 on DP cores, with each
    session pinned to one shard.
  - Each session is a tunnel interface in the tenant's VRF; the tenant comes from the authenticated
    msg2.
  - **A G19 v2 with IPv6 DATA is needed.**
  - The custody of the PoP responder's static key is still open (ADR 0050 step 4).
- **IPsec/IKEv2:**
  - Route-based tunnels.
  - IKEv2 runs in EL0. ESP runs in EL1 using constant-time AEAD (ADR 0062).
  - PQ-hybrid crypto is a policy choice under ADR 0002.

### 3.5 Tenancy and configuration

- **Owner bundle:** underlay, profile, VRF creation, tenant budgets, tenant-key delegation scoped
  to `(device, vrf)`, and leak authorization.
- **Tenant bundle:** its own VRF only, through the same cfgd trial, scoped per VRF.
- **Leaks:** both sides sign, and the owner bundle authorizes the pair.
- **Large policy objects:** signed artifacts referenced by digest. This removes the 16 KiB HQCFG1
  limit for policy.

### 3.6 MPLS readiness (deferred)

- The ingress-demux key and the next-hop encapsulation chain are generic, and ribd reserves a
  label-allocation API.
- A future PE then adds a label demux key, a LabelStack encapsulation, an LFIB pool and the VPN
  address families (4364/4659/8277). No new OS is needed.

## 4. Data model (Deliverable D, illustrative)

```rust
struct LogicalIf { idx: IfIndex /*u16+gen*/, name: Name16, role: IfRole, kind: IfKind /*Sub{port,encap}|Tunnel|Wifi*/,
                   vrf: VrfId /*cfgd only*/, l3: L3Mode, mtu: u16, nat: NatMode /*explicit*/, acl_in: Option<AclH>,
                   acl_out: Option<AclH>, oper: OperState }
// lan/eth1/wan/mgmt become RESERVED ALIASES of IfIndex 0..3, so HQPOL1, hsh R2 and signed bundles keep their meaning.
struct Vrf { id: VrfId /*0 default, 1 mgmt*/, tenant: Option<TenantId>, quota: VrfQuota, fib4: FibH, fib6: FibH }
struct FibEntry { pfx: Prefix, nhg: NhgId, src: RouteSrc, flags: FibFlags /*LEAKED|STALE|PROTECTED|OWNER_BLACKHOLE*/ }
struct NextHop { idx: NhId, ifx: IfIndex, gw: Option<Addr>, live: Liveness /*arp|probe|bfd*/, encap: EncapChainH }
struct NhGroup { id: NhgId, members: [NhId; ECMP_MAX], n: u8, hash_seed: u64 }
struct FlowKey { vrf: VrfId, proto: u8, src: Addr, dst: Addr, sport: u16, dport: u16 } // NAT/conntrack/IDS
// ip_held(u32) → held(VrfId, Addr); ADR 0049 SrcKey gains VrfId.
struct RibRoute { vrf, pfx, src: RouteSrc, inst: InstanceId, nh: NhSpec, metric: u32, ad: u8, tag: u32,
                  attrs: Option<AttrH> /*interned in the owning service*/, rov: Rov, state: RouteState }
struct BgpPeer { inst, addr, remote_as: u32, role: Option<Rfc9234Role>, auth: Option<SecretRef /*TCP-AO*/>,
                 ttl_security: bool, max_prefix: (u32, Act) /*MANDATORY*/, import: PolicyH /*MANDATORY for eBGP*/ }
struct ProtoQuota { neighbors: u16, prefixes_in: u32, lsas: u32, mem_kib: u32, cpu_budget: Budget, updates_per_s: u32 }
```

**Ownership and allocation:**
- **EL1:** fixed pools sized at boot from budgets.
- **EL0:** freeing heaps inside each service's Untyped grant.
- **Signed configuration objects:** immutable per generation.
- **Handles:** generation-tagged.

## 5. Security (Deliverable E)

| Attack surface | Mitigations |
|---|---|
| Route injection | Instance badges; mandatory eBGP import policy (RFC 8212); protected prefixes enforced by the **EL1 installer** |
| Route leaks | RFC 9234 roles and OTC, RFC 8893, default-deny export |
| Cross-VRF forwarding | VRF id in every FIB, NAT, conntrack and IDS key; leaks only through signed configuration, flagged and counted |
| Table exhaustion | Per-instance and per-VRF quotas, mandatory max-prefix, LSA caps |
| Malformed protocol packets | EL0 parsers with libFuzzer corpora; RFC 7606 treat-as-withdraw; service fault → stale routes → withdrawal |
| Route churn | Damping, rate-limited FIB transactions |
| Next-hop recursion | Depth ≤ 4, loop detection |
| ECMP | Keyed hash; NAT pins each flow's egress |
| MPLS, if ever built | Labels accepted only on enabled interfaces and never from the internet side; push depth ≤ 3 |
| TTL / MTU | RFC 3443 modes; MTU derived from the full encapsulation chain; rate-limited ICMP |
| Control-plane DoS | Punt caps, GTSM, TCP-AO, peer-address-only listeners |
| Compromised EL0 service | No FIB write path except through ribd and the validating installer; **never the device identity key** |
| Unauthorized policy change | Only through cfgd (signature, generation floor, the D7 management-path guard extended to PoP/tunnel paths) |
| RTBH / FlowSpec | Excluded (ADR 0023) |

## 6. Roadmap (Deliverable F)

| Phase | Scope | Key ADRs |
|---|---|---|
| **R0** (prerequisite) | SMP through hboot with stage-2 on every core; DRAM discovery; budgets; persistent EL0 services; per-core data-plane sharding; capacity profile and qualification harness | **0060, 0061, 0062**; amend `ARCHITECTURE.md:142-175` |
| R1 | Logical interfaces and demux; hierarchical FIB; VRF id in every key; real support for LAN-side next hops and IPv6 route selection. The interim fixes for the four §1.2/§1.3 defects are owned by the heqk session (2026-11-11). **The management VRF must keep** cfgd's D7 management-path invariant (`kernel/src/cfgd.rs:42-101`), and **frames addressed to the device's own address are handled without an uplink** (heqk rule-7 fix). | Interface ADR (amends hsh R2 and ADR 0059 D3); HQCFG schema major |
| R2 | ribd and the install ring; safe FIB; route-explain API | RIB placement ADR |
| R3 | Multi-WAN, per-next-hop health, NHG failover, ECMP, PBR, IPv6 multihoming, SQM, BFD-lite (EL1 fixed engine; an ADR 0050 exception) | Multi-WAN ADR |
| R4 | Multiple VRFs, leaks, tenant bundles, policy objects, keyed IDS/NAT state, MPLS decode for the IDS | VRF ADR; ADR 0049 amendment; separation-matrix re-proof |
| R5 | eBGP (default-only → selective → full) | BGP profile ADR |
| R6 | G19 PoP on heqk (v2 with IPv6), IPsec/IKEv2 | Tunnel ADR |
| R7 | iBGP/RR, communities, RPKI | — |
| R8 | PoP qualification per SKU (§7) → signed capacity attestations | — |
| R9 | OSPFv2/v3 | — |
| R10 | MP-BGP VPN / PE (named customer only) | — |

**Acceptance for every phase:** QEMU markers and metal evidence, fuzz budgets, an extended
separation matrix, and no regression of the ADR 0050 throughput floor.

## 7. PoP admission and qualification

**Admission rule:**

```
requested ≤ min(qualified envelope, available resources) and every hard ceiling holds
```

**Qualification suite**, run per (SKU, RAM, NICs, firmware, image, profile):
1. Memory headroom, including 2× churn.
2. Convergence: initial load, peer flap, NHG failover independent of table size, MRT replay at
   1× and 10×.
3. Forwarding: IMIX p50/p99, with IDS, NAT and tunnels active, **during** convergence storms.
4. CPU: control-plane core within budget; the forwarding cores unaffected by punt or UPDATE
   floods.
5. Security: fuzzing, max-prefix, leaks, capability misuse, the cross-VRF matrix, RFC 8212 and
   RFC 9234 behaviour.
6. Fault recovery under load.
7. Soak with churn replay and a RIB/FIB consistency audit.

**Security eligibility is a separate gate:** ADR 0062.

## 8. hsh and Mission Control

- **hsh:**
  - Read-only, view role: `interface`, `vrf`, `route show`, **`route lookup [vrf X] <addr>
    [from S]`** (the explain trace), protocol summaries, BFD and WAN history.
  - These need paged cursor messages in mgmtabi.
  - Operate role: `OP_*` messages for route refresh and peer reset. Journaled; never
    configuration.
  - **No routing writes in hsh.**
- **Mission Control:**
  - Essential view: WAN cards only.
  - Pro / Administration (capability-gated): topology, VRFs, route table with the explain trace,
    neighbours, route-change history, assurance status.

## 9. Decisions recorded and still open

- **Recorded:** see §0, plus the closure in ADR 0060/0062.
- **Still open:**
  - who signs capacity attestations (release only, or also on-site qualification);
  - the `HQRISK1` expiry ceiling;
  - custody of the qualification key;
  - confirmation of the `spec-test` image class.
