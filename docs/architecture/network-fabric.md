# Network Fabric — modular L2/L3 data plane (one model, every edge)

> One declarative fabric model that scales from a 4-port edge LAN (the N100) to a
> single-NIC cloud router of segmented VRFs. The operator declares **segments and
> policy**; `crate::fabric` renders the bring-up plan from the **signed manifest** +
> intent; the shell oneshot (`modules/ovs`) becomes a thin executor of a generated
> plan. Same intent→artifact loop as `multi_wan` / `wifi_cfg`.
>
> Device→segment **identity** (why MAC filtering isn't enough) is a separate concern:
> see **`docs/architecture/network-segmentation.md`**.

## The load-bearing idea: two complementary planes

OVS and VRF are **not** alternatives — they solve different problems and compose:

| Plane | Job | Meaningful when | Backed by |
|---|---|---|---|
| **L2 switching** | move frames between local ports; VLAN-segment a LAN | **≥2 LAN carriers** (ports/AP radios to switch between) | OVS bridge (OpenFlow), or a kernel **Linux bridge** fallback |
| **L3 routing separation** | split routes out of the global table into isolated domains | any time you need route isolation — **even on 1 NIC** | kernel **VRF** + per-VRF table + nftables |

A box can run **both** (hybrid): switch its LAN at L2 *and* be a multi-domain router at L3.
The plane(s) are chosen from **topology + capability** (`kind: auto`, the default), with
explicit `ovs-bridge` / `vrf-segmented` / `hybrid` as overrides.

```
                       kind: auto
                          │
        ┌─────────────────┴───────────────────┐
   ≥2 LAN carriers?                      else (≤1 carrier)
        │ yes                                  │
   L2 switching                          segments declared?
   (OVS, or Linux-bridge                  │ yes        │ no
    fallback if openvswitch         L3 VRF routing   flat bridge
    capability not granted)         separation       (nothing to switch yet)
```

## What the reconciler generates

`hookprobe-supervisor --fabric-plan [--fabric-intent f.yaml] [--fabric-write DIR]`
reads `network.interfaces` + `network.uplinks` (WAN uplink = top wired uplink, kept OFF
the bridge) + the `openvswitch` capability, and emits idempotent artifacts:

- **`fabric/60-<br>.ovs.plan`** — `ovs-vsctl --may-exist add-br/add-port`, `fail_mode`
  (`standalone`=fail-open default / `secure`=fail-closed if any segment is), per-segment
  internal VLAN ports (`type=internal tag=<vlan>`), and `tc mirred` taps for out-of-band
  ports → the IDS mirror (`mirror_to`). *(V1: `FTS` bridge + `setup-ids-mirror.sh`.)*
- **`fabric/61-<br>.flows.of`** — OpenFlow: baseline `arp/ip → normal`, MAC→VLAN bindings
  (`priority=200,dl_src=…,actions=mod_vlan_vid:…`), onboarding catch-all, fail-closed drop.
  *(V1: `fortress` + `vlan_manager.py` flows.)*
- **`fabric/62-<br>.radius`** — 802.1X identity → `Tunnel-Private-Group-Id` (durable, see
  segmentation doc). *(V1: FreeRADIUS `authorize`.)*
- **`fabric/60-<br>.linux-bridge.plan`** — kernel-bridge fallback (`ip link … type bridge`,
  `vlan_filtering 1`) when OVS isn't granted; honestly notes MAC binding needs OpenFlow.
- **`fabric/60-vrf.plan`** — `ip link add vrf-hp-<seg> type vrf table <100+vlan>` per
  segment + an `nft inet hookprobe_vrf` forward chain (`policy drop`, fail-closed → no
  egress). *(V1: `setup-vrf.sh`.)*

Every artifact carries the "do not edit — declare intent instead" banner.

## Intent schema (`fabric-intent.yaml`)

```yaml
kind: auto | ovs-bridge | vrf-segmented | hybrid   # default: auto
bridge: hp-br0                                      # L2 bridge name
mirror_to: dummy-mirror                             # out-of-band IDS tap (optional)
unknown_segment: onboarding                         # where un-bound devices land
segments:
  - { name: trusted,  vlan: 10 }
  - { name: cameras,  vlan: 30, fail: fail-closed } # fail-closed → secure / no-egress
mac_bindings:
  - { mac: "9c:8e:cd:11:22:33", segment: cameras }            # stable-OUI IoT (flow)
  - { mac: "alice@corp", segment: corp, via: dot1x }          # 802.1X identity (RADIUS)
```

## Validated against the live exemplars (read-only)

- **N100 (LAN):** `auto` → **ovs-bridge** — 5 LAN members (3 ethernet + both AP radios),
  `enp1s0` WAN left off-bridge, fail-closed `cameras` → `fail_mode=secure`. Matches the
  running V1 `FTS`/OVS posture.
- **Cloud (WAN):** `auto` → **vrf-segmented** — `vrf-hp-{public,mssp,ids}` on tables
  101/102/103, `ids` fail-closed → no egress. Matches the live `vrf-hp-*` deployment.

## Invariants

- **Capability-gated, never hardware-branched** — OVS vs Linux-bridge vs VRF is decided by
  the `openvswitch` capability + topology, read from the manifest, not by "is this a Pi?".
- **WAN never bridged** — the route to the internet is never enslaved to the LAN switch.
- **Fail-open by default** — an edge never takes the network down; fail-closed is per-segment opt-in.
- **Config is a generated artifact** — reproduced from the signed manifest every run; the
  oneshot executes, it does not author.

## Status / next

Built: the reconciler + both planes + capability fallback + the segmentation primitives
(52 lib tests; report §8.17). Next: align `modules/ovs/ovs-bringup` to consume these
generated plans; behavioural fingerprinting, hostapd-EAP, microsegmentation, and
continuous-trust dynamic re-segmentation (see `docs/architecture/network-segmentation.md` §5).
