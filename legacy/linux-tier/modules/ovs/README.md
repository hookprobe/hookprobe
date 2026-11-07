# ovs — OpenVSwitch dataplane (host-integral SDN)

> The programmable forwarding plane. Host-integral (kernel datapath + control daemons),
> so it is delivered as an **image-layer module**, not Wasm. The supervisor gates it by
> the `openvswitch` capability and enables the bring-up unit; flow PROGRAMMING by policy
> modules funnels through the OS-Agent bridge.

Canon: `docs/architecture/runtime-engine-map.md` (`shared/hostapd-ovs` + `shared/network`; `sdn`
token), `docs/architecture/Readme.md` (Pillar 1 image-layer; "Data plane"), `docs/architecture/Architecture.md`
(C12; §4.4 OS-Agent bridge), `docs/adr/0003` (`openvswitch` capability). Sysext-vs-image
model + supervisor gating: `../../base/sysext/README.md`.

## Runtime choice: image-layer (not sysext) — why

OVS binaries (`openvswitch-switch`, `openvswitch-common`) are **already in the base image**
(`base/Containerfile` Layer A). A sysext re-shipping `/usr/bin/ovs-*` would duplicate that.
So this module ships only **config + a manifest-driven bring-up unit + per-segment
fail-mode wiring**, all baked into the same bootc image and versioned atomically with it.
CI copies `modules/ovs/units/` → `/usr/lib/systemd/system/` and `modules/ovs/config/` →
`/usr/lib/hookprobe/ovs/` (mirroring how `base/units/` are installed).

It would instead be a **sysext** if (a) OVS were dropped from the base to keep it minimal,
or (b) for the patched **`hostapd-ovs`** build (`~/hookprobe/shared/hostapd-ovs`, NOT in the
base) — that patched hostapd is a separate sysext candidate providing `wifi_ap`-over-OVS,
out of scope here.

## Host capabilities = honest non-Wasm boundary

`CAP_NET_ADMIN` (create bridges/ports, set OpenFlow flows + fail-mode) and `CAP_SYS_MODULE`
(load the `openvswitch` kernel datapath). A Wasm module can hold neither. Segmentation
policy modules (`shared/network` OpenFlow controller) are Wasm and emit intent; the actual
privileged `ovs-vsctl`/`ovs-ofctl` calls go through the OS-Agent bridge (Architecture §4.4),
keeping the privileged surface narrow and auditable rather than scattered.

## Inline vs out-of-band posture

OVS is inherently an **inline** element (it forwards). HookProbe's default is still
out-of-band: for an out-of-band interface, `ovs-bringup` does **not** add it to the
forwarding bridge — it mirrors a copy to a SPAN port that feeds the NAPSE capture path,
leaving production forwarding on the host (zero connectivity risk). Inline OVS forwarding
is the explicit opt-in (segmentation, VLAN isolation, "isolate this host").

## Fail-open (default) / fail-closed — wiring

The bring-up maps the manifest's per-interface `fail_mode` directly onto OVS's own bridge
`fail_mode`:

| HookProbe | OVS `fail_mode` | Behavior if the OpenFlow controller is gone |
|---|---|---|
| **fail-open** (default) | `standalone` | bridge acts as a normal learning L2 switch → traffic flows |
| **fail-closed** (high-security) | `secure` | only existing flows kept, no new flows → unknown traffic dropped |

Default bridge `hp-br0` is `standalone` (fail-open). An inline interface with
`fail_mode=fail-closed` in the manifest flips its bridge to `secure`. This is the OVS-side
mirror of the NAPSE fail-closed handler and realizes the Readme invariant: an edge box must
never be able to take the network down with it.

## TODOs only CI / real hardware can close

- Validate bridge bring-up + `fail_mode` flip on real OVS (no OVS/root/datapath here).
- Kernel datapath (`openvswitch.ko`) vs `netdev` (userspace) datapath fallback per platform;
  confirm the module is present on Pi5/RK3588/N100 kernels or set `datapath_type=netdev`.
- Lock the **segment schema** (`config/segments.yaml`) in an ADR (VLANs, inter-segment policy).
- Wire SPAN/mirror creation for out-of-band interfaces.
- Confirm OpenFlow flow programming funnels through the single OS-Agent bridge (open-Q 4 in
  runtime-engine-map), not this oneshot (which only creates bridges/ports + sets fail-mode).
