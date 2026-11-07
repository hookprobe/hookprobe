# os/networking — packet path, IPS and network services (index)

| Area | Source |
|---|---|
| Packet engine + IPS verdict (`decide()`, ADR 0023) | [`packet.rs`](../kernel/kernel/src/packet.rs), [`verdict.rs`](../kernel/kernel/src/verdict.rs), [`napi.rs`](../kernel/kernel/src/napi.rs), [`ratelimit.rs`](../kernel/kernel/src/ratelimit.rs) |
| TCP/IP stack and services (smoltcp) | [`net.rs`](../kernel/kernel/src/net.rs), [`netsvc.rs`](../kernel/kernel/src/netsvc.rs), [`netcfg.rs`](../kernel/kernel/src/netcfg.rs) |
| WAN uplink, NAT, PPPoE, IPv6 | [`uplink.rs`](../kernel/arch-aarch64/src/uplink.rs), [`nat.rs`](../kernel/arch-aarch64/src/nat.rs), [`pppoe.rs`](../kernel/arch-aarch64/src/pppoe.rs), [`ip6.rs`](../kernel/arch-aarch64/src/ip6.rs), [`ip6lan.rs`](../kernel/arch-aarch64/src/ip6lan.rs) |
| Segmentation (reach policy) | [`segment.rs`](../kernel/kernel/src/segment.rs) |
| L7 / DNS sinkhole / blocklist | [`l7.rs`](../kernel/kernel/src/l7.rs), [`dnssink.rs`](../kernel/kernel/src/dnssink.rs), [`dnsblock.rs`](../kernel/kernel/src/dnsblock.rs), [`blocklist.rs`](../kernel/kernel/src/blocklist.rs) |
| Zero-copy ring design | [ZEROCOPY_IPC_RING.md](../kernel/ZEROCOPY_IPC_RING.md) |

Design docs: [network-fabric](../../docs/architecture/network-fabric.md),
[network-segmentation](../../docs/architecture/network-segmentation.md), ADR 0049 (WAN policy).
