# os/networking — packet path, IPS and network services (index)

| Area | Source |
|---|---|
| Packet engine + IPS verdict (`decide()`, ADR 0023) | [`packet.rs`](../kernel/kernel/src/packet.rs), [`verdict.rs`](../kernel/kernel/src/verdict.rs), [`napi.rs`](../kernel/kernel/src/napi.rs), [`ratelimit.rs`](../kernel/kernel/src/ratelimit.rs) |
| TCP/IP stack and services (smoltcp) | [`net.rs`](../kernel/kernel/src/net.rs), [`netsvc.rs`](../kernel/kernel/src/netsvc.rs), [`netcfg.rs`](../kernel/kernel/src/netcfg.rs) |
| WAN uplink, NAT, PPPoE, IPv6 | [`uplink.rs`](../kernel/arch-aarch64/src/uplink.rs), [`nat.rs`](../kernel/arch-aarch64/src/nat.rs), [`pppoe.rs`](../kernel/arch-aarch64/src/pppoe.rs), [`ip6.rs`](../kernel/arch-aarch64/src/ip6.rs), [`ip6lan.rs`](../kernel/arch-aarch64/src/ip6lan.rs) |
| Segmentation (reach policy) | [`segment.rs`](../kernel/kernel/src/segment.rs) |
| L7 / blocklist | [`l7.rs`](../kernel/kernel/src/l7.rs) (signed L7 byte-pattern matching in the fast path), [`blocklist.rs`](../kernel/kernel/src/blocklist.rs) (signed threat-feed CIDR blocklist) |
| Shield v2 DNS protection (ADR 0052) | [`shield.rs`](../kernel/kernel/src/shield.rs) (per-query DNS policy on the AP: signed BLOCK/ALLOW lists, system floor, CNAME-cloak check, per-client profiles), [`dnssink.rs`](../kernel/kernel/src/dnssink.rs) (RPZ sinkhole answer: refuse a name, never a packet) |
| Threat intel + TLS fingerprinting | [`ioc.rs`](../kernel/kernel/src/ioc.rs) (operator-signed `IOC.TXT` pack: IPs, CIDRs, domains, expiry), [`ja4.rs`](../kernel/kernel/src/ja4.rs) (passive JA4 TLS client fingerprint + SNI from a ClientHello) |
| Device discovery + identity | [`devid.rs`](../kernel/kernel/src/devid.rs) (Fingerbank-parity device identification from DHCP evidence), [`oui.rs`](../kernel/kernel/src/oui.rs) (operator-signed full IEEE OUI registry `OUI.TXT`), [`discovery.rs`](../kernel/kernel/src/discovery.rs) (passive mDNS/SSDP announcements per MAC) |
| Wi-Fi station-to-station relay (G10) | [`lanrelay.rs`](../kernel/kernel/src/lanrelay.rs) (AP keeps `ap_isolate`; heqk relays unicast, mDNS/SSDP/LLMNR and IPv6 between stations after the lease + IDS gates) |
| Zero-copy ring design | [ZEROCOPY_IPC_RING.md](../kernel/ZEROCOPY_IPC_RING.md) |

Design docs: [network-fabric](../../docs/architecture/network-fabric.md),
[network-segmentation](../../docs/architecture/network-segmentation.md), ADR 0049 (WAN policy).
