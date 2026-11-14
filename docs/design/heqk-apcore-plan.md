# G0 — extracting the AP loop into `apcore` (plan, 2026-11-09)

The AP loop (`cm5_p10_probe` in `os/kernel/kernel/src/main.rs`, ~1,400 lines, `cm5`-only) had no QEMU
coverage; "passes QEMU, fails on metal" bugs concentrate in its glue. `apcore.rs` takes the decisions out,
behind an `ApNic` trait, so the code the board runs is the code `[P-apcore*]` runs on a recording fake NIC.

Rules for every step: generic `N: ApNic` (no `dyn` on the hot path), frames borrowed (no extra copy), the
metal boot log and counters byte-identical, every shipped flavor builds (`apmode`, the AP product, `prod`,
`prod-mc`), metal throughput (120–160 Mbps) and `[P11-AP3]` / `[M-NAT1]` re-checked after steps 1–3.

| Step | Scope (main.rs regions as of 2026-11-09) | Self-test | Status |
|---|---|---|---|
| 1 | `fwd4!` → `apcore::forward4` (in-ACL → route → out-ACL → hold → device policy → exfil → Shield → SNAT / reject / drop) | `[P-apcore]` | done |
| 2 | WAN drain → `on_wan_frame` (martian floor, `to_us`, reject rate limit 20/s, un-NAT, `lan out` block-as-drop, IPv6 new-flow `wan in`, Wi-Fi send / queue / drop, WIFI_MAX_FRAME) | `[P-apcore-wan]` | done (IPv4 leg; probe / NTP / IPv6 branches and the Wi-Fi queue still in the loop) |
| 3 | rest of the Wi-Fi data arm + eth1 + the Wi-Fi queue as `WifiQ` (bind check, `net::parse`, IDS, MC-bound, relay, proxy-ARP, IPv6); first move `ap_handle_data_into` into the pure `dhcpd` | `[P-apcore-lan]` (3a) | done: 3a IPv4 gate chain → `apcore::client4` (`[P-apcore-lan]`), 3b IPv6 → `apcore::client6`, 3c station-to-station → `apcore::station_relay` (`[P-apcore-relay]`) and eth1 → `client4` with `ETH1_PORT`; `WifiQ` still in the loop; metal re-check pending |
| 4 | `on_mgmt_frame` + MC flush routing | `[P-apcore-mgmt]` | done: the management inbound path → `apcore::on_mgmt_frame` (un-NAT → `<lan\|eth1> out` → IDS, else `mgmt in` → Mission Control); the MC flush routing was already the pure `mcmgmt::route` (A-03 own-address ARP, 2026-11-14) |
| 5 | `tick()`: stall detector, IPv6 renumber / RA, wanhealth scheduling, SIEM cursor, rule-drop table; `POLICY` / `V6` passed by reference | | |

Divergences to decide on purpose (kept identical for now, behind explicit per-port flags in step 3):
the eth1 path skips `net::parse`, `mc_bound`, `relay_target` and IPv6; mgmt un-NAT skips the
WIFI_MAX_FRAME check on the eth1 leg; `cyw43::ap_handle_data` sends ARP/DHCP replies straight through
`sdpcm_data_tx`, bypassing the Wi-Fi queue ordering.

Risks: aliasing (split borrows of `dh` / the Wi-Fi queue; never hold `&mut` to `MGMT` / `WAN6` / `V6`
across an `ApNic` call — pass copies), hot-path cost (compare the profiler `loop` / `wan_drain` slots),
image size (≤ 5 MiB; step 1 shrank `.text`).
