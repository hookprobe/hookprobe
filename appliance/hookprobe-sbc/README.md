# appliance/hookprobe-sbc — HookProbe SBC (RK3588), rev A

**Status: research design. Not routed, not built, no heqk port yet.** Gated behind CM5 validation
([ADR 0064](../../docs/adr/0064-open-hardware-hookprobe-board.md) D1/D3: H0 CM5 validated → H1 HAL decoupling →
H2 heqk on ROCK 5B → H3 routed + reviewed → H4 prototype bring-up).

| What | Where |
|---|---|
| Board design (KiCad, generator scripts, BOM, renders, validation report) | [`hardware/hookprobe-sbc/`](../../hardware/hookprobe-sbc/) |
| Direction, gates, driver delta, boot chain, licence | [ADR 0064](../../docs/adr/0064-open-hardware-hookprobe-board.md) |
| Legacy Linux-tier RK3588 profile (capability policy reference) | [`legacy/linux-tier/platforms/rk3588.yaml`](../../legacy/linux-tier/platforms/rk3588.yaml) |
| heqk port sizing | [`heqk-everywhere-report-2026-10-09.md`](../../docs/design/heqk-everywhere-report-2026-10-09.md) §4 item 9 (see ADR 0064 D4: this board uses PCIe RTL8125, not stmmac) |

## Capabilities the board would grant (once each driver passes its metal gate)

Granted from the Platform Manifest, never from the board name. Everything starts absent and is granted only when
its driver passes its metal gate.

| Capability (ADR 0003 token) | Hardware | Phase |
|---|---|---|
| `soc`, `ids`, `inline_ips` (two-port inline) | RK3588 + 2× RTL8125BG 2.5 GbE (PCIe) | H4 |
| `tpm`, `tpm_sealed` (crypto posture) | Infineon SLB9670, SPI1 | H4 |
| local retention on NVMe (storage fact, sizes the retention window) | M.2 M-key 2280 | H4 |
| RTC across power loss (hardware fact) | HYM8563 + battery | H4 |
| `wifi`, `wifi_ap` (WIDS receive-only) | M.2 E-key card, chipset to be chosen | later |
| `cellular` (5G) | M.2 B-key on USB 3 + nano-SIM | later |
| `edge_ai` | RK3588 NPU; M.2 M-key accelerator slot | later |
| Thread / Matter (**no token yet**: needs an ADR 0003 amendment) | ESP32-H2-MINI-1 on a UART | later |
| USB-C PD power input (boot-chain feature, not a capability) | FUSB302 (until then: DC jack 12–20 V only) | later |

Token names are the ones in `legacy/linux-tier/manifest/schema/manifest.schema.json` and the legacy
`rk3588.yaml`. New tokens are added in ADR 0003, never invented here.
