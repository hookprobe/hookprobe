# appliance/hookprobe-sbc — HookProbe board (RK3588)

**Status: in design. Not built, no heqk port yet.** Gated behind CM5 validation
([ADR 0064](../../docs/adr/0064-hookprobe-hardware-program.md): H0 CM5 validated → H1 HAL decoupling → H2 heqk on an
intermediate RK3588 board → H3 our board routed + reviewed → H4 prototype bring-up).

The board's design files are in [`hardware/hookprobe-sbc/`](../../hardware/hookprobe-sbc/) (CERN-OHL-S-2.0 +
commercial, ADR 0064 D6). This page is only how HookProbe OS sees the board.

## Capabilities the board would grant (once each driver passes its metal gate)

Granted from the Platform Manifest, never from the board name. Everything starts absent.

| Capability (ADR 0003 token) | Hardware | Phase |
|---|---|---|
| `soc`, `ids`, `inline_ips` (two-port inline) | RK3588 + 2× RTL8125 2.5 GbE (PCIe) | H2 → H4 |
| `tpm`, `tpm_sealed` (crypto posture) | TPM 2.0 on SPI | H4 |
| local retention on NVMe (storage fact, sizes the retention window) | M.2 NVMe | H4 |
| `wifi`, `wifi_ap` (WIDS receive-only) | Qualcomm QCN9274 Wi-Fi 7 (M.2, PCIe) | H2 bring-up → H4 |
| `cellular` (5G) | Sierra Wireless EM9293 (M.2, USB 3, MBIM) | H2 bring-up → H4 |
| `edge_ai` | RK3588 NPU; M.2 accelerator slot | later |
| Thread / Matter (**no token yet**: needs an ADR 0003 amendment) | Thread module on a UART | later |

Token names are the ones in `legacy/linux-tier/manifest/schema/manifest.schema.json` and the legacy
`rk3588.yaml`. New tokens are added in ADR 0003, never invented here.
