# heqk driver provenance register

This register records, per heqk driver file, the external sources its own comments cite. ADR 0067 D11
requires it: every driver has a provenance entry, and code whose only recorded source is a GPL-2.0 file
is rewritten from a functional note. Date: 2026-11-19. Commit: `a25eb6464`.

The register records what our own comments say. It is not a legal opinion and not a code comparison.
No upstream source was read to build it beyond the first lines that carry the SPDX identifier.

Classes (the worst class in a file wins: D > C > B > A):

- **A** — no external code cited. Own design, or only specifications, datasheets, standards, register facts.
- **B** — cites permissively licensed code (ISC, BSD, MIT, Apache-2.0) as a source.
- **C** — cites GPL-2.0 code only as a behaviour or register-value reference ("as Linux does", "Linux uses X").
- **D** — says it was transcribed, ported, mirrored or copied from GPL-2.0 code, or quotes its lines.

Scope: every `.rs` file in `os/kernel/arch-aarch64/src` and `os/kernel/hboot/src` (57 files), plus the
files in `hal/src`, `sae/src`, `el0-wifi/src`, `el0-wpa/src` and `kernel/src` that cite an external code
base (14 files). Paths are relative to `os/kernel`. "Linux" in a comment that means HookProbe's own
legacy Linux tier (parity notes, rule numbers, `legacy/linux-tier` ports) is not provenance and is not listed.

## Summary

| Class | arch-aarch64/src | hboot/src | other dirs | Total |
|---|---|---|---|---|
| A | 31 | 8 | 1 | 40 |
| B | 1 | 0 | 7 | 8 |
| C | 8 | 2 | 6 | 16 |
| D | 5 | 2 | 0 | 7 |
| Total | 45 | 12 | 14 | 71 |

Class D files. Each needs a clean rewrite from a functional note, or a counsel decision.

- `arch-aarch64/src/gem.rs` — RP1 MSI-X enable "mirroring Linux drivers/mfd/rp1.c EXACTLY" (GPL-2.0), and
  three comment blocks that quote `macb_main.c` source lines (GPL-2.0-only). Rewrite the MSI-X enable from the
  RP1 datasheet; delete the quoted lines.
- `arch-aarch64/src/rtl8111.rs` — PCIe RC MDIO read and outbound window "Mirrors Linux" `pcie-brcmstb.c`
  (GPL-2.0+); station address follows `r8169` `rtl_rar_set` (GPL-2.0-only). No datasheet is cited for either.
- `arch-aarch64/src/cyw43.rs` — SDHCI cfg block "Mirrors sdhci_brcmstb_cfginit_2712" (GPL-2.0-only). The rest
  of the file cites ISC code (brcmfmac, OpenBSD bwfm). Only the cfg init and the Linux MMC references need work.
- `arch-aarch64/src/rng200.rs` — register map "transcribed from Linux" `iproc-rng200.c` (GPL-2.0-only). No
  datasheet is cited. Sole recorded source is GPL.
- `arch-aarch64/src/mailbox.rs` — quotes seven lines of `drivers/firmware/raspberrypi.c` (GPL-2.0) in a comment.
  The code itself uses firmware property tags (facts). Deleting the quote would leave class C.
- `hboot/src/rng.rs` — "Register map + init/read sequence transcribed from Linux" `iproc-rng200.c`
  (GPL-2.0-only). Sole recorded source is GPL.
- `hboot/src/watchdog.rs` — disarm "Mirrors the Linux bcm2835_wdt stop sequence" (GPL-2.0+). One function,
  about four lines; the arm path cites only our own `boot.s`.

## Register

Citations give our file:line. Quotes are the comment's own words.

### arch-aarch64/src

| File | What it drives | Cited sources | Relation, in the comment's own words | Upstream licence | Class |
|---|---|---|---|---|---|
| `arch-aarch64/src/apparse.rs` | Parsers: DHCP, CYW43455 firmware events, EAPOL match | `bcmevent.h` (:6); brcmfmac struct `brcmf_event_msg_be` (:17) | "brcmf event codes the authenticator reacts to (bcmevent.h)" (:6) | brcmfmac ISC; `bcmevent.h` not verified | B |
| `arch-aarch64/src/bpf_jit.rs` | BPF JIT to aarch64 | RFC 9669 (:3); PREVAIL-style verifier (:11); Linux BPF JIT (:215) | "per the ... hardening + the Linux JIT constant-blinding design" (:215) | Linux JIT GPL-2.0 (file not identified, not verified) | C |
| `arch-aarch64/src/bt.rs` | CYW43455 Bluetooth over HCI-UART | `bcm2712-rpi-cm5.dtsi` (:7), `bcm2712-ds.dtsi` (:9), `gpio-brcmstb.c` (:11), `btbcm_initialize()` (:17), `pinctrl-bcm2712.c` (:26, :84) | "Source-verified against the RPi kernel tree" (:6); "Register-EXACT from the working CM5 Linux + pinctrl-bcm2712.c" (:26) | `gpio-brcmstb.c` GPL-2.0-only; `pinctrl-bcm2712.c` GPL-2.0+; `btbcm.c` GPL-2.0-or-later; DT GPL-2.0 / (GPL-2.0 OR MIT) | C |
| `arch-aarch64/src/crashrec.rs` | Crash record in reserved DRAM | none | own design, placed by measurement | — | A |
| `arch-aarch64/src/cyw43.rs` | CYW43455 Wi-Fi over SDIO (STA + AP), SDHCI host setup | brcmfmac `sdio.c`, `chip.c`, `cfg80211.c`, `common.c`, `fwil_types.h`, `fweh.h` (:530, :628, :643, :703, :1026, :1037, :1360, :1937, :2128, :2725, :2773, :3328); OpenBSD `bwfm` (:602, :887, :1361); Pico-W `cyw43-driver` (:11); `sdhci_brcmstb_cfginit_2712` (:322); Linux `mmc_sdio_switch_hs` (:1300); `pinctrl-bcm2712.c` (:404); hostapd (:3156, :5536, :6657); SD specification (:11) | "Mirrors sdhci_brcmstb_cfginit_2712" (:322); "a port of brcmf_sdio_rxfail (sdio.c, ...)" (:2128); "mirror brcmf_config_dongle, cfg80211.c:7968 ... EXACT ORDER" (:2773); "Mirrors brcmfmac `brcmf_process_nvram`" (:703); "Linux `mmc_sdio_switch_hs` / `sdio_enable_hs`" (:1300); "structured from brcmfmac + OpenBSD bwfm" (:602) | `sdhci-brcmstb.c` GPL-2.0-only; `mmc/core/sdio.c` GPL-2.0-or-later; `pinctrl-bcm2712.c` GPL-2.0+; brcmfmac ISC; OpenBSD bwfm ISC (not verified by SPDX); cyw43-driver not verified; hostapd BSD-3-Clause | D |
| `arch-aarch64/src/dhcpd.rs` | DHCP server lease table, client fingerprint | none ("Linux" at :212–:231 is a fingerprint label) | own design | — | A |
| `arch-aarch64/src/emmc.rs` | eMMC block device on the second BCM2712 SDHCI | SD/eMMC specification (:14); own `sdhci.rs` (:15) | "structured off the SD/eMMC spec + the metal-proven SDHCI primitives" (:14) | — | A |
| `arch-aarch64/src/exception.rs` | Unexpected-fault handler | none | own design | — | A |
| `arch-aarch64/src/gem.rs` | RP1 Cadence GEM Ethernet (MAC, PHY, rings, MSI-X, PCIe windows) | `drivers/net/ethernet/cadence/macb_main.c` (:6, :128, :137, :146, :243, :265, :291, :331, :440, :900, :1053, :1062, :1064, :1089, :1171, :1967, :1992); `drivers/mfd/rp1.c` (:1363, :1530); `pcie-brcmstb.c` (:185, :210, :224, :1403, :1464, :1533, :1656); `irq-bcm2712-mip.c` (:1653, :1668); `broadcom.c` (:586), `bcm-phy-lib.h` (:601), `bcm54xx_config_clock_delay()` (:569); U-Boot macb (:137); `bcm2712.dtsi`, `rp1.dtsi` (:221, :803, :1527); RP1 datasheet (:975, :1598, :1770, :1838, :1873) | "mirroring Linux drivers/mfd/rp1.c EXACTLY (not a guess)" (:1363); "Match the Linux reference EXACTLY" (:1559); "Grounded in the reference driver for this exact controller" (:1052); "exactly as Linux bcm54xx_config_clock_delay()" (:569); "Register map + descriptor format confirmed vs the Linux `macb` driver" (:5). Upstream source lines are quoted in comments at :245–:246, :1055–:1058, :1994–:1999 | `macb_main.c` GPL-2.0-only; `rp1.c` GPL-2.0 (raspberrypi/linux); `pcie-brcmstb.c` GPL-2.0+; `irq-bcm2712-mip.c` GPL-2.0-only; `broadcom.c` GPL-2.0+; `bcm-phy-lib.h` GPL-2.0; U-Boot `macb.c` GPL-2.0+; DT (GPL-2.0 OR MIT) | D |
| `arch-aarch64/src/gic.rs` | GICv2 | Arm GIC register layout | register facts | — | A |
| `arch-aarch64/src/gic_v3.rs` | GICv3 (cloud tier) | Arm GICv3 register layout; measured OCI A1 | register facts | — | A |
| `arch-aarch64/src/iommu.rs` | BCM2712 IOMMU address fence | `raspberrypi/linux drivers/iommu/bcm2712-iommu.c` (:15, :27); `bcm2712.dtsi` (:16); RPi forum t=391572 (:16) | "Sources: raspberrypi/linux drivers/iommu/bcm2712-iommu.c + bcm2712.dtsi" (:15); "Register offsets ... (from bcm2712-iommu.c)" (:27) | `bcm2712-iommu.c` GPL-2.0-only; DT (GPL-2.0 OR MIT) | C |
| `arch-aarch64/src/ip6.rs` | Re-export of `hal::ip6` | none | own code | — | A |
| `arch-aarch64/src/ip6lan.rs` | IPv6 LAN router and firewall | RFC 4861, RFC 8106, RFC 4890 (:4–:10) | standards | — | A |
| `arch-aarch64/src/lib.rs` | aarch64 HAL crate root | none | own design | — | A |
| `arch-aarch64/src/mailbox.rs` | VideoCore property mailbox (clock, power, reboot flags, RTC) | own `hboot/src/mailbox.rs` (:2); `drivers/firmware/raspberrypi.c` (:132, :222); `include/soc/bcm2835/raspberrypi-firmware.h` (:142); Linux `rtc-rpi` (:191) | "From the reference driver, Linux drivers/firmware/raspberrypi.c:204" (:131), followed by seven quoted source lines (:134–:140); "Linux issues this on EVERY reboot" (:221) | `raspberrypi.c` GPL-2.0; `raspberrypi-firmware.h` GPL-2.0; `rtc-rpi.c` GPL-2.0 OR BSD-3-Clause (raspberrypi/linux) | D |
| `arch-aarch64/src/mgmtproto.rs` | Management sub-interface IPv4 (ARP, ping, DHCP client) | none | own design | — | A |
| `arch-aarch64/src/mmu.rs` | Stage-1 MMU and frame allocator (QEMU) | Arm architecture | own design | — | A |
| `arch-aarch64/src/mmu_cm5.rs` | Stage-1 MMU on BCM2712 | Linux `dma_alloc_coherent` (:38); own `mmu.rs` (:51, :397) | "matching Linux's dma_alloc_coherent" (:38) | Linux DMA API GPL-2.0 (file not identified, not verified) | C |
| `arch-aarch64/src/nat.rs` | IPv4 source NAT | Linux SDIO trace on the CM5 (:38) | "the Linux-traced sequence, metal-proven 2026-11-04" (:38) | observed behaviour of GPL-2.0 code, no file cited | C |
| `arch-aarch64/src/pci.rs` | PCIe ECAM config access (cloud tier) | PCI configuration space layout | specification facts | — | A |
| `arch-aarch64/src/perfctr.rs` | Work counters (ADR 0067 D1) | none | own design | — | A |
| `arch-aarch64/src/pppoe.rs` | PPPoE and PPP client | RFC 2516, 1661, 1334, 1994, 1332, 1877, 5072 (:1, :20); pppd option names (:57) | "as pppd's lcp-echo-interval / lcp-echo-failure" (:57) — configuration names, no code cited | — | A |
| `arch-aarch64/src/reject.rs` | TCP RST / ICMP reject builder | RFC 9293, RFC 1812, RFC 4443 (:3–:7) | standards | — | A |
| `arch-aarch64/src/rng200.rs` | BCM2712 TRNG (rng200), fail-closed | `drivers/char/hw_random/iproc-rng200.c` (:15–:16) | "shares the register map (transcribed from Linux ... same source HBoot used)" (:15) | GPL-2.0-only | D |
| `arch-aarch64/src/rp1.rs` | RP1 common layer (bases, clocks, delays) | RP1 datasheet (:14, :29, :36, :61, :143, :148, :154); `rp1.dtsi` (:36); `clk-rp1.c` (:148) | "register offsets (from clk-rp1.c / RP1 datasheet CLOCKS map)" (:148) | `clk-rp1.c` GPL-2.0 (mainline), GPL-2.0+ (raspberrypi/linux); `rp1.dtsi` no SPDX in first lines, not verified | C |
| `arch-aarch64/src/rp1_gpio.rs` | RP1 bank0 GPIO and pinmux | RP1 datasheet (:49) | register facts | — | A |
| `arch-aarch64/src/rp1_i2c.rs` | RP1 I2C master (Synopsys DW_apb_i2c) | Synopsys DW_apb_i2c register facts | register facts | — | A |
| `arch-aarch64/src/rp1_spi.rs` | RP1 SPI master (Synopsys DW_apb_ssi) | Synopsys DW_apb_ssi register facts | register facts | — | A |
| `arch-aarch64/src/rp1_uartp.rs` | RP1 peripheral UART (PL011) | Arm PL011 register facts | register facts | — | A |
| `arch-aarch64/src/rtl8111.rs` | RTL8111H Ethernet on external PCIe RC1, RC bring-up | own `gem.rs` (:3); `pcie-brcmstb.c` `brcm_pcie_mdio_read` (:196), `brcm_pcie_set_gen` rpi-6.6.y (:230), `brcm_pcie_set_outbound_win` (:377); Linux PERST timing (:305, :314); `r8169` (:470, :610); FreeBSD link-state register (:94) | "Mirrors Linux `brcm_pcie_mdio_read`" (:195); "Mirrors Linux `brcm_pcie_set_outbound_win`" (:377); "r8169's rtl_rar_set: unlock CFG9346, write MAC4" (:610) | `pcie-brcmstb.c` GPL-2.0+; `r8169_main.c` GPL-2.0-only; FreeBSD not verified | D |
| `arch-aarch64/src/sdhci.rs` | SDHCI v3 helper layer (base-parameterized) | own `cyw43.rs` (:3, :189, :251, :298, :348); Linux `sdhci_set_transfer_mode` (:340) | "a faithful TRANSCRIPTION of the metal-proven SDHCI knowledge in `cyw43.rs`" (:3); "Matches Linux `sdhci_set_transfer_mode`" (:340) | `sdhci.c` GPL-2.0-or-later | C |
| `arch-aarch64/src/semihosting.rs` | Arm semihosting exit (QEMU) | Arm semihosting; PSCI | specification facts | — | A |
| `arch-aarch64/src/smccc.rs` | SMCCC over HVC: PSCI, TRNG (cloud tier) | Arm DEN0098 (:2); Linux `smccc_trng` (:3); Linux `psci_init_smccc` (:15) | "(the Linux `psci_init_smccc` procedure)" (:15) | `psci.c` GPL-2.0-only; `smccc.c` GPL-2.0-only | C |
| `arch-aarch64/src/syscall.rs` | EL0 entry / kernel resume glue | none | own design | — | A |
| `arch-aarch64/src/thread.rs` | Thread trap-frame context | none | own design | — | A |
| `arch-aarch64/src/timer.rs` | Arm generic timer | Arm architecture | register facts | — | A |
| `arch-aarch64/src/uart.rs` | PL011 console | Arm PL011; board wiring ("Linux's ttyAMA0" at :9 names the port) | register facts | — | A |
| `arch-aarch64/src/uplink.rs` | Wired WAN uplink (DHCP, ARP, PPPoE dial) | own `cyw43.rs` builders (:9) | own design | — | A |
| `arch-aarch64/src/virtio.rs` | virtio-net one-shot (QEMU / cloud) | virtio specification | specification facts | — | A |
| `arch-aarch64/src/virtio_blk.rs` | virtio-blk | virtio specification | specification facts | — | A |
| `arch-aarch64/src/virtio_net.rs` | virtio-net, persistent | virtio specification | specification facts | — | A |
| `arch-aarch64/src/virtio_transport.rs` | virtio-mmio v2 / virtio-pci modern transport | virtio 1.x specification | specification facts | — | A |
| `arch-aarch64/src/wan6eth.rs` | IPv6 on an Ethernet WAN | RFC 4861, RFC 4443 (:5) | standards | — | A |
| `arch-aarch64/src/wanparse.rs` | WAN control parser dispatch (kernel / EL0) | none | own design | — | A |

### hboot/src

| File | What it drives | Cited sources | Relation, in the comment's own words | Upstream licence | Class |
|---|---|---|---|---|---|
| `hboot/src/ak_derive.rs` | Per-device attestation key from OTP | none | own design | — | A |
| `hboot/src/attest.rs` | Attestation quote signing | none | own design | — | A |
| `hboot/src/attest_keys.rs` | Software attestation keys | none | own design | — | A |
| `hboot/src/mailbox.rs` | VideoCore property mailbox at EL2 (OTP, serial) | `bcm2835-mailbox.c`, `raspberrypi.c` (:19–:20); rpi-6.12 DT (:17) | "Registers ... and the pointer rule are from Linux `bcm2835-mailbox.c` + `raspberrypi.c`" (:19) | `bcm2835-mailbox.c` GPL-2.0; `raspberrypi.c` GPL-2.0 | C |
| `hboot/src/main.rs` | Boot manager: verify, measure, hand off | FIPS 205 (:7) | own design | — | A |
| `hboot/src/measure.rs` | Measured-boot PCR chain | none | own design | — | A |
| `hboot/src/mmu.rs` | EL2 identity MMU | Arm architecture | own design | — | A |
| `hboot/src/rng.rs` | BCM2712 TRNG (rng200) for the boot nonce | `drivers/char/hw_random/iproc-rng200.c` (:14) | "Register map + init/read sequence transcribed from Linux" (:13) | GPL-2.0-only | D |
| `hboot/src/rollback.rs` | Anti-rollback floor | none | own design | — | A |
| `hboot/src/stage2.rs` | Stage-2 isolation of HBoot | Arm ARM DDI0487 (:13); Linux KVM, Xen (:13) | "Register values ... from the Arm ARM (DDI0487 D8/D19) + Linux KVM/Xen" (:12) | KVM GPL-2.0 (file not identified, not verified); Xen not verified | C |
| `hboot/src/t0inv.rs` | Read-only platform inventory at EL2 | SMCCC / PSCI; devicetree | specification facts | — | A |
| `hboot/src/watchdog.rs` | BCM2712 PM watchdog (A/B trial boot) | own `boot.s` (:11); Linux `bcm2835_wdt` (:63) | "Mirrors the Linux bcm2835_wdt stop sequence" (:63) | `bcm2835_wdt.c` GPL-2.0+ | D |

### hal/src (citing files only)

| File | What it drives | Cited sources | Relation, in the comment's own words | Upstream licence | Class |
|---|---|---|---|---|---|
| `hal/src/bcdc.rs` | CYW43455 BCDC control channel, key install record | brcmfmac `brcmf_wsec_key_le` (:117, :124) | "The brcmf_wsec_key_le payload: index @0, len @4, data @8" (:124) | `fwil_types.h` ISC | B |
| `hal/src/lib.rs` | HAL root; SDPCM superframe (glom) framing | brcmfmac `brcmf_sdio_rxglom`, `brcmf_sdio_hdparse` (:336, :362, :432, :484) | "a port of brcmfmac brcmf_sdio_rxglom's framing rules" (:336); "Mirrors brcmf_sdio_rxglom" (:432) | `sdio.c` ISC | B |
| `hal/src/rsnassoc.rs` | Station RSNE parse and AP keying decision | IEEE 802.11-2020 (:2); hostapd `wpa_validate_wpa_ie` (:2, :139, :171); brcmfmac structs (:5, :110, :275, :295); cfg80211 `IEEE80211_SCAN_RESULT_EXPIRE` (:205); wpa_supplicant behaviour (:205, :211) | "what hostapd's `wpa_validate_wpa_ie` decides" (:2); "cfg80211 keeps a BSS entry 30 s (IEEE80211_SCAN_RESULT_EXPIRE)" (:205) | hostapd / wpa_supplicant BSD-3-Clause; brcmfmac ISC; cfg80211 `net/wireless` GPL-2.0 | C |
| `hal/src/sdio.rs` | SDHCI / SDIO bus primitives for the CYW43455 | own `arch-aarch64::cyw43` (:3); brcmfmac (:147, :282, :337, :384, :541); Linux SDIO sequence on the CM5 (:215, :518) | "Lifted unchanged from `arch-aarch64::cyw43`" (:3); "F2: FIXED address, as Linux on this CM5" (:215); "brcmf_sdio_rxfail: terminate the current frame" (:384) | brcmfmac `sdio.c` ISC; Linux MMC core GPL-2.0-or-later (observed behaviour, no file cited) | C |
| `hal/src/wpa.rs` | WPA2 PMK derivation (PBKDF2-HMAC-SHA1) | IEEE 802.11i (:3); names the "brcmfmac firmware" (:4) | standard; the firmware's interface is described, no code cited | — | A |
| `hal/src/wpaauth.rs` | WPA authenticator key derivation | IEEE 802.11 KDF; hostapd `sha256_prf_bits` (:12) | "IEEE 802.11 KDF-SHA256 ... (hostapd `sha256_prf_bits`, AKM 8)" (:12) | hostapd BSD-3-Clause | B |
| `hal/src/wpakeyer.rs` | 4-way handshake keyer | hostapd behaviour (:314) | "wrong PSK, forged, or stale — keep waiting (hostapd)" (:314) | hostapd BSD-3-Clause | B |
| `hal/src/wpasrvabi.rs` | WPA server ABI | brcmfmac behaviour (:75) | "brcmfmac falls back the same way" (:75) | brcmfmac ISC | B |

### sae/src (citing files only)

| File | What it drives | Cited sources | Relation, in the comment's own words | Upstream licence | Class |
|---|---|---|---|---|---|
| `sae/src/lib.rs` | WPA3-SAE (P-256, hunting-and-pecking, H2E) | IEEE 802.11-2020 §12.4, Annex J.10 (:6, :144, :924); hostapd `sae_derive_pt_ecc`, `sswu`, `sha256_prf_bits`, `dragonfly_min_pwe_loop_iter`, `common_module_tests.c` (:4, :25, :59, :146, :191, :924, :976, :1046, :1123) | "Mirrors hostapd's sae_derive_pt_ecc / sswu" (:146); "constant shape as hostapd's sswu()" (:191) | hostapd BSD-3-Clause | B |

### el0-wifi/src, el0-wpa/src

No file in either directory cites an external code base. No rows.

### kernel/src (citing files only)

| File | What it drives | Cited sources | Relation, in the comment's own words | Upstream licence | Class |
|---|---|---|---|---|---|
| `kernel/src/controlplane.rs` | Control-plane initiator over the GEM | Linux `macb` (:3) | "the Linux-`macb` single-ring-owner discipline" (:3) | `macb_main.c` GPL-2.0-only | C |
| `kernel/src/ja4.rs` | JA4 TLS fingerprint | FoxIO JA4 reference implementation (:3); own `legacy/linux-tier` `dpi.rs` (:3) | "cross-checked against the FoxIO reference implementation" (:3) | FoxIO JA4 not verified | B |
| `kernel/src/main.rs` | Kernel main: GEM drain loop, Wi-Fi pump, self-tests | `macb_main.c` (:1466, :1731, :1818, :1846, :2116, :2135, :2354–:2355); `rp1.c` (:6612); `raspberrypi.c`, `raspberrypi-firmware.h` (:6906); Linux NAPI (:5020); brcmfmac (:3587, :3686, :4346, :4555, :14587) | "analog of Linux macb gem_rx's `while (count < budget)` loop" (:2354); "exactly as Linux macb does for the RP1 GEM" (:1818); "Linux rp1.c-exact, a config write" (:6612); "as brcmfmac's dpc" (:4346) | `macb_main.c` GPL-2.0-only; `rp1.c` GPL-2.0; `raspberrypi.c` GPL-2.0; brcmfmac ISC | C |
| `kernel/src/netsvc.rs` | Network services; control-plane transport | `drivers/net/ethernet/cadence/macb_main.c` (:485) | "LESSON FROM LINUX (drivers/net/ethernet/cadence/macb_main.c ...)" (:485) | GPL-2.0-only | C |
| `kernel/src/prodfull.rs` | Production boot composition | Linux `macb` (:32) | "the Linux-`macb` single-ring-owner rule" (:32) | `macb_main.c` GPL-2.0-only | C |

Files that match the search terms but cite no external code as a source, and so have no row:
`kernel/src/absdom.rs` (a research finding about the Linux verifier), `kernel/src/mcserve.rs` (an analogy to a
Linux accept queue), `kernel/src/ratelimit.rs`, `verdict.rs`, `behavioral.rs`, `net.rs`, `rules.rs`, `bpf.rs`,
`dga.rs`, `segment.rs` (all refer to HookProbe's own Linux tier), `kernel/src/fpdb.rs`, `devid.rs`,
`discovery.rs` (device fingerprint labels), and the remaining matches on "derived from" / "mirrors" that
refer to our own code.

## Upstream licences checked

Verified means: the first lines of the file were fetched from GitHub on 2026-11-19 and the SPDX line read.
Nothing beyond the first five lines of any upstream file was read.

| Upstream file | SPDX | How verified |
|---|---|---|
| `drivers/char/hw_random/iproc-rng200.c` | GPL-2.0-only | torvalds/linux, SPDX line |
| `drivers/net/ethernet/cadence/macb_main.c` | GPL-2.0-only | torvalds/linux, SPDX line |
| `drivers/pci/controller/pcie-brcmstb.c` | GPL-2.0+ | torvalds/linux and raspberrypi/linux rpi-6.12.y, SPDX line |
| `drivers/mmc/host/sdhci-brcmstb.c` | GPL-2.0-only | torvalds/linux and raspberrypi/linux rpi-6.12.y, SPDX line. That `sdhci_brcmstb_cfginit_2712` lives in this file was not checked |
| `drivers/watchdog/bcm2835_wdt.c` | GPL-2.0+ | torvalds/linux, SPDX line |
| `drivers/net/ethernet/realtek/r8169_main.c` | GPL-2.0-only | torvalds/linux, SPDX line |
| `drivers/mfd/rp1.c` | GPL-2.0 | raspberrypi/linux rpi-6.12.y, SPDX line |
| `drivers/iommu/bcm2712-iommu.c` | GPL-2.0-only | raspberrypi/linux rpi-6.12.y, SPDX line |
| `drivers/pinctrl/bcm/pinctrl-bcm2712.c` | GPL-2.0+ | raspberrypi/linux rpi-6.12.y, SPDX line |
| `drivers/rtc/rtc-rpi.c` | GPL-2.0 OR BSD-3-Clause | raspberrypi/linux rpi-6.12.y, SPDX line |
| `drivers/clk/clk-rp1.c` | GPL-2.0 (mainline); GPL-2.0+ (rpi-6.12.y) | both trees, SPDX line |
| `drivers/irqchip/irq-bcm2712-mip.c` | GPL-2.0-only | torvalds/linux and raspberrypi/linux, SPDX line |
| `drivers/gpio/gpio-brcmstb.c` | GPL-2.0-only | torvalds/linux, SPDX line |
| `drivers/firmware/raspberrypi.c` | GPL-2.0 | torvalds/linux, SPDX line |
| `include/soc/bcm2835/raspberrypi-firmware.h` | GPL-2.0 | torvalds/linux, SPDX line |
| `drivers/mailbox/bcm2835-mailbox.c` | GPL-2.0 | torvalds/linux, SPDX line |
| `drivers/net/phy/broadcom.c` | GPL-2.0+ | torvalds/linux, SPDX line |
| `drivers/net/phy/bcm-phy-lib.h` | GPL-2.0 | torvalds/linux, SPDX line |
| `drivers/mmc/core/sdio.c` | GPL-2.0-or-later | torvalds/linux, SPDX line |
| `drivers/mmc/host/sdhci.c` | GPL-2.0-or-later | torvalds/linux, SPDX line |
| `drivers/firmware/psci/psci.c` | GPL-2.0-only | torvalds/linux, SPDX line |
| `drivers/firmware/smccc/smccc.c` | GPL-2.0-only | torvalds/linux, SPDX line |
| `drivers/bluetooth/btbcm.c` | GPL-2.0-or-later | torvalds/linux, SPDX line |
| `net/wireless/core.h`, `net/wireless/scan.c` | GPL-2.0 | torvalds/linux, SPDX line. Which file defines `IEEE80211_SCAN_RESULT_EXPIRE` was not checked |
| brcmfmac `sdio.c`, `bcmsdh.c`, `cfg80211.c`, `firmware.c`, `chip.c`, `common.c`, `fwsignal.c`, `fwil.c`, `bcdc.c`, `fwil_types.h`, `fweh.h` | ISC | torvalds/linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/`, SPDX line of each |
| `arch/arm64/boot/dts/broadcom/bcm2712.dtsi`, `bcm2712-rpi-cm5.dtsi` | (GPL-2.0 OR MIT) | torvalds/linux and raspberrypi/linux, SPDX line |
| `arch/arm64/boot/dts/broadcom/bcm2712-ds.dtsi` | GPL-2.0 | raspberrypi/linux rpi-6.12.y, SPDX line |
| `arch/arm64/boot/dts/broadcom/rp1.dtsi` | not verified | raspberrypi/linux rpi-6.12.y: no SPDX line in the first lines |
| U-Boot `drivers/net/macb.c` | GPL-2.0+ | u-boot/u-boot, SPDX line |
| OpenBSD `sys/dev/ic/bwfm.c`, `sys/dev/sdmmc/if_bwfm_sdio.c` | ISC, not verified | openbsd/src: the first five lines carry copyright lines only, no SPDX. ISC is the OpenBSD default |
| hostapd / wpa_supplicant (`sae.c`, `sha256-prf.c`, `common_module_tests.c`, `wpa_auth_ie.c`) | BSD-3-Clause | per hostapd COPYING, not re-verified per file |
| Pico-W `cyw43-driver` | not verified | not fetched; it ships its own licence file |
| `bcmevent.h` | not verified | path not found in mainline brcmfmac |
| FoxIO JA4 reference implementation | not verified | not fetched |
| Linux BPF JIT, `dma_alloc_coherent`, KVM stage-2, Xen, FreeBSD PCIe link-state, pppd | not verified | cited by name only, no file given |

## Open questions

1. **GPL-2.0-only versus GPL-2.0-or-later.** `pcie-brcmstb.c`, `bcm2835_wdt.c`, `pinctrl-bcm2712.c`,
   `broadcom.c` and the MMC core are "or later". That may matter for AGPL-3.0 distribution. It does not help
   the commercial licence. `rtl8111.rs` and `watchdog.rs` are class D here either way. Counsel decides.
2. **Quoted upstream lines in comments.** `gem.rs` (:245–:246, :1055–:1058, :1994–:1999) and
   `arch-aarch64/src/mailbox.rs` (:134–:140) carry what the comments present as source lines of GPL files.
   `kernel/src/main.rs:2354` carries a four-token fragment. Whether the quotes are exact was not checked.
   Removing them is cheap and independent of any rewrite.
3. **Mixed ISC and GPL in `cyw43.rs`.** A port of an ISC file is fine. The class D rating rests on one function
   (`sdhci_cfg_init`, :322) and the class C notes on `mmc_sdio_switch_hs` (:1300) and `pinctrl-bcm2712.c` (:404).
   Splitting the SDHCI host setup from the brcmfmac-derived SDIO protocol would confine the problem.
4. **Code moved out of `cyw43.rs` keeps its provenance.** `hal/src/sdio.rs` says "Lifted unchanged from"
   `cyw43.rs`. `sdhci.rs` says it is a "faithful TRANSCRIPTION" of it. `emmc.rs:115` forces card presence in the
   same cfg block as `cyw43.rs:322` and cites no source. These are rated on their own comments (C, C, A). If the
   `cyw43.rs` cfg init is rewritten, check these three for the same sequence.
5. **Class C files whose only code source is GPL.** `iommu.rs` (only `bcm2712-iommu.c`, a forum post and the DT)
   and `hboot/src/mailbox.rs` (only two Linux files) cite no datasheet. D11 says code whose only recorded source
   is a GPL-2.0 file is rewritten. Their wording is "sources" / "are from", not "transcribed", so they are C here.
   Either record a non-GPL source (the firmware property-interface documentation, the DT under MIT) or treat as D.
6. **Device trees as a source.** Most BCM2712 DT files are (GPL-2.0 OR MIT). `bcm2712-ds.dtsi` is GPL-2.0 only in
   the raspberrypi tree, and `rp1.dtsi` has no SPDX line in its first lines. Addresses and interrupt numbers
   are facts, but record which DT was used.
7. **`rng200.rs` and `hboot/src/rng.rs` are the same register block twice.** Both say "transcribed". One
   functional note and one rewrite covers both. No public datasheet is cited for the rng200.
8. **`bcmevent.h`** (`apparse.rs:6`) is not a mainline brcmfmac file. If it came from a Broadcom DHD tree the
   licence differs. The event numbers also appear in brcmfmac `fweh.h` (ISC, cited at `cyw43.rs:1937`).
9. **Pico-W `cyw43-driver`** (`cyw43.rs:11`) is cited as a sequence source. Its licence was not checked and
   is not the pico-sdk BSD licence by default. Record it or drop the citation if it was not used.
10. **"Linux oracle" and traces.** `cyw43.rs` (:348, :487, :1302, :3328), `nat.rs:38` and `hal/src/sdio.rs`
    (:215, :518) cite register values and call sequences observed on a running Linux on the same board. That is
    observation of behaviour, rated C. It is weaker evidence of independence than a datasheet.
11. **ADR 0067 F14 line numbers have drifted.** F14 cites `cyw43.rs:293, 2096`. The comments are now at
    `cyw43.rs:322` and `cyw43.rs:2128`. `gem.rs:1363`, `rtl8111.rs:377`, `rng200.rs:15` and `watchdog.rs:63` still match.
12. **Assembly files are out of scope.** `arch-aarch64/src/*.s` and `hboot/src/boot.s` carry an "ARM64 Linux
    Image header" (a boot-protocol fact). They have no rows because the scope is `.rs` files.
13. **hostapd per-file licence.** Classed B on the project-level COPYING. A few hostapd files carry other
    terms; the cited ones were not checked individually.
