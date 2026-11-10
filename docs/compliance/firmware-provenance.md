# CYW43455 firmware provenance and licence (release-gate item CMP-02)

Draft. Records exactly which radio blobs heqk uses, where each comes from, which hashes are recorded, and
what is still missing. **Nothing here is a redistribution approval.**

> **CI licence scanning is not redistribution approval.** `cargo-deny` licence checks (`tools/ci/deny.toml`),
> npm audit and syft SBOMs in gate g4 cover Rust/npm dependencies; they do not read the firmware licence,
> and a green scan says nothing about whether HookProbe may redistribute the Cypress/Broadcom/Infineon
> binaries in a device image, a GitHub release asset or this repository. Redistribution requires a legal
> sign-off `docs/release/signoffs/firmware-licence.md` (release gate CMP-02), written by the operator only
> after legal review. Until then CMP-02 stays blocked.

## 1. What is embedded in the shipped image

`os/kernel/arch-aarch64/src/cyw43.rs` lines 590-592 embed three files into the kernel binary with
`include_bytes!`, so they are part of every shipped flavour (`prod`, `prod-mc`, the AP image) and of the
release ELF assets `heqk-<tag>-prod-mc.elf` / `heqk-<tag>-ap.elf` that `.github/workflows/release.yml`
attaches to a (draft) GitHub release:

| Embedded as | Staged file (`os/kernel/firmware/brcm/`, gitignored per `os/kernel/.gitignore` lines 5-7) | Role |
|---|---|---|
| `FW_BIN` | `cyw43455-sdio.bin` | Radio firmware (runs on the CYW43455) |
| `CLM_BLOB` | `cyw43455-sdio.clm_blob` | Regulatory channel/power database (CLM) |
| `NVRAM_TXT` | `cyw43455-sdio-cm5.nvram.txt` | Board NVRAM (RF calibration / board parameters), modified at staging |

Bluetooth patch (`.hcd`): **not used** (`arch-aarch64/src/bt.rs` header: patch optional; `p10bt` is not in
shipped flavours). No other radio firmware is embedded.

## 2. Per-file provenance

| File | Upstream origin (as recorded in repo) | Hash recorded in repo | Pinned at build? | Licence text in repo? |
|---|---|---|---|---|
| Firmware `.bin` | Raspberry Pi archive package `firmware-brcm80211_20260519-1~bpo13+1+rpt1_all.deb` (http://archive.raspberrypi.com/debian/pool/main/f/firmware-nonfree/), member `usr/lib/firmware/cypress/cyfmac43455-sdio-standard.bin`, version 7.45.265 (`tools/ci/stage-firmware.sh`) | `.deb` sha256 `c25e13e84be8dbf58b6b3381b4a10ad7e9dbeae101579376f457e0f17e60d902`; `.bin` sha256 `d608f866582519c0a28d86db43040f4f1b98dd1d153e72e9752586546b4a36c3` (`tools/ci/stage-firmware.sh`) | **Yes** in CI/release (`stage-firmware.sh` verifies both, aborts on mismatch). **No** on a dev box: `os/kernel/cm5-boot/stage-wifi-firmware.sh` falls back to `/lib/firmware/...` candidates with only a version-string check (≥ 7.45.265) | **GAP** |
| CLM blob | **Committed in this repository**: `os/drivers/firmware/brcm-firmware-rpt/brcmfmac43455-sdio.clm_blob` (2,676 B; strings `CLM DATA` / `RPi.4` / `1.29.4` / `ClmImport: 1.39.1` / `2021-11-15`). Moved from `base/drivers/brcm-firmware-rpt/` (`docs/PATHS.md`); first added in commit `525a4c64` (2026-07-25). ADR 0034 (line ~1322) states it is byte-identical to the current `RPi-Distro/firmware-nonfree` (`1:20260519`) `cyfmac43455-sdio.clm_blob` | sha256 `9823842cae9fb9a5dd1e5fb31f595516ec7deee341354bef30bb3026eee29cc1` (computed for this draft; same value recorded in ADR 0034) | **No**: `stage-wifi-firmware.sh` copies the in-repo blob (else `/lib/firmware` fallbacks) without a hash check; the CLM inside the pinned `.deb` is not used | **GAP** |
| NVRAM | **Committed in this repository**: `os/drivers/firmware/brcm-firmware-rpt/brcmfmac43455-sdio.raspberrypi,5-compute-module.txt` (header `# Cloned from bcm94345wlpagb_p2xx.txt`, `NVRAMRev=$Rev: 498373 $`; `macaddr` scrubbed) | sha256 `57cba1b42f57194a1c9134abf9b94b4411ddfe093a395e69c31824753e83a6a5`, **identical** for the `raspberrypi,4-model-b.txt` and generic `brcmfmac43455-sdio.txt` files | **No** hash check. Staging then **modifies** it: inserts placeholder `macaddr=00:90:4c:c5:12:38` if absent and appends `ccode=${REGDOMAIN:-RO}` / `regrev=0` (`stage-wifi-firmware.sh`) | **GAP** |

Observations for legal / lab:

1. The CLM blob and the three NVRAM files are **already redistributed** in the repository (public on
   GitHub per ADR 0046). The firmware `.bin` is not committed but **is** redistributed inside every image
   and every release ELF. All three are covered by CMP-02.
2. The staged NVRAM differs from the committed file (macaddr, ccode, regrev). The hash of the **staged**
   NVRAM actually embedded is not recorded anywhere. **GAP.**
3. The embedded CM5 NVRAM is byte-identical to the Pi 4 NVRAM in the repo. Whether Raspberry Pi ships a
   distinct CM5 NVRAM upstream was not verified. Radio relevance in `red-radio.md` §3.
4. Repo documents disagree on firmware 7.45.265 behaviour: ADR 0034 (≈ line 1332) says 7.45.265 still
   rejects the country handoff (`raspberrypi/linux#6669`); `stage-wifi-firmware.sh` and `cyw43.rs`
   (metal 2026-07-23) say ≥ 7.45.265 honours the country set by heqk's own loader. The later metal result
   is plausibly specific to heqk's verbatim NVRAM path; the lab must test the regulatory behaviour of the
   exact pinned blob rather than rely on either document.
5. The release SBOM (`syft scan dir:.` in `release.yml`) is not known to list any of these blobs (they are
   not package-manager artefacts). **GAP**: add explicit SBOM components (CycloneDX `firmware` type) with
   name, version, supplier, sha256 and licence.
6. Supplier chain: Cypress/Infineon (silicon vendor firmware) → Raspberry Pi (`firmware-nonfree` package,
   `+rpt1` build) → HookProbe. The upstream licence is whatever the `.deb`'s
   `usr/share/doc/firmware-brcm80211/copyright` and the upstream licence file state; **this draft did not
   read either** and asserts no licence terms.

## 3. Required actions (all open)

| # | Action | Owner (role) | Status |
|---|---|---|---|
| F1 | At build time record sha256 of the three **staged** files (post-modification NVRAM included) in the image manifest `<image>.json` (`os/build/make-cm5-heqk-disk.sh`) and in the release `SHA256SUMS` | Build engineering | GAP |
| F2 | Pin the CLM blob and NVRAM by sha256 in `stage-wifi-firmware.sh` / `stage-firmware.sh` (as already done for the `.bin`); fail the build on mismatch; remove the `/lib/firmware` fallbacks for release builds | Build engineering | GAP |
| F3 | Record the upstream source for CLM and NVRAM (package, version, path) next to the files, e.g. a `SOURCE` / `PROVENANCE` file in `os/drivers/firmware/brcm-firmware-rpt/` | Build engineering | GAP |
| F4 | Vendor the upstream licence text verbatim (from the pinned `.deb` and upstream firmware repository) into the repo and into the image's third-party notices, and ship it to users | Build engineering + legal | GAP |
| F5 | Legal review: redistribution of the `.bin`, CLM and NVRAM in (a) device images, (b) GitHub release assets, (c) the public repository; compatibility of the licence with AGPL + commercial distribution (`LICENSING.md`); conditions such as "use only with the vendor's chips"; whether NVRAM modification is permitted | Legal counsel | LEGAL |
| F6 | Module-vendor confirmation that this firmware/CLM/NVRAM combination, loaded by a non-vendor driver, stays within the module's radio approvals (`red-radio.md` §2, `fcc-gate.md` §3) | Compliance lead + module vendor | GAP |
| F7 | SBOM entries for the three blobs (see observation 5) | Build engineering | GAP |
| F8 | Change control: any change to these three files is a radio change (re-test decision) and a CMP-02 re-review | Compliance lead | GAP |
| F9 | Operator sign-off `firmware-licence` after F4-F6 | Release owner | Blocked |

Evidence that exists today (not approval): pinned `.deb` + `.bin` hashes and URL in
`tools/ci/stage-firmware.sh`; minimum-version gate in `os/kernel/cm5-boot/stage-wifi-firmware.sh`; CI
placeholders that prevent a placeholder blob from reaching a disk image (`.github/workflows/build-heqk.yml`
lines ~126-131, `os/build/make-cm5-heqk-disk.sh` lines ~85-91); `tools/ci/README.md` "Shipped-flavour
firmware".
