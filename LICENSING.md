# HookProbe OS — Licensing

> **Transparent licensing for transparent technology.**
> Run it to protect yourself or your organisation: free. Build on it: share your changes, or buy a commercial
> licence. Audit everything: always.

**Applies to:** this whole repository. This file is the licensing policy of record; every other licensing
statement in the repository points here.

| What | Licence |
|---|---|
| **All HookProbe software**: the heqk kernel, Mission Control, detection modules (NAPSE, dnsXai, QSECBIT, AEGIS guard, DGA, Sigma, …), build and signing tools, tests, docs, and the frozen `legacy/` trees | **GNU AGPL-3.0-only**, or a **commercial licence** |
| **HookProbe hardware designs** (`hardware/`) | **CERN-OHL-S-2.0**, or a **commercial hardware licence** |
| **Third-party components** (below) | Their own licences, unchanged |
| **The "HookProbe" name, logos and any "HookProbe Certified" mark** | Not licensed by any of the above |

There are **no proprietary parts** in this repository. Components that older documents called proprietary
(QSECBIT, dnsXai, Neural Resonance, DSM, AIOCHI, SLA AI, NAPSE, the Fortress AI modules) were relicensed to
AGPL-3.0-only by the copyright holder on 2026-11-14, as were the Wasm modules that used to declare Apache-2.0.

---

## Software: AGPL-3.0-only or commercial

The full AGPL-3.0 text is in [`LICENSE`](LICENSE). Every HookProbe crate and package declares
`AGPL-3.0-only` in its metadata.

| You want to… | Licence | Cost |
|---|---|---|
| Protect your own home network | AGPL-3.0 | Free |
| Protect your own business (internal use) | AGPL-3.0 | Free |
| Research, teaching, evaluation | AGPL-3.0 | Free |
| Modify it and distribute it, or run it as a service for others, **publishing your source** under AGPL-3.0 | AGPL-3.0 | Free |
| Offer it as a managed service, SaaS, OEM or white-label product **without publishing your changes** | Commercial | Contact |

The AGPL's network clause (section 13) counts offering modified software over a network as distribution: users
of the service are entitled to its source. A commercial licence removes that obligation.

## Hardware: CERN-OHL-S-2.0 or commercial

HookProbe's board designs follow the same dual model (ADR 0064 D6): **CERN-OHL-S-2.0** (anyone may build and sell;
modified designs must be published under the same licence) **or a commercial hardware licence** (closed
derivatives, white-label). Designs are published in [`hardware/`](hardware/) as work in progress, each with its real
status. The CERN licence notice, Source Location and full text are in [`hardware/README.md`](hardware/README.md).

## Contributions

Contributions are accepted under AGPL-3.0-only (software) or CERN-OHL-S-2.0 (hardware), **and** under the
HookProbe Contributor Licence Agreement, so that HookProbe can also offer them under the commercial licences.
Request the CLA from the contact below before your first pull request is merged.

---

## Third-party components

These are not HookProbe's to relicense. They keep their own terms:

| Component | Where | Licence |
|---|---|---|
| Rust crates and npm packages pulled as dependencies | `Cargo.lock`, `package-lock.json` files | Their own; `tools/ci/deny.toml` allows only permissive and AGPL-compatible licences, checked by gate g4 |
| CYW43455 Wi-Fi firmware (CLM blob, NVRAM, staged `.bin`) | `os/drivers/firmware/brcm-firmware-rpt/` | Cypress binary-redistribution licence; NVRAM files GPL-2 ([details](os/drivers/firmware/brcm-firmware-rpt/LICENSE.md)) |
| Raspberry Pi `usbboot` (vendored tool) | `os/kernel/tools/usbboot/` | Apache-2.0 ([LICENSE](os/kernel/tools/usbboot/LICENSE)) |
| Realtek USB Wi-Fi drivers (Linux tier, frozen) | `legacy/linux-tier/base/drivers/rtl*` | GPL-2.0 |
| HookProbe's own Linux eBPF programs (Linux tier, frozen) | `legacy/linux-tier/modules/*/bpf/*.bpf.c`, `legacy/v1/core/napse/kernel/` | **GPL-2.0**, the one exception for HookProbe code: the Linux kernel only lets GPL-declared BPF programs use its GPL-only helpers |
| Component symbols and footprints in the board design | `hardware/hookprobe-sbc/vendor/` | Their owners' terms (LCSC/EasyEDA library) |
| V1 third-party notices | [`legacy/v1/3rd-party-licenses.md`](legacy/v1/3rd-party-licenses.md) | As listed there |

Component datasheets and the Radxa ROCK 5B reference schematic are not redistributed here.

---

## Contact

Commercial licences, the CLA, compliance questions: **qsecbit@hookprobe.com**
