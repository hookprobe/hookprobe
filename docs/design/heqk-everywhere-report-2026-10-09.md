# heqk everywhere — comprehensive report (2026-10-09)

**Decision (ADR 0047, operator-ratified 2026-10-09):** heqk replaces Linux on **every** platform, and Mission Control is **served by heqk on the device**. This report covers what is proven, what is not, and the order of work. Branch `worktree-heqk-premetal-gaps` (HEAD `94e1c40`; `master` is still behind and needs an operator fast-forward).

Tags: **PROVEN** = a reproducible gate passes · **BUILT** = compiles, no live proof · **VISION** = design only.

## 1. What is proven today

| Capability | State | Evidence |
|---|---|---|
| heqk boots, schedules, isolates (caps, EL0, IPC, W^X, ELF loader) | PROVEN (QEMU) · metal-proven earlier on CM5 | `validate.sh` (0 failing) |
| Inline IPS: detect + tri-state `decide()` + self-reverting shed + legit-never-dropped | PROVEN (QEMU) · 31/31 heqk-plane rows on CM5 metal (M2) | `[P8-*]`, Gate-R logs |
| **End to end through the UI, no Linux in the device path:** real attack → `packet::verdict` drop → SOAR → device evidence → heqk HTTP API → unchanged Mission Control UI in a browser | **PROVEN (QEMU)** | `kernel/heqk/tools/mc-e2e.sh` → `MC-E2E: PASS` (screenshots: Detect feed shows "Known C2 port 4444 (DROP, framedrop)"; Home "1 incident need your review.") |
| On-device API logic (detections/incidents/QSecBit/SSE/static UI) | PROVEN (QEMU) | `[P-mc]` |
| Evidence persistence (sealed snapshot v2, in-order after wrap) | PROVEN (QEMU) · sealed store metal-proven (M3) | `[P-snapshot]`, `[P15-*]` |
| Fleet export (loss-tolerant v2 records, SRK identity) → receiver → evidence graph | PROVEN (QEMU/host) · live run = metal day | `[P-m6-export]`, `responder-sim` tests, cross-crate e2e |
| Wasm detection host (wasmi in EL0, wasip1) | PROVEN on CM5 metal for fixtures; **no catalogue module yet** | `[P-wasip1*]`, M5.5/M5.6 |
| CM5 Wi-Fi AP + STA | Metal-proven by the peer session (AP 2/2 joins, reconnect) | peer logs 2026-10-09 |

## 2. How to validate it yourself

```bash
cd kernel/heqk
tools/mc-e2e.sh                 # build UI + heqk, boot QEMU, attack, assert API + browser
MC_E2E_KEEP=1 tools/mc-e2e.sh   # then open http://127.0.0.1:18080 — Mission Control served by heqk
```
The browser leg needs Node + Playwright Chromium (`~/.local/node`, `tools/mc-e2e/`). Without them the script reports `BROWSER LEG SKIPPED — the UI rendering was NOT verified`, never a pass.

## 3. Defects found and fixed this session (root-caused, each with a regression)

| # | Defect | Root cause | Fix |
|---|---|---|---|
| 1 | The shipped CM5 `prod` image never started the IPS | A hard-wired `AP_MODE=true` loop never returned | `apmode`/`stajoin` features; `prod`+bench = compile_error; CI builds `prod` |
| 2 | Wi-Fi passphrases in source | Bench constants | Build-time env; CI literal gate. **History purge + password rotation still owed (operator)** |
| 3 | Resource-shed latched forever (ADR 0023) | Lifetime per-ACK counter | Decaying new-flow gauge |
| 4 | Legit fragments dropped as signature hits | Fragment offset ignored (v4 + v6) | Non-first fragment = no L4 |
| 5 | Signed containment lost on hash collision | Direct-mapped evict | Open addressing; unplaceable policy refused |
| 6 | Anti-rollback floor could drop a generation | Shared 32-sector window | No fallback; no DataVolume ⇒ disarmed |
| 7 | Two severity scales in one column (UI showed "suspicious" as CRITICAL) | Producers disagreed | One canonical scale + migration |
| 8 | Device evidence never left the device; export desynced on one lost datagram | Self-test-only export; implicit nonce | v2 export, explicit-seq records, receiver, ingest |
| 9 | Device identity forgeable | Key = sha256(printed serial) | HKDF(SRK, label) |
| 10 | **Unarmed rule plane passes everything, silently** | `rules::init()` required; nothing reported its absence | `mcserve` arms it; `rules_active` in heartbeat + `/api/health` |
| 11 | virtio-net overwrote in-flight TX buffers on bursts > 8 | Fire-and-forget ring | Completion-checked reuse; QSZ 64 |
| 12 | False-red QEMU gate on a loaded host | Fixed 45 s budget | `HEQK_QEMU_TIMEOUT`, timeout named as timeout |

## 4. Open gaps, ranked (what stands between this and a shippable heqk product)

**P0, security, before any real-network use of the on-device UI**
1. **The on-device UI/API has no authentication and no TLS.** It's read-only, but on a LAN anyone on the segment can read detections. Need an operator credential, a session cookie (SSE cannot send headers), and TLS (rustls-no_std, or the existing Noise identity for pairing). Until then, use `mcserve` only in QEMU or on an isolated management link.
2. Purge the Wi-Fi password from git history and rotate it before any push (ADR 0046).

**P1, finish the one-device product on CM5**
3. Wire `mcstate`/`http` into the CM5 prod loop (GEM + the existing MetalBridge drain) — the same pieces, a different NIC. Today `mcserve` is QEMU-only.
4. Mission Control state survives reboot: persist the detection ring through the sealed `fslog` DataVolume (today the UI state is RAM; the sealed snapshot holds 64 events without metadata).
5. The SOAR ring (64 slots) is drained once per loop or heartbeat; a burst between drains is counted as `overruns` but lost. Drain on demand, or deepen the ring.
6. UI widgets still on mock against a device: the sidebar score ("PROTECTED 92"), the "cloud-linked" badge (the device is standalone), ATT&CK coverage, engines (honestly empty), and capability gating. Events carry no dst IP/port (`:0` in the feed). Small server-side additions plus one UI store each.
7. Wasm catalogue on heqk: napse/dnsxai need `random_get` (std HashMap); ship raw `.wasm`, not wasmtime `.cwasm`. **Signing mismatch:** the catalogue is Ed25519 + ML-DSA-65, but heqk verifies only Ed25519, so CLAUDE.md's "hybrid ML-DSA fail-closed" is false on heqk until heqk verifies ML-DSA or the catalogue is re-signed SLH-DSA.

**P2, other platforms (ADR 0047 D1, honest scale)**
8. **Prerequisite on all targets:** the kernel crate calls `arch_aarch64::` directly at 336 sites (main.rs alone is ~11k lines). Route them through `hal` traits first, or every port forks the kernel.
9. RK3588 (aarch64): GICv3, stmmac GMAC, eMMC variant, a U-Boot/TF-A handoff instead of `config.txt`/tryboot. **Weeks to months.**
10. VM/cloud: virtio-**pci** (only virtio-mmio exists), UEFI boot, ENA/gVNIC for AWS/GCP. arm64 cloud is closest.
11. x86_64 / N100: a new `arch-x86_64` (paging, IDT/APIC, ring 3, context switch), a UEFI loader replacing hboot, ACPI + PCIe/MSI-X, igc (i225/i226) NIC, NVMe, TPM 2.0 for the SRK, RDRAND, and an x86 BPF JIT (or the interpreter). **Multi-quarter.**

## 5. Linux-tier inventory and fate (ADR 0047 D3: bug and security fixes only)

| Fate | Components (LOC) |
|---|---|
| **REPLACED by heqk** (already superseded) | napse-capture (9.8k + BPF C) → packet/rules/l7/bpf/blocklist · napse-quarantine/l2guard → verdict/ratelimit · OVS/microseg → segment.rs · dns-sinkhole → dnssink · senzorium-flow → export/telemetry · supervisor (4.6k) → wasmhost + el0-wasmhost · fleet/agent.sh → enroll/controlplane/ota · LUKS/dm-verity/secureboot → seal/store/hboot · hookprobe-api (1.4k) → http.rs (contract = interface spec) |
| **PORT** (logic reusable, re-host no_std) | bootstrap probe → device-tree/ACPI · manifest types, module_sig, trust, mgmt-guard, rbac core · requires/grants resolver · sigma (to wasip1) · evidence-graph model (heqk has fslog, not SQL) |
| **KEEP** (portable or host tooling) | ui/ (static) · Wasm catalogue (napse, dnsxai, qsecbit, aegis-guard, dga-lm) · manifest schema · platforms/*.yaml (+ heqk board map) · heqk build/sign tooling · sbom/cbom/slsa data · responder-sim, redteam engine (host test tools) |
| **RETIRE** | base/ (12.8k: Containerfile, systemd, greenboot, initramfs) + vendored USB Wi-Fi C drivers · mkosi/build-edge-kernel/glibc pins · host-telemetry (no Linux processes to watch) · sd_notify · hostapd paths (heqk cyw43) · yara-scan (no file tree on heqk) |

`retirement-agent` owns turning the RETIRE row into EOL events; nothing is deleted until its heqk replacement passes the platform's metal gate.

## 6. Documents superseded by ADR 0047 (marked, not deleted)
CLAUDE.md (banner) · ADR 0044 D2/D3 · ADR 0043 tier split · ADR 0019 (bootc substrate, now transitional) · docs/BuildPlan.md Track B "canonical + permanent" · docs/MIGRATION-heqk.md rpi-only scope · docs/Readme.md Pillar 1 · ADR 0001 (the Axum backend becomes the interface spec; heqk `http.rs` is the device server). Each carries a pointer to ADR 0047.

## 7. Recommended next phases
1. **P0 auth + TLS** on the device UI (gap 1). Small, and it unblocks real-network use.
2. **CM5 Mission Control on metal** (gaps 3–6) with the peer session's bench: the same `mc-e2e` assertions over the real GEM wire.
3. **Wasm catalogue on heqk** (gap 7): turns heqk's detection from 11 static rules into the real NAPSE/dnsXai engines.
4. **HAL decoupling** (gap 8), then RK3588 → arm64 cloud → x86_64.
