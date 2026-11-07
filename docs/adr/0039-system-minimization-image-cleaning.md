# ADR 0039 — System minimization & image cleaning: the actionable trim and the ongoing "only what we need" discipline

**Status:** 🟡 Proposed (2026-07-17) — a design-session posture pending operator ratification. Each item is tagged **[measured]** (a byte-count established today), **[action]** (a concrete change to make in the current image), or **[gate]** (a standing discipline to enforce), so this ADR never claims a trim already happened. This is the near-term, *current-image* arm of [ADR 0035](0035-substrate-ownership-underlay-overlay.md)'s strategic minimal-base posture.
**Deciders:** release-engineer (author), os-architect, verification-engineer, security-auditor.
**Relates to:** [ADR 0035](0035-substrate-ownership-underlay-overlay.md) (the strategic "own a minimal base via Buildroot/Yocto" posture — 0039 is its immediately-actionable complement, D4's filter reused here), [ADR 0019](0019-bootc-debian-substrate.md) (the Debian substrate being trimmed), [ADR 0036](0036-verifiable-supply-chain-reproducible-bootstrappable.md) (every byte removed is one less thing to reproduce/bootstrap), [ADR 0038](0038-ai-tiers-bpf-lsm-process-trust.md) (freed RAM/CPU serves the on-device ML tier). `builder/mkosi-arm64/mkosi.conf`, `base/Containerfile`.

This ADR is deliberately narrow and separate from [ADR 0035]. **0035 is the strategic path** — own a minimal base via a deterministic builder, a long-horizon bet. **0039 is what to clean in the *current* Debian image right now**, with no builder change and no functional loss: the ~40% of dead weight that can be removed this week while the strategic base is still Debian.

---

## Context — measured reality (2026-07-16, this box)

The built Pi image was measured byte-for-byte (`debugfs rdump` on the real `.img`): **~1.3 GB, of which ~89% is Debian and ~4% (≈40 MB) is HookProbe's own code.** Crucially, **~40% of the image is provable dead weight** [measured]:

- A **~328 MB stock Debian kernel** (`linux-image-arm64`), dragged in by a meta-dependency, that **never boots** — the Pi boots the self-compiled *edge* kernels from the FAT partition ([ADR 0032]); the stock kernel's modules are pure ballast. It alone outweighs everything HookProbe ships by ~8×.
- **~110 MB of firmware for hardware the board does not have**: ath11k 42 MB, i915 25 MB, ath10k 15 MB, plus mediatek/nvidia — generic `linux-firmware` for Intel/Atheros/MediaTek radios a Pi will never contain. Only ~18 MB (brcm/cypress) is Pi-relevant.

None of this is exotic to remove; it is the ordinary consequence of a general-purpose distro serving a single-purpose appliance. The trim below is orthogonal to [ADR 0035]'s Buildroot endgame and can ship on the current image.

---

## Decision

### D1 · Drop the never-booted stock kernel **[action]**

Remove the `linux-image-arm64` meta-pull (and its transitive stock-kernel modules) from the image package set so **only the edge kernel(s) ship**. The Pi already boots `kernel8.img`/`kernel_2712.img` from FAT; nothing consumes the stock kernel. **≈ −328 MB, zero functional change.** Guard it: a build assertion that fails if a non-`hookprobe-edge` kernel package reappears in the staged rootfs.

### D2 · Scope firmware to the actual hardware, not the world **[action]**

Ship only the radio/NIC firmware the target board uses — on Pi, `firmware-brcm80211` + cypress (~18 MB); on other platforms, that platform's radio set — and drop the blanket `firmware-misc-nonfree`/`firmware-atheros`/`firmware-realtek`/`i915`/mediatek/nvidia bulk. This is **hardware/capability-scoped, not blanket-stripped**: the firmware set becomes a per-platform input (the same "adding hardware = one file" discipline as `platforms/*.yaml`). **≈ −110 MB on the Pi image.** Keep RTL-dongle firmware only where the USB-Wi-Fi capability is granted.

### D3 · Shed the runtime general-purpose surface an immutable appliance never uses **[action, cautiously]**

An immutable, image-updated OS installs nothing at runtime, so several general-purpose components are noise *at runtime*: **apt/dpkg** (keep build-time only, not on the running image), man pages, docs, locales, redundant shells/editors. **But strip by evidence, not reflex** — some things that *look* like noise are load-bearing: `python3-openvswitch` is needed by OVS, `modemmanager` only where cellular is a granted capability, etc. So D3 is applied through D4's filter (capability-gate, don't blindly remove), and every removal is validated by a smoketest that the boot→detect→enforce→report path still works.

### D4 · Cleaning is a durable *gate*, not a one-time diet **[gate]**

Adopt [ADR 0035] D4's filter as a standing build gate:

> **A component earns its place only if it is on the boot → detect → enforce → report critical path, OR it is a capability the Platform Manifest grants on *this* hardware. Everything else is noise.**

Concretely: the image carries a **size/attack-surface budget it must stay under**, and a build gate (verification-engineer, alongside the existing gate ladder) that **flags newly-added dead weight** — a new large package, a re-introduced second kernel, unscoped firmware — before it merges. This turns "we trimmed the image once" into "the image cannot silently re-bloat." Minimization becomes a property the build *maintains*, not an event.

---

## Consequences / risks

- **The payoff is large and low-risk: ≈ −40% (≈1.3 GB → ~800 MB or less) with zero functional loss** — D1+D2 alone are ~438 MB of ballast removed without touching a single working code path. Faster boot, less flash, and **more RAM/CPU headroom for the on-device ML tier** ([ADR 0038]).
- **For a security product, the size win *is* a security win.** Every package not shipped is a CVE that cannot apply and an exploit primitive that is not present. This ADR shrinks the attack surface as a side effect of shrinking the image — the two are the same act.
- **D3 is the only place to be careful** — an over-eager strip breaks a granted capability. Mitigated by capability-gating (D4) + a mandatory smoketest per removal; when in doubt, keep and flag, don't strip.
- **This does not preempt [ADR 0035].** 0039 trims the *current Debian image*; the deeper minimal-owned base is still 0035's Buildroot/Yocto path. 0039 is what buys the win this week; 0035 is what makes it structural. And every byte 0039 removes is one less thing [ADR 0036] must reproduce and bootstrap — the arc *minimal → owned → reproducible → bootstrappable* starts here, cheaply.
- **Nothing here changes the boot substrate or the update model** ([ADR 0019]); it only changes which packages the existing image carries.

---

## Alternatives considered

- **Wait for the Buildroot base ([ADR 0035] D5) to get minimal "for free."** Rejected as the *only* plan: the Buildroot endgame is quarters out; the ~40% dead weight is removable from the Debian image *now*, and there is no reason to ship a 1.3 GB image with a 328 MB kernel that never runs while waiting. 0039 and 0035 are complementary, not sequential.
- **Aggressive one-shot strip (rip out apt, coreutils, shells wholesale).** Rejected in favor of the capability-gated, smoketest-guarded D3 — a security appliance that fails to bring up a granted capability because a "noise" package was actually load-bearing is a worse outcome than 50 MB of caution.
- **Leave the image as-is and rely on compression.** Rejected: compression hides the bloat on disk but not the *attack surface* — a shipped-but-unused package is still an exploit primitive and a CVE obligation whether or not it compresses well.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT (mostly moot under heqk).** The specific Debian-package trims (drop the 328 MB stock kernel, scope firmware, shed apt/dpkg) are obsolete because there is no Debian to clean; but the durable "only what we need" standing gate transfers, and heqk achieves this ADR's goal **structurally** (kernel + this-hardware firmware + static-Rust + Wasm + BPF, no shell/SSH). → **Phase M7**.
