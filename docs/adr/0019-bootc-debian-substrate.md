# ADR 0019 — The bootc/Debian substrate: how "the OS is a Containerfile" actually boots and updates

> 🛑 **Superseded in part by [ADR 0047](0047-heqk-everywhere-on-device-mission-control.md) (2026-10-09):** heqk replaces Linux on **every** platform and Mission Control is served by heqk on the device. bootc/Debian is now the TRANSITIONAL substrate only (bug and security fixes, no new features) until each platform's heqk port passes its metal gate.

**Status:** ✅ Accepted (2026-07-05) — **⚠️ Phase-1 base only.** The Containerfile base is switched to `docker.io/library/debian:trixie`, but **bootc / composefs / bootupd are absent**, and **`bootc upgrade`/`rollback` (UEFI) + the Pi A/B image-sync agent are ⬜ NOT BUILT.** Images boot today via the non-bootc mkosi path; the transactional-update/rollback promise this whole "OS is a Containerfile" decision rests on does not yet run end-to-end (needs a CI-egress build env for the self-built Debian-bootc base, and UEFI/Pi hardware to validate).
**Deciders:** os-architect (author), release-engineer, verification-engineer, security-auditor.
**Relates to:** `docs/Readme.md` Pillar 1 ("The OS is a Containerfile (bootc)"), CLAUDE.md load-bearing decision #1, `docs/driver-strategy.md` (the "UEFI everywhere" boot-model note), [ADR 0006](0006-os-hardening.md) (/usr dm-verity — the composefs/ostree integrity complement), [ADR 0016](0016-artifact-hash-signing.md) + [ADR 0017](0017-authenticated-aot-cache.md) (module signing — the layer bootc's *image* signature composes with), [ADR 0012](0012-release-definition-cortex-pass.md) (release = an OCI digest; `bootc upgrade --check` in the ring gate), [ADR 0015](0015-registry-driven-module-inclusion.md) (the OCI image is the single source of truth for module inclusion).

This ADR grounds and, where reality demands, **refines** the single most load-bearing claim in the project. It does not relitigate that the OS is a signed OCI image — that survives intact. It resolves *how that image boots and updates on each hardware tier*, because the literal "every device runs `bootc upgrade`" claim does **not** survive contact with the Raspberry Pi.

---

## Context — the gap between the claim and the tree

CLAUDE.md decision #1 states, verbatim: *"The OS is a Containerfile (bootc). The OS ships as a signed OCI image; build with podman build, ship to a registry, devices `bootc upgrade` / `bootc rollback`. Base distro is Debian/Ubuntu."* Verified current state on this box, 2026-07-05:

1. **No bootc anywhere.** `which bootc composefs bootupd ostree` → all absent on the dev box. Every repo hit for `bootc`/`composefs`/`ostree`/`bootupd` is prose, a systemd unit that *invokes* `bootc rollback` as a greenboot action, or a scaffold comment — **zero** bootc/ostree/composefs wiring is actually present. There is no `bootc status`, no ostree repo, no composefs deployment anywhere in the build.
2. **`base/Containerfile`'s base image was fictional.** *(Snapshot note, 2026-07-05: this finding captured the state where `ARG BASE_IMAGE=ghcr.io/bootcrew/debian-bootc:trixie` — not pullable from any registry. Post-switch, `base/Containerfile` now uses `ARG BASE_IMAGE=docker.io/library/debian:trixie` (plain Debian, Phase-1 bootstrap toward D2's self-built bootc base). The finding below is retained as the pre-switch record; the fictional-image blocker is what D2 resolves.)* `ARG BASE_IMAGE=ghcr.io/bootcrew/debian-bootc:trixie` is not pullable from any registry. The file's own Layer-0 comment already records this blocker (found 2026-06-30) and that no official Debian/Ubuntu bootc base is published anywhere — only RPM bases (`quay.io/fedora/fedora-bootc`, `quay.io/centos-bootc`) are real. `bootc container lint` (Layer K) is deliberately non-fatal for exactly this reason. **The image as written cannot build.**
3. **The OS nonetheless boots — via a completely different, non-bootc path.** `builder/mkosi/` (amd64, systemd-boot/UEFI, UKI) and `builder/mkosi-arm64/` (arm64) produce plain immutable Debian `.raw`/`.efi` images; `make-pi4-image.sh` reworks the arm64 rootfs into a Pi4 SD `.img`. Per BuildPlan, these boot + self-provision green on amd64 KVM (Gate 1, 12 s), arm64-virt (Gate 3b), and a real Pi4 (Gate 3c assembled/verified; on-metal flash pending). **The self-detect → sign manifest → verify → reconcile chain is proven — with no bootc in the picture.**

So the load-bearing decision is, today, an aspiration bolted onto a Containerfile that references a base that does not exist, over a boot substrate (mkosi + raspi-firmware) that is not bootc and gives up the very properties bootc was chosen for. This ADR closes that gap honestly.

---

## Investigation findings (verified, not assumed)

### F1 · Debian/Ubuntu bootc is real but experimental in mid-2026 — a bounded task on UEFI, not a research project

The Readme's "there is an active Debian/Ubuntu effort (Bootcrew, composefs-rs)" claim checks out, with important caveats:

- **`bootcrew/debian-bootc` and `jmarrero/ubuntu-bootc` exist** (both now consolidated into `bootcrew/mono`) — real reference images that make a Debian/Ubuntu container bootc-managed using the **composefs-native backend** (composefs-rs), i.e. *not* the ostree backend Fedora uses. This is the path the operator's "build our own Debian base" decision anticipated.
- **What the base actually needs**, per those guides: `bootc` + `composefs` + `systemd-boot` + `bootupd`, on **kernel 6.x** (Ubuntu 26.04's kernel 7.0 has an fsverity regression that breaks composefs boot; the workaround pins kernel 6.17). Debian trixie's apt already ships kernel/systemd-boot/dracut/ostree/ukify/grub-efi/skopeo; only `bootc` + `composefs`(-rs) + `bootupd` must be compiled in. That matches the earlier apt probe — the missing pieces are two-to-three compilable Rust/Go components, not a distro port.
- **But the composefs-native backend is officially experimental** — "under active development, not yet suitable for production use," always compiled in as of bootc **v1.10.1**, and *download-only mode is explicitly unsupported on it*. Stabilization is in progress (composefs manifest is now a GC root; rollback + boot-entry sorting fixed for systemd-boot and GRUB) but not done.

**Verdict on F1:** building a Debian bootc base is a **bounded engineering task on the UEFI tier**, riding an **experimental storage backend** — moderate, trackable risk, not a research project. It is *not* bounded on the Raspberry Pi rpi-native tier (see F2).

### F2 · The Pi4 boot path does not fit bootc's model — this is the crux

Prior work established two boot models, and they diverge exactly where bootc's assumptions live:

- **UEFI tier** (amd64 N100/VM/cloud; arm64-virt via AAVMF): OVMF/AAVMF → systemd-boot → UKI. This *is* bootc's world.
- **rpi-native tier** (the **validated** Pi4 path in `make-pi4-image.sh`): **MBR** partition table, a FAT32 boot partition, the BCM2711 SoC bootloader reads `config.txt` and loads `kernel8.img` + DTB + initramfs **directly**. There is **no UEFI, no systemd-boot, no bootloader bootc/bootupd can manage.** The script's own comments record that a GPT table leaves the Pi stuck on the rainbow splash — the Pi firmware wants MBR + FAT32.

bootc is architecturally UEFI-first: `bootc install` "will always run **bootupd** to handle bootloader installation," DPS auto-discovery requires **GRUB 2.12+ (bli, EFI-only) or systemd-boot**, and every Debian/Ubuntu-bootc guide is ESP + `efibootmgr` + systemd-boot. **No bootc documentation addresses Raspberry Pi `config.txt`/u-boot/direct-kernel boot at all.** The rpi-native path bootc cannot touch: there is no bootloader for bootupd to own and no ESP for composefs deployments to hang off in the way bootc expects.

There are exactly two ways to reconcile the Pi with bootc, and both have real cost:
- **(a) pftf/EDK2 UEFI firmware on the Pi's ESP** — the "UEFI everywhere" convergence `docs/driver-strategy.md` already names as the bootc-aligned option. It would let one bootc model span the Pi. But it inserts a *third-party firmware layer HookProbe does not control* under its immutable OS; pftf's Pi5/CM5 support lags the Pi4's; and the operator already shipped the raspi-native path *because* the UEFI-on-Pi route was flaky enough to be the "fallback if pftf proves flaky." Shipping a customer appliance on someone else's beta UEFI is a durable risk.
- **(b) A different update mechanism for the rpi-native tier**, unified under the same OCI source of truth (see the Decision).

### F3 · What bootc buys that the mkosi/make-pi4 path does **not** have today

The honest gap, stated concretely: today's images are **single-slot**. There is no second deployment to roll back *to*.

- greenboot + `--health-gate` (`base/greenboot/…`, supervisor) already produce a per-boot **verdict** and *invoke* `bootc rollback` on failure — but on the mkosi/Pi path **that rollback target does not exist**. The verdict is real; the rollback is a call into a binary that isn't installed against deployments that don't exist. **A bad update on the Pi today is a reflash, not a rollback.**
- The immutable `/usr` + `/usr`-only dm-verity (ADR 0006) approximate bootc's integrity guarantees at the block layer, and the OCI image is already the single build source of truth (ADR 0015). So we *have* immutability and integrity; we lack **transactional A/B update + actionable rollback + registry-delta pull**. That triad is precisely what bootc (or an equivalent A/B image-sync) adds — and it is the operational payoff the whole "one OS, fleet at scale" story rests on.

### F4 · The image signature (bootc) and the module signature (ADR 0016/0017) compose — they do not duplicate

Two distinct trust decisions, both already scaffolded:

- **Whole-OS image trust** — bootc verifies the OCI image at pull/upgrade time against the sigstore/cosign policy in `/etc/containers/policy.json` (staged today by Containerfile Layer H). This answers *"is this entire OS image from the HookProbe release identity?"*
- **Per-module payload trust** — `module.sig` over the `artifacts:`-digest manifest (ADR 0016), enforced before compile/execute by the supervisor (ADR 0017). This answers *"is this detection/policy module from HookProbe?"* for artifacts that live inside the running OS and update out-of-band from the image.

They nest cleanly: bootc gates the substrate, module signing gates the payloads the substrate runs. The only wiring needed is the existing Layer-H TODO — CI must inject the real release public key / sigstore identity that `policy.json` references. **No signing rework; the ADR 0016/0017 work is complementary and already correctly placed.**

---

## Decision

**Uphold "the OS is a Containerfile," and make the OCI image the universal source of truth for every tier — but split the *update mechanism* by boot model, because bootc cannot cover rpi-native.**

### D1 · The OCI image is the single source of truth on every platform (unchanged, load-bearing)

One `podman build` per arch produces one signed OCI image. Every platform's on-disk system is derived from *that image*. This is the part of decision #1 that is genuinely universal and it stands without qualification. Modules, presets, manifests, trust store — all flow from the image (ADR 0015). Nothing below weakens this.

### D2 · Build our own Debian bootc base (UEFI tier) — replace the fictional base image

Create a self-built Debian-bootc base recipe: `debian:trixie` + apt (kernel 6.x, systemd-boot, dracut/ukify, ostree, grub-efi, skopeo) + compiled `bootc` + `composefs`(-rs) + `bootupd`, tracking the `bootcrew/mono` reference. Replace `ARG BASE_IMAGE=ghcr.io/bootcrew/debian-bootc:trixie` with this locally-built, cosign-signed base. Pin the bootc/composefs versions explicitly (F1 — the composefs-native backend is experimental; never float `latest`). On the UEFI tier this delivers real `bootc status`/`upgrade`/`rollback`.

### D3 · rpi-native tier — an OCI-derived A/B image-sync path, not the bootc binary

Because bootc cannot manage the Pi's `config.txt`/SoC-firmware boot (F2), the Pi tier gets a **functionally equivalent** update path built from the *same OCI image*: a dual-slot (A/B) root layout on the SD/eMMC, an update agent that pulls the target image from the registry, unpacks it into the **inactive** slot, verifies its cosign signature (same policy as D4), flips the active-slot pointer in `config.txt`/`cmdline.txt`, and lets greenboot's existing verdict flip it back on a bad boot. This turns the *already-real* greenboot rollback verdict (F3) into an *actionable* rollback — closing the single-slot gap without depending on pftf UEFI. `make-pi4-image.sh` remains the **bootstrap/factory** path that produces the first flashable image (with the A/B layout); the image-sync agent owns updates thereafter.

### D4 · Image trust is bootc/policy.json; it composes with module signing (no rework)

Both the bootc `upgrade` path (D2) and the rpi-native image-sync path (D3) verify the OCI image's cosign signature against `/etc/containers/policy.json` before deploying it. CI injects the real release identity there (the existing Layer-H TODO). This is orthogonal to and layered above ADR 0016/0017 module signing (F4).

### D5 · pftf-UEFI-on-Pi stays a tracked *convergence*, not a dependency

If pftf/EDK2 UEFI matures to production quality on Pi4 **and** Pi5/CM5, the Pi tier can later fold into the D2 bootc path for a single boot model — a strict simplification. Until then it is a research spike, never on the shipping critical path. The A/B image-sync (D3) is the path we ship.

### D6 · Keep mkosi/make-pi4 as the bootstrap; bootc/image-sync takes over updates

The proven mkosi (`.raw`) → `make-pi4-image.sh` (`.img`) pipeline is retained as the **first-image / factory-flash** producer for every tier (it is what actually boots today). bootc `install`/`upgrade` (UEFI) and image-sync (rpi-native) take over *post-first-boot updates*. This preserves the boot-first discipline: nothing that boots green today regresses; the update layer is added on top and independently gated.

---

## The Pi4/bootc verdict (the crux, stated plainly)

**bootc does not, and in mid-2026 cannot, cover the Raspberry Pi rpi-native tier.** bootc is UEFI + bootupd + systemd-boot/GRUB; the validated Pi4 path is MBR + FAT32 + `config.txt` + SoC-firmware direct-kernel load, with no bootloader bootc can manage. The only route to literal bootc-on-Pi is pftf UEFI firmware on the Pi's ESP, which is third-party, immature on Pi5/CM5, and already found flaky enough that the operator shipped the native path instead. **Recommendation: do not block on bootc-on-Pi.** Give the Pi tier an OCI-derived A/B image-sync update path (D3) that delivers the same transactional-update-plus-rollback guarantee from the same signed image, and keep pftf-UEFI as a tracked future convergence (D5). bootc is the *UEFI-tier* update mechanism; the OCI image is the *universal* source of truth.

---

## Is Debian-bootc viable? (with citations)

**Yes on UEFI, as a bounded task riding an experimental backend; no on rpi-native.** Real reference work exists (`bootcrew/debian-bootc`, `jmarrero/ubuntu-bootc`, now `bootcrew/mono`) using the composefs-native backend; the missing Debian pieces are `bootc`+`composefs`+`bootupd` (compilable) on kernel 6.x. The composefs-native backend is officially experimental as of bootc v1.10.1 ("not yet suitable for production," download-only mode unsupported on it), so we pin versions and track stabilization rather than assume it. See Sources.

---

## Does CLAUDE.md decision #1 stand?

**It stands in substance and needs one honest wording refinement — flagged here, not silently resolved.** The universal, load-bearing half — *"the OS ships as a signed OCI image; build with podman build, ship to a registry"* — is true and upheld (D1). The literal *"devices `bootc upgrade`/`rollback`"* half is **not universally true**: it holds on the UEFI tier and is unattainable on the rpi-native tier in 2026 (the crux). Proposed revision to decision #1 (and Readme Pillar 1) for the operator to accept:

> *"The OS is a Containerfile — one signed OCI image is the source of truth for every platform. On UEFI platforms bootc performs `upgrade`/`rollback`; on Raspberry-Pi-native platforms an OCI-derived A/B image-sync path delivers equivalent transactional update + rollback from the same image. Base distro Debian/Ubuntu; the composefs-native backend is pinned and tracked while it stabilizes."*

Until the operator accepts this, CLAUDE.md and Readme Pillar 1 **overstate** bootc's reach on the Pi. This is the contradiction flagged per the repo's "docs win; flag don't silently resolve" rule.

---

## Phased plan (each phase independently verifiable on the gate ladder)

- **Phase 0 — bootstrap (DONE).** mkosi + `make-pi4-image.sh` produce first flashable images; boot + self-provision green on amd64 KVM, arm64-virt, Pi4 (flash pending). Retained as the factory path (D6).
- **Phase 1 — Debian bootc base + `bootc status` in a VM (minimal first bootc milestone).** Build the self-built Debian-bootc base (D2), replace the fictional `BASE_IMAGE`, build the OS image on a real build host (podman), boot it in amd64 KVM. **Gate:** `bootc status` returns a valid composefs deployment; `bootc container lint` passes as a hard gate. No hardware; QEMU-verifiable.
- **Phase 2 — `bootc upgrade`/`rollback` on UEFI.** Push image to a registry, `bootc upgrade` to a newer digest, force a bad boot, confirm greenboot → `bootc rollback` reverts. **Gate:** upgrade+rollback cycle green in amd64 KVM and arm64-virt (AAVMF); `policy.json` rejects an unsigned image (D4).
- **Phase 3 — rpi-native A/B image-sync on real hardware.** Ship the A/B slot layout in `make-pi4-image.sh`; build the image-sync agent (D3). **Gate:** on a real Pi4/Pi5/CM5, an OTA update installs to the inactive slot from the registry and a forced-bad boot rolls back — the first *actionable* Pi rollback.
- **Phase 4 — composefs stabilization tracking.** Re-pin bootc/composefs as the composefs-native backend leaves experimental; re-evaluate pftf-UEFI-on-Pi convergence (D5). **Gate:** version bump passes Phases 1–2 unchanged.

---

## Files that will change (when Accepted)

- **`base/Containerfile`** — replace `ARG BASE_IMAGE=ghcr.io/bootcrew/debian-bootc:trixie` with the self-built Debian-bootc base; make `bootc container lint` (Layer K) a hard gate; pin bootc/composefs versions.
- **New `base/bootc-base/Containerfile`** (or `builder/debian-bootc/`) — the self-built Debian bootc base recipe (apt kernel-6.x/systemd-boot/ostree/dracut/ukify/bootupd + compiled `bootc`+`composefs`-rs).
- **`builder/build.sh`, `builder/gen-matrix.sh`** — build the base first, then the OS image; per-tier artifact + update-path selection.
- **`builder/mkosi-arm64/make-pi4-image.sh`** — add the A/B slot layout (dual root + active-slot pointer in `config.txt`/`cmdline.txt`) for the D3 image-sync path.
- **New rpi-native image-sync agent** (`fleet/` or `base/`) — registry pull → inactive-slot unpack → cosign verify → slot flip; greenboot flips back on bad boot.
- **`base/config/containers/policy.json`** + CI — inject the real release cosign identity (existing Layer-H TODO) so both bootc and image-sync verify the image (D4).
- **`docs/Readme.md`** Pillar 1 — refine the universal "bootc upgrade everywhere" claim to the UEFI-bootc + rpi-native-image-sync split; fix the illustrative `FROM`.
- **`CLAUDE.md`** decision #1 — the wording refinement above (operator-gated).
- **`docs/BuildPlan.md`** — bootc-substrate rows; the phased plan status.

---

## Alternatives considered

- **Pivot the base to Fedora/CentOS-bootc** (real, production bootc today). Rejected: discards the entire Debian/apt investment (driver vendoring, `make-pi4-image.sh`, every `apt-get` layer), re-writes the OS to dnf, and *still* does not solve rpi-native (Fedora bootc is equally UEFI-first). Trades a bounded Debian-base task for a full rewrite and no Pi gain.
- **Drop bootc entirely; ship immutable-image + greenboot only.** Honest fallback, and closest to today's reality. Rejected as the *primary* path: it abandons registry-delta pulls, composefs dedup/integrity, and a maintained upgrade/rollback CLI on the UEFI tier where they are free — and leaves the "one OS, fleet at scale" story without a real transactional update mechanism. But note: D3's image-sync *is* essentially this model made A/B-capable for the Pi, so the fallback is not discarded — it is the rpi-native design.
- **pftf UEFI everywhere, one bootc model (D5 now instead of later).** Rejected as a *dependency*: third-party firmware under our immutable OS, immature on Pi5/CM5, already found flaky. Kept as a tracked convergence, not the shipping path.
- **ostree backend instead of composefs-native.** Viable on Fedora but the Debian/Ubuntu-bootc reference work targets composefs-native; the ostree backend on Debian is less trodden. Deferred to Phase-1 empirical choice — whichever the self-built base boots reliably wins; composefs-native is the current bet, ostree the fallback.

---

## Consequences / risks

- **Two update mechanisms to maintain** (bootc on UEFI, image-sync on rpi-native) until/unless pftf-UEFI converges. Mitigated by both deriving from one OCI image and one signature policy — the divergence is confined to the boot substrate, not the OS.
- **Experimental composefs-native dependency** — pinned and tracked (Phase 4); a composefs regression could block a bootc bump. The immutable-image + greenboot floor still boots if bootc is held back.
- **Self-built base is our maintenance burden** — we now own kernel/bootloader/bootc currency for the Debian base that no upstream vendor ships. Bounded, but real; release-engineer owns the bump cadence.
- **Residual honesty gap until Phase 3** — the Pi's greenboot rollback verdict remains non-actionable (single-slot) until image-sync ships. This ADR names it; it is not fixed by writing the ADR.

---

## Sources

- [bootcrew/debian-bootc — Debian bootc experiment, composefs-native backend (moved to bootcrew/mono)](https://github.com/bootcrew/debian-bootc)
- [jmarrero/ubuntu-bootc — GUIDE.md (Ubuntu/Debian → bootc with composefs, systemd-boot, UEFI, kernel 6.x)](https://github.com/jmarrero/ubuntu-bootc/blob/main/GUIDE.md)
- [bootc — composefs backend (experimental; always compiled in as of v1.10.1)](https://bootc.dev/bootc/experimental-composefs.html)
- [bootc — Understanding bootc install (bootupd bootloader install; GRUB 2.12+ bli / systemd-boot; EFI)](https://bootc.dev/bootc/bootc-install.html)
- [bootc composefs-native backend — issue #1190](https://github.com/bootc-dev/bootc/issues/1190)
- [Red Hat Developer — download-only mode unsupported on composefs backend (2026-02)](https://developers.redhat.com/articles/2026/02/18/control-updates-download-only-mode-bootc)
</content>
</invoke>

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: HARD — scoped by ADR 0043.** heqk is a **third boot model** (bare-metal aarch64: no UEFI, no bootc, no composefs, no systemd, no OCI) adopted on the **rpi-native tier only**. This ADR's "the OCI image is the *universal* source of truth" claim is narrowed to the Linux tiers (UEFI-bootc + amd64); the rpi-native tier's source of truth becomes the signed `heqk8.img`. D3's A/B image-sync intent is fulfilled natively by heqk's `ab-update.sh`/`tryboot`. → **Phase M1**.
