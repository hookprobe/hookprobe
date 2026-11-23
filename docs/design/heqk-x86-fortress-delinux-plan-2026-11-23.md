# De-Linuxing the production N100 (Fortress) — x86 heqk plan

**Status:** Proposed (2026-11-23). Analysis + plan only; no code, no host change.
**Track:** x86 side track (ADR 0068), **out of the MVP** (operator 2026-11-23). Nothing
here touches `arch-aarch64`, `kernel/src`, MVP gates, images or the REL-05 soak.
**Related:** ADR 0047 (heqk everywhere), ADR 0044 D3 (heavy tier native or off-device),
ADR 0068 (x86 boot/trust/entropy), `os/kernel/arch-x86_64/README.md`.

## 1. The question

The N100 that runs Fortress is production: it is the site gateway + SOC **and** the
place where all development, Claude sessions and data live. We cannot do boot/EFI
experiments on it. Goal: a plan to remove Linux from that platform while Fortress
keeps working, learning N100 platform dynamics from the live box without risking it.

## 2. What the box actually is (read-only inventory, 2026-11-23)

**Hardware** — Intel N100 (4C/4T, VT-x + EPT, VT-d active with 2 DMAR units,
RDSEED/RDRAND, SHA-NI, AVX2, CET-IBT, x2APIC), 15 GiB RAM, 1 TB Kingston NVMe
(ESP 1 G + /boot 2 G + one LVM PV holding a single ext4 root), **4× Intel I226-V**
(`igc`), **Qualcomm QCN9274** Wi-Fi 7 (`ath12k`, two AP radios), **Sierra EM9293**
5G over USB (`cdc_mbim`), TPM 2.0 (PTT), xHCI, two USB-serial adapters (CM5/bench
consoles). UEFI: Secure Boot **disabled**, platform in **Setup Mode** (no PK).
Each I226 and the QCN9274 sit in their **own IOMMU group**.

> This is the same radio/modem set chosen for the HookProbe RK3588 board (ADR 0064):
> QCN9274 + EM9293. Driver work done here pays twice.

The box carries **two distinct roles**, and that split drives the whole plan:

| Role A — the appliance (what heqk must replace) | Role B — dev/build/data host (legitimately Linux per CLAUDE.md, but must leave this box) |
|---|---|
| PPPoE WAN + DHCPv6-PD, 5G failover (`fts-wan-failover`), HTP VPN | Claude Code sessions (two users), Opencode |
| OVS LAN bridge (`FTS`) + VLANs + mirror ports | Cargo builds, QEMU (aarch64 + x86), headless Chrome (mc-e2e) |
| Two hostapd APs (2.4/5 GHz), dnsmasq/DHCP/DNS, DoT, Kea6 bench | ~145 GiB home: ~90 GiB `~/.claude`, repos, worktrees, metal logs, archives |
| NAPSE: Suricata + Zeek on the mirror | USB-serial consoles to the CM5/Pi benches; superpop bench |
| ClickHouse, Postgres, Redis, fts-web, dnsXai, 11× HYDRA, CNO, fingerprint, SLAAI, presence, device-lifecycle (rootful Podman + systemd) | |

**Consequence:** "remove Linux from Fortress" is two projects:
(1) heqk takes over **Role A** on the N100; (2) **Role B moves to another machine first**.
heqk will never host Claude, cargo or Chrome, and it should not. Nothing can cut over
until Role B has a new home.

Within Role A, the heavy stateful services (ClickHouse, Postgres/Redis, HYDRA, CNO,
fts-web) follow **ADR 0044 D3 B2: hosted off-device**. They move with Role B, or to the
control plane, and are fed by the heqk appliance. heqk keeps the data plane, detection
(BPF/Wasm), sealed evidence and the on-device Mission Control (ADR 0047).

## 3. Where x86 heqk stands (origin/main 1d8563591)

- `os/kernel/arch-x86_64` is a detached UEFI crate. It has UEFI→ExitBootServices, its own GDT/TSS/IDT,
  ACPI MADT/MCFG, x2APIC/xAPIC + IOAPIC (all inputs masked), PCIe ECAM, virtio-pci blk (read) + net (DHCP),
  4-level paging with NX/SMEP/SMAP, a ring-3 SYSCALL path and fail-closed RDSEED. It runs under
  KVM/TCG with 6 negative controls.
- **Missing:** SMP/AP bring-up, HPET/TSC calibration, MSI-X, higher-half/W^X/KPTI, ELF
  userland, BPF, and every real driver (igc, NVMe, xHCI, TPM-CRB, ath12k, MBIM).
- **X0 (hal extraction) has not started:** 931 `arch_aarch64::` refs in `kernel/src`, and it is gated
  on the soak cut. Until then, x86 work stays inside the detached crate plus new
  arch-neutral crates.

## 4. Strategy: "learn on the live box, prove on a twin, swap the box, not the OS"

The rules that keep production safe:

1. **No EFI, boot-order, partition or firmware-key change on the production unit** until the
   final cutover, and that cutover is a hardware swap with cable-move rollback.
2. **Read-only capture** of the live platform becomes test fixtures. This is how we "learn platform
   dynamics".
3. **Real silicon without a reboot.** VT-d is on and the spare I226 is in its own IOMMU
   group, so heqk can drive a *real* I226 as a KVM guest through VFIO (F2).
4. **No hardware purchase (operator 2026-11-23).** Real-silicon tests use what we own: VFIO of the idle
   I226 and the idle USB-C xHCI with no window; the production QCN9274/EM9293 lent to a heqk guest in maintenance
   windows; and CM5 (RP1 xHCI, a heqk STA client). See the radio plan §5a.
5. Evidence classes stay unmixed (E1 QEMU / E2 QEMU→real peer / E3 metal), as with S1.

Rejected alternatives:
- *heqk as a type-1 hypervisor hosting a Linux guest:* a large VMM effort, and it contradicts
  ADR 0047 D1 and ADR 0068 D2. It still leaves Linux on the device.
- *In-place dual boot on the production NVMe:* the single ext4 LV fills the disk, ext4 only
  shrinks offline, enrolling a PK on prod firmware changes its boot policy, and the rollback
  path is the very box at risk.
- *Big-bang reinstall:* violates "Fortress keeps working".

## 4a. "Can we run Claude from heqk?" (operator question, 2026-11-23)

The model never runs on the box; it is served by the Anthropic API over HTTPS. What runs
locally is a **harness**: a loop that calls the Messages API and executes the tools the model
asks for. So the question splits three ways:

| Meaning | Verdict | Why / how |
|---|---|---|
| **(a) Claude as heqk's on-device AI** (AEGIS planner + Copilot: investigate, explain, propose intents) | **Yes — build it natively** | The endpoints exist as honest stubs (`kernel/src/http.rs`: `/api/planner/{propose,approve,status}` → `not_configured`). Needed pieces: (1) an **outbound TLS 1.3 client**, because `tlsprov` is server-only today; it goes in the EL0 TLS host. (2) An EL0 **planner excursion**: HTTPS + JSON + SSE streaming, running the tool-use loop. (3) Tools = the same bounded `mgmtabi` requests `hsh` and `GET /api/*` use (read-only evidence queries), plus **intent proposals that the deterministic reconciler applies and verifies**. The model never enforces (ADR 0011 C9, the AEGIS invariant). (4) The API key is sealed, and each prompt carries an audit record of exactly what evidence left the device. The endpoint is BYO: the Anthropic API or any OpenAI-compatible one, including a local model on another box. With no planner, the device stays a full SOC (standalone default). |
| **(b) Claude Code itself, natively on heqk** | **No** | Claude Code is a Bun/JS binary. It needs a POSIX world: processes, fork/exec of `bash`, PTYs, a POSIX filesystem, a JIT runtime. Its real work also needs `git`, `cargo`/`rustc`, QEMU and Chrome. Hosting that means a Linux-ABI personality (a starnix-style syscall layer). That is re-implementing Linux on the device, which contradicts ADR 0047. Building heqk on heqk has the same problem. |
| **(c) Claude Code operating heqk devices remotely** | **Yes — the dev workflow** | Claude Code runs on the dev host (Linux is allowed there per CLAUDE.md) or in cloud sessions. It reaches heqk devices through `hsh`/the mgmt API over an authenticated channel, the way it reaches the CM5 bench today. |

**Implication for this plan:** (a) is a new heqk feature: arch-neutral, valuable on CM5 too,
and a candidate requirement (outbound TLS client + planner excursion). It does **not** remove
the need for Role B's new home (F3). Development, builds and the benches still need a Linux
dev host or cloud sessions. After cutover the Fortress device itself gets "Claude" through (a),
and engineers reach it through (c).

## 5. Phases

### F0 — Platform dossier from the live box (now; zero risk; read-only)
Operator-run root captures (one script; output reviewed and scrubbed of MACs, serials,
IPs and hostnames before commit) into `os/kernel/arch-x86_64/fixtures/n100/`:
- `acpidump` (all tables: DSDT/SSDT, MADT, MCFG, **DMAR**, HPET, FADT, TPM2, FPDT), `dmidecode`,
  `/sys/firmware/memmap` + EFI memmap, `cpuid -r` (all leaves), relevant MSRs read-only.
- `lspci -vvv -xxxx` for the I226, NVMe, QCN9274 and xHCI (capabilities, BAR sizes, MSI-X table size,
  ASPM/L1 substates, PTM on I226), `/proc/interrupts` (vector/MSI-X distribution).
- `ethtool -d/-S/-i/-k` per I226: register dump, stats and offloads, as the igc driver's reference
  state. The EEPROM/NVM version comes from `ethtool -i`.
- TPM: `tpm2_getcap`, PCR 0–7 values, and the measured-boot event log
  (`/sys/kernel/security/tpm0/binary_bios_measurements`). These are the inputs ADR 0068 D3 needs
  to design the heqk PCR policy.
- Behaviour baselines that later serve as **parity targets**: per-interface pps/bps, conntrack size,
  CPU/RSS per service, PSI, RAPL package power, idle C-states, thermal under load.
- Detection corpus: a scrubbed export of Suricata alerts, Zeek logs and the CH tables already
  retained (D1 DNS 30 d) for **detection-parity replay** (NAPSE BPF/Wasm vs Suricata/Zeek).

Use in code right away: the `acpi.rs` parser and a new AML-free table walker get host
unit tests against the real N100 tables (MADT IOAPIC/x2APIC layout, MCFG, DMAR scopes).

### F1 — QEMU x86 to a "Fortress-shaped" guest (now; E1; unprivileged KVM)
Continue X2 in the detached crate, and add QEMU device models that mirror the N100:
- SMP AP bring-up (INIT-SIPI-SIPI), TSC calibration (CPUID 0x15 / HPET), MSI-X, higher
  half + W^X + KPTI-lite. These are **N100-relevant first**: 4 cores and the ADR 0060 core roles.
- `-device nvme` for the NVMe driver, `-device qemu-xhci` for xHCI/USB, and `tpm-crb` + **swtpm**
  for TPM measured boot (operator: `apt install swtpm swtpm-tools`).
- **Secure Boot with our own PK/KEK/db** via `OVMF_CODE_4M.secboot.fd` and custom vars. This
  answers ADR 0068 open question 2 in QEMU first, never on prod firmware.
- Portable logic that does not need X0: new arch-neutral `no_std` crates for igc register
  logic, an NVMe queue engine and an MBIM codec, host-unit-tested against F0 fixtures.

### F2 — Real I226 silicon, no reboot (VFIO; E3-lite; operator-run, reversible)
The I226 with no cable is still an OVS port of the LAN bridge, and the bridge borrows that
port's MAC, which also sets the LAN's EUI-64 IPv6 address. Procedure (root, operator):
1. **Pin the bridge MAC first:** `ovs-vsctl set bridge FTS other-config:hwaddr=<current>`.
   Verify that the LAN IPv6 address and RA are unchanged.
2. `ovs-vsctl del-port FTS <spare-port>`; unbind it from `igc` and bind it to `vfio-pci`;
   `chown` its `/dev/vfio/<group>` to the dev user.
3. Run the heqk x86 guest with `-device vfio-pci,host=<bdf>` under KVM.

**Rollback:** unbind vfio, rebind igc, re-add the OVS port. Nothing touches
EFI, the boot order or the disk.
**Risks:** FLR/reset of an I226 on its own root port (isolated by the IOMMU group). A guest DMA bug
is contained by VT-d. Its effect on the bridge MAC is removed by step 1.
**This is where the igc driver is written:** real PHY auto-neg, MSI-X, PTM, EEE and the
real RX/TX ring timing. A loopback cable to the LAN switch gives real traffic. A second
spare port can be freed only by an operator decision; none is free today.

The QCN9274, EM9293 and NVMe **cannot** be passed through, because they are in production use (APs,
failover, root disk). Their drivers get E1 (QEMU/fixtures) until F5.

### F3 — Move Role B off the box (prerequisite for any cutover)
- New dev/build/data host (decision D-A). Move `~/.claude` (~90 GiB), repos and worktrees,
  heqk metal logs, the QEMU/Chrome toolchain, the USB-serial bench consoles, the Pi4/CM5 bench
  access and the superpop bench. Do it per user, with the two users' sessions moved separately.
- The heavy services' new home (decision D-B): ClickHouse, Postgres/Redis, HYDRA, CNO, fts-web
  and dnsXai's model side. During the transition they keep being **fed by Linux Fortress**,
  remote-written over the LAN/VPN. That decouples data from the appliance before heqk exists.
- Exit criterion: the N100 runs **Role A only**, and a clean reboot of it loses no dev work.

### F4 — Role-A functional parity on heqk x86 (after X0 lands post-soak)
Bring the already metal-proven aarch64 network logic across through the X0 hal traits.
That covers PPPoE + IPv6-PD, NAT, VLANs/ACLs, DHCP/DNS, reject and the mgmt protocol. Build it as a
VFIO-I226 guest first, then on the twin. Parity checklist, each item versus the F0 baselines:

| Function (today) | heqk path | Size |
|---|---|---|
| PPPoE + DHCPv6-PD WAN | existing aarch64 logic via X0 | S |
| OVS bridge + VLANs + mirror | native L2 bridge + VLAN (CM5 done) | M |
| dnsmasq/DHCP/DNS/DoT | existing dhcpd + DNS; DoT via tlsprov | M |
| HTP VPN | **replace with G19 Noise IK to the PoP** (S1 proven) | M |
| NAPSE (Suricata/Zeek) | BPF threat plane + Wasm host; replay parity on the F0 corpus | M |
| 5G failover (EM9293) | xHCI + USB + MBIM driver | **L** |
| Wi-Fi 7 AP (QCN9274) | ath12k-class host driver (WMI/HTT + firmware) | **XL, long pole** |
| CH/Postgres/HYDRA/web | off-device (F3), fed by heqk export | — |

**Interim for the long poles (decision D-D):** an external AP on a LAN port, and 5G
failover deferred or provided by an external router, so cutover does not wait on ath12k.

Driver plan for the two long poles (QCN9274 Wi-Fi 7, EM9293 5G): `heqk-radio-drivers-qcn9274-em9293-plan-2026-11-23.md`.

### F5 — Shadow run on real traffic (E2/E3)
The heqk guest (F2), and later the twin, consumes the live mirror port in **observe-only** mode.
Compare detections against Suricata/Zeek, check resource behaviour, and run the
0.7-separation-matrix rows. Production is unaffected.

### F6 — Metal + cutover on the production box (no twin; operator rule 2026-11-23)
- **Rehearsal boots (D-G):** heqk on the existing ESP via one-shot `BootNext`. heqk arms the iTCO watchdog
  first, so a hang resets back to Linux. A `metal-readonly` profile: no NVMe writes, no TPM NV writes, no key
  enrolment. Each boot is a short, announced site outage.
- **Cutover** is only after the rehearsals pass and Role B has moved: heqk becomes the default boot entry
  and Linux stays as the fallback entry until a defined soak passes. Repartitioning or reclaiming the Linux LV
  comes last, after the data is off-box.
- Secure Boot with our own keys (rehearsed in QEMU in F1) is enrolled only at the very end, because Setup
  Mode enrolment changes the box's boot policy.

## 6. Decisions needed (operator)

- **D-A** — Role B's new home: a dedicated local x86 box (recommended, because of the USB benches,
  ~145 GiB of data and Claude latency) or a cloud VM.
- **D-B** — where the heavy services land: the same box as D-A (recommended for standalone) or the
  control plane.
- **D-C** — approve the F2 VFIO procedure on the production unit (operator-run, reversible).
- **D-D** — interim Wi-Fi/5G at cutover: an external AP, with 5G deferred.
- **D-E** — *(withdrawn: no purchases)*. Replaced by **D-G**: allow a one-shot `BootNext` + iTCO-watchdog
  metal boot on the production box (read-only profile, site down during the boot), after all VFIO stages are green.
- **Role B without new hardware** is the open gap. Candidates: cloud Claude Code sessions for code work; the
  Pi4 bench (Linux, allowed as a dev host) for the bench consoles; the OCI A1 for some heavy services (capacity to
  check). Until Role B has a home, everything up to F5 proceeds, and the final removal of Linux waits.

## 7. Flagged contradictions (not resolved here)

- ADR 0068 is **Proposed**, but X1/X2 are merged. Its own text says nothing merges before
  acceptance.
- ADR 0068 D4 says "RDSEED, RDRAND fallback"; `arch-x86_64` README/`rng.rs` say there is no RDRAND
  fallback.
- `os/kernel/ARCHITECTURE.md` (VT-x capability for a user VMM; a "Zone 4" Linux guest) and
  `docs/architecture/MIGRATION-heqk.md` (an M6 Linux guest) still describe a Linux guest that
  ADR 0047 D1 / ADR 0068 D2 rule out.

## 8. What can start today without touching the soak

F0 (capture script + fixtures) and F1 (SMP, TSC, MSI-X, NVMe/xHCI/TPM-CRB under QEMU, Secure
Boot rehearsal in OVMF) are entirely inside the detached crate, plus the operator-run
captures. F2 needs only D-C. Everything from F4 on waits for X0, after the soak cut.
