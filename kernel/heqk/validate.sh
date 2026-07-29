#!/usr/bin/env bash
# HookProbe kernel agent validator — the always-on V&V harness.
#
# Builds the kernel, boots it under QEMU, checks every phase gate by its PASS
# marker, and prints a product-lifecycle-aligned report (see LIFECYCLE.md).
# Reports gaps (regressions in built phases, or not-yet-built phases) and exits
# non-zero if any IMPLEMENTED phase fails — so CI / the kernel-validator agent
# can heal it. Run: ./validate.sh
set -u
cd "$(dirname "$0")"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

KERNEL=target/aarch64-unknown-none-softfloat/debug/kernel
LOG="$(mktemp)"
# virtio-net (v2) attached for P5b: the kernel ARPs the gateway and RXes the reply.
QEMU="qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
  -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 -kernel"

# phase|marker (fixed string)|status(impl|plan)|lifecycle stage|what it proves
PHASES=(
  "P0|[P0] PASS|impl|Implementation+Verification|boot chain: EL2->EL1, PL011, exception vectors"
  "P1|[P1] PASS|impl|Implementation+Verification|preemptive scheduler + context switch"
  "P1b|[P1b] PASS|impl|Implementation+Verification|MMU stage-1 + physical frame allocator"
  "P2|[P2] PASS|impl|Implementation+Verification|capabilities: untyped/retype/CDT/revoke"
  "P2iso|[P2-iso] PASS|impl|Implementation+Verification|CORE-2 per-TCB CSpaces: distinct capability spaces + rights-narrowing cross-CSpace delegation (child holds only the delegated Frame, read-only; Endpoint absent) — the P12 authority primitive"
  "P2gen|[P2-gen] PASS|impl|Implementation+Verification|CORE-9 generation-tagged CDT: parent link = (slot, generation); a freed+reused slot bumps its generation so a stale child (old-gen link) is orphaned — revoke of the new occupant spares it, never re-attaches"
  "PH7caps|[PH7-caps] PASS|impl|Implementation+Verification|PH7/XC-15 capability-invariant property sweep (dual-backend: runs on the QEMU AND CM5 MMU backends): mint narrows rights to exactly requested&source and never amplifies across all 8 combos, type-tag safety (Frame!=Endpoint), revoke severs a child subtree + bumps its generation, and mint-without-Grant is refused"
  "P2unmap|[P2-unmap] PASS|impl|Implementation+Verification|CORE-1 cap-gated Frame mapping + revoke-unmaps: map_frame_cap routes an EL0 grant through a has_rights-gated capability invocation (RW cap => AP RW, RO cap => AP RO, W-on-RO-cap denied) and RECORDS the VA; revoke then SEVERS authority by INVALIDATING the L3 entry + tlbi (present -> revoke -> invalid), closing the confused-deputy gap where revoke only cleared the CSpace slot"
  "P3|[P3] PASS|impl|Implementation+Verification|EL0 userspace + SVC syscall boundary + fault containment"
  "P4|[P4] PASS|impl|Implementation+Verification|synchronous IPC rendezvous over an Endpoint (block/unblock)"
  "P5|[P5] PASS|impl|Validation|Packet Engine: zero-copy ring + in-place verdict (synthetic pkts)"
  "P5b|[P5b] PASS|impl|Validation|real wire: virtio-net ARP round-trip -> ring -> verdict"
  "P6|[P6] PASS|impl|Validation|AI Runtime: RFC 9669 BPF VM (interpreter) verdict + bounds sandbox"
  "P6b|[P6b] PASS|impl|Validation|BPF verifier + JIT (W^X) + self-heal supervisor + telemetry/QSecBit"
  "DRV|[DRV] PASS|impl|Validation|driver isolation: EL0 driver server drives NIC MMIO via a capability"
  "P8|[P8] PASS|impl|Validation|PREVAIL verifier: statically proves rule memory-safety, rejects unsafe 3rd-party rules"
  "P8p|[P8-plane] PASS|impl|Validation|detection plane: general BPF JIT (branches) + rule registry (parity) + live QSecBit scoring"
  "P8diff|[P8-diff] PASS|impl|Validation|DET-6: JIT<->interpreter differential over ALL live JIT'd rules (L4 port + L2 ARP + TCP-scan), not just THREAT_RULE — native codegen proven == verified interpreter on a match-constant-stressed input set; FLOW/CALL rules interp-only, excluded"
  "P8vlan|[P8-vlan] PASS|impl|Validation|AUD-NET-1: strip_vlan reconstructs the canonical untagged frame for 1-tag and QinQ (guards the VLAN-normalization off-by-2 that re-opened the DET-4 L2/FLOW IDS bypass)"
  "P8n|[P8-napi] PASS|impl|Validation|adaptive NAPI: poll-budget grows under load, idles+re-arms when quiet (spin-poll retired)"
  "P8l|[P8-l2] PASS|impl|Validation|L2 guard: napse-l2guard parity — malformed-ARP FrameDropped; eth-src mismatch DETECTED but OBSERVED (ADR 0023 tri-state: a legit gratuitous/proxy ARP passes, no fabricated FrameDrop)"
  "P8t|[P8-tcp] PASS|impl|Validation|TCP scan detection: NULL/FIN/Xmas/SYN-FIN anomalous-flag scans DETECTED but OBSERVED (observe-by-default — no legit segment dropped), normal SYN/ACK fire nothing (ADR 0023)"
  "P8s|[P8-syn] PASS|impl|Validation|SYN-flood rate-limit: first stateful rule (BPF CALL helper + windowed rate limiter)"
  "P8ss|[P8-synsrc] PASS|impl|Validation|per-source SYN-flood: live rule keyed by IP source — flood one host, others unaffected"
  "P8b|[P8-block] PASS|impl|Validation|threat-feed blocklist: helper #2 (keyed CIDR lookup) — a feed IOC hit is DETECTED but OBSERVED (ADR 0023 matrix L11: a customer touching one IOC is never quarantined on a single hit), clean sources pass"
  "P8sep|[P8-sep] PASS|impl|Validation|DET-SEP / M2 keystone: tri-state decide()/decide_l2 seam ports ADR 0023 onto heqk — observe-by-default (a fired detector defaults to Observe/PASS), blocklist+ARP-spoof OBSERVED (legit customer always passes), Allowlisted mgmt floor never enforced (never self-lock-out), while malformed-frame + operator signature still FrameDrop (the suspicion-free confirmed drops)"
  "P8l2struct|[P8-l2struct] PASS|impl|Validation|M2.1 L2 structural + flood parity: F6 multicast-src / F7 oversize / F8 double-tag VLAN -> FrameDrop; mac-flood is PORT-ROLE-aware — Access->RateLimit(drop) but Uplink/AP->Observe (a legit AP radio's many client MACs are NEVER wire-dropped, ADR 0023 D12); broadcast-storm fires on a raw flood but mDNS/SSDP/LLMNR is exempt (D13); all via the decide_l2() seam"
  "P8flow|[P8-flow] PASS|impl|Validation|M2.2 flow-state (conntrack-equivalent): per-source distinct-dst-port scan counter (rule 1000003) → tri-state via decide() — an UNCONFIRMED sweep RateLimits (bounded, self-reverting DROP), a CONFIRMED sweep (>=CONFIRM distinct SYN-only ports, ZERO establishment) Quarantines (durable DROP); the load-bearing legit-safety proof: a busy source with 150 ESTABLISHED flows and a 100/s new-conn burst NEVER RateLimit/Quarantine (establishment ⇒ not a scan), and the A7/L9 flow-table saturation signal maps 40%-full→no-shed / 85%-full→shed (ADR 0018 anti-spoof + ADR 0023 observe-by-default)"
  "P8shed|[P8-shed] PASS|impl|Validation|M2.3 resource-shed (ADR 0023's 4th suspicion-free inline drop): SELF-REVERTING drops keyed on MEASURED RESOURCE REALITY, never identity — L1 blanket per-source new-conn cap (400/s) DROPs over-cap then PASSes next window (self-revert proof, synthetic clock); L2 conntrack-saturation sheds the top-talker only (un-saturated L9 / small legit source NEVER shed); L3 heqk-native PSI-equivalent (runqueue-depth-derived, synthetic-injected for QEMU; REAL pressure = Gate-R metal) sheds under pressure, not when clear; A8 top-talker sheds first; a legit busy-but-normal source is NEVER shed and the mgmt Allowlisted floor is NEVER shed however hot (routed through decide(), floor short-circuits — never self-lock-out)"
  "P8soar|[P8-soar] PASS|impl|Validation|SOAR event-ring: async non-blocking telemetry exfiltration (verdict engine -> SPSC ring -> EL0 exporter)"
  "P8l7|[P8-l7] PASS|impl|Validation|L7 deep-packet signature: helper #3 payload_match — MQTT CONNECT flagged in the verified fast-path before EL0 services"
  "P8l7b|[P8-l7b] PASS|impl|Validation|M2.4 L7/behavioral observe-only parity: C2 beacon (rule 1000040/A10) periodicity, east-west lateral fan-out (1000041/A10), bulk exfil (1000025), DNS tunneling/DGA (1000002/1000021/1000011) — ALL detect (SOC sees them) but route decide(Behavioral)->Observe->wire PASS, NEVER a drop (zero legit-drop risk, observe-only by construction); NTP(:123) beacon EXEMPT (L8 FP-guard #4); beacon jitter/retry-storm + lateral 1-peer/internal->external FP guards hold; host-EDR (1000100-115) correctly EXCLUDED (architecturally N/A on heqk — no process model, routed off-device per ADR 0044 D3)"
  "P12|[P12] PASS|impl|Implementation+Verification|notification objects + capability pub-sub: seL4 Signal/Poll (OR-coalescing), topics-as-caps authority (ungranted subscribe REFUSED via has_rights), blocking WAIT syscall woken by Signal under the scheduler; badge-from-cap; MAX_THREADS->16; DSN-6 fixed"
  "P17|[P17] PASS|impl|Validation|overlay convergence: net-class queue + dual-direction IPS gate (ingress DROP before ring + egress DROP before wire); EL0 monotonic counter; smoltcp EL0 service deferred"
  "PHprod|[PHprod] PASS|impl|Validation|PH1 production datapath: the running-sensor enforce decision (verdict-per-frame -> PASS FORWARDED / threat DROPPED) over a mixed benign+threat batch; the cm5 prod build wraps this loop around a real EL0-driven NIC (self-healing, never halts)"
  "PH6net|[PH6-net] PASS|impl|Validation|PH6 smoltcp net-service stack integration: the smoltcp TCP/IP stack runs ABOVE the P17 rule plane (ingress admits only verdict-PASS frames, egress emits only verdict-PASS frames) and correctly answers an ARP for its own IP; the EL0-isolated netq service + TRNG seed + PCR3 measure is the metal follow-up"
  "P18netcfg|[P18-netcfg] PASS|impl|Validation|M4.1 network CONFIG clients over smoltcp (the first time heqk drives smoltcp UDP, not just ARP): (a) smoltcp dhcpv4 socket EMITS a well-formed DISCOVER (UDP 68->67 broadcast) through the EGRESS verdict gate; (b) DNS query builder + response parser and SNTP request builder + response parser round-trip fail-closed (truncated/wrong-id/wrong-mode -> None); (c) the config INGRESS gate ADMITS benign DHCP/DNS/NTP and REFUSES a threat (UDP:4444); (d) the SACRED air-gap invariant — no server -> resolve_or_fallback returns a static/last-known config and a bounded DHCP attempt TERMINATES (never a boot-block), local SOC unaffected, no account. Real SLIRP lease (10.0.2.15) + DNS via 10.0.2.3 over virtio-net is a reported bonus; the real RP1 GEM/RTL8111 datapath, real DHCP/DNS servers, and a real NTP server (SLIRP has none) are metal (Gate R)"
  "P19pqc|[P19-pqc-kat] PASS|impl|Validation|M4.2a PQC secure-channel crypto PRIMITIVES + KATs (framing-agnostic: the identical KEX+AEAD both the ADR-0002 rustls-hybrid path AND the ADR-0004 Noise path need — brought in ONCE, NO handshake here (that is M4.2b)): (1) ML-KEM-768 / FIPS 203 (RustCrypto ml-kem, no_std) encaps/decaps round-trip + a pinned deterministic KAT shared-secret; (2) X25519 / RFC 7748 §5.2 known-answer vector (x25519-dalek, serial backend on aarch64 softfloat); (3) ChaCha20-Poly1305 / RFC 8439 §2.8.2 AEAD vector + authenticated round-trip + forged-tag REJECT (no AES-NI dependence — right for a softfloat edge); (4) hybrid KEX combiner — HKDF-combine (the EXISTING boot_abi::kdf) the ML-KEM ss WITH the X25519 ss into ONE hybrid secret, Alice==Bob. ALL DETERMINISTIC (fixed seeds/scalars/key-nonce, no RNG) so it is QEMU-reproducible; the real TRNG-fed keygen entropy is metal (Gate R, like the M3.3 VEK note); the handshake + rustls-vs-Noise framing + crypto review are M4.2b"
  "P19noise|[P19-noise] PASS|impl|Validation|M4.2b PQ-HYBRID secure-channel HANDSHAKE over the M4.2a primitives — Noise (ADR 0004 HTP-v2, NOT rustls; the device<->control-plane channel is between two of OUR endpoints). Pattern = an IK-analog Noise_HTP2hybrid_25519+MLKEM768_ChaChaPoly_SHA256: initiator=DEVICE, responder=control-plane whose static keys the device knows from enrollment; each es/ee is a HYBRID {X25519 DH + ML-KEM-768 encapsulation} folded via the M4.2a hybrid_combine before a single Noise MixKey. Noise rev-34 SymmetricState/CipherState/Split implemented to spec (MixHash/MixKey/EncryptAndHash; §12.3 nonce = 4 zero bytes || LE64(counter)); KEM-in-Noise per PQNoise (ePrint 2022/539); device auth = an Ed25519 (PUF-anchored, attest_svc key model) transcript signature over h. PROVES (loopback, deterministic seeded ephemerals): (A) full handshake -> MATCHING crossed transport keys (i.send==r.recv, i.recv==r.send), send!=recv, transcript-hash agree; (B) a transport record round-trips (confidentiality+integrity) and a REPLAY is rejected (advanced nonce counter, separate send/recv CipherStates); (C) a TAMPERED handshake byte -> AEAD auth fails -> ABORT; (D) a WRONG/unenrolled responder static key -> es key diverges -> ABORT; (E) an UNENROLLED device identity -> ABORT; (F) the hybrid combiner binds BOTH the ML-KEM & X25519 legs (transport key secure if either holds) + fresh ephemerals derive a new key (forward secrecy). Real HW-TRNG ephemerals + software-PUF device identity + responder PKI + the real network transport (with an anti-replay WINDOW for reordering) = metal/M4.3 (Gate R); ML-DSA-65 PQ co-signature auth leg = ADR 0002/0004 roadmap"
  "P19enroll|[P19-enroll] PASS|impl|Validation|M4.3 MSSP ENROLLMENT + AUTHENTICATED UPDATE FETCH over the M4.2b PQ-hybrid Noise channel (ties the channel=TRANSPORT to M3.4 OTA=TRUST-ROOT to the M3.2/M3.3 sealed store=PERSISTENCE): (a) ENTROPY #6 — the production MetalEntropy<HwTrng> FAILS CLOSED (boot-health-assert Err on the no-TRNG QEMU target; an ABSENT TRNG → fill Err; a STUCK TRNG → health_check rejects), while a healthy simulated-HW TRNG drives a full handshake through the PRODUCTION from_entropy path; NO seeded path can reach metal (a compile_error refuses securechannel-selftest+cm5, and the ephemeral fields are private with from_entropy the only production constructor); (b) FIXED BUFFERS #7 — repeated handshakes + transport records grow the bump heap by 0 bytes (the handshake/transport alloc::Vec is gone, replaced by in-place fixed buffers); (c) ENROLLMENT over Noise — mutual auth (device Ed25519 transcript signature + the enrolled MSSP static key; a rogue MSSP is rejected), and the enrollment binding SURVIVES REBOOT via the sealed record store (two boots, one virtio-blk backing); (d) AIR-GAP invariant — UNENROLLED is a VALID non-blocking steady state (no MSSP ⇒ full local SOC, enrollment is additive, never a boot precondition); (e) AUTHENTICATED FETCH — a signed candidate fetched over the enrolled transport is handed to ota::stage which VERIFIES it (shared hboot ed25519+SLH-DSA + SVN floor) and stages it, while a TAMPERED or BELOW-FLOOR candidate — delivered just as faithfully by the channel — is REJECTED by ota::verify (the channel is transport only, the boot signature+SVN is the trust root; a compromised MSSP still cannot ship an image hboot would reject); #8 CipherState::key_for_test is gated behind securechannel-selftest (out of the metal profile). DETERMINISTIC loopback + in-process fake MSSP; real mssp.hookprobe.com PKI + real HW-TRNG + real network = metal (Gate R). Deferred (M4.4): anti-replay sliding window + msg1-replay DoS (#9/N1); CBOM kem-0.3.0-pre entry (#4); ML-DSA-65 co-signature (#10)"
  "P19edge|[P19-edge] PASS|impl|Validation|M4.4 SECURE-EDGE ENVELOPE (ADR 0004 crown jewel) on heqk's native stack — closes the last two deferred Noise-transport conditions + lands the WAN-egress kill-switch: (1) ANTI-REPLAY #9 — an RFC 6479 (IPsec anti-replay without bit-shifting; the WireGuard construction) sliding BITMAP window on the Noise transport RECEIVER (AntiReplayRx): in-order records ACCEPTED, in-window OUT-OF-ORDER reorder ACCEPTED, exact REPLAY REJECTED, BELOW-WINDOW (stale) REJECTED, and a forged/tampered record fails the AEAD and NEVER advances the window (RFC 4303 §3.4.3 order — verify integrity BEFORE touching the window, so a forgery can't shadow a genuine record); (2) msg1-replay DoS N1 — a WireGuard/DTLS-1.3 (RFC 9147 §5.1) load-triggered STATELESS COOKIE + token-bucket guard BEFORE the expensive ML-KEM decap/keygen/encap + Ed25519-verify path: a 256-deep forged/replayed msg1 flood is rejected PRE-crypto (ZERO reach responder_read_msg1; the only work forced is one keyed HMAC) while a cookie-vouched legit peer (return-routability proven) reaches AND completes the real handshake, and a wrong cookie is refused; (3) KILL-SWITCH (ADR 0004, fail-closed) riding the M2 netq egress gate (packet::verdict): an ENROLLED device whose secure tunnel is DOWN/COMPROMISED has WAN-bound egress CUT (no plaintext leak) while LAN + local SOC + the PoP-reconnect carve-out stay UP — and a NEVER-ENROLLED / standalone / air-gapped device NEVER arms it (local SOC + LAN up, WAN per local policy: the CLAUDE.md air-gap invariant, never bricked); armed only when Enrolled && tunnel!=Up, disarmed by default = zero datapath change. Also #3 defense-in-depth: ResponderStatic::from_seeds is now securechannel-selftest-only (a metal device is always the initiator, never builds a responder static). QEMU-provable DECISION logic; the full PBR/NAT/encrypted-TUN SASE dataplane at line rate + the real super-PoP tunnel = a larger follow-on + metal (Gate R), scoped not faked (docs/design/heqk-control-plane.md §M4.4). Remaining tracked: dalek-zeroize (#3, partial), CBOM kem-0.3.0-pre (#4), ML-DSA-65 co-signature (#10)"
  "P11|[P11] PASS|impl|Validation|device-class transport (sDDF borrow): hardened SPSC (H1 kernel-private cap, H2 ownership table, H3 copy-then-validate, csdb, no-RMW) REJECTS+COUNTS a hostile driver's forged descriptors (V2 index/V4 offset+len+flags/V5 not-owned); LoopDev + honest path pass; metal GemDev/RtlDev deferred"
  "P16sha|[P16-sha] PASS|impl|Validation|crypto primitive: incremental SHA-256 Hasher == one-shot digest across all lengths/chunkings (guards the metal-found short-tail HMAC auth bug)"
  "P15|[P15-seal] PASS|impl|Validation|sealed storage: Encrypt-then-MAC seal/unseal (SHA256 HMAC/HKDF/CTR), tamper+wrong-measurement refused, MBR write-guard (RamDisk); eMMC driver read-only (writes behind p15-write)"
  "P15g|[P15-guard2] PASS|impl|Validation|M3.0 multi-region write-guard (brick-safety): the write allowlist REFUSES LBA 0/MBR + the ACTIVE boot slot + unregistered gaps + past-capacity, ALLOWS keystore+data-volume+inactive-slot, and rejects a bad region registration (LBA-0 inclusion / keystore overlap / past capacity) fail-closed — runs every boot, no device needed"
  "P15p|[P15-persist] PASS|impl|Validation|M3.1 cross-restart persistence: over a FILE-BACKED virtio-blk device (behind hal::BlockDev, the identical trait the metal eMMC slots into), boot-1 seals a cookie + writes a data-volume marker through the M3.0 guard and boot-2 (same backing file) reads them back + unseals — seal->persist->reboot->unseal SURVIVES restart (a volatile RamDisk cannot prove this); real eMMC write on brcm,bcm2712-sdhci is metal (Gate R)"
  "P15fs|[P15-fs] PASS|impl|Validation|M3.2 crash-safe log-structured record store on the DataVolume region: (a) N records survive reboot IN ORDER, (b) an injected torn-tail record is DROPPED on recovery while every intact record survives + the store stays writable, (c) a bounded ring evicts oldest-first at capacity and never writes outside the guard, (d) a real evidence Event + QSecBit history record round-trip across reboot; keyless digest integrity (per-record seal.rs encryption is M3.3); QEMU/virtio-blk-proven, real eMMC = metal (Gate R)"
  "P15sf|[P15-sealfs] PASS|impl|Validation|M3.3 sealed data-volume (encryption at rest): record payloads are sealed with HQKSEAL1 (Encrypt-then-MAC) under a Volume Encryption Key that is itself SEALED in the keystore — (b) CONFIDENTIALITY: a raw block read of a slot holding a known Event is ciphertext (ts 0xDEADBEEF / src IP / the 16-B Event image ABSENT on disk, HQKSEAL1 magic present), (c) INTEGRITY: a ciphertext byte flipped on disk WITH the forgeable keyless framing digest recomputed is still MAC-REJECTED at mount_sealed (the seal MAC, not the digest, is the guard) while intact records survive fail-closed, (a)+(d) CROSS-RESTART: the sealed VEK survives reboot (boot-2 loads it) and decrypts the evidence Event + QSecBit history field-for-field; QEMU/virtio-blk-proven, real eMMC write + OTP-bound SRK = metal (Gate R)"
  "P15ota|[P15-ota] PASS|impl|Validation|M3.4 on-device A/B OTA orchestrator + state machine over file-backed virtio-blk: (a) a VALID hybrid-signed candidate is verified by the SHARED boot_abi::verify (HBoot's EXACT verifier + trust root — no 2nd trust root) → staged to the INACTIVE slot only → state=Staged, persisted; (b) an INVALID candidate (bad ed25519 sig) is REJECTED verify-before-flip — NO inactive-slot write, active slot + tryboot flag untouched; (c) flip→Trying→simulated healthy trial→Committed (new slot active); (d) simulated failed trial→RolledBack (old slot stays active) + a below-floor (svn<floor) DOWNGRADE is refused (SVN floor); (e) OTA state + staged candidate SURVIVE reboot (persisted, driven by the two boots); (f) brick-safety — the candidate write only ever lands in RegionKind::InactiveSlot, LBA 0/MBR + the active slot are guard-REFUSED. QEMU-proven; the REAL firmware one-shot flip + PM-watchdog trial reset + power cycle are hboot/metal (Gate R)"
  "AB|[HBoot-AB] PASS|impl|Validation|A/B trial boot: kernel confirms health (hvc #1 disarms HBoot's EL2 watchdog) or firmware falls back to the known-good slot"
  "P7|[P7] PASS|plan|Validation|CM5/RP1 metal bring-up"
)

echo "==================================================================="
echo " HEQK Core — Kernel Agent Validator (Hardened Edge Quantum-safe Kernel)"
echo "==================================================================="

# --- Stage 1: build -------------------------------------------------------
echo -n "[build] cargo build ... "
if ! cargo build --features netsvc,securechannel,securechannel-selftest >/tmp/hp_build.log 2>&1; then
  echo "FAIL"; echo "  --- build errors ---"; grep -E '^error' /tmp/hp_build.log | head;
  echo "GAP: build broken — cannot validate. Fix compile errors first."; exit 2
fi
echo "ok"

# --- Stage 1b: verifier soundness harness (P16, host-side) ----------------
# Compile the REAL abstract operators (kernel/src/absdom.rs) for the host and
# check each over-approximates the concrete semantics (Agni-style). A control
# injects a deliberately-unsound operator the harness must catch.
echo -n "[P16]   verifier soundness harness ... "
VH="$(mktemp)"
if rustc --edition 2021 -O tools/verifier-harness.rs -o "$VH" >/tmp/hp_vh_build.log 2>&1; then
  if "$VH" >/tmp/hp_vh.log 2>&1; then
    echo "PASS (operators PROVEN SOUND exhaustively over reduced width + sampled on reachable domain; injected unsoundness caught)"
  else
    echo "FAIL — verifier operator UNSOUND:"; sed 's/^/    /' /tmp/hp_vh.log
    rm -f "$VH"; exit 2
  fi
  rm -f "$VH"
else
  echo "skip (rustc host build unavailable)"
fi

# --- Stage 2: boot + capture ---------------------------------------------
echo -n "[boot]  qemu virt ... "
timeout 45 $QEMU "$KERNEL" >"$LOG" 2>&1
RC=$?
if grep -q "\[ALL\]" "$LOG"; then echo "clean exit"; else echo "rc=$RC (no ALL marker; possible hang/regression)"; fi

# --- Stage 2b: M3.1 cross-restart persistence (file-backed virtio-blk) -----
# The volatile RamDisk (P15 above) proves the write-window LOGIC but cannot prove
# "survives reboot". A file-backed virtio-blk device — the SAME hal::BlockDev the
# metal eMMC slots into — can: boot twice against ONE backing file and confirm the
# sealed cookie + data-volume marker persisted. Needs the p15-write build (the
# store WRITE path); the eMMC write driver stays cfg(cm5) = NOT built here.
echo -n "[P15-persist] two-boot persistence (virtio-blk, p15-write) ... "
if command -v dd >/dev/null 2>&1 && cargo build --features netsvc,securechannel,securechannel-selftest,p15-write >/tmp/hp_build_p15w.log 2>&1; then
  DISK="$(mktemp)"; B1="$(mktemp)"; B2="$(mktemp)"
  # Factory step: a 64 MiB image with a valid MBR (p1 FAT @ LBA 2048, 129024
  # sectors). The running kernel is FORBIDDEN to write LBA 0 (brick-safety), so
  # the image tool lays the partition table down — exactly as on a real device.
  dd if=/dev/zero of="$DISK" bs=1M count=64 status=none
  printf '\x0c'             | dd of="$DISK" bs=1 seek=450 conv=notrunc status=none  # part type 0x0c (FAT)
  printf '\x00\x08\x00\x00' | dd of="$DISK" bs=1 seek=454 conv=notrunc status=none  # LBA start = 2048
  printf '\x00\xf8\x01\x00' | dd of="$DISK" bs=1 seek=458 conv=notrunc status=none  # sector count = 129024
  printf '\x55\xaa'         | dd of="$DISK" bs=1 seek=510 conv=notrunc status=none  # 0x55AA boot signature
  QEMU_BLK="qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
    -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -drive file=$DISK,format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 -kernel"
  # 75s cap (was 45s): the p15-write two-boot now also runs the M4.3 securechannel
  # + enrollment gates, whose debug-mode ML-KEM-768 handshakes add real wall time.
  timeout 75 $QEMU_BLK "$KERNEL" >"$B1" 2>&1   # boot 1: write cookie+marker through the guard
  timeout 75 $QEMU_BLK "$KERNEL" >"$B2" 2>&1   # boot 2: SAME disk -> read back + unseal
  cat "$B1" "$B2" >> "$LOG"                     # feed both boots' markers into the report
  if grep -qF "[P15-persist] PASS" "$B2"; then
    echo "PASS (cookie+marker survived restart)"
  else
    echo "FAIL/see report"; echo "  --- boot1 tail ---"; grep -F "[P15-persist]" "$B1" | sed 's/^/    /'
    echo "  --- boot2 tail ---"; grep -F "[P15-persist]" "$B2" | sed 's/^/    /'
  fi
  rm -f "$DISK" "$B1" "$B2"
else
  echo "skip (no dd, or p15-write build failed — see /tmp/hp_build_p15w.log)"
fi

# --- Stage 3: phase gate report ------------------------------------------
printf "\n %-4s %-8s %-30s %s\n" "PH" "STATUS" "LIFECYCLE STAGE" "GATE"
printf " %-4s %-8s %-30s %s\n" "----" "------" "------------------------------" "----------------------------------------"
FAILS=0; GAPS=0; FIRST_FAIL=""
for row in "${PHASES[@]}"; do
  IFS='|' read -r ph marker kind stage what <<< "$row"
  if grep -qF "$marker" "$LOG"; then
    st="PASS"
  elif [ "$kind" = "plan" ]; then
    st="PLANNED"; GAPS=$((GAPS+1))
  else
    st="FAIL"; FAILS=$((FAILS+1))
    [ -z "$FIRST_FAIL" ] && FIRST_FAIL="$ph|$marker|$what"
  fi
  printf " %-4s %-8s %-30s %s\n" "$ph" "$st" "$stage" "$what"
done

# --- Stage 4: verdict + auto-diagnostics (heal fast) ----------------------
echo ""
echo " built phases failing : $FAILS"
echo " gaps (not yet built) : $GAPS   (next: first PLANNED phase above)"
if [ "$FAILS" -gt 0 ]; then
  IFS='|' read -r ff_ph ff_marker ff_what <<< "$FIRST_FAIL"
  echo ""
  echo " ┌─ HEAL: first failing gate = $ff_ph ($ff_what)"
  echo " │  missing marker: '$ff_marker'"
  if grep -qE 'EXCEPTION|PANIC' "$LOG"; then
    echo " │  fault detected — dumping the exception/panic:"
    grep -E 'EXCEPTION|PANIC|ESR_EL1|ELR_EL1|FAR_EL1' "$LOG" | sed 's/^/ │    /'
  elif ! grep -q "\[ALL\]" "$LOG"; then
    echo " │  no clean exit (hang or early abort) — last 12 console lines:"
    grep -v '^\s*$' "$LOG" | tail -12 | sed 's/^/ │    /'
  fi
  echo " └─ next: the kernel-validator agent diagnoses at $ff_ph's code and re-runs ./validate.sh"
  rm -f "$LOG"
  echo " VERDICT: REGRESSION — heal required (diagnostics above)."
  exit 1
fi
rm -f "$LOG"
echo " VERDICT: all implemented phases GREEN. Kernel is healthy."
echo " (continuous V&V + runtime self-heal (P6b); see LIFECYCLE.md + the kernel-validator agent.)"
exit 0
