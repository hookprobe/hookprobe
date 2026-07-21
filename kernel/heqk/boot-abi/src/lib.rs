#![no_std]
//! HEQK boot ABI — the typed contract between HBoot (heqk-boot, EL2) and the
//! HEQK microkernel (heqk-core, EL1). The kernel never parses raw DTBs: HBoot
//! owns platform discovery and hands over this structure (the seed of the
//! Phase-2 HEQK Object Model).

pub mod sha256;

/// "HBOTINF1" little-endian.
pub const BOOTINFO_MAGIC: u64 = 0x31464e49_544f4248;

/// Register x1 at kernel entry when launched by HBoot ("HBOT").
pub const HBOOT_ENTRY_MAGIC: u64 = 0x544f4248;

/// Fixed physical address of the BootInfo page (one page below the BootDebug
/// crumb page at 0x3FFF0000).
pub const BOOTINFO_ADDR: usize = 0x3FFE_0000;

// -------------------- Measured boot / attestation --------------------------
/// Reserved page for the measured-boot event log (one page below BootInfo).
pub const MEASURE_LOG_ADDR: usize = 0x3FFD_0000;
/// "HEQKMLG1" little-endian (H E Q K M L G 1).
pub const MEASURE_LOG_MAGIC: u64 = 0x31_47_4c_4d_4b_51_45_48;
/// Number of measurement registers (PCR-like accumulators).
pub const NUM_PCR: usize = 4;

/// Measurement register assignment (which PCR each measurement extends):
pub const PCR_FIRMWARE: u32 = 0; // HBoot self-measurement (recorded baseline)
pub const PCR_KERNEL: u32 = 1; // the launched kernel payload
pub const PCR_CONFIG: u32 = 2; // boot configuration (svn/floor/addrs/verify)
pub const PCR_SERVICES: u32 = 3; // reserved: kernel extends with EL0 services

/// Event kinds recorded in the log.
pub const EV_HBOOT_SELF: u32 = 1;
pub const EV_KERNEL: u32 = 2;
pub const EV_CONFIG: u32 = 3;
pub const EV_VERIFY: u32 = 4;

/// One measured-boot event: `pcr` was extended with `digest` (kind is a label).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MeasureEvent {
    pub pcr: u32,
    pub kind: u32,
    pub digest: [u8; 32],
}

// -------------------- Remote attestation quote -----------------------------
/// Reserved page for the attestation quote (below the measure log).
pub const ATTEST_QUOTE_ADDR: usize = 0x3FFC_0000;
/// Verifier challenge nonce (fixed for the demo; a real deployment injects a
/// fresh per-request nonce over a channel). Must match heqk-sign.
pub const CHALLENGE_NONCE: [u8; 32] = *b"HEQK-attestation-demo-nonce-0001";
/// AK SLH-DSA signature length. The AK uses the FAST-signing FIPS 205 variant
/// (SHA2-128f) because the quote is signed ON-DEVICE: 128s (slow-sign) is
/// unusable with software SHA-256 on bare metal, 128f signs in seconds. Same
/// 128-bit quantum security; larger signature (fine for once-per-boot).
pub const AK_SLHDSA_SIG_LEN: usize = 17088;
/// Context string bound into the AK signatures (must match heqk-sign).
pub const AK_SIG_CTX: &[u8] = b"HEQK-ATTEST-v1";

/// Quote body length: nonce(32) + svn(8) + PCR0..3(32*NUM_PCR).
pub const QUOTE_BODY_LEN: usize = 32 + 8 + 32 * NUM_PCR;

/// The attestation quote HBoot writes at ATTEST_QUOTE_ADDR. `nonce||svn||pcr`
/// is the signed body; both AK signatures cover exactly those bytes. A remote
/// verifier checks both signatures against the AK public keys, the nonce for
/// freshness, and the PCRs against known-good — proving the exact software
/// state, cryptographically, quantum-safely.
#[repr(C)]
pub struct AttestQuote {
    pub magic: u64, // ATTEST_QUOTE_MAGIC
    pub nonce: [u8; 32],
    pub svn: u64,
    pub pcr: [[u8; 32]; NUM_PCR],
    pub ed25519_sig: [u8; ED25519_SIG_LEN],
    pub slhdsa_sig: [u8; AK_SLHDSA_SIG_LEN],
}
/// "HEQKQOT1" little-endian.
pub const ATTEST_QUOTE_MAGIC: u64 = 0x31_54_4f_51_4b_51_45_48;

/// Header of the event log at MEASURE_LOG_ADDR; `count` MeasureEvents follow it
/// contiguously. `pcr` holds the final accumulator values a verifier must be
/// able to reproduce by replaying the events (that replay is the integrity
/// check — the log is tamper-evident because each PCR folds order-dependently).
#[repr(C)]
pub struct MeasureLog {
    pub magic: u64,
    pub version: u32,
    pub num_pcr: u32,
    pub count: u32,
    pub _pad: u32,
    pub pcr: [[u8; 32]; NUM_PCR],
    // MeasureEvent[count] immediately follows.
}

// ---------------- Runtime attestation: per-boot ephemeral key (B-2) ----------
/// Reserved page (below the quote) for the per-boot ephemeral attestation key
/// + its AK-issued certificate. HBoot mints a fresh ephemeral ed25519 key each
/// boot (seeded from the hardware TRNG), hybrid-signs a cert binding it to
/// (svn, PCRs) with the device AK, then SCRUBS the AK private key. The kernel
/// holds only the ephemeral key and signs verifier-supplied challenge nonces
/// with it — genuine per-request freshness (closes B-2) without the device AK
/// ever persisting in RAM or SLH-DSA signing living in the kernel.
pub const ATTEST_EPH_ADDR: usize = 0x3FFB_0000;
/// "HEQKEPH1" little-endian.
pub const ATTEST_EPH_MAGIC: u64 = 0x31_48_50_45_4b_51_45_48;
/// Context string bound into the ephemeral-key certificate (must match heqk-sign).
pub const EPH_CERT_CTX: &[u8] = b"HEQK-EPHCERT-v1";
/// Cert body the AK signs = eph_pk(32) || svn(8) || device_id(8) || PCR0..3.
/// `device_id` is the BCM2712 board serial (per-device identity, read over the
/// VideoCore mailbox) — binding it means a quote/cert from one device cannot be
/// presented as another's (closes the anonymity half of B-1).
pub const EPH_CERT_BODY_LEN: usize = 32 + 8 + 8 + 32 * NUM_PCR;
/// Context string bound into a runtime challenge response (must match heqk-sign).
pub const CHALLENGE_CTX: &[u8] = b"HEQK-CHALLENGE-v1";

/// Per-boot ephemeral attestation key + AK cert, written by HBoot at
/// ATTEST_EPH_ADDR and consumed by the kernel's runtime attestation service.
#[repr(C)]
pub struct AttestEphemeral {
    pub magic: u64,                       // ATTEST_EPH_MAGIC
    pub eph_ed_pk: [u8; 32],              // ephemeral ed25519 public key (this boot)
    pub eph_ed_sk: [u8; 64],             // ephemeral ed25519 secret key (kernel signs challenges)
    pub cert_ed_sig: [u8; ED25519_SIG_LEN],   // AK ed25519 sig over the cert body
    pub cert_slh_sig: [u8; AK_SLHDSA_SIG_LEN], // AK SLH-DSA sig over the cert body (quantum-safe)
    pub svn: u64,                         // bound into the cert body
    pub device_id: u64,                   // BCM2712 board serial (0 = mailbox unreachable)
    pub otp_provisioned: u64,             // 1 = OTP device-key region non-blank (secret AK possible)
    pub pcr: [[u8; 32]; NUM_PCR],         // bound into the cert body
}

/// Payload header magic "HQKPLD3\0" little-endian (v3 = hybrid sigs + SVN).
pub const PAYLOAD_MAGIC: u64 = 0x00_33444c_504b_5148;

/// Handed to the kernel in x0. Extend by APPENDING fields only; bump
/// `version` when you do.
#[repr(C)]
pub struct BootInfo {
    pub magic: u64,        // BOOTINFO_MAGIC
    pub version: u64,      // 1
    pub dtb_pa: u64,       // firmware DTB physical address (transitional; the
                           // kernel must not parse it — Object Model comes)
    pub kernel_pa: u64,    // where the payload was relocated
    pub kernel_size: u64,  // payload size in bytes
    pub kernel_hash: [u8; 32], // SHA-256 measurement HBoot computed
    pub hboot_version: u64,
    pub el2_gate: u64,     // nonzero => `hvc #0` reboot gate is resident
    pub verify_flags: u64, // bit0 = ed25519 verified, bit1 = SLH-DSA verified
    pub svn: u64,          // security version number of the booted image
    pub svn_floor: u64,    // the anti-rollback floor HBoot enforced
    pub measure_log_pa: u64, // MEASURE_LOG_ADDR (measured-boot event log)
    pub measure_count: u64,  // number of events in the log
    pub quote_pa: u64,       // ATTEST_QUOTE_ADDR (AK-signed attestation quote)
    pub eph_pa: u64,         // v5: ATTEST_EPH_ADDR (per-boot ephemeral key + AK cert), 0 if absent
}

/// BootInfo.verify_flags bits.
pub const VERIFY_ED25519: u64 = 1 << 0;
pub const VERIFY_SLHDSA: u64 = 1 << 1;

/// SLH-DSA-SHA2-128s (FIPS 205) sizes.
pub const SLHDSA_SIG_LEN: usize = 7856;
pub const PUBKEY_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;

/// Context string bound into both signatures (must match heqk-sign).
pub const SIG_CTX: &[u8] = b"HEQK-BOOT-v1";

/// HBoot v1 header: HYBRID secure boot + anti-rollback. Both signatures are
/// over the *signed message* below (which binds the security version `svn`, so
/// the version cannot be altered without breaking the signatures). HBoot
/// requires BOTH to verify AND `svn >= floor`. Prepended to the kernel payload
/// inside the combined image at HBOOT_PAYLOAD_OFFSET.
#[repr(C)]
pub struct PayloadHeader {
    pub magic: u64,        // PAYLOAD_MAGIC
    pub size: u64,         // payload bytes following this header
    pub entry_offset: u64, // entry point offset inside the payload (0)
    pub load_pa: u64,      // where the payload must be relocated (0x1000000)
    pub svn: u64,          // security version number (anti-rollback; signed)
    pub sha256: [u8; 32],  // measurement (informational; verify binds to recompute)
    pub ed25519_sig: [u8; ED25519_SIG_LEN], // classical signature over signed_message
    pub slhdsa_sig: [u8; SLHDSA_SIG_LEN],   // post-quantum signature over signed_message
}

/// The message both signatures cover: `SHA-256( LE64(svn) || sha256(payload) )`.
/// Binding the SVN into the signed message is what makes anti-rollback sound —
/// an attacker cannot raise the version on an old payload without invalidating
/// both signatures. Signer (heqk-sign) and HBoot MUST compute this identically.
/// `sha256` here is any correct SHA-256; the 40-byte input is (svn_le, hash).
pub fn signed_message_input(svn: u64, payload_hash: &[u8; 32]) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[..8].copy_from_slice(&svn.to_le_bytes());
    buf[8..].copy_from_slice(payload_hash);
    buf
}

/// The payload header sits at this offset inside the combined hboot8.img
/// (HBoot's binary is padded to this boundary by mkimage-hboot.sh). 2 MiB
/// gives room for the PQ crypto (SLH-DSA/SHA3) in a debug build.
pub const HBOOT_PAYLOAD_OFFSET: usize = 0x200000; // 2 MiB

/// Physical load/link address of the kernel payload.
pub const KERNEL_LOAD_PA: usize = 0x0100_0000; // 16 MiB
