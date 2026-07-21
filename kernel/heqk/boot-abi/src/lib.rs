#![no_std]
//! HEQK boot ABI — the typed contract between HBoot (heqk-boot, EL2) and the
//! HEQK microkernel (heqk-core, EL1). The kernel never parses raw DTBs: HBoot
//! owns platform discovery and hands over this structure (the seed of the
//! Phase-2 HEQK Object Model).

/// "HBOTINF1" little-endian.
pub const BOOTINFO_MAGIC: u64 = 0x31464e49_544f4248;

/// Register x1 at kernel entry when launched by HBoot ("HBOT").
pub const HBOOT_ENTRY_MAGIC: u64 = 0x544f4248;

/// Fixed physical address of the BootInfo page (one page below the BootDebug
/// crumb page at 0x3FFF0000).
pub const BOOTINFO_ADDR: usize = 0x3FFE_0000;

/// Payload header magic "HQKPLD1\0" little-endian.
pub const PAYLOAD_MAGIC: u64 = 0x00_31444c_504b_5148;

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
}

/// Header prepended to the kernel payload inside the combined image.
/// Located at HBOOT_PAYLOAD_OFFSET from the image base (0x200000 in RAM).
#[repr(C)]
pub struct PayloadHeader {
    pub magic: u64,        // PAYLOAD_MAGIC
    pub size: u64,         // payload bytes following this header
    pub entry_offset: u64, // entry point offset inside the payload (0)
    pub load_pa: u64,      // where the payload must be relocated (0x1000000)
    pub sha256: [u8; 32],  // integrity hash of the payload
    pub sig: [u8; 64],     // ed25519 signature slot (v1; zero in v0)
}

/// The payload header sits at this offset inside the combined hboot8.img
/// (HBoot's binary is padded to this boundary by mkimage-hboot.sh).
pub const HBOOT_PAYLOAD_OFFSET: usize = 0x40000; // 256 KiB

/// Physical load/link address of the kernel payload.
pub const KERNEL_LOAD_PA: usize = 0x0100_0000; // 16 MiB
