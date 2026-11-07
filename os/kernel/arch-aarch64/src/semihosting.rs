//! Minimal ARM semihosting — lets bare-metal code terminate QEMU (test harness
//! + the P0 self-test). Requires QEMU's `-semihosting` flag. Not shipped on real
//! hardware; a debug-build convenience only.

const SYS_EXIT: u64 = 0x18;
const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x2_0026;

/// Terminate the QEMU `virt` guest, surfacing `code` as the process exit status.
pub fn exit(code: u32) -> ! {
    // A64 semihosting call: op in x0, parameter block pointer in x1.
    let block = [ADP_STOPPED_APPLICATION_EXIT, code as u64];
    unsafe {
        core::arch::asm!(
            "hlt #0xf000",
            in("x0") SYS_EXIT,
            in("x1") block.as_ptr(),
            options(noreturn, nostack),
        );
    }
}
