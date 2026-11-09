//! Minimal ARM semihosting — lets bare-metal code terminate QEMU (test harness
//! + the P0 self-test). Requires QEMU's `-semihosting` flag. Not shipped on real
//! hardware; a debug-build convenience only.

const SYS_EXIT: u64 = 0x18;
const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x2_0026;

/// Terminate the guest, surfacing `code`.
///
/// Cloud tier (feature `smccc`): semihosting (`hlt #0xf000`) is an UNDEFINED instruction on
/// a real VM — the first exit or fault would re-fault in the fault handler. Instead print the
/// code (the QEMU-model harness reads it: tools/oci-a1/boot-heqk.sh) and use PSCI:
/// success -> SYSTEM_OFF, failure -> SYSTEM_RESET (fail closed into a visible reboot loop,
/// like the CM5 fault path; the QEMU model runs with -no-reboot so a reset ends the run).
#[cfg(feature = "smccc")]
pub fn exit(code: u32) -> ! {
    crate::_print(format_args!("\n[heqk-exit] code={}\n", code));
    if code == 0 {
        crate::smccc::system_off()
    } else {
        crate::smccc::system_reset()
    }
}

/// Terminate the QEMU `virt` guest, surfacing `code` as the process exit status.
#[cfg(not(feature = "smccc"))]
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
