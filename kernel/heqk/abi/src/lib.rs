#![no_std]
//! Shared kernel<->userspace ABI: syscall numbers, trap-frame layout, cap structs.
//!
//! P0 placeholder — the real surface lands at P3 (SVC syscall boundary) and
//! P4 (IPC). Kept in the workspace now so the ring-0/ring-3 contract has a home
//! from the start and both sides depend on exactly one crate for it.

/// Syscall numbers (passed in x8 by convention on aarch64).
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall {
    Yield = 0,
    // P3/P4: IpcCall, IpcReplyRecv, CapCopy, CapRevoke, UntypedRetype, ...
}
