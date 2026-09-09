//! Host stub of the kernel `arch_aarch64` crate. securechannel.rs's `securechannel_selftest`
//! (the in-kernel KAT printer) is the only consumer, and it only calls `_print`. On the host
//! we route it to stdout so the sim's --selftest can print the same KAT lines if invoked.
use std::io::Write;

pub fn _print(args: core::fmt::Arguments) {
    let _ = std::io::stdout().write_fmt(args);
}
