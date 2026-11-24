// SPDX-License-Identifier: AGPL-3.0-only
#![no_std]
//! The heqk flash stub (ADR 0070): a separate heqk build that does one thing — verify a signed slot image with the
//! shared boot verifier, then write a whole disk image to the CM5 eMMC and prove it by read-back.
//!
//! * `dwc2`   — the BCM2712 DWC2 OTG core in device mode (polled, FIFO mode), behind a register trait;
//! * `desc`   — USB descriptors (vendor interface ff/48/01, BOS + MS OS 2.0 for WinUSB);
//! * `proto`  — HQFL v1 framing, status codes, CRC-32;
//! * `server` — the HQFL server and its security contract (verify before write, MBR last, read-back, slots);
//! * `image`  — the slot-image checks (boot_abi::verify, SVN floor, HBoot prefix) and the both-slot check;
//! * `release`— release vs debug stub, from the dev-key fingerprint block-list.
//!
//! The bare-metal binary (`src/main.rs`, feature `flashstub`) wires these to the real MMIO and the eMMC driver.
//! Everything here is plain logic over traits, so the host tests drive the same code.

pub mod desc;
pub mod dwc2;
pub mod image;
pub mod proto;
pub mod release;
pub mod server;

use proto::MAX_RESP;

/// One turn of the stub's main loop: service the USB core, answer at most one HQFL frame. Returns the bus event.
pub fn service<R: dwc2::Regs, M: server::Medium>(
    usb: &mut dwc2::Dwc2<'_, R>,
    srv: &mut server::Server<'_>,
    m: &mut M,
) -> Option<dwc2::Event> {
    let ev = usb.poll();
    if ev == Some(dwc2::Event::Reset) {
        srv.on_bus_reset(m);
    }
    // One request, one response: the next frame is taken only once the previous response has gone out.
    if !usb.in_busy() {
        if let Some(req) = usb.frame() {
            let mut out = [0u8; MAX_RESP];
            let n = srv.handle(m, req, &mut out);
            usb.rearm_out();
            usb.send(&out[..n]);
        }
    }
    ev
}
