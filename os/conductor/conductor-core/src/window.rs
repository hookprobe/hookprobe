// SPDX-License-Identifier: AGPL-3.0-only
//! A window of the device's own telemetry, as the kernel hands it over, and the context built from it.
//!
//! The cards a model reads are built here, in the harness's server, by `neuro_contract::cards::build_window`
//! (operator decision 2026-11-28, Neuro doc 53 R12): the same function, and so the same bytes, as Neuro's
//! builder. The kernel supplies events, never prose. [`build`] decodes the window and writes the context that
//! becomes `JobSpec::context`.
//!
//! Wire format, little-endian. Strings are stored once and referred to by index:
//! ```text
//! n_strings u16   { len u8, bytes }*
//! n_flows u32     { t_ms u32, src u16, dst u16, port u16, bytes_out u64, rst u8 }*
//! n_dns u32       { src u16, qname u16, nxdomain u8 }*
//! n_dets u16      { id u16, src u16, dst u16, port u16, category u16, mitre u16, severity u8, rule_msg u16 }*
//! n_behav u16     { src u16, hour u8, driver u16, score_q8 u32 }*
//! n_pairs u32     { src u16, dst u16 }*          baseline pairs
//! n_suffixes u16  { suffix u16 }*                baseline DNS suffixes
//! ```
//! String index 0xFFFF is the empty string (a detection with no destination or technique). Flags are 0 or 1.
//! Nothing may follow. Every text is checked again by the card builder (printable ASCII, bounded), so a
//! window cannot put a line break or a control character into a context.
//!
//! Memory is the caller's ([`Bufs`]): the server owns fixed arrays sized for the largest window it accepts,
//! and a window that does not fit is refused, never cut.

use crate::wire::Reader;
use neuro_contract::cards::{self, Behaviour, Built, Detection, Dns, Flow, Scratch, Window};
use neuro_contract::{ContractError, Sink};

/// The index that stands for the empty string.
pub const NONE: u16 = 0xffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    /// Truncated, trailing bytes, or a count that does not match the data.
    Length,
    /// A string that is not UTF-8, an index with no string, or a flag that is not 0 or 1.
    Format,
    /// More strings or events than the caller's buffers hold.
    Space,
    /// The card builder refused the window (a text it will not write, or its own working memory is full).
    Cards(ContractError),
}

/// The caller's memory for one window. Each slice bounds what a window may hold.
pub struct Bufs<'s, 'a> {
    pub strings: &'s mut [&'a str],
    pub flows: &'s mut [Flow<'a>],
    pub dns: &'s mut [Dns<'a>],
    pub detections: &'s mut [Detection<'a>],
    pub behaviour: &'s mut [Behaviour<'a>],
    pub pairs: &'s mut [(&'a str, &'a str)],
    pub suffixes: &'s mut [&'a str],
}

fn flag(r: &mut Reader) -> Result<bool, WindowError> {
    match r.u8().ok_or(WindowError::Length)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WindowError::Format),
    }
}

/// Decode `window` and write its context (ranked cards within `budget`, then the `REST` line) to `out`.
pub fn build<'a>(window: &'a [u8], budget: u32, bufs: &mut Bufs<'_, 'a>, scratch: &mut Scratch<'_, 'a>, out: &mut (impl Sink + ?Sized)) -> Result<Built, WindowError> {
    let (l, sp) = (WindowError::Length, WindowError::Space);
    let r = &mut Reader::new(window);
    let n_str = usize::from(r.u16().ok_or(l)?);
    let strings = bufs.strings.get_mut(..n_str).ok_or(sp)?;
    for s in strings.iter_mut() {
        let n = usize::from(r.u8().ok_or(l)?);
        *s = core::str::from_utf8(r.take(n).ok_or(l)?).map_err(|_| WindowError::Format)?;
    }
    let strings: &[&'a str] = strings;
    let text = |i: u16| -> Result<&'a str, WindowError> {
        if i == NONE {
            return Ok("");
        }
        strings.get(usize::from(i)).copied().ok_or(WindowError::Format)
    };
    let idx = |r: &mut Reader<'a>| -> Result<&'a str, WindowError> { text(r.u16().ok_or(WindowError::Length)?) };

    let n = usize::try_from(r.u32().ok_or(l)?).map_err(|_| sp)?;
    let flows = bufs.flows.get_mut(..n).ok_or(sp)?;
    for f in flows.iter_mut() {
        let t_ms = r.u32().ok_or(l)?;
        let (src, dst) = (idx(r)?, idx(r)?);
        let port = u32::from(r.u16().ok_or(l)?);
        let bytes_out = r.u64().ok_or(l)?;
        *f = Flow::new(t_ms, src, dst, port, bytes_out, flag(r)?);
    }
    let n = usize::try_from(r.u32().ok_or(l)?).map_err(|_| sp)?;
    let dns = bufs.dns.get_mut(..n).ok_or(sp)?;
    for q in dns.iter_mut() {
        let (src, qname) = (idx(r)?, idx(r)?);
        *q = Dns::new(src, qname, flag(r)?);
    }
    let n = usize::from(r.u16().ok_or(l)?);
    let dets = bufs.detections.get_mut(..n).ok_or(sp)?;
    for d in dets.iter_mut() {
        let (id, src, dst) = (idx(r)?, idx(r)?, idx(r)?);
        let port = u32::from(r.u16().ok_or(l)?);
        let (category, mitre) = (idx(r)?, idx(r)?);
        let severity = u32::from(r.u8().ok_or(l)?);
        *d = Detection { id, src, dst, port, category, mitre, severity, rule_msg: idx(r)? };
    }
    let n = usize::from(r.u16().ok_or(l)?);
    let behav = bufs.behaviour.get_mut(..n).ok_or(sp)?;
    for b in behav.iter_mut() {
        let src = idx(r)?;
        let hour = u32::from(r.u8().ok_or(l)?);
        let driver = idx(r)?;
        *b = Behaviour { src, hour, driver, score_q8: r.u32().ok_or(l)? };
    }
    let n = usize::try_from(r.u32().ok_or(l)?).map_err(|_| sp)?;
    let pairs = bufs.pairs.get_mut(..n).ok_or(sp)?;
    for p in pairs.iter_mut() {
        *p = (idx(r)?, idx(r)?);
    }
    let n = usize::from(r.u16().ok_or(l)?);
    let suffixes = bufs.suffixes.get_mut(..n).ok_or(sp)?;
    for s in suffixes.iter_mut() {
        *s = idx(r)?;
    }
    if !r.done() {
        return Err(l);
    }
    let w = Window { flows, dns, detections: dets, behaviour: behav, baseline_pairs: pairs, baseline_suffixes: suffixes };
    cards::build_window(w, budget, scratch, out).map_err(WindowError::Cards)
}
