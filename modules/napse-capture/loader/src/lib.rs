//! napse-capture userspace — shared library for the two binaries:
//!   - `napse-loader` — attach the CO-RE detection object (XDP/TC) + drain its events ringbuf.
//!   - `napse-dpi`    — deep-packet sensor on the mirror sink (dns/tls/http).
//!
//! Both emit NAPSE flow records to `/var/lib/hookprobe/flows`. See ADR 0005.

pub mod beacon;
pub mod capture;
pub mod confirm;
pub mod dpi;
pub mod event;
pub mod feed;
pub mod l2guard;
pub mod lateral;
pub mod plan;
pub mod portscan;
pub mod shed;
