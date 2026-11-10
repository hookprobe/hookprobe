//! IPv6 WAN builders/parsers — moved to `hal::ip6` (ADR 0050 D4 step 3: one pure source for the kernel and the
//! EL0 network-services server). Re-exported here so every caller keeps its path.
pub use hal::ip6::*;
