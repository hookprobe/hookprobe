//! Host build of the kernel crate's network-facing parsers (release gate SEC-02). The kernel is a bare-metal binary,
//! so its pure parser modules are compiled here from the SAME source files (`#[path]`), not copies:
//! HTTP request + form bodies (`httpreq.rs`), DNS wire (`dnswire.rs`), TLS ClientHello / JA4 (`tlshello.rs`) and the
//! frame classifier (`net.rs`). A parser that grows a `crate::` dependency breaks this build on purpose.
#![allow(dead_code, unused_imports)]

#[path = "../../../../os/kernel/kernel/src/httpreq.rs"]
pub mod httpreq;
#[path = "../../../../os/kernel/kernel/src/dnswire.rs"]
pub mod dnswire;
#[path = "../../../../os/kernel/kernel/src/tlshello.rs"]
pub mod tlshello;
#[path = "../../../../os/kernel/kernel/src/net.rs"]
pub mod net;
