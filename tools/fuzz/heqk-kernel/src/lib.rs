//! Host build of the kernel crate's network-facing parsers (release gate SEC-02). The kernel is a bare-metal binary,
//! so its pure parser modules are compiled here from the SAME source files (`#[path]`), not copies:
//! HTTP request + form bodies (`httpreq.rs`), DNS wire (`dnswire.rs`), TLS ClientHello / JA4 (`tlshello.rs`) and the
//! frame classifier (`net.rs`), the ADR 0059 HQCFG1 configuration-bundle verifier (`cfgbundle.rs`), and the owner journal replay (`ownerjournal.rs`, A9). A parser that grows a `crate::` dependency breaks this build on purpose.
#![allow(dead_code, unused_imports)]

#[path = "../../../../os/kernel/kernel/src/httpreq.rs"]
pub mod httpreq;
#[path = "../../../../os/kernel/kernel/src/dnswire.rs"]
pub mod dnswire;
#[path = "../../../../os/kernel/kernel/src/tlshello.rs"]
pub mod tlshello;
#[path = "../../../../os/kernel/kernel/src/net.rs"]
pub mod net;
#[path = "../../../../os/kernel/kernel/src/cfgbundle.rs"]
pub mod cfgbundle;
// A9: the owner journal's REPLAY (sealed records off the eMMC → the owner-rule table), with the RPMB anchor types and
// the alert-hook record decoder it calls. Same source files; `devpolicy` is a host stand-in for its self-test only.
#[path = "../../../../os/kernel/kernel/src/ownerjournal.rs"]
pub mod ownerjournal;
#[path = "../../../../os/kernel/kernel/src/rpmb.rs"]
pub mod rpmb;
#[path = "../../../../os/kernel/kernel/src/alerthook.rs"]
pub mod alerthook;
pub mod devpolicy;
