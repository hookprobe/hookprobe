//! Host stand-in for the `devpolicy` items `ownerjournal::selftest` names (the self-test is not run by the fuzz
//! targets; this only lets the SAME journal source compile). The kernel's real `devpolicy.rs` is not fuzzed here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pol {
    Full = 0,
    InternetOnly = 1,
    LanOnly = 2,
    Quarantine = 3,
}
pub fn load_text(_: &[u8]) -> u32 {
    0
}
pub fn policy_of(_: &[u8; 6]) -> Pol {
    Pol::Full
}
