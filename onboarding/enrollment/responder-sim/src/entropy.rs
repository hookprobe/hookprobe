//! HOST entropy shim for the responder-sim.
//!
//! `securechannel.rs` (included verbatim from the kernel) refers to
//! `crate::entropy::{EntropySource, EntropyError}`. In the kernel that is the fail-closed
//! TRNG abstraction; here it is the SAME trait shape backed by the OS CSPRNG (getrandom).
//! The trait signature MUST match the kernel's `entropy::EntropySource` exactly so the
//! `&mut dyn EntropySource` call sites in securechannel.rs type-check.

/// Fail-closed entropy error — mirrors kernel `entropy::EntropyError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// The source is absent / not ready.
    Unavailable,
    /// The source is present but failed a startup health check.
    HealthCheckFailed,
}

/// Object-safe entropy source — mirrors kernel `entropy::EntropySource`.
pub trait EntropySource {
    /// Fill `out` with cryptographic-quality random bytes, or fail closed.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError>;

    /// A fresh 32-byte secret (ephemeral scalar / KEM seed). Default impl over `fill`.
    fn fill_32(&mut self) -> Result<[u8; 32], EntropyError> {
        let mut b = [0u8; 32];
        self.fill(&mut b)?;
        Ok(b)
    }

    /// Startup health check. The OS CSPRNG is trusted, so this is a no-op success.
    fn health_check(&mut self) -> Result<(), EntropyError>;
}

/// The host CSPRNG leaf. This is a SIMULATOR — using getrandom is correct here (the metal
/// device uses its real fail-closed BCM2712 RNG200; only the on-device path must be TRNG).
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::getrandom(out).map_err(|_| EntropyError::Unavailable)
    }
    fn health_check(&mut self) -> Result<(), EntropyError> {
        Ok(())
    }
}
