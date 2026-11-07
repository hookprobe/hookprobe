#![no_std]
#![no_main]
extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::UnbufferedServerConnection;

const HEAP: usize = 256 * 1024;
static mut ARENA: [u8; HEAP] = [0; HEAP];
#[global_allocator]
static ALLOC: talc::Talck<spin::Mutex<()>, talc::ClaimOnOom> =
    talc::Talc::new(unsafe { talc::ClaimOnOom::new(talc::Span::from_array(core::ptr::addr_of_mut!(ARENA))) }).lock();

#[derive(Debug)]
struct NoTime;
impl rustls::time_provider::TimeProvider for NoTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_794_000_000)))
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let cert = CertificateDer::from(include_bytes!("cert.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(include_bytes!("key.der").to_vec()));
    let provider = Arc::new(rustls_rustcrypto::provider());
    let cfg = rustls::ServerConfig::builder_with_details(provider, Arc::new(NoTime))
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .with_no_client_auth()
        .with_single_cert(Vec::from([cert]), key).unwrap();
    let conn = UnbufferedServerConnection::new(Arc::new(cfg)).unwrap();
    core::hint::black_box(&conn);
    loop {}
}

// On the device: a SYS_TRNG call into the kernel's RNG200 (fail-closed if it is absent).
fn kernel_trng(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(151); // spike stub ONLY
    }
    Ok(())
}
getrandom::register_custom_getrandom!(kernel_trng);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
