use std::io::{Read, Write};
use std::sync::Arc;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
fn main() {
    let cert = CertificateDer::from(include_bytes!("cert.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(include_bytes!("key.der").to_vec()));
    let cfg = Arc::new(rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
        .with_no_client_auth().with_single_cert(vec![cert], key).unwrap());
    let l = std::net::TcpListener::bind("127.0.0.1:18443").unwrap();
    for _ in 0..3 {
        let (mut s, _) = l.accept().unwrap();
        let mut c = rustls::ServerConnection::new(cfg.clone()).unwrap();
        let mut t = rustls::Stream::new(&mut c, &mut s);
        let mut buf = [0u8; 2048];
        let n = t.read(&mut buf).unwrap_or(0);
        let body = b"{\"status\":\"ok\",\"substrate\":\"heqk\"}";
        let _ = write!(t, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = t.write_all(body);
        let _ = t.flush();
        let suite = c.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite()));
        eprintln!("served {} B request, suite {:?}, kx {:?}", n, suite, c.negotiated_key_exchange_group().map(|g| g.name()));
    }
}
