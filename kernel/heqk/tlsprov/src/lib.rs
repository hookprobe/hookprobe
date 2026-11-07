//! heqk's thin rustls `CryptoProvider` (ADR 0051 D1).
//!
//! Server-only, TLS 1.3 only, exactly one cipher suite (`TLS13_CHACHA20_POLY1305_SHA256`), X25519 key
//! exchange and an ECDSA P-256/SHA-256 signing key. Everything here is glue between rustls' provider traits
//! and RustCrypto / dalek primitives — no cryptographic algorithm is implemented in this crate.
//!
//! Entropy is injected by the host (`set_rng`): on heqk the EL0 TLS server passes a function backed by the
//! kernel's hardware TRNG; a missing or failing source makes every handshake fail (fail-closed).
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use chacha20poly1305::aead::{AeadInPlace, Buffer, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::Mac;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::crypto::{
    hash, hmac as rhmac, tls13::HkdfUsingHmac, ActiveKeyExchange, CipherSuiteCommon, CryptoProvider, GetRandomFailed,
    KeyProvider, SecureRandom, SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
    SignatureAlgorithm, SignatureScheme, SupportedCipherSuite, Tls13CipherSuite,
};

// ------------------------------------------------------------------ entropy (injected)

/// `fill(buf) -> bool`: true when `buf` was filled from a real entropy source.
pub type RngFn = fn(&mut [u8]) -> bool;
static RNG: AtomicUsize = AtomicUsize::new(0);

/// Install the entropy source (call once before building a `ServerConfig`).
pub fn set_rng(f: RngFn) {
    RNG.store(f as usize, Ordering::Release);
}

#[derive(Debug)]
struct Rng;
impl SecureRandom for Rng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let p = RNG.load(Ordering::Acquire);
        if p == 0 {
            return Err(GetRandomFailed); // no source installed: fail closed
        }
        let f: RngFn = unsafe { core::mem::transmute::<usize, RngFn>(p) };
        if f(buf) { Ok(()) } else { Err(GetRandomFailed) }
    }
}

// ------------------------------------------------------------------ SHA-256 / HMAC / HKDF

struct Sha256Hash;
struct Sha256Ctx(sha2::Sha256);

impl hash::Hash for Sha256Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Ctx(<sha2::Sha256 as sha2::Digest>::new()))
    }
    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&<sha2::Sha256 as sha2::Digest>::digest(data)[..])
    }
    fn output_len(&self) -> usize {
        32
    }
    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        rustls::crypto::hash::HashAlgorithm::SHA256
    }
}
impl hash::Context for Sha256Ctx {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&sha2::Digest::finalize(self.0.clone())[..])
    }
    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Ctx(self.0.clone()))
    }
    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&sha2::Digest::finalize(self.0)[..])
    }
    fn update(&mut self, data: &[u8]) {
        sha2::Digest::update(&mut self.0, data);
    }
}

struct HmacSha256;
struct HmacSha256Key(hmac::Hmac<sha2::Sha256>);
impl rhmac::Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn rhmac::Key> {
        // HMAC accepts keys of any length (RFC 2104), so this cannot fail.
        Box::new(HmacSha256Key(<hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).expect("HMAC: any key length")))
    }
    fn hash_output_len(&self) -> usize {
        32
    }
}
impl rhmac::Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> rhmac::Tag {
        let mut m = self.0.clone();
        m.update(first);
        for x in middle {
            m.update(x);
        }
        m.update(last);
        rhmac::Tag::new(&m.finalize().into_bytes()[..])
    }
    fn tag_len(&self) -> usize {
        32
    }
}
static HMAC_SHA256: HmacSha256 = HmacSha256;
static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA256);

// ------------------------------------------------------------------ the one AEAD: ChaCha20-Poly1305

struct ChaChaAead;
struct ChaChaEnc(ChaCha20Poly1305, Iv);
struct ChaChaDec(ChaCha20Poly1305, Iv);
const TAG_LEN: usize = 16;

impl Tls13AeadAlgorithm for ChaChaAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(ChaChaEnc(ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key"), iv))
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(ChaChaDec(ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key"), iv))
    }
    fn key_len(&self) -> usize {
        32
    }
    fn extract_keys(&self, key: AeadKey, iv: Iv) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

/// `aead::Buffer` over rustls' outbound payload (encrypt appends the tag).
struct EncBuf<'a>(&'a mut PrefixedPayload);
impl AsRef<[u8]> for EncBuf<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl AsMut<[u8]> for EncBuf<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl Buffer for EncBuf<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }
    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

/// `aead::Buffer` over rustls' inbound payload (decrypt only truncates; growing is an error, never a panic).
struct DecBuf<'a, 'p>(&'a mut BorrowedPayload<'p>);
impl AsRef<[u8]> for DecBuf<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}
impl AsMut<[u8]> for DecBuf<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0
    }
}
impl Buffer for DecBuf<'_, '_> {
    fn extend_from_slice(&mut self, _: &[u8]) -> chacha20poly1305::aead::Result<()> {
        Err(chacha20poly1305::aead::Error)
    }
    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

impl MessageEncrypter for ChaChaEnc {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        let nonce = Nonce::new(&self.1, seq).0;
        let aad = make_tls13_aad(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array()); // TLSInnerPlaintext content type
        self.0
            .encrypt_in_place((&nonce).into(), &aad, &mut EncBuf(&mut payload))
            .map_err(|_| Error::EncryptError)?;
        // RFC 8446 §5.1: TLS 1.3 records carry the legacy 0x0303 version and outer type application_data.
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }
    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for ChaChaDec {
    fn decrypt<'a>(&mut self, mut msg: InboundOpaqueMessage<'a>, seq: u64) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.1, seq).0;
        let aad = make_tls13_aad(payload.len());
        self.0
            .decrypt_in_place((&nonce).into(), &aad, &mut DecBuf(payload))
            .map_err(|_| Error::DecryptError)?;
        msg.into_tls13_unpadded_message()
    }
}

static CHACHA: ChaChaAead = ChaChaAead;
static SHA256: Sha256Hash = Sha256Hash;

/// The only suite this provider offers.
pub static TLS13_CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &SHA256,
        // RFC 8446 §5.5: ChaCha20-Poly1305 has no practical per-key record limit.
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &CHACHA,
    quic: None,
};

// ------------------------------------------------------------------ X25519

#[derive(Debug)]
struct X25519;
struct X25519Active {
    secret: x25519_dalek::StaticSecret,
    public: [u8; 32],
}

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut seed = [0u8; 32];
        Rng.fill(&mut seed).map_err(|_| Error::FailedToGetRandomBytes)?;
        let secret = x25519_dalek::StaticSecret::from(seed);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Ok(Box::new(X25519Active { secret, public }))
    }
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for X25519Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer_pub_key.try_into().map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // RFC 7748 §6.1 / RFC 8446 §7.4.2: an all-zero shared secret (small-order peer key) is refused.
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

static X25519_GROUP: X25519 = X25519;

// ------------------------------------------------------------------ ECDSA P-256 signing key

#[derive(Debug)]
struct EcdsaP256Key(Arc<p256::ecdsa::SigningKey>);
#[derive(Debug)]
struct EcdsaP256Signer(Arc<p256::ecdsa::SigningKey>);

impl SigningKey for EcdsaP256Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(EcdsaP256Signer(self.0.clone())) as Box<dyn Signer>)
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaP256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // RFC 6979 deterministic nonce (no RNG on the signing path); DER encoding as TLS requires.
        let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::try_sign(&*self.0, message)
            .map_err(|_| Error::General("ecdsa sign".into()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[derive(Debug)]
struct Keys;
impl KeyProvider for Keys {
    fn load_private_key(&self, key_der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        use p256::pkcs8::DecodePrivateKey;
        let k = match &key_der {
            PrivateKeyDer::Pkcs8(der) => p256::ecdsa::SigningKey::from_pkcs8_der(der.secret_pkcs8_der()),
            _ => return Err(Error::General("only a PKCS#8 ECDSA P-256 key is supported".into())),
        }
        .map_err(|_| Error::General("not an ECDSA P-256 PKCS#8 key".into()))?;
        Ok(Arc::new(EcdsaP256Key(Arc::new(k))))
    }
}

/// An ECDSA P-256 signing key from a raw 32-byte scalar (the device derives it from its SRK — the key never
/// exists as a file). `None` if the scalar is zero or ≥ the group order.
pub fn signing_key_from_scalar(scalar: &[u8; 32]) -> Option<Arc<dyn SigningKey>> {
    let k = p256::ecdsa::SigningKey::from_bytes(scalar.into()).ok()?;
    Some(Arc::new(EcdsaP256Key(Arc::new(k))))
}

/// The SEC1 uncompressed public point (65 bytes) of a scalar's key — what provisioning publishes so the
/// owner's CA can certify it (ADR 0051 D3).
pub fn public_point_from_scalar(scalar: &[u8; 32]) -> Option<[u8; 65]> {
    let k = p256::ecdsa::SigningKey::from_bytes(scalar.into()).ok()?;
    let ep = k.verifying_key().to_encoded_point(false);
    ep.as_bytes().try_into().ok()
}

// ------------------------------------------------------------------ the provider

static RNG_IMPL: Rng = Rng;
static KEYS: Keys = Keys;

/// The thin provider: one TLS 1.3 suite, X25519, ECDSA P-256 server key, injected entropy. No client
/// authentication, so no signature-verification algorithms are offered.
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: alloc::vec![SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_SHA256)],
        kx_groups: alloc::vec![&X25519_GROUP as &dyn SupportedKxGroup],
        signature_verification_algorithms: WebPkiSupportedAlgorithms { all: &[], mapping: &[] },
        secure_random: &RNG_IMPL,
        key_provider: &KEYS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_entropy_source_fails_closed() {
        // RNG unset in this test binary until set_rng: key exchange must refuse to start.
        RNG.store(0, Ordering::Release);
        assert!(X25519_GROUP.start().is_err());
        set_rng(|b| {
            b.fill(0x5a);
            false // a source that reports failure is also refused
        });
        assert!(X25519_GROUP.start().is_err());
    }

    #[test]
    fn small_order_peer_key_refused() {
        set_rng(|b| {
            for (i, x) in b.iter_mut().enumerate() {
                *x = i as u8 ^ 0x3c;
            }
            true
        });
        let a = X25519_GROUP.start().unwrap();
        assert_eq!(a.pub_key().len(), 32);
        // u = 0 is a small-order point: the shared secret is all-zero → InvalidKeyShare.
        assert!(a.complete(&[0u8; 32]).is_err());
        let b = X25519_GROUP.start().unwrap();
        assert!(b.complete(&[1u8; 31]).is_err()); // wrong length
    }

    #[test]
    fn srk_scalar_key_signs_and_publishes() {
        assert!(signing_key_from_scalar(&[0u8; 32]).is_none()); // zero scalar is not a key
        assert!(signing_key_from_scalar(&[0xff; 32]).is_none()); // ≥ group order
        let s = [7u8; 32];
        let k = signing_key_from_scalar(&s).unwrap();
        let signer = k.choose_scheme(&[SignatureScheme::ED25519, SignatureScheme::ECDSA_NISTP256_SHA256]).unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
        let sig = signer.sign(b"transcript").unwrap();
        assert_eq!(sig[0], 0x30); // DER SEQUENCE
        let pt = public_point_from_scalar(&s).unwrap();
        assert_eq!(pt[0], 0x04); // SEC1 uncompressed
        use p256::ecdsa::signature::Verifier;
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pt).unwrap();
        let der = p256::ecdsa::Signature::from_der(&sig).unwrap();
        assert!(vk.verify(b"transcript", &der).is_ok());
        assert!(k.choose_scheme(&[SignatureScheme::ED25519]).is_none()); // nothing else offered
    }
}
