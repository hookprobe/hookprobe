// SPDX-License-Identifier: AGPL-3.0-only
//! QEMU integration-test profile (`qemu-itest`, operator decision 2026-11-22, G19 S1): the self-tests of the
//! virtio-rng entropy leaf. Never in a CM5 / cloud image (compile-time refused in entropy.rs).
//!
//! `[P-itest-rng]` — with `-device virtio-rng-device`: the production `MetalEntropy<HwTrng>` passes its startup health
//! check over virtio-rng, a 4 KiB fill has a sane bit balance, two fills differ, the driver counted real device round
//! trips, and the health check rejects a stuck source (a local test double, never a key source).
//! Without the device the same boot prints `[P-itest-rng] FAIL-CLOSED` — no entropy, so no keys, no handshake — and the
//! runner (tools/itest-qemu.sh) asserts that line for the negative run.
#![cfg(feature = "qemu-itest")]

use crate::entropy::{boot_health_assert, EntropySource, HwTrng, MetalEntropy, RawTrng};

macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }

/// A stuck raw source — test double for the health-check refusal ONLY (never handed to a key generator).
struct Stuck;
impl RawTrng for Stuck {
    fn next_word(&mut self) -> Option<u64> {
        Some(0x5a5a_5a5a_5a5a_5a5a)
    }
}

pub fn selftest() -> bool {
    let health = boot_health_assert();
    let (present, _, _, why) = arch_aarch64::virtio_rng::status();
    if health.is_err() {
        kprint!(" [P-itest-rng] FAIL-CLOSED — {:?}: virtio-rng {} ({}) -> no entropy, so no key generation and no G19 handshake (no timer/counter fallback exists)\n",
            health, if present { "present but failing" } else { "absent" }, arch_aarch64::virtio_rng::dead_reason(why));
        return false;
    }
    let mut src = MetalEntropy::new(HwTrng::new());
    let (mut a, mut b) = ([0u8; 4096], [0u8; 4096]);
    let fa = src.fill(&mut a).is_ok();
    let fb = src.fill(&mut b).is_ok();
    let ones: u32 = a.iter().map(|x| x.count_ones()).sum();
    // 32,768 bits: mean 16,384, sigma ~90.5 — a ±6-sigma window (a broken / constant source lands far outside)
    let balanced = (16_384 - 543..=16_384 + 543).contains(&ones);
    let differ = a != b && a.iter().any(|x| *x != 0);
    let (_, words, requests, why2) = arch_aarch64::virtio_rng::status();
    let counted = words >= 1024 && requests >= 128 && why2 == 0;
    let stuck_refused = MetalEntropy::new(Stuck).health_check().is_err();
    let pass = fa && fb && balanced && differ && counted && stuck_refused;
    kprint!(" [P-itest-rng] {} — QEMU integration-test profile: MetalEntropy<HwTrng> over virtio-rng health-checked=true; 2 x 4 KiB fills={} bit balance {} of 32768 in the 6-sigma window={}; fills differ and are not zero={}; device round trips {} / words {} (no fallback path)={}; a stuck source is refused by the same health check={}\n",
        if pass { "PASS" } else { "FAIL" }, fa && fb, ones, balanced, differ, requests, words, counted, stuck_refused);
    // the buffers held key-grade bytes: wipe them
    a.fill(0);
    b.fill(0);
    pass
}

// ===================================================================== the per-VM sealed volume ([P-itest-vol]) ===
//
// Operator requirement (2026-11-22): keep the heqk sealed-volume architecture; a UNIQUE per-VM VEK from the approved
// QEMU entropy source, protected SEPARATELY from the backing volume; never a CM5 OTP-derived key, never a key shared
// across VMs. Mapping onto the existing architecture:
//   * root secret = the per-VM KEK from fw_cfg (`opt/hookprobe/kek`, 32 bytes) — it never touches the disk, exactly as
//     the CM5's SRK never does;
//   * VEK = 32 bytes from virtio-rng (health-checked MetalEntropy), sealed (HQKSEAL1) under the KEK at keystore LBA
//     `VEK_LBA`; data records are sealed under the VEK (fslog `append_sealed`, unchanged);
//   * device identity seed = 32 bytes from virtio-rng, sealed under the VEK at keystore LBA `ID_LBA`;
//   * a VEK blob that does not unseal (wrong KEK, corruption) is REFUSED — never replaced by a fresh key;
//   * rotation: with `opt/hookprobe/kek-next` present, the VEK is resealed under the next KEK through a staging slot
//     (`STAGE_LBA`) first, so an interrupted rotation is recovered on the next boot (under either key).
use crate::fslog::{self, SealCtx, RT_TEST};
use crate::seal::Policy;
use crate::store::{RegionKind, SealedStore};
use hal::BlockDev;

/// Keystore-window LBAs (2016..2047) used by this profile, clear of the A/B snapshot slots (2025..2034) and 2040.
const STAGE_LBA: u64 = 2036;
const ID_LBA: u64 = 2037;
/// The data volume region and the two rings this test uses inside it.
const DV_LO: u64 = 8192;
const RING: (u64, u64) = (9000, 9032);
const SCRATCH: (u64, u64) = (9100, 9108);
const MARK: &[u8] = b"HQ-ITEST-PERSIST-MARKER";

fn policy() -> Policy {
    Policy { mask: boot_abi::SEAL_POLICY_DEVICE, device_id: 0x4954_4553_5456_4d31, svn_floor: 0, pcr: [[0u8; 32]; boot_abi::NUM_PCR] }
}

/// The per-VM device identity of this boot (set by `volume_selftest`), for the G19 tunnel.
static mut IDENTITY_SEED: Option<[u8; 32]> = None;
pub fn identity_keypair() -> Option<ed25519_compact::KeyPair> {
    unsafe { (*core::ptr::addr_of!(IDENTITY_SEED)).map(|s| ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(s))) }
}

fn fresh32() -> Option<[u8; 32]> {
    let mut k = [0u8; 32];
    let mut src = MetalEntropy::new(HwTrng::new());
    (src.health_check().is_ok() && src.fill(&mut k).is_ok()).then_some(k)
}

/// The disk must already carry its partition table: the virtio-blk driver never writes LBA 0 (gate 2), and this profile
/// does not weaken that. The S1 harness provisions it on the host (one 0xDA DataVolume partition from LBA 2048).
fn check_partitioned<D: BlockDev>(d: &mut D) -> Result<(), &'static str> {
    let mut mbr = [0u8; 512];
    d.read_block(0, &mut mbr).map_err(|_| "LBA 0 unreadable")?;
    if mbr[510] == 0x55 && mbr[511] == 0xAA {
        return Ok(());
    }
    Err("the data disk has no partition table (the kernel never writes LBA 0): provision it on the host — one type 0xDA partition from LBA 2048")
}

pub fn volume_selftest() -> bool {
    macro_rules! fail { ($($t:tt)*) => {{ kprint!(" [P-itest-vol] FAIL-CLOSED — "); kprint!($($t)*); kprint!("\n"); return false; }}; }
    let mut kek = [0u8; 32];
    match arch_aarch64::fwcfg::read_file(b"opt/hookprobe/kek", &mut kek) {
        Some(32) => {}
        Some(n) => fail!("fw_cfg opt/hookprobe/kek is {} bytes (32 required): no volume, no keys", n),
        None => fail!("no per-VM KEK (fw_cfg opt/hookprobe/kek absent): no volume, no keys"),
    }
    let mut next = [0u8; 32];
    let rotate = arch_aarch64::fwcfg::read_file(b"opt/hookprobe/kek-next", &mut next) == Some(32);
    let Some(mut dev) = arch_aarch64::virtio_blk::VirtioBlk::open() else { fail!("no virtio-blk data volume") };
    if let Err(e) = check_partitioned(&mut dev) {
        fail!("{}", e);
    }
    let cap = dev.block_count();
    let mut store = match SealedStore::open(&mut dev) {
        Ok(s) => s,
        Err(e) => fail!("the store guard refused the disk: {:?}", e),
    };
    if store.add_region(DV_LO, cap, RegionKind::DataVolume).is_err() {
        fail!("data volume region refused");
    }
    let pol = policy();
    // ---- the VEK: load (or recover an interrupted rotation), create only on a disk that has none ----
    let (vek, created, recovered) = if fslog::sealed_blob_at(&store, fslog::VEK_LBA) {
        match fslog::load_key_at(&store, fslog::VEK_LBA, &kek, &pol) {
            Some(v) => (v, false, false),
            None => match fslog::load_key_at(&store, STAGE_LBA, &kek, &pol) {
                // an interrupted rotation: the staging copy is under the KEK we were given — finish it
                Some(v) => {
                    if fslog::store_key_at(&mut store, fslog::VEK_LBA, &kek, &pol, &v).is_err() {
                        fail!("rotation recovery write failed");
                    }
                    (v, false, true)
                }
                None => fail!("the volume key does not unseal under this VM's KEK (wrong KEK or corrupted keystore): volume refused, nothing written, no key generated"),
            },
        }
    } else {
        let Some(v) = fresh32() else { fail!("no entropy for a new VEK (virtio-rng absent or failing)") };
        if fslog::store_key_at(&mut store, fslog::VEK_LBA, &kek, &pol, &v).is_err() {
            fail!("VEK write failed");
        }
        (v, true, false)
    };
    // ---- the identity seed, sealed under the VEK ----
    let seed = if fslog::sealed_blob_at(&store, ID_LBA) {
        match fslog::load_key_at(&store, ID_LBA, &vek, &pol) {
            Some(s) => s,
            None => fail!("the identity seed does not unseal under the volume key (corrupted): refused"),
        }
    } else {
        let Some(s) = fresh32() else { fail!("no entropy for the identity seed") };
        if fslog::store_key_at(&mut store, ID_LBA, &vek, &pol, &s).is_err() {
            fail!("identity seed write failed");
        }
        s
    };
    unsafe { IDENTITY_SEED = Some(seed) };
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
    let fp = boot_abi::sha256::digest(&kp.pk[..]);
    kprint!(" [ITEST] device identity pk=");
    for b in kp.pk.iter() {
        kprint!("{:02x}", b);
    }
    kprint!(" fp={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x} (per-VM, from virtio-rng, sealed under the per-VM VEK)\n", fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7]);
    let ctx = SealCtx { vek: &vek, policy: &pol };
    // ---- persistence: one sealed marker record per boot; every earlier boot's records must still verify ----
    let mut log = match fslog::open_or_format(&mut store, RING.0, RING.1) {
        Ok(l) => l,
        Err(e) => fail!("ring open failed: {:?}", e),
    };
    let mut prior = 0u32;
    let _ = log.for_each_sealed(&store, &ctx, |_, rt, p| {
        if rt == RT_TEST && p.starts_with(MARK) {
            prior += 1;
        }
    });
    let mut rec = [0u8; 32];
    rec[..MARK.len()].copy_from_slice(MARK);
    if log.append_sealed(&mut store, &ctx, RT_TEST, &rec).is_err() {
        fail!("sealed append failed");
    }
    // ---- at rest: no plaintext marker, key or seed anywhere in the keystore window or the ring ----
    let mut plain = false;
    let mut sec = [0u8; 512];
    for lba in (2016..2048).chain(RING.0..RING.1) {
        if store.read_sector(lba, &mut sec).is_ok() {
            plain |= sec.windows(MARK.len()).any(|w| w == MARK) || sec.windows(32).any(|w| w == vek || w == seed || w == kek);
        }
    }
    // ---- authenticated integrity: a ciphertext byte flipped on disk is rejected by the seal MAC ----
    let integrity = (|| -> bool {
        let Ok(mut s) = fslog::format(&mut store, SCRATCH.0, SCRATCH.1) else { return false };
        for i in 0..2u8 {
            if s.append_sealed(&mut store, &ctx, RT_TEST, &[b'I', i]).is_err() {
                return false;
            }
        }
        let lba = SCRATCH.0 + 1 + 1; // seq 1
        let mut b = [0u8; 512];
        if store.read_sector(lba, &mut b).is_err() {
            return false;
        }
        b[fslog::REC_HDR + crate::seal::SEAL_HDR_LEN] ^= 0xFF;
        {
            use boot_abi::sha256::Hasher;
            let len = u16::from_le_bytes([b[16], b[17]]) as usize;
            let mut h = Hasher::new();
            h.update(&b[0..24]);
            h.update(&b[fslog::REC_HDR..fslog::REC_HDR + len]);
            let d = h.finish();
            b[24..32].copy_from_slice(&d[..8]);
        }
        if store.store_sector(lba, &b).is_err() {
            return false;
        }
        let mut ok = 0;
        match fslog::LogStore::mount_sealed(&store, &ctx, SCRATCH.0, SCRATCH.1) {
            Ok(m) => {
                let _ = m.for_each_sealed(&store, &ctx, |_, _, _| ok += 1);
                ok == 1
            }
            Err(_) => false,
        }
    })();
    // ---- wrong key: the same keystore under a different KEK must not unseal (no write happens here) ----
    let mut other = kek;
    other[0] ^= 0x80;
    let wrong_refused = fslog::load_key_at(&store, fslog::VEK_LBA, &other, &pol).is_none();
    // ---- rotation (when kek-next is offered): staging first, then the live slot, then clear the staging copy ----
    let rotated = if rotate {
        let ok = fslog::store_key_at(&mut store, STAGE_LBA, &next, &pol, &vek).is_ok()
            && fslog::load_key_at(&store, STAGE_LBA, &next, &pol) == Some(vek)
            && fslog::store_key_at(&mut store, fslog::VEK_LBA, &next, &pol, &vek).is_ok()
            && store.store_sector(STAGE_LBA, &[0u8; 512]).is_ok()
            && fslog::load_key_at(&store, fslog::VEK_LBA, &next, &pol) == Some(vek)
            && fslog::load_key_at(&store, fslog::VEK_LBA, &kek, &pol).is_none();
        Some(ok)
    } else {
        None
    };
    let pass = !plain && integrity && wrong_refused && rotated != Some(false);
    kprint!(" [P-itest-vol] {} — per-VM sealed volume: disk {} | VEK {} (sealed under the fw_cfg KEK, never on disk in clear) | this boot's marker sealed; earlier boots' markers verified={} | at rest: no plaintext marker/VEK/seed/KEK on disk={} | flipped ciphertext rejected by the seal MAC={} | another KEK does not unseal the VEK={} | rotation {}\n",
        if pass { "PASS" } else { "FAIL" },
        if created { "new" } else { "existing" },
        if created { "created from virtio-rng" } else if recovered { "recovered from an interrupted rotation" } else { "loaded" },
        prior, !plain, integrity, wrong_refused,
        match rotated { Some(true) => "done (VEK resealed under kek-next; the old KEK no longer opens it)", Some(false) => "FAILED", None => "not requested" });
    pass
}

// ============================================================ the G19 tunnel to a real PoP ([P-itest-g19], S1 / E2) ===
//
// Build-time PoP (test profile only): HEQK_ITEST_POP=<ipv4> (+ HEQK_POP_PUB=<the PoP's 1216-byte public blob>, as for
// every G19 build). The guest's per-VM identity (sealed volume above) is the Noise static key; its ephemerals come from
// virtio-rng (MetalEntropy, fail closed). Once the PoP assigns an inner address, one ICMP echo to 1.1.1.1 goes INSIDE
// the tunnel and its reply must come back through it. This is the QEMU-to-real-PoP evidence; never a metal claim.

/// The PoP address of this build (`HEQK_ITEST_POP`), if any.
pub fn pop_addr() -> Option<[u8; 4]> {
    let s = option_env!("HEQK_ITEST_POP")?;
    let mut ip = [0u8; 4];
    let mut it = s.trim().split('.');
    for b in ip.iter_mut() {
        *b = it.next()?.parse().ok()?;
    }
    it.next().is_none().then_some(ip)
}

pub struct G19Probe {
    gw_mac: Option<[u8; 6]>,
    last_tick: i64,
    started: i64,
    echo_tries: u32,
    echo_at: i64,
    assigned_at: i64,
    done: bool,
}

const PROBE_ID: u16 = 0x4851; // "HQ"
const PROBE_DST: [u8; 4] = [1, 1, 1, 1];
const PROBE_DEADLINE_MS: i64 = 120_000;

impl G19Probe {
    /// Configure the tunnel (full mode) to the build-time PoP. None = no PoP in this build, or no identity / entropy.
    pub fn start(now_ms: i64) -> Option<G19Probe> {
        let pop = pop_addr()?;
        if identity_keypair().is_none() {
            kprint!(" [P-itest-g19] FAIL-CLOSED — no per-VM identity (the sealed volume did not open): no handshake\n");
            return None;
        }
        let t = hal::policy::Tunnel { pop, full: true, split: [([0u8; 4], 0u8); hal::policy::TUNNEL_SPLIT_MAX], nsplit: 0 };
        if !crate::g19::configure(Some(t)) {
            kprint!(" [P-itest-g19] FAIL — the tunnel did not configure\n");
            return None;
        }
        kprint!(" [ITEST] G19 tunnel configured: PoP {}.{}.{}.{} UDP 7654/7655, full mode; identity = the per-VM key above\n", pop[0], pop[1], pop[2], pop[3]);
        Some(G19Probe { gw_mac: None, last_tick: 0, started: now_ms, echo_tries: 0, echo_at: 0, assigned_at: 0, done: false })
    }

    /// Every received frame, before the node: learns the gateway MAC; consumes the PoP's datagrams. True = consumed.
    pub fn rx(&mut self, frame: &mut [u8], n: usize, now_ms: i64) -> bool {
        if n >= 34 && frame[12] == 0x08 && frame[13] == 0x00 && self.gw_mac.is_none() {
            // QEMU user-mode net: the DHCP server / gateway is 10.0.2.2; any IPv4 frame from it carries the gateway MAC
            if frame[26..30] == [10, 0, 2, 2] {
                let mut m = [0u8; 6];
                m.copy_from_slice(&frame[6..12]);
                self.gw_mac = Some(m);
            }
        }
        if !crate::g19::wan_wants(&frame[..n]) {
            return false;
        }
        if let Some(m) = crate::g19::wan_ingress(frame, n, now_ms) {
            // a DATA packet, rewritten as a WAN frame: is it our echo reply from 1.1.1.1?
            let ip = &frame[14..m];
            if !self.done && ip.len() >= 28 && ip[9] == 1 && ip[12..16] == PROBE_DST {
                let ihl = ((ip[0] & 0x0f) as usize) * 4;
                if ip.len() >= ihl + 8 && ip[ihl] == 0 && u16::from_be_bytes([ip[ihl + 4], ip[ihl + 5]]) == PROBE_ID {
                    self.done = true;
                    kprint!(" [P-itest-g19] PASS — S1/E2 QEMU-to-real-PoP: Noise IK handshake with the per-VM identity (virtio-rng ephemerals), ASSIGN {}.{}.{}.{}, ICMP echo to 1.1.1.1 INSIDE the tunnel answered in {} ms (attempt {}); QEMU evidence only — not metal\n",
                        crate::g19::assigned_inner().map_or(0, |a| a[0]), crate::g19::assigned_inner().map_or(0, |a| a[1]), crate::g19::assigned_inner().map_or(0, |a| a[2]), crate::g19::assigned_inner().map_or(0, |a| a[3]),
                        now_ms - self.echo_at, self.echo_tries);
                }
            }
        }
        true
    }

    /// Called each serve-loop pass: drives the handshake / rekey and the echo probe.
    pub fn tick(&mut self, now_ms: i64, leased: bool, ip: [u8; 4], mac: [u8; 6], tx: &mut dyn FnMut(&[u8]) -> bool) {
        if now_ms - self.last_tick < 200 {
            return;
        }
        self.last_tick = now_ms;
        let Some(gw) = self.gw_mac else { return };
        let mut fresh = || crate::securechannel::InitiatorRandomness::from_entropy(&mut MetalEntropy::new(HwTrng::new())).ok();
        crate::g19::tick(now_ms, leased, ip, mac, gw, &identity_keypair, &mut fresh, tx);
        if self.done {
            return;
        }
        if let Some(inner) = crate::g19::assigned_inner() {
            if self.assigned_at == 0 {
                self.assigned_at = now_ms;
                kprint!(" [ITEST] G19 ASSIGN {}.{}.{}.{} after {} ms\n", inner[0], inner[1], inner[2], inner[3], now_ms - self.started);
            }
            if self.echo_tries < 5 && (self.echo_tries == 0 || now_ms - self.echo_at >= 3000) {
                self.echo_tries += 1;
                self.echo_at = now_ms;
                let p = echo(inner, self.echo_tries as u16);
                if !crate::g19::send_inner(&p, now_ms, tx) {
                    kprint!(" [ITEST] G19 echo {} not sent\n", self.echo_tries);
                }
            }
        }
        if now_ms - self.started > PROBE_DEADLINE_MS {
            self.done = true;
            kprint!(" [P-itest-g19] FAIL — no echo reply through the tunnel within {} s (gateway MAC learned={}, ASSIGN={}, echo attempts {})\n",
                PROBE_DEADLINE_MS / 1000, self.gw_mac.is_some(), crate::g19::assigned_inner().is_some(), self.echo_tries);
        }
    }
}

/// An IPv4 ICMP echo request from `src` to 1.1.1.1 (id PROBE_ID, sequence `seq`), checksums filled.
fn echo(src: [u8; 4], seq: u16) -> [u8; 40] {
    let mut p = [0u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[8] = 64;
    p[9] = 1;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&PROBE_DST);
    let ip_ck = cksum(&p[..20]);
    p[10..12].copy_from_slice(&ip_ck.to_be_bytes());
    p[20] = 8;
    p[24..26].copy_from_slice(&PROBE_ID.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    p[28..40].copy_from_slice(b"HQ-ITEST-G19");
    let ic = cksum(&p[20..40]);
    p[22..24].copy_from_slice(&ic.to_be_bytes());
    p
}

fn cksum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        s += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}
