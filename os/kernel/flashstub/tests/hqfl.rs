// SPDX-License-Identifier: AGPL-3.0-only
//! The HQFL server against the browser client's behaviour — the Rust mirror of
//! tools/flash/web/test/stub.test.mjs, with the REAL verifier (boot_abi::verify, real hybrid-signed fixtures) and a
//! factory-layout FAT disk, so the slot check runs the real hal::abslot walk.
mod common;
use common::*;
use flashstub::image::{self, HbootRef, IMG_MAX, OFF};
use flashstub::proto::{s, t, MAX_CHUNK, SECTOR};
use flashstub::server::{Server, State};

const CHUNK: usize = MAX_CHUNK;

fn session<'a>(img: &'a mut Vec<u8>, href: &'a dyn HbootRef, floor: u64, sectors: u64) -> Client<Direct<'a>> {
    let srv = Server::new(config(floor, false), href, img);
    Client::new(Direct { srv, m: RamMedium::with_old(sectors) })
}

fn buf() -> Vec<u8> {
    vec![0u8; IMG_MAX]
}

#[test]
fn full_exchange_verify_write_readback_slots_mbr_last() {
    let (slot, disk) = good_disk();
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, disk.bytes.len() as u64 / 512 + 100);
    let info = c.hello();
    assert_eq!((info.ty, info.status), (t::INFO, s::OK));
    assert_eq!(info_sectors(&info), disk.bytes.len() as u64 / 512 + 100);
    assert_eq!((info_floor(&info), info_max_chunk(&info) as usize, info_release(&info)), (1, MAX_CHUNK, false));
    assert_eq!((info.payload[26], info.payload[27]), (1, 2), "eMMC wear A/B reported");
    let (svn, ph) = c.verify(&slot, CHUNK).expect("verdict");
    assert_eq!(svn, 5);
    assert_eq!(ph, digest(&CANDIDATE[7992..]), "the verdict carries the recomputed payload hash");
    assert_eq!(c.link.m.writes, 0, "nothing written before WBEGIN");
    let (dg, resumes) = c.write(&disk.bytes, CHUNK, 4).expect("write");
    assert_eq!(resumes, 0);
    assert!(c.link.m.lba0_is_zero(), "LBA 0 stays zero until FINISH has proved everything");
    let r = c.finish(&dg);
    assert_eq!((r.ty, r.status), (t::RESULT, s::OK));
    assert_eq!(&r.payload[..32], &dg, "read-back hash == what was sent");
    assert_eq!(r.payload[32], 3, "both slots hold a verifying image");
    let m = &c.link.m;
    assert_eq!(&m.data[..disk.bytes.len()], &disk.bytes[..], "the medium holds the image byte for byte");
    assert_eq!(m.order.first(), Some(&0), "the first write zeroes LBA 0");
    assert_eq!(m.order.last(), Some(&0), "the MBR is the last sector written");
    assert_eq!(m.order.iter().filter(|&&l| l == 0).count(), 2);
    assert!(!m.admitted, "the whole-medium window is closed after FINISH");
    assert_eq!(m.admits, 1);
    assert_eq!(c.link.srv.state(), State::Done);
}

#[test]
fn bad_signature_is_refused_and_nothing_is_written() {
    let (mut slot, disk) = good_disk();
    slot[OFF + 7992 + 100] ^= 1; // one payload byte
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    assert_eq!(c.verify(&slot, CHUNK), Err(ClientErr::Refused(s::SIG_FAIL)));
    // a host that ignores the refusal still gets nothing written
    let r = c.call(t::WBEGIN, &(disk.bytes.len() as u64).to_le_bytes());
    assert_eq!(r.status, s::NOT_VERIFIED);
    let mut p = 0u64.to_le_bytes().to_vec();
    p.extend_from_slice(&[0; 8]);
    p.extend_from_slice(&[0; 512]);
    assert_eq!(c.call(t::WRITE, &p).status, s::NOT_VERIFIED);
    let m = &c.link.m;
    assert_eq!((m.writes, m.admits, m.refused), (0, 0, 0), "no write, no admission, not even an attempt");
    assert!(!m.lba0_is_zero(), "the old install is untouched");
    // the refusal is final for the session
    assert_eq!(c.call(t::VBEGIN, &(slot.len() as u32).to_le_bytes()).status, s::BAD_STATE);
    c.hello();
    assert_eq!(c.call(t::VBEGIN, &(slot.len() as u32).to_le_bytes()).status, s::BAD_STATE, "HELLO does not lift a refusal");
}

#[test]
fn a_flipped_signature_byte_is_refused() {
    let (mut slot, _) = good_disk();
    slot[OFF + 72 + 10] ^= 0x40; // inside the Ed25519 signature
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    assert_eq!(c.verify(&slot, CHUNK), Err(ClientErr::Refused(s::SIG_FAIL)));
    let mut slot = good_slot();
    slot[OFF + 72 + 64 + 100] ^= 0x40; // inside the SLH-DSA signature
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    assert_eq!(c.verify(&slot, CHUNK), Err(ClientErr::Refused(s::SIG_FAIL)));
}

#[test]
fn svn_below_the_floor_is_refused_nothing_written() {
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 6, 20000); // candidate is svn 5
    assert_eq!(info_floor(&c.hello()), 6);
    assert_eq!(c.verify(&good_slot(), CHUNK), Err(ClientErr::Refused(s::ROLLBACK)));
    assert_eq!((c.link.m.writes, c.link.m.admits), (0, 0));
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 3, 20000);
    c.hello();
    assert_eq!(c.verify(&big_slot(), CHUNK), Err(ClientErr::Refused(s::ROLLBACK)), "svn 2 < floor 3");
}

#[test]
fn a_different_hboot_prefix_is_refused() {
    let mut other = hboot_bin();
    other[1000] ^= 0x10;
    let slot = slot_image(&other, CANDIDATE);
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    assert_eq!(c.verify(&slot, CHUNK), Err(ClientErr::Refused(s::BAD_HEADER)));
    assert_eq!(c.link.m.writes, 0);
    // without HBoot's self-measurement the stub refuses everything (fail-closed)
    let none = image::MeasuredHboot { digest: None };
    let mut b = buf();
    let mut c = session(&mut b, &none, 1, 20000);
    c.hello();
    assert_eq!(c.verify(&good_slot(), CHUNK), Err(ClientErr::Refused(s::BAD_HEADER)));
}

#[test]
fn hboot_prefix_match_is_exact() {
    let h = hboot_ref();
    let good = good_slot();
    assert!(h.matches(&good[..OFF]), "hboot.bin ending in zero bytes is found");
    let mut p = good[..OFF].to_vec();
    p[OFF - 1] = 1; // a non-zero byte in the padding
    assert!(!h.matches(&p));
    let mut p = good[..OFF].to_vec();
    p[0] ^= 1;
    assert!(!h.matches(&p));
    assert!(!h.matches(&good[..OFF - 1]));
    assert!(image::HbootBytes(&hboot_bin()).matches(&good[..OFF]));
}

#[test]
fn write_without_a_verdict_gets_not_verified() {
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    assert_eq!(c.call(t::WBEGIN, &(1024u64).to_le_bytes()).status, s::NOT_VERIFIED);
    let mut p = vec![0u8; 16];
    p.extend_from_slice(&[0; 512]);
    assert_eq!(c.call(t::WRITE, &p).status, s::NOT_VERIFIED);
    assert_eq!(c.call(t::FINISH, &[0; 32]).status, s::BAD_STATE);
    assert_eq!((c.link.m.writes, c.link.m.admits), (0, 0));
}

#[test]
fn short_write_and_crc_flip_resume_from_next_image_exact() {
    let (slot, disk) = good_disk();
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, disk.bytes.len() as u64 / 512);
    c.faults.short_on = vec![2, 5];
    c.faults.crc_flip_on = vec![7];
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    let (dg, resumes) = c.write(&disk.bytes, CHUNK, 4).unwrap();
    assert_eq!((resumes, c.short_writes), (3, 2));
    let r = c.finish(&dg);
    assert_eq!((r.status, r.payload[32]), (s::OK, 3));
    assert_eq!(&c.link.m.data[..], &disk.bytes[..]);
}

#[test]
fn persistent_io_error_reports_where_the_stub_stands_and_lba0_stays_zero() {
    let (slot, disk) = good_disk();
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.link.m.io_fail_lba = Some((3 * MAX_CHUNK + 512) as u64 / 512);
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    assert_eq!(c.write(&disk.bytes, CHUNK, 4), Err(ClientErr::Failed { status: s::IO, next: 3 * MAX_CHUNK as i64 }));
    assert!(c.link.m.lba0_is_zero(), "a half-written board has no MBR");
    assert_eq!(c.call(t::ABORT, &[]).status, s::OK);
    assert!(!c.link.m.admitted, "ABORT closes the window");
    assert!(c.link.m.lba0_is_zero());
    assert_eq!(c.call(t::WBEGIN, &(disk.bytes.len() as u64).to_le_bytes()).status, s::NOT_VERIFIED, "the verdict is gone");
}

#[test]
fn readback_mismatch_fails_finish_and_lba0_is_cleared() {
    let (slot, disk) = good_disk();
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    let (dg, _) = c.write(&disk.bytes, CHUNK, 4).unwrap();
    c.link.m.data[SECTOR * 10] ^= 0xff; // bit rot after the write
    let r = c.finish(&dg);
    assert_eq!((r.ty, r.status), (t::RESULT, s::READBACK_MISMATCH));
    assert_ne!(&r.payload[..32], &dg);
    assert!(c.link.m.lba0_is_zero(), "never leave a bootable half-image");
    assert!(!c.link.m.admitted);
}

#[test]
fn host_digest_that_differs_from_what_arrived_fails_finish() {
    let (slot, disk) = good_disk();
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    let (mut dg, _) = c.write(&disk.bytes, CHUNK, 4).unwrap();
    dg[0] ^= 1;
    assert_eq!(c.finish(&dg).status, s::READBACK_MISMATCH);
    assert!(c.link.m.lba0_is_zero());
}

#[test]
fn a_slot_that_does_not_verify_fails_the_slot_check() {
    let slot = good_slot();
    let mut bad = slot.clone();
    bad[OFF + 7992 + 5] ^= 1;
    let disk = factory_disk(&slot, &bad, "kernel=heqk8-a.img\n");
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    let (dg, _) = c.write(&disk.bytes, CHUNK, 4).unwrap();
    let r = c.finish(&dg);
    assert_eq!((r.status, r.payload[32]), (s::SLOT_MISMATCH, 1), "A verifies, B does not");
    assert_eq!(&r.payload[..32], &dg, "the read-back itself matched");
    assert!(c.link.m.lba0_is_zero());
}

#[test]
fn another_validly_signed_slot_passes_the_slot_check() {
    let slot = good_slot();
    let disk = factory_disk(&slot, &big_slot(), "kernel=heqk8-a.img\n");
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, disk.bytes.len() as u64 / 512);
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    let (dg, _) = c.write(&disk.bytes, CHUNK, 4).unwrap();
    let r = c.finish(&dg);
    assert_eq!((r.status, r.payload[32]), (s::OK, 3));
    assert!(!c.link.m.lba0_is_zero());
}

#[test]
fn not_the_factory_layout_fails_the_slot_check() {
    let slot = good_slot();
    let disk = factory_disk(&slot, &slot, "kernel=heqk8.img\n"); // no A/B line
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    let (dg, _) = c.write(&disk.bytes, CHUNK, 4).unwrap();
    assert_eq!(c.finish(&dg).status, s::SLOT_MISMATCH);
    assert!(c.link.m.lba0_is_zero());
}

#[test]
fn image_larger_than_the_emmc_or_misaligned_is_refused_at_wbegin() {
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 16);
    c.hello();
    c.verify(&good_slot(), CHUNK).unwrap();
    assert_eq!(c.call(t::WBEGIN, &(32u64 * 512).to_le_bytes()).status, s::RANGE);
    assert_eq!(c.call(t::WBEGIN, &(1000u64).to_le_bytes()).status, s::RANGE);
    assert_eq!(c.call(t::WBEGIN, &0u64.to_le_bytes()).status, s::RANGE);
    assert_eq!(c.link.m.admits, 0);
}

#[test]
fn out_of_order_and_oversized_writes_are_refused_with_next() {
    let (slot, _) = good_disk();
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    assert_eq!(c.call(t::WBEGIN, &(4096u64).to_le_bytes()).status, s::OK);
    let mk = |off: u64, d: &[u8]| {
        let mut p = off.to_le_bytes().to_vec();
        p.extend_from_slice(&flashstub::proto::crc32(d).to_le_bytes());
        p.extend_from_slice(&[0; 4]);
        p.extend_from_slice(d);
        p
    };
    let r = c.call(t::WRITE, &mk(512, &[1; 512]));
    assert_eq!((r.ty, r.status, flashstub::proto::le64(&r.payload, 0)), (t::ERROR, s::BAD_OFFSET, 0));
    assert_eq!(c.call(t::WRITE, &mk(0, &[1; 8192])).status, s::RANGE, "past WBEGIN's length");
    assert_eq!(c.call(t::WRITE, &mk(0, &[1; 100])).status, s::RANGE, "not whole sectors");
    assert_eq!(c.link.m.writes, 0);
}

#[test]
fn bus_reset_mid_write_leaves_lba0_zero_and_closes_the_window() {
    let (slot, disk) = good_disk();
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    c.hello();
    c.verify(&slot, CHUNK).unwrap();
    c.call(t::WBEGIN, &(disk.bytes.len() as u64).to_le_bytes());
    let d = &disk.bytes[..MAX_CHUNK];
    let mut p = 0u64.to_le_bytes().to_vec();
    p.extend_from_slice(&flashstub::proto::crc32(d).to_le_bytes());
    p.extend_from_slice(&[0; 4]);
    p.extend_from_slice(d);
    assert_eq!(c.call(t::WRITE, &p).status, s::OK);
    let Direct { srv, m } = &mut c.link;
    srv.on_bus_reset(m);
    assert_eq!(srv.state(), State::Init);
    assert!(m.lba0_is_zero() && !m.admitted);
    assert_eq!(c.call(t::WBEGIN, &(4096u64).to_le_bytes()).status, s::NOT_VERIFIED);
}

#[test]
fn a_refusal_is_lifted_only_by_a_new_session() {
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 6, 20000);
    c.hello();
    assert!(c.verify(&good_slot(), CHUNK).is_err());
    let Direct { srv, m } = &mut c.link;
    srv.on_bus_reset(m);
    c.hello();
    assert_eq!(c.call(t::VBEGIN, &(100u32).to_le_bytes()).status, s::OK, "a new session may verify again");
}

#[test]
fn malformed_frames() {
    let (mut b, h) = (buf(), hboot_ref());
    let mut c = session(&mut b, &h, 1, 20000);
    let r = c.link.call(b"HQFL\x01\x01\x00\x00\x09\x00\x00\x00\x08\x00\x00\x00abc");
    let f = flashstub::proto::decode(&r).unwrap();
    assert_eq!((f.ty, f.status, f.seq), (t::ERROR, s::BAD_FRAME, 9));
    assert_eq!(c.call(t::HELLO, &2u32.to_le_bytes()).status, s::BAD_VERSION);
    assert_eq!(c.call(0x55, &[]).status, s::BAD_FRAME);
    c.hello();
    assert_eq!(c.call(t::VBEGIN, &((IMG_MAX + 1) as u32).to_le_bytes()).status, s::TOO_BIG);
    assert_eq!(c.call(t::VBEGIN, &0u32.to_le_bytes()).status, s::TOO_BIG);
    assert_eq!(c.call(t::VEND, &[]).status, s::BAD_STATE);
    // a slot image that is too short for a header is refused at VEND
    assert_eq!(c.call(t::VBEGIN, &8u32.to_le_bytes()).status, s::OK);
    let mut p = vec![0u8; 8];
    p.extend_from_slice(&[7; 8]);
    assert_eq!(c.call(t::VDATA, &p).status, s::OK);
    assert_eq!(c.call(t::VEND, &[]).status, s::BAD_HEADER);
}

#[test]
fn the_compiled_trust_root_today_is_the_development_key_so_the_stub_reports_debug() {
    // boot-abi's TRUSTED_* keys are the dev keys listed in os/build/heqk-dev-key-fingerprints.txt (the fixtures
    // above are signed with them). When release keys replace them this flips to true — and these fixtures stop
    // verifying, which is the intended signal to re-sign them.
    assert!(!flashstub::release::trust_root_is_release());
}
