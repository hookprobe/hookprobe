// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0065 step 4g (S1): the ABI of `el0-wpa`, the resident EL0 WPA security server.
//!
//! Window: the image, its stack, one control page (the SAME layout as el0-wifi's, `crate::wifisrvabi::H_*` /
//! `IN_OFF` / `OUT_OFF`), the PERSISTENT state pages (a normal restart after a fault keeps them; only a full wipe
//! zeroes them — operator decision 2026-11-15: a bus fault must never erase the PMKSA cache, a security-server fault
//! wipes secrets only when its state cannot be trusted), then the key-transfer page (RW here, read-only in el0-wifi:
//! the only path a key takes to the chip, design docs/design/wifi-el0-split.md §3).

pub const BASE_QEMU: usize = 0xBD00_0000;
/// After el0-wifi (ends 0x1_4039_C000), inside the CM5 GB5 user window (ends 0x1_4040_0000).
pub const BASE_CM5: usize = 0x1_403A_0000;
pub const IMAGE_MAX: usize = 0x2_0000; // 128 KiB
pub const STACK_OFF: usize = 0x2_0000;
pub const STACK_SIZE: usize = 0x1_0000; // 64 KiB: the SAE curve arithmetic moves here in S2
pub const CTRL_OFF: usize = 0x3_0000;
/// Persistent state: survives a restart after a fault, zeroed by a full wipe.
pub const STATE_OFF: usize = 0x3_1000;
pub const STATE_PAGES: usize = 8;
pub const STATE_SIZE: usize = STATE_PAGES * 0x1000;
/// The key-transfer page (RW in el0-wpa, RO in el0-wifi at `crate::wifisrvabi::KEYX_OFF`).
pub const KEYX_OFF: usize = STATE_OFF + STATE_SIZE;
pub const WINDOW_END: usize = KEYX_OFF + 0x1000;
const _: () = assert!(BASE_CM5 + WINDOW_END <= 0x1_4040_0000);
const _: () = assert!(crate::wifisrvabi::BASE_CM5 + crate::wifisrvabi::WINDOW_END <= BASE_CM5);
const _: () = assert!(crate::wifisrvabi::BASE_QEMU + crate::wifisrvabi::WINDOW_END <= BASE_QEMU);

pub const MAGIC: u32 = u32::from_le_bytes(*b"HQWP");

pub const CMD_INIT: u32 = 1;
/// S1 substrate test: add 1 to a counter in the persistent state. R0 = the new value.
pub const CMD_STATE_BUMP: u32 = 40;
/// S1 substrate test: R0 = the counter.
pub const CMD_STATE_READ: u32 = 41;
/// S1 substrate test: IN bytes copied to the key-transfer page (S3 puts a key record there).
pub const CMD_KEYX_PUT: u32 = 42;
/// Test only: fault on purpose.
pub const CMD_SELFTEST_FAULT: u32 = 99;

// ---- S2: the security server's commands are the keying / SAE / PMKSA commands el0-wifi served
// (`crate::wifisrvabi::CMD_KEY_*`, `CMD_SAE_*`, `CMD_PMKSA_REMOVE`, the `keymsg` / `saemsg` encodings), plus: ----
/// R0 = PMKSA cache entries (`/api/health` wifi_driver.security.pmksa_entries).
pub const CMD_PMKSA_COUNT: u32 = 44;
/// Test only: IN = a station MAC [‖ a command u32 LE] — the next command about that station (that command only, when
/// given: S4 faults station B's M2 with `CMD_KEY_EAPOL`) faults (per-station containment proof).
pub const CMD_SELFTEST_ARM_FAULT: u32 = 45;
/// S3b: new group keys. IN = 32 B of TRNG entropy (the kernel's; design D-c) ‖ flags (bit0 = an IGTK too, PMF). The
/// server mixes the entropy into its pool and derives its GTK / IGTK from the pool (S3d: never the entropy bytes
/// themselves), keeps them, and writes the install records to key-transfer slots 1 (GTK), 2 (IGTK, BIP) and 3 (IGTK,
/// AES-CCM: the firmware's fallback). R0 = 1.
pub const CMD_GROUP_NEW: u32 = 46;
/// The persistent state failed its check after a restart: the kernel must full-wipe (every station re-authenticates).
pub const ST_STATE_BAD: u32 = 3;
/// D-c: the DRBG is unseeded (never seeded, or full-wiped) or past its reseed interval: nothing was generated and
/// nothing changed — the kernel seeds it (`CMD_DRBG_SEED`) and retries the call once; a TRNG failure fails closed.
pub const ST_NEED_SEED: u32 = 4;
/// D-c (operator 2026-11-16): IN = `DRBG_SEED_LEN` bytes of fresh kernel TRNG entropy. Instantiates el0-wpa's
/// HMAC-DRBG (`hal::drbg`) when unseeded, reseeds it otherwise. R0 = 1 (seeded) / 0 (refused: too little entropy).
pub const CMD_DRBG_SEED: u32 = 47;
pub const DRBG_SEED_LEN: usize = 48;

// ---- S3: the key-transfer page records (written by el0-wpa, read by el0-wifi, zeroed by the kernel) ----
/// Bus server (el0-wifi) command: install the key in key-transfer slot `slot` as a WLC_SET_KEY control request.
/// IN = [`keyx::encode_install`]; R0 = 1 written / 4 the write failed / 5 the record is absent or does not match
/// what the kernel asked to install (station, key index) — refused, nothing sent.
pub const CMD_KEY_INSTALL: u32 = 35;

pub mod keyx {
    /// Up to 4 records (the pairwise TK in slot 0; S3b: the GTK and the IGTK in slots 1 and 2).
    pub const SLOTS: usize = 4;
    pub const SLOT_SIZE: usize = 64;
    pub const MAGIC: u32 = u32::from_le_bytes(*b"HQKX");
    pub const SLOT_TK: u8 = 0;
    pub const SLOT_GTK: u8 = 1;
    pub const SLOT_IGTK: u8 = 2;
    /// The IGTK again with AES-CCM (the firmware refuses BIP on some builds; brcmfmac falls back the same way).
    pub const SLOT_IGTK_CCM: u8 = 3;

    /// One key on its way to the chip.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Rec {
        pub index: u32,
        pub algo: u32,
        pub flags: u32,
        pub ea: [u8; 6],
        pub klen: u8,
        pub key: [u8; 32],
    }
    /// magic u32 @0, index @4, algo @8, flags @12, ea @16, klen @22, key @24..56.
    pub fn encode(r: &Rec, o: &mut [u8; SLOT_SIZE]) {
        o.fill(0);
        o[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        o[4..8].copy_from_slice(&r.index.to_le_bytes());
        o[8..12].copy_from_slice(&r.algo.to_le_bytes());
        o[12..16].copy_from_slice(&r.flags.to_le_bytes());
        o[16..22].copy_from_slice(&r.ea);
        o[22] = r.klen.min(32);
        o[24..56].copy_from_slice(&r.key);
    }
    pub fn decode(b: &[u8]) -> Option<Rec> {
        let b = b.get(..SLOT_SIZE)?;
        let u = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        if u(0) != MAGIC || b[22] > 32 {
            return None;
        }
        let mut ea = [0u8; 6];
        ea.copy_from_slice(&b[16..22]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&b[24..56]);
        Some(Rec { index: u(4), algo: u(8), flags: u(12), ea, klen: b[22], key })
    }
    /// The install request the kernel sends the bus server: SDPCM seq, interface, BCDC request id, slot, and the
    /// station + key index it expects in that slot.
    pub const INSTALL_LEN: usize = 14;
    pub fn encode_install(seq: u8, ifidx: u8, reqid: u16, slot: u8, ea: &[u8; 6], index: u32) -> [u8; INSTALL_LEN] {
        let mut o = [0u8; INSTALL_LEN];
        o[0] = seq;
        o[1] = ifidx;
        o[2..4].copy_from_slice(&reqid.to_le_bytes());
        o[4] = slot;
        o[5] = 0;
        o[6..12].copy_from_slice(ea);
        o[12..14].copy_from_slice(&(index as u16).to_le_bytes());
        o
    }
    /// -> (seq, interface, request id, slot, station, key index).
    #[allow(clippy::type_complexity)]
    pub fn decode_install(b: &[u8]) -> Option<(u8, u8, u16, u8, [u8; 6], u32)> {
        if b.len() != INSTALL_LEN || b[4] as usize >= SLOTS {
            return None;
        }
        let mut ea = [0u8; 6];
        ea.copy_from_slice(&b[6..12]);
        Some((b[0], b[1], u16::from_le_bytes([b[2], b[3]]), b[4], ea, u16::from_le_bytes([b[12], b[13]]) as u32))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn records_and_requests() {
            let r = Rec { index: 0, algo: 4, flags: 0, ea: [2, 0x5a, 0, 0, 0, 9], klen: 16, key: [0x3c; 32] };
            let mut o = [0u8; SLOT_SIZE];
            encode(&r, &mut o);
            assert_eq!(decode(&o), Some(r));
            assert_eq!(decode(&[0u8; SLOT_SIZE]), None, "an empty (zeroed) slot is no record");
            let mut bad = o;
            bad[22] = 33;
            assert_eq!(decode(&bad), None);
            let i = encode_install(7, 0, 0x1234, SLOT_TK, &r.ea, 0);
            assert_eq!(decode_install(&i), Some((7, 0, 0x1234, 0, r.ea, 0)));
            let mut j = i;
            j[4] = 9;
            assert_eq!(decode_install(&j), None);
            assert_eq!(decode_install(&i[..13]), None);
        }
    }
}
