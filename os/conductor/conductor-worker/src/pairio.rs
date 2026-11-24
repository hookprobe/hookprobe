// SPDX-License-Identifier: AGPL-3.0-only
//! Pairing over the wire (before any trust exists, so plain TCP: the six digits authenticate it).
//!
//! W1 worker → device: result_pk[32] ‖ channel_blob[1216] ‖ commit[32]
//! D1 device → worker: delegation_pk[32] ‖ channel_identity_pk[32] ‖ device_nonce[16] ‖ tier u8
//! W2 worker → device: worker_nonce[16]
//! Both: code = sas(device_keys_digest, worker_keys_digest, device_nonce, worker_nonce).
//!
//! The worker commits to its nonce before seeing the device's, so a man in the middle gets one guess in a
//! million per attempt. The code covers both keys on both sides. The owner compares the code on the worker
//! with the one in Mission Control; only then does the worker save the pairing and the device's owner sign
//! the pairing record.

use crate::files::{Keys, Paired};
use conductor_core::pairing::{check_commit, commit, device_keys_digest, sas, worker_keys_digest};
use std::io::{Read, Write};
use std::net::TcpStream;

pub const CHANNEL_BLOB_LEN: usize = 32 + 1184;
const W1_LEN: usize = 32 + CHANNEL_BLOB_LEN + 32;
const D1_LEN: usize = 32 + 32 + 16 + 1;

pub struct WorkerSide {
    pub paired: Paired,
    pub code: u32,
}

/// Worker side. `confirm(code)` returns true once the owner has checked the code (interactive prompt, or a
/// code typed from Mission Control). Nothing is saved here; the caller saves `paired` after confirmation.
pub fn worker_pair(s: &mut TcpStream, keys: &Keys, nonce: [u8; 16], confirm: &mut dyn FnMut(u32) -> bool) -> Result<WorkerSide, String> {
    let blob = keys.channel_blob();
    if blob.len() != CHANNEL_BLOB_LEN {
        return Err("unexpected channel key size".into());
    }
    let wd = worker_keys_digest(&keys.result_pk(), &blob);
    let mut w1 = keys.result_pk().to_vec();
    w1.extend_from_slice(&blob);
    w1.extend_from_slice(&commit(&wd, &nonce));
    s.write_all(&w1).map_err(|e| e.to_string())?;
    let mut d1 = [0u8; D1_LEN];
    s.read_exact(&mut d1).map_err(|e| e.to_string())?;
    let mut dpk = [0u8; 32];
    let mut ipk = [0u8; 32];
    let mut dn = [0u8; 16];
    dpk.copy_from_slice(&d1[..32]);
    ipk.copy_from_slice(&d1[32..64]);
    dn.copy_from_slice(&d1[64..80]);
    let tier = d1[80];
    s.write_all(&nonce).map_err(|e| e.to_string())?;
    let code = sas(&device_keys_digest(&dpk, &ipk), &wd, &dn, &nonce);
    if !confirm(code) {
        return Err("pairing code not confirmed: nothing saved".into());
    }
    Ok(WorkerSide { paired: Paired { delegation_pk: dpk, channel_identity_pk: ipk, tier }, code })
}

pub struct DeviceSide {
    pub worker_result_pk: [u8; 32],
    pub worker_channel_blob: Vec<u8>,
    pub code: u32,
}

/// Device side (what Mission Control's pairing flow does; used by tests and the device simulator).
pub fn device_pair(s: &mut TcpStream, delegation_pk: &[u8; 32], identity_pk: &[u8; 32], tier: u8, nonce: [u8; 16]) -> Result<DeviceSide, String> {
    let mut w1 = vec![0u8; W1_LEN];
    s.read_exact(&mut w1).map_err(|e| e.to_string())?;
    let mut rpk = [0u8; 32];
    rpk.copy_from_slice(&w1[..32]);
    let blob = w1[32..32 + CHANNEL_BLOB_LEN].to_vec();
    let mut c = [0u8; 32];
    c.copy_from_slice(&w1[32 + CHANNEL_BLOB_LEN..]);
    let mut d1 = delegation_pk.to_vec();
    d1.extend_from_slice(identity_pk);
    d1.extend_from_slice(&nonce);
    d1.push(tier);
    s.write_all(&d1).map_err(|e| e.to_string())?;
    let mut wn = [0u8; 16];
    s.read_exact(&mut wn).map_err(|e| e.to_string())?;
    let wd = worker_keys_digest(&rpk, &blob);
    if !check_commit(&c, &wd, &wn) {
        return Err("worker nonce does not match its commitment: possible man in the middle".into());
    }
    let code = sas(&device_keys_digest(delegation_pk, identity_pk), &wd, &nonce, &wn);
    Ok(DeviceSide { worker_result_pk: rpk, worker_channel_blob: blob, code })
}
