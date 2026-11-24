// SPDX-License-Identifier: AGPL-3.0-only
//! Keys, the pairing record and the replay state, on disk. Every secret file is created 0600 and refused
//! when group/other can read it (the superpop rule). State is written atomically and fsynced BEFORE the
//! worker executes the capability that advanced it (ADR 0069: a crash can never roll the mark back).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::entropy::{EntropySource, OsEntropy};
use crate::securechannel::{ResponderPub, ResponderStatic};

pub fn read_secret(path: &Path, len: usize) -> Result<Vec<u8>, String> {
    let meta = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!("{}: refusing a key file readable by group/other (chmod 600)", path.display()));
    }
    let mut b = Vec::new();
    File::open(path).and_then(|mut f| f.read_to_end(&mut b)).map_err(|e| format!("{}: {e}", path.display()))?;
    if b.len() != len {
        return Err(format!("{}: expected {len} bytes, found {}", path.display(), b.len()));
    }
    Ok(b)
}

fn write_new_secret(path: &Path, b: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e} (refusing to overwrite an existing key)", path.display()))?;
    f.write_all(b).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", path.display()))
}

/// The worker's two keys: the result-signing Ed25519 seed and the Noise responder static seeds.
pub struct Keys {
    pub result_seed: [u8; 32],
    pub noise: ResponderStatic,
}

impl Keys {
    pub const RESULT_FILE: &'static str = "result.key";
    pub const NOISE_FILE: &'static str = "channel.key";

    pub fn generate(dir: &Path) -> Result<(), String> {
        let mut e = OsEntropy;
        let r = e.fill_32().map_err(|_| "no entropy")?;
        let mut n = [0u8; 96];
        e.fill(&mut n).map_err(|_| "no entropy")?;
        write_new_secret(&dir.join(Self::RESULT_FILE), &r)?;
        write_new_secret(&dir.join(Self::NOISE_FILE), &n)
    }

    pub fn load(dir: &Path) -> Result<Self, String> {
        let r = read_secret(&dir.join(Self::RESULT_FILE), 32)?;
        let n = read_secret(&dir.join(Self::NOISE_FILE), 96)?;
        let mut result_seed = [0u8; 32];
        result_seed.copy_from_slice(&r);
        let (mut x, mut d, mut z) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        x.copy_from_slice(&n[..32]);
        d.copy_from_slice(&n[32..64]);
        z.copy_from_slice(&n[64..]);
        Ok(Self { result_seed, noise: ResponderStatic::from_seeds(&x, &d, &z) })
    }

    pub fn result_pk(&self) -> [u8; 32] {
        conductor_core::crypto::public_key(&self.result_seed)
    }

    /// The channel static public blob the device pins: X25519 pk ‖ ML-KEM-768 encapsulation key.
    pub fn channel_blob(&self) -> Vec<u8> {
        let p = self.noise.public();
        let mut b = p.x_pk().to_vec();
        b.extend_from_slice(p.k_ek_bytes());
        b
    }

    pub fn channel_pub(&self) -> ResponderPub {
        self.noise.public()
    }
}

/// What the owner paired this worker to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Paired {
    /// The device's Conductor delegation key: verifies HP-EXEC capabilities and epoch announcements.
    pub delegation_pk: [u8; 32],
    /// The device's channel identity: authenticates the Noise handshake.
    pub channel_identity_pk: [u8; 32],
    /// The tier this worker serves for that device.
    pub tier: u8,
}

pub const PAIRED_FILE: &str = "paired";

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl Paired {
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let text = format!(
            "delegation_pk={}\nchannel_identity_pk={}\ntier={}\n",
            hex(&self.delegation_pk),
            hex(&self.channel_identity_pk),
            self.tier
        );
        atomic_write(&dir.join(PAIRED_FILE), text.as_bytes())
    }
    pub fn load(dir: &Path) -> Result<Self, String> {
        let p = dir.join(PAIRED_FILE);
        let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e} (pair this worker first)", p.display()))?;
        let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')));
        Ok(Self {
            delegation_pk: get("delegation_pk").and_then(unhex).ok_or("paired: bad delegation_pk")?,
            channel_identity_pk: get("channel_identity_pk").and_then(unhex).ok_or("paired: bad channel_identity_pk")?,
            tier: get("tier").and_then(|t| t.trim().parse().ok()).ok_or("paired: bad tier")?,
        })
    }
}

/// Replay high-water mark and revocation epoch (ADR 0069 pattern).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub high_water: u64,
    pub min_epoch: u32,
}

pub const STATE_FILE: &str = "state";

impl State {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let p = dir.join(STATE_FILE);
        match fs::read_to_string(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", p.display())),
            Ok(text) => {
                let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')));
                Ok(Self {
                    high_water: get("high_water").and_then(|v| v.trim().parse().ok()).ok_or("state: bad high_water")?,
                    min_epoch: get("min_epoch").and_then(|v| v.trim().parse().ok()).ok_or("state: bad min_epoch")?,
                })
            }
        }
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        atomic_write(&dir.join(STATE_FILE), format!("high_water={}\nmin_epoch={}\n", self.high_water, self.min_epoch).as_bytes())
    }
}

/// Write `tmp`, fsync it, rename over `path`, fsync the directory. Either the old or the new content
/// survives a power cut; never a mix.
pub fn atomic_write(path: &Path, b: &[u8]) -> Result<(), String> {
    let dir: PathBuf = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(b).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    File::open(&dir).and_then(|d| d.sync_all()).map_err(|e| format!("{}: {e}", dir.display()))
}
