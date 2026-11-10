/**
 * signing — the owner's signing key, held in THIS browser (ADR 0058 D4; requirements doc §Configuration
 * journey: "the owner signs in the browser"). The private key never reaches the device.
 *
 *   key      Ed25519 via WebCrypto, stored as a CryptoKey in IndexedDB; PKCS#8 PEM backup — the exact
 *            format `os/kernel/tools/policy-sign.py keygen` writes, so an existing operator key can be
 *            imported and the CLI keeps working with a key made here.
 *   sign     byte-identical to policy-sign.py (Ed25519 is deterministic):
 *              tagged packs  magic8 · gen u64 LE · len u64 LE · sha256 · sig · 0-pad to 512   (WAN, WIFI, …)
 *              POLICY        "HQPSIG1\0" · gen · sha256(4096 B) · sig · 0-pad to 512
 *
 *   storage  NON-extractable: the private key cannot be read back out of this browser, not even by
 *            Mission Control. The only copy that leaves is the passphrase-wrapped backup (keyBackup.ts),
 *            offered once — when the key is made (or rotated). Keys stored before this rule
 *            (extractable) can still be backed up, wrapped the same way.
 *
 * Passkeys / security keys are NOT used: WebAuthn signs its own wrapped structure, which the device's
 * verifier does not accept (ADR 0058 D4, open item 1).
 */
import { createSignal } from 'solid-js';
import { wrapPkcs8, unwrapPkcs8, isEncryptedPem } from './keyBackup';

const DB = 'hp-signing';
const STORE = 'keys';
const ID = 'owner';

interface Stored { privateKey: CryptoKey; publicKey: CryptoKey; created: number; source: 'generated' | 'imported' }

export const [ownerKey, setOwnerKey] = createSignal<{ pubHex: string; created: number; source: 'generated' | 'imported'; exportable: boolean } | null>(null);
export const MIN_PASSPHRASE = 10;
export const [signingSupported, setSigningSupported] = createSignal<boolean | null>(null);

function idb(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idbGet(): Promise<Stored | undefined> {
  const db = await idb();
  return new Promise((res, rej) => {
    const q = db.transaction(STORE).objectStore(STORE).get(ID);
    q.onsuccess = () => res(q.result as Stored | undefined);
    q.onerror = () => rej(q.error);
  });
}
async function idbPut(v: Stored | null): Promise<void> {
  const db = await idb();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite');
    if (v) tx.objectStore(STORE).put(v, ID); else tx.objectStore(STORE).delete(ID);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

async function pubHexOf(k: CryptoKey): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.exportKey('raw', k)));
}

/** Can this browser do Ed25519 at all (Chrome 137+, Firefox 129+, Safari 17+)? */
export async function checkSigning(): Promise<boolean> {
  try {
    if (!globalThis.crypto?.subtle) { setSigningSupported(false); return false; }
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    setSigningSupported(true);
    return true;
  } catch {
    setSigningSupported(false);
    return false;
  }
}

/** Load the stored key (if any) into `ownerKey`. */
export async function loadOwnerKey(): Promise<void> {
  try {
    const s = await idbGet();
    setOwnerKey(s ? { pubHex: await pubHexOf(s.publicKey), created: s.created, source: s.source, exportable: s.privateKey.extractable } : null);
  } catch {
    setOwnerKey(null);
  }
}

/** Store a PKCS#8 key NON-extractable; derive its public half first (through a short-lived JWK). */
async function storePkcs8(der: Uint8Array, source: Stored['source']): Promise<void> {
  const tmp = await crypto.subtle.importKey('pkcs8', new Uint8Array(der), { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', tmp);
  if (!jwk.x) throw new Error('The key has no public part.');
  const pub = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, true, ['verify']);
  const priv = await crypto.subtle.importKey('pkcs8', new Uint8Array(der), { name: 'Ed25519' }, false, ['sign']);
  await idbPut({ privateKey: priv, publicKey: pub, created: Date.now(), source });
}

function checkPass(p: string): void {
  if (p.length < MIN_PASSPHRASE) throw new Error(`The backup passphrase needs at least ${MIN_PASSPHRASE} characters.`);
}

/** Make a new key: returns the passphrase-wrapped backup (the only copy that ever leaves this browser). */
export async function generateOwnerKey(passphrase: string): Promise<{ pubHex: string; backup: string }> {
  checkPass(passphrase);
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const backup = await wrapPkcs8(der, passphrase);
  await storePkcs8(der, 'generated');
  der.fill(0);
  await loadOwnerKey();
  return { pubHex: ownerKey()!.pubHex, backup };
}

function pemBody(pem: string): Uint8Array {
  const b64 = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Import a backup: encrypted PKCS#8 (needs the passphrase) or a plain PKCS#8 PEM (`policy-sign.py keygen`). */
export async function importOwnerKeyPem(pem: string, passphrase = ''): Promise<string> {
  let der: Uint8Array;
  if (isEncryptedPem(pem)) der = await unwrapPkcs8(pem, passphrase);
  else if (/BEGIN PRIVATE KEY/.test(pem)) der = pemBody(pem);
  else throw new Error('Not a private key backup (expected "BEGIN ENCRYPTED PRIVATE KEY" or "BEGIN PRIVATE KEY").');
  await storePkcs8(der, 'imported');
  der.fill(0);
  await loadOwnerKey();
  return ownerKey()!.pubHex;
}

/** Passphrase-wrapped backup of a key stored before keys became non-extractable. A non-extractable key
 *  cannot be exported by anyone — its backup is the one saved when it was made. */
export async function exportOwnerKeyBackup(passphrase: string): Promise<string> {
  checkPass(passphrase);
  const s = await idbGet();
  if (!s) throw new Error('No signing key in this browser.');
  if (!s.privateKey.extractable) throw new Error('This key cannot leave the browser. Use the backup you saved when you made it.');
  return wrapPkcs8(new Uint8Array(await crypto.subtle.exportKey('pkcs8', s.privateKey)), passphrase);
}

export async function deleteOwnerKey(): Promise<void> {
  await idbPut(null);
  setOwnerKey(null);
}

const enc = (s: string) => new TextEncoder().encode(s);
function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}
function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function sha(b: Uint8Array): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(b))); }
async function sign(msg: Uint8Array): Promise<Uint8Array> {
  const s = await idbGet();
  if (!s) throw new Error('No signing key in this browser. Create or import one in Administration → Signing key.');
  return new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, s.privateKey, new Uint8Array(msg)));
}
function pad512(b: Uint8Array): Uint8Array { const out = new Uint8Array(512); out.set(b); return out; }

export interface PackKind { tag: string; magic: string; cap: number }
export const PACKS = {
  wan: { tag: 'HQWAN1', magic: 'HQNSIG1\0', cap: 512 },
  wifi: { tag: 'HQWIF1', magic: 'HQWSIG1\0', cap: 1024 },
  devices: { tag: 'HQDEV1', magic: 'HQDSIG1\0', cap: 16 << 10 },
} satisfies Record<string, PackKind>;

/** Tagged pack signature (WAN.SIG, WIFI.SIG, …): 512 B, byte-identical to policy-sign.py. */
export async function signPack(kind: PackKind, gen: number, body: Uint8Array): Promise<Uint8Array> {
  if (body.length > kind.cap) throw new Error(`File larger than ${kind.cap} bytes.`);
  const d = await sha(body);
  const meta = cat(u64le(gen), u64le(body.length));
  const sig = await sign(cat(enc(kind.tag), meta, d));
  return pad512(cat(enc(kind.magic), meta, d, sig));
}

/** POLICY.SIG over the exact 4096-byte staged POLICY.TXT. */
export async function signPolicy(gen: number, policy4096: Uint8Array): Promise<Uint8Array> {
  if (policy4096.length !== 4096) throw new Error('POLICY.TXT must be exactly 4096 bytes.');
  const d = await sha(policy4096);
  const sig = await sign(cat(enc('HQPOL1'), u64le(gen), d));
  return pad512(cat(enc('HQPSIG1\0'), u64le(gen), d, sig));
}

export function download(name: string, data: Uint8Array | string, mime = 'application/octet-stream'): void {
  const blob = new Blob([typeof data === 'string' ? data : new Uint8Array(data)], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

/** Enrollment proof (ADR 0058 D3): this browser's key signs "HQENR1" || its own public key (32 raw bytes). */
export async function enrollProof(): Promise<{ publicKey: string; proof: string }> {
  const s = await idbGet();
  if (!s) throw new Error('No signing key in this browser.');
  const pub = await pubHexOf(s.publicKey);
  return { publicKey: pub, proof: hex(await sign(cat(enc('HQENR1'), unhex(pub)))) };
}

/** Rotation (ADR 0058 D3): a NEW key is made here; the CURRENT key signs "HQROT1" || new(32) || gen u64 LE
 *  and the new key proves possession (HQENR1). The new key replaces the stored one only on `commit()`,
 *  after the device accepted it — until then the current key stays. */
export async function prepareRotation(generation: number, passphrase: string): Promise<{ publicKey: string; proof: string; signature: string; backup: string; commit: () => Promise<void> }> {
  checkPass(passphrase);
  if (!(await idbGet())) throw new Error('No signing key in this browser: import the current owner key first.');
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const pub = await pubHexOf(kp.publicKey);
  const proof = hex(new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, kp.privateKey, new Uint8Array(cat(enc('HQENR1'), unhex(pub))))));
  const signature = hex(await sign(cat(enc('HQROT1'), unhex(pub), u64le(generation))));
  const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const backup = await wrapPkcs8(der, passphrase);
  return { publicKey: pub, proof, signature, backup, commit: async () => { await storePkcs8(der, 'generated'); der.fill(0); await loadOwnerKey(); } };
}
