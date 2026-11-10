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
 * Passkeys / security keys are NOT used: WebAuthn signs its own wrapped structure, which the device's
 * verifier does not accept (ADR 0058 D4, open item 1).
 */
import { createSignal } from 'solid-js';

const DB = 'hp-signing';
const STORE = 'keys';
const ID = 'owner';

interface Stored { privateKey: CryptoKey; publicKey: CryptoKey; created: number; source: 'generated' | 'imported' }

export const [ownerKey, setOwnerKey] = createSignal<{ pubHex: string; created: number; source: 'generated' | 'imported' } | null>(null);
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
    setOwnerKey(s ? { pubHex: await pubHexOf(s.publicKey), created: s.created, source: s.source } : null);
  } catch {
    setOwnerKey(null);
  }
}

export async function generateOwnerKey(): Promise<string> {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  await idbPut({ privateKey: kp.privateKey, publicKey: kp.publicKey, created: Date.now(), source: 'generated' });
  await loadOwnerKey();
  return ownerKey()!.pubHex;
}

function pemBody(pem: string): Uint8Array {
  const b64 = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Import a PKCS#8 PEM Ed25519 key (e.g. from `policy-sign.py keygen`). */
export async function importOwnerKeyPem(pem: string): Promise<string> {
  if (!/BEGIN PRIVATE KEY/.test(pem)) throw new Error('Not a PKCS#8 private key (expected "-----BEGIN PRIVATE KEY-----").');
  const priv = await crypto.subtle.importKey('pkcs8', new Uint8Array(pemBody(pem)), { name: 'Ed25519' }, true, ['sign']);
  // Derive the public half through JWK (x = public key).
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  if (!jwk.x) throw new Error('The key has no public part.');
  const pub = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, true, ['verify']);
  await idbPut({ privateKey: priv, publicKey: pub, created: Date.now(), source: 'imported' });
  await loadOwnerKey();
  return ownerKey()!.pubHex;
}

/** PKCS#8 PEM backup of the stored key (same format policy-sign.py reads). */
export async function exportOwnerKeyPem(): Promise<string> {
  const s = await idbGet();
  if (!s) throw new Error('No signing key in this browser.');
  const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', s.privateKey));
  const b64 = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, '$1\n');
  return `-----BEGIN PRIVATE KEY-----\n${b64}${b64.endsWith('\n') ? '' : '\n'}-----END PRIVATE KEY-----\n`;
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
