/**
 * keyBackup — passphrase-wrapped backup of the owner's signing key: an encrypted PKCS#8 PEM
 * ("-----BEGIN ENCRYPTED PRIVATE KEY-----", RFC 5958 / RFC 8018 PBES2: PBKDF2-HMAC-SHA256, 600 000
 * iterations, AES-256-CBC). It is the format OpenSSL and Python `cryptography` read with a password, so
 * `policy-sign.py` can use the same backup (HQ_KEY_PASSPHRASE or a prompt).
 * Runs in the browser only: the key and the passphrase never reach the device.
 */

const ITER = 600_000;
const OID = {
  pbes2: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d],
  pbkdf2: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c],
  hmacSha256: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09],
  aes256cbc: [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a],
};

function len(n: number): number[] {
  if (n < 0x80) return [n];
  const b: number[] = [];
  while (n > 0) { b.unshift(n & 0xff); n >>= 8; }
  return [0x80 | b.length, ...b];
}
const tlv = (tag: number, body: number[] | Uint8Array): number[] => [tag, ...len(body.length), ...body];
const seq = (...items: number[][]) => tlv(0x30, items.flat());
const oid = (o: number[]) => tlv(0x06, o);
const octets = (b: Uint8Array) => tlv(0x04, b);
function int(n: number): number[] {
  const b: number[] = [];
  do { b.unshift(n & 0xff); n = Math.floor(n / 256); } while (n > 0);
  if (b[0] & 0x80) b.unshift(0);
  return tlv(0x02, b);
}

/** Minimal DER reader: returns [tag, body, next offset]. */
function read(d: Uint8Array, o: number): [number, Uint8Array, number] {
  const tag = d[o];
  let l = d[o + 1], p = o + 2;
  if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + d[p++]; }
  return [tag, d.subarray(p, p + l), p + l];
}
function children(body: Uint8Array): [number, Uint8Array][] {
  const out: [number, Uint8Array][] = [];
  for (let o = 0; o < body.length;) { const [t, b, n] = read(body, o); out.push([t, b]); o = n; }
  return out;
}
const eq = (a: Uint8Array, b: number[]) => a.length === b.length && a.every((x, i) => x === b[i]);

async function derive(pass: string, salt: Uint8Array, iter: number): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: new Uint8Array(salt), iterations: iter }, base, { name: 'AES-CBC', length: 256 }, false, ['encrypt', 'decrypt']);
}

function pem(label: string, der: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...der)).replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ${label}-----\n${b64}${b64.endsWith('\n') ? '' : '\n'}-----END ${label}-----\n`;
}
function unpem(text: string): Uint8Array {
  const b64 = text.replace(/-----(BEGIN|END) [A-Z ]+-----/g, '').replace(/\s+/g, '');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export const isEncryptedPem = (text: string) => /BEGIN ENCRYPTED PRIVATE KEY/.test(text);

/** PKCS#8 DER → encrypted PEM. */
export async function wrapPkcs8(der: Uint8Array, pass: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, await derive(pass, salt, ITER), new Uint8Array(der)));
  const alg = seq(oid(OID.pbes2), seq(
    seq(oid(OID.pbkdf2), seq(octets(salt), int(ITER), seq(oid(OID.hmacSha256), [0x05, 0x00]))),
    seq(oid(OID.aes256cbc), octets(iv)),
  ));
  return pem('ENCRYPTED PRIVATE KEY', new Uint8Array(seq(alg, octets(ct))));
}

/** Encrypted PEM → PKCS#8 DER. Throws "Wrong passphrase…" on a bad passphrase. */
export async function unwrapPkcs8(text: string, pass: string): Promise<Uint8Array> {
  const [, top] = read(unpem(text), 0);
  const [[, alg], [, ct]] = children(top);
  const [[, algOid], [, params]] = children(alg);
  if (!eq(algOid, OID.pbes2)) throw new Error('Unsupported backup encryption (expected PBES2).');
  const [[, kdf], [, enc]] = children(params);
  const [[, kdfOid], [, kdfParams]] = children(kdf);
  if (!eq(kdfOid, OID.pbkdf2)) throw new Error('Unsupported key derivation (expected PBKDF2).');
  const kp = children(kdfParams);
  const salt = kp[0][1];
  const iter = kp[1][1].reduce((n, b) => n * 256 + b, 0);
  const prf = kp.find(([t, b]) => t === 0x30 && b.length > 0);
  if (!prf || !eq(children(prf[1])[0][1], OID.hmacSha256)) throw new Error('Unsupported PRF (expected HMAC-SHA256).');
  const [[, encOid], [, iv]] = children(enc);
  if (!eq(encOid, OID.aes256cbc)) throw new Error('Unsupported cipher (expected AES-256-CBC).');
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(iv) }, await derive(pass, salt, iter), new Uint8Array(ct)));
  } catch {
    throw new Error('Wrong passphrase, or the backup is damaged.');
  }
}
