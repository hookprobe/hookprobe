/**
 * packUpload — ADR 0056 signed-pack upload to heqk (`/api/upload/*`).
 *
 *   begin    type + size + sha256 + owner key       (re-authentication)
 *   chunk    raw bytes in order, ?id=&off=           (bound to the upload id, session and offset)
 *   finish   the device checks the digest, the pack's own signature and anti-rollback
 *   activate owner key again; A/B artifact store + live reload, rolled back if refused
 *
 * The file is the CONTAINER the operator built offline: `cat X.SIG X.TXT`. Nothing here is trusted;
 * the operator signature verified on the device is the authority.
 */
import { createSignal } from 'solid-js';
import { fetchJson } from './api';
import { post } from './actions';
import { postSigned, MSG, TYPE_CODE } from './envelope';

export interface PackSlot { type: string; cap: number; generation: number; source: 'store' | 'boot'; applies?: 'now' | 'next_boot';
  /** The verified generation a rollback would return to (GET /api/upload, kernel PR #1047; null = nothing to roll back to). */
  rollback_to?: number | null }
export interface UploadEvent { ms: number; session: string; step: string; type: string; ok: boolean; generation: number; why: string }
export interface UploadView { store: boolean; chunk_max: number; types: PackSlot[]; in_flight: null | { id: string; type: string; size: number; received: number; verified: boolean; type_code?: number; generation?: number; digest?: string }; recent: UploadEvent[] }

export const [uploadView, setUploadView] = createSignal<UploadView | null>(null);
export async function refreshUploads(): Promise<void> {
  try { setUploadView(await fetchJson<UploadView>('/api/upload')); } catch { /* not a heqk device */ }
}

export const PACK_LABEL: Record<string, string> = {
  shield_block: 'Shield block list (BLOCK.TXT)', shield_allow: 'Shield allow list (ALLOW.TXT)', ioc: 'Threat-intel pack (IOC.TXT)',
  rules: 'Signed rule pack (RULES.BIN)', oui: 'Vendor list (OUI.TXT)', devices: 'Device policy (DEVICES.TXT)',
  wan: 'Internet settings (WAN.TXT)', wifi: 'Wi-Fi settings (WIFI.TXT)', policy: 'Firewall policy (POLICY.TXT)',
};
/** Types whose rollback changes how the device connects. */
export const CONNECTIVITY = new Set(['wan', 'wifi', 'policy']);

// ── SHA-256: Web Crypto when the page is a secure context, else a small pure implementation
// (a device is reachable over plain HTTP before its TLS certificate is provisioned).
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
function sha256Pure(data: Uint8Array): Uint8Array {
  const len = data.length, bits = len * 8;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(data); padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bits / 2 ** 32)); dv.setUint32(padded.length - 4, bits >>> 0);
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  const r = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let o = 0; o < padded.length; o += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = r(W[i - 15], 7) ^ r(W[i - 15], 18) ^ (W[i - 15] >>> 3), s1 = r(W[i - 2], 17) ^ r(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) >>> 0;
      const t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) new DataView(out.buffer).setUint32(i * 4, H[i]);
  return out;
}
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const d = globalThis.crypto?.subtle ? new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(data))) : sha256Pure(data);
  return [...d].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export type UploadStep = 'begin' | 'upload' | 'verify' | 'activate' | 'done';
interface Resp { ok: boolean; refused?: string; id?: string; chunk_max?: number; received?: number; generation?: number; active_generation?: number; staged?: boolean; activated?: boolean; journal_seq?: number; live?: boolean; needs_confirm?: boolean }
export interface UploadResult { text: string; staged: boolean; generation: number }

async function session(): Promise<{ csrf: string }> {
  return fetchJson<{ csrf: string }>('/api/session');
}

/** Run the whole flow; `progress` reports the step and the bytes sent. Throws with the device's refusal. */
export async function uploadPack(type: string, file: File, askKey: () => Promise<string | null> | string | null, progress: (s: UploadStep, sent: number) => void): Promise<UploadResult> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const sha = await sha256Hex(bytes);
  const key = await askKey();
  if (!key) throw new Error('Cancelled.');
  progress('begin', 0);
  const b = await post<Resp>('/api/upload/begin', { type, size: String(bytes.length), sha256: sha, owner_key: key });
  if (!b.ok || !b.id) throw new Error(`Refused at begin: ${b.refused}`);
  const max = b.chunk_max ?? 16384;
  const { csrf } = await session();
  for (let off = 0; off < bytes.length; off += max) {
    progress('upload', off);
    const r = await fetch(`/api/upload/chunk?id=${b.id}&off=${off}`, { method: 'POST', credentials: 'same-origin', headers: { 'X-HQ-CSRF': csrf, 'content-type': 'application/octet-stream' }, body: bytes.slice(off, off + max) });
    const j = (await r.json().catch(() => ({ ok: false, refused: `HTTP ${r.status}` }))) as Resp;
    if (!j.ok) { await post('/api/upload/abort', { id: b.id }).catch(() => undefined); throw new Error(`Refused while uploading: ${j.refused}`); }
  }
  progress('verify', bytes.length);
  const f = await post<Resp>('/api/upload/finish', { id: b.id });
  if (!f.ok) throw new Error(`The device did not accept the pack: ${f.refused}`);
  // R6 = D: activation is authorised by an HQMGMT1 envelope (msg 23) bound to exactly what the device verified —
  // its type code, staged generation and staged digest (GET /api/upload → in_flight). The browser checks that digest
  // against its own SHA-256 of the same bytes (everything after the 512-byte signature) before it signs.
  progress('activate', bytes.length);
  const abort = () => post('/api/upload/abort', { id: b.id! }).catch(() => undefined);
  await refreshUploads();
  const fl = uploadView()?.in_flight;
  if (!fl || fl.id !== b.id || !fl.verified || fl.type_code === undefined || fl.generation === undefined || !fl.digest) {
    await abort();
    throw new Error('The device did not report what it verified, so this browser cannot sign the activation. Nothing changed.');
  }
  if (type !== 'os_image' && (await sha256Hex(bytes.subarray(512))) !== fl.digest.toLowerCase()) {
    await abort();
    throw new Error('The device verified different bytes from the file in this browser. Nothing was activated.');
  }
  let a: Resp;
  try {
    a = await postSigned<Resp>('/api/upload/activate', { id: b.id }, { msg: MSG.UPLOAD_ACTIVATE, arg: BigInt(fl.type_code), generation: fl.generation, digest: fl.digest });
  } catch (e) { await abort(); throw e; }
  if (!a.ok) { await abort(); throw new Error(`Activation refused (the previous pack stays active): ${a.refused}`); }
  progress('done', bytes.length);
  await refreshUploads();
  // `staged` comes from the device: next-boot types (wan / wifi / policy / os_image) only take effect at the next restart.
  const staged = a.staged ?? uploadView()?.types.find((t) => t.type === type)?.applies === 'next_boot';
  // `live` (ADR 0059 step 3): a configuration bundle the device applied at once and is now trying.
  if (a.live) return { staged: false, generation: a.generation ?? 0, text: `Generation ${a.generation} verified and applied live. It is on trial now: ${a.needs_confirm ? 'press Keep within the window, or it switches back by itself.' : 'the device keeps it once the internet works, or switches back by itself.'}` };
  return { staged, generation: a.generation ?? 0, text: staged ? `Generation ${a.generation} verified and staged: it takes effect at the next restart.` : `Generation ${a.generation} verified and applied now.` };
}

/** Roll a pack back to the other A/B half (re-verified by the device). Throws with the device's refusal. */
export async function rollbackPack(type: string, target: number | null | undefined): Promise<UploadResult> {
  // R6 = D: msg 24 binds the type code and the generation it rolls back TO. That target must come from the device
  // (a guessed one is refused and consumes a sequence number), so without it the rollback is not offered.
  if (typeof target !== 'number' || !(type in TYPE_CODE)) throw new Error('This device does not report which generation a rollback would return to yet, so it cannot be signed. Nothing changed.');
  const a = await postSigned<Resp>('/api/upload/rollback', { type }, { msg: MSG.UPLOAD_ROLLBACK, arg: BigInt(TYPE_CODE[type]), generation: target });
  await refreshUploads();
  if (!a.ok) throw new Error(`Rollback refused: ${a.refused}`);
  const staged = !!a.staged;
  return { staged, generation: a.generation ?? 0, text: staged ? `Rolled back to generation ${a.generation}: it takes effect at the next restart.` : `Rolled back to generation ${a.generation}, applied now.` };
}
