/**
 * envelope — owner-signed HQMGMT1 authority for privileged actions (operator decision R6 = D, 12 Nov 2026;
 * docs/design/mgmt-envelope-api.md). Since then the device ignores the owner token for: trial confirm / rollback
 * (msg 20 / 21), upload activate (23), pack rollback (24), factory reset (32) and signing-key rotation (33).
 *
 * The browser signs with the key it already holds (store/signing.ts), which must be the device's ENROLLED owner
 * key. `device_id`, `epoch` and `next_seq` are read from GET /api/config → envelope immediately before each
 * signature: the sequence is consumed once the signature verifies (even if a later check refuses) and the floor is
 * shared with hsh and the CLI, so a stale number is retried once with a fresh read.
 */
import { fetchJson } from './api';
import { post } from './actions';
import { signEnvelope } from './signing';

export const MSG = { CFG_CONFIRM: 20, CFG_ROLLBACK: 21, UPLOAD_ACTIVATE: 23, UPLOAD_ROLLBACK: 24, FACTORY_RESET: 32, ANCHOR_ROTATE: 33 } as const;
export const TYPE_CODE: Record<string, number> = { shield_block: 0, shield_allow: 1, ioc: 2, rules: 3, oui: 4, devices: 5, wan: 6, wifi: 7, policy: 8, config: 9, os_image: 254 };

export interface EnvelopeState { format: string; device_id: string; epoch: string; next_seq: number; generation: number; digest: string; owner_enrolled: boolean }

const unhex = (h: string, n: number): Uint8Array => {
  const s = (h || '').trim();
  if (s.length !== n * 2 || !/^[0-9a-f]*$/i.test(s)) throw new Error('The device sent an envelope field this browser cannot read.');
  return Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
};
export const ZERO32 = new Uint8Array(32);

/** What the device says to bind (null when it does not serve envelopes: an older image). */
export async function readEnvelope(): Promise<EnvelopeState | null> {
  try { return (await fetchJson<{ envelope?: EnvelopeState }>('/api/config')).envelope ?? null; } catch { return null; }
}

/** The first 8 bytes of SHA-256(public key) as a little-endian u64 — the rotate `arg`. */
export async function fp8(pubHex: string): Promise<bigint> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(unhex(pubHex, 32))));
  return new DataView(d.buffer).getBigUint64(0, true);
}

export interface Binding { msg: number; arg?: bigint; generation?: bigint | number; digest?: Uint8Array | string }

async function build(b: Binding, e: EnvelopeState): Promise<string> {
  if (!e.owner_enrolled) throw new Error('This device does not trust a signing key yet. Make it trust yours first (Administration → Signing key).');
  const digest = typeof b.digest === 'string' ? unhex(b.digest, 32) : b.digest ?? ZERO32;
  return signEnvelope({ msg: b.msg, deviceId: unhex(e.device_id, 16), epoch: unhex(e.epoch, 8), seq: BigInt(e.next_seq), arg: b.arg ?? 0n, generation: BigInt(b.generation ?? 0), digest });
}

/** A signed envelope (312 hex) for `binding`, from a fresh read of the device's envelope state — for carriers that
 *  post it themselves (the hsh web console attaches it as the second line). */
export async function envelopeFor(binding: Binding | ((e: EnvelopeState) => Binding)): Promise<string> {
  const e = await readEnvelope();
  if (!e) throw new Error('This device does not take signed owner actions (no envelope in GET /api/config).');
  return build(typeof binding === 'function' ? binding(e) : binding, e);
}

type Res = { ok: boolean; refused?: string };

/**
 * Sign `binding` against the device's current envelope state and POST it with `fields`. `bindFrom` lets the
 * caller derive generation / digest from the same read (trial confirm binds the bundle in force). A refusal for
 * a stale sequence is retried once with a fresh read; any other refusal is returned as the device said it.
 */
export async function postSigned<T extends Res = Res>(path: string, fields: Record<string, string>, binding: Binding | ((e: EnvelopeState) => Binding)): Promise<T> {
  for (let attempt = 0; attempt < 2; attempt++) {
    const e = await readEnvelope();
    if (!e) throw new Error('This device does not take signed owner actions (no envelope in GET /api/config).');
    const env = await build(typeof binding === 'function' ? binding(e) : binding, e);
    const r = await post<T>(path, { ...fields, envelope: env });
    if (r.ok || attempt === 1 || !/seq|sequence|replay/i.test(String(r.refused ?? ''))) return r;
  }
  throw new Error('unreachable');
}
