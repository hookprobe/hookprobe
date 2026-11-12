/**
 * hqmgmt1 — the HQMGMT1 owner-command envelope layout (docs/design/mgmt-envelope-api.md). Pure, with no imports, so
 * the UI suite can run it in Node against the API doc's test vector. Signing is in signing.ts.
 */

const enc = (s: string) => new TextEncoder().encode(s);

/** HQMGMT1 body (92 bytes, little-endian; docs/design/mgmt-envelope-api.md step 2) — pure, so it can be tested
 *  without a key. */
export function envelopeBody(f: { msg: number; deviceId: Uint8Array; epoch: Uint8Array; seq: bigint; arg: bigint; generation: bigint; digest: Uint8Array }): Uint8Array {
  if (f.deviceId.length !== 16 || f.epoch.length !== 8 || f.digest.length !== 32) throw new Error('Envelope field has the wrong length.');
  const b = new Uint8Array(92);
  const v = new DataView(b.buffer);
  b.set(enc('HQMGMT1'), 0); // byte 7 stays 0
  v.setUint16(8, 1, true);
  v.setUint16(10, f.msg, true);
  b.set(f.deviceId, 12);
  b.set(f.epoch, 28);
  v.setBigUint64(36, f.seq, true);
  v.setBigUint64(44, f.arg, true);
  v.setBigUint64(52, f.generation, true);
  b.set(f.digest, 60);
  return b;
}

