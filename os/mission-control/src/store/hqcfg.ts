/**
 * hqcfg — the HQCFG1 configuration bundle (ADR 0059 Step 2; assessment §B.4). Pure (no Solid, no DOM), so
 * the UI suite can import it in Node and compare it byte-for-byte with os/kernel/tools/hqcfg.py and the
 * kernel's [P-cfgbundle] vectors. The signature (HQCSIG1) is made in signing.ts with the browser key.
 *
 *   bundle  "HQCFG1\0\0" | schema u16 (0x0100) | flags u16 | generation u64 | device_id[16] | key_id[8]
 *           | count u8 | 0 0 0 | count × {kind u8, 0, len u16} | bodies     (little-endian; ≤ 16 KiB)
 *
 * Sections hold canonical text only: the legacy "HQWAN1"/"HQPOL1" header lines and the POLICY 4096-byte
 * newline padding are not part of a bundle. The PPPoE password and Wi-Fi PSK are inside the signed region
 * in clear — not protected at rest until the secrets section ships.
 */

export const SCHEMA = 0x0100;
export const KIND = { wan: 1, link: 2, lan: 3, wifi: 4, policy: 5, mgmt: 6, tunnel: 7, secrets: 8 } as const;
export type SectionKind = keyof typeof KIND;
export const V1_KINDS: ReadonlySet<SectionKind> = new Set(['wan', 'wifi', 'policy']);
const MAX = 16 << 10;

/** Throws unless `body` is canonical section text (mirrors hqcfg.py `canonical`). */
export function canonicalSection(kind: SectionKind, body: string): void {
  if (!body || !body.endsWith('\n')) throw new Error(`${kind}: empty or missing final line break`);
  const seen = new Set<string>();
  for (const ln of body.slice(0, -1).split('\n')) {
    if (!ln) throw new Error(`${kind}: blank line`);
    if (!/^[\x20-\x7e]*$/.test(ln) || ln !== ln.replace(/ +$/, '')) throw new Error(`${kind}: non-canonical character or trailing space`);
    let key: string;
    if (kind === 'policy') {
      const w = ln.split(' ');
      if ((w[0] === 'acl' || w[0] === 'prefix-list') && w.length > 3 && w[2] === 'seq') key = [w[0], w[1], 'seq', w[3]].join(' ');
      else if (w[0] === 'acl' && w.length > 2 && w[2] === 'default') key = `acl ${w[1]} default`;
      else if (w[0] === 'interface' && w.length >= 4) key = w.slice(0, 4).join(' ');
      else if (w[0] === 'route' && w.length > 1) {
        // (dst, from|any, via): failover through different interfaces is fine; same interface twice is not.
        const v = w.indexOf('via');
        key = `route ${w[1]} ${w.length > 3 && w[2] === 'from' ? w[3] : 'any'} ${v >= 0 && v < w.length - 1 ? w[v + 1] : ''}`;
      }
      else key = ln;
    } else {
      if (!ln.includes('=')) throw new Error(`${kind}: not key=value`);
      key = ln.slice(0, ln.indexOf('='));
    }
    if (seen.has(key)) throw new Error(`${kind}: "${key}" repeated`);
    seen.add(key);
  }
}

/** Legacy per-file text (WAN.TXT / WIFI.TXT / POLICY text) → canonical section body. */
export function fromLegacy(kind: SectionKind, text: string): string {
  let t = text;
  if (kind === 'policy') { t = t.replace(/\n+$/, '') + '\n'; if (t.startsWith('HQPOL1\n')) t = t.slice(7); }
  if (kind === 'wan' && t.startsWith('HQWAN1\n')) t = t.slice(7);
  canonicalSection(kind, t);
  return t;
}

const u16 = (n: number) => [n & 0xff, (n >> 8) & 0xff];
function u64(n: number): number[] { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return [...b]; }

/** Build the bundle. `keyId` = sha256(signer public key)[0..8]; `deviceId` all-zero = any device. */
export function buildBundle(sections: Partial<Record<SectionKind, string>>, generation: number, keyId: Uint8Array, deviceId: Uint8Array = new Uint8Array(16)): Uint8Array {
  const enc = new TextEncoder();
  const order = (Object.keys(sections) as SectionKind[]).filter((k) => sections[k] !== undefined).sort((a, b) => KIND[a] - KIND[b]);
  // Schema 1.0 carries wan, wifi and policy only (link/mgmt reserved; the device refuses any other kind).
  if (order.some((k) => !V1_KINDS.has(k))) throw new Error('A schema 1.0 bundle carries only internet (wan), Wi-Fi and firewall sections.');
  const bodies = order.map((k) => { canonicalSection(k, sections[k]!); const b = enc.encode(sections[k]!); if (b.length > 0xffff) throw new Error(`${k}: section too long`); return b; });
  const flags = deviceId.some((x) => x) ? 1 : 0;
  const head = [...enc.encode('HQCFG1\0\0'), ...u16(SCHEMA), ...u16(flags), ...u64(generation), ...deviceId, ...keyId.slice(0, 8), order.length, 0, 0, 0];
  const table = order.flatMap((k, i) => [KIND[k], 0, ...u16(bodies[i].length)]);
  const total = head.length + table.length + bodies.reduce((s, b) => s + b.length, 0);
  if (total > MAX) throw new Error('The configuration is larger than the 16 KiB a bundle may hold.');
  const out = new Uint8Array(total);
  out.set(head, 0); out.set(table, head.length);
  let o = head.length + table.length;
  for (const b of bodies) { out.set(b, o); o += b.length; }
  return out;
}
