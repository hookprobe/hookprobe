/**
 * qr — a minimal QR Code encoder (ISO/IEC 18004): byte mode, error-correction level M, versions 1–10, mask chosen by
 * the standard penalty rules. Enough for a Wi-Fi join code (WIFI:T:WPA;S:…;P:…;;), built in the browser so the
 * password never leaves it. Checked module-for-module against a reference encoder (tests/ui/specs/qr-golden.json).
 */

// [EC codewords per block, [[blocks, data codewords per block], …]] for level M, versions 1..10.
const EC: [number, [number, number][]][] = [
  [10, [[1, 16]]], [16, [[1, 28]]], [26, [[1, 44]]], [18, [[2, 32]]], [24, [[2, 43]]],
  [16, [[4, 27]]], [18, [[4, 31]]], [22, [[2, 38], [2, 39]]], [22, [[3, 36], [2, 37]]], [26, [[4, 43], [1, 44]]],
];
const ALIGN = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x = (x << 1) ^ (x & 0x80 ? 0x11d : 0); }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a: number, b: number) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

function rs(data: number[], n: number): number[] {
  let g = [1];
  for (let i = 0; i < n; i++) { const r = new Array(g.length + 1).fill(0); g.forEach((c, j) => { r[j] ^= c; r[j + 1] ^= mul(c, EXP[i]); }); g = r; }
  const rem = new Array(n).fill(0);
  for (const d of data) { const f = d ^ rem.shift()!; rem.push(0); for (let j = 0; j < n; j++) rem[j] ^= mul(g[j + 1], f); }
  return rem;
}

const MASKS: ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0, (_, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

/** Encode `text` (UTF-8) as a QR matrix: rows of booleans, true = dark. `mask` forces a mask (tests); else best. */
export function qrMatrix(text: string, mask?: number): boolean[][] {
  const bytes = new TextEncoder().encode(text);
  let v = 0, cap = 0;
  for (; v < 10; v++) { cap = EC[v][1].reduce((s, [b, d]) => s + b * d, 0); if (4 + (v < 9 ? 8 : 16) + 8 * bytes.length <= cap * 8) break; }
  if (v === 10) throw new Error('Too long for a QR code here.');
  const ver = v + 1, size = 17 + 4 * ver;

  // data bits → codewords (mode 0100, count, bytes, terminator, pad)
  const bits: number[] = [];
  const put = (val: number, len: number) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(4, 4); put(bytes.length, ver < 10 ? 8 : 16); bytes.forEach((b) => put(b, 8));
  put(0, Math.min(4, cap * 8 - bits.length)); while (bits.length % 8) bits.push(0);
  const cw: number[] = []; for (let i = 0; i < bits.length; i += 8) cw.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  for (let p = 0; cw.length < cap; p ^= 1) cw.push(p ? 0x11 : 0xec);

  // blocks + Reed-Solomon, interleaved
  const [ecn, groups] = EC[v], blocks: number[][] = [];
  let o = 0; for (const [b, d] of groups) for (let i = 0; i < b; i++) { blocks.push(cw.slice(o, o + d)); o += d; }
  const ecs = blocks.map((b) => rs(b, ecn)), out: number[] = [];
  for (let i = 0; i < Math.max(...blocks.map((b) => b.length)); i++) for (const b of blocks) if (i < b.length) out.push(b[i]);
  for (let i = 0; i < ecn; i++) for (const e of ecs) out.push(e[i]);

  // function patterns
  const m = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const fn = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const set = (x: number, y: number, d: boolean) => { m[y][x] = d; fn[y][x] = true; };
  for (const [fx, fy] of [[0, 0], [size - 7, 0], [0, size - 7]]) for (let dy = -1; dy <= 7; dy++) for (let dx = -1; dx <= 7; dx++) {
    const x = fx + dx, y = fy + dy; if (x < 0 || y < 0 || x >= size || y >= size) continue;
    const r = Math.max(Math.abs(dx - 3), Math.abs(dy - 3)); set(x, y, r !== 2 && r !== 4);
  }
  for (let i = 8; i < size - 8; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const al = ALIGN[v];
  for (const ay of al) for (const ax of al) {
    if ((ax === 6 && ay === 6) || (ax === 6 && ay === al[al.length - 1]) || (ax === al[al.length - 1] && ay === 6)) continue;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  const format = (mk: number) => {
    const data = (0 << 3) | mk; let r = data; for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537);
    const f = ((data << 10) | r) ^ 0x5412, b = (i: number) => ((f >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, b(i));
    set(8, 7, b(6)); set(8, 8, b(7)); set(7, 8, b(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, b(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, b(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, b(i));
    set(8, size - 8, true);
  };
  format(0);
  if (ver >= 7) {
    let r = ver; for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25);
    const vb = (ver << 12) | r;
    for (let i = 0; i < 18; i++) { const d = ((vb >>> i) & 1) === 1, a = size - 11 + (i % 3), b = Math.floor(i / 3); set(a, b, d); set(b, a, d); }
  }

  // data placement (zigzag, skipping the timing column)
  const dbits: number[] = []; out.forEach((c) => { for (let i = 7; i >= 0; i--) dbits.push((c >>> i) & 1); });
  let k = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) {
      const x = right - j, up = ((right + 1) & 2) === 0, y = up ? size - 1 - vert : vert;
      if (!fn[y][x]) { m[y][x] = k < dbits.length && dbits[k] === 1; k++; }
    }
  }

  const apply = (mk: number) => { for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fn[y][x] && MASKS[mk](x, y)) m[y][x] = !m[y][x]; };
  let best = mask ?? 0;
  if (mask === undefined) {
    let lo = Infinity;
    for (let mk = 0; mk < 8; mk++) { apply(mk); format(mk); const p = penalty(m); if (p < lo) { lo = p; best = mk; } apply(mk); }
  }
  apply(best); format(best);
  return m;
}

/** ISO 18004 §7.8.3 penalty (N1 runs, N2 blocks, N3 finder-like, N4 balance). */
function penalty(m: boolean[][]): number {
  const n = m.length; let p = 0, dark = 0;
  const line = (get: (i: number) => boolean) => {
    let run = 1;
    for (let i = 1; i <= n; i++) {
      if (i < n && get(i) === get(i - 1)) run++;
      else { if (run >= 5) p += 3 + run - 5; run = 1; }
    }
    for (let i = 0; i + 11 <= n; i++) {
      const s = Array.from({ length: 11 }, (_, j) => (get(i + j) ? 1 : 0)).join('');
      if (s === '10111010000' || s === '00001011101') p += 40;
    }
  };
  for (let i = 0; i < n; i++) { line((j) => m[i][j]); line((j) => m[j][i]); }
  for (let y = 0; y < n - 1; y++) for (let x = 0; x < n - 1; x++) { const c = m[y][x]; if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) p += 3; }
  m.forEach((r) => r.forEach((c) => { if (c) dark++; }));
  return p + 10 * Math.floor(Math.abs((dark * 100) / (n * n) - 50) / 5);
}

/** The Wi-Fi join string phones read (special characters escaped). WPA3-only networks say SAE. */
export function wifiQrText(ssid: string, psk: string, security: string): string {
  const esc = (s: string) => s.replace(/([\\;,:"])/g, '\\$1');
  return `WIFI:T:${security === 'wpa3' ? 'SAE' : 'WPA'};S:${esc(ssid)};P:${esc(psk)};;`;
}
