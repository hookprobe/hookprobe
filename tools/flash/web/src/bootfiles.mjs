// SPDX-License-Identifier: AGPL-3.0-only
// The set of files the rpiboot file server hands to the BCM2712 second stage.
//
// Raspberry Pi ships the 2712 boot-stage firmware as `bootfiles.bin`, a POSIX ustar archive with one
// directory per SoC (`2712/bootcode5.bin`, `2712/bootmain`, `2712/memsys0N.bin`, ...). The flasher reads
// that archive in the browser (no server), keeps the `2712/` entries, and lays its own files over them:
// `config.txt` and `boot.img` (the heqk flash stub ramdisk). A ustar header is a 512-byte block: name
// [0,100), size in octal [124,136), type flag at 156, prefix [345,500); data follows in 512-byte blocks.

const td = new TextDecoder();

function field(b, off, len) {
  let end = off;
  while (end < off + len && b[end] !== 0) end++;
  return td.decode(b.subarray(off, end));
}

/** Parse a ustar archive into Map<path, Uint8Array>. Regular files only; anything malformed throws. */
export function readTar(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const out = new Map();
  let off = 0;
  while (off + 512 <= b.length) {
    const h = b.subarray(off, off + 512);
    if (h.every((x) => x === 0)) break; // end-of-archive marker
    const name = field(h, 0, 100);
    const prefix = td.decode(h.subarray(257, 263)).startsWith('ustar') ? field(h, 345, 155) : '';
    const sizeStr = field(h, 124, 12).trim();
    if (!/^[0-7]+$/.test(sizeStr)) throw new Error(`bootfiles: bad size field for "${name}"`);
    const size = parseInt(sizeStr, 8);
    const type = h[156];
    const data = off + 512;
    if (data + size > b.length) throw new Error(`bootfiles: "${name}" runs past the end of the archive`);
    if (type === 0x30 || type === 0) out.set(prefix ? `${prefix}/${name}` : name, b.slice(data, data + size));
    off = data + Math.ceil(size / 512) * 512;
  }
  return out;
}

/**
 * The files served for one SoC: `<soc>/` entries of the archive with the prefix stripped, then `overlay`
 * (name -> bytes) on top. Lookups are exact first, then case-insensitive (the firmware asks in lower case).
 */
export class FileSet {
  constructor(entries = new Map()) {
    this.files = new Map(entries);
  }

  static fromBootfiles(tarBytes, soc = '2712', overlay = {}) {
    const set = new FileSet();
    for (const [path, data] of readTar(tarBytes)) {
      if (path.startsWith(`${soc}/`) && path.length > soc.length + 1) set.files.set(path.slice(soc.length + 1), data);
    }
    for (const [n, d] of Object.entries(overlay)) set.files.set(n, d);
    return set;
  }

  set(name, data) { this.files.set(name, data); return this; }

  get(name) {
    if (!name || name.includes('..') || name.startsWith('/') || name.includes('\\')) return null;
    if (this.files.has(name)) return this.files.get(name);
    const lc = name.toLowerCase();
    for (const [n, d] of this.files) if (n.toLowerCase() === lc) return d;
    return null;
  }
}

/** Build a ustar archive (tests and tooling; the device never sees this). */
export function makeTar(entries) {
  const te = new TextEncoder();
  const parts = [];
  for (const [name, data] of Object.entries(entries)) {
    const h = new Uint8Array(512);
    h.set(te.encode(name).subarray(0, 100), 0);
    h.set(te.encode('0000644\0'), 100);
    h.set(te.encode('0000000\0'), 108);
    h.set(te.encode('0000000\0'), 116);
    h.set(te.encode(data.length.toString(8).padStart(11, '0') + '\0'), 124);
    h.set(te.encode('00000000000\0'), 136);
    h[156] = 0x30;
    h.set(te.encode('ustar\0' + '00'), 257);
    h.fill(0x20, 148, 156);
    let sum = 0;
    for (const x of h) sum += x;
    h.set(te.encode(sum.toString(8).padStart(6, '0') + '\0 '), 148);
    parts.push(h, data, new Uint8Array((512 - (data.length % 512)) % 512));
  }
  parts.push(new Uint8Array(1024));
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
