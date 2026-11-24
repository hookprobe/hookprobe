// SPDX-License-Identifier: AGPL-3.0-only
// The HQFL vendor protocol: browser <-> heqk flash stub (ADR 0070 D4). Host side only; the stub is a separate
// heqk build that is NOT written yet.
//
// Transport: one vendor-class interface (class 0xff, subclass 0x48 'H', protocol 0x01), one bulk OUT and one
// bulk IN endpoint. Every message is ONE bulk transfer; a frame's length is never a multiple of 512 (the
// high-speed max packet), so the transfer always ends in a short packet and neither side needs a ZLP — the
// encoder enforces it. The stub answers every request with exactly one response frame.
//
// Frame (little-endian), 16-byte header then payload:
//   0  magic "HQFL"   4  version (1)   5  type   6  status (responses; 0 in requests)   7  reserved (0)
//   8  seq u32 (request seq, echoed in the response)   12  payload length u32
//
// Requests (host -> stub)                        Response (stub -> host)
//   0x01 HELLO   u32 host version                 0x81 INFO    (layout in parseInfo)
//   0x02 VBEGIN  u32 boot image length            0x82 ACK     u64 next
//   0x03 VDATA   u32 offset, u32 0, data           0x82 ACK     u64 next
//   0x04 VEND    -                                0x84 VERDICT u64 svn, 32 B payload hash (status != 0: refused)
//   0x05 WBEGIN  u64 disk length                   0x82 ACK     u64 next (0)
//   0x06 WRITE   u64 offset, u32 crc32, u32 0, data (n * 512 B)   0x82 ACK u64 next
//   0x07 FINISH  32 B sha-256 of everything sent  0x87 RESULT  32 B read-back sha-256, u8 slot flags
//   0x08 ABORT   -                                0x82 ACK     u64 0
// Any request may instead get 0xEE ERROR: u64 next (where the stub expects the host to continue).

import { Sha256, crc32, bytesEqual, hex } from './hash.mjs';

export const STUB_IFACE = { classCode: 0xff, subclassCode: 0x48, protocolCode: 0x01 };
export const VERSION = 1;
export const HDR = 16;
export const SECTOR = 512;
export const MAX_CHUNK = 64 * 1024; // data bytes per VDATA / WRITE
export const MAX_FRAME = HDR + 16 + MAX_CHUNK;
export const BOOT_IMG_MAX = 5 * 1024 * 1024; // the A/B slot size HBoot loads (otaimg::IMG_MAX)
export const T = Object.freeze({
  HELLO: 0x01, VBEGIN: 0x02, VDATA: 0x03, VEND: 0x04, WBEGIN: 0x05, WRITE: 0x06, FINISH: 0x07, ABORT: 0x08,
  INFO: 0x81, ACK: 0x82, VERDICT: 0x84, RESULT: 0x87, ERROR: 0xee,
});
export const S = Object.freeze({
  OK: 0, BAD_FRAME: 1, BAD_VERSION: 2, BAD_STATE: 3, TOO_BIG: 4, BAD_HEADER: 5, SIG_FAIL: 6, ROLLBACK: 7,
  BAD_OFFSET: 8, BAD_CRC: 9, IO: 10, RANGE: 11, READBACK_MISMATCH: 12, SLOT_MISMATCH: 13, NOT_VERIFIED: 14,
});
export const STATUS_NAME = Object.fromEntries(Object.entries(S).map(([k, v]) => [v, k]));
/** Status codes a retry of the same request may cure. */
const TRANSIENT = new Set([S.BAD_FRAME, S.BAD_CRC, S.IO]);
const MAGIC = [0x48, 0x51, 0x46, 0x4c]; // "HQFL"

export class StubError extends Error {
  constructor(msg, status = null) {
    super(msg);
    this.name = 'StubError';
    this.status = status;
  }
}

export class Refused extends StubError {
  constructor(status) {
    super(`stub refused the image: ${STATUS_NAME[status] ?? status}`, status);
    this.name = 'Refused';
  }
}

export function encode(type, seq, payload = new Uint8Array(0), status = 0) {
  const f = new Uint8Array(HDR + payload.length);
  f.set(MAGIC, 0);
  f[4] = VERSION; f[5] = type; f[6] = status;
  const v = new DataView(f.buffer);
  v.setUint32(8, seq, true);
  v.setUint32(12, payload.length, true);
  f.set(payload, HDR);
  if (f.length % SECTOR === 0) throw new Error(`frame of ${f.length} bytes is a multiple of 512 (would need a ZLP)`);
  if (f.length > MAX_FRAME) throw new Error(`frame of ${f.length} bytes exceeds ${MAX_FRAME}`);
  return f;
}

export function decode(b) {
  if (b.length < HDR) throw new StubError(`frame shorter than its header (${b.length} bytes)`);
  if (!MAGIC.every((x, i) => b[i] === x)) throw new StubError('bad frame magic');
  const v = new DataView(b.buffer, b.byteOffset, b.length);
  const len = v.getUint32(12, true);
  if (b.length !== HDR + len) throw new StubError(`frame length ${b.length} != ${HDR} + ${len}`);
  return { version: b[4], type: b[5], status: b[6], seq: v.getUint32(8, true), payload: b.subarray(HDR) };
}

const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const cat = (...a) => { const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
export const rdU64 = (b, off = 0) => Number(new DataView(b.buffer, b.byteOffset, b.length).getBigUint64(off, true));
export const rdU32 = (b, off = 0) => new DataView(b.buffer, b.byteOffset, b.length).getUint32(off, true);

export const req = {
  hello: () => u32(VERSION),
  vbegin: (len) => u32(len),
  vdata: (off, data) => cat(u32(off), u32(0), data),
  wbegin: (len) => u64(len),
  write: (off, data) => cat(u64(off), u32(crc32(data)), u32(0), data),
  finish: (digest) => digest,
};

/** INFO payload (64 B): u32 version, u32 max chunk, u64 eMMC sectors, u64 SVN floor, u8 release(1)/debug(0),
 *  u8 eMMC cache on, u8 wear A, u8 wear B, 4 reserved, 32 B stub build hash. */
export function parseInfo(p) {
  if (p.length < 64) throw new StubError(`INFO payload ${p.length} < 64`);
  return {
    version: rdU32(p, 0), maxChunk: rdU32(p, 4), sectors: rdU64(p, 8), svnFloor: rdU64(p, 16),
    release: p[24] === 1, cacheOn: p[25] === 1, wear: [p[26], p[27]], build: hex(p.subarray(32, 64)),
  };
}

/** A bulk pipe to the stub's vendor interface over a WebUSB-shaped device. */
export class StubLink {
  constructor(device, eps, { timeoutMs = 30000 } = {}) {
    this.device = device; this.eps = eps; this.timeoutMs = timeoutMs;
  }

  static async open(device, opts = {}) {
    await device.open();
    if (!device.configuration) await device.selectConfiguration(1);
    const iface = device.configuration.interfaces.find((i) => {
      const a = i.alternate ?? i.alternates?.[0];
      return a && a.interfaceClass === STUB_IFACE.classCode && a.interfaceSubclass === STUB_IFACE.subclassCode && a.interfaceProtocol === STUB_IFACE.protocolCode;
    });
    if (!iface) throw new StubError('no HQFL vendor interface (class ff/48/01) on this device');
    const eps = (iface.alternate ?? iface.alternates[0]).endpoints;
    const out = eps.find((e) => e.direction === 'out' && e.type === 'bulk');
    const inn = eps.find((e) => e.direction === 'in' && e.type === 'bulk');
    if (!out || !inn) throw new StubError('HQFL interface lacks a bulk IN/OUT pair');
    await device.claimInterface(iface.interfaceNumber);
    return new StubLink(device, { iface: iface.interfaceNumber, out: out.endpointNumber, in: inn.endpointNumber }, opts);
  }

  /** Send one frame. Returns bytes the browser reports written (may be short). */
  async send(frame) {
    const r = await this.device.transferOut(this.eps.out, frame);
    if (r.status === 'stall') { await this.device.clearHalt('out', this.eps.out).catch(() => {}); return 0; }
    return r.bytesWritten;
  }

  async recv() {
    const r = await this.device.transferIn(this.eps.in, MAX_FRAME);
    if (r.status === 'stall') { await this.device.clearHalt('in', this.eps.in).catch(() => {}); throw new StubError('IN endpoint stalled'); }
    if (r.status !== 'ok' || !r.data) throw new StubError(`IN transfer status ${r.status}`);
    return new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength);
  }

  async close() { try { await this.device.close(); } catch { /* gone */ } }
}

/** Request/response client with sequence checking. */
export class StubClient {
  constructor(link, { log = () => {} } = {}) {
    this.link = link; this.seq = 1; this.log = log;
    this.shortWrites = 0;
  }

  async call(type, payload) {
    const seq = this.seq++ >>> 0;
    const frame = encode(type, seq, payload);
    const n = await this.link.send(frame);
    if (n !== frame.length) {
      this.shortWrites++;
      this.log(`stub: short write (${n} of ${frame.length} bytes) for request ${type.toString(16)}`);
    }
    const r = decode(await this.link.recv());
    if (r.seq !== seq) throw new StubError(`response seq ${r.seq} != request seq ${seq}`);
    return r;
  }

  async hello() {
    const r = await this.call(T.HELLO, req.hello());
    if (r.type !== T.INFO || r.status !== S.OK) throw new StubError(`HELLO: ${STATUS_NAME[r.status]}`, r.status);
    const info = parseInfo(r.payload);
    if (info.version !== VERSION) throw new StubError(`stub speaks HQFL v${info.version}, flasher v${VERSION}`);
    return info;
  }

  /** Send the signed boot image (the A/B slot file); resolve with the verdict or throw Refused. */
  async verify(bootImage, chunk) {
    if (bootImage.length === 0 || bootImage.length > BOOT_IMG_MAX) throw new StubError(`boot image of ${bootImage.length} bytes (max ${BOOT_IMG_MAX})`);
    let r = await this.call(T.VBEGIN, req.vbegin(bootImage.length));
    if (r.status !== S.OK) throw new Refused(r.status);
    let off = 0, retries = 0;
    while (off < bootImage.length) {
      let n = Math.min(chunk, bootImage.length - off);
      if ((HDR + 8 + n) % SECTOR === 0) n -= 1; // keep every frame off a 512 multiple (no ZLP needed)
      r = await this.call(T.VDATA, req.vdata(off, bootImage.subarray(off, off + n)));
      const next = r.payload.length >= 8 ? rdU64(r.payload) : off;
      if (r.status === S.OK) { off = next; retries = 0; continue; }
      if ((TRANSIENT.has(r.status) || r.status === S.BAD_OFFSET) && ++retries <= 3 && next <= off) { off = next; continue; }
      throw new Refused(r.status);
    }
    r = await this.call(T.VEND, new Uint8Array(0));
    if (r.type !== T.VERDICT || r.status !== S.OK) throw new Refused(r.status);
    return { svn: rdU64(r.payload, 0), payloadHash: hex(r.payload.subarray(8, 40)) };
  }

  /**
   * Stream the disk image. `readAt(offset, length)` returns a Uint8Array (a File slice in the browser).
   * Resumes from the stub's `next` after a short write, a CRC error or a bad-offset answer (at most
   * `maxRetries` in a row); anything else throws, with `.next` = where the stub stands.
   */
  async write(diskLen, readAt, { chunk, maxRetries = 4, onProgress = () => {} } = {}) {
    if (diskLen % SECTOR !== 0) throw new StubError(`disk image length ${diskLen} is not a multiple of 512`);
    const c = Math.min(chunk, MAX_CHUNK) - (Math.min(chunk, MAX_CHUNK) % SECTOR);
    let r = await this.call(T.WBEGIN, req.wbegin(diskLen));
    if (r.status !== S.OK) throw new Refused(r.status);
    const h = new Sha256();
    let hashed = 0; // bytes of the image already in `h` (resends never hash twice)
    let off = 0, retries = 0, resumes = 0;
    while (off < diskLen) {
      const n = Math.min(c, diskLen - off);
      const data = await readAt(off, n);
      if (data.length !== n) throw new StubError(`image source returned ${data.length} of ${n} bytes at ${off}`);
      r = await this.call(T.WRITE, req.write(off, data));
      const next = r.payload.length >= 8 ? rdU64(r.payload) : -1;
      if (r.status === S.OK && next === off + n) {
        if (off + n > hashed) { h.update(data.subarray(hashed - off)); hashed = off + n; }
        off = next; retries = 0;
        onProgress(off, diskLen);
        continue;
      }
      const resumable = (TRANSIENT.has(r.status) || r.status === S.BAD_OFFSET) && next >= 0 && next <= off && next % SECTOR === 0;
      if (resumable && ++retries <= maxRetries) {
        resumes++;
        this.log(`stub: ${STATUS_NAME[r.status]} at ${off}; resuming at ${next} (retry ${retries}/${maxRetries})`);
        off = next;
        continue;
      }
      const e = new StubError(`write failed at ${off}: ${STATUS_NAME[r.status] ?? r.status} (stub next=${next})`, r.status);
      e.next = next;
      throw e;
    }
    return { digest: h.digest(), resumes };
  }

  /** Ask the stub to read the whole written range back and check the boot slots. */
  async finish(digest) {
    const r = await this.call(T.FINISH, req.finish(digest));
    if (r.type !== T.RESULT) throw new StubError(`FINISH: unexpected response ${r.type.toString(16)}`, r.status);
    const readback = r.payload.subarray(0, 32);
    const slots = r.payload[32];
    if (r.status !== S.OK) throw new StubError(`FINISH: ${STATUS_NAME[r.status]} (read-back ${hex(readback)})`, r.status);
    if (!bytesEqual(readback, digest)) throw new StubError(`read-back ${hex(readback)} != sent ${hex(digest)}`, S.READBACK_MISMATCH);
    return { readback: hex(readback), slots };
  }

  async abort() { return this.call(T.ABORT, new Uint8Array(0)); }
}

/**
 * The whole stub session: HELLO -> verify the signed boot image -> write -> FINISH (read-back).
 * Nothing is written unless the stub's verdict is OK; a refusal throws Refused before WBEGIN is sent.
 */
export async function flashWithStub(link, { bootImage, diskLen, readAt, log = () => {}, onProgress, verifyOnly = false, allowDebugStub = false } = {}) {
  const cl = new StubClient(link, { log });
  const info = await cl.hello();
  log(`stub: HQFL v${info.version}, ${info.release ? 'release' : 'DEBUG'} build ${info.build.slice(0, 16)}, eMMC ${info.sectors} sectors, SVN floor ${info.svnFloor}`);
  // A debug stub carries the development trust root (heqk-boot-key-check.sh lets it through only in debug mode).
  if (!info.release && !allowDebugStub) throw new StubError('the stub is a DEBUG build (development keys); refusing unless allowDebugStub is set');
  if (diskLen > info.sectors * SECTOR) throw new StubError(`image (${diskLen} B) larger than the eMMC (${info.sectors * SECTOR} B)`, S.RANGE);
  const chunk = Math.min(info.maxChunk, MAX_CHUNK);
  const verdict = await cl.verify(bootImage, chunk);
  log(`stub: signature OK (svn ${verdict.svn}, payload ${verdict.payloadHash.slice(0, 16)})`);
  if (verifyOnly) { log('stub: verify-only run — nothing written'); return { info, verdict, written: false }; }
  const w = await cl.write(diskLen, readAt, { chunk, onProgress });
  log(`stub: wrote ${diskLen} bytes (${w.resumes} resumes), sha-256 ${hex(w.digest)}`);
  const fin = await cl.finish(w.digest);
  log(`stub: read-back matches; slot flags 0x${fin.slots.toString(16)}`);
  return { info, verdict, written: true, digest: hex(w.digest), resumes: w.resumes, slots: fin.slots, shortWrites: cl.shortWrites };
}
