// SPDX-License-Identifier: AGPL-3.0-only
// Offline stand-ins for navigator.usb, a BCM2712 in USB boot mode (boot ROM, then the second-stage file
// server) and the heqk flash stub (HQFL). They implement the WebUSB calls the flasher uses and fail the
// test on any out-of-protocol transfer, so a passing run proves the order and sizes the host sent.
// Not a model of real silicon timing; the metal test plan in ADR 0070 covers that.

import { sha256, Sha256, crc32, bytesEqual } from '../src/hash.mjs';
import { decode, encode, T, S, HDR, SECTOR, MAX_CHUNK, BOOT_IMG_MAX, STUB_IFACE, rdU32, rdU64 } from '../src/stubproto.mjs';

const gone = () => Object.assign(new Error('The device was disconnected.'), { name: 'NotFoundError' });
const ok = (extra = {}) => ({ status: 'ok', ...extra });
const nval = (s) => s.value | (s.index << 16);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class MockUsb {
  constructor() { this.devices = []; this.listeners = { connect: new Set(), disconnect: new Set() }; this.events = []; }
  async getDevices() { return this.devices.filter((d) => d.permitted && !d.gone); }
  addEventListener(t, f) { this.listeners[t].add(f); }
  removeEventListener(t, f) { this.listeners[t].delete(f); }
  /** Simulate the chooser: grants permission to the first matching present device. */
  async requestDevice({ filters }) {
    const d = this.devices.find((x) => !x.gone && filters.some((f) => x.vendorId === f.vendorId && x.productId === f.productId));
    if (!d) throw Object.assign(new Error('No device selected.'), { name: 'NotFoundError' });
    d.permitted = true;
    return d;
  }
  plug(dev) {
    this.devices.push(dev);
    this.events.push(`connect ${dev.label}`);
    if (dev.permitted) for (const f of [...this.listeners.connect]) f({ device: dev });
  }
  unplug(dev) {
    dev.gone = true;
    this.events.push(`disconnect ${dev.label}`);
    for (const f of [...this.listeners.disconnect]) f({ device: dev });
  }
}

/** A WebUSB-shaped device whose transfers are handled by `fw`. */
export class MockDevice {
  constructor({ vendorId, productId, label, interfaces, serialIndex, fw, permitted = true }) {
    Object.assign(this, { vendorId, productId, label, fw, permitted, serialIndex });
    this.configuration = { configurationValue: 1, interfaces };
    this.opened = false; this.claimed = new Set(); this.gone = false;
    fw.dev = this;
  }
  check() { if (this.gone) throw gone(); }
  async open() { this.check(); this.opened = true; }
  async close() { this.opened = false; }
  async selectConfiguration() { this.check(); }
  async claimInterface(n) { this.check(); if (!this.opened) throw new Error('claim before open'); this.claimed.add(n); }
  async clearHalt() { this.check(); }
  guard() { this.check(); if (!this.opened || this.claimed.size === 0) throw new Error('transfer before open/claim'); }
  async controlTransferIn(setup, len) {
    this.check();
    if (setup.requestType === 'standard' && setup.request === 6 && setup.value === 0x0100) {
      if (this.serialIndex === null) return { status: 'stall' };
      const d = new Uint8Array(18); d[0] = 18; d[1] = 1; d[16] = this.serialIndex;
      return ok({ data: new DataView(d.buffer, 0, Math.min(len, 18)) });
    }
    this.guard();
    return this.fw.controlIn(setup, len);
  }
  async controlTransferOut(setup, data) { this.guard(); return this.fw.controlOut(setup, data); }
  async transferOut(ep, data) { this.guard(); return this.fw.bulkOut(ep, new Uint8Array(data)); }
  async transferIn(ep, len) { this.guard(); return this.fw.bulkIn(ep, len); }
}

const bootIface = () => [{ interfaceNumber: 0, alternate: { interfaceClass: 0xff, interfaceSubclass: 0, interfaceProtocol: 0, endpoints: [
  { endpointNumber: 1, direction: 'out', type: 'bulk', packetSize: 512 },
  { endpointNumber: 2, direction: 'in', type: 'bulk', packetSize: 512 }] } }];

/** Boot ROM: boot message, second stage, return code; then resets into `next()`. */
export class RomFw {
  constructor({ usb, expect, next, reenumMs = 5, permitAfterReset = true, log }) {
    Object.assign(this, { usb, expect, next, reenumMs, permitAfterReset, log: log ?? (() => {}) });
    this.state = 'msg'; this.want = 0; this.buf = []; this.bulkSizes = []; this.ret = null;
  }
  controlOut(setup) {
    const n = nval(setup);
    if (setup.requestType !== 'vendor' || setup.request !== 0) throw new Error(`ROM: unexpected control OUT ${JSON.stringify(setup)}`);
    if (this.want !== 0) throw new Error('ROM: new announce while bulk data is pending');
    if (this.state === 'msg' && n !== 24) throw new Error(`ROM: boot message must be 24 bytes, got ${n}`);
    if (this.state === 'code' && n !== this.length) throw new Error(`ROM: announced ${n}, boot message said ${this.length}`);
    if (this.state === 'ret') throw new Error('ROM: OUT after the second stage');
    this.want = n; this.buf = [];
    return ok();
  }
  bulkOut(ep, data) {
    if (ep !== 1) throw new Error(`ROM: bulk OUT on ep ${ep}`);
    if (data.length > 16384) throw new Error(`ROM: bulk transfer of ${data.length} > 16 KiB`);
    if (data.length > this.want) throw new Error(`ROM: ${data.length} bytes, only ${this.want} announced`);
    this.bulkSizes.push(data.length);
    this.buf.push(data); this.want -= data.length;
    if (this.want === 0) {
      const all = Buffer.concat(this.buf);
      if (this.state === 'msg') { this.length = all.readInt32LE(0); this.sig = all.subarray(4, 24); this.state = 'code'; }
      else if (this.state === 'code') {
        this.code = new Uint8Array(all);
        this.ret = bytesEqual(sha256(this.code), sha256(this.expect)) ? 0 : 0x4001;
        this.state = 'ret';
      }
    }
    return ok({ bytesWritten: data.length });
  }
  controlIn(setup, len) {
    if (this.state !== 'ret' || nval(setup) !== 4 || len !== 4) throw new Error(`ROM: unexpected control IN (state ${this.state}, ${nval(setup)})`);
    const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, this.ret, true);
    if (this.ret === 0) this.reset();
    return ok({ data: new DataView(b.buffer) });
  }
  bulkIn() { throw new Error('ROM: no bulk IN in this protocol'); }
  reset() {
    setTimeout(() => {
      this.usb.unplug(this.dev);
      setTimeout(() => { const d = this.next(); d.permitted = this.permitAfterReset; this.usb.plug(d); }, this.reenumMs);
    }, 1);
  }
}

/** Second stage: asks for `script` ({cmd, name}) and checks each answer against `files` (what it expects). */
export class FileServerFw {
  constructor({ usb, script, files, next, reenumMs = 5, permitAfterReset = true }) {
    Object.assign(this, { usb, script: [...script], files, next, reenumMs, permitAfterReset });
    this.pending = null; this.answers = []; this.bulkSizes = [];
  }
  controlIn(setup, len) {
    if (this.pending) throw new Error(`file server: read while ${this.pending.kind} answer is pending`);
    if (nval(setup) !== 260 || len !== 260) throw new Error(`file server: message read of ${nval(setup)}`);
    const m = this.script.shift();
    if (!m) throw gone();
    const b = new Uint8Array(260);
    new DataView(b.buffer).setInt32(0, m.cmd, true);
    b.set(new TextEncoder().encode(m.name), 4);
    if (m.cmd === 2) this.reset();
    else if (m.name === '' ) this.pending = { kind: 'zero', m };
    else if (m.name[0] === '*') this.pending = { kind: 'zero', m };
    else if (m.cmd === 0) this.pending = { kind: 'size', m };
    else if (m.cmd === 1) this.pending = { kind: 'read', m };
    return ok({ data: new DataView(b.buffer) });
  }
  controlOut(setup) {
    const p = this.pending; const n = nval(setup);
    if (!p) throw new Error(`file server: unsolicited control OUT (${n})`);
    const f = this.files[p.m.name];
    if (p.kind === 'zero') { if (n !== 0) throw new Error(`file server: ${p.m.name || '(empty)'} needs a zero reply, got ${n}`); this.pending = null; if (p.m.name === '') this.reset(); }
    else if (p.kind === 'size') {
      const want = f ? f.length : 0;
      if (n !== want) throw new Error(`file server: size of ${p.m.name} answered ${n}, expected ${want}`);
      this.answers.push(`size ${p.m.name}=${n}`); this.pending = null;
    } else if (p.kind === 'read') {
      if (!f) { if (n !== 0) throw new Error(`file server: ${p.m.name} does not exist but host sent ${n}`); this.answers.push(`read ${p.m.name}=none`); this.pending = null; }
      else { if (n !== f.length) throw new Error(`file server: ${p.m.name} announced ${n} != ${f.length}`); this.pending = { kind: 'bulk', m: p.m, want: n, got: [] }; if (n === 0) this.pending = null; }
    } else throw new Error(`file server: control OUT during ${p.kind}`);
    return ok();
  }
  bulkOut(ep, data) {
    const p = this.pending;
    if (!p || p.kind !== 'bulk') throw new Error('file server: unsolicited bulk OUT');
    if (data.length > 16384) throw new Error(`file server: bulk transfer ${data.length} > 16 KiB`);
    this.bulkSizes.push(data.length);
    p.got.push(data); p.want -= data.length;
    if (p.want < 0) throw new Error('file server: more bytes than announced');
    if (p.want === 0) {
      const all = new Uint8Array(Buffer.concat(p.got));
      if (!bytesEqual(sha256(all), sha256(this.files[p.m.name]))) throw new Error(`file server: ${p.m.name} content differs`);
      this.answers.push(`read ${p.m.name}=${all.length}`); this.pending = null;
    }
    return ok({ bytesWritten: data.length });
  }
  bulkIn() { throw new Error('file server: no bulk IN'); }
  reset() {
    setTimeout(() => {
      this.usb.unplug(this.dev);
      if (this.next) setTimeout(() => { const d = this.next(); d.permitted = this.permitAfterReset; this.usb.plug(d); }, this.reenumMs);
    }, 1);
  }
}

export const STUB_VID = 0x1209; // placeholder (pid.codes test range) until ADR 0070 Q2 assigns an ID
export const STUB_PID = 0x0001;

/**
 * The heqk flash stub, HQFL side. `verifyBoot(bytes)` stands in for boot_abi::verify (the real stub runs the
 * same hybrid verifier as OTA); `slotCheck(disk, verdict)` stands in for locating HEQK8-A.IMG through FAT.
 * Fault knobs: shortWriteOn (Set of WRITE request ordinals truncated in flight), crcFlipOn (Set of WRITE
 * ordinals with one data byte flipped in flight), ioFailAt (sector offset that always fails).
 */
export class StubFw {
  constructor({ sectors = 4096, verifyBoot, slotCheck = () => 1, faults = {}, release = true, svnFloor = 1 }) {
    Object.assign(this, { verifyBoot, slotCheck, faults, release, svnFloor });
    this.disk = new Uint8Array(sectors * SECTOR); this.sectors = sectors;
    this.state = 'init'; this.out = []; this.writes = 0; this.writeReqs = 0; this.sectorWrites = 0;
    this.log = []; this.vbuf = null; this.verdict = null;
  }
  respond(type, seq, status, payload = new Uint8Array(0)) { this.out.push(encode(type, seq, payload, status)); this.log.push(`${type.toString(16)}:${status}`); }
  ack(seq, next, status = S.OK) { const p = new Uint8Array(8); new DataView(p.buffer).setBigUint64(0, BigInt(next), true); this.respond(status === S.OK ? T.ACK : T.ERROR, seq, status, p); }
  bulkOut(ep, frame) {
    if (ep !== 1) throw new Error(`stub: OUT on ep ${ep}`);
    if (frame.length % SECTOR === 0) throw new Error(`stub: frame of ${frame.length} B is a multiple of 512 (needs a ZLP)`);
    let f = frame, written = frame.length;
    const isWrite = frame.length > 5 && frame[5] === T.WRITE;
    if (isWrite) this.writeReqs++;
    if (isWrite && this.faults.shortWriteOn?.has(this.writeReqs)) { written = frame.length - 100; f = frame.subarray(0, written); }
    if (isWrite && this.faults.crcFlipOn?.has(this.writeReqs)) { f = new Uint8Array(frame); f[HDR + 16 + 7] ^= 0xff; }
    this.handle(f);
    return ok({ bytesWritten: written });
  }
  bulkIn(ep) {
    if (ep !== 2) throw new Error(`stub: IN on ep ${ep}`);
    const r = this.out.shift();
    if (!r) throw new Error('stub: IN with no response queued');
    return ok({ data: new DataView(r.buffer) });
  }
  controlIn() { throw new Error('stub: no control transfers in HQFL'); }
  controlOut() { throw new Error('stub: no control transfers in HQFL'); }
  handle(b) {
    let m;
    const seq = b.length >= 12 ? rdU32(b, 8) : 0;
    try { m = decode(b); } catch { return this.ack(seq, this.next ?? 0, S.BAD_FRAME); }
    const p = m.payload;
    switch (m.type) {
      case T.HELLO: {
        if (rdU32(p) !== 1) return this.ack(m.seq, 0, S.BAD_VERSION);
        const i = new Uint8Array(64); const v = new DataView(i.buffer);
        v.setUint32(0, 1, true); v.setUint32(4, MAX_CHUNK, true); v.setBigUint64(8, BigInt(this.sectors), true);
        v.setBigUint64(16, BigInt(this.svnFloor), true); i[24] = this.release ? 1 : 0;
        this.state = 'ready';
        return this.respond(T.INFO, m.seq, S.OK, i);
      }
      case T.VBEGIN: {
        if (this.state !== 'ready') return this.ack(m.seq, 0, S.BAD_STATE);
        const len = rdU32(p);
        if (len === 0 || len > BOOT_IMG_MAX) return this.ack(m.seq, 0, S.TOO_BIG);
        this.vbuf = new Uint8Array(len); this.vnext = 0; this.state = 'verifying';
        return this.ack(m.seq, 0);
      }
      case T.VDATA: {
        if (this.state !== 'verifying') return this.ack(m.seq, 0, S.BAD_STATE);
        const off = rdU32(p); const d = p.subarray(8);
        if (off !== this.vnext) return this.ack(m.seq, this.vnext, S.BAD_OFFSET);
        if (off + d.length > this.vbuf.length) return this.ack(m.seq, this.vnext, S.RANGE);
        this.vbuf.set(d, off); this.vnext += d.length;
        return this.ack(m.seq, this.vnext);
      }
      case T.VEND: {
        if (this.state !== 'verifying' || this.vnext !== this.vbuf.length) return this.ack(m.seq, 0, S.BAD_STATE);
        const r = this.verifyBoot(this.vbuf);
        if (r.status === S.OK && r.svn < this.svnFloor) r.status = S.ROLLBACK;
        const out = new Uint8Array(40); new DataView(out.buffer).setBigUint64(0, BigInt(r.svn ?? 0), true);
        if (r.hash) out.set(r.hash, 8);
        this.state = r.status === S.OK ? 'verified' : 'refused';
        this.verdict = r.status === S.OK ? r : null;
        return this.respond(T.VERDICT, m.seq, r.status, out);
      }
      case T.WBEGIN: {
        if (this.state !== 'verified') return this.ack(m.seq, 0, S.NOT_VERIFIED);
        const len = rdU64(p);
        if (len % SECTOR || len === 0 || len > this.disk.length) return this.ack(m.seq, 0, S.RANGE);
        this.wlen = len; this.next = 0; this.hash = new Sha256(); this.state = 'writing';
        return this.ack(m.seq, 0);
      }
      case T.WRITE: {
        if (this.state !== 'writing') return this.ack(m.seq, 0, S.NOT_VERIFIED);
        const off = rdU64(p); const crc = rdU32(p, 8); const d = p.subarray(16);
        if (off !== this.next) return this.ack(m.seq, this.next, S.BAD_OFFSET);
        if (d.length === 0 || d.length % SECTOR || off + d.length > this.wlen) return this.ack(m.seq, this.next, S.RANGE);
        if (crc32(d) !== crc) return this.ack(m.seq, this.next, S.BAD_CRC);
        if (this.faults.ioFailAt !== undefined && off <= this.faults.ioFailAt && this.faults.ioFailAt < off + d.length) return this.ack(m.seq, this.next, S.IO);
        this.disk.set(d, off); this.writes++; this.sectorWrites += d.length / SECTOR;
        this.hash.update(d); this.next += d.length;
        return this.ack(m.seq, this.next);
      }
      case T.FINISH: {
        const empty = new Uint8Array(33);
        if (this.state !== 'writing' || this.next !== this.wlen) return this.respond(T.RESULT, m.seq, S.BAD_STATE, empty);
        const recv = this.hash.digest();
        const readback = sha256(this.disk.subarray(0, this.wlen));
        const out = new Uint8Array(33); out.set(readback, 0);
        let st = S.OK;
        if (!bytesEqual(readback, recv) || !bytesEqual(p, recv)) st = S.READBACK_MISMATCH;
        else { out[32] = this.slotCheck(this.disk, this.verdict); if (!(out[32] & 1)) st = S.SLOT_MISMATCH; }
        if (st !== S.OK) this.disk.fill(0, 0, SECTOR); // never leave a bootable half-image
        this.state = 'done';
        return this.respond(T.RESULT, m.seq, st, out);
      }
      case T.ABORT: { if (this.writes) this.disk.fill(0, 0, SECTOR); this.state = 'ready'; return this.ack(m.seq, 0); }
      default: return this.ack(m.seq, 0, S.BAD_FRAME);
    }
  }
}

export const stubDevice = (fw, opts = {}) => new MockDevice({
  vendorId: STUB_VID, productId: STUB_PID, label: 'heqk-stub', serialIndex: 3, fw, ...opts,
  interfaces: [{ interfaceNumber: 0, alternate: { interfaceClass: STUB_IFACE.classCode, interfaceSubclass: STUB_IFACE.subclassCode, interfaceProtocol: STUB_IFACE.protocolCode, endpoints: [
    { endpointNumber: 1, direction: 'out', type: 'bulk', packetSize: 512 },
    { endpointNumber: 2, direction: 'in', type: 'bulk', packetSize: 512 }] } }],
});

export const romDevice = (fw, opts = {}) => new MockDevice({ vendorId: 0x0a5c, productId: 0x2712, label: 'bcm2712-rom', serialIndex: 0, interfaces: bootIface(), fw, ...opts });
export const fsDevice = (fw, opts = {}) => new MockDevice({ vendorId: 0x0a5c, productId: 0x2712, label: 'bcm2712-2nd', serialIndex: 1, interfaces: bootIface(), fw, ...opts });

// ── fixtures: a stand-in "signed" boot image (NOT the real hybrid format — the stub's verifier is boot_abi) ──
const te = new TextEncoder();
export function fakeSigned(payload, svn = 5) {
  const h = sha256(new Uint8Array([...te.encode(`svn${svn}`), ...payload]));
  return new Uint8Array([...te.encode('HQSIG'), svn, ...payload, ...h]);
}
export function fakeVerify(img) {
  if (img.length < 38 || new TextDecoder().decode(img.subarray(0, 5)) !== 'HQSIG') return { status: S.BAD_HEADER, svn: 0 };
  const svn = img[5]; const payload = img.subarray(6, img.length - 32); const sig = img.subarray(img.length - 32);
  const want = sha256(new Uint8Array([...te.encode(`svn${svn}`), ...payload]));
  return bytesEqual(sig, want) ? { status: S.OK, svn, hash: sha256(payload) } : { status: S.SIG_FAIL, svn };
}
export { sleep };
