// SPDX-License-Identifier: AGPL-3.0-only
// rpiboot for BCM2712 (CM5) over a WebUSB-shaped device — our own implementation, written from the protocol
// as documented below (ADR 0070). Transport-agnostic: `device` is anything with the WebUSB USBDevice methods
// used here (open, selectConfiguration, claimInterface, controlTransferIn/Out, transferOut, clearHalt, close),
// so the same code runs against navigator.usb in Chrome and against the mock in test/.
//
// Protocol (BCM2712 USB device boot, VID 0x0a5c PID 0x2712):
//   * One interface (two on old SoCs: then interface 1, the vendor one), one bulk OUT and one bulk IN endpoint.
//   * "write N bytes": a vendor control OUT, bRequest 0, wValue = N & 0xffff, wIndex = N >> 16, no data stage,
//     then N bytes on bulk OUT. N = 0 is the control transfer alone (the "nothing" reply).
//   * "read N bytes": a vendor control IN, bRequest 0, wValue/wIndex = N, data stage of N bytes.
//   * Stage 1 (boot ROM, device descriptor iSerialNumber index 0 or 3): write the 24-byte boot message
//     {LE32 length, 20-byte signature (zero when unsigned)}, write the second stage (bootcode5.bin), read a
//     LE32 return code (0 = accepted). The device then resets and re-enumerates.
//   * Stage 2 (second stage, any other iSerialNumber): a file server. Read a 260-byte message
//     {LE32 command, 256-byte NUL-terminated file name}; command 0 GetFileSize -> reply with the size in the
//     control transfer alone (wValue/wIndex) or "write 0" if unknown; 1 ReadFile -> "write" the file or
//     "write 0"; 2 Done -> stop. An empty name also ends the exchange (reply "write 0"). A name starting
//     with '*' is board metadata (serial, MAC, ...): recorded, answered with "write 0".
//   * Bulk OUT is sent in <= 16 KiB transfers. No zero-length packet: the length is announced up front.

export const RPI_VID = 0x0a5c;
export const BCM2712_PID = 0x2712;
export const ROM_FILTERS = [{ vendorId: RPI_VID, productId: BCM2712_PID }];
export const MAX_BULK = 16 * 1024;
export const BOOT_MSG_LEN = 24;
export const FILE_MSG_LEN = 260;
export const CMD = Object.freeze({ GET_FILE_SIZE: 0, READ_FILE: 1, DONE: 2 });
const CMD_NAME = ['GetFileSize', 'ReadFile', 'Done'];

export class UsbError extends Error {
  constructor(msg, { gone = false } = {}) {
    super(msg);
    this.name = 'UsbError';
    this.gone = gone; // the device disconnected (expected at stage boundaries)
  }
}

const isGone = (e) => e && (e.name === 'NotFoundError' || e.name === 'NetworkError' || e.gone === true);

function withTimeout(p, ms, what) {
  let t;
  return Promise.race([
    p.finally(() => clearTimeout(t)),
    new Promise((_, rej) => { t = setTimeout(() => rej(new UsbError(`${what}: timed out after ${ms} ms`)), ms); }),
  ]);
}

export const lenSetup = (n) => ({ requestType: 'vendor', recipient: 'device', request: 0, value: n & 0xffff, index: (n >>> 16) & 0xffff });

/** The bulk endpoints + interface of a boot-mode device, from its descriptors (fallback: the fixed numbers). */
export function pickEndpoints(configuration) {
  const ifaces = configuration?.interfaces ?? [];
  const iface = ifaces.length > 1 ? ifaces[1] : ifaces[0];
  const num = iface ? iface.interfaceNumber : 0;
  const eps = iface?.alternate?.endpoints ?? iface?.alternates?.[0]?.endpoints ?? [];
  const out = eps.find((e) => e.direction === 'out' && e.type === 'bulk');
  const inn = eps.find((e) => e.direction === 'in' && e.type === 'bulk');
  const two = ifaces.length > 1;
  return { iface: num, out: out ? out.endpointNumber : (two ? 3 : 1), in: inn ? inn.endpointNumber : (two ? 4 : 2) };
}

/** An opened boot-mode device: the write/read primitives of the protocol. */
export class RpiLink {
  constructor(device, eps, { timeoutMs = 20000 } = {}) {
    this.device = device;
    this.eps = eps;
    this.timeoutMs = timeoutMs;
  }

  static async open(device, opts = {}) {
    try {
      await device.open();
      if (!device.configuration) await device.selectConfiguration(1);
      const eps = pickEndpoints(device.configuration);
      await device.claimInterface(eps.iface);
      return new RpiLink(device, eps, opts);
    } catch (e) {
      throw new UsbError(`open ${hex4(device.vendorId)}:${hex4(device.productId)}: ${e.message}`, { gone: isGone(e) });
    }
  }

  /** iSerialNumber index from the raw device descriptor; null if the browser refuses the request. */
  async serialIndex() {
    try {
      const r = await withTimeout(this.device.controlTransferIn(
        { requestType: 'standard', recipient: 'device', request: 6, value: 0x0100, index: 0 }, 18), 2000, 'GET_DESCRIPTOR');
      if (r.status !== 'ok' || !r.data || r.data.byteLength < 17) return null;
      return r.data.getUint8(16);
    } catch {
      return null;
    }
  }

  async control(n, what) {
    let r;
    try {
      r = await withTimeout(this.device.controlTransferOut(lenSetup(n)), this.timeoutMs, what);
    } catch (e) {
      throw new UsbError(`${what}: control OUT failed: ${e.message}`, { gone: isGone(e) });
    }
    if (r.status !== 'ok') throw new UsbError(`${what}: control OUT status ${r.status}`);
  }

  /** Announce N then send N bytes on bulk OUT (N may be 0). Returns bytes sent; throws on a short write. */
  async write(data, what = 'write') {
    const b = data ?? new Uint8Array(0);
    await this.control(b.length, what);
    let sent = 0;
    while (sent < b.length) {
      const n = Math.min(MAX_BULK, b.length - sent);
      let r;
      try {
        r = await withTimeout(this.device.transferOut(this.eps.out, b.subarray(sent, sent + n)), this.timeoutMs, what);
      } catch (e) {
        throw new UsbError(`${what}: bulk OUT failed at ${sent}/${b.length}: ${e.message}`, { gone: isGone(e) });
      }
      if (r.status === 'stall') {
        await this.device.clearHalt('out', this.eps.out).catch(() => {});
        throw new UsbError(`${what}: endpoint stalled at ${sent}/${b.length}`);
      }
      if (r.status !== 'ok' || r.bytesWritten !== n) {
        throw new UsbError(`${what}: short bulk write at ${sent}/${b.length} (${r.bytesWritten} of ${n}, ${r.status})`);
      }
      sent += n;
    }
    return sent;
  }

  async read(n, what = 'read') {
    let r;
    try {
      r = await withTimeout(this.device.controlTransferIn(lenSetup(n), n), this.timeoutMs, what);
    } catch (e) {
      throw new UsbError(`${what}: control IN failed: ${e.message}`, { gone: isGone(e) });
    }
    if (r.status !== 'ok' || !r.data) throw new UsbError(`${what}: control IN status ${r.status}`);
    return new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength);
  }

  async close() {
    try { await this.device.close(); } catch { /* already gone */ }
  }
}

const hex4 = (n) => (n ?? 0).toString(16).padStart(4, '0');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function bootMessage(length, signature = null) {
  const m = new Uint8Array(BOOT_MSG_LEN);
  new DataView(m.buffer).setInt32(0, length, true);
  if (signature) {
    if (signature.length !== 20) throw new Error('boot message signature must be 20 bytes');
    m.set(signature, 4);
  }
  return m;
}

export function parseFileMessage(b) {
  if (b.length < FILE_MSG_LEN) throw new UsbError(`file server: short message (${b.length} of ${FILE_MSG_LEN} bytes)`);
  const command = new DataView(b.buffer, b.byteOffset, 4).getInt32(0, true);
  const raw = b.subarray(4, FILE_MSG_LEN);
  const end = raw.indexOf(0);
  const name = new TextDecoder().decode(raw.subarray(0, end < 0 ? raw.length : end));
  return { command, name };
}

/** Stage 1: hand the boot ROM the second stage. Resolves when the ROM accepted it. */
export async function sendSecondStage(link, code, { signature = null, settleMs = 1000, log = () => {} } = {}) {
  if (!code || !code.length) throw new Error('second stage (bootcode5.bin) is missing or empty');
  await link.write(bootMessage(code.length, signature), 'boot message');
  await link.write(code, 'second stage');
  log(`rpiboot: second stage sent (${code.length} bytes)`);
  await sleep(settleMs);
  let ret;
  try {
    const r = await link.read(4, 'second stage return code');
    ret = new DataView(r.buffer, r.byteOffset, 4).getInt32(0, true);
  } catch (e) {
    // The second stage may already be resetting the USB core; the next enumeration decides.
    if (e.gone) { log('rpiboot: device reset before the return code (continuing)'); return null; }
    throw e;
  }
  if (ret !== 0) throw new UsbError(`second stage refused by the boot ROM: 0x${(ret >>> 0).toString(16)}`);
  log('rpiboot: second stage accepted (return code 0)');
  return ret;
}

/** Stage 2: serve files until Done. Returns { served: [names], missing: [names], metadata: {k: v}, end }. */
export async function fileServer(link, files, { log = () => {}, maxIdleRetries = 5, retryMs = 1000 } = {}) {
  const res = { served: [], missing: [], metadata: {}, end: null };
  let idle = 0;
  for (;;) {
    let msg;
    try {
      msg = parseFileMessage(await link.read(FILE_MSG_LEN, 'file server message'));
      idle = 0;
    } catch (e) {
      if (e.gone) { res.end = 'gone'; return res; }
      if (++idle > maxIdleRetries) throw e;
      await sleep(retryMs);
      continue;
    }
    const { command, name } = msg;
    if (name.length === 0) {
      await link.write(null, 'end');
      res.end = 'empty-name';
      return res;
    }
    if (name[0] === '*' && command !== CMD.DONE) {
      res.metadata[name.slice(1)] = true;
      await link.write(null, 'metadata ack');
      continue;
    }
    log(`rpiboot: ${CMD_NAME[command] ?? `command ${command}`} ${name}`);
    if (command === CMD.GET_FILE_SIZE) {
      const f = files.get(name);
      if (f) await link.control(f.length, `size of ${name}`);
      else { res.missing.push(name); await link.write(null, `no ${name}`); }
    } else if (command === CMD.READ_FILE) {
      const f = files.get(name);
      if (f) { await link.write(f, `file ${name}`); res.served.push(name); } else { await link.write(null, `no ${name}`); }
    } else if (command === CMD.DONE) {
      res.end = 'done';
      return res;
    } else {
      throw new UsbError(`file server: unknown command ${command} (${name})`);
    }
  }
}

/**
 * The whole rpiboot exchange: ROM -> second stage -> file server, across re-enumeration.
 * @param {object} o { usb, device?, files: FileSet, waitForDevice, askUser?, log, timeouts }
 *   `device` is the USBDevice the user picked (requestDevice, needs a gesture: the page does that).
 * Resolves with the file-server result once the second stage says Done; the stub boots after that.
 */
export async function runRpiboot({ usb, device, files, waitForDevice, askUser = null, log = () => {}, reenumMs = 15000, pollMs = 250, settleMs = 1000, maxStages = 4 }) {
  let dev = device;
  let previous = null;
  const ss = files.get('bootcode5.bin');
  for (let stage = 0; stage < maxStages; stage++) {
    if (!dev) {
      dev = await waitForDevice(usb, { filters: ROM_FILTERS, previous, timeoutMs: reenumMs, pollMs, askUser, what: 'CM5 (re-enumerated)', log });
    }
    const link = await RpiLink.open(dev);
    const idx = await link.serialIndex();
    // Without the descriptor (browser refused), the first device is the ROM and every later one the file server.
    const isRom = idx === null ? stage === 0 : idx === 0 || idx === 3;
    log(`rpiboot: ${hex4(dev.vendorId)}:${hex4(dev.productId)} iSerialNumber=${idx ?? '?'} -> ${isRom ? 'boot ROM' : 'file server'}`);
    try {
      if (isRom) {
        await sendSecondStage(link, ss, { log, settleMs });
      } else {
        const r = await fileServer(link, files, { log });
        log(`rpiboot: file server ${r.end}; served ${r.served.join(', ') || 'nothing'}`);
        if (r.end === 'done' || r.end === 'empty-name') return r;
        // gone mid-exchange: the second stage reset; the next enumeration continues
      }
    } finally {
      await link.close();
    }
    previous = dev;
    dev = null;
  }
  throw new UsbError(`rpiboot: no Done after ${maxStages} enumerations`);
}
