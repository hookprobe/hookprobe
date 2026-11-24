// SPDX-License-Identifier: AGPL-3.0-only
// The browser flasher end to end (ADR 0070): rpiboot loads the heqk flash stub, the stub re-enumerates with
// its HQFL vendor interface, the stub verifies the signed boot image, then the disk image is written and
// read back. The page supplies the user gestures (requestDevice) and the bytes; this module has no DOM.

import { runRpiboot } from './rpiboot.mjs';
import { waitForDevice } from './reenum.mjs';
import { StubLink, flashWithStub } from './stubproto.mjs';

// pid.codes test VID/PID — a PLACEHOLDER for development only. ADR 0070 Q2: the stub needs its own USB ID
// before anything ships (pid.codes allocation or a vendor ID).
export const STUB_FILTERS = [{ vendorId: 0x1209, productId: 0x0001 }];

/**
 * @param {object} o
 *   usb        navigator.usb
 *   device     the BCM2712 the user picked (USB boot mode, 0a5c:2712)
 *   files      FileSet: 2712 boot firmware + config.txt + boot.img (the stub)
 *   bootImage  Uint8Array: the signed A/B slot file (heqk8-a.img) from the disk image
 *   diskLen, readAt(offset, length) -> Uint8Array : the disk image
 *   askUser    (filters) => Promise<USBDevice> — runs requestDevice from a click (permission after reset)
 *   verifyOnly HELLO + signature verdict, no write (metal step M2)
 *   allowDebugStub  accept a stub built with development keys (bench only)
 */
export async function flash({ usb, device, files, bootImage, diskLen, readAt, askUser = null, log = () => {}, onProgress, stubFilters = STUB_FILTERS, verifyOnly = false, allowDebugStub = false, reenumMs = 15000, stubWaitMs = 30000, pollMs = 250, settleMs = 1000 }) {
  log('step 1/3: rpiboot (boot ROM -> second stage -> file server)');
  const rb = await runRpiboot({ usb, device, files, waitForDevice, askUser, log, reenumMs, pollMs, settleMs });
  log('step 2/3: waiting for the heqk flash stub');
  const stub = await waitForDevice(usb, { filters: stubFilters, timeoutMs: stubWaitMs, pollMs, askUser, what: 'heqk flash stub', log });
  const link = await StubLink.open(stub);
  try {
    log('step 3/3: verify, write, read back');
    const r = await flashWithStub(link, { bootImage, diskLen, readAt, log, onProgress, verifyOnly, allowDebugStub });
    return { rpiboot: rb, ...r };
  } finally {
    await link.close();
  }
}
