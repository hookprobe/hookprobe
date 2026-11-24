// SPDX-License-Identifier: AGPL-3.0-only
// Waiting for a USB device to come back after it re-enumerates (WebUSB).
//
// rpiboot makes the CM5 disconnect and reappear twice: boot ROM -> second stage (file server) -> the heqk
// flash stub. Each time the page holds a dead USBDevice and must find the new one:
//   1. `navigator.usb.getDevices()` lists devices this origin already has permission for;
//   2. the `connect` event fires when such a device appears;
//   3. Chrome keeps a permission across a reconnect only for a device that reports a serial number. A device
//      without one (or with a new VID/PID, as the stub has) needs `requestDevice()` again, and that call
//      needs a user gesture — so the caller passes `askUser`, which the page wires to a "Reconnect" button.
// `previous` is the USBDevice from before the reset; it is never returned (after a disconnect the browser
// hands out a new object, so identity is the right test).

export class ReenumTimeout extends Error {
  constructor(what, ms) {
    super(`${what}: no device after ${ms} ms`);
    this.name = 'ReenumTimeout';
  }
}

export const matches = (dev, filters) =>
  filters.some((f) => (f.vendorId === undefined || dev.vendorId === f.vendorId) &&
    (f.productId === undefined || dev.productId === f.productId));

/**
 * Resolve with the first USBDevice matching `filters` that is not `previous`.
 * @param {object} usb  navigator.usb (or a mock with getDevices/addEventListener/removeEventListener)
 * @param {object} o    { filters, previous, timeoutMs, askUser?: (filters) => Promise<USBDevice>, what, log }
 */
export async function waitForDevice(usb, { filters, previous = null, timeoutMs = 15000, pollMs = 250, askUser = null, what = 'device', log = () => {} }) {
  const ok = (d) => d && d !== previous && matches(d, filters);
  for (const d of await usb.getDevices()) if (ok(d)) return d;

  let cancelEvent = () => {};
  const viaEvent = new Promise((resolve) => {
    const on = (ev) => {
      if (ok(ev.device)) { usb.removeEventListener('connect', on); resolve(ev.device); }
    };
    usb.addEventListener('connect', on);
    cancelEvent = () => usb.removeEventListener('connect', on);
  });
  // Some platforms deliver no connect event for an already-permitted device; poll getDevices too.
  let polling = true;
  const viaPoll = (async () => {
    while (polling) {
      await new Promise((r) => setTimeout(r, pollMs));
      if (!polling) return null;
      for (const d of await usb.getDevices()) if (ok(d)) return d;
    }
    return null;
  })();
  let timer;
  const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(null), timeoutMs); });

  let dev = await Promise.race([viaEvent, viaPoll.then((d) => d || new Promise(() => {})), timeout]);
  polling = false;
  clearTimeout(timer);
  cancelEvent();
  if (dev) return dev;
  if (!askUser) throw new ReenumTimeout(what, timeoutMs);
  log(`${what}: not visible without a new permission grant — waiting for the user (Reconnect)`);
  dev = await askUser(filters);
  if (!ok(dev)) throw new Error(`${what}: the device chosen does not match ${JSON.stringify(filters)}`);
  return dev;
}
