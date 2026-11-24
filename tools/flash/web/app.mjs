// SPDX-License-Identifier: AGPL-3.0-only
// Glue for index.html: file inputs -> FileSet / disk reader, buttons -> user gestures for WebUSB.
import { FileSet } from './src/bootfiles.mjs';
import { ROM_FILTERS, runRpiboot } from './src/rpiboot.mjs';
import { waitForDevice } from './src/reenum.mjs';
import { flash } from './src/flasher.mjs';

const $ = (id) => document.getElementById(id);
const logEl = $('log');
const log = (s) => { logEl.textContent += `${new Date().toISOString().slice(11, 19)} ${s}\n`; };
const bytes = async (input) => (input.files[0] ? new Uint8Array(await input.files[0].arrayBuffer()) : null);

// A device whose permission did not survive re-enumeration can only be requested from a click.
let pendingAsk = null;
function askUser(filters) {
  $('reconnect').disabled = false;
  log('Click "Reconnect" and pick the device that just appeared.');
  return new Promise((resolve, reject) => { pendingAsk = { filters, resolve, reject }; });
}
$('reconnect').addEventListener('click', async () => {
  if (!pendingAsk) return;
  const a = pendingAsk; pendingAsk = null;
  $('reconnect').disabled = true;
  try { a.resolve(await navigator.usb.requestDevice({ filters: a.filters })); } catch (e) { a.reject(e); }
});

$('go').addEventListener('click', async () => {
  if (!('usb' in navigator)) { log('This browser has no WebUSB (use Chrome or Edge, over https or localhost).'); return; }
  try {
    const device = await navigator.usb.requestDevice({ filters: ROM_FILTERS }); // must run first, inside the click
    const [tar, stub, cfg] = [await bytes($('bootfiles')), await bytes($('stub')), await bytes($('config'))];
    if (!tar || !stub) { log('Choose bootfiles.bin and the boot.img to serve first.'); return; }
    const files0 = FileSet.fromBootfiles(tar, '2712', { 'config.txt': cfg ?? new TextEncoder().encode('boot_ramdisk=1\n'), 'boot.img': stub });
    if ($('rpibootonly').checked) {
      $('go').disabled = true;
      const rb = await runRpiboot({ usb: navigator.usb, device, files: files0, waitForDevice, askUser, log });
      log(`RPIBOOT DONE: file server ${rb.end}; served ${rb.served.join(', ')}; missing ${rb.missing.join(', ') || 'none'}`);
      return;
    }
    const disk = $('disk').files[0];
    if (!disk) { log('Choose a disk image first.'); return; }
    const manifest = $('manifest').files[0] ? JSON.parse(await $('manifest').files[0].text()) : null;
    if (!manifest?.slot_a) { log('The manifest has no slot_a {offset, length}: rebuild the image with the current make-cm5-heqk-disk.sh.'); return; }
    const files = files0;
    const bootImage = new Uint8Array(await disk.slice(manifest.slot_a.offset, manifest.slot_a.offset + manifest.slot_a.length).arrayBuffer());
    const readAt = async (off, n) => new Uint8Array(await disk.slice(off, off + n).arrayBuffer());
    $('go').disabled = true;
    const r = await flash({
      usb: navigator.usb, device, files, bootImage, diskLen: disk.size, readAt, askUser, log,
      verifyOnly: $('verifyonly').checked, allowDebugStub: $('debugstub').checked,
      onProgress: (done, total) => { $('progress').value = done / total; },
    });
    if (!r.written) log(`VERIFIED (svn ${r.verdict.svn}); nothing written.`);
    else log(`DONE: ${disk.size} bytes written and read back (sha-256 ${r.digest}). Power-cycle the CM5 without nRPIBOOT.`);
  } catch (e) {
    log(`FAILED: ${e.name}: ${e.message}`);
  } finally {
    $('go').disabled = false;
  }
});
