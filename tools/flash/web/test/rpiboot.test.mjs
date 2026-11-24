// SPDX-License-Identifier: AGPL-3.0-only
// rpiboot against the mock BCM2712: boot ROM, re-enumeration, file server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { runRpiboot, bootMessage, parseFileMessage, pickEndpoints, RpiLink, sendSecondStage, ROM_FILTERS } from '../src/rpiboot.mjs';
import { waitForDevice, ReenumTimeout } from '../src/reenum.mjs';
import { FileSet } from '../src/bootfiles.mjs';
import { MockUsb, RomFw, FileServerFw, romDevice, fsDevice } from './mock-usb.mjs';

const te = new TextEncoder();
const FAST = { reenumMs: 2000, pollMs: 5, settleMs: 1 };

function bootSet() {
  return new FileSet(new Map([
    ['bootcode5.bin', new Uint8Array(randomBytes(78332))], // > 16 KiB: several bulk transfers
    ['bootmain', new Uint8Array(randomBytes(556668))],
    ['config.txt', te.encode('boot_ramdisk=1\n')],
    ['boot.img', new Uint8Array(randomBytes(40000))],
  ]));
}
const SCRIPT = [
  { cmd: 0, name: 'bootmain' }, { cmd: 1, name: 'bootmain' },
  { cmd: 0, name: '*serial' }, // metadata
  { cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' },
  { cmd: 0, name: 'pieeprom.upd' }, { cmd: 1, name: 'pieeprom.upd' }, // absent: both answered "nothing"
  { cmd: 0, name: 'boot.img' }, { cmd: 1, name: 'boot.img' },
  { cmd: 2, name: 'Done' },
];
const asMap = (fs) => Object.fromEntries(fs.files);

function rig({ permitAfterReset = true, serialIndex } = {}) {
  const usb = new MockUsb();
  const files = bootSet();
  const fsFw = new FileServerFw({ usb, script: SCRIPT, files: asMap(files) });
  const rom = new RomFw({ usb, expect: files.get('bootcode5.bin'), next: () => fsDevice(fsFw, serialIndex === undefined ? {} : { serialIndex }), permitAfterReset });
  const romDev = romDevice(rom, serialIndex === undefined ? {} : { serialIndex });
  usb.plug(romDev);
  return { usb, files, rom, fsFw, romDev };
}

test('boot message: LE32 length + 20-byte signature', () => {
  const m = bootMessage(0x12345, new Uint8Array(20).fill(7));
  assert.equal(m.length, 24);
  assert.deepEqual([...m.subarray(0, 4)], [0x45, 0x23, 0x01, 0x00]);
  assert.ok(m.subarray(4).every((x) => x === 7));
  assert.throws(() => bootMessage(1, new Uint8Array(19)));
});

test('file message: command + NUL-terminated name', () => {
  const b = new Uint8Array(260); b[0] = 1; b.set(te.encode('config.txt'), 4);
  assert.deepEqual(parseFileMessage(b), { command: 1, name: 'config.txt' });
});

test('endpoints come from the descriptors; two-interface fallback is interface 1, ep 3/4', () => {
  assert.deepEqual(pickEndpoints({ interfaces: [{ interfaceNumber: 0, alternate: { endpoints: [
    { endpointNumber: 5, direction: 'out', type: 'bulk' }, { endpointNumber: 6, direction: 'in', type: 'bulk' }] } }] }), { iface: 0, out: 5, in: 6 });
  assert.deepEqual(pickEndpoints({ interfaces: [{ interfaceNumber: 0 }, { interfaceNumber: 1 }] }), { iface: 1, out: 3, in: 4 });
});

test('full exchange: ROM -> second stage -> re-enumeration -> file server -> Done', async () => {
  const { usb, files, rom, fsFw, romDev } = rig();
  const log = [];
  const r = await runRpiboot({ usb, device: romDev, files, waitForDevice, log: (s) => log.push(s), ...FAST });
  assert.equal(rom.ret, 0, 'ROM accepted the second stage byte for byte');
  assert.equal(rom.length, 78332);
  assert.ok(rom.bulkSizes.every((n) => n <= 16384) && rom.bulkSizes.length >= 5, `ROM bulk sizes ${rom.bulkSizes}`);
  assert.equal(r.end, 'done');
  assert.deepEqual(r.served, ['bootmain', 'config.txt', 'boot.img']);
  assert.deepEqual(r.missing, ['pieeprom.upd']);
  assert.deepEqual(r.metadata, { serial: true });
  assert.deepEqual(fsFw.answers, ['size bootmain=556668', 'read bootmain=556668', 'size config.txt=15', 'read config.txt=15',
    'size pieeprom.upd=0', 'read pieeprom.upd=none', 'size boot.img=40000', 'read boot.img=40000']);
  assert.ok(fsFw.bulkSizes.every((n) => n <= 16384));
  assert.deepEqual(usb.events.slice(0, 3), ['connect bcm2712-rom', 'disconnect bcm2712-rom', 'connect bcm2712-2nd']);
  assert.ok(log.some((l) => l.includes('iSerialNumber=0 -> boot ROM')));
  assert.ok(log.some((l) => l.includes('iSerialNumber=1 -> file server')));
});

test('re-enumeration without a kept permission: waits, then asks the user (gesture) and continues', async () => {
  const { usb, files, romDev } = rig({ permitAfterReset: false });
  let asked = 0;
  const askUser = async (filters) => { asked++; return usb.requestDevice({ filters }); };
  const r = await runRpiboot({ usb, device: romDev, files, waitForDevice, askUser, ...FAST, reenumMs: 100 });
  assert.equal(asked, 1);
  assert.equal(r.end, 'done');
});

test('re-enumeration without permission and no way to ask: a clear timeout, not a hang', async () => {
  const { usb, files, romDev } = rig({ permitAfterReset: false });
  await assert.rejects(runRpiboot({ usb, device: romDev, files, waitForDevice, ...FAST, reenumMs: 50 }), ReenumTimeout);
});

test('browser refuses GET_DESCRIPTOR: stage falls back to order (first = ROM)', async () => {
  const { usb, files, romDev } = rig({ serialIndex: null });
  const r = await runRpiboot({ usb, device: romDev, files, waitForDevice, ...FAST });
  assert.equal(r.end, 'done');
});

test('ROM rejects a corrupted second stage: error names the return code', async () => {
  const usb = new MockUsb();
  const files = bootSet();
  const rom = new RomFw({ usb, expect: new Uint8Array(78332), next: () => null });
  const dev = romDevice(rom); usb.plug(dev);
  const link = await RpiLink.open(dev);
  await assert.rejects(sendSecondStage(link, files.get('bootcode5.bin'), { settleMs: 1 }), /refused by the boot ROM: 0x4001/);
});

test('missing bootcode5.bin is refused before any transfer', async () => {
  const { usb, romDev } = rig();
  await assert.rejects(runRpiboot({ usb, device: romDev, files: new FileSet(), waitForDevice, ...FAST }), /bootcode5.bin/);
});

test('waitForDevice ignores the stale pre-reset device object', async () => {
  const usb = new MockUsb();
  const a = romDevice(new RomFw({ usb, expect: new Uint8Array(1), next: () => null }));
  usb.plug(a);
  await assert.rejects(waitForDevice(usb, { filters: ROM_FILTERS, previous: a, timeoutMs: 30, pollMs: 5 }), ReenumTimeout);
});
