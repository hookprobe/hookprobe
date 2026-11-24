// SPDX-License-Identifier: AGPL-3.0-only
// HQFL client against the mock stub, and the whole flasher (rpiboot -> stub -> write) end to end.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { StubLink, StubClient, flashWithStub, encode, decode, T, S, Refused, StubError, SECTOR, MAX_CHUNK } from '../src/stubproto.mjs';
import { flash } from '../src/flasher.mjs';
import { FileSet } from '../src/bootfiles.mjs';
import { sha256, hex, bytesEqual } from '../src/hash.mjs';
import { MockUsb, StubFw, RomFw, FileServerFw, stubDevice, romDevice, fsDevice, fakeSigned, fakeVerify } from './mock-usb.mjs';

const te = new TextEncoder();

/** A disk image with the signed boot image placed at SLOT_OFF (the stand-in for HEQK8-A.IMG on p1). */
const SLOT_OFF = 64 * SECTOR;
function fixture({ sectors = 1024, svn = 5, tamper = false } = {}) {
  const boot = fakeSigned(new Uint8Array(randomBytes(30000)), svn);
  if (tamper) boot[100] ^= 1;
  const disk = new Uint8Array(randomBytes(sectors * SECTOR));
  disk.set(boot, SLOT_OFF);
  return { boot, disk };
}
const slotCheck = (disk, verdict) => {
  const b = disk.subarray(SLOT_OFF);
  const r = fakeVerify(b.subarray(0, verdict ? 30000 + 38 : 0));
  return r.status === S.OK && bytesEqual(r.hash, verdict.hash) ? 1 : 0;
};
const readerOf = (disk) => async (off, n) => disk.slice(off, off + n);

async function openStub(fw) {
  const dev = stubDevice(fw);
  return StubLink.open(dev);
}

test('frames: round trip; no frame length is a multiple of 512 (no ZLP needed)', () => {
  const f = encode(T.HELLO, 7, new Uint8Array([1, 0, 0, 0]));
  assert.deepEqual({ ...decode(f), payload: [...decode(f).payload] }, { version: 1, type: 1, status: 0, seq: 7, payload: [1, 0, 0, 0] });
  for (let n = 0; n <= MAX_CHUNK; n += SECTOR) assert.notEqual((16 + 16 + n) % 512, 0); // WRITE frames
  assert.throws(() => encode(T.VDATA, 1, new Uint8Array(512 - 16)), /multiple of 512/);
  assert.throws(() => decode(f.subarray(0, f.length - 1)), /length/);
});

test('stub: full exchange — verify, write, read-back, slot check', async () => {
  const { boot, disk } = fixture();
  const fw = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck });
  const progress = [];
  const r = await flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk), onProgress: (o) => progress.push(o) });
  assert.equal(r.verdict.svn, 5);
  assert.equal(r.digest, hex(sha256(disk)));
  assert.equal(r.slots & 1, 1);
  assert.ok(bytesEqual(fw.disk.subarray(0, disk.length), disk), 'the eMMC holds the image byte for byte');
  assert.equal(progress.at(-1), disk.length);
  assert.equal(r.resumes, 0);
});

test('stub: a bad signature is refused and NOTHING is written', async () => {
  const { boot, disk } = fixture({ tamper: true });
  const fw = new StubFw({ verifyBoot: fakeVerify });
  await assert.rejects(flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk) }),
    (e) => e instanceof Refused && e.status === S.SIG_FAIL);
  assert.equal(fw.writes, 0);
  assert.equal(fw.writeReqs, 0, 'the client never even sent a WRITE');
  assert.ok(fw.disk.every((x) => x === 0));
});

test('stub: an SVN below the floor is refused (rollback), nothing written', async () => {
  const { boot, disk } = fixture({ svn: 2 });
  const fw = new StubFw({ verifyBoot: fakeVerify, svnFloor: 3 });
  await assert.rejects(flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk) }),
    (e) => e instanceof Refused && e.status === S.ROLLBACK);
  assert.equal(fw.writes, 0);
});

test('stub: a host that skips verification gets NOT_VERIFIED on WRITE; the stub writes nothing', async () => {
  const fw = new StubFw({ verifyBoot: fakeVerify });
  const cl = new StubClient(await openStub(fw));
  await cl.hello();
  const r1 = await cl.call(T.WBEGIN, new Uint8Array(8).fill(0).map((_, i) => (i === 1 ? 2 : 0)));
  assert.equal(r1.status, S.NOT_VERIFIED);
  const w = new Uint8Array(16 + SECTOR);
  const r2 = await cl.call(T.WRITE, w);
  assert.equal(r2.status, S.NOT_VERIFIED);
  assert.equal(fw.writes, 0);
});

test('stub: a short write in flight is resumed from the stub\'s next offset; image still exact', async () => {
  const { boot, disk } = fixture();
  const fw = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck, faults: { shortWriteOn: new Set([2, 5]), crcFlipOn: new Set([7]) } });
  const r = await flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk) });
  assert.equal(r.resumes, 3);
  assert.equal(r.shortWrites, 2);
  assert.ok(bytesEqual(fw.disk.subarray(0, disk.length), disk));
  assert.equal(r.digest, hex(sha256(disk)));
});

test('stub: a persistent I/O error ends with an error that says where the stub stands', async () => {
  const { boot, disk } = fixture();
  const fw = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck, faults: { ioFailAt: 3 * MAX_CHUNK + 512 } });
  await assert.rejects(flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk) }),
    (e) => e instanceof StubError && e.status === S.IO && e.next === 3 * MAX_CHUNK);
});

test('stub: read-back that does not match what was sent fails FINISH and the MBR sector is cleared', async () => {
  const { boot, disk } = fixture();
  const fw = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck });
  const orig = fw.handle.bind(fw);
  fw.handle = (b) => { if (b[5] === T.FINISH) fw.disk[SECTOR * 10] ^= 0xff; return orig(b); }; // bit rot after write
  await assert.rejects(flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk) }),
    (e) => e.status === S.READBACK_MISMATCH);
  assert.ok(fw.disk.subarray(0, SECTOR).every((x) => x === 0));
});

test('stub: an image whose slot does not hold the verified boot image fails the slot check', async () => {
  const { boot, disk } = fixture();
  const other = fixture();
  disk.set(other.boot, SLOT_OFF); // verified A, but the disk carries a different (validly signed) B
  const fw = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck });
  await assert.rejects(flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk) }),
    (e) => e.status === S.SLOT_MISMATCH);
});

test('stub: image larger than the eMMC is refused before verification', async () => {
  const { boot } = fixture();
  const fw = new StubFw({ sectors: 16, verifyBoot: fakeVerify });
  await assert.rejects(flashWithStub(await openStub(fw), { bootImage: boot, diskLen: 32 * SECTOR, readAt: async () => new Uint8Array(0) }), (e) => e.status === S.RANGE);
  assert.equal(fw.state, 'ready');
});

test('END TO END: rpiboot (ROM, file server) -> stub re-enumerates (new permission) -> verify -> write -> read-back', async () => {
  const usb = new MockUsb();
  const { boot, disk } = fixture();
  const stubFw = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck });
  const files = new FileSet(new Map([
    ['bootcode5.bin', new Uint8Array(randomBytes(78332))], ['config.txt', te.encode('boot_ramdisk=1\n')], ['boot.img', new Uint8Array(randomBytes(20000))],
  ]));
  const fsFw = new FileServerFw({ usb, files: Object.fromEntries(files.files), next: () => stubDevice(stubFw), permitAfterReset: false, script: [
    { cmd: 0, name: 'config.txt' }, { cmd: 1, name: 'config.txt' }, { cmd: 0, name: 'boot.img' }, { cmd: 1, name: 'boot.img' }, { cmd: 2, name: 'Done' }] });
  const rom = new RomFw({ usb, expect: files.get('bootcode5.bin'), next: () => fsDevice(fsFw) });
  const romDev = romDevice(rom); usb.plug(romDev);
  const log = [];
  let asked = 0;
  const r = await flash({ usb, device: romDev, files, bootImage: boot, diskLen: disk.length, readAt: readerOf(disk),
    askUser: async (filters) => { asked++; return usb.requestDevice({ filters }); }, log: (s) => log.push(s),
    reenumMs: 2000, stubWaitMs: 100, pollMs: 5, settleMs: 1 });
  assert.equal(rom.ret, 0);
  assert.deepEqual(r.rpiboot.served, ['config.txt', 'boot.img']);
  assert.equal(asked, 1, 'one Reconnect click for the stub (new VID/PID)');
  assert.ok(bytesEqual(stubFw.disk.subarray(0, disk.length), disk));
  assert.equal(r.digest, hex(sha256(disk)));
  assert.deepEqual(usb.events, ['connect bcm2712-rom', 'disconnect bcm2712-rom', 'connect bcm2712-2nd', 'disconnect bcm2712-2nd', 'connect heqk-stub']);
  for (const l of log) console.log(`    | ${l}`);
});

test('stub: a DEBUG stub (development keys) is refused unless explicitly allowed; nothing written', async () => {
  const { boot, disk } = fixture();
  const fw = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck, release: false });
  await assert.rejects(flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk) }), /DEBUG build/);
  assert.equal(fw.writes, 0);
  const fw2 = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck, release: false });
  const r = await flashWithStub(await openStub(fw2), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk), allowDebugStub: true });
  assert.equal(r.written, true);
});

test('stub: verify-only run returns the verdict and writes nothing', async () => {
  const { boot, disk } = fixture();
  const fw = new StubFw({ sectors: 2048, verifyBoot: fakeVerify, slotCheck });
  const r = await flashWithStub(await openStub(fw), { bootImage: boot, diskLen: disk.length, readAt: readerOf(disk), verifyOnly: true });
  assert.equal(r.written, false);
  assert.equal(r.verdict.svn, 5);
  assert.equal(fw.writeReqs, 0);
});
