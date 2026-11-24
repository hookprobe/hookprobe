// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { Sha256, sha256, crc32, hex } from '../src/hash.mjs';
import { readTar, makeTar, FileSet } from '../src/bootfiles.mjs';

const te = new TextEncoder();

test('sha256: FIPS 180-4 vectors', () => {
  assert.equal(hex(sha256(te.encode(''))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(hex(sha256(te.encode('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(hex(sha256(te.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
});

test('sha256: incremental over odd splits equals node:crypto', () => {
  for (const len of [0, 1, 55, 56, 63, 64, 65, 1000, 70001]) {
    const data = new Uint8Array(randomBytes(len));
    const h = new Sha256();
    for (let i = 0; i < len;) { const n = Math.min(1 + (i % 97), len - i); h.update(data.subarray(i, i + n)); i += n; }
    assert.equal(hex(h.digest()), createHash('sha256').update(data).digest('hex'), `len ${len}`);
  }
});

test('crc32: IEEE check value', () => {
  assert.equal(crc32(te.encode('123456789')), 0xcbf43926);
});

test('bootfiles: ustar round trip, 2712 prefix, overlay wins, traversal refused', () => {
  const tar = makeTar({ '2712/bootcode5.bin': te.encode('ROMCODE'), '2712/config.txt': te.encode('old'), '2711/bootcode4.bin': te.encode('x') });
  assert.equal(readTar(tar).size, 3);
  const fs = FileSet.fromBootfiles(tar, '2712', { 'config.txt': te.encode('new') });
  assert.deepEqual([...fs.files.keys()].sort(), ['bootcode5.bin', 'config.txt']);
  assert.equal(new TextDecoder().decode(fs.get('config.txt')), 'new');
  assert.equal(new TextDecoder().decode(fs.get('BOOTCODE5.BIN')), 'ROMCODE');
  assert.equal(fs.get('../etc/passwd'), null);
  assert.equal(fs.get('/abs'), null);
});
