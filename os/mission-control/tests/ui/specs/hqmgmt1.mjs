// HQMGMT1 owner-signed envelopes (operator decision R6 = D; docs/design/mgmt-envelope-api.md). Since 12 Nov the
// device ignores the owner token for trial confirm / rollback, upload activate, pack rollback, factory reset and
// signing-key rotation. This spec proves the browser builds the exact bytes the device checks: the reference test
// vector from the API doc (also asserted by the kernel's [P-hsh-web]) is reproduced through the real UI.
import { createHash, createPrivateKey, sign as edSign, createPublicKey, verify as edVerify } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const SEED = '6b'.repeat(32);
const PKCS8 = Buffer.from('302e020100300506032b657004220420' + SEED, 'hex');
const PEM = `-----BEGIN PRIVATE KEY-----\n${PKCS8.toString('base64')}\n-----END PRIVATE KEY-----\n`;
const VECTOR = '48514d474d54310001001400000102030405060708090a0b0c0d0e0f01020304050607082a0000000000000000000000000000000900000000'
  + '0000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5adfc7bdb7a85f4a16d96169c3d59a2637e34e004846b5'
  + '5873df5462fe705386a8214d8586401693da20cf3c71ee015f959484845e59d366148730d8ec761d020e';
const ENV = { format: 'HQMGMT1', device_id: '000102030405060708090a0b0c0d0e0f', epoch: '0102030405060708', next_seq: 42, generation: 9, digest: '5a'.repeat(32), owner_enrolled: true };

const priv = createPrivateKey({ key: PKCS8, format: 'der', type: 'pkcs8' });
const pub = createPublicKey(priv);
const PUBHEX = pub.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
function parse(hex) {
  const b = Buffer.from(hex, 'hex');
  return { len: b.length, msg: b.readUInt16LE(10), seq: Number(b.readBigUInt64LE(36)), arg: b.readBigUInt64LE(44), gen: Number(b.readBigUInt64LE(52)), digest: b.subarray(60, 92).toString('hex'),
    sigOk: b.length === 156 && edVerify(null, Buffer.concat([Buffer.from('HQMGMT1-SIG'), b.subarray(0, 92)]), pub, b.subarray(92)) };
}

export default async function (t) {
  const { page, ok, go, vis } = t;

  // 1. Pure layout + standard Ed25519 = the reference vector.
  const { envelopeBody } = await import(pathToFileURL(join(ROOT, 'os/mission-control/src/store/hqmgmt1.ts')).href);
  const body = Buffer.from(envelopeBody({ msg: 20, deviceId: Buffer.from(ENV.device_id, 'hex'), epoch: Buffer.from(ENV.epoch, 'hex'), seq: 42n, arg: 0n, generation: 9n, digest: Buffer.from(ENV.digest, 'hex') }));
  const sig = edSign(null, Buffer.concat([Buffer.from('HQMGMT1-SIG'), body]), priv);
  ok(body.toString('hex') + sig.toString('hex') === VECTOR, 'envelope body layout + signature reproduce the API-doc test vector');

  // A mocked device with the vector's envelope state; record every POST.
  const posts = [];
  const state = { config: { state: 'trial', generation: 9, floor: 8, on_trial: true, needs_confirm: true, window_s: 300, elapsed_s: 10, auto_rollback: true, health: '', envelope: ENV }, upload: null, chunks: [] };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', async (route) => {
    const u = new URL(route.request().url()), m = route.request().method(), p = u.pathname;
    const form = m === 'POST' && p !== '/api/upload/chunk' ? Object.fromEntries(new URLSearchParams(route.request().postData() ?? '')) : {};
    if (m === 'POST') posts.push({ p, form });
    if (p === '/api/health') return route.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/session') return route.fulfill(json({ csrf: 'x', next_seq: 1 }));
    if (p === '/api/config') return route.fulfill(json(state.config));
    if (p === '/api/anchor') return route.fulfill(json({ vendor_key: null, owner_key: PUBHEX, owner_enrolled: true, owner_generation: 1, config_files_verified_by: 'owner', can: 'rotate', device_id: ENV.device_id, state: 'protected' }));
    if (p === '/api/config/confirm') return route.fulfill(json({ ok: true, committed: true, generation: 9 }));
    if (p === '/api/factory-reset') return route.fulfill(json({ ok: true, note: 'Factory reset sealed.' }));
    if (p === '/api/upload' && m === 'GET') return route.fulfill(json({ store: true, chunk_max: 16384, recent: [], types: [{ type: 'ioc', cap: 16 << 20, generation: 3, source: 'store', applies: 'now', rollback_to: state.rollbackTo ?? null }], in_flight: state.upload }));
    if (p === '/api/upload/begin') { state.upload = { id: 'u1', type: 'ioc', size: Number(form.size), received: 0, verified: false }; return route.fulfill(json({ ok: true, id: 'u1', chunk_max: 16384 })); }
    if (p === '/api/upload/chunk') { state.chunks.push(route.request().postDataBuffer()); return route.fulfill(json({ ok: true })); }
    if (p === '/api/upload/finish') {
      const box = Buffer.concat(state.chunks);
      state.upload = { ...state.upload, verified: true, type_code: 2, generation: 4, digest: state.tamper ? 'ff'.repeat(32) : createHash('sha256').update(box.subarray(512)).digest('hex') };
      return route.fulfill(json({ ok: true, generation: 4 }));
    }
    if (p === '/api/upload/activate') { state.upload = null; return route.fulfill(json({ ok: true, generation: 4, staged: false })); }
    if (p === '/api/upload/rollback') return route.fulfill(json({ ok: true, generation: 3, staged: false }));
    if (p === '/api/upload/abort') { state.upload = null; return route.fulfill(json({ ok: true })); }
    return route.fulfill(json({}, 404));
  });

  // Import the vector's key as this browser's signing key.
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup'); await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);

  // 2. Keep it on the trial banner → the exact reference envelope, no owner token.
  await page.click('[aria-label="Configuration trial"] button:has-text("Keep it")');
  const sheet = page.locator('.approve-sheet');
  await sheet.waitFor({ state: 'visible' });
  ok(await sheet.getAttribute('aria-modal') === 'true' && (await sheet.locator('input[type=password]').count()) === 0 && await sheet.locator('label:has-text("Reason") input').inputValue() === 'works for me',
    'Keep it opens the Approve sheet (modal, reason prefilled, no owner-key field: the signature is the authority)');
  await t.approve({ reason: 'probe reason' }); await page.waitForTimeout(1200);
  const c = posts.find((x) => x.p === '/api/config/confirm');
  ok(c && c.form.envelope === VECTOR, 'Keep it sends the reference envelope byte-for-byte (msg 20, seq 42, generation 9, digest 5a…)');
  ok(c && !('owner_key' in c.form) && c.form.reason === 'probe reason', 'Keep it sends no owner token, only reason + envelope');

  // 3. Factory reset → msg 32, arg 0, generation 0, zero digest, valid signature.
  state.config = { ...state.config, envelope: { ...ENV, next_seq: 43 } };
  await page.click('[aria-label="Settings"] >> text=Factory reset'); await page.waitForTimeout(200);
  await page.fill('input[autocomplete=off]', 'ERASE');
  await page.locator('button', { hasText: /factory reset|Erase/i }).last().click(); await t.approve({ reason: 'probe reason' }); await page.waitForTimeout(1200);
  const fr = posts.find((x) => x.p === '/api/factory-reset');
  const fe = fr && parse(fr.form.envelope ?? '');
  ok(fe && fe.sigOk && fe.msg === 32 && fe.seq === 43 && fe.arg === 0n && fe.gen === 0 && /^0+$/.test(fe.digest) && !('owner_key' in fr.form), 'factory reset: signed msg 32 bound to nothing else, no owner token');

  // 4. Pack upload → begin with the token once, activate with msg 23 bound to type code, staged generation, digest.
  state.config = { ...state.config, envelope: { ...ENV, next_seq: 44 } };
  await page.click('[aria-label="Settings"] >> text=Signed packs'); await page.waitForTimeout(200);
  const pack = Buffer.concat([Buffer.alloc(512, 7), Buffer.from('1.2.3.4 bad\n')]);
  await page.click('[aria-label="Pack type"] .l0-chip >> nth=2');
  await page.setInputFiles('input[type=file]', { name: 'ioc.pack', mimeType: 'application/octet-stream', buffer: pack });
  await page.click('button:has-text("Upload and verify")'); await t.approve({ key: 'label-key-123' }); await page.waitForTimeout(2000);
  const secondKey = await vis(page.locator('.approve-sheet'));
  const act = posts.find((x) => x.p === '/api/upload/activate');
  const ae = act && parse(act.form.envelope ?? '');
  ok(ae && ae.sigOk && ae.msg === 23 && ae.arg === 2n && ae.gen === 4 && ae.digest === createHash('sha256').update(pack.subarray(512)).digest('hex') && !('owner_key' in act.form),
    'activate: signed msg 23 bound to type code, staged generation and the digest of the bytes the browser sent');
  ok(!secondKey && posts.find((x) => x.p === '/api/upload/begin')?.form.owner_key === 'label-key-123', 'pack upload asks for the owner key once (begin, in the masked sheet), not twice');

  // 5. Device reports different bytes → the browser refuses to sign and aborts.
  state.tamper = true; state.chunks = []; state.config = { ...state.config, envelope: { ...ENV, next_seq: 45 } };
  const before = posts.filter((x) => x.p === '/api/upload/activate').length;
  await page.setInputFiles('input[type=file]', { name: 'ioc.pack', mimeType: 'application/octet-stream', buffer: pack });
  await page.click('button:has-text("Upload and verify")'); await t.approve({ key: 'label-key-123' }); await page.waitForTimeout(2000);
  ok(posts.filter((x) => x.p === '/api/upload/activate').length === before && posts.some((x) => x.p === '/api/upload/abort') && await vis(page.locator('text=verified different bytes')),
    'digest mismatch: nothing is signed or activated, the upload is aborted, and the owner is told why');
  state.tamper = false;

  // 6. Pack rollback: no button without a device-reported target; with rollback_to, a signed msg 24.
  ok(!(await vis(page.locator('td button:has-text("Roll back")'))), 'no rollback offered when the device reports nothing to roll back to');
  state.rollbackTo = 3; state.config = { ...state.config, envelope: { ...ENV, next_seq: 46 } };
  await go('/admin/identity', 1200); await page.click('[aria-label="Settings"] >> text=Signed packs'); await page.waitForTimeout(300);
  await page.click('td button:has-text("Roll back to 3")'); await t.approve(); await page.waitForTimeout(1200);
  const rbp = posts.find((x) => x.p === '/api/upload/rollback');
  const re = rbp && parse(rbp.form.envelope ?? '');
  ok(re && re.sigOk && re.msg === 24 && re.arg === 2n && re.gen === 3 && /^0+$/.test(re.digest) && !('owner_key' in rbp.form), 'pack rollback: signed msg 24 bound to type code and the rollback_to generation, no owner token');
}
