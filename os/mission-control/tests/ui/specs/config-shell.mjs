// Administration → Configuration and keys (/admin/config) and Shell (/admin/shell), canvas boards AdminConfig and
// AdminShell, against a mocked device with the shapes heqk serves (GET /api/config, /api/anchor, /api/upload with
// rollback_to + activations; POST /api/hsh?seq=). Signed actions are verified as the device verifies them.
import { createPrivateKey, createPublicKey, verify as edVerify } from 'node:crypto';

const SEED = '6b'.repeat(32);
const PKCS8 = Buffer.from('302e020100300506032b657004220420' + SEED, 'hex');
const PEM = `-----BEGIN PRIVATE KEY-----\n${PKCS8.toString('base64')}\n-----END PRIVATE KEY-----\n`;
const pub = createPublicKey(createPrivateKey({ key: PKCS8, format: 'der', type: 'pkcs8' }));
const PUBHEX = pub.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const ENV = { format: 'HQMGMT1', device_id: '000102030405060708090a0b0c0d0e0f', epoch: '0102030405060708', next_seq: 50, generation: 9, digest: '5a'.repeat(32), owner_enrolled: true };
const env = (hex) => { const b = Buffer.from(hex, 'hex'); return { msg: b.readUInt16LE(10), arg: b.readBigUInt64LE(44), gen: Number(b.readBigUInt64LE(52)), ok: b.length === 156 && edVerify(null, Buffer.concat([Buffer.from('HQMGMT1-SIG'), b.subarray(0, 92)]), pub, b.subarray(92)) }; };

export default async function (t) {
  const { page, ok, go, vis } = t;
  const posts = [];
  const st = { hsh405: false };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', async (route) => {
    const u = new URL(route.request().url()), m = route.request().method(), p = u.pathname;
    if (m === 'POST') posts.push({ p, q: u.search, body: route.request().postData() ?? '' });
    if (p === '/api/health') return route.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/session') return route.fulfill(json({ csrf: 'x', next_seq: 7 }));
    if (p === '/api/config') return route.fulfill(json({ state: 'committed', generation: 9, floor: 9, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      live: { phase: 'idle', changes: [], needs_confirm: false, window_s: 120, remaining_s: 0, last: { result: 'committed', generation: 9 }, policy_generation: 9, mgmt_ok: null, mgmt_probe: null },
      at_rest: { sealed: true, secrets_protected: true, migrated: 0, device_key: true, volatile_ram_only: false, persisted: true }, envelope: ENV }));
    if (p === '/api/anchor') return route.fulfill(json({ vendor_key: 'ab'.repeat(32), owner_key: PUBHEX, owner_enrolled: true, owner_generation: 1, config_files_verified_by: 'owner', can: 'rotate', device_id: ENV.device_id, state: 'protected', floors: { wan: { current: 9, floor: 9 }, wifi: { current: 9, floor: 9 }, policy: 9 } }));
    if (p === '/api/upload' && m === 'GET') return route.fulfill(json({ store: true, chunk_max: 16384, recent: [], in_flight: null,
      types: [{ type: 'config', cap: 16384, generation: 9, source: 'store', applies: 'next_boot', rollback_to: 8 }],
      activations: [{ seq: 1, ms: 1, type: 'config', result: 'ok', detail: 'gen 7->8 sha256:aa' }, { seq: 2, ms: 2, type: 'config', result: 'refused', detail: 'activate gen 9 bad signature' }, { seq: 3, ms: 3, type: 'config', result: 'ok', detail: 'gen 8->9 sha256:bb' }] }));
    if (p === '/api/upload/rollback') return route.fulfill(json({ ok: true, generation: 8, staged: false }));
    if (p === '/api/hsh') {
      if (st.hsh405) return route.fulfill({ status: 405, contentType: 'text/plain', body: 'method not allowed' });
      const line = (route.request().postData() ?? '').split('\n')[0];
      return route.fulfill({ status: 200, contentType: 'text/plain', body: line === 'config status' ? 'config: committed  generation 9  bundle floor 9\n' : line === 'config confirm' ? 'OK: committed generation 9\n' : `${line}: ok\n` });
    }
    return route.fulfill(json({}, 404));
  });

  // Signing key = the key the device trusts.
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup'); await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);
  ok(await vis(page.locator('[aria-label="Settings"] a[href="/admin/config"]')) && await vis(page.locator('[aria-label="Settings"] a[href="/admin/shell"]')), 'Administration links to Configuration and keys and to Shell');

  // Configuration and keys.
  await go('/admin/config', 1500);
  ok(await vis(page.locator('[aria-label="Configuration in force"] >> text=Committed · generation 9')), 'configuration in force: committed, generation 9');
  ok(await vis(page.locator('[aria-label="Who can change it"] >> text=Only your signing key')) && await vis(page.locator(`[aria-label="Who can change it"] >> text=${PUBHEX.slice(0, 8)}`)), 'who can change it: only your signing key, with its fingerprint');
  ok(await vis(page.locator('[aria-label="Stored settings"] >> text=Sealed with the device key')), 'stored settings: sealed with the device key (from at_rest)');
  ok(await vis(page.locator('[aria-label="Recent changes"] >> text=generation 8 → 9')) && await vis(page.locator('[aria-label="Recent changes"] >> text=refused')), 'journal: readable entries, refusals shown as refused');
  await page.click('button:has-text("Roll back to 8")'); await t.approve(); await page.waitForTimeout(1200);
  const rb = posts.find((x) => x.p === '/api/upload/rollback');
  const re = rb && env(new URLSearchParams(rb.body).get('envelope') ?? '');
  ok(re && re.ok && re.msg === 24 && re.arg === 9n && re.gen === 8, 'Roll back to 8: a signed msg 24 for the configuration bundle (type 9, generation 8)');

  // Shell.
  await go('/admin/shell', 1200);
  ok(await vis(page.locator('text=Role: view (read-only)')) || await vis(page.locator('.shell-info >> text=view (read-only)')), 'shell: role view and journaling are stated');
  await page.fill('#hsh-line', 'config status'); await page.keyboard.press('Enter'); await page.waitForTimeout(800);
  const q = posts.find((x) => x.p === '/api/hsh');
  ok(q && q.q === '?seq=7' && q.body === 'config status' && await vis(page.locator('.shell-screen >> text=bundle floor 9')), 'shell: posts the command with the session seq and shows the device output');
  await page.click('.shell-cmd:text-is("config confirm")'); await t.approve(); await page.waitForTimeout(1200);
  const cc = posts.filter((x) => x.p === '/api/hsh').pop();
  const [l1, l2] = cc.body.split('\n');
  const ce = env(l2 ?? '');
  ok(l1 === 'config confirm' && ce.ok && ce.msg === 20 && ce.gen === 9, 'shell: config confirm carries an owner-signed envelope line (msg 20), the session has no authority');
  st.hsh405 = true;
  await go('/admin/shell', 1200);
  await page.fill('#hsh-line', 'help'); await page.keyboard.press('Enter'); await page.waitForTimeout(800);
  ok(await vis(page.locator('text=This build has no management shell')) && await page.locator('#hsh-line').isDisabled(), 'shell: a build without hsh says so and disables the console');
}
