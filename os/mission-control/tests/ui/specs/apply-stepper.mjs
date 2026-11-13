// Board AdvApply: the bundle drawer shows Review → Sign → Send and check → Apply live → Trial, and says it applies live.
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';

const DEV = '00112233445566778899aabbccddeeff';
const PKCS8 = Buffer.from('302e020100300506032b657004220420' + '6d'.repeat(32), 'hex');
const PEM = `-----BEGIN PRIVATE KEY-----\n${PKCS8.toString('base64')}\n-----END PRIVATE KEY-----\n`;
const PUBHEX = createPublicKey(createPrivateKey({ key: PKCS8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');

export default async function (t) {
  const { page, ok, go, vis } = t;
  const st = { chunks: [], trial: false };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname, m = r.request().method();
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/session') return r.fulfill(json({ csrf: 'x', next_seq: 1 }));
    if (p === '/api/anchor') return r.fulfill(json({ vendor_key: null, owner_key: PUBHEX, owner_enrolled: true, owner_generation: 1, config_files_verified_by: 'owner', can: 'rotate', device_id: DEV, state: 'protected' }));
    if (p === '/api/config') return r.fulfill(json({ state: st.trial ? 'trial' : 'none', generation: st.trial ? 1 : 0, floor: 0, on_trial: st.trial, needs_confirm: st.trial, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      envelope: { format: 'HQMGMT1', device_id: DEV, epoch: '0102030405060708', next_seq: 5, generation: 0, digest: '00'.repeat(32), owner_enrolled: true } }));
    if (p === '/api/upload' && m === 'GET') return r.fulfill(json({ store: true, chunk_max: 16384, in_flight: st.inFlight ?? null, recent: [], types: [{ type: 'config', cap: 16384, generation: 0, source: 'boot', applies: 'live' }] }));
    if (p === '/api/upload/begin') return r.fulfill(json({ ok: true, id: 'u1', chunk_max: 16384 }));
    if (p === '/api/upload/chunk') { st.chunks.push(r.request().postDataBuffer()); return r.fulfill(json({ ok: true })); }
    if (p === '/api/upload/finish') { const box = Buffer.concat(st.chunks); st.inFlight = { id: 'u1', type: 'config', size: box.length, received: box.length, verified: true, type_code: 9, generation: 1, digest: createHash('sha256').update(box.subarray(512)).digest('hex') }; return r.fulfill(json({ ok: true })); }
    if (p === '/api/upload/activate') { st.inFlight = null; st.trial = true; return r.fulfill(json({ ok: true, activated: true, live: true, needs_confirm: true, generation: 1 })); }
    return r.fulfill(json({}, 404));
  });
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup'); await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);

  await go('/network/wifi', 1500);
  await page.fill('input[placeholder="HookProbe-Home"]', 'Popescu-Home'); await page.fill('input[type=password]', 'correct horse battery');
  await page.click('button:has-text("Review and apply live")'); await page.waitForTimeout(300);
  const d = page.locator('.drawer', { hasText: 'Apply all three together' });
  const now = async () => (await d.locator('.apply-steps li[aria-current="step"]').textContent())?.replace(/^\d\s*/, '').trim();
  ok(await d.locator('.apply-steps li').count() === 5 && await now() === 'Review', 'stepper: five steps, starting at Review');
  ok(await vis(d.locator('text=It applies live, without a restart')), 'drawer: says the bundle applies live (not "after the restart")');
  await d.locator('button:has-text("Sign and upload the bundle")').click(); await page.waitForTimeout(300);
  await t.approve({ key: 'label-password-0001' }); await page.waitForTimeout(1500);
  ok(await now() === 'Trial' && await d.locator('.apply-steps li.is-done').count() === 4, 'stepper: after a live apply it is on Trial, the four steps before done');
  // the trial banner (the only Keep button for a Wi-Fi change) shows right after the apply, without a reload
  ok(await vis(page.locator('.hp-banner--trial')) && await vis(page.locator('.hp-banner--trial button:has-text("Keep it")')), 'after the apply: the trial banner with Keep shows at once');
}
