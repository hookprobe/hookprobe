// Board AdvApply "Preview the change": over a bundle in force the review shows, per section, what the bundle removes
// and adds (secrets masked on both sides), and "Unchanged" for sections left alone — so a removed rule is visible.
import { createPrivateKey, createPublicKey } from 'node:crypto';

const PKCS8 = Buffer.from('302e020100300506032b657004220420' + '6e'.repeat(32), 'hex');
const PEM = `-----BEGIN PRIVATE KEY-----\n${PKCS8.toString('base64')}\n-----END PRIVATE KEY-----\n`;
const PUBHEX = createPublicKey(createPrivateKey({ key: PKCS8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const POLICY = 'acl LAN_IN seq 10 block tcp any 192.168.1.50 22\nacl LAN_IN seq 20 allow any any any\ninterface lan acl in LAN_IN\n';

export default async function (t) {
  const { page, ok, go, vis } = t;
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/config') return r.fulfill(json({ state: 'committed', generation: 9, floor: 9, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      sections: { wan: { present: true, digest: 'aa' }, wifi: { present: true, digest: 'bb' }, policy: { present: true, digest: 'cc' } }, policy_text: POLICY,
      wan_keys: { mode: 'dhcp' }, wifi_keys: { ssid: 'Popescu-Home', security: 'wpa3-transition', psk_set: true } }));
    if (p === '/api/anchor') return r.fulfill(json({ vendor_key: null, owner_key: PUBHEX, owner_enrolled: true, owner_generation: 1, config_files_verified_by: 'owner', can: 'rotate', device_id: null, state: 'protected' }));
    if (p === '/api/upload') return r.fulfill(json({ store: true, chunk_max: 16384, recent: [], in_flight: null, types: [] }));
    return r.fulfill(json({}, 404));
  });
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup'); await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);

  // rename the Wi-Fi only
  await go('/network/wifi', 2000);
  await page.fill('input[placeholder="HookProbe-Home"]', 'Popescu-Guest'); await page.fill('input[type=password]', 'correct horse battery');
  await page.click('button:has-text("Review all three"), button:has-text("Review and apply live")'); await page.waitForTimeout(400);
  const d = page.locator('.drawer', { hasText: 'Apply all three together' });
  const wifi = d.locator('[aria-label="wifi changes"]');
  ok(await vis(wifi.locator('text=ssid=Popescu-Home')) && await vis(wifi.locator('text=ssid=Popescu-Guest')) && !(await wifi.locator('text=correct horse battery').count()),
    'review: the Wi-Fi section shows − old name / + new name (password never shown)');
  ok(await vis(d.locator('[aria-label="wan unchanged"]')) && await vis(d.locator('[aria-label="policy unchanged"]')), 'review: Internet and Firewall say Unchanged (sent again as in force)');
  ok(await vis(d.locator('text=type them again, even if they stay the same')), 'review: says why the passwords are asked again');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);

  // remove a firewall rule: the review shows it removed
  await page.click('.tab:has-text("Firewall")'); await page.waitForTimeout(300);
  await page.locator('main .l0-table tbody tr').first().locator('button[aria-label="Remove rule"]').click(); await page.waitForTimeout(200);
  await page.click('button:has-text("Review all three"), button:has-text("Review and apply live")'); await page.waitForTimeout(400);
  ok(await vis(d.locator('[aria-label="policy changes"] .plan-diff-line--removed', { hasText: '192.168.1.50' })), 'review: a removed firewall rule shows as a − line');
}
