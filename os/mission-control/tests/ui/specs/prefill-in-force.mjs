// Edits over a bundle in force (kernel #1055: GET /api/config sections / policy_text / wan_keys / wifi_keys).
// A bundle is the WHOLE configuration, so changing only the customer's Wi-Fi password must re-send the internet
// and firewall in force: the editors prefill from the device, the firewall goes back byte-for-byte, and only the
// secrets (never served) are typed again. Verified with os/kernel/tools/hqcfg.py.
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPrivateKey, createPublicKey } from 'node:crypto';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const PKCS8 = Buffer.from('302e020100300506032b657004220420' + '6b'.repeat(32), 'hex');
const PEM = `-----BEGIN PRIVATE KEY-----\n${PKCS8.toString('base64')}\n-----END PRIVATE KEY-----\n`;
const PUBHEX = createPublicKey(createPrivateKey({ key: PKCS8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const POLICY = 'acl MGMT_IN seq 10 allow tcp 192.168.88.0/24 any 443\nacl MGMT_IN default drop\ninterface mgmt acl in MGMT_IN\nroute 0.0.0.0/0 via wan metric 10\n';

export default async function (t) {
  const { page, ok, go, vis } = t;
  const st = { policy: POLICY };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/config') return r.fulfill(json({ state: 'committed', generation: 9, floor: 9, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      sections: { wan: { present: true, digest: 'aa' }, wifi: { present: true, digest: 'bb' }, policy: { present: true, digest: 'cc' } }, policy_text: st.policy,
      wan_keys: { mode: 'pppoe', pppoe_user: 'user@isp', vlan: '6', pppoe_pass_set: true }, wifi_keys: { ssid: 'Popescu-Home', security: 'wpa3-transition', psk_set: true } }));
    if (p === '/api/anchor') return r.fulfill(json({ vendor_key: null, owner_key: PUBHEX, owner_enrolled: true, owner_generation: 1, config_files_verified_by: 'owner', can: 'rotate', device_id: null, state: 'protected' }));
    if (p === '/api/upload') return r.fulfill(json({ store: true, chunk_max: 16384, recent: [], in_flight: null, types: [] }));
    return r.fulfill(json({}, 404));
  });
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup'); await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);

  // The customer changes only the Wi-Fi password.
  await go('/network/wifi', 2000);
  ok(await page.inputValue('input[placeholder="HookProbe-Home"]') === 'Popescu-Home', 'Wi-Fi editor opens with the network name in force (a value, not a placeholder)');
  await page.click('.tab:has-text("Firewall")'); await page.waitForTimeout(300);
  ok(await vis(page.locator('text=These are the rules in force on the device')) && !(await vis(page.locator('text=an example to start from'))), 'firewall editor starts from the rules in force, not the example');
  await page.click('.tab:has-text("Wi-Fi")'); await page.waitForTimeout(200);
  await page.fill('input[type=password]', 'New family password 2026');
  await page.click('button:has-text("Review all three")'); await page.waitForTimeout(400);
  const d = page.locator('.drawer', { hasText: 'Apply all three together' });
  ok(!(await vis(d.locator('text=leaving it out removes it'))) && await vis(d.locator('text=Unchanged: sent again exactly as in force')), 'bundle: the firewall in force is kept (no edit demanded)');
  ok(await vis(d.locator('text=type the PPPoE password again')), 'bundle: the PPPoE password is typed again (the device never serves it)');
  await d.locator('label:has-text("PPPoE password (again)") input').fill('isp-secret');
  const files = [];
  page.on('download', async (x) => files.push([x.suggestedFilename(), readFileSync(await x.path())]));
  await d.locator('button:has-text("the bundle")').click(); await page.waitForTimeout(900);
  await d.locator('button:has-text("Download HQCFG1.BIN")').click(); await d.locator('button:has-text("Download HQCFG1.SIG")').click(); await page.waitForTimeout(1200);
  const bin = files.find(([n]) => n === 'HQCFG1.BIN')?.[1], sig = files.find(([n]) => n === 'HQCFG1.SIG')?.[1];
  const dir = mkdtempSync(join(tmpdir(), 'prefill-'));
  writeFileSync(join(dir, 'b'), bin ?? ''); writeFileSync(join(dir, 's'), sig ?? '');
  let out = '';
  try { out = execFileSync('python3', ['-I', join(ROOT, 'os/kernel/tools/hqcfg.py'), 'verify', PUBHEX, join(dir, 'b'), join(dir, 's')]).toString(); } catch (e) { out = String(e.stderr ?? e.message); }
  const pol = out.split('--- policy')[1]?.replace(/^ \(\d+ B\)\n/, '') ?? '';
  ok(pol === POLICY, 'the firewall section is the policy in force, byte-for-byte');
  ok(/--- wan[\s\S]*mode=pppoe[\s\S]*pppoe_user=user@isp[\s\S]*pppoe_pass=isp-secret[\s\S]*vlan=6/.test(out) && /ssid=Popescu-Home[\s\S]*psk=New family password 2026/.test(out),
    'internet in force (+ retyped PPPoE password) and the new Wi-Fi password, in one verified bundle');
  await page.keyboard.press('Escape');

  // A firewall with statements this editor does not model: shown as text, sent back verbatim.
  st.policy = POLICY + 'tunnel pop1 wg 203.0.113.9:51820\n';
  await go('/protect/policies', 2000);
  ok(await vis(page.locator('[aria-label="Firewall in force"]')) && await vis(page.locator('text=statements this editor does not handle')), 'an unfamiliar firewall statement: shown as text and kept, not rebuilt');
}
