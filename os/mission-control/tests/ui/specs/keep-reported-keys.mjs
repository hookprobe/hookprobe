// A bundle is the whole configuration: every key the device reports must come back, or a change silently removes it.
// Found 13 Nov before the metal journey: mgmt_floor (the management-access floor) was not carried, so a Wi-Fi password
// change over the bench's static + VLAN + management-VLAN WAN would have dropped it. Bench-shaped mock; the bundle the
// device receives is verified with os/kernel/tools/hqcfg.py. A key the editor does not know refuses the change.
import { writeFileSync, mkdtempSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const DEV = '00112233445566778899aabbccddeeff';
const PKCS8 = Buffer.from('302e020100300506032b657004220420' + '6f'.repeat(32), 'hex');
const PEM = `-----BEGIN PRIVATE KEY-----\n${PKCS8.toString('base64')}\n-----END PRIVATE KEY-----\n`;
const PUBHEX = createPublicKey(createPrivateKey({ key: PKCS8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const WAN = { mode: 'static', ip: '10.100.0.200/24', gw: '10.100.0.254', vlan: '100', mgmt_vlan: '200', mgmt: 'static', mgmt_ip: '192.168.200.2/24', mgmt_gw: '192.168.200.1', mgmt_floor: '192.168.200.0/24' };

export default async function (t) {
  const { page, ok, go, vis } = t;
  const st = { chunks: [], wan: { ...WAN } };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname, m = r.request().method();
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/session') return r.fulfill(json({ csrf: 'x', next_seq: 1 }));
    if (p === '/api/network') return r.fulfill(json({ available: true, wifi: { ssid: 'bench-ap', channel: 36, width_mhz: 80, security: 'WPA3', source: 'bundle' } }));
    if (p === '/api/anchor') return r.fulfill(json({ vendor_key: null, owner_key: PUBHEX, owner_enrolled: true, owner_generation: 1, config_files_verified_by: 'owner', can: 'rotate', device_id: DEV, state: 'protected' }));
    if (p === '/api/config') return r.fulfill(json({ state: 'committed', generation: 5, floor: 5, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      sections: { wan: { present: true, digest: 'aa' }, wifi: { present: true, digest: 'bb' }, policy: { present: false, digest: null } }, policy_text: null,
      wan_keys: st.wan, wifi_keys: { ssid: 'bench-ap', security: 'wpa3-transition', psk_set: true },
      envelope: { format: 'HQMGMT1', device_id: DEV, epoch: '0102030405060708', next_seq: 5, generation: 5, digest: '00'.repeat(32), owner_enrolled: true } }));
    if (p === '/api/upload' && m === 'GET') return r.fulfill(json({ store: true, chunk_max: 16384, in_flight: st.inFlight ?? null, recent: [], types: [{ type: 'config', cap: 16384, generation: 5, source: 'upload', applies: 'live' }] }));
    if (p === '/api/upload/begin') return r.fulfill(json({ ok: true, id: 'u1', chunk_max: 16384 }));
    if (p === '/api/upload/chunk') { st.chunks.push(r.request().postDataBuffer()); return r.fulfill(json({ ok: true })); }
    if (p === '/api/upload/finish') { const box = Buffer.concat(st.chunks); st.inFlight = { id: 'u1', type: 'config', size: box.length, received: box.length, verified: true, type_code: 9, generation: 6, digest: createHash('sha256').update(box.subarray(512)).digest('hex') }; return r.fulfill(json({ ok: true })); }
    if (p === '/api/upload/activate') { st.inFlight = null; return r.fulfill(json({ ok: true, activated: true, applies: 'live', reboot_required: false, needs_confirm: true, generation: 6 })); }
    return r.fulfill(json({}, 404));
  });
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup'); await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);

  // Wi-Fi password change from Get Online over the bench WAN
  await go('/network/wan', 1500);
  await page.click('section[aria-label="Wi-Fi"] button:has-text("Change password")'); await page.waitForTimeout(800);
  const sheet = page.locator('[role=dialog][aria-labelledby="wifi-sheet-title"]');
  await sheet.locator('label:has-text("New Wi-Fi password") input').fill('a new bench password');
  await sheet.locator('label:has-text("Device password") input').fill('label-password-0001');
  await sheet.locator('button:has-text("Change password")').click(); await page.waitForTimeout(1500);
  const box = Buffer.concat(st.chunks), dir = mkdtempSync(join(tmpdir(), 'keepkeys-'));
  writeFileSync(join(dir, 's'), box.subarray(0, 512)); writeFileSync(join(dir, 'b'), box.subarray(512));
  let out = '';
  try { out = execFileSync('python3', ['-I', join(ROOT, 'os/kernel/tools/hqcfg.py'), 'verify', PUBHEX, join(dir, 'b'), join(dir, 's'), '5', DEV]).toString(); } catch (e) { out = String(e.stderr ?? e.message); }
  const wan = out.split('--- wan')[1]?.split('---')[0] ?? '';
  ok(['mode=static', 'ip=10.100.0.200/24', 'gw=10.100.0.254', 'vlan=100', 'mgmt_vlan=200', 'mgmt=static', 'mgmt_ip=192.168.200.2/24', 'mgmt_gw=192.168.200.1', 'mgmt_floor=192.168.200.0/24'].every((l) => wan.includes(l)),
    'Wi-Fi change over the bench WAN: every internet key comes back, including mgmt_floor (verified with hqcfg.py)');
  await page.keyboard.press('Escape');

  // the Internet editor shows the floor in force
  await page.evaluate(() => { try { localStorage.setItem('hp.proView', '1'); } catch { /* */ } });
  await go('/network/wan/advanced', 1500);
  ok(await page.locator('label:has-text("Management access floor") input').inputValue() === '192.168.200.0/24', 'Internet editor: the management access floor in force is shown, prefilled');

  // a key this UI does not know: refuse rather than drop it
  st.wan = { ...WAN, mgmt_dhcp_hint: 'x' };
  await go('/network/wan', 1500);
  await page.click('section[aria-label="Wi-Fi"] button:has-text("Change password")'); await page.waitForTimeout(800);
  ok(await vis(sheet.locator('text=settings this screen cannot keep')), 'unknown key in force: the Wi-Fi sheet refuses (it would remove it) and says why');
  await page.keyboard.press('Escape');
  await go('/network/wifi', 1500);
  await page.fill('input[type=password]', 'correct horse battery');
  await page.click('button:has-text("Review and apply live")'); await page.waitForTimeout(400);
  ok(await vis(page.locator('.drawer >> text=internet "mgmt_dhcp_hint"')), 'unknown key in force: the bundle names the setting it cannot keep and is not offered');
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
