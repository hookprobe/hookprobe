// Layer 0 "Change password" on the Wi-Fi card (wireframe GetOnline): a sheet, not the three-tab editor. Over a bundle
// in force it re-sends the internet (PPPoE password typed again) and the firewall byte-for-byte; the bundle the
// device receives is verified with os/kernel/tools/hqcfg.py. Blocked states say why and where to go.
import { writeFileSync, mkdtempSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { rendered, GOLD } from './wifi-qr.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const DEV = '00112233445566778899aabbccddeeff';
const PKCS8 = Buffer.from('302e020100300506032b657004220420' + '6c'.repeat(32), 'hex');
const PEM = `-----BEGIN PRIVATE KEY-----\n${PKCS8.toString('base64')}\n-----END PRIVATE KEY-----\n`;
const PUBHEX = createPublicKey(createPrivateKey({ key: PKCS8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const POLICY = 'acl LAN_IN seq 10 allow any any any\ninterface lan acl in LAN_IN\n';

export default async function (t) {
  const { page, ok, go, vis } = t;
  const st = { enrolled: false, chunks: [], begin: '' };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname, m = r.request().method();
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/session') return r.fulfill(json({ csrf: 'x', next_seq: 1 }));
    if (p === '/api/network') return r.fulfill(json({ available: true, wifi: { ssid: 'Popescu-Home', channel: 6, width_mhz: 20, security: 'WPA3', source: 'bundle' } }));
    if (p === '/api/anchor') return r.fulfill(json({ vendor_key: null, owner_key: st.enrolled ? PUBHEX : null, owner_enrolled: st.enrolled, owner_generation: 1, config_files_verified_by: 'owner', can: 'rotate', device_id: DEV, state: 'protected' }));
    if (p === '/api/config') return r.fulfill(json({ state: 'committed', generation: 9, floor: 9, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      sections: { wan: { present: true, digest: 'aa' }, wifi: { present: true, digest: 'bb' }, policy: { present: true, digest: 'cc' } }, policy_text: POLICY,
      wan_keys: { mode: 'pppoe', pppoe_user: 'user@isp', pppoe_pass_set: true }, wifi_keys: { ssid: 'Popescu-Home', security: 'wpa3-transition', psk_set: true },
      envelope: { format: 'HQMGMT1', device_id: DEV, epoch: '0102030405060708', next_seq: 5, generation: 9, digest: '00'.repeat(32), owner_enrolled: st.enrolled } }));
    if (p === '/api/upload' && m === 'GET') return r.fulfill(json({ store: true, chunk_max: 16384, in_flight: st.inFlight ?? null, recent: [], types: [{ type: 'config', cap: 16384, generation: 9, source: 'upload', applies: 'live' }] }));
    if (p === '/api/upload/begin') { st.begin = r.request().postData() ?? ''; return r.fulfill(json({ ok: true, id: 'u1', chunk_max: 16384 })); }
    if (p === '/api/upload/chunk') { st.chunks.push(r.request().postDataBuffer()); return r.fulfill(json({ ok: true })); }
    if (p === '/api/upload/finish') { const box = Buffer.concat(st.chunks); st.inFlight = { id: 'u1', type: 'config', size: box.length, received: box.length, verified: true, type_code: 9, generation: 10, digest: createHash('sha256').update(box.subarray(512)).digest('hex') }; return r.fulfill(json({ ok: true })); }
    if (p === '/api/upload/activate') { st.inFlight = null; return r.fulfill(json({ ok: true, activated: true, live: true, needs_confirm: true, generation: 10 })); }
    return r.fulfill(json({}, 404));
  });

  // No signing key trusted yet: the sheet says so and points at the fix, instead of a dead form.
  await go('/network/wan', 1500);
  const card = page.locator('section[aria-label="Wi-Fi"]');
  ok(await vis(card.locator('button:has-text("Change password")')) && await vis(card.locator('a:has-text("More Wi-Fi settings")')), 'Wi-Fi card: "Change password" opens a sheet; the advanced editor is a secondary link');
  await card.locator('button:has-text("Change password")').click(); await page.waitForTimeout(500);
  const sheet = page.locator('[role=dialog][aria-labelledby="wifi-sheet-title"]');
  ok(await vis(sheet.locator('text=does not trust one yet')) && await vis(sheet.locator('a:has-text("Set up your signing key")')), 'no trusted signing key: says why, links to set it up');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  ok(!(await vis(sheet)), 'Esc closes the sheet');

  st.enrolled = true;
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup'); await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);

  await go('/network/wan', 1500);
  await card.locator('button:has-text("Change password")').click(); await page.waitForTimeout(600);
  ok(await sheet.locator('label:has-text("Wi-Fi name") input').inputValue() === 'Popescu-Home', 'the sheet starts from the Wi-Fi name in force');
  ok(await vis(sheet.locator('label:has-text("Internet (PPPoE) password")')), 'the PPPoE password in force is asked for again (never served)');
  await sheet.locator('label:has-text("New Wi-Fi password") input').fill('short');
  ok(await vis(sheet.locator('text=Password: 8–63 printable characters')) && await sheet.locator('button:has-text("Change password")').isDisabled(), 'a too-short password is explained and cannot be sent');
  await sheet.locator('label:has-text("New Wi-Fi password") input').fill('Our new family password');
  await sheet.locator('label:has-text("Internet (PPPoE) password") input').fill('isp-secret');
  await sheet.locator('label:has-text("Device password") input').fill('label-password-0001');
  await sheet.locator('button:has-text("Change password")').click(); await page.waitForTimeout(1500);
  ok(await vis(sheet.locator('text=press Keep within 5 minutes')), 'after sending: live trial explained, with Keep within 5 minutes');
  // the network just set can be shared as a QR code (password still in this sheet only), and Esc closes only the QR
  await sheet.locator('button:has-text("Show QR code")').click(); await page.waitForTimeout(300);
  const want = GOLD.find((c) => c.text === 'WIFI:T:WPA;S:Popescu-Home;P:Our new family password;;').rows;
  const got = await rendered(page);
  ok(got.length === want.length && got.every((r, i) => r === want[i]), 'after the change: "Show QR code" renders the code for the new password');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  ok(!(await page.locator('[aria-labelledby="qr-sheet-title"]').count()) && await vis(sheet), 'Esc closes the QR code only, the Wi-Fi sheet stays');
  ok(new URLSearchParams(st.begin).get('type') === 'config' && new URLSearchParams(st.begin).get('owner_key') === 'label-password-0001', 'sent as a configuration bundle, authorised with the device password');

  const box = Buffer.concat(st.chunks), dir = mkdtempSync(join(tmpdir(), 'l0wifi-'));
  writeFileSync(join(dir, 's'), box.subarray(0, 512)); writeFileSync(join(dir, 'b'), box.subarray(512));
  let out = '';
  try { out = execFileSync('python3', ['-I', join(ROOT, 'os/kernel/tools/hqcfg.py'), 'verify', PUBHEX, join(dir, 'b'), join(dir, 's'), '9', DEV]).toString(); } catch (e) { out = String(e.stderr ?? e.message); }
  ok(/ssid=Popescu-Home[\s\S]*psk=Our new family password[\s\S]*security=wpa3-transition/.test(out), 'bundle verified: the new Wi-Fi password, security kept');
  ok(/pppoe_user=user@isp[\s\S]*pppoe_pass=isp-secret/.test(out) && out.split('--- policy')[1]?.replace(/^ \(\d+ B\)\n/, '') === POLICY, 'bundle verified: internet re-sent with the retyped password, firewall byte-for-byte');

  // Phone: a bottom sheet, full width, nothing scrolls sideways.
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 390, height: 844 }); await page.waitForTimeout(300);
  await card.locator('button:has-text("Change password")').click(); await page.waitForTimeout(600);
  const bb = await page.locator('.approve-sheet').boundingBox();
  const sx = await page.evaluate(() => document.documentElement.scrollWidth);
  await page.screenshot({ path: join(tmpdir(), 'l0-wifi-sheet-phone.png') });
  ok(bb && Math.round(bb.x) === 0 && Math.round(bb.width) === 390 && Math.abs(bb.y + bb.height - 844) <= 1 && sx <= 390, 'phone: a full-width bottom sheet, no sideways scroll');
  await page.setViewportSize({ width: 1440, height: 900 });
}
