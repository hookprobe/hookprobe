// First-run setup on a device that takes configuration bundles (ADR 0059): enroll the owner key, send ONE
// wan+wifi bundle (no policy section: the device keeps its per-file / boot-card policy), bound to the device,
// at generation max(generation, floor)+1 — then show the trial. The device is mocked by route interception
// with the shapes heqk serves; the uploaded bundle is verified with os/kernel/tools/hqcfg.py.
import { writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const DEV = '00112233445566778899aabbccddeeff';

export default async function (t) {
  const { page, ok, go, vis } = t;
  const state = { enrolledKey: null, chunks: [], config: { state: 'none', generation: 4, floor: 6, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '' } };
  const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/api/**', async (route) => {
    const u = new URL(route.request().url()), m = route.request().method();
    const p = u.pathname;
    if (p === '/api/health') return route.fulfill(json({ substrate: 'heqk', mode: 'standalone', wan: { up: true, ip: '', mode: 'dhcp', ipv6: false, clients: 0, pkts_out: 0, pkts_in: 0, dns_inspected: 0 } }));
    if (p === '/api/session') return route.fulfill(json({ csrf: 'x', next_seq: 1 }));
    if (p === '/api/anchor') return route.fulfill(json({ vendor_key: null, owner_key: state.enrolledKey, owner_enrolled: !!state.enrolledKey, owner_generation: state.enrolledKey ? 1 : 0, config_files_verified_by: state.enrolledKey ? 'owner' : 'none (standalone)', can: state.enrolledKey ? 'rotate' : 'enroll', device_id: DEV, state: 'CONFIG UNPROTECTED' }));
    if (p === '/api/anchor/enroll' && m === 'POST') { state.enrolledKey = new URLSearchParams(route.request().postData()).get('public_key'); return route.fulfill(json({ ok: true, owner_generation: 1 })); }
    if (p === '/api/config') return route.fulfill(json(state.config));
    if (p === '/api/upload' && m === 'GET') return route.fulfill(json({ store: true, chunk_max: 16384, in_flight: null, recent: [], types: [{ type: 'wan', cap: 512, generation: 0, source: 'boot', applies: 'next_boot' }, { type: 'config', cap: 16384, generation: 0, source: 'boot', applies: 'next_boot' }] }));
    if (p === '/api/upload/begin') { state.type = new URLSearchParams(route.request().postData()).get('type'); return route.fulfill(json({ ok: true, id: 'u1', chunk_max: 16384 })); }
    if (p === '/api/upload/chunk') { state.chunks.push(route.request().postDataBuffer()); return route.fulfill(json({ ok: true })); }
    if (p === '/api/upload/finish') return route.fulfill(json({ ok: true }));
    if (p === '/api/upload/activate') return route.fulfill(json({ ok: true, activated: true, staged: true, generation: 7 }));
    return route.fulfill(json({}, 404));
  });

  await go('/setup', 1500);
  await page.click('button:has-text("Start")'); await page.waitForTimeout(200);
  await page.click('text=I have a PPPoE login');
  await page.fill('input[placeholder="from your ISP letter"]', 'user@isp');
  await page.locator('label:has-text("PPPoE password") input').fill('s3cret');
  await page.click('button:has-text("Continue")'); await page.waitForTimeout(200);
  await page.fill('input[placeholder]:not([type=password])', 'Popescu-Home');
  await page.fill('input[type=password]', 'Correct horse battery 9');
  await page.click('button:has-text("Continue")'); await page.waitForTimeout(200);

  // Key step: create, then the one-shot enrollment is required before continuing.
  await page.locator('label:has-text("Backup passphrase") input').fill('setup bundle pass');
  await page.locator('label:has-text("Repeat it") input').fill('setup bundle pass');
  await Promise.all([page.waitForEvent('download'), page.click('text=Create key and download backup')]); await page.waitForTimeout(600);
  ok(await page.locator('button:has-text("Continue")').isDisabled() && await vis(page.locator('[aria-label="Enroll"] >> text=one-shot')),
    'bundle setup: the owner key must be enrolled (one-shot, stated) before continuing');
  const answers = ['', 'label-key'];
  page.on('dialog', (d) => d.accept(answers.shift() ?? 'label-key'));
  await page.click('button:has-text("Make this the owner key")'); await page.waitForTimeout(800);
  ok(await page.locator('button:has-text("Continue")').isEnabled(), 'bundle setup: enrolled → can continue');
  await page.click('button:has-text("Continue")'); await page.waitForTimeout(200);
  ok(await vis(page.locator('text=goes back to the previous settings by itself')) && await vis(page.locator("text=The Wi-Fi isn't checked that way")),
    'review: explains the trial (internet health-checked, Wi-Fi not)');

  await page.click('button:has-text("Launch")'); await page.waitForTimeout(2500);
  ok(state.type === 'config', 'launch: uploads ONE configuration bundle (type config), not per-file files');
  ok(await vis(page.locator('h1', { hasText: 'Restart to try your settings' })) && await vis(page.locator('button:has-text("Restart and try them")')), 'done: restart to start the trial');

  // The uploaded container = HQCSIG1 (512) || bundle; verify like the device, bound to DEV.
  const box = Buffer.concat(state.chunks);
  const dir = mkdtempSync(join(tmpdir(), 'setupb-'));
  writeFileSync(join(dir, 's'), box.subarray(0, 512)); writeFileSync(join(dir, 'b'), box.subarray(512));
  let out = '';
  try { out = execFileSync('python3', ['-I', join(ROOT, 'os/kernel/tools/hqcfg.py'), 'verify', state.enrolledKey, join(dir, 'b'), join(dir, 's'), '6', DEV]).toString(); } catch (e) { out = String(e.stderr ?? e.message); }
  const hdr = JSON.parse(out.split('\n')[0] || '{}');
  ok(hdr.generation === 7 && hdr.flags === 1 && hdr.device_id === DEV, `bundle: generation max(4, floor 6)+1 = 7, bound to the device (${out.split('\n')[0]})`);
  ok(/--- wan/.test(out) && /pppoe_user=user@isp/.test(out) && /--- wifi/.test(out) && /ssid=Popescu-Home/.test(out) && !/--- policy/.test(out),
    'bundle: wan + wifi, no policy section (the device keeps its own policy); signed by the enrolled key');

  // After the restart: the trial shows in setup, then the commit.
  state.config = { ...state.config, state: 'trial', generation: 7, on_trial: true, elapsed_s: 20 };
  await page.waitForTimeout(5600);
  ok(await vis(page.locator('[aria-label="Configuration trial"] >> text=generation 7 is on trial')), 'setup shows the trial with its countdown after the restart');
  state.config = { ...state.config, state: 'committed' };
  await page.waitForTimeout(5600);
  ok(await vis(page.locator('text=Kept: you\'re online with your new settings')), 'setup confirms when the device keeps the settings');
}
