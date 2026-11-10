// HQCFG1 bundle parity (ADR 0059 Step 2): the browser builder + signer must produce exactly the bytes in
// os/kernel/tools/vectors/hqcfg-vectors.json — the same vectors os/kernel/tools/hqcfg.py writes and the
// kernel's [P-cfgbundle] asserts. Uses the public RFC 8032 TEST 1 key (never a real key).
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const V = JSON.parse(readFileSync(join(ROOT, 'os/kernel/tools/vectors/hqcfg-vectors.json'), 'utf8'));
const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const PEM = `-----BEGIN PRIVATE KEY-----\n${Buffer.from('302e020100300506032b657004220420' + SEED, 'hex').toString('base64')}\n-----END PRIVATE KEY-----\n`;

export default async function (t) {
  const { page, ok, go, vis } = t;

  // 1. The pure builder (Node, type-stripped TS) against every valid vector.
  const { buildBundle, canonicalSection } = await import(pathToFileURL(join(ROOT, 'os/mission-control/src/store/hqcfg.ts')).href);
  const kid = createHash('sha256').update(Buffer.from(V.public_key, 'hex')).digest().subarray(0, 8);
  const s = V.sections_full;
  ok(Buffer.from(buildBundle({ policy: s.policy, wifi: s.wifi, wan: s.wan }, 7, kid)).toString('hex') === V.cases['valid-wan-wifi-policy'].bundle,
    'builder: wan+wifi+policy bundle byte-identical to hqcfg.py (sections ordered by kind)');
  const fo = 'route 0.0.0.0/0 via wan metric 10\nroute 0.0.0.0/0 via mgmt gw 192.168.200.1 metric 100\n';
  ok(Buffer.from(buildBundle({ policy: fo }, 10, kid)).toString('hex') === V.cases['two-default-routes-wan-mgmt'].bundle,
    'builder: metric-ordered failover (default route via wan and via mgmt) accepted, byte-identical to the vector');
  const dev = Buffer.from(V.cases['bound-to-this-device'].device_id, 'hex');
  ok(Buffer.from(buildBundle({ wan: s.wan, wifi: s.wifi, policy: s.policy }, 12, kid, dev)).toString('hex') === V.cases['bound-to-this-device'].bundle,
    'builder: device-bound bundle (flags bit0 + device_id) byte-identical to the vector');
  let refused = '';
  try { canonicalSection('wifi', 'ssid=a\nssid=b\n'); } catch (e) { refused = e.message; }
  ok(/repeated/.test(refused), 'builder: a repeated key is refused before signing');

  // 2. Browser end to end: import the test key, build the Wi-Fi vector in the editor, sign, download.
  await go('/admin/identity');
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup');
  await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);
  ok((await page.locator('.prow', { hasText: 'Public key' }).locator('span').nth(1).textContent()).trim() === V.public_key, 'imported the RFC 8032 test key');

  // The device reports its id: bundles made here are bound to it.
  await page.route('**/api/anchor', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ vendor_key: null, owner_key: null, owner_enrolled: false, owner_generation: 0, config_files_verified_by: 'none (standalone)', can: 'enroll', device_id: V.cases['bound-to-this-device'].device_id }) }));
  await go('/network/wifi');
  await page.fill('input[placeholder="HookProbe-Home"]', 'Popescu-Home');
  await page.fill('input[type=password]', 'correct horse battery');
  // Single-section path: legacy files only, stated as not health-checked; the at-rest caveat shown.
  ok(await vis(page.locator('[aria-label="Apply all together"] >> text=A single-section change (above) is not health-checked')), 'editor: bundle vs single-section difference is stated');
  await page.click('button:has-text("Review and sign")'); await page.waitForTimeout(300);
  await page.click('text=Looks right · sign it'); await page.click('text=Sign in this browser'); await page.waitForTimeout(800);
  ok(await vis(page.locator('text=not protected at rest yet')), 'the Wi-Fi password is stated as not protected at rest');
  ok(!(await page.locator('button:has-text("Download as a signed bundle")').count()), 'no single-section bundle (a bundle replaces all three sections)');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);

  // Combined: switch tabs client-side (drafts survive), then review all three.
  await page.click('.tab:has-text("Internet")'); await page.waitForTimeout(200);
  await page.click('[aria-label="Connection type"] >> text=PPPoE');
  await page.fill('input[placeholder="from your ISP letter"]', 'user@isp');
  await page.click('.tab:has-text("Wi-Fi")'); await page.waitForTimeout(200);
  ok(await page.inputValue('input[placeholder="HookProbe-Home"]') === 'Popescu-Home', 'tabs switch in the page: the Wi-Fi draft survives');
  await page.click('button:has-text("Review all three")'); await page.waitForTimeout(300);
  const drawer = page.locator('.drawer', { hasText: 'Apply all three together' });
  ok(await vis(drawer.locator('text=type the PPPoE password again')), 'bundle: the PPPoE password must be typed again (never read back)');
  await drawer.locator('label:has-text("PPPoE password (again)") input').fill('s3cret');
  ok(await drawer.locator('button:has-text("Sign the bundle")').isEnabled(), 'bundle: all three sections valid → can sign');
  ok(await vis(drawer.locator('[aria-label="Device binding"] >> text=Bound to this device (id 01234567')), 'bundle: bound to the device id the device reports');
  const files = [];
  page.on('download', async (d) => files.push([d.suggestedFilename(), readFileSync(await d.path())]));
  await drawer.locator('button:has-text("Sign the bundle")').click(); await page.waitForTimeout(800);
  await drawer.locator('button:has-text("Download HQCFG1.BIN")').click(); await drawer.locator('button:has-text("Download HQCFG1.SIG")').click(); await page.waitForTimeout(1200);
  const bin = files.find(([n]) => n === 'HQCFG1.BIN')?.[1], sig = files.find(([n]) => n === 'HQCFG1.SIG')?.[1];
  let out = '';
  try {
    const dir = mkdtempSync(join(tmpdir(), 'hqcfg-')); writeFileSync(join(dir, 'b'), bin); writeFileSync(join(dir, 's'), sig);
    out = execFileSync('python3', ['-I', join(ROOT, 'os/kernel/tools/hqcfg.py'), 'verify', V.public_key, join(dir, 'b'), join(dir, 's'), '0', V.cases['bound-to-this-device'].device_id]).toString();
    let other = '';
    try { execFileSync('python3', ['-I', join(ROOT, 'os/kernel/tools/hqcfg.py'), 'verify', V.public_key, join(dir, 'b'), join(dir, 's')], { stdio: 'pipe' }); } catch (e) { other = String(e.stderr); }
    ok(/bound to another device/.test(other), 'browser bundle is refused on any other device');
  } catch (e) { out = String(e.stdout ?? e.message); }
  ok(/--- wan/.test(out) && /pppoe_user=user@isp/.test(out) && /--- wifi/.test(out) && /ssid=Popescu-Home/.test(out) && /--- policy/.test(out),
    'browser bundle (wan + wifi + policy, device-bound) verifies with hqcfg.py exactly as the device will');
}
