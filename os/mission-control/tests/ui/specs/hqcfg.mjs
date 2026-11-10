// HQCFG1 bundle parity (ADR 0059 Step 2): the browser builder + signer must produce exactly the bytes in
// os/kernel/tools/vectors/hqcfg-vectors.json — the same vectors os/kernel/tools/hqcfg.py writes and the
// kernel's [P-cfgbundle] asserts. Uses the public RFC 8032 TEST 1 key (never a real key).
import { readFileSync } from 'node:fs';
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

  await go('/network/wifi');
  await page.fill('input[placeholder="HookProbe-Home"]', 'Popescu-Home');
  await page.fill('input[type=password]', 'correct horse battery');
  await page.fill('aside input[inputmode=numeric]', '8');
  await page.click('button:has-text("Review and sign")'); await page.waitForTimeout(300);
  await page.click('text=Looks right · sign it'); await page.click('text=Sign in this browser'); await page.waitForTimeout(800);
  ok(await vis(page.locator('text=not protected at rest yet')), 'the Wi-Fi password is stated as not protected at rest');
  const files = [];
  page.on('download', async (d) => files.push([d.suggestedFilename(), readFileSync(await d.path())]));
  await page.click('button:has-text("Download as a signed bundle")'); await page.waitForTimeout(1500);
  const bin = files.find(([n]) => n === 'HQCFG1.BIN')?.[1], sig = files.find(([n]) => n === 'HQCFG1.SIG')?.[1];
  ok(bin && bin.toString('hex') === V.cases['valid-wifi-only'].bundle, 'browser HQCFG1.BIN byte-identical to the shared vector');
  ok(sig && sig.toString('hex') === V.cases['valid-wifi-only'].sig, 'browser HQCFG1.SIG byte-identical to the shared vector (hqcfg.py, kernel)');
}
