// Share QR (wireframe GetOnline Wi-Fi card): the code is built in the browser from a password typed here (the device
// never shows it) and rendered as dark-on-light SVG. The rendered modules are read back from the SVG path and compared
// with golden matrices (qr-golden.json; the encoder was checked against a reference encoder module for module).
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const GOLD = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'qr-golden.json'), 'utf8')).cases;

/** Rebuild the module matrix from the SVG: "M{x} {y}h1v1h-1z" per dark module, offset by a 4-module quiet zone. */
export async function rendered(page) {
  const { d, n } = await page.evaluate(() => {
    const s = document.querySelector('svg.qr-code');
    return { d: s?.querySelector('path')?.getAttribute('d') ?? '', n: Number(s?.getAttribute('viewBox')?.split(' ')[2] ?? 0) };
  });
  const size = n - 8, m = Array.from({ length: size }, () => new Array(size).fill('0'));
  for (const [, x, y] of d.matchAll(/M(\d+) (\d+)h1v1h-1z/g)) m[+y - 4][+x - 4] = '1';
  return m.map((r) => r.join(''));
}

export default async function (t) {
  const { page, ok, go, vis } = t;

  // From the Wi-Fi card (sample network: HookProbe-Home, WPA3)
  await go('/network/wan', 1500);
  await page.click('section[aria-label="Wi-Fi"] button:has-text("Share QR")'); await page.waitForTimeout(300);
  const sheet = page.locator('[role=dialog][aria-labelledby="qr-sheet-title"]');
  ok(await vis(sheet.locator('text=The code appears once the password is at least 8 characters')) && !(await sheet.locator('svg.qr-code').count()), 'Share QR: no code until a password is typed (the device never shows it)');
  await sheet.locator('input[type=password]').fill('correct horse battery'); await page.waitForTimeout(200);
  const want = GOLD.find((c) => c.text === 'WIFI:T:SAE;S:HookProbe-Home;P:correct horse battery;;').rows;
  const got = await rendered(page);
  ok(got.length === want.length && got.every((r, i) => r === want[i]), `Share QR: the rendered code is the expected ${want.length}×${want.length} matrix for WIFI:T:SAE;S:HookProbe-Home;…`);
  ok(await page.evaluate(() => getComputedStyle(document.querySelector('svg.qr-code rect')).fill || document.querySelector('svg.qr-code rect').getAttribute('fill')) !== null
    && await page.locator('svg.qr-code rect').getAttribute('fill') === '#fff' && await page.locator('svg.qr-code path').getAttribute('fill') === '#000', 'Share QR: dark modules on a white quiet zone (scannable in the dark theme)');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  ok(!(await vis(sheet)), 'Share QR: Esc closes it');
}
