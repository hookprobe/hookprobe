// The Approve sheet (store/approve.ts) replaces every browser prompt()/confirm(): one modal, masked secrets, focus
// held inside, Esc cancels without acting, focus returns to the control that opened it.
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'src');
export default async function (t) {
  const { page, ok, go, vis } = t;
  await go('/admin/identity');
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.locator('label:has-text("Backup passphrase") input').fill('sheet test pass');
  await page.locator('label:has-text("Repeat it") input').fill('sheet test pass');
  await Promise.all([page.waitForEvent('download'), page.click('text=Create key and download backup')]); await page.waitForTimeout(600);

  const sheet = page.locator('.approve-sheet');
  const opener = page.locator('button:has-text("Remove from this browser")');
  await opener.click();
  await sheet.waitFor({ state: 'visible' });
  ok(await sheet.getAttribute('role') === 'dialog' && await sheet.getAttribute('aria-modal') === 'true' && await vis(sheet.locator('#approve-title')), 'opens as a labelled modal dialog');
  ok(await sheet.evaluate((el) => el.contains(document.activeElement)), 'focus moves into the sheet');
  for (let i = 0; i < 6; i++) await page.keyboard.press('Tab');
  ok(await sheet.evaluate((el) => el.contains(document.activeElement)), 'Tab stays inside the sheet (focus trap)');
  ok(await sheet.locator('button[type=submit]').evaluate((b) => getComputedStyle(b).backgroundColor) !== 'rgba(0, 0, 0, 0)', 'destructive confirm is styled (filled), not a plain link');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  ok(!(await vis(sheet)) && await vis(page.locator('.prow', { hasText: 'Public key' })), 'Esc cancels: nothing is removed');
  ok(await opener.evaluate((b) => b === document.activeElement), 'focus returns to the button that opened it');
  const offenders = [];
  const walk = (d) => { for (const f of readdirSync(d, { withFileTypes: true })) { const q = join(d, f.name); if (f.isDirectory()) walk(q); else if (/\.(tsx?|astro)$/.test(f.name) && /window\.(prompt|confirm)\(/.test(readFileSync(q, 'utf8'))) offenders.push(q.split('/src/')[1]); } };
  walk(SRC);
  ok(offenders.length === 0, `no window.prompt / window.confirm anywhere in the UI source${offenders.length ? ': ' + offenders.join(', ') : ''}`);

  // Phone: a bottom sheet with 16 px, 44 px inputs (no iOS zoom).
  await page.setViewportSize({ width: 390, height: 844 });
  await opener.click(); await sheet.waitFor({ state: 'visible' });
  const box = await sheet.boundingBox();
  ok(box && Math.round(box.y + box.height) >= 840 && box.width >= 388, 'on a phone it is a full-width bottom sheet');
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 1440, height: 900 });
}
