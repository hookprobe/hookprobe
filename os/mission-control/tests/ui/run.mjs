// Mission Control UI suite runner — see run.sh. Usage: node run.mjs <playwright node_modules> <base url> [spec…]
// Live mode (UI_LIVE_TOKEN set, called by os/kernel/tools/mc-e2e.sh): runs specs/live/*.mjs against a real
// heqk device, signing in with the owner key first. Live specs must be read-only (the e2e run continues).
// Metal mode (UI_SPEC_DIR=specs/metal + UI_LIVE_TOKEN): the change journeys, opt-in, see specs/metal/README.
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [pwDir, base, ...only] = process.argv.slice(2);
const here = dirname(fileURLToPath(import.meta.url));
const { chromium } = await import(pathToFileURL(join(pwDir, 'playwright', 'index.mjs')).href);
const shots = process.env.UI_SHOTS || '';
const token = process.env.UI_LIVE_TOKEN || '';
// UI_SPEC_DIR=specs/metal: opt-in specs that CHANGE the device (run by the heqk session in a metal batch, never in g3).
const dir = join(here, process.env.UI_SPEC_DIR || (token ? 'specs/live' : 'specs'));

const specs = readdirSync(dir).filter((f) => f.endsWith('.mjs')).map((f) => f.replace(/\.mjs$/, '')).sort()
  .filter((s) => only.length === 0 || only.includes(s));

const browser = await chromium.launch();
let fails = 0, passes = 0;
for (const name of specs) {
  const { default: spec } = await import(pathToFileURL(join(dir, `${name}.mjs`)).href);
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, ignoreHTTPSErrors: process.env.UI_INSECURE_TLS === '1' });
  const page = await ctx.newPage();
  page.setDefaultTimeout(6000);
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const t = {
    page, base, at: '',
    ok(cond, msg) { if (cond) { passes++; console.log(`  PASS  ${name}: ${msg}`); } else { fails++; console.log(`  FAIL  ${name}: ${msg}`); } },
    async go(path, settle = 900) { await page.goto(base + path, { waitUntil: 'load' }); await page.waitForTimeout(settle); },
    async shot(file, full = false) { if (shots) await page.screenshot({ path: join(shots, `${name}-${file}.png`), fullPage: full }); },
    async vis(loc) { return loc.first().isVisible().catch(() => false); },
    // Fill and submit the Approve sheet (store/approve.ts): { reason?, key?, passphrase? }.
    async approve(v = {}) {
      const s = page.locator('.approve-sheet[aria-labelledby="approve-title"]');
      await s.waitFor({ state: 'visible', timeout: 5000 });
      if (v.reason !== undefined) await s.locator('label:has-text("Reason") input').fill(v.reason);
      const pw = s.locator('input[type=password]');
      if (v.key !== undefined) await pw.first().fill(v.key);
      if (v.passphrase !== undefined) { await pw.nth(0).fill(v.passphrase); await pw.nth(1).fill(v.passphrase); }
      await s.locator('button[type=submit]').click();
      await s.waitFor({ state: 'hidden', timeout: 5000 });
    },
  };
  try {
    if (token) {
      await page.goto(base + '/login', { waitUntil: 'load' });
      await page.fill('input[name=token]', token);
      await Promise.all([page.waitForURL((u) => new URL(u).pathname === '/'), page.click('button[type=submit]')]);
    }
    await spec(t);
  } catch (e) {
    fails++;
    console.log(`  FAIL  ${name}: aborted${t.at ? ` at "${t.at}"` : ''} (${page.url()}) — ${String(e.message || e).split('\n')[0]}`);
    if (shots) await page.screenshot({ path: join(shots, `${name}-ABORT.png`), fullPage: true }).catch(() => {});
  }
  if (errors.length) { fails++; console.log(`  FAIL  ${name}: page errors — ${errors.join(' | ')}`); }
  await ctx.close();
}
await browser.close();
console.log(`UI-SUITE${token ? ' (live device)' : ''}: ${fails === 0 ? 'PASS' : 'FAIL'} — ${passes} passed, ${fails} failed (${specs.join(', ')})`);
process.exit(Math.min(fails, 100));
