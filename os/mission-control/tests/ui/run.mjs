// Mission Control UI suite runner — see run.sh. Usage: node run.mjs <playwright node_modules> <base url> [spec…]
// Live mode (UI_LIVE_TOKEN set, called by os/kernel/tools/mc-e2e.sh): runs specs/live/*.mjs against a real
// heqk device, signing in with the owner key first. Live specs must be read-only (the e2e run continues).
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [pwDir, base, ...only] = process.argv.slice(2);
const here = dirname(fileURLToPath(import.meta.url));
const { chromium } = await import(pathToFileURL(join(pwDir, 'playwright', 'index.mjs')).href);
const shots = process.env.UI_SHOTS || '';
const token = process.env.UI_LIVE_TOKEN || '';
const dir = join(here, token ? 'specs/live' : 'specs');

const specs = readdirSync(dir).filter((f) => f.endsWith('.mjs')).map((f) => f.replace(/\.mjs$/, '')).sort()
  .filter((s) => only.length === 0 || only.includes(s));

const browser = await chromium.launch();
let fails = 0, passes = 0;
for (const name of specs) {
  const { default: spec } = await import(pathToFileURL(join(dir, `${name}.mjs`)).href);
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  page.setDefaultTimeout(6000);
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const t = {
    page, base,
    ok(cond, msg) { if (cond) { passes++; console.log(`  PASS  ${name}: ${msg}`); } else { fails++; console.log(`  FAIL  ${name}: ${msg}`); } },
    async go(path, settle = 900) { await page.goto(base + path, { waitUntil: 'load' }); await page.waitForTimeout(settle); },
    async shot(file, full = false) { if (shots) await page.screenshot({ path: join(shots, `${name}-${file}.png`), fullPage: full }); },
    async vis(loc) { return loc.first().isVisible().catch(() => false); },
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
    console.log(`  FAIL  ${name}: aborted — ${String(e.message || e).split('\n')[0]}`);
  }
  if (errors.length) { fails++; console.log(`  FAIL  ${name}: page errors — ${errors.join(' | ')}`); }
  await ctx.close();
}
await browser.close();
console.log(`UI-SUITE${token ? ' (live device)' : ''}: ${fails === 0 ? 'PASS' : 'FAIL'} — ${passes} passed, ${fails} failed (${specs.join(', ')})`);
process.exit(Math.min(fails, 100));
