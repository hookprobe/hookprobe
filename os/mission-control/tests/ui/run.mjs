// Mission Control UI suite runner — see run.sh. Usage: node run.mjs <playwright node_modules> <base url> [spec…]
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [pwDir, base, ...only] = process.argv.slice(2);
const here = dirname(fileURLToPath(import.meta.url));
const { chromium } = await import(pathToFileURL(join(pwDir, 'playwright', 'index.mjs')).href);
const shots = process.env.UI_SHOTS || '';

const specs = readdirSync(join(here, 'specs')).filter((f) => f.endsWith('.mjs')).map((f) => f.replace(/\.mjs$/, '')).sort()
  .filter((s) => only.length === 0 || only.includes(s));

const browser = await chromium.launch();
let fails = 0, passes = 0;
for (const name of specs) {
  const { default: spec } = await import(pathToFileURL(join(here, 'specs', `${name}.mjs`)).href);
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
    await spec(t);
  } catch (e) {
    fails++;
    console.log(`  FAIL  ${name}: aborted — ${String(e.message || e).split('\n')[0]}`);
  }
  if (errors.length) { fails++; console.log(`  FAIL  ${name}: page errors — ${errors.join(' | ')}`); }
  await ctx.close();
}
await browser.close();
console.log(`UI-SUITE: ${fails === 0 ? 'PASS' : 'FAIL'} — ${passes} passed, ${fails} failed (${specs.join(', ')})`);
process.exit(Math.min(fails, 100));
