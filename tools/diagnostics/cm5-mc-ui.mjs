// cm5-mc-ui.mjs — run Mission Control's LIVE UI specs (os/mission-control/tests/ui/specs/live/*.mjs, read-only by
// contract) in a real Chromium against a real CM5. Same `t` API as tests/ui/run.mjs; the only difference is that the
// device's certificate (issued by the owner CA) is trusted by pinning its SPKI, so nothing in the UI tree is changed.
//   node cm5-mc-ui.mjs <playwright node_modules> <base url> <spki sha256 base64> [shots dir]
// Owner token in $UI_LIVE_TOKEN (sign-in). Exit code = failed checks.
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [pwDir, base, spki, shots = ''] = process.argv.slice(2);
const token = process.env.UI_LIVE_TOKEN || '';
if (!token) { console.log('UI_LIVE_TOKEN (the device password) is required'); process.exit(2); }
const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '../../os/mission-control/tests/ui/specs/live');
const { chromium } = await import(pathToFileURL(join(pwDir, 'playwright', 'index.mjs')).href);
const browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${spki}`] });
let fails = 0, passes = 0;
const specs = readdirSync(dir).filter((f) => f.endsWith('.mjs')).map((f) => f.replace(/\.mjs$/, '')).sort();
for (const name of specs) {
  const { default: spec } = await import(pathToFileURL(join(dir, `${name}.mjs`)).href);
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  page.setDefaultTimeout(8000);
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const t = {
    page, base, at: '',
    ok(cond, msg) { if (cond) { passes++; console.log(`  PASS  ${name}: ${msg}`); } else { fails++; console.log(`  FAIL  ${name}: ${msg}`); } },
    async go(path, settle = 900) { await page.goto(base + path, { waitUntil: 'load' }); await page.waitForTimeout(settle); },
    async shot(file, full = false) { if (shots) await page.screenshot({ path: join(shots, `${name}-${file}.png`), fullPage: full }); },
    async vis(loc) { return loc.first().isVisible().catch(() => false); },
  };
  try {
    await page.goto(base + '/login', { waitUntil: 'load' });
    await page.fill('input[name=token]', token);
    await Promise.all([page.waitForURL((u) => new URL(u).pathname === '/', { timeout: 15000 }), page.click('button[type=submit]')]);
    passes++; console.log(`  PASS  ${name}: signed in with the device password`);
    await spec(t);
    if (shots) await page.screenshot({ path: join(shots, `${name}-last.png`), fullPage: true });
  } catch (e) {
    fails++;
    console.log(`  FAIL  ${name}: aborted${t.at ? ` at "${t.at}"` : ''} (${page.url()}) — ${String(e.message || e).split('\n')[0]}`);
  }
  if (errors.length) { fails++; console.log(`  FAIL  ${name}: page errors — ${errors.join(' | ')}`); }
  await ctx.close();
}
await browser.close();
console.log(`MC-UI (live CM5, ${base}): ${fails === 0 ? 'PASS' : 'FAIL'} — ${passes} passed, ${fails} failed (${specs.join(', ')})`);
process.exit(Math.min(fails, 100));
