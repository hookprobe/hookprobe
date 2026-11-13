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
// MC_UI_SPECS: run another read-only spec directory instead (e.g. tools/diagnostics/mc-ui-specs, owned by diagnostics)
const dir = process.env.MC_UI_SPECS || join(here, '../../os/mission-control/tests/ui/specs/live');
const { chromium } = await import(pathToFileURL(join(pwDir, 'playwright', 'index.mjs')).href);
const browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${spki}`] });
let fails = 0, passes = 0;
const timing = []; // [ms, path] per page load (TLS slot pressure on metal)
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
    async go(path, settle = 900) { const t0 = Date.now(); await page.goto(base + path, { waitUntil: 'load' }); timing.push([Date.now() - t0, path]); await page.waitForTimeout(settle); },
    async shot(file, full = false) { if (shots) await page.screenshot({ path: join(shots, `${name}-${file}.png`), fullPage: full }); },
    async vis(loc) { return loc.first().isVisible().catch(() => false); },
    shotPath(file) { return shots ? join(shots, `${name}-${file}.png`) : ''; },
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
if (timing.length) {
  const ms = timing.map((x) => x[0]).sort((a, b) => a - b);
  const slow = [...timing].sort((a, b) => b[0] - a[0]).slice(0, 5).map(([m, p]) => `${p} ${m} ms`).join(', ');
  console.log(`  TIMING page loads: n=${ms.length} median=${ms[ms.length >> 1]} ms p90=${ms[Math.floor(ms.length * 0.9)]} ms max=${ms[ms.length - 1]} ms | slowest: ${slow}`);
}
console.log(`MC-UI (live CM5, ${base}): ${fails === 0 ? 'PASS' : 'FAIL'} — ${passes} passed, ${fails} failed (${specs.join(', ')})`);
process.exit(Math.min(fails, 100));
