// Real-browser leg of tools/mc-e2e.sh. Loads the UNCHANGED Mission Control UI from the heqk
// device (same origin: the device served the HTML, JS and API) and asserts it rendered LIVE heqk
// data — text the UI's mock fallback can never produce.
import { chromium } from 'playwright';

const base = process.argv[2] ?? 'http://127.0.0.1:18080';
// HTTPS leg (ADR 0051): trust ONLY the device's own key (SPKI pin) and map its name to the QEMU forward —
// certificate checking stays on for everything else.
const spki = process.env.MC_E2E_SPKI;
const browser = await chromium.launch(spki ? {
  args: [`--ignore-certificate-errors-spki-list=${spki}`, `--host-resolver-rules=MAP heqk.local ${process.env.MC_E2E_MAP_IP ?? '127.0.0.1'}`],
} : {});
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const apiCalls = [];
page.on('response', (r) => { if (r.url().includes('/api/')) apiCalls.push(`${r.status()} ${new URL(r.url()).pathname}`); });
let fails = 0;
const check = (ok, what) => { console.log(`    ${ok ? 'ok ' : 'BAD'} ${what}`); if (!ok) fails++; };

// Sign in through the device's own login page with the owner key (ADR 0037 D3 (retired 2026-11-12; see in part 0051 / 0054 / 0058 / 0059)).
const token = process.argv[3] ?? '';
await page.goto(`${base}/detect/feed`, { waitUntil: 'load' });
check(new URL(page.url()).pathname === '/login', 'an unauthenticated browser is sent to the login page');
await page.fill('input[name=token]', token);
await Promise.all([page.waitForURL(`${base}/`), page.click('button[type=submit]')]);
check(new URL(page.url()).pathname === '/', 'signing in with the owner key lands on Mission Control');

// Detect workspace: the live detection feed from the device.
// 'load', not 'networkidle': the UI holds an SSE stream open by design, so the network never idles.
await page.goto(`${base}/detect/feed`, { waitUntil: 'load' });
const c2 = page.locator('.det-title', { hasText: 'Known C2 port 4444 (DROP, framedrop)' }).first();
// isVisible() does NOT wait; waitFor does (the rows arrive after /api/detections answers).
// HTTPS on TCG-emulated QEMU (CI) is slow, so it gets 60 s; plain HTTP 20 s. No reload: the page-change stall
// (all TLS slots busy -> RST on the next SYN -> a shared script failed -> the island never ran) was fixed in the
// kernel (#1078: SYN hold/replay, clean idle close), so a miss here is a real failure again.
const ROWS_MS = spki ? 60000 : 20000;
const rows = await c2.waitFor({ state: 'visible', timeout: ROWS_MS }).then(() => true).catch(() => false);
check(rows, 'Detect feed shows the heqk C2-4444 detection (rule msg + wire action + class)');
check(!(await page.getByText('Live detections unavailable').isVisible().catch(() => false)), 'Detect feed is LIVE (no "unavailable" fallback)');
await page.screenshot({ path: `${process.env.MC_E2E_SHOTS || '/tmp'}/mc-e2e-detect.png`, fullPage: true });

// Home: the "Needs you" queue counts the device's real open incidents (mock says "Nothing to approve").
await page.goto(`${base}/`, { waitUntil: 'load' });
const needs = page.locator('.needs-msg');
await needs.waitFor({ timeout: ROWS_MS });
// the live fetch replaces the mock text once /api/incidents answers
await page.waitForFunction(() => /need your review/.test(document.querySelector('.needs-msg')?.textContent ?? ''), null, { timeout: ROWS_MS }).catch(() => {});
const txt = (await needs.textContent())?.trim() ?? '';
check(/^\d+ incidents? need your review\.$/.test(txt), `Home "Needs you" is live: "${txt}"`);
await page.screenshot({ path: `${process.env.MC_E2E_SHOTS || '/tmp'}/mc-e2e-home.png`, fullPage: true });

// Shield v2 (ADR 0052): the DNS page renders the device's live data, not the sample layout.
await page.goto(`${base}/network/dns`, { waitUntil: 'load' });
// Only the live view renders the "Lists and policy" panel (the sample layout has none); a text regex over split text nodes
// matched intermittently on the HTTPS leg (local g3, 12 Nov).
const live = page.locator('section[aria-label="Lists and policy"]');
check(await live.waitFor({ state: 'visible', timeout: ROWS_MS }).then(() => true).catch(() => false), 'Shield page renders LIVE device data (/api/dns)');
check(!(await page.getByText('Sample data').first().isVisible().catch(() => false)), 'Shield page shows no "Sample data" notice');
await page.screenshot({ path: `${process.env.MC_E2E_SHOTS || '/tmp'}/mc-e2e-shield.png`, fullPage: true });

// My Network (parity G13): the device inventory, grouped by the signed DEVICES.TXT policy — not the sample map.
await page.goto(`${base}/network/map`, { waitUntil: 'load' });
const netLive = page.getByText(/grouped by the policy in your signed DEVICES\.TXT/);
check(await netLive.waitFor({ state: 'visible', timeout: ROWS_MS }).then(() => true).catch(() => false), 'My Network renders the LIVE device inventory (/api/devices)');
check(!(await page.getByText('Sample data').first().isVisible().catch(() => false)), 'My Network shows no "Sample data" notice');
await page.screenshot({ path: `${process.env.MC_E2E_SHOTS || '/tmp'}/mc-e2e-network.png`, fullPage: true });

check(apiCalls.some((c) => c.startsWith('200 /api/detections')) && apiCalls.some((c) => c.startsWith('200 /api/incidents')) && apiCalls.some((c) => c.startsWith('200 /api/dns')),
  `the UI fetched its data from the device: ${[...new Set(apiCalls)].join(', ')}`);
await browser.close();
process.exit(fails ? 1 : 0);
