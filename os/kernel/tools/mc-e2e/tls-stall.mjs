// HTTPS keep-alive stall probe (mc-e2e [7], CI g3 2026-11-12): after the TLS stress steps, a signed-in browser
// goes Home (its SSE /api/stream stays open) -> Detect, and every API call the Detect page makes must answer
// within STALL_MS. Repeats REPS times: each repetition is a fresh browser context (fresh sockets) that signs in,
// then INNER Home -> Detect round trips on the same keep-alive sockets. Prints one summary line:
//   TLS-STALL reps=<n> navigations=<n> calls=<n> stalls=<n> max_ms=<n>
// and exits 1 if any call stalled (or never answered). Run by tools/mc-e2e.sh (regression) and
// tools/mc-e2e-tls-soak.sh (repro loop).
import { chromium } from 'playwright';

const base = process.argv[2];
const token = process.argv[3] ?? '';
const REPS = Number(process.env.REPS ?? 3);
const INNER = Number(process.env.INNER ?? 3);
const STALL_MS = Number(process.env.STALL_MS ?? 5000);
const spki = process.env.MC_E2E_SPKI;
const browser = await chromium.launch(spki ? {
  args: [`--ignore-certificate-errors-spki-list=${spki}`, `--host-resolver-rules=MAP heqk.local ${process.env.MC_E2E_MAP_IP ?? '127.0.0.1'}`],
} : {});

const DETECT_CALLS = ['/api/engines', '/api/detections', '/api/reports'];
let navs = 0, calls = 0, stalls = 0, maxMs = 0;
const t0 = Date.now();
const ts = () => ((Date.now() - t0) / 1000).toFixed(1);

for (let rep = 1; rep <= REPS; rep++) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const pending = new Map(); // request -> start ms
  const done = []; // {path, ms, status}
  page.on('request', (q) => { if (q.url().includes('/api/')) pending.set(q, Date.now()); });
  page.on('response', (r) => {
    const q = r.request();
    if (!pending.has(q)) return;
    done.push({ path: new URL(r.url()).pathname, ms: Date.now() - pending.get(q), status: r.status() });
    pending.delete(q);
  });
  // every request of the page (not only /api/): a refused asset stalls the page before it makes its API calls
  const inflight = new Map();
  const failed = [];
  page.on('request', (q) => inflight.set(q, Date.now()));
  page.on('requestfinished', (q) => inflight.delete(q));
  page.on('requestfailed', (q) => { inflight.delete(q); failed.push(`${new URL(q.url()).pathname}:${q.failure()?.errorText ?? '?'}`); });
  page.on('requestfailed', (q) => { if (pending.has(q)) { done.push({ path: new URL(q.url()).pathname, ms: Date.now() - pending.get(q), status: 'failed:' + (q.failure()?.errorText ?? '?') }); pending.delete(q); } });

  await page.goto(`${base}/detect/feed`, { waitUntil: 'load' });
  await page.fill('input[name=token]', token);
  await Promise.all([page.waitForURL(`${base}/`), page.click('button[type=submit]')]);

  for (let j = 1; j <= INNER; j++) {
    if (j > 1) {
      await page.goto(`${base}/`, { waitUntil: 'load' });
    }
    // Home's fan-out + SSE stream: the first round trip leaves at once, like ui-check.mjs (Home's requests are
    // cancelled mid-flight); later ones let Home settle on the keep-alive sockets first
    if (j > 1) {
      await page.waitForResponse((r) => new URL(r.url()).pathname === '/api/stream', { timeout: 30000 }).catch(() => {});
      await page.waitForTimeout(500);
    }
    done.length = 0;
    pending.clear();
    failed.length = 0;
    const start = Date.now();
    await page.goto(`${base}/detect/feed`, { waitUntil: 'load', timeout: 60000 }).catch((e) => console.log(`    goto detect: ${e.message.split('\n')[0]}`));
    navs++;
    // every Detect call answered, or the stall budget (x3, to measure how long it really takes) ran out
    const deadline = Date.now() + STALL_MS * 3;
    while (Date.now() < deadline && !DETECT_CALLS.every((p) => done.some((d) => d.path === p))) await page.waitForTimeout(100);
    const mine = done.filter((d) => DETECT_CALLS.includes(d.path));
    const missing = DETECT_CALLS.filter((p) => !mine.some((d) => d.path === p));
    const worst = Math.max(0, ...mine.map((d) => d.ms));
    calls += mine.length + missing.length;
    maxMs = Math.max(maxMs, worst);
    const bad = mine.filter((d) => d.ms > STALL_MS || d.status !== 200).length + missing.length;
    stalls += bad;
    if (bad) {
      const now = Date.now();
      console.log(`      requests failed: ${failed.join(' ') || 'none'}; still open: ${[...inflight].filter(([q]) => !q.url().endsWith('/api/stream')).map(([q, t]) => `${new URL(q.url()).pathname}(${now - t}ms)`).join(' ') || 'none'}`);
    }
    console.log(`    [${ts()}s] rep ${rep}.${j} Home->Detect ${Date.now() - start} ms: ${mine.map((d) => `${d.path}=${d.status}/${d.ms}ms`).join(' ')}${missing.length ? ' NO-ANSWER: ' + missing.join(' ') : ''}${bad ? `  <-- STALL (epoch ${(start / 1000).toFixed(1)})` : ''}`);
  }
  await ctx.close();
}
await browser.close();
console.log(`TLS-STALL reps=${REPS} navigations=${navs} calls=${calls} stalls=${stalls} max_ms=${maxMs}`);
process.exit(stalls ? 1 : 0);
