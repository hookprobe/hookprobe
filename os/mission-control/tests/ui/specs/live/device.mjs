// Live leg (run by os/kernel/tools/mc-e2e.sh against heqk in QEMU, signed in with the owner key).
// READ-ONLY by contract: no owner rules, uploads, actions or restarts — the e2e run continues after this.
// Asserts what only a real device can produce: no sample banner anywhere, and device-reported values.
import { readFileSync } from 'node:fs';

const ROUTES = ['/', '/mission', '/workspace', '/observe/events', '/observe/live', '/detect/feed', '/investigate/queue',
  '/investigate/incident', '/protect/firewall', '/protect/policies', '/network/zones', '/network/map', '/network/devices',
  '/network/dns', '/network/wan', '/network/wan/advanced', '/network/wifi', '/automate/playbooks', '/intelligence/cves',
  '/customers/managed', '/business/dashboard', '/knowledge/blog', '/admin/identity', '/admin/feedback', '/setup'];

export default async function (t) {
  const { page, ok, go, vis } = t;

  // 1. Every route: served by the device, no "Sample data" banner once health has answered.
  const sampled = [];
  for (const r of ROUTES) {
    await go(r, 1800);
    if (new URL(page.url()).pathname === '/login') { sampled.push(`${r} (sent to login)`); continue; }
    if (await vis(page.locator('.hp-banner--sample'))) sampled.push(r);
  }
  ok(sampled.length === 0, `all ${ROUTES.length} routes render live device data (no sample banner)${sampled.length ? ': ' + sampled.join(', ') : ''}`);

  // 2. First-run setup describes the device's real WAN port (never the sample sentence).
  await go('/setup', 2500);
  await page.click('button:has-text("Start")'); await page.waitForTimeout(300);
  const bubble = await page.locator('.setup-bubble').innerText();
  ok(!bubble.includes('I see a cable on the internet port'), `setup: internet step reflects the device, not the sample (“${bubble.slice(0, 70)}…”)`);

  // 3. Feedback: the beacon preview carries the device's own substrate; the export says "device".
  await go('/admin/feedback', 2500);
  const beacon = JSON.parse(await page.locator('[aria-label="Beacon preview"] pre').innerText());
  ok(beacon.device_class === 'heqk' && beacon.consent.startsWith('not given'), 'feedback: beacon preview filled from the device (heqk), consent not given');
  const [d] = await Promise.all([page.waitForEvent('download'), page.click('button:has-text("Export diagnostics file")')]);
  const diag = JSON.parse(readFileSync(await d.path(), 'utf8'));
  ok(diag.source === 'device' && diag.capabilities.source === 'device' && diag.packet_path && diag.packet_path.seen > 0,
    `feedback: diagnostics from the device (capabilities reported by it, ${diag.packet_path?.seen} packets seen)`);
  ok(!/"ip"|gateway|"mac"|owner_key/i.test(JSON.stringify(diag)), 'feedback: live diagnostics carry no addresses or keys');

  // 4. Administration: Restart is offered for real (not the preview reason), and the signing-key panel renders.
  await go('/admin/identity', 2500);
  ok(await page.locator('[aria-label="Restart"] button:has-text("Restart now")').isEnabled()
    && !(await vis(page.locator('[aria-label="Restart"] >> text=Preview:'))), 'admin: Restart offered on the device');
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  ok(await vis(page.locator('[aria-label="Signing key"] >> text=Create a key in this browser')), 'admin: signing-key panel ready on the device');
}
