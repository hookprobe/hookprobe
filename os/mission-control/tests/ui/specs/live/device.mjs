// Live leg (run by os/kernel/tools/mc-e2e.sh against heqk in QEMU, signed in with the owner key).
// READ-ONLY by contract: no owner rules, uploads, actions or restarts — the e2e run continues after this.
// Asserts what only a real device can produce: no sample banner anywhere, and device-reported values.
import { readFileSync } from 'node:fs';

const ROUTES = ['/', '/mission', '/workspace', '/observe/events', '/observe/live', '/detect/feed', '/investigate/queue',
  '/investigate/incident', '/protect/firewall', '/protect/policies', '/network/zones', '/network/map', '/network/devices',
  '/network/dns', '/network/wan', '/network/wan/advanced', '/network/wifi', '/automate/playbooks', '/intelligence/cves',
  '/customers/managed', '/business/dashboard', '/knowledge/blog', '/admin/identity', '/admin/feedback', '/admin/config', '/admin/shell', '/setup'];

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
  t.at = 'setup: Start';
  await go('/setup', 2500);
  await page.click('button:has-text("Start")'); await page.waitForTimeout(300);
  const bubble = await page.locator('.setup-bubble').innerText();
  ok(!bubble.includes('I see a cable on the internet port'), `setup: internet step reflects the device, not the sample (“${bubble.slice(0, 70)}…”)`);

  // 3. Feedback: the beacon preview carries the device's own substrate; the export says "device".
  t.at = 'feedback: Export diagnostics file';
  await go('/admin/feedback', 2500);
  const beacon = JSON.parse(await page.locator('[aria-label="Beacon preview"] pre').innerText());
  ok(beacon.device_class === 'heqk' && beacon.consent.startsWith('not given'), 'feedback: beacon preview filled from the device (heqk), consent not given');
  const [d] = await Promise.all([page.waitForEvent('download'), page.click('button:has-text("Export diagnostics file")')]);
  const diag = JSON.parse(readFileSync(await d.path(), 'utf8'));
  ok(diag.source === 'device' && diag.capabilities.source === 'device' && diag.packet_path && diag.packet_path.seen > 0,
    `feedback: diagnostics from the device (capabilities reported by it, ${diag.packet_path?.seen} packets seen)`);
  ok(!/"ip"|gateway|"mac"|owner_key/i.test(JSON.stringify(diag)), 'feedback: live diagnostics carry no addresses or keys');

  // 4. Administration: Restart is offered for real (not the preview reason), and the signing-key panel renders.
  t.at = 'admin: Restart / Signing key tab';
  await go('/admin/identity', 2500);
  ok(await page.locator('[aria-label="Restart"] button:has-text("Restart now")').isEnabled()
    && !(await vis(page.locator('[aria-label="Restart"] >> text=Preview:'))), 'admin: Restart offered on the device');
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  ok(await vis(page.locator('[aria-label="Signing key"] >> text=Create key and download backup')), 'admin: signing-key panel ready on the device');

  // 5. Screens built 12 Nov, read-only: nothing below signs, uploads or sends.
  t.at = 'get online: Change password sheet';
  await go('/network/wan', 2500);
  await page.click('section[aria-label="Wi-Fi"] button:has-text("Change password")'); await page.waitForTimeout(1500);
  const sheet = page.locator('[role=dialog][aria-labelledby="wifi-sheet-title"]');
  ok(await vis(sheet) && !(await vis(sheet.locator('text=Preview: no device is connected'))), 'get online: the Wi-Fi sheet opens on the device (a form, or why it cannot change it here)');
  await page.keyboard.press('Escape'); await page.waitForTimeout(300);
  ok(!(await vis(sheet)), 'get online: Esc closes the Wi-Fi sheet without sending anything');

  t.at = 'admin config: device values';
  await go('/admin/config', 2500);
  const inForce = await page.locator('[aria-label="Configuration in force"] .cfg-big').innerText();
  ok(inForce !== 'Not reported' && !(await vis(page.locator('[aria-label="Recent changes"] >> text=Preview: no device is answering'))), `admin config: configuration in force from the device (“${inForce}”)`);

  t.at = 'shield: live panels';
  await go('/network/dns', 2500);
  ok(await vis(page.locator('section[aria-label="Lists and policy"]')) && !(await page.locator('.hp-dot').count()), 'shield: live panels in the wireframe layout (no terminal frame)');

  t.at = 'investigate: no sample row';
  await go('/investigate/queue', 2500);
  ok(!(await vis(page.locator('.inv-q-meta', { hasText: '· sample' }))), 'investigate: the queue is the device\'s, not the sample incident');
}
