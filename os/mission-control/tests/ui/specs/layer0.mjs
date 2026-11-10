// Layer 0 pillars: Home, My Network (Zones / Map / List), Shield, Get Online, Timeline & Export.
import { readFileSync } from 'node:fs';

export default async function (t) {
  const { page, ok, go, vis } = t;

  await go('/');
  ok(await vis(page.locator('.home-verdict h1')), 'home: verdict');
  ok(/Nothing to approve|need your review/.test(await page.locator('.needs-msg').textContent()), 'home: needs-msg wording (read by mc-e2e)');
  await page.click('text=What happened today'); await page.waitForTimeout(300);
  ok(await vis(page.locator('.drawer >> .l0-ev')), 'home: today drawer lists events');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  await page.click('text=See what we did and why'); await page.waitForTimeout(300);
  ok(await vis(page.locator('.drawer >> text=Confidence')), 'home: why drawer');
  await page.keyboard.press('Escape');
  await t.shot('home', true);

  await go('/network/zones');
  ok(await vis(page.locator('.l0-seg-item.is-active', { hasText: 'Zones' })), 'network: Zones segment active');
  ok(await vis(page.getByText(/grouped by the policy in your signed DEVICES\.TXT/)), 'network: subtitle (read by mc-e2e)');
  await page.click('.dev-btn >> text=Kitchen camera'); await page.waitForTimeout(300);
  ok(await vis(page.locator('.drawer-title', { hasText: 'Kitchen camera' })), 'network: device drawer');
  ok(await vis(page.locator('.drawer >> text=Re-sign it to rename a device')), 'network: rename greyed with the reason');
  await go('/network/devices');
  ok(await page.locator('.l0-table tbody tr').count() >= 5, 'network: List view table');
  ok(await vis(page.locator('.l0-seg-item.is-active', { hasText: 'List' })), 'network: List segment active');

  await go('/network/dns');
  ok(await vis(page.locator('.l0-title', { hasText: 'Shield' })), 'shield: header');

  await go('/network/wan');
  ok(await vis(page.locator('.l0-status')), 'get online: status line');
  ok(await vis(page.locator('text=Needs a second WAN port')), 'get online: backup line gated on multi_wan');
  await page.click('button:has-text("Advanced")'); await page.waitForTimeout(200);
  ok(await vis(page.locator('text=Connection type')), 'get online: Advanced shows reported settings');

  await go('/observe/events');
  ok(await page.locator('.tl-item').count() >= 4, 'timeline: events');
  await page.click('.l0-chip:has-text("Security")'); await page.waitForTimeout(200);
  const n = await page.locator('.tl-item').count();
  ok(n >= 1 && n < 6, `timeline: Security filter (${n})`);
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('button:has-text("Export")')]);
  const csv = readFileSync(await dl.path(), 'utf8');
  ok(/^time,category,title,detail,evidence/.test(csv) && csv.trim().split('\n').length === n + 1, 'timeline: CSV has the header + exactly the rows shown');
  await page.click('.l0-chip:has-text("JSON")');
  const [dj] = await Promise.all([page.waitForEvent('download'), page.click('button:has-text("Export")')]);
  const js = JSON.parse(readFileSync(await dj.path(), 'utf8'));
  ok(js.source === 'sample' && js.events.length === n, 'timeline: JSON export is labelled sample and matches');

  await page.setViewportSize({ width: 390, height: 844 });
  await go('/network/zones');
  ok(await vis(page.locator('.shell-tab.is-active', { hasText: 'My Network' })), 'phone: My Network tab active');
}
