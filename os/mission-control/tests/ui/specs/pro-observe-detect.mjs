// Pro batch 2: Detect (feed / rules / ATT&CK) and Observe (merged live table).
export default async function (t) {
  const { page, ok, go, vis } = t;

  await go('/detect/feed');
  ok(await page.locator('.det-title').count() === 4, 'detect: sample cards with .det-title (read by mc-e2e)');
  await page.click('.l0-chip:has-text("High")'); await page.waitForTimeout(150);
  ok(await page.locator('.det-title').count() === 2, 'detect: severity filter');
  await page.click('.l0-chip:has-text("All")');
  await page.click('.tab:has-text("Rules")'); await page.waitForTimeout(150);
  ok(await page.locator('.l0-table tbody tr').count() === 4, 'detect: engines table');
  ok(await vis(page.getByText('this device accepts signed rule packs only')), 'detect: builder greyed with the reason');
  await page.click('.tab:has-text("MITRE")'); await page.waitForTimeout(150);
  await page.click('button.pcard:has-text("Command and Control")'); await page.waitForTimeout(150);
  ok(await vis(page.locator('.tab[aria-selected="true"]', { hasText: 'Threat feed' })) && await page.locator('.det-title').count() >= 1, 'detect: a tactic filters the feed');
  ok(await vis(page.locator('.l0-chip', { hasText: 'Tactic: Command and Control' })), 'detect: active tactic filter shown');
  await t.shot('detect', true);

  await go('/observe/live');
  ok(await page.locator('.obs-table tbody tr').count() === 6, 'observe: merged rows');
  await page.click('.obs-sources .shell-rail-item:has-text("DNS")'); await page.waitForTimeout(150);
  ok(await page.locator('.obs-table tbody tr').count() === 2, 'observe: source filter');
  await page.click('.obs-sources .shell-rail-item:has-text("All")');
  await page.fill('input[placeholder^="address"]', 'smart tv'); await page.waitForTimeout(150);
  ok(await page.locator('.obs-table tbody tr').count() === 1, 'observe: text filter');
  await page.fill('input[placeholder^="address"]', '');
  await page.click('button:has-text("Live")'); await page.waitForTimeout(150);
  ok(await vis(page.locator('button:has-text("Paused")')), 'observe: pause freezes');
  await page.click('.obs-table tbody tr >> nth=0 >> button'); await page.waitForTimeout(250);
  ok(await vis(page.locator('.drawer')), 'observe: row opens the Drawer');
  ok(await vis(page.locator('.drawer .gate-reason', { hasText: 'Preview: no device is answering, so there is no capture' })), 'observe: Download pcap shown greyed, with why (preview: no device)');

  await page.setViewportSize({ width: 390, height: 844 });
  await go('/observe/live');
  ok(await page.locator('.obs-table thead').evaluate((el) => el.getBoundingClientRect().height <= 1), 'observe phone: rows are cards (header hidden)');
}
