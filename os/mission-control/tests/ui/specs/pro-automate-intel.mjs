// Pro batch 4: Automate (pipeline, autonomy, queue, notifications) and Intelligence (IOC, CVEs, feeds).
export default async function (t) {
  const { page, ok, go, vis } = t;

  await go('/automate/playbooks');
  ok(await page.locator('.auto-grid .shell-rail-item').count() === 3, 'automate: sample playbooks');
  ok(await page.locator('[aria-label="Stages"] .pcard').count() === 7, 'automate: seven pipeline stages');
  await page.click('[aria-label="Stages"] .pcard:has-text("Contain")'); await page.waitForTimeout(150);
  ok(await vis(page.locator('text=Isolating a server always needs approval')), 'automate: stage explains why');
  ok(await vis(page.locator('.gate--off', { hasText: 'Needs approval' })), 'automate: autonomy toggle greyed with its reason');
  ok(await vis(page.locator('.gate--off', { hasText: '+ New playbook' })), 'automate: new playbook greyed with its reason');
  ok(await vis(page.locator('[aria-label="Approval queue"] >> text=NAS-01')), 'automate: approval queue item');
  ok(await vis(page.locator('[aria-label="Notifications"]')), 'automate: notifications card');
  await t.shot('automate', true);

  await go('/intelligence/cves');
  ok(await vis(page.locator('[aria-label="Threat-intel pack"]')), 'intel: IOC pack card');
  ok(await page.locator('[aria-label="Matches on this network"] .prow').count() === 2, 'intel: matches listed');
  await page.click('.tab:has-text("CVEs")'); await page.waitForTimeout(150);
  ok(await page.locator('.obs-table tbody tr').count() === 3, 'intel: CVE table');
  await page.click('.obs-table tbody tr >> nth=0 >> button'); await page.waitForTimeout(250);
  ok(await vis(page.locator('.drawer-title', { hasText: 'CVE-2024-3094' })), 'intel: CVE drawer');
  ok(await vis(page.locator('.drawer >> text=Home server')), 'intel: exposed assets in the drawer');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  await page.click('.tab:has-text("Feeds")'); await page.waitForTimeout(150);
  ok(await vis(page.locator('.gate--off', { hasText: 'STIX/TAXII' })), 'intel: feed subscriptions greyed with the reason');

  await page.setViewportSize({ width: 390, height: 844 });
  await go('/automate/playbooks');
  ok(await page.locator('.auto-grid').evaluate((el) => getComputedStyle(el).gridTemplateColumns.split(' ').length === 1), 'automate phone: single column');
}
