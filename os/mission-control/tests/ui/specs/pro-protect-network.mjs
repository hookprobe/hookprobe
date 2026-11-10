// Pro batch 3: Protect (owner rules, enforcement, policies) and My Network's Move to zone.
export default async function (t) {
  const { page, ok, go, vis } = t;

  await go('/protect/firewall');
  ok(await vis(page.locator('.pcard', { hasText: 'Enforcement policy' })), 'protect: enforcement policy statement');
  ok(await page.locator('.obs-table tbody tr').count() === 3, 'protect: owner rules table');
  ok(await vis(page.locator('.go-state--up', { hasText: 'Effective' })), 'protect: rule result shown');

  await page.click('button:has-text("+ Rule")'); await page.waitForTimeout(250);
  ok(await vis(page.locator('.drawer-title', { hasText: 'New rule' })), 'protect: + Rule opens the drawer');
  ok(await vis(page.locator('.drawer .plan-diff')), 'protect: new rule shows a plan (preview)');
  await page.click('.drawer .plan-diff >> text=Approve plan'); await page.waitForTimeout(300);
  ok(/Preview: no device/.test(await page.locator('.drawer .plan-diff-status').textContent()), 'protect: preview approve fails honestly');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);

  await page.click('.tab:has-text("Enforcement")'); await page.waitForTimeout(150);
  ok(await vis(page.locator('.pcard', { hasText: 'Acting against now' })), 'protect: acting-against list');
  ok(await vis(page.locator('.pcard', { hasText: 'Isolation and other actions' })), 'protect: actions in force with End now');
  await page.click('.tab:has-text("Policies")'); await page.waitForTimeout(150);
  ok(await vis(page.locator('.pcard', { hasText: 'Threat-intel pack' })), 'protect: IOC pack');
  ok(await vis(page.locator('.gate--off', { hasText: 'Configure segmentation' })), 'protect: segmentation gated on openvswitch');
  await t.shot('protect', true);

  await go('/network/zones');
  await page.click('.dev-btn >> text=Kitchen camera'); await page.waitForTimeout(300);
  ok(await page.locator('.drawer .l0-chips[aria-label="Move to zone"] .l0-chip').count() === 3, 'network: Move to zone offers the other zones');
  ok(await vis(page.locator('.drawer >> text=Preview: on a device this becomes a permanent owner rule')), 'network: preview explains the owner rule');
  ok(await vis(page.locator('.drawer .gate--off', { hasText: 'Rename' })), 'network: Rename greyed with its reason');
}
