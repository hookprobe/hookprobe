// Pro batch 1: Mission Control bento + drawers; the incident story (tabs, why, plan, routes).
export default async function (t) {
  const { page, ok, go, vis } = t;

  await go('/mission');
  ok(await page.locator('.pcard').count() >= 8, 'mission: cards render');
  for (const c of ['Global health', 'Threat pulse', 'Engines', 'Active incidents', 'Autonomous actions', 'Infrastructure', 'Performance', 'Activity timeline']) {
    ok(await vis(page.locator('.pcard', { hasText: c })), `mission: ${c} card`);
  }
  ok(await page.locator('.pcard', { hasText: 'Fleet health' }).count() === 0, 'mission: fleet card hidden in standalone');
  await page.click('button.pcard:has-text("Threat pulse")'); await page.waitForTimeout(250);
  ok(await vis(page.locator('.drawer >> text=Open Detect')), 'mission: card drawer links to its full view');
  await page.keyboard.press('Escape');
  await t.shot('mission', true);

  await go('/investigate/incident/?id=INC-0142');
  ok(await vis(page.locator('.pro-title', { hasText: 'Kitchen camera' })), 'incident: title');
  ok(await vis(page.locator('.pro-crumb a', { hasText: 'Investigate' })), 'incident: breadcrumb');
  ok(await page.locator('.story-step').count() === 4, 'incident: story steps');
  for (const tab of ['Evidence', 'Graph', 'Executive summary']) {
    await page.click(`.tab:has-text("${tab}")`); await page.waitForTimeout(150);
    ok(await vis(page.locator('.tab[aria-selected="true"]', { hasText: tab })), `incident: ${tab} tab`);
  }
  ok(await vis(page.getByText('Print or save as PDF')), 'incident: printable summary');
  ok(await vis(page.locator('.inc-side >> text=Why this was decided')), 'incident: why column');
  await t.shot('incident', true);

  await go('/investigate/incident/');
  ok(await vis(page.locator('.pro-main')), 'incident: renders without an id');

  await page.setViewportSize({ width: 900, height: 1100 });
  await go('/investigate/incident/?id=INC-0142');
  ok(await page.locator('.inc-plan-sticky').evaluate((el) => getComputedStyle(el).position === 'sticky'), 'incident tablet: plan is a sticky bar');
}
