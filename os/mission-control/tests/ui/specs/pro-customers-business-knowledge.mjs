// Pro batch 6: Customers (tenant tree), Business (licensing / overview / marketplace), Knowledge (runbooks).
export default async function (t) {
  const { page, ok, go, vis } = t;

  await go('/customers/managed');
  ok(await page.locator('[aria-label="Tenant tree"] .shell-rail-item').count() === 5, 'customers: tenant tree');
  await page.click('[aria-label="Tenant tree"] >> text=Bakery Sud'); await page.waitForTimeout(150);
  ok(await vis(page.locator('h2', { hasText: 'Bakery Sud' })), 'customers: selecting a tenant shows its dashboard');
  ok(await vis(page.getByText('you see aggregates only above this level')), 'customers: isolation statement');

  await go('/business/dashboard');
  ok(await vis(page.getByText('HookProbe OS · Community')), 'business: licensing panel');
  ok(await vis(page.getByText(/GNU AGPL-3.0/)), 'business: licence named');
  await page.click('.tab:has-text("Marketplace")'); await page.waitForTimeout(150);
  ok(await page.locator('.gate--off', { hasText: 'Install' }).count() === 3, 'business: modules greyed with the reason');

  await go('/knowledge/blog');
  ok(await page.locator('[aria-label="Documents"] .shell-rail-item').count() === 6, 'knowledge: six built-in documents');
  await page.click('[aria-label="Documents"] >> text=Lost owner key'); await page.waitForTimeout(150);
  ok(await vis(page.locator('article h2', { hasText: 'Lost owner key' })), 'knowledge: selecting opens the document');
  ok(await page.locator('article ol li').count() >= 3, 'knowledge: numbered steps');
  ok((await page.locator('article a.hp-btn--primary').getAttribute('href')) === '/admin/identity', 'knowledge: links to the screen it describes');
  await page.fill('[aria-label="Documents"] input', 'zone'); await page.waitForTimeout(150);
  ok(await page.locator('[aria-label="Documents"] .shell-rail-item').count() === 1, 'knowledge: search filters');
  ok(await vis(page.locator('.gate--off', { hasText: 'AI writer' })), 'knowledge: authoring greyed with the reason');
  await t.shot('knowledge', true);

  await page.setViewportSize({ width: 390, height: 844 });
  await go('/knowledge/blog');
  ok(await page.locator('.obs-grid--wide').evaluate((el) => getComputedStyle(el).gridTemplateColumns.split(' ').length === 1), 'knowledge phone: single column');
}
