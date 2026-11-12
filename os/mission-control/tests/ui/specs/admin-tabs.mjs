// The Administration tab strip (boards Admin / AdminConfig / AdminShell): each admin page reaches the others in one
// click and marks itself as the current one.
export default async function (t) {
  const { page, ok, go } = t;
  for (const [href, label] of [['/admin/identity', 'Settings'], ['/admin/config', 'Configuration and keys'], ['/admin/shell', 'Shell']]) {
    await go(href, 1200);
    const nav = page.locator('nav[aria-label="Administration pages"]');
    const n = await nav.locator('a.tab').count();
    const cur = await nav.locator('a.tab[aria-current="page"]').allTextContents();
    ok(n === 3 && cur.length === 1 && cur[0] === label, `${href}: the admin tab strip, "${label}" marked current`);
  }
  await page.locator('nav[aria-label="Administration pages"] a', { hasText: 'Configuration and keys' }).click();
  await page.waitForURL(/\/admin\/config/);
  ok(/\/admin\/config/.test(page.url()), 'Shell → Configuration in one click');
}
