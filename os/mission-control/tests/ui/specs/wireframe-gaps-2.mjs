// Wireframe gap audit, batch 2: Shield's top-blocked list, Protect's segment posture (greyed with the reason).
export default async function (t) {
  const { page, ok, go, vis } = t;
  await go('/network/dns', 1500);
  ok(await page.locator('section[aria-label="Top blocked today"] .shield-list-row').count() === 4 && await vis(page.locator('text=1,204 · Smart TV')), 'Shield: top blocked today, domain · count · device');

  await page.evaluate(() => { try { localStorage.setItem('hp.proView', '1'); } catch { /* */ } });
  await go('/protect/firewall', 1500);
  await page.click('.tab:has-text("Policies")'); await page.waitForTimeout(200);
  const post = page.locator('section[aria-label="Segment posture"]');
  ok(await vis(post) && await vis(post.locator('.gate-reason', { hasText: 'does not report its fail mode' })), 'Protect: segment posture shown greyed, with why it cannot be changed');
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
