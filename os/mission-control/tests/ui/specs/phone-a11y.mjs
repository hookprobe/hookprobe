// Phone layout and keyboard access (UX review step 5): the Advanced editors fit a 390 px phone with the draft panel
// stacked under the form; the shared Drawer is modal and keeps Tab inside; form inputs are at least 16 px (no iOS zoom).
export default async function (t) {
  const { page, ok, go } = t;
  await page.setViewportSize({ width: 390, height: 844 });
  for (const r of ['/network/wan/advanced', '/network/wifi', '/protect/policies']) {
    await go(r, 1200);
    const m = await page.evaluate(() => {
      const main = document.querySelector('.adv-grid');
      const kids = main ? [...main.children].map((c) => c.getBoundingClientRect()) : [];
      return { over: document.documentElement.scrollWidth - window.innerWidth, stacked: kids.length >= 2 && kids[1].top >= kids[0].bottom - 1 };
    });
    ok(m.over <= 0 && m.stacked, `${r}: no horizontal overflow at 390 px and the draft panel sits under the form (overflow ${m.over}px)`);
  }
  await page.setViewportSize({ width: 1440, height: 900 });

  // Drawer: modal, Tab stays inside.
  await go('/network/zones', 1200);
  await page.click('.dev-btn >> nth=0'); await page.waitForTimeout(300);
  const drawer = page.locator('aside.drawer');
  ok(await drawer.getAttribute('aria-modal') === 'true', 'drawer is announced as modal (aria-modal)');
  for (let i = 0; i < 30; i++) await page.keyboard.press('Tab');
  ok(await drawer.evaluate((el) => el.contains(document.activeElement)), 'Tab keeps focus inside the open drawer (no escape to the page behind)');
  await page.keyboard.press('Escape');

  // Inputs at least 16 px where people type keys and reasons.
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Identity and access'); await page.waitForTimeout(200);
  const sizes = await page.$$eval('main input[type=password], main input[type=text], main input:not([type])', (els) => els.map((e) => parseFloat(getComputedStyle(e).fontSize)));
  ok(sizes.length > 0 && sizes.every((s) => s >= 16), `administration inputs are at least 16 px (${sizes.join(', ')})`);
}
