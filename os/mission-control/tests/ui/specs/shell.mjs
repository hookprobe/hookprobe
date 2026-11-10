// Global shell: top bar, rails, Pro view persistence, Copilot, Sample-data banner, tablet/phone nav,
// Drawer (Esc + focus), PlanDiff failure → Retry, capability gating with a reason.
export default async function (t) {
  const { page, ok, go, vis } = t;
  await go('/');
  ok(await vis(page.locator('.shell-topbar .organism-pill')), 'status pill in the top bar');
  ok((await page.locator('.shell-topbar .organism-pill').getAttribute('href')) === '/mission', 'status pill links to /mission');
  ok(await vis(page.locator('.shell-rail:not(.shell-rail--pro)')), 'standalone default: the Layer 0 rail');
  ok(await page.locator('.shell-rail-item').filter({ hasText: /^(Home|Shield|My Network|Get Online|Timeline & Export)$/ }).count() === 5, 'five pillars');
  ok(await vis(page.getByText('Sample data')), 'Sample-data banner when no device answers');

  await page.click('.shell-rail-pro');
  await page.reload({ waitUntil: 'load' }); await page.waitForTimeout(500);
  ok(await vis(page.locator('.shell-rail--pro')), 'Pro view persists across reload');
  ok(await vis(page.locator('.shell-rail-item', { hasText: 'Network / Gateway' })), 'Pro rail lists Network / Gateway');
  ok(await page.locator('.shell-rail-item', { hasText: 'Customers' }).count() === 0, 'standalone hides Customers');
  await page.click('.shell-rail-back'); await page.waitForTimeout(200);
  ok(await page.locator('.shell-rail--pro').count() === 0, 'Back to simple view');

  await page.keyboard.press('Control+k'); await page.waitForTimeout(300);
  ok(await vis(page.locator('.cmdpalette-backdrop')), 'Ctrl+K opens the Copilot');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  ok(await page.locator('.cmdpalette-backdrop').count() === 0, 'Esc closes the Copilot');

  // Drawer: open, focus inside, Esc closes, focus returns
  await go('/mission');
  const card = page.locator('button.pcard', { hasText: 'Performance' });
  await card.click(); await page.waitForTimeout(250);
  ok(await vis(page.locator('.drawer')), 'Drawer opens from a card');
  ok(await page.evaluate(() => document.activeElement?.classList.contains('drawer-close')), 'focus moves into the Drawer');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);
  ok(await page.locator('.drawer').count() === 0, 'Esc closes the Drawer');
  ok(await page.evaluate(() => document.activeElement?.classList.contains('pcard')), 'focus returns to the opener');

  // PlanDiff: a failed approve names the failure and offers Retry (preview has no device)
  await go('/investigate/incident/?id=INC-0142');
  await page.click('.plan-diff >> text=Approve plan'); await page.waitForTimeout(300);
  ok(/Failed/.test(await page.locator('.plan-diff-status').textContent()), 'PlanDiff: failure is stated');
  ok(await vis(page.locator('.plan-diff >> text=Retry')), 'PlanDiff: Retry offered');
  ok(await page.locator('.plan-step--failed').count() === 1, 'PlanDiff: exactly the failed step is marked');

  // Gate: denied control greyed, inert, with its reason
  await go('/network/wan');
  const gated = page.locator('.gate--off', { hasText: 'Add backup' });
  ok(await vis(gated), 'Gate: denied control rendered greyed');
  ok(await gated.locator('[inert]').count() === 1, 'Gate: denied control is inert');
  ok(await vis(gated.locator('.gate-reason')), 'Gate: the reason is written next to it');

  // Tablet: rail is a drawer behind the menu button
  await page.setViewportSize({ width: 900, height: 1000 });
  await go('/');
  ok(!(await page.locator('.shell-rail-wrap').evaluate((el) => el.getBoundingClientRect().right > 0)), 'tablet: rail hidden');
  await page.click('.tb-menu'); await page.waitForTimeout(300);
  ok(await page.locator('.shell-rail-wrap.is-open').count() === 1, 'tablet: menu opens the rail');
  await page.keyboard.press('Escape'); await page.waitForTimeout(250);
  ok(await page.locator('.shell-rail-wrap.is-open').count() === 0, 'tablet: Esc closes it');

  // Phone: bottom tabs
  await page.setViewportSize({ width: 390, height: 844 });
  await go('/');
  ok(await page.locator('.shell-tab').count() === 5, 'phone: five bottom tabs');
  ok(await vis(page.locator('.shell-tab.is-active', { hasText: 'Home' })), 'phone: Home tab active on /');
  await t.shot('phone-home', true);
}
