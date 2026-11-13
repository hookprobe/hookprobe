// UX validation 13 Nov: "who can reach what" is findable from both sides (zones <-> firewall), and the Wi-Fi editor does
// not show an error for a password nobody has typed yet (the device never shows the current one).
export default async function (t) {
  const { page, ok, go, vis } = t;
  await page.evaluate(() => { try { localStorage.setItem('hp.proView', '1'); } catch { /* */ } });
  await go('/protect/policies', 1500);
  ok(await vis(page.locator('main a[href="/network/zones"]', { hasText: 'My Network' })), 'firewall: points to zones in My Network for device-to-device');
  await go('/network/wifi', 1500);
  const probs = page.locator('[aria-label="Problems"]');
  ok(!(await probs.locator('.plan-diff-warn', { hasText: 'Password:' }).count()) && await vis(probs.locator('text=Type the Wi-Fi password: the device never shows the current one')),
    'Wi-Fi editor: an untyped password is a hint, not an error');
  await page.fill('input[type=password]', 'short'); await page.waitForTimeout(200);
  ok(await vis(probs.locator('.plan-diff-warn', { hasText: 'Password: 8–63' })), 'Wi-Fi editor: a password that is too short is an error');
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
