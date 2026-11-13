// UX validation 13 Nov, layout and copy: Admin links not duplicated, /admin/config fits a phone, Get Online without a
// Wi-Fi network offers to set one up (QEMU finding), Guest Wi-Fi says why there is no switch, Shell in preview says why.
export default async function (t) {
  const { page, ok, go, vis } = t;

  await go('/admin/identity', 1200);
  ok(!(await page.locator('[aria-label="Settings"] a[href="/admin/config"]').count()) && !(await page.locator('[aria-label="Settings"] a[href="/admin/shell"]').count())
    && await page.locator('nav[aria-label="Administration pages"] a').count() === 3, 'Admin: Configuration and Shell only in the tab strip (no second copy in the side list)');

  await page.setViewportSize({ width: 390, height: 844 });
  await go('/admin/config', 1500);
  const w = await page.evaluate(() => document.documentElement.scrollWidth);
  ok(w <= 390, `/admin/config on a phone: no sideways scroll (${w} px)`);
  await page.setViewportSize({ width: 1440, height: 900 });

  await go('/admin/shell', 1200);
  ok(await vis(page.locator('text=Preview: no device is answering, so there is no shell to talk to')) && await page.locator('#hsh-line').isDisabled(), 'Shell in preview: the reason, input disabled (no raw HTTP 404)');

  await go('/network/wan', 1200);
  ok(await vis(page.locator('text=This device runs one Wi-Fi network. Put visitors')), 'Guest Wi-Fi: says why there is no switch, and where to put visitors');

  // a device that is not running a Wi-Fi network
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/network') return r.fulfill(json({ available: false }));
    return r.fulfill(json({}, 404));
  });
  await go('/network/wan', 1500);
  const card = page.locator('section[aria-label="Wi-Fi"]');
  ok(await vis(card.locator('a:has-text("Set up Wi-Fi")')) && !(await card.locator('button:has-text("Change password")').count()) && !(await card.locator('button:has-text("Share QR")').count()),
    'no Wi-Fi network: "Set up Wi-Fi", not Change password / an unexplained greyed Share QR');
}
