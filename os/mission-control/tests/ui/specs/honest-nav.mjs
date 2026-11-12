// Honest fallbacks and two-way navigation (UX review step 8): never show sample data once a device has answered,
// a 401 is "signed out" (not "no device"), the home hero waits for the device, and each view links to the other.
export default async function (t) {
  const { page, ok, go, vis } = t;
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });

  // Navigation both ways (preview).
  await go('/');
  ok(await vis(page.locator('nav[aria-label="Main"] a[href="/admin/identity"]')), 'simple view: the rail links to Settings (Administration)');
  await page.evaluate(() => localStorage.setItem('hp.proView', '1'));
  await go('/mission');
  ok(await page.locator('nav[aria-label="Workspaces"] a[href="/"]', { hasText: 'Home' }).count() === 1, 'Pro view: the rail links back to the simple Home');
  await page.evaluate(() => localStorage.setItem('hp.proView', '0'));

  // Signed out: 401 from the device.
  await page.route('**/api/**', (r) => r.fulfill(json({ error: 'unauthorized' }, 401)));
  await go('/', 2500);
  ok(await vis(page.locator('.hp-banner >> text=Signed out')) && await page.locator('.hp-banner a[href="/login"]').count() === 1 && !(await vis(page.locator('text=No device is answering'))),
    'a 401 reads "Signed out — sign in again", never "no device is answering"');
  await page.unroute('**/api/**');

  // Home hero waits for the device (health never answers yet).
  await page.route('**/api/health', () => { /* hold the request: the device has not answered yet */ });
  await go('/', 1200);
  ok(await vis(page.locator('h1', { hasText: 'Checking your network' })) && !(await vis(page.locator('.home-orb-num b', { hasText: '92' }))), 'home hero: "Checking…" until the device answers (no sample score)');
  await page.unroute('**/api/health');

  // A device that answers but cannot list devices: an error, never the sample map.
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/devices') return r.fulfill(json({ error: 'boom' }, 500));
    if (p === '/api/dns') return r.fulfill(json({}, 404));
    return r.fulfill(json({}, 404));
  });
  await go('/network/map', 12500);
  ok(await vis(page.locator('text=Cannot read the device list from this device right now')) && !(await vis(page.locator('text=Kitchen camera'))), 'device list failing on a real device: an error message, no sample devices');

  // Shield on a device build without /api/dns: said plainly, no sample counters.
  await go('/network/dns', 2500);
  ok(await vis(page.locator('text=does not serve Shield')) && !(await vis(page.locator('button:has-text("Balanced")'))), 'Shield not served by this device: said plainly, no sample controls');
  await page.unroute('**/api/**');
}
