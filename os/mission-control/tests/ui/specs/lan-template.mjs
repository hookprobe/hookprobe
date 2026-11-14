// The "block device-to-device" template uses the LAN range the device reports (heqk #1140, GET /api/network lan.cidr)
// instead of a hard-coded subnet the user had to check.
export default async function (t) {
  const { page, ok, go, vis } = t;
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/network') return r.fulfill(json({ available: true, lan: { ip: '10.99.0.1', prefix: 24, cidr: '10.99.0.0/24' } }));
    if (p === '/api/config') return r.fulfill(json({ state: 'committed', generation: 4, floor: 4, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      sections: { wan: { present: false, digest: null }, wifi: { present: false, digest: null }, policy: { present: true, digest: 'cc' } }, policy_text: 'acl MGMT_IN seq 10 allow tcp any any 443\ninterface mgmt acl in MGMT_IN\n', wan_keys: null, wifi_keys: null }));
    return r.fulfill(json({}, 404));
  });
  await go('/protect/policies', 2000);
  await page.click('button:has-text("From template: block device-to-device")'); await page.waitForTimeout(300);
  const src = await page.locator('main .l0-table input[aria-label="Source"]').evaluateAll((xs) => xs.map((x) => x.value).find((v) => v.includes('/')) ?? '');
  ok(src === '10.99.0.0/24', `template: the LAN range the device reports (${src})`);
  ok(await vis(page.locator('text=Template added for your LAN, 10.99.0.0/24 (as this device reports it)')) && !(await page.locator('text=Check the subnet').count()), 'template: says the range came from the device (nothing to check)');
}
