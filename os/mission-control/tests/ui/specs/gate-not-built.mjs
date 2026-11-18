// AB-12 / U-11: a control whose screen is not built stays greyed with its reason even when the device GRANTS the
// capability — never a live-looking button that does nothing. heqk denies all three today; this grants them.
export default async function (t) {
  const { page, ok, go, vis } = t;
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone', capabilities: ['wan', 'wifi_ap', 'multi_wan', 'guest_ssid', 'openvswitch'] }));
    return r.fulfill(json({}, 404));
  });
  const notBuilt = async (where, label) => {
    const g = page.locator('.gate--off', { hasText: label });
    ok(await vis(g), `${where}: "${label}" greyed although the capability is granted`);
    ok(await g.locator('[inert]').count() === 1, `${where}: "${label}" is inert`);
    ok(/no screen for this yet/.test(await g.locator('.gate-reason').textContent() ?? ''), `${where}: "${label}" says why`);
  };
  await go('/network/wan', 1500);
  await notBuilt('get online', 'Add backup');
  await notBuilt('get online', 'Turn on guest Wi-Fi');
  await go('/protect/firewall', 1500);
  await page.click('.tab:has-text("Policies")'); await page.waitForTimeout(200);
  await notBuilt('protect', 'Configure segmentation');
}
