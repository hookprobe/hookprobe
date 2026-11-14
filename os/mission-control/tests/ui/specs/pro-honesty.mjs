// Pro validation (14 Nov), honesty: no sample score on a device, a failed device list says so at once, dead controls
// are greyed with a reason, and an incident id that is not in the sample is named.
export default async function (t) {
  const { page, ok, go, vis } = t;
  await page.evaluate(() => { try { localStorage.setItem('hp.proView', '1'); } catch { /* */ } });

  // preview: Customers' Generate report is greyed with why; an unknown incident id is named
  await go('/customers/managed', 1200);
  ok(await vis(page.locator('.gate--off', { hasText: 'Generate report' })) && await vis(page.locator('text=Reports come from the control plane')), 'Customers: Generate report greyed with the reason (no dead button)');
  await go('/investigate/incident?id=INC-0999', 1500);
  ok(await vis(page.locator('text=INC-0999 is not in the sample data')), 'Incident: an id outside the sample is named, not silently swapped');

  // a device that answers but has no score and whose device list fails
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/devices') return r.fulfill(json({ error: 'boom' }, 500));
    return r.fulfill(json({}, 404));
  });
  await go('/mission', 2000);
  const badge = (await page.locator('.tb-mono').first().textContent())?.trim();
  ok(badge === '—', `live device without /api/qsecbit: the top badge shows "—", not the sample 92 (${badge})`);
  await go('/network/zones', 2500);
  ok(await vis(page.locator('text=Cannot read the device list from this device right now')), 'device list fails: said at the first failure, not "Loading…" for 10–20 s');
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
