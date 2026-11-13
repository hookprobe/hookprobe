// Board "Admin": the operating-system card. Update opens Signed packs on the OS image type (the kernel takes signed
// os_image uploads); a manual roll back is not offered as if it worked (greyed, with the reason). On a device the
// version / slot / storage come from GET /api/system; nulls and an older image without it read "not reported".
export default async function (t) {
  const { page, ok, go, vis } = t;
  await go('/admin/identity', 1200);
  const card = page.locator('[aria-label="Operating system"]');
  ok(await vis(card.locator('text=Signed OS image')) && await vis(card.locator('.gate-reason')), 'OS card: signed image generation, roll back greyed with the reason');
  await card.locator('button:has-text("Update")').click(); await page.waitForTimeout(300);
  ok(await page.locator('[aria-label="Pack type"] button[aria-pressed="true"]').textContent().then((x) => /OS image/.test(x ?? '')), 'Update: opens Signed packs with the OS image type chosen');

  // A device serving /api/system (kernel feat/api-system)
  let sys = { version: '0.9.3', build: 'd231eae7', slot: 'B', trial: true, svn: 12, storage: { used: 1.2e9, total: 7.3e9, retention_days: 7 } };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/system') return sys ? r.fulfill(json(sys)) : r.fulfill(json({}, 404));
    return r.fulfill(json({}, 404));
  });
  await go('/admin/identity', 1500);
  ok(await vis(card.locator('text=0.9.3 · build d231eae7')) && await vis(card.locator('text=B · on trial')) && await vis(card.locator('text=1.2 GB of 7.3 GB · 7 days kept')) && await vis(card.locator('text=security version 12')),
    'device: version and build, boot slot on trial, storage and retention, security version');

  // Nulls (QEMU) read "not reported", never filled in
  sys = { version: null, build: '', slot: 'A', trial: false, svn: 3, storage: null };
  await go('/admin/identity', 1500);
  ok(await vis(card.locator('text=not reported by this device yet')) && await card.locator('.prow', { hasText: 'Storage' }).textContent().then((x) => /not reported/.test(x ?? '')), 'device nulls: version and storage say not reported');

  // An older image without /api/system: the card keeps working, without slot / storage rows
  sys = null;
  await go('/admin/identity', 1500);
  ok(await vis(card.locator('text=not reported by this device yet')) && !(await card.locator('.prow', { hasText: 'Boot slot' }).count()), 'older image (no /api/system): version not reported, no invented slot or storage');
}
