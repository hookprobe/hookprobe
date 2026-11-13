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
  // Final shape (docs/design/mgmt-envelope-api.md, kernel #1108): version always null, the build id identifies the image
  let sys = { version: null, build: 'm19-3f2a9c1', slot: 'B', trial: true, svn: 12, storage: { used: 1.2e9, total: 7.3e9, retention_days: null } };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/system') return sys ? r.fulfill(json(sys)) : r.fulfill(json({}, 404));
    return r.fulfill(json({}, 404));
  });
  await go('/admin/identity', 1500);
  ok(await vis(card.locator('text=build m19-3f2a9c1')) && await vis(card.locator('text=B · on trial')) && await vis(card.locator('.prow', { hasText: '1.2 GB of 7.3 GB' }))
    && !(await card.locator('text=days kept').count()) && await vis(card.locator('text=security version 12')),
    'metal: the build id (version is always null), boot slot on trial, storage (no invented retention window), security version');

  // metal MB19 (fresh flash): 512 B used reads as 512 B, not "0 MB"
  sys = { version: null, build: 'm19-db8821e9', slot: 'A', trial: false, svn: 1, storage: { used: 512, total: 465567744, retention_days: null } };
  await go('/admin/identity', 1500);
  ok(await vis(card.locator('.prow', { hasText: '512 B of 466 MB' })) && await vis(card.locator('text=build m19-db8821e9')), 'metal MB19 values: 512 B of 466 MB (not "0 MB"), build shown');

  // QEMU: everything null — every row says not reported, and "null" never reaches the screen
  sys = { version: null, build: null, slot: null, trial: null, svn: null, storage: { used: null, total: null, retention_days: null } };
  await go('/admin/identity', 1500);
  const text = (await card.textContent()) ?? '';
  ok(/not reported by this device yet/.test(text) && !/\bnull\b|NaN|undefined/.test(text)
    && await card.locator('.prow', { hasText: 'Boot slot' }).textContent().then((x) => /not reported/.test(x ?? ''))
    && await card.locator('.prow', { hasText: 'Storage' }).textContent().then((x) => /not reported/.test(x ?? '')), 'QEMU nulls: every row says not reported, no "null" on screen');

  // An older image without /api/system: the card keeps working, without slot / storage rows
  sys = null;
  await go('/admin/identity', 1500);
  ok(await vis(card.locator('text=not reported by this device yet')) && !(await card.locator('.prow', { hasText: 'Boot slot' }).count()), 'older image (no /api/system): version not reported, no invented slot or storage');
}
