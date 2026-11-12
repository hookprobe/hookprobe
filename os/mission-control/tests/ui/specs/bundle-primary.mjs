// Wireframe AdvInternet / AdvApply: on a device that takes configuration bundles, the bundle (live, trial, switches
// back by itself) is the main path; a single file is the secondary one, and is gone when a bundle is in force.
export default async function (t) {
  const { page, ok, go, vis } = t;
  const st = { cfg: { state: 'none', generation: 0, floor: 0, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '' } };
  const json = (b) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/config') return r.fulfill(json(st.cfg));
    if (p === '/api/upload') return r.fulfill(json({ store: true, chunk_max: 16384, recent: [], in_flight: null, types: [{ type: 'config', cap: 16384, generation: 0, source: 'boot', applies: 'live' }, { type: 'wifi', cap: 512, generation: 0, source: 'boot', applies: 'next_boot' }] }));
    return r.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
  });
  await go('/network/wifi', 1500);
  await page.fill('input[placeholder="HookProbe-Home"]', 'Popescu-Home'); await page.fill('input[type=password]', 'correct horse battery');
  ok(await vis(page.locator('text=apply live, without a restart')), 'header: changes apply live as a trial (not "on the next reboot")');
  ok(await vis(page.locator('button.hp-btn--primary:has-text("Review and apply live")')) && await vis(page.locator('text=bundle generation 0 → 1')), 'the bundle is the main path, with its generation');
  ok(await vis(page.locator('button:has-text("Send just this file instead")')), 'a single file is the secondary path, saying it applies at the next restart without rollback');
  await page.click('button:has-text("Review and apply live")'); await page.waitForTimeout(300);
  ok(await vis(page.locator('.drawer', { hasText: 'Apply all three together' })), 'the main button opens the bundle review');
  await page.keyboard.press('Escape');

  st.cfg = { ...st.cfg, state: 'committed', generation: 4, floor: 4 };
  await go('/network/wifi', 1500);
  ok(!(await page.locator('button:has-text("Send just this file instead")').count()) && await vis(page.locator('text=every change goes in a bundle')), 'a bundle in force: no single-file path, and why');
}
