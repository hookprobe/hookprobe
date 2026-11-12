// Device-wide configuration banners (ADR 0059): the red "Configuration unprotected" banner and the trial
// banner with its countdown. Device answers are served by route interception (shapes from the heqk session).
export default async function (t) {
  const { page, ok, go, vis } = t;
  const json = (body) => (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

  // Nothing served → no banners (older devices, preview).
  await go('/');
  ok(!(await vis(page.locator('.hp-banner--danger, .hp-banner--trial'))), 'no banners when the device does not serve /api/config or /api/anchor');

  await page.route('**/api/anchor', json({ vendor_key: null, owner_key: null, owner_enrolled: false, owner_generation: 0, config_files_verified_by: 'none (standalone)', can: 'enroll',
    config_protected: false, state: 'CONFIG UNPROTECTED', floors: { wan: { current: 3, floor: 3 }, wifi: { current: 1, floor: 1 }, policy: 2 } }));
  await page.route('**/api/config', json({ state: 'trial', generation: 5, floor: 3, on_trial: true, window_s: 300, elapsed_s: 60, auto_rollback: true, health: 'waiting for the internet' }));
  await go('/network/wan', 1500);
  ok(await vis(page.locator('.hp-banner--danger >> text=Configuration unprotected')), 'red banner when the device reports CONFIG UNPROTECTED');
  ok(await page.locator('.hp-banner--danger a[href="/admin/identity"]').count() === 1, 'unprotected banner links to the fix');
  const trial = page.locator('[aria-label="Configuration trial"]');
  ok(await vis(trial.locator('text=generation 5 is on trial')), 'trial banner names the generation on trial');
  const t1 = await trial.locator('b').innerText();
  await page.waitForTimeout(2200);
  const t2 = await trial.locator('b').innerText();
  ok(/^[34]:\d\d$/.test(t1) && t2 < t1, `countdown runs from the device's window (${t1} → ${t2})`);
  ok(await vis(trial.locator('text=goes back to the previous settings (generation 3) by itself')), 'automatic rollback promised (auto_rollback), naming the last committed generation (floor)');
  ok(await vis(trial.locator('button:has-text("Keep it")')) && await vis(trial.locator('button:has-text("Roll back now")')), 'Keep it and Roll back now offered');

  // Without auto_rollback the banner must not promise one.
  await page.unroute('**/api/config');
  await page.route('**/api/config', json({ state: 'trial', generation: 5, floor: 3, on_trial: true, window_s: 300, elapsed_s: 0, auto_rollback: false, health: '' }));
  await go('/network/wan', 1500);
  ok(await vis(trial.locator('text=It stays until you keep it or roll it back')) && !(await vis(trial.locator('text=by itself'))), 'no rollback promise when the device does not report one');

  // Management-plane change: Keep is required, not automatic.
  await page.unroute('**/api/config');
  await page.route('**/api/config', json({ state: 'trial', generation: 5, floor: 3, on_trial: true, window_s: 300, elapsed_s: 10, auto_rollback: true, needs_confirm: true, health: 'internet up' }));
  await go('/network/wan', 1500);
  ok(await vis(trial.locator('text=Keep it is required')) && !(await vis(trial.locator('text=by itself in'))), 'management-plane trial: Keep is required (not auto-committed)');

  // A bundle in force: single-file changes are refused by the device, so the editor steers to the bundle.
  await page.unroute('**/api/config');
  await page.route('**/api/config', json({ state: 'committed', generation: 5, floor: 5, on_trial: false, window_s: 300, elapsed_s: 0, auto_rollback: true, needs_confirm: false, health: '' }));
  await go('/network/wifi', 1500);
  await page.fill('input[placeholder="HookProbe-Home"]', 'Locked'); await page.fill('input[type=password]', 'correct horse battery');
  ok(await vis(page.locator('text=A configuration bundle is in force (generation 5)')) && await page.locator('button:has-text("Review and sign")').isDisabled(),
    'bundle in force: single-file change disabled, steered to "Apply all three together"');
  await page.click('button:has-text("Review all three")'); await page.waitForTimeout(300);
  const bd = page.locator('.drawer', { hasText: 'Apply all three together' });
  ok(await vis(bd.locator('[aria-label="Bundle problems"] >> text=leaving it out removes it')) && ((await bd.locator('button:has-text("the bundle")').count()) === 0 || await bd.locator('button:has-text("the bundle")').isDisabled()),
    'bundle in force: a new bundle without the firewall is refused (a bundle replaces all of it; leaving a section out removes it)');
  await page.keyboard.press('Escape'); await page.waitForTimeout(200);

  // Floors in the key panel.
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.locator('label:has-text("Backup passphrase") input').fill('floors passphrase');
  await page.locator('label:has-text("Repeat it") input').fill('floors passphrase');
  await Promise.all([page.waitForEvent('download'), page.click('text=Create key and download backup')]); await page.waitForTimeout(800);
  ok(await vis(page.locator('.prow', { hasText: 'Internet settings' }).locator('text=generation 3')), 'key panel shows per-file generation floors');
  ok(await vis(page.locator('.prow', { hasText: 'Firewall settings' }).locator('text=older than 3 refused')), 'policy floor as a bare number (device shape) shown');
}
