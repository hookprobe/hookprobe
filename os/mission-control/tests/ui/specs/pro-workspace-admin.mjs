// Pro batch 5: Workspace (recent + pinned, this browser) and Administration (sections, guards).
export default async function (t) {
  const { page, ok, go, vis } = t;

  // A fresh context: Workspace starts empty, then records what we open.
  await go('/workspace');
  ok(await vis(page.getByText('Nothing here yet.')), 'workspace: empty state with first actions');
  await go('/detect/feed', 400);
  await go('/investigate/incident/?id=INC-0142', 400);
  await go('/workspace');
  ok(await page.locator('.obs-table tbody tr').count() >= 2, 'workspace: records the screens opened');
  await page.click('.obs-table tbody tr >> nth=0 >> button[aria-label^="Pin"]'); await page.waitForTimeout(150);
  await page.reload({ waitUntil: 'load' }); await page.waitForTimeout(500);
  await page.click('.l0-chip:has-text("Pinned")'); await page.waitForTimeout(150);
  ok(await page.locator('.obs-table tbody tr').count() === 1, 'workspace: a pin persists across reload');
  await page.click('.l0-chip:has-text("All")');
  await page.click('button:has-text("Clear recent")'); await page.waitForTimeout(150);
  ok(await page.locator('.obs-table tbody tr').count() === 1, 'workspace: Clear recent keeps pinned items');

  await go('/admin/identity');
  ok(await page.locator('[aria-label="Settings"] .shell-rail-item').count() === 8, 'admin: eight sections (incl. Signing key)');
  ok(await vis(page.getByText(/Platform manifest/)), 'admin: manifest card');
  ok(await page.locator('.inc-status', { hasText: '✓' }).count() >= 5, 'admin: granted capabilities listed');
  await page.click('[aria-label="Settings"] >> text=Signed packs'); await page.waitForTimeout(150);
  ok(await page.locator('[aria-label="Pack type"] .l0-chip').count() === 6, 'admin: six pack types');
  ok(await page.locator('button:has-text("Upload and verify")').isDisabled(), 'admin: upload disabled in preview');
  await page.click('[aria-label="Settings"] >> text=Identity and access'); await page.waitForTimeout(150);
  ok(await page.locator('button:has-text("Rotate owner key")').isDisabled(), 'admin: rotation needs a 16+ character key');
  await page.click('[aria-label="Settings"] >> text=AI models'); await page.waitForTimeout(800);
  ok(await vis(page.locator('.gate--off', { hasText: 'no on-device planner' })), 'admin: planner endpoint greyed with the reason');
  await page.click('[aria-label="Settings"] >> text=Factory reset'); await page.waitForTimeout(150);
  ok(await page.locator('button:has-text("Erase this device")').isDisabled(), 'admin: erase needs ERASE typed (and a device)');
  await t.shot('admin', true);
}
