// Board "Admin": the operating-system card. Update opens Signed packs on the OS image type (the kernel takes signed
// os_image uploads); a manual roll back is not offered as if it worked (greyed, with the reason).
export default async function (t) {
  const { page, ok, go, vis } = t;
  await go('/admin/identity', 1200);
  const card = page.locator('[aria-label="Operating system"]');
  ok(await vis(card.locator('text=Signed OS image')) && await vis(card.locator('.gate-reason')), 'OS card: signed image generation, roll back greyed with the reason');
  await card.locator('button:has-text("Update")').click(); await page.waitForTimeout(300);
  ok(await page.locator('[aria-label="Pack type"] button[aria-pressed="true"]').textContent().then((x) => /OS image/.test(x ?? '')), 'Update: opens Signed packs with the OS image type chosen');
}
