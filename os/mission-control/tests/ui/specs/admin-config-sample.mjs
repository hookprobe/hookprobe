// /admin/config with no device answering: the board's cards with labelled sample values (not an empty page), and
// nothing that would act on a device is live.
export default async function (t) {
  const { page, ok, go, vis } = t;
  await go('/admin/config', 1500);
  ok(await vis(page.locator('text=No device is answering, so everything here is sample data')), 'the page says it is sample data');
  ok(await vis(page.locator('[aria-label="Configuration in force"] >> text=Committed · generation 9'))
    && await vis(page.locator('[aria-label="Who can change it"] >> text=Only your signing key'))
    && await vis(page.locator('[aria-label="Stored settings"] >> text=Sealed with the device key')), 'sample: in force, who can change it, stored at rest');
  ok(await vis(page.locator('[aria-label="Recent changes"] >> text=generation 8 → 9')), 'sample: the journal');
  ok(await vis(page.locator('[aria-label="Recent changes"] .gate-reason')) && !(await page.locator('[aria-label="Recent changes"] button:not([inert] *):has-text("Roll back")').count()), 'sample: Roll back is greyed with the reason');
}
