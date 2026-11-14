// Pro validation (14 Nov): the sample data must not contradict itself — only the kitchen camera's detections open the
// sample incident, each playbook shows its own pipeline, and Intelligence's actions don't lead nowhere.
export default async function (t) {
  const { page, ok, go, vis } = t;
  await page.evaluate(() => { try { localStorage.setItem('hp.proView', '1'); } catch { /* */ } });

  await go('/detect/feed', 1500);
  const cards = page.locator('article', { has: page.locator('.det-title') });
  const brute = cards.filter({ hasText: 'Brute force on router admin' });
  const camera = cards.filter({ hasText: 'Device resolved known C2 domain' });
  ok(await camera.locator('a:has-text("Open story")').count() === 1 && !(await brute.locator('a:has-text("Open story")').count()) && await vis(brute.locator('text=Not part of an incident in the sample data')),
    'Detect (sample): only the kitchen camera opens INC-0142; the others say they are not part of an incident');

  await go('/automate/playbooks', 1500);
  const why = async () => { await page.click('[aria-label="Stages"] .pcard:has-text("Detect")'); await page.waitForTimeout(150); return (await page.locator('section[aria-label="Pipeline"]').innerText()).replace(/\s+/g, ' '); };
  const a = await why();
  await page.click('.shell-rail-item:has-text("Compromised IoT device")'); await page.waitForTimeout(200);
  const b = await why();
  ok(/Admin brute force/.test(a) && /C2 domain/.test(b) && a !== b, 'Automate (sample): each playbook shows its own pipeline');

  await go('/intelligence/cves', 1500);
  await page.click('.obs-table tbody tr >> nth=0 >> button'); await page.waitForTimeout(250);
  ok(await vis(page.locator('.drawer .gate--off', { hasText: 'Propose a fix plan' })) && !(await page.locator('.drawer a[href="/network/devices"]').count()),
    'Intelligence (sample): Propose a fix plan greyed with the reason; exposed assets are not links to a list that lacks them');
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
