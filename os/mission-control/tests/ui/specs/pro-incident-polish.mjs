// Pro validation (14 Nov), PR D: the incident story drills to its evidence, the sample plan never loosens containment and
// cannot be approved in a preview, the phone plan bar does not cover the story, and Mission / Customers / Business don't overclaim.
export default async function (t) {
  const { page, ok, go, vis } = t;
  await page.evaluate(() => { try { localStorage.setItem('hp.proView', '1'); } catch { /* */ } });

  await go('/investigate/incident/?id=INC-0142', 1500);
  await page.click('button.story-link:has-text("Local scanning detected")'); await page.waitForTimeout(200);
  ok(await page.locator('#tab-evidence[aria-selected="true"]').count() === 1 && /Flows ×6/.test(await page.locator('tr.is-focus').innerText().catch(() => '')),
    'incident: a story step opens the Evidence tab at its row');
  await page.click('#tab-graph'); await page.click('button.chain-link:has-text("Malware host")'); await page.waitForTimeout(200);
  ok(/Intel match/.test(await page.locator('tr.is-focus').innerText().catch(() => '')), 'incident: a graph node opens its evidence');

  const plan = (await page.locator('#inc-plan').innerText()).replace(/\s+/g, ' ');
  ok(!/internet only/.test(plan) && /isolated until you release it/.test(plan), 'incident (sample): the plan keeps the camera contained, never loosens it');
  ok(await vis(page.locator('#inc-plan .gate--off', { hasText: 'Approve plan' })) && (await page.locator('#inc-plan button', { hasText: 'Approve plan' }).evaluateAll((bs) => bs.filter((b) => !b.closest('[inert]')).length)) === 0,
    'incident (sample): Approve plan greyed with the reason');

  await page.setViewportSize({ width: 390, height: 844 }); await go('/investigate/incident/?id=INC-0142', 1200);
  const bar = await page.evaluate(() => {
    const b = document.querySelector('.inc-plan-bar')?.getBoundingClientRect();
    const card = document.getElementById('inc-plan');
    return { h: b ? b.height : 0, cardSticky: card ? getComputedStyle(card).position === 'sticky' : true };
  });
  ok(bar.h > 0 && bar.h <= 72 && !bar.cardSticky, `phone: a slim Review-plan bar (${Math.round(bar.h)} px), not the whole plan card stuck over the story`);
  await page.click('.inc-plan-bar button'); await page.waitForTimeout(700);
  ok(await page.evaluate(() => { const r = document.getElementById('inc-plan').getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0; }), 'phone: Review plan jumps to the plan');
  await page.setViewportSize({ width: 1440, height: 900 });

  await go('/mission', 1500);
  await page.click('button.pcard:has-text("Autonomous actions")'); await page.waitForTimeout(250);
  ok(await vis(page.locator('text=Durable changes (a zone move, a permanent block) happen only with your approval')), 'Mission: autonomous actions do not claim every action expires');

  await go('/customers/managed', 1500);
  ok(await vis(page.locator('.gate--off', { hasText: 'Open as this customer' })) && !(await page.locator('main a:has-text("Open as this customer")').count()), 'Customers (sample): Open as this customer greyed with the reason');

  await go('/business/dashboard', 1500);
  await page.click('.tab:has-text("Overview")'); await page.waitForTimeout(200);
  ok(await vis(page.locator('text=A standalone device has no billing')) && !(await page.locator('text=[MRR]').count()), 'Business (sample): overview labelled as a cloud-linked preview; no [MRR] placeholder');
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
