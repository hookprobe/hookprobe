// Pro validation (14 Nov): sample times come from one clock (store/sampleClock.ts), so the kitchen-camera incident has the
// same time on every page, the C2 lookup comes before the scan, and the timeline never shows an event in the future.
export default async function (t) {
  const { page, ok, go } = t;
  await page.evaluate(() => { try { localStorage.setItem('hp.proView', '1'); } catch { /* */ } });
  const hm = (s) => (s.match(/\b(\d{2}:\d{2})/) ?? [])[1] ?? '';

  await go('/investigate/incident/?id=INC-0142', 1500);
  const opened = hm((await page.locator('.pro-sub').innerText()).split('opened')[1] ?? '');
  const isolatedStep = hm(await page.locator('.story-step', { hasText: 'Isolated automatically' }).locator('.story-meta').innerText());

  await go('/mission', 1500);
  const mission = hm(await page.locator('.prow', { hasText: 'Kitchen camera contacted malware host' }).innerText());
  const tl = hm(await page.locator('.aitl-item', { hasText: 'Kitchen camera isolated' }).locator('.aitl-when').innerText());

  await go('/investigate/queue', 1500);
  const queue = hm(await page.locator('.inv-q-item', { hasText: 'Kitchen camera' }).locator('.inv-q-time').innerText());

  ok(opened && [isolatedStep, mission, tl, queue].every((x) => x === opened),
    `the camera incident has one time everywhere (incident ${opened}, step ${isolatedStep}, Mission ${mission}, timeline ${tl}, queue ${queue})`);

  // nothing in the sample timeline is later than now
  await go('/mission', 1200);
  const future = await page.evaluate(() => {
    const now = new Date(); const cur = now.getHours() * 60 + now.getMinutes();
    return [...document.querySelectorAll('.aitl-when')].map((e) => e.textContent ?? '').map((s) => (s.match(/(\d{2}):(\d{2})/) ?? []).slice(1).map(Number))
      .filter((x) => x.length === 2).filter(([h, m], i, all) => i === 0 && h * 60 + m > cur + 1).length;
  });
  ok(future === 0, 'the newest sample timeline event is not in the future');

  // Detect: the C2 lookup precedes the LAN scan (the feed is newest first)
  await go('/detect/feed', 1500);
  const order = await page.evaluate(() => [...document.querySelectorAll('.det-title')].map((e) => e.textContent ?? ''));
  const iC2 = order.findIndex((x) => /C2 domain/.test(x)), iScan = order.findIndex((x) => /scanning LAN/.test(x));
  ok(iC2 >= 0 && iScan >= 0 && iScan < iC2, 'Detect (sample): the scan is newer than the C2 lookup, as in the story');

  // Protect: the 1-hour isolation that started a minute ago has ~59 min left
  await go('/protect/firewall', 1500);
  await page.click('.tab:has-text("Enforcement")').catch(() => {}); await page.waitForTimeout(200);
  const left = await page.evaluate(() => (document.querySelector('main')?.innerText.match(/(\d+) min left/) ?? [])[1]);
  ok(!!left && Number(left) >= 55, `Protect (sample): the camera isolation shows the time it really has left (${left ?? 'n/a'} min)`);
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
