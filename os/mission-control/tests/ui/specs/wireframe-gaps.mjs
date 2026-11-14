// Wireframe gap audit (2026-11-12), small fixes: map icons without emoji, one recents row per screen, readable
// firewall cells, every Automate stage visible, no "T1200 · T1200".
export default async function (t) {
  const { page, ok, go, vis } = t;

  // Network map: the same Network screen as Zones (one device set, the Zones / Map / List switcher), no separate
  // sample map with actions that pretended to apply (retired 14 Nov)
  await go('/network/zones', 1200);
  const zonesFirst = (await page.locator('main').innerText()).match(/Alina MacBook/) !== null;
  await go('/network/map', 1200);
  const mapText = await page.locator('main').innerText();
  ok(zonesFirst && /Alina MacBook/.test(mapText) && !/Unknown Camera|Sam's iPhone/.test(mapText) && await page.locator('main a[href="/network/zones"]').count() > 0,
    'network map: the same devices and switcher as Zones (no second sample app)');
  // the device drawer: Isolate shown greyed with the reason; a time from another day carries its date
  await page.locator('main button', { hasText: 'Alina MacBook' }).first().click(); await page.waitForTimeout(300);
  ok(await vis(page.locator('.drawer .gate--off', { hasText: 'Isolate 1 h' })), 'network drawer (preview): Isolate shown greyed with the reason');
  const first = await page.locator('.drawer .l0-card-sub', { hasText: 'First seen' }).innerText();
  ok(/[A-Za-z]{3}/.test(first.replace('First seen', '')), `network drawer: "first seen" three days ago shows its date (${first.replace(/\s+/g, ' ')})`);
  await page.keyboard.press('Escape');

  // Workspace recents: My Network reached by two routes is one row
  await page.evaluate(() => { try { localStorage.removeItem('hp.workspace.v1'); localStorage.setItem('hp.proView', '1'); } catch { /* */ } });
  await go('/network/zones', 900); await go('/network/map', 900); await go('/workspace', 1200);
  const rows = await page.evaluate(() => JSON.parse(localStorage.getItem('hp.workspace.v1') ?? '[]').filter((x) => x.title === 'My Network').length);
  ok(rows === 1, `Workspace recents: one "My Network" row, not one per route (${rows})`);

  // Firewall rules: each cell shows its whole value
  await go('/protect/policies', 1500);
  const clipped = await page.evaluate(() => [...document.querySelectorAll('.l0-table input')].filter((i) => i.value && i.scrollWidth > i.clientWidth + 1).map((i) => i.value));
  ok(clipped.length === 0, `firewall rule cells are readable (clipped: ${clipped.join(', ') || 'none'})`);
  // the whole rule table fits at laptop widths (the draft panel goes under the editor on the Firewall tab)
  for (const w of [1280, 1440]) {
    await page.setViewportSize({ width: w, height: 900 }); await go('/protect/policies', 1000);
    const fit = await page.evaluate(() => { const x = document.querySelector('main .l0-table-wrap'); return x ? x.scrollWidth <= x.clientWidth + 1 : false; });
    ok(fit, `firewall table at ${w} px: every column visible, no sideways scroll`);
  }
  await page.setViewportSize({ width: 1440, height: 900 });

  // Automate: every stage is inside the pipeline card (a grid, not a row clipping Notify)
  await go('/automate/playbooks', 1500);
  const fit = await page.evaluate(() => {
    const box = document.querySelector('section[aria-label="Pipeline"]')?.getBoundingClientRect();
    const st = [...document.querySelectorAll('[aria-label="Stages"] > [role=listitem]')].map((e) => e.getBoundingClientRect());
    return { n: st.length, inside: !!box && st.every((r) => r.right <= box.right + 1 && r.left >= box.left - 1) };
  });
  ok(fit.n >= 7 && fit.inside, `Automate: all ${fit.n} stages visible inside the pipeline card`);
  ok(await page.locator('section[aria-label="Approval queue"] .gate-reason').isVisible(), 'Automate: Approve / Reject shown greyed, with the reason');

  // Detect: an unknown technique shows its id once
  await go('/detect/feed', 1500);
  const dup = await page.evaluate(() => /\b(T\d{4}(?:\.\d{3})?) · \1\b/.test(document.querySelector('main')?.innerText ?? ''));
  ok(!dup, 'Detect: no "T1200 · T1200" (the id once when the name is unknown)');
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
