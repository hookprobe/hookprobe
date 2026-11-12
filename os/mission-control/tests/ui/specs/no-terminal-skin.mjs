// The wireframes have no terminal windows: no traffic-light dots, no "hookprobe@edge" titles or shell prompts.
// Guards Shield, Investigate, the network map and the Copilot dialog against the retired skin coming back.
export default async function (t) {
  const { page, ok, go } = t;
  const skin = () => page.evaluate(() => ({ dots: document.querySelectorAll('.hp-dot').length, shell: /hookprobe@edge/.test(document.body.innerText) }));
  for (const p of ['/network/dns', '/investigate/queue', '/network/map']) {
    await go(p, 1200);
    const s = await skin();
    ok(s.dots === 0 && !s.shell, `${p}: no terminal dots or hookprobe@edge prompt`);
  }
  // Investigate: a page title (not the all-caps monospace one), no "cloud-linked" badge, and a sample incident
  // instead of a 404 when no device answers
  await go('/investigate/queue', 1500);
  ok(await page.locator('h1.pro-title:text-is("Investigate")').isVisible() && !(await page.getByText('cloud-linked').isVisible().catch(() => false)), 'Investigate: wireframe page title, no contradicting mode badge');
  ok(await page.locator('.inv-q-item', { hasText: 'Kitchen camera contacted a malware host' }).isVisible() && !(await page.getByText('Incident queue unavailable').isVisible().catch(() => false)), 'Investigate with no device: a labelled sample incident, not "unavailable"');
  await go('/', 1200);
  await page.keyboard.press('Control+k'); await page.waitForTimeout(400);
  const s = await skin();
  const open = await page.locator('[role=dialog][aria-label="AI Copilot"]').isVisible().catch(() => false);
  ok(open && s.dots === 0 && !s.shell && !(await page.locator('.cmdpalette-modal.hp-terminal').count()), 'Copilot (Ctrl-K): a dialog, not a shell prompt');
  await page.keyboard.press('Escape');
}
