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
  await go('/', 1200);
  await page.keyboard.press('Control+k'); await page.waitForTimeout(400);
  const s = await skin();
  const open = await page.locator('[role=dialog][aria-label="AI Copilot"]').isVisible().catch(() => false);
  ok(open && s.dots === 0 && !s.shell, 'Copilot (Ctrl-K): a dialog, not a shell prompt');
  await page.keyboard.press('Escape');
}
