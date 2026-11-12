// Visual pass A (UX review step 9): contrast of muted text, disabled buttons that look disabled, a visible focus
// ring everywhere, and form controls that inherit the page font (no 13.33 px browser default).
const lum = (hex) => {
  const c = hex.replace('#', '').match(/../g).map((x) => parseInt(x, 16) / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

export default async function (t) {
  const { page, ok, go } = t;
  await go('/');
  const v = await page.evaluate(() => { const s = getComputedStyle(document.documentElement); return { muted: s.getPropertyValue('--hp-text-muted').trim(), label: s.getPropertyValue('--hp-text-label').trim(), surface: s.getPropertyValue('--hp-surface').trim(), raised: s.getPropertyValue('--hp-surface-elevated').trim() }; });
  ok(ratio(v.muted, v.surface) >= 4.5 && ratio(v.muted, v.raised) >= 4.5, `muted text meets 4.5:1 on cards (${ratio(v.muted, v.surface).toFixed(2)} / ${ratio(v.muted, v.raised).toFixed(2)})`);
  ok(ratio(v.label, v.surface) >= 4.5, `label text meets 4.5:1 (${ratio(v.label, v.surface).toFixed(2)}, was 2.2)`);

  const btn = await page.locator('button.hp-btn').first().evaluate((b) => getComputedStyle(b).fontSize);
  ok(btn !== '13.3333px', `buttons inherit the page font (${btn}), not the 13.33 px browser default`);

  await page.keyboard.press('Tab'); await page.keyboard.press('Tab');
  const ring = await page.evaluate(() => { const s = getComputedStyle(document.activeElement); return `${s.outlineStyle} ${s.outlineWidth}`; });
  ok(/solid 2px/.test(ring), `keyboard focus shows a visible ring (${ring})`);

  await go('/setup');
  await page.click('button:has-text("Start")'); await page.click('.setup-cta.hp-btn--primary'); await page.waitForTimeout(200);
  const dis = await page.locator('button.hp-btn--primary:disabled').first().evaluate((b) => ({ bg: getComputedStyle(b).backgroundColor, op: getComputedStyle(b).opacity }));
  ok(dis.bg === 'rgba(0, 0, 0, 0)' && dis.op === '1', `a disabled primary button is plainly disabled (no half-lit fill: ${dis.bg})`);
}
