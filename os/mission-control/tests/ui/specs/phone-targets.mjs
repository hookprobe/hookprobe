// Phone pass (14 Nov): on a phone every control in the page is a 44 px target and no text is under 11 px — the screens
// that had 28–36 px chips / row buttons and 9–10 px badges (all Pro screens and the Layer 0 ones).
export default async function (t) {
  const { page, ok, go } = t;
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => { try { localStorage.setItem('hp.proView', '1'); } catch { /* */ } });
  for (const r of ['/workspace', '/observe/live', '/observe/events', '/detect/feed', '/intelligence/cves', '/network/devices', '/network/map', '/network/dns', '/investigate/queue']) {
    await go(r, 1100);
    const res = await page.evaluate(() => {
      const shown = (e) => { const b = e.getBoundingClientRect(); return b.width > 0 && b.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
      const small = [...document.querySelectorAll('main button, main [role=tab], main select')].filter(shown)
        .filter((e) => { const b = e.getBoundingClientRect(); return b.height < 43.5 || b.width < 43.5; }).map((e) => (e.textContent || e.getAttribute('aria-label') || '').trim().slice(0, 16));
      const tiny = [...document.querySelectorAll('main *')].filter((e) => shown(e) && [...e.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim()) && parseFloat(getComputedStyle(e).fontSize) < 11)
        .map((e) => e.textContent.trim().slice(0, 16));
      return { small, tiny };
    });
    ok(res.small.length === 0 && res.tiny.length === 0, `${r} on a phone: 44 px targets, text ≥ 11 px${res.small.length ? ` (small: ${res.small.slice(0, 3).join(', ')})` : ''}${res.tiny.length ? ` (tiny: ${res.tiny.slice(0, 3).join(', ')})` : ''}`);
  }
  await page.evaluate(() => { try { localStorage.removeItem('hp.proView'); } catch { /* */ } });
}
