// Diagnostics-owned live spec (READ-ONLY): the Administration "Operating system" card against a real CM5, compared
// with what the device itself answers on GET /api/system. Run with MC_UI_SPECS=tools/diagnostics/mc-ui-specs.
// Expected build id in $EXPECT_BUILD (optional). Screenshot: <shots>/os-card-card.png.
export default async function (t) {
  const { page, ok, go, vis } = t;
  t.at = 'admin: Operating system card';
  await go('/admin/identity', 2500);
  // fetched by the page itself (same session cookie, same pinned TLS as the UI)
  const [st, sys] = await page.evaluate(async () => { const r = await fetch('/api/system'); return [r.status, r.ok ? await r.json() : {}]; });
  ok(st === 200, `GET /api/system answers 200 on the device (got ${st})`);
  console.log(`        /api/system: ${JSON.stringify(sys)}`);
  const want = process.env.EXPECT_BUILD || '';
  if (want) ok(sys.build === want, `build is this image (${want}): ${sys.build}`);
  ok(sys.slot === 'A' || sys.slot === 'B', `boot slot reported on metal: ${sys.slot}`);
  ok(sys.trial === false, `not on trial after a cold flash: trial=${sys.trial}`);
  ok(Number.isInteger(sys.svn) && sys.svn >= 1, `security version from HBoot: ${sys.svn}`);
  const s = sys.storage || {};
  ok(Number.isInteger(s.total) && s.total > 0 && Number.isInteger(s.used) && s.used > 0 && s.used <= s.total,
    `DataVolume usage: ${s.used} of ${s.total} bytes`);
  const card = page.locator('[aria-label="Operating system"]');
  await card.scrollIntoViewIfNeeded().catch(() => {});
  ok(await vis(card), 'the Operating system card renders');
  const text = (await card.innerText().catch(() => '')).replace(/\s+/g, ' ');
  console.log(`        card: ${text.slice(0, 300)}`);
  if (sys.slot) ok(text.includes(`Boot slot ${sys.slot}`), `card shows the device's boot slot (${sys.slot})`);
  if (Number.isInteger(sys.svn)) ok(text.includes(`security version ${sys.svn}`), `card shows the device's security version (${sys.svn})`);
  await card.screenshot({ path: t.shotPath ? t.shotPath('card') : '/dev/null' }).catch(() => {});
}
