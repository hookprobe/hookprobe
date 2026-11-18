// AB-11 / U-10: Protect → Rules offers "Remove all owner rules" (heqk ADR 0055 D7/D8 `/api/owner-rules/revoke-all`).
// The device's dry run gates the plan, Approve sends op=revoke_all + reason + permanent=true + owner_key, and
// "verified" appears only once the device reports no owner rules and no LAN-access exceptions.
export default async function (t) {
  const { page, ok, go, vis } = t;
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  const RULES = [
    { seq: 4, kind: 'shield_block', target: 'games.example', value: 'block', effective: true, shadowed_by: null },
    { seq: 5, kind: 'device_policy', target: '02:00:00:00:00:42', value: 'quarantine', effective: true, shadowed_by: null },
  ];
  const st = { cleared: false, posts: [] };
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname, m = r.request().method();
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/session') return r.fulfill(json({ csrf: 'x', next_seq: 1 }));
    if (p === '/api/owner-rules' && m === 'GET') return r.fulfill(json({ persistent: true, journal: { records: st.cleared ? 3 : 2, damaged: false, full: false }, rules: st.cleared ? [] : RULES, refused: [] }));
    if (p === '/api/lan-access') return r.fulfill(json({ default: 'block', blocked: [], exceptions: st.cleared ? [] : [{ source: 'owner', device: '02:00:00:00:00:07', dst: '192.168.1.10' }] }));
    if (p === '/api/owner-rules/revoke-all' && m === 'POST') {
      const f = Object.fromEntries(new URLSearchParams(r.request().postData() ?? ''));
      st.posts.push(f);
      if (f.dry_run === '1') return r.fulfill(json({ ok: true, seq: 0, dry_run: true, before: 'owner rules active', after: 'no owner rules (signed baseline only)', shadowed_by: null }));
      st.cleared = true;
      return r.fulfill(json({ ok: true, seq: 9, dry_run: false, before: 'owner rules active', after: 'no owner rules (signed baseline only)', shadowed_by: null }));
    }
    return r.fulfill(json({}, 404));
  });

  await go('/protect/firewall', 1500);
  const btn = page.locator('button:has-text("Remove all owner rules")');
  ok(await btn.isEnabled(), 'protect: Remove all owner rules offered when the device reports rules');
  await btn.click(); await page.waitForTimeout(600);
  const d = page.locator('.drawer');
  ok(await vis(d.locator('.drawer-title', { hasText: 'Remove all owner rules' })), 'revoke-all: opens its own drawer');
  ok(st.posts[0]?.op === 'revoke_all' && st.posts[0]?.dry_run === '1' && !st.posts[0]?.owner_key, 'revoke-all: preview is a dry run without the owner key');
  const lines = await d.locator('.plan-diff-line').allTextContents();
  ok(lines.some((l) => l.includes('games.example')) && lines.some((l) => l.includes('02:00:00:00:00:42')), 'revoke-all: plan lists each rule the device reports');
  ok(lines.some((l) => l.includes('LAN-access exceptions · 1 in force')), 'revoke-all: plan counts LAN-access exceptions');
  ok(lines.some((l) => l.includes('Signed baseline')), 'revoke-all: plan says the signed baseline stays');

  await d.locator('.plan-diff >> text=Approve plan').click();
  const sheet = page.locator('.approve-sheet');
  await sheet.waitFor({ state: 'visible' });
  ok(await vis(sheet.locator('text=cannot be undone')), 'revoke-all: approve sheet says it cannot be undone');
  ok(await sheet.locator('button[type=submit]').isDisabled(), 'revoke-all: cannot confirm without a reason and the device password');
  await t.approve({ reason: 'start over after the move', key: 'label-password-0001' }); await page.waitForTimeout(1500);
  const sent = st.posts[1] ?? {};
  ok(sent.op === 'revoke_all' && sent.permanent === 'true' && sent.owner_key === 'label-password-0001' && sent.reason === 'start over after the move' && !sent.dry_run, 'revoke-all: approve sends reason, permanent=true and the owner key');
  ok(/No owner rules are left/.test(await d.locator('.plan-diff-status').textContent() ?? ''), 'revoke-all: verified from the device read-back');
  await page.keyboard.press('Escape'); await page.waitForTimeout(300);
  ok(await vis(page.locator('text=No owner rules. The signed baseline applies as shipped.')), 'protect: table is empty after revoke-all');
  ok(await btn.isDisabled(), 'protect: nothing left to remove → button disabled');
  await page.unroute('**/api/**');
}
