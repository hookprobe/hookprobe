// The device (sign-in) password change: the device's refusals read as words, and success ends the session honestly.
export default async function (t) {
  const { page, ok, go, vis } = t;
  let reply = { ok: false, refused: 're-authentication failed' }, body = '';
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/session') return r.fulfill(json({ csrf: 'c', next_seq: 4 }));
    if (p === '/api/owner-key') { body = r.request().postData() ?? ''; return r.fulfill(json(reply, reply.ok ? 200 : 403)); }
    if (p === '/api/login') return r.fulfill(json({}));
    return r.fulfill(json({}, 404));
  });
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Identity and access'); await page.waitForTimeout(300);
  const pw = page.locator('input[autocomplete="new-password"]');
  await pw.nth(0).fill('  a brand new password  '); await pw.nth(1).fill('  a brand new password  ');
  await page.click('button:has-text("Change device password")');
  await t.approve({ reason: 'yearly change', key: 'the old label password' });
  await page.waitForTimeout(500);
  ok(await vis(page.locator('text=Not changed: the current password is wrong.')), 'wrong current password: said in words, not "re-authentication failed"');
  const f = new URLSearchParams(body);
  ok(f.get('new_owner_key') === 'a brand new password' && f.get('owner_key') === 'the old label password' && f.get('seq') === '4', 'sends the new password trimmed (as the device stores it), the current one, and the session seq');
  reply = { ok: true, seq: 9, note: 'owner key rotated; every session ended - sign in with the new key' };
  await page.click('button:has-text("Change device password")');
  await t.approve({ reason: 'yearly change', key: 'the old label password' });
  await page.waitForTimeout(400);
  ok(await vis(page.locator('text=Device password changed. Every session has ended')) && await pw.nth(0).inputValue() === '', 'success: says "device password" (not "owner key") and clears the fields');
}
