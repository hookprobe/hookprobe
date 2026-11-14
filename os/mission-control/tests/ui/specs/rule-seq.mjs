// "+ Rule" takes the next free seq in the list; count-based numbering repeated a seq the device already had
// (e.g. one rule "LAN_IN seq 20" in force → a second seq 20 → "appears twice" → the bundle could not be sent).
const POLICY = 'acl LAN_IN seq 20 allow any any any\ninterface lan acl in LAN_IN\n';

export default async function (t) {
  const { page, ok, go, vis } = t;
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/config') return r.fulfill(json({ state: 'committed', generation: 4, floor: 4, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      sections: { wan: { present: false, digest: null }, wifi: { present: false, digest: null }, policy: { present: true, digest: 'cc' } }, policy_text: POLICY, wan_keys: null, wifi_keys: null }));
    return r.fulfill(json({}, 404));
  });
  await go('/protect/policies', 1500);
  await page.click('button:has-text("+ Rule")'); await page.waitForTimeout(200);
  const seqs = await page.locator('main .l0-table input[aria-label="Sequence"]').evaluateAll((xs) => xs.map((x) => x.value));
  ok(JSON.stringify(seqs) === '["20","30"]', `+ Rule: the new rule gets the next free seq (${seqs.join(', ')})`);
  ok(!(await vis(page.locator('text=appears twice'))), '+ Rule: no duplicate-seq problem');
}
