// UX validation 13 Nov, the destructive paths in the firewall editor:
// 1) a firewall the editor cannot parse is shown as text, the editor is hidden and the draft is the policy in force
//    (it used to sit on an editable EXAMPLE: one "+ Rule" replaced the whole firewall);
// 2) the "block device-to-device" template says which LAN_IN rules it replaces and asks first (it dropped them silently).
const POLICY = 'acl LAN_IN seq 10 block tcp any 192.168.1.50 22\nacl LAN_IN default allow\ninterface lan acl in LAN_IN\n';

export default async function (t) {
  const { page, ok, go, vis } = t;
  const st = { policy: POLICY + 'tunnel pop1 wg 203.0.113.9:51820\n' };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname;
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/config') return r.fulfill(json({ state: 'committed', generation: 9, floor: 9, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      sections: { wan: { present: false, digest: null }, wifi: { present: false, digest: null }, policy: { present: true, digest: 'cc' } }, policy_text: st.policy, wan_keys: null, wifi_keys: null }));
    if (p === '/api/upload') return r.fulfill(json({ store: true, chunk_max: 16384, recent: [], in_flight: null, types: [] }));
    return r.fulfill(json({}, 404));
  });

  await go('/protect/policies', 2000);
  ok(await vis(page.locator('[aria-label="Firewall in force"]')) && !(await page.locator('main .l0-table input').count()) && !(await page.locator('button:has-text("+ Rule")').count()),
    'unparsable firewall: shown as text, no editable table, no "+ Rule"');
  ok((await page.locator('aside[aria-label="Draft file"] pre').innerText()).includes('tunnel pop1 wg'), 'unparsable firewall: the draft is the policy in force, not the example');
  ok(await vis(page.locator('text=policy-sign.py')), 'unparsable firewall: says how to change it (no dead end)');

  st.policy = POLICY;
  await go('/protect/policies', 2000);
  const rows = () => page.locator('main .l0-table tbody tr').count();
  const before = await rows();
  await page.click('button:has-text("From template: block device-to-device")'); await page.waitForTimeout(300);
  const sheet = page.locator('.approve-sheet[aria-labelledby="approve-title"]');
  ok(await vis(sheet.locator('text=Replace the LAN_IN rules?')) && await vis(sheet.locator('text=block tcp any → 192.168.1.50 port 22')), 'template: names the LAN_IN rule it would replace and asks first');
  await sheet.locator('button:has-text("Cancel")').click(); await page.waitForTimeout(200);
  ok(await rows() === before && await page.locator('main .l0-table input[aria-label="Destination"]').first().inputValue() === '192.168.1.50', 'template cancelled: the rules are untouched');
  await page.click('button:has-text("From template: block device-to-device")'); await page.waitForTimeout(300);
  await sheet.locator('button:has-text("Replace them")').click(); await page.waitForTimeout(300);
  ok(await vis(page.locator('text=Check the subnet (10.66.0.0/24)')), 'template applied: the subnet to check is stated (the device does not report its LAN range)');
}
