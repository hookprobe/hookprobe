// The bench CM5's exact configuration shape (heqk session, metal MB27): the bundle in force has a WAN and a firewall
// section but NO Wi-Fi section (its Wi-Fi comes from the per-file WIFI.TXT). The first metal journey could not send:
// the editor assumed every bundle carries Wi-Fi. Now a firewall change sends WAN + firewall only — Wi-Fi keeps its
// per-file settings, no Wi-Fi password is asked — verified with os/kernel/tools/hqcfg.py.
import { writeFileSync, mkdtempSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const DEV = '00112233445566778899aabbccddeeff';
const PKCS8 = Buffer.from('302e020100300506032b657004220420' + '71'.repeat(32), 'hex');
const PEM = `-----BEGIN PRIVATE KEY-----\n${PKCS8.toString('base64')}\n-----END PRIVATE KEY-----\n`;
const PUBHEX = createPublicKey(createPrivateKey({ key: PKCS8, format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
const POLICY = 'acl LAN-IN seq 10 block tcp any 1.1.1.1/32 80\nacl LAN-IN default allow\ninterface lan acl in LAN-IN\nroute 0.0.0.0/0 via wan\n';

export default async function (t) {
  const { page, ok, go, vis } = t;
  const st = { chunks: [] };
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  await page.route('**/api/**', (r) => {
    const p = new URL(r.request().url()).pathname, m = r.request().method();
    if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone' }));
    if (p === '/api/session') return r.fulfill(json({ csrf: 'x', next_seq: 1 }));
    if (p === '/api/network') return r.fulfill(json({ available: true, wifi: { ssid: 'HookProbe-7c1e', channel: 6, width_mhz: 20, security: 'WPA2', source: 'signed WIFI.TXT' } }));
    if (p === '/api/anchor') return r.fulfill(json({ vendor_key: null, owner_key: PUBHEX, owner_enrolled: true, owner_generation: 1, config_files_verified_by: 'owner', can: 'rotate', device_id: DEV, state: 'protected' }));
    if (p === '/api/config') return r.fulfill(json({ state: 'committed', generation: 4, floor: 4, on_trial: false, needs_confirm: false, window_s: 300, elapsed_s: 0, auto_rollback: true, health: '',
      sections: { wan: { present: true, digest: '7b52306e' }, wifi: { present: false, digest: null }, policy: { present: true, digest: 'ccf95e95' } },
      wan_keys: { mode: 'dhcp', vlan: '100', mgmt_vlan: '200', mgmt: 'dhcp', pppoe_pass_set: false }, wifi_keys: null, policy_text: POLICY,
      envelope: { format: 'HQMGMT1', device_id: DEV, epoch: '0102030405060708', next_seq: 5, generation: 4, digest: '00'.repeat(32), owner_enrolled: true } }));
    if (p === '/api/upload' && m === 'GET') return r.fulfill(json({ store: true, chunk_max: 16384, in_flight: st.inFlight ?? null, recent: [], types: [{ type: 'config', cap: 16384, generation: 4, source: 'upload', applies: 'live' }] }));
    if (p === '/api/upload/begin') return r.fulfill(json({ ok: true, id: 'u1', chunk_max: 16384 }));
    if (p === '/api/upload/chunk') { st.chunks.push(r.request().postDataBuffer()); return r.fulfill(json({ ok: true })); }
    if (p === '/api/upload/finish') { const box = Buffer.concat(st.chunks); st.inFlight = { id: 'u1', type: 'config', size: box.length, received: box.length, verified: true, type_code: 9, generation: 5, digest: createHash('sha256').update(box.subarray(512)).digest('hex') }; return r.fulfill(json({ ok: true })); }
    if (p === '/api/upload/activate') { st.inFlight = null; return r.fulfill(json({ ok: true, activated: true, live: true, needs_confirm: false, generation: 5 })); }
    return r.fulfill(json({}, 404));
  });
  await go('/admin/identity', 1200);
  await page.click('[aria-label="Settings"] >> text=Signing key'); await page.waitForTimeout(300);
  await page.click('text=Import a backup'); await page.fill('textarea', PEM);
  await page.click('.pcard[aria-label="Signing key"] button:text-is("Import")'); await page.waitForTimeout(800);

  await go('/protect/policies', 2000);
  await page.click('button:has-text("+ Rule")'); await page.waitForTimeout(200);
  await page.click('button:has-text("Review and apply live")'); await page.waitForTimeout(500);
  const d = page.locator('.drawer', { hasText: 'Apply all three together' });
  ok(await vis(d.locator('[aria-label="wifi not included"]')) && !(await d.locator('label:has-text("Wi-Fi password (again)")').count()),
    'bench shape: Wi-Fi is not included (the bundle in force has none) and no Wi-Fi password is asked');
  ok(!(await d.locator('[aria-label="Bundle problems"] li').count()) && await d.locator('button:has-text("Sign and upload the bundle")').isEnabled(), 'bench shape: no problems, "Sign and upload" is enabled');
  await d.locator('button:has-text("Sign and upload the bundle")').click();
  await t.approve({ key: 'bench-device-password' }); await page.waitForTimeout(1500);

  const box = Buffer.concat(st.chunks), dir = mkdtempSync(join(tmpdir(), 'bench-'));
  writeFileSync(join(dir, 's'), box.subarray(0, 512)); writeFileSync(join(dir, 'b'), box.subarray(512));
  let out = '';
  try { out = execFileSync('python3', ['-I', join(ROOT, 'os/kernel/tools/hqcfg.py'), 'verify', PUBHEX, join(dir, 'b'), join(dir, 's'), '4', DEV]).toString(); } catch (e) { out = String(e.stderr ?? e.message); }
  const wan = out.split('--- wan')[1]?.split('---')[0] ?? '';
  ok(!/--- wifi/.test(out) && /--- policy/.test(out) && ['mode=dhcp', 'vlan=100', 'mgmt_vlan=200', 'mgmt=dhcp'].every((l) => wan.includes(l)),
    'bench shape: the bundle carries WAN (dhcp, vlan 100, mgmt vlan 200 dhcp) and the firewall, no Wi-Fi section (verified with hqcfg.py)');
  ok(out.includes('acl LAN-IN seq 10 block tcp any 1.1.1.1/32 80'), 'bench shape: the firewall in force is carried with the new rule');
}
