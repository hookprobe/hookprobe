// AB-09 / AB-10 (UX audit U-06, U-09): Investigate on a heqk device.
//  - heqk has no endpoint agent, so the process tree is always empty: the panel says this device does not see
//    processes, instead of implying an EDR layer that "may not have observed" them yet.
//  - heqk lists at most 32 reports and does not say when it cut the list: a full page says it is capped.
const ip = (i) => `198.51.100.${i + 1}`;
const incidents = (n) => Array.from({ length: n }, (_, i) => ({ id: `inc:heqk:${ip(i)}`, ts: 1795000000 - i * 60, title: `Port scan from ${ip(i)}`, device_ip: ip(i), priority: 'medium', status: 'open', threat_score: 40 }));
const reports = (n) => Array.from({ length: n }, (_, i) => ({ id: `rep:heqk:${ip(i)}`, ts: 1795000000 - i * 60, incident_id: `inc:heqk:${ip(i)}`, title: `Incident report — Port scan from ${ip(i)}`, summary: '1 detection(s)' }));

export default async function (t) {
  const { page, ok, go, vis } = t;
  const json = (b, s = 200) => ({ status: s, contentType: 'application/json', body: JSON.stringify(b) });
  const mock = async (n, caps) => {
    await page.unroute('**/api/**').catch(() => {});
    await page.route('**/api/**', (r) => {
      const p = new URL(r.request().url()).pathname;
      if (p === '/api/health') return r.fulfill(json({ substrate: 'heqk', mode: 'standalone', capabilities: caps }));
      if (p === '/api/incidents') return r.fulfill(json({ count: n, incidents: incidents(n) }));
      if (p.startsWith('/api/incidents/') && p.endsWith('/processes')) return r.fulfill(json({ incident: decodeURIComponent(p.split('/')[3]), found: true, process_count: 0, roots: [] }));
      if (p === '/api/reports') return r.fulfill(json({ count: n, reports: reports(n) }));
      // The detail panels (process tree, report list) render only once the selected incident's detail loads.
      const m = p.match(/^\/api\/incidents\/([^/]+)$/);
      if (m) {
        const id = decodeURIComponent(m[1]), row = incidents(n).find((x) => x.id === id) ?? incidents(n)[0];
        return r.fulfill(json({ ...row, explanation: { why: 'Port scan seen from this address.', confidence: 80, evidence: 1, model: null, related_events: [] },
          attack_path: { incident: id, node_count: 1, edge_count: 0, nodes: [{ id: `ip:${row.device_ip}`, type: 'ip', label: row.device_ip }], edges: [] } }));
      }
      return r.fulfill(json({}, 404));
    });
  };

  await mock(32, ['ids', 'wan']);
  await go('/investigate/queue', 2500);
  ok(await vis(page.locator('.inv-title', { hasText: 'Port scan from 198.51.100.1' })), 'detail: the selected incident loaded (the panels below depend on it)');
  ok(await vis(page.locator('.hp-live-state', { hasText: 'This device does not see processes' })), 'process tree: no host_telemetry → says this device does not see processes');
  ok(!(await vis(page.locator('text=EDR layer may not have observed'))), 'process tree: no hint of an EDR layer that does not exist');
  ok(await page.locator('.inv-report-row').count() === 32, 'reports: the 32 rows the device returned');
  ok(await vis(page.locator('[role=note]', { hasText: 'the most this device lists' })), 'reports: a full page of 32 says the list is capped');

  await mock(3, ['ids', 'wan', 'host_telemetry']);
  await go('/investigate/queue', 2500);
  ok(await vis(page.locator('.hp-live-state', { hasText: 'No host process telemetry linked yet' })), 'process tree: host_telemetry granted → "not linked yet"');
  ok(await page.locator('.inv-report-row').count() === 3 && !(await vis(page.locator('[role=note]', { hasText: 'the most this device lists' }))), 'reports: a short list has no cap note');
}
