// Unit tests for src/store/explain.ts: incident parsing, QSECBIT band rendering logic, the DNS
// audit, and graceful degradation when the device leaves fields out.
// Run: npm run test:unit   (Node's own test runner with type stripping; no extra dependency)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseIncident, triggers, attackPath, evidenceRef, evidenceExport, exportFileName, parseRuleMsg, confidencePct,
  bandOf, rowBand, resilience, windowStats, bandShifts, shiftSignals, explainShift, BAND_TEXT,
  dnsAudit, blockSource, type DetectionRowX, type DnsLiveX,
} from '../../src/store/explain.ts';

// A record exactly as heqk's mcstate.rs::render_incident writes it.
const DEVICE_INCIDENT = {
  id: 'inc:heqk:203.0.114.9', ts: 1700000100, title: 'TCP port scan from 203.0.114.9 (3 detections)',
  device_ip: '203.0.114.9', priority: 'High', status: 'open', threat_score: 0.8,
  explanation: {
    why: '3 detection(s) from 203.0.114.9 matched 1 rule(s) on this device: TCP port scan. Deterministic rule match (no AI planner run).',
    confidence: 0.9, evidence: 3, model: null, related_events: ['det:heqk:7', 'det:heqk:8', 'det:heqk:9'],
  },
  attack_path: { incident: 'inc:heqk:203.0.114.9', node_count: 2, edge_count: 1, nodes: [{ id: 'ip:203.0.114.9', type: 'dev', label: '203.0.114.9' }, { id: 'ip:10.0.0.5', type: 'dev', label: '10.0.0.5' }], edges: [{ src: 'ip:203.0.114.9', type: 'targets', dst: 'ip:10.0.0.5' }] },
};

const det = (id: string, ts: number, rule_msg: string, extra: Partial<DetectionRowX> = {}): DetectionRowX => ({
  id, ts, rule_id: 100004, rule_msg, category: 'scan', severity: 2, mitre: 'T1046', src_ip: '203.0.114.9', dst_ip: '10.0.0.5', dst_port: 22, confidence: 0.9, build: 'v0.0-26', ...extra,
});
const DETS: DetectionRowX[] = [
  det('det:heqk:7', 1700000090, 'TCP port scan (PASS, observe)', { confidence: 0.6 }),
  det('det:heqk:8', 1700000095, 'TCP port scan (DROP, ratelimit_enforced)'),
  det('det:heqk:9', 1700000099, 'TCP port scan (DROP, framedrop)', { dst_port: 23 }),
  det('det:heqk:99', 1700000099, 'Unrelated (PASS, observe)', { rule_id: 100099 }),
];

test('parses a real device incident record', () => {
  const d = parseIncident(DEVICE_INCIDENT)!;
  assert.equal(d.id, 'inc:heqk:203.0.114.9');
  assert.equal(d.explanation.model, null);
  assert.equal(d.attack_path.nodes.length, 2);
  assert.equal(d.trigger, undefined);
  assert.equal(d.evidence_ref, undefined);
});

test('missing fields degrade to safe defaults, never throw', () => {
  assert.equal(parseIncident(null), null);
  assert.equal(parseIncident({ title: 'no id' }), null);
  const d = parseIncident({ id: 'inc:x' })!;
  assert.equal(d.title, 'inc:x');
  assert.deepEqual(d.explanation.related_events, []);
  assert.equal(d.attack_path.node_count, 0);
  // malformed extensions are dropped, well-formed ones kept
  const e = parseIncident({ id: 'inc:y', ingress: 5, evidence_ref: { record_id: '' }, trigger: { rule_id: 'x' } })!;
  assert.equal(e.ingress, undefined);
  assert.equal(e.evidence_ref, undefined);
  assert.equal(e.trigger?.rule_id, undefined);
  // and every view still renders
  assert.equal(triggers(e, []).length, 0);
  const path = attackPath(e, []);
  assert.equal(path[0].known, false);
  assert.match(path[0].detail, /does not report the interface/);
  assert.equal(path[path.length - 1].title, 'Recorded');
  assert.equal(evidenceRef(e).recordId, null);
});

test('rule message splits into reason, verdict and class', () => {
  assert.deepEqual(parseRuleMsg('TCP port scan (DROP, framedrop)'), { text: 'TCP port scan', verdict: 'DROP', cls: 'framedrop' });
  assert.deepEqual(parseRuleMsg('free text'), { text: 'free text' });
  assert.equal(confidencePct(0.9), 90);
  assert.equal(confidencePct(87), 87);
  assert.equal(confidencePct(Number.NaN), 0);
});

test('trigger source comes from the related detections, strongest action first', () => {
  const d = parseIncident(DEVICE_INCIDENT)!;
  const t = triggers(d, DETS);
  assert.equal(t.length, 1, 'one rule, unrelated detection ignored');
  assert.equal(t[0].kind, 'bpf');
  assert.equal(t[0].ruleId, 100004);
  assert.equal(t[0].hits, 3);
  assert.equal(t[0].verdict, 'DROP');
  assert.match(t[0].action, /dropped/);
  assert.equal(t[0].confidence, 90);
  assert.equal(t[0].reason, 'TCP port scan');
});

test('a device-sent trigger (Wasm module) leads when present', () => {
  const d = parseIncident({ ...DEVICE_INCIDENT, trigger: { kind: 'wasm', module_name: 'dga-detector', module_hash: 'ab12', verdict: 'DROP', reason: 'algorithmic domain' } })!;
  const t = triggers(d, DETS);
  assert.equal(t[0].kind, 'wasm');
  assert.equal(t[0].moduleHash, 'ab12');
  assert.equal(t[0].reason, 'algorithmic domain');
  assert.equal(t[1].ruleId, 100004);
});

test('attack path: ingress, rule, targets, action', () => {
  const d = parseIncident({ ...DEVICE_INCIDENT, ingress: { interface: 'eth0', zone: 'WAN' } })!;
  const p = attackPath(d, DETS);
  assert.deepEqual(p.map((s) => s.kind), ['ingress', 'inspect', 'target', 'target', 'action']);
  assert.match(p[0].detail, /eth0 \(WAN\)/);
  assert.match(p[2].title, /10\.0\.0\.5 port 22/);
  assert.match(p[4].title, /dropped/);
});

test('sealed evidence reference and the on-device export', () => {
  const d = parseIncident({ ...DEVICE_INCIDENT, evidence_ref: { record_id: 'ev:4182', sealed_ts: 1700000101, verified: true } })!;
  assert.equal(evidenceRef(d).status, 'Seal verified on this device.');
  const bad = parseIncident({ ...DEVICE_INCIDENT, evidence_ref: { record_id: 'ev:1', verified: false } })!;
  assert.match(evidenceRef(bad).status, /FAILED/);
  const x = evidenceExport(d, DETS, [], Date.UTC(2026, 10, 17));
  assert.equal(x.related_detections.length, 3);
  assert.equal(x.exported_at, '2026-11-17T00:00:00.000Z');
  assert.match(x.note, /Nothing was sent/);
  assert.doesNotThrow(() => JSON.stringify(x));
  assert.equal(exportFileName('inc:heqk:1.2.3.4'), 'inc_heqk_1.2.3.4-evidence.json');
});

test('QSECBIT bands match the device thresholds (risk < .3 GREEN, < .7 AMBER)', () => {
  assert.equal(bandOf(0), 'GREEN');
  assert.equal(bandOf(0.299), 'GREEN');
  assert.equal(bandOf(0.3), 'AMBER');
  assert.equal(bandOf(0.699), 'AMBER');
  assert.equal(bandOf(0.7), 'RED');
  assert.equal(bandOf(Number.NaN), 'AMBER');
  assert.equal(rowBand({ ts: 1, score: 0.1, band: 'RED' }), 'RED', 'the device band wins');
  assert.equal(rowBand({ ts: 1, score: 0.1, band: '' }), 'GREEN');
  assert.equal(resilience(0.22), 78);
  assert.equal(BAND_TEXT.GREEN.line, 'All clear · Protected');
  assert.equal(BAND_TEXT.AMBER.line, 'Monitoring · Stay alert');
  assert.equal(BAND_TEXT.RED.line, 'Under attack · Defending');
});

// Newest first, as GET /api/qsecbit returns it.
const HISTORY = [
  { ts: 1700000400, score: 0.2, band: 'GREEN' },
  { ts: 1700000300, score: 0.75, band: 'RED' },
  { ts: 1700000200, score: 0.4, band: 'AMBER' },
  { ts: 1700000100, score: 0.1, band: 'GREEN' },
];

test('sliding window and band shifts', () => {
  const w = windowStats(HISTORY);
  assert.equal(w.n, 4);
  assert.equal(w.min, 25);
  assert.equal(w.max, 90);
  assert.equal(w.latest, 80);
  assert.deepEqual(w.inBand, { GREEN: 2, AMBER: 1, RED: 1 });
  assert.equal(windowStats(HISTORY, 150).n, 2);
  assert.equal(windowStats([]).latest, null);
  const s = bandShifts(HISTORY);
  assert.deepEqual(s.map((x) => `${x.from}>${x.to}`), ['RED>GREEN', 'AMBER>RED', 'GREEN>AMBER']);
});

test('the signals behind a shift explain why the band moved', () => {
  const [, toRed] = bandShifts(HISTORY);
  const dets = [det('a', 1700000250, 'TCP port scan (DROP, framedrop)', { severity: 2 }), det('b', 1700000260, 'TCP port scan (DROP, framedrop)', { severity: 2 }), det('c', 1700000290, 'Malformed frame (DROP, framedrop)', { severity: 1 }), det('old', 1700000000, 'Old (PASS, observe)')];
  const sig = shiftSignals(toRed, dets);
  assert.deepEqual(sig.map((g) => [g.label, g.count]), [['Malformed frame', 1], ['TCP port scan', 2]]);
  assert.match(explainShift(toRed, sig), /dropped from 60 to 25 \(AMBER → RED\).*Malformed frame ×1; TCP port scan ×2/);
  const [recover] = bandShifts(HISTORY);
  assert.deepEqual(shiftSignals(recover, dets), []);
  assert.match(explainShift(recover, []), /recovered/);
});

const DNS: DnsLiveX = {
  lists: { blocked_domains: 1200, allowed_domains: 4, block_file: 'loaded', allow_file: 'loaded', signed: true, generation: 7, skipped_lines: 0, truncated: 0, refused: null },
  policy: { encrypted_dns: 'block', private_relay: 'report' },
  counters: { allowed: 900, blocked: 80, 'blocked-cname': 15, ddr: 3, canary: 2, 'doh-blocked': 1, 'tcp53-refused': 4, unparsable: 9, floor: 20 },
  top_blocked: [], clients: [{ ip: '10.0.0.5', queries: 600, blocked: 50, bypass: 0 }],
  recent: [
    { ts: 1, client: '10.0.0.5', qtype: 1, name: 'ads.example', verdict: 'blocked', category: 'ads', level: 'balanced' },
    { ts: 2, client: '10.0.0.5', qtype: 1, name: 'x.example', verdict: 'blocked' },
    { ts: 3, client: '10.0.0.6', qtype: 65, name: 'dns.example', verdict: 'doh-blocked' },
  ],
  recent_count: 3,
};

test('Shield audit: answered locally, blocked, reasons; interfaces absent → null', () => {
  const a = dnsAudit(DNS);
  assert.equal(a.total, 1025, 'unparsable excluded');
  assert.equal(a.answeredLocally, 80 + 3 + 2 + 1);
  assert.equal(a.blocked, 80 + 15 + 4);
  assert.equal(a.reasons[0].verdict, 'blocked');
  assert.ok(!a.reasons.some((r) => r.verdict === 'allowed' || r.verdict === 'floor'));
  assert.equal(a.interfaces, null);
  assert.deepEqual(dnsAudit({ ...DNS, interfaces: [{ name: 'wlan0', queries: 5, blocked: 1 }] }).interfaces, [{ name: 'wlan0', queries: 5, blocked: 1 }]);
  assert.equal(dnsAudit({ ...DNS, counters: {} }).total, 0);
});

test('Shield: each block names its source rule', () => {
  assert.equal(blockSource(DNS.recent[0], DNS.lists), 'ads category, blocked at the balanced protection level');
  assert.equal(blockSource(DNS.recent[1], DNS.lists), 'your block list BLOCK.TXT, signed, generation 7');
  assert.equal(blockSource(DNS.recent[2], DNS.lists), 'policy: encrypted DNS (DoH) blocked');
  assert.equal(blockSource({ ...DNS.recent[1] }, { ...DNS.lists, block_file: 'none' }), 'block list');
});
