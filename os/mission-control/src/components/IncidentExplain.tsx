/**
 * IncidentExplain — the explainability parts of the incident view (`/investigate/incident`):
 *
 *   CaseCard      always visible: priority, what the device did, asset, confidence, evidence, status
 *   IncidentDeep  behind "Dig deeper": attack path, trigger source, sealed evidence + on-device
 *                 JSON export, and the raw record
 *
 * All values come from `GET /api/incidents/:id` and the related `/api/detections` rows through
 * `store/explain.ts`. Fields the device does not send yet show "not reported", never a guess.
 * In preview (no device) the labelled sample incident is shown, as everywhere else.
 */
import { type Component, For, Show, createSignal } from 'solid-js';
import { formatTime, mitreLabel, type IncidentTimelineEvent } from '../store/api';
import {
  attackPath, confidencePct, evidenceExport, evidenceRef, exportFileName, triggers,
  type DetectionRowX, type IncidentDetailX,
} from '../store/explain';

/** The preview incident, the same story as IncidentApp's SAMPLE (Kitchen camera, INC-0142). */
export const SAMPLE_INCIDENT: IncidentDetailX = {
  id: 'INC-0142', ts: 0, title: 'Kitchen camera contacted a malware host', device_ip: '10.66.0.42',
  priority: 'HIGH', status: 'open', threat_score: 0.8,
  explanation: { why: "The camera's TLS client matched a known-malicious fingerprint (JA4) on your threat-intel pack, then it tried to connect to 6 other devices.", confidence: 0.94, evidence: 4, model: null, related_events: ['s:1', 's:2', 's:3'] },
  attack_path: { incident: 'INC-0142', node_count: 0, edge_count: 0, nodes: [], edges: [] },
  ingress: { interface: 'wlan0', zone: 'Full access' },
  evidence_ref: { record_id: 'sample-record', verified: true },
};
export const SAMPLE_DETECTIONS: DetectionRowX[] = [
  { id: 's:1', ts: 0, rule_id: 1200125, rule_msg: 'Known-malicious TLS client (JA4) (PASS, observe)', category: 'ioc_match', severity: 2, mitre: 'T1071.001', src_ip: '10.66.0.42', dst_ip: '198.51.100.23', dst_port: 443, confidence: 0.6 },
  { id: 's:2', ts: 0, rule_id: 1200113, rule_msg: 'Port scan (DROP, framedrop)', category: 'port_scan', severity: 3, mitre: 'T1046', src_ip: '10.66.0.42', dst_ip: '10.66.0.7', dst_port: 23, confidence: 0.9 },
  { id: 's:3', ts: 0, rule_id: 1200113, rule_msg: 'Port scan (DROP, quarantine)', category: 'port_scan', severity: 3, mitre: 'T1046', src_ip: '10.66.0.42', dst_ip: '10.66.0.9', dst_port: 554, confidence: 0.9 },
];

interface Props {
  d: IncidentDetailX;
  dets: DetectionRowX[];
  timeline: IncidentTimelineEvent[];
  sample: boolean;
}

/** The always-visible case summary. */
export const CaseCard: Component<Props> = (p) => {
  const t = () => triggers(p.d, p.dets)[0];
  const ev = () => evidenceRef(p.d);
  const rows = (): [string, string][] => [
    ['Priority', p.d.priority || '—'],
    ['Action', t()?.action ?? 'Recorded'],
    ['Asset', p.d.device_ip || '—'],
    ['Confidence', `${confidencePct(p.d.explanation.confidence)}%`],
    ['Evidence', `${p.d.explanation.evidence} item${p.d.explanation.evidence === 1 ? '' : 's'} · ${ev().recordId ? (ev().verified === true ? 'seal verified' : ev().verified === false ? 'seal FAILED' : 'sealed') : 'sealed on device'}`],
    ['Status', p.d.status || '—'],
  ];
  return (
    <div class="pcard xp-wrap" aria-label="Case">
      <p class="l0-label">Case</p>
      <For each={rows()}>{([k, v]) => <span class="prow"><span>{k}</span><span>{v}</span></span>}</For>
    </div>
  );
};

async function sha256Hex(text: string): Promise<string | null> {
  try {
    if (!globalThis.crypto?.subtle) return null; // only in a secure context (the device serves HTTPS, ADR 0051)
    const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  }
}

/** Save the evidence bundle as a file. Built and saved in the browser: no network request. */
async function saveEvidence(p: Props): Promise<string> {
  const body = evidenceExport(p.d, p.dets, p.timeline, Date.now());
  const text = JSON.stringify(body, null, 2);
  const digest = await sha256Hex(text);
  const out = JSON.stringify(digest ? { ...body, sha256_of_content_without_this_field: digest } : body, null, 2);
  const url = URL.createObjectURL(new Blob([out], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = exportFileName(p.d.id);
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return `Saved ${a.download}${digest ? ` · SHA-256 ${digest.slice(0, 12)}…` : ''}. Nothing was sent anywhere.`;
}

const STEP_MARK: Record<string, string> = { ingress: 'In', inspect: 'Rule', target: 'To', action: 'Act' };

/** Everything behind "Dig deeper". */
export const IncidentDeep: Component<Props> = (p) => {
  const [saved, setSaved] = createSignal('');
  const path = () => attackPath(p.d, p.dets);
  const ts = () => triggers(p.d, p.dets);
  const ev = () => evidenceRef(p.d);
  return (
    <>
      <section aria-label="Attack path">
        <p class="l0-label">Attack path</p>
        <ol class="xp-path">
          <For each={path()}>{(s) => (
            <li class={`xp-step${s.known ? '' : ' xp-step--unknown'}`}>
              <span class="xp-mark" aria-hidden="true">{STEP_MARK[s.kind]}</span>
              <span><b>{s.title}</b><span class="pcard-note">{s.detail}</span></span>
            </li>
          )}</For>
        </ol>
      </section>

      <section aria-label="Trigger source">
        <p class="l0-label">Why it was flagged</p>
        <Show when={ts().length > 0} fallback={<p class="pcard-note">The detections behind this incident are no longer in the recent list. What the device recorded: {p.d.explanation.why || '—'}</p>}>
          <For each={ts().slice(0, 3)}>{(t) => (
            <div class="xp-trigger xp-wrap">
              <span class="prow"><span><b>{t.name}</b></span><span>{t.hits} hit{t.hits === 1 ? '' : 's'}</span></span>
              <span class="prow"><span>Looks for</span><span>{t.reason || '—'}</span></span>
              <span class="prow"><span>Verdict</span><span>{t.verdict ?? '—'} · {t.action}</span></span>
              <span class="prow"><span>Confidence</span><span>{t.confidence}%</span></span>
              <Show when={t.mitre}><span class="prow"><span>ATT&amp;CK</span><span>{mitreLabel(t.mitre!)}</span></span></Show>
              <Show when={t.kind === 'wasm'}><span class="prow"><span>Module hash</span><span class="xp-mono">{t.moduleHash ?? 'not reported'}</span></span></Show>
              <Show when={t.build}><span class="prow"><span>Detected by build</span><span class="xp-mono">{t.build}</span></span></Show>
            </div>
          )}</For>
          <p class="pcard-note">Decided by {p.d.explanation.model ?? 'the device rules (no AI model)'}.</p>
        </Show>
      </section>

      <section class="xp-wrap" aria-label="Sealed evidence">
        <p class="l0-label">Sealed evidence</p>
        <span class="prow"><span>Record</span><span class="xp-mono">{ev().recordId ?? 'not reported by this build'}</span></span>
        <span class="prow"><span>Sealed</span><span>{ev().sealedAt ? formatTime(ev().sealedAt!) : 'not reported'}</span></span>
        <span class="prow"><span>Seal check</span><span>{ev().verified === true ? 'verified' : ev().verified === false ? 'FAILED' : 'not reported'}</span></span>
        <p class="pcard-note">{ev().status}</p>
        <div>
          <button class="hp-btn" disabled={p.sample} title={p.sample ? 'Sample data: connect a device to export its evidence' : 'Saves a JSON file from this page; nothing leaves the device'}
            onClick={async () => setSaved(await saveEvidence(p))}>Export JSON (on device)</button>
        </div>
        <Show when={saved()}><p class="pcard-note" role="status">{saved()}</p></Show>
      </section>

      <details>
        <summary class="l0-label" style={{ cursor: 'pointer' }}>Raw record · GET /api/incidents/{p.d.id}</summary>
        <pre class="xp-raw">{JSON.stringify(p.d, null, 2)}</pre>
      </details>
    </>
  );
};
