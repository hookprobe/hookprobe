/**
 * KnowledgeApp — Knowledge (`/knowledge/blog`): runbooks, SOPs and docs on the same evidence as your
 * incidents (wireframe "Knowledge"; requirements doc §11).
 *
 * On every device: built-in runbooks shipped with Mission Control (real, matching how these screens
 * behave), each linking to the screen it describes. Writing your own content, the blog and the AI
 * writer belong to a content service in a control plane, so they are greyed with that reason.
 */
import { type Component, For, createMemo, createSignal } from 'solid-js';
import AppShell from './AppShell';

interface Doc { id: string; kind: 'Runbook' | 'SOP' | 'Guide'; title: string; summary: string; steps: string[]; link: [string, string] }

const DOCS: Doc[] = [
  { id: 'incident', kind: 'Runbook', title: 'Respond to an incident', summary: 'From the alert to a closed, documented incident.',
    steps: ['Open Investigate and pick the incident at the top of the queue (highest priority first).', 'Read the Story tab: each step shows the time, the engine and what happened.', 'Check "Why this was decided": confidence, evidence count and the ATT&CK technique. "Device rules · no AI model" means a deterministic rule match.', 'If the source is hostile, use "Hold source 1 h" — it expires on its own and is written to the audit log.', 'Print the Executive summary for your records, then Acknowledge.'],
    link: ['/investigate/queue', 'Open Investigate'] },
  { id: 'zone', kind: 'SOP', title: 'Move a device to another zone', summary: 'A permanent owner rule, previewed by the device before it applies.',
    steps: ['Open My Network and select the device.', 'Under "Move to zone" pick the new zone. The device previews the change (before → after) without writing anything.', 'Approve, give a short reason and your device password. The change is written to the journal.', 'Mission Control reads it back: "Applied and verified", or "Applied, but not kept across a restart" on a device without a persistent journal, or the reason a signed DEVICES.TXT line still wins.'],
    link: ['/network/zones', 'Open My Network'] },
  { id: 'pack', kind: 'SOP', title: 'Update a signed pack (rules, IOC, Shield lists)', summary: 'Packs are signed offline with your operator key; the device verifies before anything changes.',
    steps: ['Build the pack offline and sign it with your operator key, producing X.TXT and X.SIG.', 'Make the container: cat X.SIG X.TXT > pack.bin.', 'Administration → Signed packs: choose the type and the file, then "Upload and verify" (device password).', 'The device checks the digest, your signature and that the generation is newer, then you sign the activation with your signing key.', 'If activation is refused, the previous pack stays active.'],
    link: ['/admin/identity', 'Open Administration'] },
  { id: 'alerts', kind: 'Guide', title: 'Get alerts on your phone', summary: 'Send new incidents to ntfy, Gotify or your own JSON endpoint.',
    steps: ['Automate → Notifications → "Set up alerts".', 'Choose the format, the server address and port, a path and a secret of at least 16 characters.', 'Pick the minimum severity (high is a good start).', 'Save with your device password; the device reports the destination back. It sends at most a dozen alerts an hour and holds back the rest.'],
    link: ['/automate/playbooks', 'Open Automate'] },
  { id: 'key', kind: 'Runbook', title: 'Lost device password', summary: 'Recover access without losing your evidence.',
    steps: ['Power off the device and take out its boot disk (or the CM5 eMMC via USB boot).', 'Write a new OWNER.TXT made with your provisioning tool. A re-flashed OWNER.TXT always wins over a rotated key.', 'Boot and sign in with the new key; then rotate it from Administration → Identity and access if you want a fresh one.', 'Factory reset is the last resort: it erases every owner setting.'],
    link: ['/admin/identity', 'Open Administration'] },
  { id: 'export', kind: 'Guide', title: 'Keep more than the device can hold', summary: 'The device keeps a bounded window and says how much.',
    steps: ['Timeline & Export shows what the device keeps (for example its newest 256 detections).', 'Export CSV or JSON of exactly the rows shown, or print a report.', 'For continuous copies, send alerts to your own system with the alert webhook.'],
    link: ['/observe/events', 'Open Timeline & Export'] },
];

const KnowledgeApp: Component = () => {
  const [sel, setSel] = createSignal(DOCS[0].id);
  const [q, setQ] = createSignal('');
  const shown = createMemo(() => DOCS.filter((d) => !q().trim() || `${d.title} ${d.summary} ${d.steps.join(' ')}`.toLowerCase().includes(q().trim().toLowerCase())));
  const doc = () => DOCS.find((d) => d.id === sel()) ?? DOCS[0];

  return (
    <AppShell path="/knowledge/blog">
      <main class="pro-main" aria-label="Knowledge">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Knowledge</h1>
            <p class="pro-sub">Runbooks, SOPs and guides for this device, linked to the screens they describe</p>
          </div>
          <span class="gate gate--off">
            <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">+ New</button> <button class="hp-btn">AI writer</button></span>
            <span class="gate-reason" role="note">Writing your own content and the AI writer need the content service of a control plane.</span>
          </span>
        </div>

        <div class="obs-grid obs-grid--wide">
          <nav class="pcard obs-sources" aria-label="Documents">
            <label class="l0-card-sub" style={{ display: 'flex', 'flex-direction': 'column', gap: '4px', width: '100%' }}>Search
              <input value={q()} onInput={(e) => setQ(e.currentTarget.value)} placeholder="key, zone, pack…"
                style={{ font: 'inherit', 'min-height': '40px', padding: '0 12px', background: 'var(--hp-surface)', color: 'var(--hp-text-primary)', border: '1px solid var(--hp-border)', 'border-radius': 'var(--hp-radius)' }} /></label>
            <For each={shown()} fallback={<p class="pcard-note">No document matches.</p>}>{(d) => (
              <button class={`shell-rail-item${sel() === d.id ? ' is-active' : ''}`} aria-pressed={sel() === d.id} onClick={() => setSel(d.id)}
                style={{ 'flex-direction': 'column', 'align-items': 'flex-start', gap: '2px', 'min-height': '52px' }}>
                <span>{d.title}</span><span class="pcard-note">{d.kind}</span>
              </button>
            )}</For>
          </nav>
          <article class="pcard" aria-label={doc().title}>
            <span class="inc-status" style={{ 'align-self': 'flex-start' }}>{doc().kind}</span>
            <h2 style={{ margin: 0, 'font-size': '20px' }}>{doc().title}</h2>
            <p class="l0-card-sub" style={{ margin: 0 }}>{doc().summary}</p>
            <ol style={{ margin: 0, 'padding-left': '20px', display: 'flex', 'flex-direction': 'column', gap: '8px', 'line-height': 1.5 }}>
              <For each={doc().steps}>{(s) => <li>{s}</li>}</For>
            </ol>
            <div class="l0-card-foot"><a class="hp-btn hp-btn--primary" href={doc().link[0]}>{doc().link[1]} →</a></div>
          </article>
        </div>
      </main>
    </AppShell>
  );
};

export default KnowledgeApp;
