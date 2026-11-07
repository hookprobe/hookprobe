/**
 * FeedbackApp — Administration → Feedback & Diagnostics (§12, ADR 0012 D5).
 *
 * The consent screen for the opt-in, off-by-default product-health beacon.
 * Spec: docs/research/feedback-ux.md (canonical UX — copy, wireframes, state matrix,
 * anti-nag rules). Follow it faithfully; this file implements it against
 * Layer-0 mock state (no backend).
 *
 * The one design move (spec §0): render the *actual* beacon.json next to the
 * toggle, live, generated from this device's mock values — never a marketing
 * description. `buildBeacon()` is the single code path both the live preview
 * and "Export diagnostics file" use, so what you see is what would leave.
 *
 * Panels (terminal-framed):
 *   PRODUCT-HEALTH BEACON — the toggle (one control, OFF by default, symmetric
 *     revoke), delivery status, hard deny-list, Export (works in every state).
 *   LIVE PAYLOAD / LAST BEACON — the 12-field beacon.json, live.
 *   TENANT EVIDENCE OFFLOAD (ADR 0009) — cloud-linked only, read-only,
 *     separate consent already given at enrollment — never conflated with
 *     the local toggle.
 *
 * State model (spec §4): disabled (default) / enabled-healthy / enabled-
 * degraded. The toggle alone drives disabled↔enabled; a small demo-only
 * affordance (clearly marked "(demo)") flips healthy↔degraded so both
 * enabled sub-states are reachable without a real egress failure to show —
 * per the task's allowance for a mock state-switcher. No other page in this
 * repo needs this because their state comes from a single mock signal; a
 * failed send is a second, independent axis the toggle alone can't express.
 *
 * Anti-nag (spec §6): nothing here reaches Mission Control or the orb. The
 * "Edge Nodes" per-device beacon status chip from the spec is out of scope
 * for this task — pending, not hacked in.
 *
 * Capability gating: page itself requires manifest `feedback_beacon`; when
 * absent the page is hidden from the Administration nav entirely (spec §4)
 * — not rendered greyed. This mock keeps GRANTS.feedback_beacon = true so
 * the states are demonstrable; the gate is still shown explicitly below for
 * completeness (see `GRANTS` guard just under LeftRail).
 */

import { type Component, For, Show, createSignal, createMemo } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import type { DeployMode } from './LeftRail';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import {
  type BeaconPayload,
  GRANTS, DEVICE_BEACON_BASE, CONSENT_TAG_ON, CONSENT_TAG_OFF,
  ENABLED_SINCE, LAST_SENT_AT, NEXT_SEND_ETA, BEACON_TS_LIVE,
  DENY_LIST, TENANT_OFFLOAD,
} from '../store/fbkMock';

// Mode is mocked the same way the sibling Administration page mocks it
// (AdministrationApp.tsx hardcodes 'cloud-linked') — no live mode source
// exists in Layer 0. Flip to 'standalone' to see the tenant-offload card
// disappear, per spec §3.3 / §4.
const MODE: DeployMode = 'cloud-linked';

type BeaconState = 'disabled' | 'enabled-healthy' | 'enabled-degraded';

/** Single code path for both the live preview and the exported file. */
function buildBeacon(consentOn: boolean): BeaconPayload {
  return {
    ...DEVICE_BEACON_BASE,
    consent: consentOn ? CONSENT_TAG_ON : CONSENT_TAG_OFF,
    ts: BEACON_TS_LIVE,
  };
}

const Panel: Component<{ ctx: string; title: string; span?: string; children: any }> = (p) => (
  <section class="hp-terminal mc-panel" style={p.span ? { 'grid-column': p.span } : undefined}>
    <div class="hp-terminal-bar">
      <span class="hp-dot red" aria-hidden="true" />
      <span class="hp-dot yellow" aria-hidden="true" />
      <span class="hp-dot green" aria-hidden="true" />
      <span class="mc-panel-title">{p.title}</span>
      <span class="hp-terminal-title">hookprobe@edge ~ {p.ctx}</span>
    </div>
    <div class="hp-terminal-body mc-panel-body">{p.children}</div>
  </section>
);

const FeedbackApp: Component = () => {
  const [consentOn, setConsentOn]     = createSignal(false);   // OFF by default
  const [degradedDemo, setDegraded]   = createSignal(false);   // demo-only 2nd axis
  const [lastExportAt, setLastExport] = createSignal<string | null>(null);

  const state = createMemo<BeaconState>(() => {
    if (!consentOn()) return 'disabled';
    return degradedDemo() ? 'enabled-degraded' : 'enabled-healthy';
  });

  const beacon = createMemo(() => buildBeacon(consentOn()));
  const payloadText = createMemo(() => JSON.stringify(beacon(), null, 2));

  const toggleHelp = createMemo(() =>
    consentOn()
      ? `On since ${ENABLED_SINCE}. Sends once/day and on boot-health change. Turn off any time — takes effect immediately.`
      : 'Off. This device sends nothing. Turn on to share release health; see exactly what leaves on the right.'
  );

  const payloadTitle = createMemo(() =>
    state() === 'disabled' ? 'SEE EXACTLY WHAT LEAVES' : 'LAST BEACON (SENT)'
  );

  const allowlistCaption = createMemo(() =>
    state() === 'disabled'
      ? 'This is the entire payload. See exactly what leaves this device:'
      : 'This is exactly what was sent:'
  );

  function toggleConsent() {
    setConsentOn((v) => {
      const next = !v;
      if (!next) setDegraded(false); // revoke clears the demo-degraded axis too
      return next;
    });
  }

  /** Works in every state (even disabled/degraded) — no connectivity required. */
  function exportDiagnostics() {
    const payload = beacon();
    const filename = `beacon-${payload.image_version}-${payload.ts.replace(/[:]/g, '')}.json`;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setLastExport(new Date().toLocaleString());
  }

  return (
    <div class="dash-layout">
      <LeftRail active="/admin" mode={MODE} onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="dash-main">
        <header class="mc-header">
          <div>
            <div class="fbk-breadcrumb">
              <a href="/admin/identity">Administration</a>
              <span aria-hidden="true"> › </span>
              Feedback &amp; Diagnostics
            </div>
            <h1 class="mc-h1">FEEDBACK &amp; DIAGNOSTICS</h1>
            <div class="mc-sub">
              Help improve HookProbe OS by sharing how this release behaves — nothing about your network.
            </div>
          </div>
          <div class="mc-header-actions">
            <button
              class="mc-chip"
              onClick={() => { setCopilotQuery('turn on the product health beacon'); setCopilotOpen(true); }}
            >
              ⌘ "turn on the product health beacon"
            </button>
            <span class="mc-mode-badge">● {MODE}</span>
          </div>
        </header>

        <Show
          when={GRANTS.feedback_beacon}
          fallback={
            <div class="mc-grid">
              <Panel ctx="feedback" title="FEEDBACK & DIAGNOSTICS" span="span 12">
                <div class="fbk-nograt">
                  Manifest: <code>feedback_beacon</code> not granted on this device.
                </div>
              </Panel>
            </div>
          }
        >
          <div class="mc-grid">

            {/* ── Product-health beacon (consent card) ─────────────────────── */}
            <Panel ctx="feedback" title="PRODUCT-HEALTH BEACON" span="span 5">

              <div class="fbk-toggle-row">
                <button
                  type="button"
                  role="switch"
                  aria-checked={consentOn()}
                  aria-labelledby="fbk-toggle-label"
                  aria-describedby="fbk-toggle-help"
                  class={`fbk-toggle${consentOn() ? ' fbk-toggle--on' : ''}`}
                  onClick={toggleConsent}
                >
                  <span class="fbk-toggle-track" aria-hidden="true">
                    <span class="fbk-toggle-thumb" />
                  </span>
                  <span class="fbk-toggle-word">{consentOn() ? 'ON' : 'OFF'}</span>
                </button>
                <div class="fbk-toggle-copy">
                  <span id="fbk-toggle-label" class="fbk-toggle-label-text">
                    Send the product-health beacon
                  </span>
                  <p id="fbk-toggle-help" class="fbk-help">{toggleHelp()}</p>
                </div>
              </div>

              <Show when={state() !== 'disabled'}>
                <div class="fbk-status-line">
                  <span>Last sent: {LAST_SENT_AT}</span>
                  <span>Next: {NEXT_SEND_ETA}</span>
                  <span class={`fbk-status-word fbk-status-word--${state() === 'enabled-healthy' ? 'ok' : 'fail'}`}>
                    Status: {state() === 'enabled-healthy' ? 'delivered' : 'failed'}
                  </span>
                </div>
              </Show>

              <Show when={state() === 'enabled-degraded'}>
                <div class="fbk-banner" role="status">
                  <span class="fbk-banner-dot" aria-hidden="true" />
                  <span class="fbk-banner-text">
                    Beacon on, but the last send failed — endpoint unreachable / offline. Enforcing your
                    last choice; will retry. Export instead ⤓.
                  </span>
                </div>
              </Show>

              <div class="adm-divider" />

              <div class="adm-section-head">NEVER SENT</div>
              <p class="fbk-deny-line">
                Never included: IPs, hostnames, flows, detections, IOCs, rules, files, users, or any
                customer data. There is no free-text field.
              </p>
              <ul class="fbk-deny-list">
                <For each={DENY_LIST}>{(item) => <li>{item}</li>}</For>
              </ul>

              <div class="adm-divider" />

              <button class="hp-btn-primary fbk-export-btn" type="button" onClick={exportDiagnostics}>
                Export diagnostics file ⤓
              </button>
              <p class="fbk-export-help">
                Download this exact beacon.json to attach to a GitHub issue. Works with no connectivity.
              </p>
              <Show when={lastExportAt() !== null}>
                <p class="fbk-export-meta">Last export: {lastExportAt()}</p>
              </Show>

              <Show when={consentOn()}>
                <button
                  type="button"
                  class="fbk-demo-link"
                  onClick={() => setDegraded((v) => !v)}
                >
                  (demo) simulate {degradedDemo() ? 'recovery' : 'a failed send'}
                </button>
              </Show>

            </Panel>

            {/* ── Live payload preview — the trust move ─────────────────────── */}
            <Panel ctx="payload" title={payloadTitle()} span="span 7">
              <div class="fbk-allowlist-caption">{allowlistCaption()}</div>
              <pre class="fbk-payload inv-tech"><span class="hp-prompt">$</span> cat beacon.json
{payloadText()}</pre>
              <p class="fbk-beaconid-note">
                Beacon ID is a salted one-way hash — it cannot be reversed to your device or serial.
              </p>
              <Show when={state() === 'enabled-healthy'}>
                <p class="fbk-sent-confirm">This is exactly what was sent.</p>
              </Show>
            </Panel>

            {/* ── Cloud-linked: separate, already-consented tenant offload ──── */}
            <Show when={MODE === 'cloud-linked'}>
              <Panel ctx="tenant-offload" title="TENANT EVIDENCE OFFLOAD · ADR 0009" span="span 12">
                <div class="fbk-tenant-row">
                  <div class="fbk-tenant-body">
                    <div class="fbk-tenant-line">Managed by your MSSP tenant policy.</div>
                    <div class="fbk-tenant-line">
                      Status: <span class="fbk-tenant-status">{TENANT_OFFLOAD.status}</span>
                      {' · endpoint: '}
                      <span class="fbk-mono">{TENANT_OFFLOAD.endpoint}</span>
                    </div>
                    <div class="fbk-tenant-line">
                      Consented at enrollment on {TENANT_OFFLOAD.consentedAt} by {TENANT_OFFLOAD.consentedBy}.
                      {' '}
                      <a class="adm-link" href="/admin/identity">View terms →</a>
                    </div>
                    <div class="fbk-tenant-note">
                      This is a separate channel from the beacon above and is governed by your tenant
                      agreement, not this toggle. To change it, see Administration → Enrollment &amp; mode.
                    </div>
                  </div>
                  <span class="fbk-consented-pill">consented ✓</span>
                </div>
              </Panel>
            </Show>

          </div>
        </Show>
      </main>

      <CommandPalette
        open={copilotOpen()}
        query={copilotQuery()}
        onQuery={setCopilotQuery}
        onClose={() => { setCopilotOpen(false); setCopilotQuery(''); }}
      />
    </div>
  );
};

export default FeedbackApp;
