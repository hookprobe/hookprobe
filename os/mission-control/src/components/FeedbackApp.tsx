/**
 * FeedbackApp — Administration → Feedback and diagnostics (`/admin/feedback`; ADR 0012 D5;
 * docs/research/feedback-ux.md; requirements doc §12).
 *
 * The spec's one design move stays: show the exact bytes that would leave, built by the same function
 * the Export uses. What changed is honesty: every value comes from this device (`/api/health`,
 * `/api/capabilities`, `/api/upload`), a field the device does not report says so instead of showing
 * an invented number, and the beacon toggle is off and greyed with its reason — heqk has no beacon
 * sender, so nothing can be sent. The diagnostics file works in every state, air-gapped.
 *
 * Never included (enforced by construction — the builders below only read these fields): addresses,
 * hostnames, MACs, flows, detections, incidents, IOCs, rules, owner keys, configs.
 */
import { type Component, For, Show, createMemo, onMount } from 'solid-js';
import { substrate, deviceStats, deployMode } from '../store/mock';
import { healthChecked, loadHealth } from '../store/health';
import { capList } from '../store/capabilities';
import { uploadView, refreshUploads, PACK_LABEL } from '../store/packUpload';
import { download } from '../store/signing';
import AppShell from './AppShell';

const NOT = 'not reported by this device';

const FeedbackApp: Component = () => {
  onMount(() => { void loadHealth(); void refreshUploads(); });
  const sample = () => healthChecked() && !substrate();

  /** The 12-field beacon of feedback-ux.md §1, filled only with what this device actually reports. */
  const beacon = createMemo(() => ({
    schema: 'hookprobe.beacon/1',
    beacon_id: NOT,
    image_version: NOT,
    device_class: substrate() || NOT,
    profile: deployMode(),
    arch: substrate() ? 'aarch64' : NOT,
    uptime_hours: NOT,
    boot: NOT,
    health: NOT,
    qsecbit_avg: NOT,
    consent: 'not given (beacon off)',
    ts: new Date().toISOString().slice(0, 19) + 'Z',
  }));

  /** The diagnostics file: product health only. */
  const diagnostics = createMemo(() => {
    const s = deviceStats();
    const c = capList();
    const u = uploadView();
    return {
      schema: 'hookprobe.diagnostics/1',
      generated: new Date().toISOString(),
      source: sample() ? 'preview build (no device)' : 'device',
      substrate: substrate() || null,
      mode: deployMode(),
      capabilities: { source: c.source, granted: c.granted, denied: Object.fromEntries(c.denied) },
      packet_path: s ? { seen: s.seen ?? null, forwarded: s.forwarded ?? null, dropped: s.dropped ?? null, rules_active: s.rulesActive ?? null } : null,
      storage: s ? { detections_cap: s.detectionsCap ?? null, sealed_cap: s.sealedCap } : null,
      internet: s?.wan ? { up: s.wan.up, mode: s.wan.mode, ipv6: s.wan.ipv6 } : null,
      packs: u ? { store: u.store, slots: u.types.map((t) => ({ type: t.type, generation: t.generation, source: t.source })),
        recent: u.recent.map((e) => ({ step: e.step, type: e.type, ok: e.ok, why: e.why })) } : null,
      clock: s?.clock ?? null,
      last_reset: s?.lastReset ?? null,
      ui: { path: typeof location !== 'undefined' ? location.pathname : '', agent: typeof navigator !== 'undefined' ? navigator.userAgent : '' },
    };
  });
  const json = (o: unknown) => JSON.stringify(o, null, 2);

  return (
    <AppShell path="/admin/identity">
      <div class="pro-head">
        <div>
          <h1 class="pro-title">Feedback and diagnostics</h1>
          <p class="pro-sub">Beacon off · nothing leaves this device unless you export it.</p>
        </div>
      </div>

      <div class="pro-grid" style={{ 'grid-template-columns': 'repeat(auto-fit, minmax(320px, 1fr))' }}>
        <div class="pcard" aria-label="Product-health beacon">
          <p class="l0-label">Product-health beacon</p>
          <label class="prow" style={{ opacity: 0.55 }}>
            <span>Send product health to HookProbe</span>
            <input type="checkbox" checked={false} disabled aria-describedby="beacon-why" />
          </label>
          <p class="gate-reason" id="beacon-why">Off. This device has no beacon sender, so nothing can be sent. When it ships it stays off until you turn it on here, and turns off in one click.</p>
          <p class="l0-label" style={{ 'margin-top': '8px' }}>Never sent</p>
          <p class="l0-card-sub">IP addresses · hostnames · MACs · flows or captures · detections and alerts · IOCs · rules · user or customer data · file paths · configs · location. The fields on the right are the whole schema; there is no free-text field.</p>
        </div>

        <div class="pcard" aria-label="Beacon preview">
          <p class="l0-label">What it would send, from this device now</p>
          <pre class="pro-pre" style={{ margin: 0, 'white-space': 'pre-wrap', 'font-size': '12px' }}>{json(beacon())}</pre>
          <p class="pcard-note">"{NOT}" means the device does not measure it yet; nothing is made up.</p>
        </div>

        <div class="pcard" aria-label="Diagnostics file">
          <p class="l0-label">Diagnostics file</p>
          <p class="l0-card-sub">For a support request or your own records. Product health only: capabilities, packet-path counters, storage limits, pack generations, clock. Works with no internet.</p>
          <Show when={sample()}><p class="plan-diff-warn" style={{ margin: 0 }}>Preview build: no device is connected, so most values are empty.</p></Show>
          <div class="l0-card-foot">
            <button class="hp-btn hp-btn--primary" onClick={() => download(`hookprobe-diagnostics-${new Date().toISOString().slice(0, 10)}.json`, json(diagnostics()) + '\n', 'application/json')}>Export diagnostics file</button>
            <a class="hp-btn" href="https://github.com/hookprobe/hookprobe/issues" target="_blank" rel="noopener noreferrer">Report a problem</a>
          </div>
          <Show when={(uploadView()?.types.length ?? 0) > 0}>
            <For each={uploadView()!.types}>{(t) => <span class="prow"><span>{PACK_LABEL[t.type] ?? t.type}</span><span>gen {t.generation} · {t.source}</span></span>}</For>
          </Show>
          <details>
            <summary class="l0-card-sub" style={{ cursor: 'pointer', 'min-height': '32px' }}>Show the exact file</summary>
            <pre class="pro-pre" aria-label="Diagnostics preview" style={{ margin: 0, 'white-space': 'pre-wrap', 'font-size': '12px' }}>{json(diagnostics())}</pre>
          </details>
        </div>
      </div>
    </AppShell>
  );
};

export default FeedbackApp;
