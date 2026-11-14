/**
 * IntelligenceApp — Intelligence (`/intelligence/cves`, HYDRA): threat intelligence matched against
 * your assets (wireframe "Intelligence"; requirements doc §8).
 *
 *   IOC   the signed threat-intel pack (/api/intel) and what actually matched on this network:
 *         known-bad TLS clients (JA4, rule 125), Shield bypasses (rule 126), IOC detections
 *   CVEs  exposure per CVE with VEX status and SSVC decision (/api/exploitability) when the device
 *         serves it; otherwise said so — never a sample count presented as yours
 *   Feeds STIX/TAXII and MISP subscriptions are a control-plane feature: shown greyed with why
 */
import { type Component, For, Show, createEffect, createMemo, createSignal, onMount } from 'solid-js';
import { substrate } from '../store/mock';
import { healthChecked } from '../store/health';
import { formatTime } from '../store/api';
import { intel, refreshProtect } from '../store/protectLive';
import { tlsClients, refetchTls } from '../store/tlsLive';
import { detections, startDetectLive } from '../store/detectLive';
import { exploitFindings, exploitStatus, startItlLive, type ExploitFinding } from '../store/itlLive';
import AppShell from './AppShell';
import Drawer from './Drawer';

type Tab = 'ioc' | 'cves' | 'feeds';

const SAMPLE_CVES: (Pick<ExploitFinding, 'cve' | 'component' | 'summary' | 'cvss' | 'status' | 'ssvc' | 'exposed' | 'reason' | 'fixed_version'> & { assets: string[] })[] = [
  { cve: 'CVE-2024-3094', component: 'xz / liblzma', summary: 'Malicious code in xz 5.6.0–5.6.1 that can compromise SSH authentication.', cvss: 10, status: 'affected', ssvc: 'act', exposed: true, reason: 'xz 5.6.1 found on a home server', fixed_version: '5.6.2', assets: ['Home server (Linux)'] },
  { cve: 'CVE-2021-44228', component: 'Log4j 2', summary: 'Remote code execution in Apache Log4j 2 via JNDI lookups.', cvss: 10, status: 'not_affected', ssvc: 'track', exposed: false, reason: 'No Log4j in scope', fixed_version: '2.17.1', assets: [] },
  { cve: 'CVE-2023-4863', component: 'libwebp', summary: 'Heap buffer overflow in WebP image decoding, used in many browsers and apps.', cvss: 8.8, status: 'under_investigation', ssvc: 'attend', exposed: true, reason: 'Two devices run affected browsers', fixed_version: '1.3.2', assets: ['Ana iPad', 'Smart TV'] },
];
const STATUS: Record<string, string> = { affected: 'Affected', not_affected: 'Not affected', under_investigation: 'Under investigation', fixed: 'Fixed' };

const IntelligenceApp: Component = () => {
  const [tab, setTab] = createSignal<Tab>('ioc');
  const [sel, setSel] = createSignal<string | null>(null);
  onMount(() => { void refreshProtect(); void refetchTls(); startDetectLive(); startItlLive(); });

  const sample = () => healthChecked() && !substrate();
  const cves = () => (sample() ? SAMPLE_CVES : exploitFindings().map((f) => ({ ...f, assets: [] as string[] })));
  const cvesServed = () => sample() || exploitStatus() === 'live';
  // The page is /intelligence/cves and the board opens on CVEs: start there once CVEs are actually served (sample, or a
  // device reporting exploit findings); otherwise stay on IOC rather than open on an empty card. Only until the user picks.
  let picked = false;
  createEffect(() => { if (!picked && cvesServed()) setTab('cves'); });
  const selected = () => cves().find((c) => c.cve === sel()) ?? null;

  const iocHits = createMemo(() => {
    if (sample()) return [
      { ts: Math.floor(Date.now() / 1000) - 600, what: 'Known-bad TLS client (JA4 on the pack)', who: 'Kitchen camera', detail: 't13d1516h2_8daaf6152771_e5627efa2ab1' },
      { ts: Math.floor(Date.now() / 1000) - 3600, what: 'Connected to a name Shield blocks', who: 'Smart TV', detail: 'ads.example-tracker.net' },
    ];
    const out: { ts: number; what: string; who: string; detail: string }[] = [];
    for (const t of tlsClients()) {
      if (t.ioc) out.push({ ts: Math.floor(t.last_ms / 1000), what: 'Known-bad TLS client (JA4 on your pack, rule 125)', who: t.lease || t.client, detail: t.ja4 });
      if (t.shield_bypass) out.push({ ts: Math.floor(t.last_ms / 1000), what: 'Bypassed Shield (rule 126)', who: t.lease || t.client, detail: t.sni });
    }
    for (const d of detections()) if (d.category === 'ioc' || d.rule_id === 125) out.push({ ts: d.ts, what: d.rule_msg, who: d.src_ip, detail: `${d.dst_ip}${d.dst_port ? `:${d.dst_port}` : ''}` });
    return out.sort((a, b) => b.ts - a.ts);
  });

  return (
    <AppShell path="/intelligence/cves">
      <main class="pro-main" aria-label="Intelligence">
        <div class="pro-head">
          <div>
            <h1 class="pro-title">Intelligence</h1>
            <p class="pro-sub">Threat intel matched against your assets · HYDRA{substrate() ? ' · live from this device' : ''}</p>
          </div>
        </div>
        <div class="tabs" role="tablist" aria-label="Intelligence views">
          <For each={[['ioc', 'IOC'], ['cves', 'CVEs'], ['feeds', 'Feeds']] as [Tab, string][]}>{([t, label]) => (
            <button class="tab" role="tab" aria-selected={tab() === t} onClick={() => { picked = true; setTab(t); }}>{label}</button>
          )}</For>
        </div>

        <Show when={tab() === 'ioc'}>
          <div class="bento">
            <section class="pcard span-4" aria-label="Threat-intel pack">
              <p class="l0-label">Your threat-intel pack</p>
              <Show when={!sample()} fallback={<><p class="pcard-kpi">15,610</p><p class="pcard-note">indicators · signed · generation 7 · detect-only</p></>}>
                <Show when={intel()} fallback={<p class="pcard-note">Not reported.</p>}>
                  <Show when={intel()!.ioc.file === 'loaded'} fallback={<p class="l0-card-sub">No pack {intel()!.ioc.file === 'refused' ? 'loaded: the signature was refused' : 'loaded yet'}. Upload a signed IOC pack in Administration.</p>}>
                    <p class="pcard-kpi">{(intel()!.ioc.ipv4_prefixes + intel()!.ioc.domains).toLocaleString()}</p>
                    <p class="pcard-note">{intel()!.ioc.ipv4_prefixes.toLocaleString()} address ranges · {intel()!.ioc.domains.toLocaleString()} domains · {intel()!.ioc.signed ? 'signed' : 'unsigned'} · generation {intel()!.ioc.generation} · {intel()!.ioc.mode}</p>
                  </Show>
                </Show>
              </Show>
            </section>
            <section class="pcard span-8" aria-label="Matches on this network">
              <p class="l0-label">Matched on this network · {iocHits().length}</p>
              <Show when={iocHits().length > 0} fallback={<p class="pcard-note">Nothing on your network matched the pack. That is good news.</p>}>
                <For each={iocHits().slice(0, 30)}>{(h) => (
                  <span class="prow"><span>{h.what} · <b>{h.who}</b> <span class="l0-muted">{h.detail}</span></span><span>{formatTime(h.ts)}</span></span>
                )}</For>
              </Show>
            </section>
          </div>
        </Show>

        <Show when={tab() === 'cves'}>
          <Show when={cvesServed()} fallback={
            <div class="pcard">
              <p>This device does not report software exposure yet.</p>
              <p class="pcard-note">CVE matching needs an inventory of the software on your devices (VEX + SSVC). It appears here when the device or your control plane serves it; no sample numbers are shown as yours.</p>
            </div>
          }>
            <div class="l0-table-wrap"><table class="l0-table obs-table">
              <thead><tr><th scope="col">CVE</th><th scope="col">Component</th><th scope="col">CVSS</th><th scope="col">Exposed here</th><th scope="col">Status</th></tr></thead>
              <tbody><For each={cves()}>{(c) => (
                <tr>
                  <td><button class="dev-btn" style={{ border: 0, padding: 0, background: 'none', 'min-height': '28px' }} onClick={() => setSel(c.cve)}>{c.cve}</button></td>
                  <td>{c.component}</td>
                  <td class="l0-num" style={{ 'font-weight': 400 }}>{c.cvss.toFixed(1)}</td>
                  <td>{c.exposed ? (c.assets.length ? `${c.assets.length} device${c.assets.length === 1 ? '' : 's'}` : 'Yes') : 'No'}</td>
                  <td>{STATUS[c.status] ?? c.status} · {c.ssvc}</td>
                </tr>
              )}</For></tbody>
            </table></div>
          </Show>
        </Show>

        <Show when={tab() === 'feeds'}>
          <div class="pcard">
            <p class="l0-label">Feed subscriptions</p>
            <p class="l0-card-sub">Your threat-intel pack is signed offline and uploaded, so the device never trusts a feed it cannot verify.</p>
            <span class="gate gate--off">
              <span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn">Add STIX/TAXII feed</button> <button class="hp-btn">Add MISP instance</button></span>
              <span class="gate-reason" role="note">Live feed subscriptions run in a control plane (cloud-linked or self-hosted), which then signs packs for this device.</span>
            </span>
            <a class="hp-btn" href="/admin/identity">Upload a signed IOC pack</a>
          </div>
        </Show>
      </main>

      <Drawer open={!!selected()} title={selected()?.cve ?? ''} crumb={selected() ? `${selected()!.component} · CVSS ${selected()!.cvss.toFixed(1)} · ${STATUS[selected()!.status] ?? selected()!.status}` : ''} onClose={() => setSel(null)}
        footer={<span class="gate gate--off"><span class="gate-body" ref={(el) => el.setAttribute('inert', '')} aria-hidden="true"><button class="hp-btn hp-btn--primary">Propose a fix plan</button></span>
          <span class="gate-reason" role="note">Fix plans need the AI planner and a software inventory of your devices; neither is on this device yet.</span></span>}>
        <p>{selected()?.summary}</p>
        <p class="l0-label">Exposed assets</p>
        <Show when={(selected()?.assets.length ?? 0) > 0} fallback={<p class="pcard-note">{selected()?.exposed ? selected()?.reason : 'No exposed assets in scope.'}</p>}>
          <For each={selected()!.assets}>{(a) => (sample() ? <p class="l0-card-sub" style={{ margin: 0 }}>{a}</p> : <a class="l0-link-row" href="/network/devices">{a} →</a>)}</For>
        </Show>
        <Show when={selected()?.fixed_version}><p class="pcard-note">Fixed in {selected()!.fixed_version}.</p></Show>
      </Drawer>
    </AppShell>
  );
};

export default IntelligenceApp;
