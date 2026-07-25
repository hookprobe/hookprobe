/**
 * AdministrationApp — Administration (§12): identity, infrastructure, and the
 * OS lifecycle (Build → Deploy).
 *
 * Spec: docs/MissionControl.md §12. Panels:
 *   - KPI row (users / edge nodes / built images / modules)
 *   - IDENTITY & ACCESS (users, roles/RBAC, SSO, API keys / secrets)
 *   - EDGE NODES · PLATFORM MANIFEST (hardware, capabilities, crypto posture,
 *     bootc upgrade/rollback, storage & retention tiers)
 *   - IMAGES & ARTIFACTS (channel, cosign sig, SBOM/CBOM, provenance)
 *   - MODULES (runtime: wasm/container/sysext, grants, signatures)
 *   - PROVISIONING & ENROLLMENT (lifecycle steps, current deploy mode)
 *   - AI MODELS · AEGIS (Ollama/OpenAI-compatible endpoint, autonomy, confidence)
 *
 * Capability-gated in a real build (manifest grants gate each panel).
 * Cyber-industrial terminal soul. Mode: cloud-linked.
 */

import { type Component, For } from 'solid-js';
import LeftRail from './LeftRail';
import CommandPalette from './CommandPalette';
import { setCopilotOpen, setCopilotQuery, copilotOpen, copilotQuery } from '../store/mock';
import type { Tone } from '../store/missionMock';
import {
  type Kpi, type UserRole, type EdgeNode, type Channel,
  type ModuleRuntime, type ModuleStatus, type ModelStatus, type AutonomyLevel,
  KPIS, USERS, SSO_PROVIDERS, API_KEYS_COUNT, SECRETS_COUNT,
  EDGE_NODES, IMAGES, MODULES, PROV_STEPS, CURRENT_MODE, AEGIS_MODEL,
} from '../store/admMock';

// ── Helpers ───────────────────────────────────────────────────────────────────

function toneVar(t: Tone): string {
  return {
    green: 'var(--hp-green)', amber: 'var(--hp-amber)', red: 'var(--hp-red)',
    blue: 'var(--hp-cyan)', cyan: 'var(--hp-cyan)', purple: 'var(--hp-purple)', orange: 'var(--hp-orange)', grey: 'var(--hp-grey)',
  }[t];
}

function roleTone(role: UserRole): string {
  if (role === 'Super Admin') return 'var(--hp-red)';
  if (role === 'SOC Analyst') return 'var(--hp-cyan)';
  if (role === 'API Service') return 'var(--hp-purple)';
  return 'var(--hp-grey)';
}

function channelTone(ch: Channel): string {
  return ch === 'stable' ? 'var(--hp-green)' : ch === 'edge' ? 'var(--hp-amber)' : 'var(--hp-grey)';
}

function runtimeTone(rt: ModuleRuntime): string {
  return rt === 'wasm' ? 'var(--hp-cyan)' : rt === 'container' ? 'var(--hp-purple)' : 'var(--hp-amber)';
}

function nodeTone(n: EdgeNode): string {
  return n.status === 'healthy' ? 'var(--hp-green)'
    : n.status === 'needs-attention' ? 'var(--hp-amber)'
    : 'var(--hp-red)';
}

function storagePct(used: number, total: number): number {
  return Math.round((used / total) * 100);
}

function storageFillTone(pct: number): string {
  return pct > 85 ? 'var(--hp-red)' : pct > 65 ? 'var(--hp-amber)' : 'var(--hp-green)';
}

function modStatusClass(s: ModuleStatus): string {
  return s === 'degraded' ? 'adm-mod-dot--deg' : s === 'disabled' ? 'adm-mod-dot--dis' : '';
}

function modelConnClass(s: ModelStatus): string {
  return `adm-model-conn--${s}`;
}

function modelDotClass(s: ModelStatus): string {
  return `adm-model-dot--${s}`;
}

function autonomyClass(l: AutonomyLevel): string {
  return `adm-level--${l}`;
}

// ── Panel ─────────────────────────────────────────────────────────────────────

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

// ── Component ─────────────────────────────────────────────────────────────────

const AdministrationApp: Component = () => {
  /* Primary node for the manifest viewer — index 0 is the "selected" node */
  const primaryNode = EDGE_NODES[0];

  return (
    <div class="dash-layout">
      <LeftRail active="/admin" mode="cloud-linked" onOpenCopilot={() => setCopilotOpen(true)} />

      <main class="dash-main">
        <header class="mc-header">
          <div>
            <h1 class="mc-h1">ADMINISTRATION</h1>
            <div class="mc-sub">Identity, infrastructure &amp; OS lifecycle (Build → Deploy)</div>
          </div>
          <div class="mc-header-actions">
            <button class="mc-chip" onClick={() => setCopilotOpen(true)}>
              ⌘ "push upgrade to fleet"
            </button>
            <a class="mc-chip" href="/admin/feedback">Feedback &amp; Diagnostics →</a>
            <span class="mc-mode-badge">● cloud-linked</span>
          </div>
        </header>

        <div class="mc-grid">

          {/* ── KPI row ──────────────────────────────────────────────────── */}
          <div class="mc-cell--kpis adm-kpis">
            <For each={KPIS}>
              {(k) => (
                <div class="mc-kpi" style={{ '--tone': toneVar(k.tone) }}>
                  <div class="mc-kpi-label">{k.label}</div>
                  <div class="mc-kpi-value">{k.value}</div>
                </div>
              )}
            </For>
          </div>

          {/* ── IDENTITY & ACCESS ─────────────────────────────────────────── */}
          <Panel ctx="identity" title="IDENTITY & ACCESS" span="span 5">

            <div class="adm-section-head">USERS &amp; ROLES</div>
            <ul class="adm-users">
              <For each={USERS}>
                {(u) => (
                  <li class="adm-user-row">
                    <span class="adm-user-avatar" aria-hidden="true">
                      {u.name[0].toUpperCase()}
                    </span>
                    <div class="adm-user-body">
                      <div class="adm-user-name">{u.name}</div>
                      <div class="adm-user-email">{u.email}</div>
                    </div>
                    <span class="adm-role-pill" style={{ '--rt': roleTone(u.role) }}>
                      {u.role}
                    </span>
                    <span class={`adm-user-status adm-status--${u.status}`} aria-label={u.status}>
                      {u.status === 'active' ? '●' : '○'}
                    </span>
                    <span class="adm-user-last">{u.lastLogin}</span>
                  </li>
                )}
              </For>
            </ul>

            <div class="adm-divider" />

            <div class="adm-section-head">SSO &amp; AUTH</div>
            <ul class="adm-sso-list">
              <For each={SSO_PROVIDERS}>
                {(s) => (
                  <li class="adm-sso-row">
                    <span class={`adm-sso-dot adm-sso-dot--${s.status}`} aria-hidden="true" />
                    <span class="adm-sso-name">{s.name}</span>
                    <span class="adm-sso-type">{s.type}</span>
                    <span class={`adm-sso-status adm-sso-status--${s.status}`}>{s.status}</span>
                  </li>
                )}
              </For>
            </ul>

            <div class="adm-divider" />

            <div class="adm-key-counts">
              <div class="adm-key-stat">
                <span class="adm-key-n">{API_KEYS_COUNT}</span>
                <span class="adm-key-k">API Keys</span>
              </div>
              <div class="adm-key-stat">
                <span class="adm-key-n">{SECRETS_COUNT}</span>
                <span class="adm-key-k">Secrets</span>
              </div>
              <a class="adm-link" href="/admin/identity">Manage →</a>
            </div>

          </Panel>

          {/* ── EDGE NODES · PLATFORM MANIFEST ───────────────────────────── */}
          <Panel ctx="edge-nodes" title="EDGE NODES · PLATFORM MANIFEST" span="span 7">

            {/* Node selector strip */}
            <div class="adm-node-strip">
              <For each={EDGE_NODES}>
                {(n, i) => (
                  <div
                    class={`adm-node-chip${i() === 0 ? ' adm-node-chip--active' : ''}`}
                    style={{ '--nt': nodeTone(n) }}
                  >
                    <span class="adm-node-chip-dot" aria-hidden="true" />
                    <span class="adm-node-chip-name">{n.hostname}</span>
                    <span class="adm-node-chip-plat">{n.platform}</span>
                  </div>
                )}
              </For>
            </div>

            {/* Primary node manifest detail */}
            <div class="adm-manifest">
              <div class="adm-manifest-cols">

                {/* Hardware */}
                <div class="adm-manifest-col">
                  <div class="adm-section-head">HARDWARE</div>
                  <ul class="adm-kv-list">
                    <li class="adm-kv">
                      <span class="adm-k">Platform</span>
                      <span class="adm-v">{primaryNode.platform}</span>
                    </li>
                    <li class="adm-kv">
                      <span class="adm-k">Arch</span>
                      <span class="adm-v">{primaryNode.arch}</span>
                    </li>
                    <li class="adm-kv">
                      <span class="adm-k">RAM</span>
                      <span class="adm-v">{primaryNode.ram}</span>
                    </li>
                    <li class="adm-kv">
                      <span class="adm-k">Enrolled</span>
                      <span class="adm-v">{primaryNode.enrolled}</span>
                    </li>
                    <li class="adm-kv">
                      <span class="adm-k">Attestation</span>
                      <span
                        class="adm-v"
                        style={{ color: primaryNode.crypto.attestation ? 'var(--hp-green)' : 'var(--hp-grey)' }}
                      >
                        {primaryNode.crypto.attestation ? 'TPM-bound' : 'no TPM'}
                      </span>
                    </li>
                  </ul>
                </div>

                {/* Crypto posture */}
                <div class="adm-manifest-col">
                  <div class="adm-section-head">CRYPTO POSTURE</div>
                  <ul class="adm-kv-list">
                    <li class="adm-kv">
                      <span class="adm-k">Signing</span>
                      <span class="adm-v adm-v--mono">{primaryNode.crypto.signing}</span>
                    </li>
                    <li class="adm-kv">
                      <span class="adm-k">KEX</span>
                      <span class="adm-v adm-v--mono">{primaryNode.crypto.kex}</span>
                    </li>
                    <li class="adm-kv">
                      <span class="adm-k">Boot</span>
                      <span class="adm-v adm-v--mono">{primaryNode.crypto.boot}</span>
                    </li>
                  </ul>
                </div>

              </div>

              {/* Granted capabilities */}
              <div class="adm-section-head" style={{ 'margin-top': '10px' }}>
                GRANTED CAPABILITIES
              </div>
              <div class="adm-caps">
                <For each={primaryNode.capabilities}>
                  {(c) => <span class="adm-cap">{c}</span>}
                </For>
              </div>

              {/* OS version / channel + bootc controls */}
              <div class="adm-os-row">
                <div class="adm-os-info">
                  <span class="adm-os-ver">{primaryNode.osVer}</span>
                  <span
                    class="adm-channel-pill"
                    style={{ '--ct': channelTone(primaryNode.channel) }}
                  >
                    {primaryNode.channel}
                  </span>
                </div>
                <div class="adm-os-actions">
                  {primaryNode.upgradeAvail && (
                    <button class="adm-action-btn adm-action-btn--upgrade" type="button">
                      bootc upgrade
                    </button>
                  )}
                  <button class="adm-action-btn adm-action-btn--rollback" type="button">
                    rollback
                  </button>
                </div>
              </div>

              {/* Storage & retention */}
              <div class="adm-section-head">STORAGE &amp; RETENTION</div>
              <ul class="adm-storage-list">
                <For each={primaryNode.storage}>
                  {(t) => {
                    const pct = storagePct(t.used, t.total);
                    return (
                      <li class="adm-storage-row">
                        <span class="adm-storage-name">{t.name}</span>
                        <span class="adm-storage-bar" aria-hidden="true">
                          <span
                            class="adm-storage-fill"
                            style={{ width: `${pct}%`, background: storageFillTone(pct) }}
                          />
                        </span>
                        <span class="adm-storage-stat">{t.used}/{t.total} {t.unit}</span>
                        <span class="adm-storage-window">{t.window}</span>
                      </li>
                    );
                  }}
                </For>
              </ul>

            </div>
          </Panel>

          {/* ── IMAGES & ARTIFACTS ───────────────────────────────────────── */}
          <Panel ctx="lifecycle/images" title="IMAGES & ARTIFACTS" span="span 8">
            <ul class="adm-image-list">
              <li class="adm-image-header adm-image-row" aria-hidden="true">
                <span>Version</span>
                <span>Channel</span>
                <span>Platform</span>
                <span>Built</span>
                <span>Size</span>
                <span>Signature</span>
                <span>SBOM</span>
                <span>CBOM</span>
              </li>
              <For each={IMAGES}>
                {(img) => (
                  <li class={`adm-image-row${img.active ? ' adm-image-row--active' : ''}`}>
                    <span class="adm-image-ver">
                      {img.version}
                      {img.active && <span class="adm-active-pill">active</span>}
                    </span>
                    <span
                      class="adm-channel-pill"
                      style={{ '--ct': channelTone(img.channel) }}
                    >
                      {img.channel}
                    </span>
                    <span class="adm-image-plat">{img.platform}</span>
                    <span class="adm-image-meta">{img.builtAt}</span>
                    <span class="adm-image-meta">{img.size}</span>
                    <span class={`adm-sig-pill adm-sig-pill--${img.signed ? 'ok' : 'missing'}`}>
                      {img.signed ? '✓ cosign' : '✗ unsigned'}
                    </span>
                    <span class={`adm-bool-pill${img.hasSbom ? ' adm-bool-pill--yes' : ''}`}>
                      {img.hasSbom ? '✓' : '—'}
                    </span>
                    <span class={`adm-bool-pill${img.hasCbom ? ' adm-bool-pill--yes' : ''}`}>
                      {img.hasCbom ? '✓' : '—'}
                    </span>
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* ── MODULES ──────────────────────────────────────────────────── */}
          <Panel ctx="lifecycle/modules" title="MODULES" span="span 4">
            <ul class="adm-module-list">
              <For each={MODULES}>
                {(m) => (
                  <li class="adm-module-row">
                    <span
                      class={`adm-mod-dot ${modStatusClass(m.status)}`}
                      aria-label={m.status}
                      aria-hidden="true"
                    />
                    <div class="adm-mod-body">
                      <div class="adm-mod-name">
                        {m.name}
                        <span class="adm-mod-ver">&nbsp;{m.version}</span>
                      </div>
                      <div class="adm-mod-grants">{m.grants.join(', ')}</div>
                    </div>
                    <span
                      class="adm-runtime"
                      style={{ '--rt': runtimeTone(m.runtime) }}
                    >
                      {m.runtime}
                    </span>
                    <span
                      class={`adm-sig-dot${m.signed ? ' adm-sig-dot--ok' : ''}`}
                      title={m.signed ? 'cosign verified' : 'unsigned'}
                      aria-hidden="true"
                    />
                  </li>
                )}
              </For>
            </ul>
          </Panel>

          {/* ── PROVISIONING & ENROLLMENT ─────────────────────────────────── */}
          <Panel ctx="lifecycle/provisioning" title="PROVISIONING & ENROLLMENT" span="span 5">

            <div class="adm-prov-mode">
              <div class="adm-section-head" style={{ 'margin-bottom': '0' }}>CURRENT MODE</div>
              <span class="adm-mode-badge">{CURRENT_MODE}</span>
            </div>

            <div class="adm-divider" />

            <ul class="adm-prov-steps">
              <For each={PROV_STEPS}>
                {(s) => (
                  <li class={`adm-prov-step adm-prov-step--${s.status}`}>
                    <span class="adm-prov-dot" aria-hidden="true" />
                    <div class="adm-prov-step-body">
                      <div class="adm-prov-label">{s.label}</div>
                      <div class="adm-prov-detail">{s.detail}</div>
                    </div>
                  </li>
                )}
              </For>
            </ul>

            <div class="adm-divider" />

            <div class="adm-prov-actions">
              <button class="adm-action-btn" type="button">Flash image →</button>
              <button class="adm-action-btn" type="button">Enroll device →</button>
              <button class="adm-action-btn adm-action-btn--muted" type="button">
                Change mode →
              </button>
            </div>

          </Panel>

          {/* ── AI MODELS · AEGIS ─────────────────────────────────────────── */}
          <Panel ctx="ai-models" title="AI MODELS · AEGIS" span="span 7">

            {/* Model header */}
            <div class="adm-model-header">
              <div class="adm-model-status-row">
                <span class={`adm-model-dot ${modelDotClass(AEGIS_MODEL.status)}`} aria-hidden="true" />
                <span class="adm-model-name">{AEGIS_MODEL.name}</span>
                <span class="adm-model-type-pill">{AEGIS_MODEL.type}</span>
              </div>
              <span class={`adm-model-conn ${modelConnClass(AEGIS_MODEL.status)}`}>
                {AEGIS_MODEL.status}
              </span>
            </div>

            {/* Endpoint config */}
            <ul class="adm-kv-list adm-model-kv">
              <li class="adm-kv">
                <span class="adm-k">Endpoint</span>
                <span class="adm-v adm-v--mono">{AEGIS_MODEL.endpoint}</span>
              </li>
              <li class="adm-kv">
                <span class="adm-k">Model</span>
                <span class="adm-v adm-v--mono">{AEGIS_MODEL.model}</span>
              </li>
              <li class="adm-kv">
                <span class="adm-k">Min. confidence</span>
                <span class="adm-v adm-v--conf">
                  <span class="adm-confidence-bar" aria-hidden="true">
                    <span
                      class="adm-confidence-fill"
                      style={{ width: `${AEGIS_MODEL.confidence}%` }}
                    />
                  </span>
                  <span class="adm-v--mono">{AEGIS_MODEL.confidence}%</span>
                </span>
              </li>
            </ul>

            <div class="adm-divider" />

            {/* Autonomy policy */}
            <div class="adm-section-head">AUTONOMY POLICY</div>
            <ul class="adm-autonomy-list">
              <For each={AEGIS_MODEL.autonomy}>
                {(r) => (
                  <li class="adm-autonomy-row">
                    <span class="adm-autonomy-action">{r.action}</span>
                    <span class={`adm-autonomy-level ${autonomyClass(r.level)}`}>
                      {r.level}
                    </span>
                  </li>
                )}
              </For>
            </ul>

          </Panel>

        </div>
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

export default AdministrationApp;
