/**
 * ConfigBanners — two device-wide states every screen must show (ADR 0059):
 *   red    "Configuration unprotected": the device accepts unsigned configuration files (GET /api/anchor
 *          state = "CONFIG UNPROTECTED") — fix: make your key the owner key.
 *   amber  a configuration trial is running (GET /api/config state = "trial"): a countdown, Keep it (confirm)
 *          and Roll back. The automatic rollback is promised only when the device reports auto_rollback.
 * Both read device state only; nothing shows on a device that does not serve these endpoints.
 */
import { type Component, Show, createSignal, onCleanup, onMount } from 'solid-js';
import { anchorView, refreshAnchor } from '../store/anchor';
import { configView, refreshConfig, secondsLeft, confirmConfig, rollbackConfig } from '../store/configState';

const mmss = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;

const ConfigBanners: Component = () => {
  const [now, setNow] = createSignal(Date.now());
  const [msg, setMsg] = createSignal('');
  onMount(() => {
    void refreshAnchor(); void refreshConfig();
    const tick = setInterval(() => setNow(Date.now()), 1000);
    const poll = setInterval(() => { const c = configView(); if (c?.state === 'trial' || (c?.live && c.live.phase !== 'idle')) void refreshConfig(); }, 5000);
    onCleanup(() => { clearInterval(tick); clearInterval(poll); });
  });
  const run = async (f: () => Promise<string>) => { setMsg(''); try { setMsg(await f()); } catch (e) { setMsg(e instanceof Error ? e.message : String(e)); } };

  return (
    <>
      <Show when={anchorView()?.state === 'CONFIG UNPROTECTED'}>
        <div class="hp-banner hp-banner--danger" role="alert">
          <strong>Configuration unprotected</strong> This device accepts internet, Wi-Fi and firewall files that nobody signed, so anyone with its boot card can change them.{' '}
          <a href="/admin/identity">Make your key the owner key</a> to protect it.
        </div>
      </Show>
      <Show when={configView()?.live?.phase === 'applying' || configView()?.live?.phase === 'reverting'}>
        <div class="hp-banner hp-banner--trial" role="status" aria-label="Configuration applying">
          <strong>{configView()!.live!.phase === 'applying' ? 'Applying new settings\u2026' : 'Switching back\u2026'}</strong>{' '}
          {configView()!.live!.phase === 'applying' ? `Changing ${configView()!.live!.changes.map((c) => ({ wan: 'the internet', wifi: 'the Wi-Fi', policy: 'the firewall' } as Record<string, string>)[c] ?? c).join(', ') || 'the configuration'} now, without a restart.` : 'The new settings did not work; the previous ones are coming back.'}
        </div>
      </Show>
      <Show when={configView()?.state === 'trial'}>
        <div class="hp-banner hp-banner--trial" role="status" aria-label="Configuration trial">
          <strong>Trying new settings</strong>
          {' '}Configuration generation {configView()!.generation} is on trial.{' '}
          <Show when={configView()!.needs_confirm} fallback={
            <Show when={configView()!.auto_rollback} fallback={<>It stays until you keep it or roll it back.</>}>
              If the internet does not work, the device goes back to the previous settings{configView()!.floor ? ` (generation ${configView()!.floor})` : ''} by itself in <b>{mmss(secondsLeft(now()))}</b>.
            </Show>
          }>
            It changes how you reach this device, so <b class="trial-required">Keep it is required</b>: unless you keep it within <b>{mmss(secondsLeft(now()))}</b>, the device goes back to the previous settings{configView()!.floor ? ` (generation ${configView()!.floor})` : ''}.
          </Show>
          <Show when={configView()!.health}>{' '}<span class="l0-muted">({configView()!.health})</span></Show>
          <Show when={configView()!.live?.mgmt_ok === false}>{' '}<b>Mission Control cannot reach the device the new way{configView()!.live!.mgmt_probe ? ` (${configView()!.live!.mgmt_probe})` : ''}.</b></Show>
          <Show when={configView()!.envelope?.owner_enrolled !== false} fallback={<span class="l0-muted">{' '}Keeping or rolling back by hand needs your signing key as the owner key.</span>}>
            <span class="hp-banner-actions">
              <button class="hp-btn hp-btn--primary" onClick={() => void run(confirmConfig)}>Keep it</button>
              <button class="hp-btn" onClick={() => void run(rollbackConfig)}>Roll back now</button>
            </span>
          </Show>
        </div>
      </Show>
      <Show when={configView()?.state === 'reverted' || (configView()?.live?.last.result === 'reverted' && configView()?.state !== 'trial')}>
        <div class="hp-banner hp-banner--sample" role="status"><strong>Settings switched back</strong> The last change did not work, so the device went back to generation {configView()!.live?.last.result === 'reverted' ? configView()!.live!.last.generation : configView()!.generation}.</div>
      </Show>
      <Show when={configView()?.live?.last.result === 'revert_failed'}>
        <div class="hp-banner hp-banner--danger" role="alert"><strong>Switching back failed</strong> The device could not restore the previous settings live; it restarts to recover them.</div>
      </Show>
      <Show when={msg()}><p class="hp-banner" role="status">{msg()}</p></Show>
    </>
  );
};

export default ConfigBanners;
