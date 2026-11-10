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
    const poll = setInterval(() => { if (configView()?.state === 'trial') void refreshConfig(); }, 5000);
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
      <Show when={configView()?.state === 'trial'}>
        <div class="hp-banner hp-banner--trial" role="status" aria-label="Configuration trial">
          <strong>Trying new settings</strong>
          {' '}Configuration generation {configView()!.on_trial ?? configView()!.generation} is on trial.{' '}
          <Show when={configView()!.needs_confirm} fallback={
            <Show when={configView()!.auto_rollback} fallback={<>It stays until you keep it or roll it back.</>}>
              If the internet does not work, the device goes back to the previous settings by itself in <b>{mmss(secondsLeft(now()))}</b>.
            </Show>
          }>
            It changes how you reach this device, so <b class="trial-required">Keep it is required</b>: unless you keep it within <b>{mmss(secondsLeft(now()))}</b>, the device goes back to the previous settings.
          </Show>
          <Show when={configView()!.health}>{' '}<span class="l0-muted">({configView()!.health})</span></Show>
          <span class="hp-banner-actions">
            <button class="hp-btn hp-btn--primary" onClick={() => void run(confirmConfig)}>Keep it</button>
            <button class="hp-btn" onClick={() => void run(rollbackConfig)}>Roll back now</button>
          </span>
        </div>
      </Show>
      <Show when={configView()?.state === 'reverted'}>
        <div class="hp-banner hp-banner--sample" role="status"><strong>Settings rolled back</strong> The last configuration did not work, so the device went back to generation {configView()!.generation}.</div>
      </Show>
      <Show when={msg()}><p class="hp-banner" role="status">{msg()}</p></Show>
    </>
  );
};

export default ConfigBanners;
