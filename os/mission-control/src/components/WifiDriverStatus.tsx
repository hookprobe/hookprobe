/**
 * WifiDriverStatus — the Wi-Fi driver's health (store/wifiDriver.ts, ADR 0065). Renders nothing until the device reports
 * `wifi_driver`. `calm` also says so when all is well (the Wi-Fi settings page); Mission shows only what needs attention.
 */
import { type Component, For, Show } from 'solid-js';
import { wifiDriver, driverLines } from '../store/wifiDriver';

const WifiDriverStatus: Component<{ calm?: boolean }> = (p) => {
  const lines = () => (wifiDriver() ? driverLines(wifiDriver()!) : []);
  return (
    <Show when={wifiDriver() && (lines().length > 0 || p.calm)}>
      <div class="pcard" role={lines().some((l) => l.level === 'warn') ? 'alert' : 'status'} aria-label="Wi-Fi driver">
        <p class="l0-label">Wi-Fi driver</p>
        <Show when={lines().length > 0} fallback={<p class="l0-card-sub" style={{ margin: 0 }}>Running isolated from the kernel; no faults since start-up.</p>}>
          <For each={lines()}>{(l) => <p class={l.level === 'warn' ? 'plan-diff-warn' : 'pcard-note'} style={{ margin: 0 }}>{l.level === 'warn' ? '⚠ ' : ''}{l.text}</p>}</For>
        </Show>
      </div>
    </Show>
  );
};

export default WifiDriverStatus;
