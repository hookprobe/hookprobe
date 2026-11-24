/**
 * WifiDriverStatus — the Wi-Fi driver's health (store/wifiDriver.ts, ADR 0065). Renders nothing until the device reports
 * `wifi_driver`. `calm` also says so when all is well (the Wi-Fi settings page); Mission shows only what needs attention.
 */
import { type Component, For, Show } from 'solid-js';
import { wifiDriver, driverLines, type WifiDriver } from '../store/wifiDriver';
import { cap } from '../store/capabilities';

const WifiDriverStatus: Component<{ calm?: boolean }> = (p) => {
  /** A device with no Wi-Fi (wifi_ap not granted, e.g. QEMU) reports "absent" with no history: there is no driver to
   *  talk about, so nothing is shown. Any fault, restart or reset is still shown: a driver did run. */
  const shown = (): WifiDriver | null => {
    const w = wifiDriver();
    if (!w) return null;
    const idle = (x: { state: string; restarts: number; faults: number }) => x.state === 'absent' && x.restarts === 0 && x.faults === 0;
    if (cap('wifi_ap').state !== 'granted' && idle(w.bus) && (!w.security || (idle(w.security) && w.security.full_wipes === 0))) return null;
    return w;
  };
  const lines = () => (shown() ? driverLines(shown()!) : []);
  return (
    <Show when={shown() && (lines().length > 0 || p.calm)}>
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
