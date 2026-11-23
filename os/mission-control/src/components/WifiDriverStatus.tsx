/**
 * WifiDriverStatus — "Wi-Fi health": the out-of-kernel driver (ADR 0065 `wifi_driver`) and the self-heal (`wifi_heal`,
 * `wifi_boot`, `wifi_files`), from /api/health (store/wifiDriver.ts). Renders nothing until the device reports them.
 * `calm` also says so when all is well (the Wi-Fi settings page); Mission shows only what needs attention.
 */
import { type Component, For, Show } from 'solid-js';
import { wifiDriver, driverLines, wifiSelfHeal, healLines, type WifiDriver } from '../store/wifiDriver';
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
  const lines = () => [...(wifiSelfHeal() ? healLines(wifiSelfHeal()!) : []), ...(shown() ? driverLines(shown()!) : [])];
  return (
    <Show when={lines().length > 0 || (p.calm && shown())}>
      <div class="pcard" role={lines().some((l) => l.level === 'warn') ? 'alert' : 'status'} aria-label="Wi-Fi health">
        <p class="l0-label">Wi-Fi health</p>
        <Show when={lines().length > 0} fallback={<p class="l0-card-sub" style={{ margin: 0 }}>Running isolated from the kernel; no faults since start-up.</p>}>
          <For each={lines()}>{(l) => <p class={l.level === 'warn' ? 'plan-diff-warn' : 'pcard-note'} style={{ margin: 0 }}>{l.level === 'warn' ? '⚠ ' : ''}{l.text}</p>}</For>
        </Show>
      </div>
    </Show>
  );
};

export default WifiDriverStatus;
