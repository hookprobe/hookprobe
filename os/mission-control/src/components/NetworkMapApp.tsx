/**
 * NetworkMapApp — My Network (/network/zones, /network/map, /network/devices).
 *
 * One Network screen: NetworkLive renders Zones / Map / List over the device's inventory (/api/devices), or its
 * labelled sample devices when no device answers. The old separate sample map (its own device set, actions that
 * pretended to apply, a breadcrumb to the wrong place) was retired after the Pro validation of 14 Nov.
 */
import { type Component, createSignal, onCleanup, onMount, Show } from 'solid-js';
import NetworkLive from './NetworkLive';
import { healthChecked, loadHealth } from '../store/health';
import { refetch, devicesStatus } from '../store/obsLive';
import { refetchTls } from '../store/tlsLive';
import { substrate } from '../store/mock';
import AppShell from './AppShell';

/** On a device: the live inventory; when its list cannot be read, say so (never sample data); no device: the sample. */
const NetworkMapApp: Component = () => {
  const [fails, setFails] = createSignal(0);
  onMount(() => {
    void loadHealth();
    const tick = async () => {
      await Promise.all([refetch(), refetchTls()]);
      if (devicesStatus() === 'error') setFails((n) => n + 1);
    };
    void tick();
    const t = setInterval(() => void tick(), 10_000);
    onCleanup(() => clearInterval(t));
  });
  return (
    <Show when={devicesStatus() === 'live' || (healthChecked() && !substrate())} fallback={
      <AppShell path="/network/zones"><main class="l0-main"><p class="l0-muted" role="status">{fails() >= 1
        ? 'Cannot read the device list from this device right now. Retrying every 10 s; nothing shown here is sample data.'
        : 'Loading devices from this device…'}</p></main></AppShell>
    }>
      <NetworkLive />
    </Show>
  );
};

export default NetworkMapApp;
