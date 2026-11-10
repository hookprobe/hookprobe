/**
 * RestartButton — "Restart now" (POST /api/reboot, gap G49): reason + owner key re-authentication,
 * like every permanent change. The device answers before it restarts (2 s later); staged signed
 * configuration applies on the way up. A device without the endpoint, or a refusal, is said plainly.
 */
import { type Component, Show, createSignal } from 'solid-js';
import { post } from '../store/actions';

const RestartButton: Component<{ sample?: boolean; primary?: boolean; label?: string }> = (props) => {
  const [msg, setMsg] = createSignal('');
  const [busy, setBusy] = createSignal(false);
  const run = async () => {
    const reason = window.prompt('Reason for the restart (kept in the journal):', 'apply staged configuration');
    if (!reason || reason.trim().length < 3) { setMsg('Cancelled: a reason of at least 3 characters is required.'); return; }
    const key = window.prompt('Restarting interrupts the network for about a minute. Enter your owner key:', '');
    if (!key) { setMsg('Cancelled: the owner key is required.'); return; }
    setBusy(true); setMsg('');
    try {
      const o = await post<{ ok: boolean; note?: string; refused?: string }>('/api/reboot', { reason: reason.trim(), permanent: 'true', owner_key: key });
      setMsg(o.ok ? `Restarting: ${o.note ?? 'the device restarts in a few seconds'}. This page reconnects when it is back.`
        : /HTTP 404/.test(o.refused ?? '') ? 'This device cannot be restarted from Mission Control yet. Power-cycle it instead.'
        : `The device refused: ${o.refused}`);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  };
  return (
    <span style={{ display: 'inline-flex', 'flex-direction': 'column', gap: '6px' }}>
      <button class={`hp-btn${props.primary ? ' hp-btn--primary' : ''}`} disabled={props.sample || busy()} onClick={() => void run()}>{props.label ?? 'Restart now'}</button>
      <Show when={props.sample}><span class="gate-reason">Preview: on a device this restarts it (owner key).</span></Show>
      <Show when={msg()}><span class="pro-sub" role="status">{msg()}</span></Show>
    </span>
  );
};

export default RestartButton;
