/**
 * RevokeAllPlan — "Remove all owner rules" as a plan-as-diff (ADR 0055 D7/D8, heqk `/api/owner-rules/revoke-all`).
 * The device's dry run gates the plan; the lines are the rules and LAN-access exceptions it reports right now;
 * Approve asks for a reason and the owner key; the read-back decides "Applied and verified".
 */
import { type Component, Show, createResource } from 'solid-js';
import { previewRevokeAll, applyRevokeAll, verifyRevokeAll } from '../store/ownerRules';
import PlanDiff from './PlanDiff';

const RevokeAllPlan: Component<{ onDone?: () => void }> = (props) => {
  const [preview] = createResource(previewRevokeAll);
  return (
    <Show when={!preview.loading} fallback={<p class="pcard-note" role="status">Asking the device what this would remove…</p>}>
      <Show when={!preview.error} fallback={<p class="plan-diff-warn" role="alert">{String((preview.error as Error)?.message ?? preview.error)}</p>}>
        <PlanDiff
          title="Remove all owner rules"
          lines={preview()!.lines}
          warnings={preview()!.warnings}
          onApprove={applyRevokeAll}
          watch={verifyRevokeAll()}
          onReject={props.onDone}
        />
      </Show>
    </Show>
  );
};

export default RevokeAllPlan;
