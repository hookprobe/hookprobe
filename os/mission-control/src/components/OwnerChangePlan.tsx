/**
 * OwnerChangePlan — one ADR 0055 owner-rule change as a plan-as-diff: the device's own dry-run
 * preview becomes the PlanDiff lines; Approve writes it (reason + owner key); the device's read-back
 * decides "Applied and verified" or the honest reason it did not take effect.
 */
import { type Component, Show, createResource } from 'solid-js';
import { previewOwnerChange, applyOwnerChange, verifyOwnerChange, type OwnerChange } from '../store/ownerRules';
import PlanDiff from './PlanDiff';

const OwnerChangePlan: Component<{ change: OwnerChange; title?: string; onDone?: () => void; onVerified?: () => void }> = (props) => {
  const [preview] = createResource(() => props.change, previewOwnerChange);
  return (
    <Show when={!preview.loading} fallback={<p class="pcard-note" role="status">Asking the device what this would change…</p>}>
      <Show when={!preview.error} fallback={<p class="plan-diff-warn" role="alert">{String((preview.error as Error)?.message ?? preview.error)}</p>}>
        <PlanDiff
          title={props.title ?? 'Proposed change'}
          lines={preview()!.lines}
          warnings={preview()!.warnings}
          onApprove={() => applyOwnerChange(props.change)}
          watch={verifyOwnerChange(props.change, props.onVerified)}
          onReject={props.onDone}
        />
      </Show>
    </Show>
  );
};

export default OwnerChangePlan;
