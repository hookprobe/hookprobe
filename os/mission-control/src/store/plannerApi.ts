/**
 * plannerApi — the AI planner HTTP client (`/api/planner/*`, ADR 0025, AEGIS BYO-LLM planner).
 *
 * Kept apart from `store/api.ts` (read-only) because this is the one narrow, additive write surface
 * the planner needs. heqk has no on-device planner yet: it answers `/api/planner/status` with
 * `configured: false` and the write routes with `503 not_configured` (`os/kernel/kernel/src/http.rs`).
 * The shapes below are the ADR 0025 planner contract (the first server's `schema.rs` is in git history).
 *
 * Honesty contract this module exists to protect: `fetchPlannerStatus()` is the ONLY way
 * `CommandPalette.tsx` learns whether a model is configured. Every other function here assumes the
 * caller already checked `configured === true` — `proposeIntent`/`explainIncident` still surface a
 * real `503 not_configured` error if called anyway (the server-side check in `main.rs`), never a
 * fabricated response.
 */

/** Same-origin by default: on heqk the device itself serves the planner routes (ADR 0047 D2).
 *  `PUBLIC_PLANNER_API_BASE` points a build at a separate planner origin instead. */
export const PLANNER_API_BASE =
  (import.meta.env.PUBLIC_PLANNER_API_BASE as string | undefined) ?? '';

export interface PlannerStatus {
  configured: boolean;
  endpoint: string | null;
  model: string | null;
  /** Present only when `configured` is `false` — the exact operator-facing copy to render. */
  message?: string;
}

/** `Explanation` (ADR 0025 contract). */
export interface PlannerExplanation {
  why: string;
  confidence: number;
  /** Non-secret `endpoint::model-id` identity — never the API key. */
  model: string;
}

/** `DiffLine` (ADR 0025 contract) (`#[serde(tag = "kind", content = "text")]`). */
export interface PlannerDiffLine {
  kind: 'added' | 'removed' | 'unchanged';
  text: string;
}

/** `ArtifactPreview` (ADR 0025 contract). */
export interface PlannerArtifactPreview {
  path: string;
  content: string;
}

/** `ProposedChange` (ADR 0025 contract). */
export interface PlannerProposedChange {
  before_plan: string[];
  after_plan: string[];
  diff: PlannerDiffLine[];
  artifacts: PlannerArtifactPreview[];
  warnings: string[];
}

/** `PlannerResponse` (ADR 0025 contract) — `POST /api/planner/propose`'s body. */
export interface PlannerResponse {
  answer: string;
  explanation: PlannerExplanation;
  /** `null` when the model proposed no state change, or its proposed patch failed validation
   *  (see `warnings` for why) — the operator still sees `answer`, never a blank screen. */
  change: PlannerProposedChange | null;
  warnings: string[];
}

/** A real, honest failure — HTTP status + whatever message the server attached (never invented). */
export class PlannerApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'PlannerApiError';
  }
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${PLANNER_API_BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new PlannerApiError(res.status, data.error ?? 'unknown', data.message ?? `HTTP ${res.status}`);
  }
  return data as T;
}

/** `GET /api/planner/status` — call before rendering anything else in the Copilot. Never throws
 *  for the honest "not configured" case (that's a `200` with `configured: false`); only throws if
 *  the planner service itself is unreachable (a distinct, also-honest "service down" state). */
export async function fetchPlannerStatus(): Promise<PlannerStatus> {
  const res = await fetch(`${PLANNER_API_BASE}/api/planner/status`, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    throw new PlannerApiError(res.status, 'unreachable', `planner status -> HTTP ${res.status}`);
  }
  return res.json() as Promise<PlannerStatus>;
}

/** `POST /api/planner/propose` — the Copilot's main intent → plan-as-diff call. */
export async function proposeIntent(intent: string): Promise<PlannerResponse> {
  return postJson<PlannerResponse>('/api/planner/propose', { intent });
}

/** `POST /api/planner/incidents/:id/explain` — grounds the same call in one incident's evidence and
 *  records the result so `/api/incidents/:id`'s `model` field populates. */
export async function explainIncident(incidentId: string, intent = ''): Promise<PlannerResponse> {
  return postJson<PlannerResponse>(`/api/planner/incidents/${encodeURIComponent(incidentId)}/explain`, { intent });
}

export interface PlannerApproveResult {
  staged: true;
  proposal_id: string;
  staged_dir: string;
  artifact_count: number;
  note: string;
}

/** `POST /api/planner/approve` — stages a proposal's artifacts for operator review. NOT an apply —
 *  promoting a staged proposal into the device's live config stays a separate, operator-approved step
 *  (ADR 0025). */
export async function approveChange(artifacts: PlannerArtifactPreview[]): Promise<PlannerApproveResult> {
  return postJson<PlannerApproveResult>('/api/planner/approve', { artifacts });
}

/** `GET /api/planner/proposals/:id` — where the reconciler is with a staged proposal. */
export interface ProposalStatus {
  state: 'staged' | 'applying' | 'verified' | 'failed';
  detail?: string;
  updated_ms?: number;
}

/**
 * Follow a staged proposal until it is verified or failed (PlanDiff's `watch`). Polls every 2 s.
 * A device that does not serve the status route yet (404) ends the watch silently: the plan then
 * honestly stays at "Staged", never a guessed "applied".
 */
export function watchProposal(
  id: string,
  update: (u: { state: 'applying' } | { state: 'verified'; detail?: string } | { state: 'failed'; detail: string }) => void,
): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const tick = async () => {
    if (stopped) return;
    try {
      const res = await fetch(`${PLANNER_API_BASE}/api/planner/proposals/${encodeURIComponent(id)}`, { headers: { accept: 'application/json' } });
      if (res.status === 404) return; // not served yet: stay at Staged
      if (res.ok) {
        const st = (await res.json()) as ProposalStatus;
        if (st.state === 'applying') update({ state: 'applying' });
        else if (st.state === 'verified') { update({ state: 'verified', detail: st.detail }); return; }
        else if (st.state === 'failed') { update({ state: 'failed', detail: st.detail ?? 'The reconciler reported a failure.' }); return; }
      }
    } catch { /* transient: try again */ }
    if (!stopped) timer = setTimeout(() => void tick(), 2000);
  };
  void tick();
  return () => { stopped = true; if (timer) clearTimeout(timer); };
}
