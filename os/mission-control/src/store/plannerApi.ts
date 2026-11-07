/**
 * plannerApi — the `hookprobe-planner` HTTP client (ADR 0025, AEGIS BYO-LLM planner).
 *
 * A SEPARATE service/origin from `store/api.ts`'s `hookprobe-api` read-API, deliberately:
 * `hookprobe-api` is read-only by construction and must never gain a write route; this is the one
 * narrow, additive write surface the planner needs (see `crates/hookprobe-planner/src/main.rs`'s
 * module doc). Shapes here mirror `crates/hookprobe-planner/src/schema.rs` 1:1 — keep them in sync.
 *
 * Honesty contract this module exists to protect: `fetchPlannerStatus()` is the ONLY way
 * `CommandPalette.tsx` learns whether a model is configured. Every other function here assumes the
 * caller already checked `configured === true` — `proposeIntent`/`explainIncident` still surface a
 * real `503 not_configured` error if called anyway (the server-side check in `main.rs`), never a
 * fabricated response.
 */

export const PLANNER_API_BASE =
  (import.meta.env.PUBLIC_PLANNER_API_BASE as string | undefined) ?? 'http://127.0.0.1:8421';

export interface PlannerStatus {
  configured: boolean;
  endpoint: string | null;
  model: string | null;
  /** Present only when `configured` is `false` — the exact operator-facing copy to render. */
  message?: string;
}

/** `crates/hookprobe-planner/src/schema.rs::Explanation`. */
export interface PlannerExplanation {
  why: string;
  confidence: number;
  /** Non-secret `endpoint::model-id` identity — never the API key. */
  model: string;
}

/** `crates/hookprobe-planner/src/schema.rs::DiffLine` (`#[serde(tag = "kind", content = "text")]`). */
export interface PlannerDiffLine {
  kind: 'added' | 'removed' | 'unchanged';
  text: string;
}

/** `crates/hookprobe-planner/src/schema.rs::ArtifactPreview`. */
export interface PlannerArtifactPreview {
  path: string;
  content: string;
}

/** `crates/hookprobe-planner/src/schema.rs::ProposedChange`. */
export interface PlannerProposedChange {
  before_plan: string[];
  after_plan: string[];
  diff: PlannerDiffLine[];
  artifacts: PlannerArtifactPreview[];
  warnings: string[];
}

/** `crates/hookprobe-planner/src/schema.rs::PlannerResponse` — `POST /api/planner/propose`'s body. */
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
 *  records the result so `/api/incidents/:id`'s `model` field (served by `hookprobe-api`) populates. */
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
 *  see `main.rs`'s handler doc: promoting a staged proposal into the device's live config still
 *  requires the existing, unchanged `hookprobe-supervisor --reconcile-network --network-write` step. */
export async function approveChange(artifacts: PlannerArtifactPreview[]): Promise<PlannerApproveResult> {
  return postJson<PlannerApproveResult>('/api/planner/approve', { artifacts });
}
