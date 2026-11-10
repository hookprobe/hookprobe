/**
 * routes — the one place that builds drill-down links (FR-06: every number links to evidence).
 *
 * One incident: canonical route `/investigate/:id` (MissionControl.md route map). The UI is a static
 * build, so today the story is served from `/investigate/incident/?id=<id>`; IncidentApp also reads
 * the id from a `/investigate/<id>` path, so when the device serves that page for `/investigate/*`,
 * only `incidentHref` changes.
 */
export const incidentHref = (id: string) => `/investigate/incident/?id=${encodeURIComponent(id)}`;

/** The incident id from `?id=` or a `/investigate/<id>` path (not `queue` / `incident`). */
export function incidentIdFromLocation(loc: { pathname: string; search: string }): string | null {
  const q = new URLSearchParams(loc.search).get('id');
  if (q) return q;
  const m = loc.pathname.replace(/\/+$/, '').match(/^\/investigate\/([^/]+)$/);
  if (m && m[1] !== 'queue' && m[1] !== 'incident') return decodeURIComponent(m[1]);
  return null;
}
