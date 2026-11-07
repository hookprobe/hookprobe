/**
 * obsLive — Observe (§3, Senzorium) real-data layer: `GET /api/flows` (the live event stream) and
 * `GET /api/devices` (asset inventory).
 *
 * `flows`/`devices` are NOT part of `/api/stream`'s poll payload (only detections/incidents/qsecbit
 * are — see `EvidenceGraph::poll_since`), so there is no SSE push for these two; a light poll
 * interval (`POLL_MS`) is the edge-cheap substitute (`ObserveApp` owns the interval's lifecycle via
 * `onMount`/`onCleanup`, this module just exposes a plain `refetch()`).
 *
 * HONESTY NOTE: `obsMock.ts`'s `SOURCES` (per-protocol ingest breakdown), `RETENTION_TIERS`
 * (pcap/events/alerts fill %) and the KPI row's `Retention window`/`Dropped %` have NO backing
 * read-API endpoint yet (no per-source counters, no retention-tier accounting exposed) — `ObserveApp`
 * keeps rendering `obsMock.ts`'s static values for those, clearly labelled "mock" in their panel
 * titles. `LIVE_EVENTS` (from flows) and `ASSET_GROUPS` (from devices, which carries no OS field —
 * rendered as a real ip/mac/last-seen list instead of a fabricated OS breakdown) ARE wired here.
 */

import { createSignal } from 'solid-js';
import { fetchJson, formatTime, type FlowRow, type FlowsResponse, type DeviceRow, type DevicesResponse } from './api';

export type LiveStatus = 'loading' | 'live' | 'error';

export const [flows, setFlows] = createSignal<FlowRow[]>([]);
export const [flowsStatus, setFlowsStatus] = createSignal<LiveStatus>('loading');
export const [flowsError, setFlowsError] = createSignal<string | null>(null);

export const [devices, setDevices] = createSignal<DeviceRow[]>([]);
export const [devicesStatus, setDevicesStatus] = createSignal<LiveStatus>('loading');
export const [devicesError, setDevicesError] = createSignal<string | null>(null);

const FLOW_LIMIT = 100;
const DEVICE_LIMIT = 200;

export async function refetch(): Promise<void> {
  const [flowsResult, devicesResult] = await Promise.allSettled([
    fetchJson<FlowsResponse>(`/api/flows?limit=${FLOW_LIMIT}`),
    fetchJson<DevicesResponse>(`/api/devices?limit=${DEVICE_LIMIT}`),
  ]);

  if (flowsResult.status === 'fulfilled') {
    setFlows(flowsResult.value.flows ?? []);
    setFlowsStatus('live');
    setFlowsError(null);
  } else {
    setFlowsStatus('error');
    setFlowsError(flowsResult.reason instanceof Error ? flowsResult.reason.message : String(flowsResult.reason));
  }

  if (devicesResult.status === 'fulfilled') {
    setDevices(devicesResult.value.devices ?? []);
    setDevicesStatus('live');
    setDevicesError(null);
  } else {
    setDevicesStatus('error');
    setDevicesError(devicesResult.reason instanceof Error ? devicesResult.reason.message : String(devicesResult.reason));
  }
}

export { formatTime };
