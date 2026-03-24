/**
 * HookProbe MSSP API Client
 *
 * Connects to hookprobe-com MSSP dashboard API for node management,
 * telemetry, QSecBit scoring, and fleet operations.
 *
 * @example
 * ```ts
 * import { HookProbeClient } from "@hookprobe/sdk";
 *
 * const client = new HookProbeClient({ apiKey: "hp_..." });
 * const nodes = await client.listNodes();
 * const score = await client.getQSecBit("node-uuid");
 * ```
 */

import type {
  Node,
  QSecBitScore,
  Incident,
  IOC,
  Verdict,
  HeartbeatPayload,
  HeartbeatResponse,
  TelemetryData,
  HookProbeClientOptions,
} from "./types.js";

export * from "./types.js";

export class HookProbeError extends Error {
  statusCode: number;
  constructor(message: string, statusCode: number = 0) {
    super(message);
    this.name = "HookProbeError";
    this.statusCode = statusCode;
  }
}

export class HookProbeClient {
  private baseUrl: string;
  private apiKey: string;
  private timeout: number;

  constructor(options: HookProbeClientOptions) {
    this.baseUrl = (options.baseUrl || "https://mssp.hookprobe.com").replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeout = options.timeout || 30000;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-API-Key": this.apiKey,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new HookProbeError(`API error ${res.status}: ${text.slice(0, 500)}`, res.status);
      }

      const text = await res.text();
      return text ? JSON.parse(text) : (null as T);
    } catch (e) {
      if (e instanceof HookProbeError) throw e;
      throw new HookProbeError(`Connection error: ${(e as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  // --- Node Management ---

  /** List all nodes, optionally filtered by site. */
  async listNodes(siteSlug?: string): Promise<Node[]> {
    const path = siteSlug ? `/api/sites/${siteSlug}/fleet` : "/api/nodes";
    return this.request<Node[]>("GET", path);
  }

  /** Get node details including telemetry and QSecBit score. */
  async getNode(nodeId: string): Promise<Node> {
    return this.request<Node>("GET", `/api/nodes/${nodeId}`);
  }

  /** Get QSecBit score breakdown for a node. */
  async getQSecBit(nodeId: string): Promise<QSecBitScore> {
    return this.request<QSecBitScore>("GET", `/api/nodes/qsecbit?nodeId=${nodeId}`);
  }

  // --- Telemetry ---

  /** Submit node heartbeat with telemetry data. */
  async heartbeat(payload: HeartbeatPayload): Promise<HeartbeatResponse> {
    return this.request<HeartbeatResponse>("POST", "/api/nodes/heartbeat", payload);
  }

  /** Submit specific telemetry data (system, network, security, fim, auth). */
  async submitTelemetry(data: TelemetryData): Promise<Record<string, unknown>> {
    return this.request("POST", "/api/nodes/telemetry", data);
  }

  // --- Threat Intelligence ---

  /** Get recent security incidents. */
  async getIncidents(limit: number = 20): Promise<Incident[]> {
    return this.request<Incident[]>("GET", `/api/xsoc/incidents?limit=${limit}`);
  }

  /** Get indicators of compromise. */
  async getIOCs(limit: number = 50): Promise<IOC[]> {
    return this.request<IOC[]>("GET", `/api/xsoc/iocs?limit=${limit}`);
  }

  /** Get SENTINEL ML verdicts. */
  async getVerdicts(limit: number = 20): Promise<Verdict[]> {
    return this.request<Verdict[]>("GET", `/api/xsoc/hydra/verdicts?limit=${limit}`);
  }

  // --- Health ---

  /** Check MSSP dashboard health. */
  async health(): Promise<string> {
    try {
      const res = await fetch(`${this.baseUrl}/health`, {
        signal: AbortSignal.timeout(5000),
      });
      return res.text();
    } catch (e) {
      return `unhealthy: ${(e as Error).message}`;
    }
  }
}
