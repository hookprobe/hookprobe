/** HookProbe MSSP API TypeScript Types */

export interface Node {
  id: string;
  site_id: string;
  name: string;
  type: string;
  status: "active" | "inactive" | "provisioning";
  ip_address: string;
  qsecbit: number;
  last_seen: string;
  created_at: string;
  fingerprint_hash?: string;
  provisioned_via?: string;
  product_state?: Record<string, unknown>;
}

export interface QSecBitScore {
  overall: number;
  components: {
    systemHealth: number;
    firewall: number;
    accessControl: number;
    patchStatus: number;
    authIntegrity: number;
    fileIntegrity: number;
    networkExposure: number;
  };
  node_id: string;
  calculated_at: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "investigating" | "resolved" | "closed";
  source: string;
  description?: string;
  created_at: string;
  resolved_at?: string;
}

export interface IOC {
  id: string;
  type: "ip" | "domain" | "hash" | "url" | "email";
  value: string;
  confidence: number;
  source: string;
  first_seen: string;
  last_seen: string;
  tags?: string[];
}

export interface Verdict {
  id: string;
  src_ip: string;
  verdict: "benign" | "suspicious" | "malicious";
  sentinel_score: number;
  anomaly_score: number;
  confidence: number;
  campaign_id?: string;
  created_at: string;
}

export interface TelemetryData {
  nodeId: string;
  type: "system" | "network" | "security" | "fim" | "auth";
  data: Record<string, unknown>;
}

export interface HeartbeatPayload {
  nodeId: string;
  qsecbit?: number;
  system?: Record<string, unknown>;
  network?: Record<string, unknown>;
  security?: Record<string, unknown>;
}

export interface HeartbeatResponse {
  status: string;
  node_id: string;
  qsecbit?: number;
}

export interface HookProbeClientOptions {
  baseUrl?: string;
  apiKey: string;
  timeout?: number;
}
