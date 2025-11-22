# Hookprobe — Dual Architecture: SBC (Podman) + Cloud/Datacenter Backend (Kubernetes)

**Purpose:**
Provide a practical, step‑by‑step architecture and migration plan to run Hookprobe as a small, efficient **SBC/edge appliance** (Podman) while operating a scalable, cloud/datacenter **backend** on Kubernetes that matches Hookprobe’s current functionality 1:1 and adds centralized orchestration, storage, analytics, and optional DFIR integration.

**Audience:** Developers, DevOps, Security engineers, product owners working on Hookprobe.

---

# 1. Executive summary

Keep Hookprobe’s existing Podman-based SBC for edge collection, enforcement, and local detection (low footprint, full control of netns/OVS/VXLAN). Add a centralized Kubernetes backend for long-term storage, cross-site correlation, ML/analytics, multi-tenant dashboards, and automated incident handling. The SBC acts as an **agent**; the backend is the **control plane / analytics brain**.

Benefits:

* Minimal disruption to existing SBC appliance code and network model
* Scalability and HA for storage/analytics
* Centralized correlation across many SBCs
* Easy integration with Velociraptor / endpoint DFIR in backend
* Optional: offer Hookprobe-as-a-service or multi-site managed deployments

Trade-offs:

* Added operational complexity for backend (k8s management)
* Network architecture design required for secure connectivity from SBCs to backend
* Storage and compute costs for cloud/datacenter resources

---

# 2. Goals & non-goals

## Goals

* Mirror Hookprobe functionality (network probes, eBPF events, WAF logs, Snort/Suricata alerts, n8n automations, metrics and logs) in the cloud backend.
* Keep SBC lightweight and standalone-capable.
* Provide a secure, encrypted channel for telemetry and commands between SBC and backend.
* Provide automation (SOAR-like flows) and searchable archives for forensic evidence.

## Non-goals

* Replace the SBC with Kubernetes on edge hardware.
* Force all telemetry through the cloud (edge-first must remain viable offline).

---

# 3. High-level architecture

(Conceptual layers — see diagram in repository / design docs)

**Edge: Hookprobe SBC (Podman)**

* Podman pods running: web, WAF, parser, detector (eBPF), flow-exporter, n8n, collector, stats pipeline, monitoring exporter
* Local components: OVS/VXLAN, PSK isolation, eBPF probes, Snort or Suricata, Nginx/NAXSI WAF
* Local queues: lightweight buffering (filesystem or embedded queue) for durability during offline periods
* Outbound connections: authenticated TLS (mTLS) to Backend Ingest API or to a message broker endpoint

**Network / Transport**

* Encrypted, authenticated transport from SBC → Backend (mTLS over TLS 1.3, client certs or vault-issued tokens)
* Optional: use a message broker (Kafka/NATS JetStream) as ingestion buffer (deployed in cloud)
* Fallback to store-and-forward on SBC when link unavailable

**Cloud/Datacenter Backend (Kubernetes)**

* Ingress & API Gateway (ingest endpoint with rate limiting, auth)
* Ingestion layer: API workers + Flow collectors + eBPF/Netflow adapters
* Message bus: Kafka or NATS JetStream (async processing, resilience)
* Processing & enrichment: enrichment workers, parsers, threat engine, WAF analysis
* Storage: VictoriaMetrics (metrics), VictoriaLogs or Loki (logs), object storage (artifacts / forensic dumps)
* Automation: n8n (or SOAR), Kubernetes Jobs for triage/remediation
* Observability: Prometheus, Grafana, Alerts
* Optional DFIR: Velociraptor server + connectors to trigger hunts via n8n

---

# 4. Component mapping (1:1 equivalence)

| Podman (SBC) Component                  |                          Cloud Backend Equivalent | Purpose / Notes                                                                                       |
| --------------------------------------- | ------------------------------------------------: | ----------------------------------------------------------------------------------------------------- |
| eBPF probes, OpenFlow-like logic        |               Cilium (optional) / Flow collectors | Backend will receive flow events; Cilium only used inside cluster for network visibility if needed    |
| Snort/Suricata (local)                  | Suricata/Snort aggregator + normalization service | Keep fast local detection at SBC; send IDS events to cloud for correlation                            |
| WAF (Nginx + NAXSI / ModSecurity)       |         WAF processing microservice + ingress WAF | Cloud WAF can handle large-scale behavioral analysis; SBC remains enforcement point for local traffic |
| VictoriaMetrics (local)                 |             VictoriaMetrics cluster (statefulset) | Long-term metrics storage & aggregation across SBC fleet                                              |
| Loki / VictoriaLogs                     |                       Loki / VictoriaLogs cluster | Centralized logs and search across SBCs                                                               |
| n8n (automation)                        |         n8n (deployment) or dedicated SOAR system | Trigger hunts, apply controls, orchestrate across cluster and SBCs                                    |
| Hookprobe detectors/parsers (go/python) |       Kubernetes Deployments / Horizontal scaling | Stateless microservices scale to process telemetry streams                                            |
| Local queue / buffering                 |                           Kafka or NATS JetStream | Durable ingestion queue; prevents data loss during spikes                                             |
| GUI / Dashboard                         |                     Grafana + Web UI (deployment) | Dashboards for metrics, logs, alerts and threat triage                                                |

---

# 5. Secure connectivity model

**Requirements:** confidentiality, integrity, authentication, resilience.

1. **mTLS with mutual client certs**: generate per-SBC client certs using a CA (cert-manager in k8s or external Vault). SBCs present certs to backend ingest endpoints.
2. **Short-lived credentials**: use Vault or cert-manager to rotate credentials. SBC bootstraps with a one-time token to request certs.
3. **Dedicated ingress endpoints**: regional LB endpoints that accept SBC telemetry. Use Layer7 rate limiting and IP allowlist if desired.
4. **Message broker auth**: if SBCs push directly to Kafka/NATS (SASL/MTLS), use per-client auth.
5. **Offline resilience**: SBC stores data locally until ingestion succeeds; backoff and jitter to avoid thundering herd.
6. **Zero trust posture**: SBCs are treated as untrusted by default; authorization scopes limit what each SBC can publish or request.

---

# 6. Data flow (detailed)

1. SBC collects events: eBPF traces, flow records, WAF logs, IDS alerts.
2. Local parser normalizes events and places them into local queue with schema (JSON+metadata: timestamp, sbc_id, tenant_id, flow_id).
3. SBC attempts to push batched events to the Backend Ingest API over mTLS.
4. Backend API validates origin, verifies schema, and writes to message bus (Kafka/NATS). This admits async processing and spikes.
5. Processing workers subscribe to message bus: enrichment (geoip, asn, ti), parsers (suricata normalization), ML models for anomaly detection.
6. Normalized outputs are written to VictoriaMetrics (metrics derived) and Loki/VictoriaLogs (log ingestion). Artifacts and heavy forensic captures are written to object storage (S3/compatible) and referenced by metadata.
7. n8n or SOAR listens to high-confidence alerts and can: (a) call the SBC to update WAF rules, (b) trigger a Velociraptor hunt, (c) quarantine a tenant via network policy or push a Cilium rule in the cluster.
8. Dashboards and alerting surfaces in Grafana / Alertmanager; operators triage and run automated or manual playbooks.

---

# 7. Automation & response

* **n8n flows**: rule triggered → enrich → triage → action. Examples:

  * IDS high severity → run enrichment → if IOC found → generate incident ticket + isolate host / SBC (if possible) + schedule Velociraptor hunt for endpoints.
  * Repeated brute-force attempts → create WAF block rule → deploy to SBCs via management API.

* **Kubernetes Jobs**: create short-lived jobs for heavy processing or enrichment tasks; allow HPA to scale workers.

---

# 8. Storage, retention & compliance

* **VictoriaMetrics**: tune for expected cardinality; compress older metrics. Retention depends on capacity (30–365d typical).
* **Loki / VictoriaLogs**: set index and chunking settings; separate hot/cold storage. Retention policies per tenant.
* **Object storage (S3)**: store large forensic artifacts. Lifecycle policies to move to Glacier or cold tier.
* **Access controls**: role-based access to logs and artifacts; audit trails for data access.

---

# 9. Velociraptor & endpoint DFIR integration

* Velociraptor server runs in backend as an optional StatefulSet.
* SBC triggers Velociraptor hunts indirectly via n8n or API (Velociraptor clients live on endpoints you protect, not on SBCs unless you want host-forensics on appliances).
* Hunt results link back into incident metadata stored in object storage and referenced in alerts.

---

# 10. Migration & rollout strategy (phased)

**Phase 0 — Plan & Prep**

* Define telemetry schemas, tenant model, and ingress API.
* Provision k8s cluster, storage (VM, Loki, S3), and message bus.
* Build CICD and image registry, push Hookprobe container images.

**Phase 1 — Observability & Ingest**

* Deploy Prometheus & Grafana, VictoriaMetrics, Loki.
* Stand up Ingest API + message broker (Kafka/NATS).
* Configure a single SBC to push telemetry to backend (dev/test tenant).

**Phase 2 — Processing & Automation**

* Deploy enrichment workers, parsers, and ML/heuristic pipeline.
* Deploy n8n and create sample playbooks for automated responses.

**Phase 3 — Scale & Optimize**

* Add more SBCs, tune retention, autoscaling policies.
* Harden security (cert rotation, RBAC, network policies).

**Phase 4 — Advanced**

* Integrate Velociraptor for endpoint hunts.
* Optionally run Cilium within backend clusters for intra-cluster networking and observability.

---

# 11. Operational considerations

* **Costs**: compute for processing workers, storage for logs/metrics/artifacts, message bus costs.
* **Availability**: consider multi‑AZ or multi‑region deployment for global customers.
* **Monitoring**: monitor ingestion lag, pipeline queue depth, error rates, and agent health.
* **Security**: rotate certs, use IAM for cloud resources, encrypt data at rest & transit.

---

# 12. Example APIs & schemas (short)

**Ingest record (JSON)**

```json
{
  "sbc_id":"sbc-01",
  "tenant_id":"t-123",
  "event_type":"suricata.alert",
  "timestamp":"2025-11-22T10:12:34Z",
  "payload": {"alert": { ... }}
}
```

**Management API: push WAF rule**

* `POST /api/v1/sbc/{sbc_id}/waf/rules` (auth: mTLS + token)
* Body: `{ rule_id, expression, action, ttl }`

**Trigger Velociraptor hunt (n8n)**

* `POST /api/velociraptor/hunt` → body contains target_endpoints, artifact_list, priority

---

# 13. Checklist: Quick decision map

* Keep SBC on Podman? ✅ if low latency, offline first, small footprint
* Build backend on Kubernetes? ✅ if you want scale, centralization, multi-tenant analytics
* Add Velociraptor? ✅ as DFIR server in backend, clients on endpoints you protect
* Use Kafka or NATS? Use Kafka for high-throughput retention; NATS JetStream for lower ops burden

---

# 14. Risks & mitigations

* **Data overload / storage cost** — mitigate with sampling, downsampling, TTLs, and artifact lifecycle policies.
* **SBC compromise** — assume breach model; authenticate and authorize every action, limit what SBCs can do via scopes.
* **Operational complexity** — start with a small POC; automate provisioning via Terraform/Helm; use managed k8s if possible.
