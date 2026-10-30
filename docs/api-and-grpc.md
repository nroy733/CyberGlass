# 🔌 API & gRPC Protocol Reference

CyberGlass provides dual API access:
1. **gRPC** on port `9400`: High-throughput binary streaming for collectors, agents, and automation.
2. **REST API Gateway** on port `9401`: Ergonomic JSON endpoints for web UI, dashboards, and curl integration.

---

## 1. REST API Endpoints

### Health & Readiness
`GET /api/v1/health`
Returns the status of all internal subsystems (ingestion, index, bus, detection, ontology, AI).

```bash
curl http://localhost:9401/api/v1/health
```

**Response**:
```json
{
  "status": "HEALTHY",
  "version": "0.1.0",
  "node": "standalone-node-1",
  "role": "all-in-one",
  "components": {
    "event_bus": "UP",
    "index_engine": "UP",
    "detection_engine": "UP",
    "ontology_graph": "UP",
    "ai_engine": "UP"
  }
}
```

---

### System Metrics
`GET /api/v1/metrics`
Returns real-time EPS, storage statistics, active detection rule counts, and tracked entities.

```bash
curl http://localhost:9401/api/v1/metrics
```

**Response**:
```json
{
  "status": "HEALTHY",
  "cluster": "cyberglass-standalone",
  "indexes": {
    "total_count": 1,
    "total_events": 4520,
    "total_bytes": 1048576
  },
  "detection": {
    "active_rules": 2,
    "total_alerts": 5
  },
  "ontology": {
    "entities_tracked": 12
  },
  "ai": {
    "models_available": 1
  }
}
```

---

### Event Ingestion
`POST /api/v1/ingest`
Ingests raw or JSON logs with automatic parsing, entity extraction, and rule evaluation.

```bash
curl -X POST http://localhost:9401/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "firewall",
    "source_type": "json",
    "data": "{\"action\": \"failure\", \"src_ip\": \"192.168.1.100\", \"user\": \"admin\"}"
  }'
```

---

### CyberQL Search Query
`POST /api/v1/query`
Executes an CyberQL search and aggregation pipeline.

```bash
curl -X POST http://localhost:9401/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "source=\"main\" | stats count by src_ip | sort -count | head 10"
  }'
```

---

### Alerts & Incidents
`GET /api/v1/alerts`
Lists generated security alerts with MITRE ATT&CK tags and triggering event IDs.

```bash
curl http://localhost:9401/api/v1/alerts
```

---

### Knowledge Graph Entities
`GET /api/v1/entities`
Returns tracked entities, first/last seen times, risk scores, and event counts.

```bash
curl http://localhost:9401/api/v1/entities
```

---

### CyberGlass AI Assistant
`POST /api/v1/ai/chat`
Interacts with the embedded local AI model for threat hunting, query translation, and incident triage.

```bash
curl -X POST http://localhost:9401/api/v1/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Find all brute force attacks from the last 24 hours and summarize the top attacking IPs",
    "prefer_local": true
  }'
```

---

## 2. gRPC Services (Port 9400)

| Service Name | Protobuf Package | Description |
|---|---|---|
| `IngestService` | `cyberglass.ingest` | Unary `IngestBatch` and bidirectional `IngestStream` |
| `QueryService` | `cyberglass.query` | `Query`, `QueryStream`, `ExplainQuery`, `ParseQuery` |
| `DetectionService` | `cyberglass.detection` | `ListRules`, `CreateRule`, `ImportSigmaRules`, `ListAlerts`, `SubscribeAlerts` |
| `OntologyService` | `cyberglass.ontology` | `GetEntity`, `SearchEntities`, `TraverseGraph`, `GetEntityRisk` |
| `AIService` | `cyberglass.ai` | `Chat`, `GenerateQuery`, `TriageAlert`, `SummarizeIncident` |
| `AdminService` | `cyberglass.admin` | `GetClusterStatus`, `GetMetrics` |

### Testing with `grpcurl`
```bash
# Query platform health via gRPC:
grpcurl -plaintext localhost:9400 cyberglass.admin.AdminService/GetClusterStatus

# Execute a CyberQL query via gRPC:
grpcurl -plaintext -d '{"query": "source=\"main\" | head 10"}' \
  localhost:9400 cyberglass.query.QueryService/Query
```
