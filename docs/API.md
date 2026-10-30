# CyberGlass API Reference

## Overview

CyberGlass exposes three API layers:

| Interface | Port | Protocol | Purpose |
|---|---|---|---|
| gRPC | 9400 | HTTP/2 + Protobuf | High-performance binary streaming for collectors and integrations |
| REST | 9401 | HTTP/1.1 + JSON | Web UI and general API access |
| WebSocket | 9401 | WS | Real-time event streaming |

Protected REST endpoints require a valid bearer session or API key; requests
without credentials are rejected. Sign in with `POST /api/v1/auth/login` using
`{"username":"admin","password":"..."}`, then send
`Authorization: Bearer <access_token>`. The web UI prompts for credentials and
holds the access token in tab-scoped session storage. On a fresh installation,
the initial administrator password is taken from `CYBERGLASS_ADMIN_PASSWORD`
or generated at `<node.data_dir>/initial-admin-password`. The server's user
and session records are currently in memory: sign in again after every server
restart.

### First Login Steps

1. Start CyberGlass and confirm the REST listener is available at
   `http://localhost:9401`. For a source checkout, run `cargo run -p cg-server`
   from the workspace root. The web UI is at `http://localhost:9401/ui`.
2. Enter `admin` as the username, unless `CYBERGLASS_ADMIN_USERNAME` was set
   before the server started.
3. Use `CYBERGLASS_ADMIN_PASSWORD` if it was set before startup. Otherwise,
   read the generated password from `<node.data_dir>/initial-admin-password`.
   With the supplied Windows configuration, the path is
   `C:\var\lib\cyberglass\initial-admin-password`. If the server was started
   with `--home "D:\CyberGlassData"`, use
   `D:\CyberGlassData\data\initial-admin-password`. The configured
   `node.data_dir` is the source of truth.
4. On Windows, copy the password directly to the clipboard without printing it:

   ```powershell
   Get-Content -Raw 'C:\var\lib\cyberglass\initial-admin-password' | Set-Clipboard
   ```

   Substitute the correct data directory if it differs.
5. After signing in, store the password in an approved password manager and
   protect the password file. **Do not delete the file** unless a replacement
   `CYBERGLASS_ADMIN_PASSWORD` has been securely configured for future server
   starts. If neither source is available on startup, the server generates a
   new administrator password. A configured password must be at least 12
   characters. `CYBERGLASS_ADMIN_PASSWORD` takes precedence over the file.

The generated username defaults to `admin`; `CYBERGLASS_ADMIN_USERNAME`
overrides it. These variables must be present in the server process
environment at startup.

### Login API

```http
POST /api/v1/auth/login
Content-Type: application/json

{"username":"admin","password":"<administrator-password>"}
```

On success, the response includes `access_token`, `refresh_token`, `user`, and
`expires_in`. Keep both tokens secret. Send the access token as
`Authorization: Bearer <access_token>` to protected endpoints. The default
access-token lifetime is eight hours. Use `POST /api/v1/auth/logout` to revoke
the current session. In-memory sessions are lost at server restart, so log in
again after restarting.

### Login Troubleshooting

- **The UI or API is unavailable:** Start the server and verify the configured
  REST port (default `9401`). A stopped server cannot authenticate logins.
- **Invalid username or password:** Confirm the username override, password
  environment variable, and data directory of the running server. With
  `--home`, the password file is under `<home>\data`. If the environment
  variable is set, it overrides the password file.
- **A copied password fails:** Copy it from the active server's password file
  again. Do not include surrounding quotes or whitespace when entering it.
- **Password file is missing:** Check the server startup log for the data
  directory and generated-password message. If no environment password is
  configured and there are no active users, startup generates a replacement
  password file.
- **Account locked:** Five failed attempts lock the account for 15 minutes by
  default. Stop repeated retries and wait for the lockout to expire.
- **Login worked, then protected requests return 401:** Sign in again. Server
  sessions are held in memory and do not survive restart.

---

## REST API (Port 9401)

### Base URL
```
http://localhost:9401
```

### Platform

#### GET /api/v1/info
Returns platform information.

**Response:**
```json
{
  "platform": "CyberGlass SIEM",
  "version": "0.1.0",
  "engine": "Rust-Native / Zero-GC",
  "intelligence": "CyberGlass Ontology + Search",
  "air_gap": true,
  "protocols": ["gRPC", "Protobuf", "REST", "CGAP"]
}
```

#### GET /api/v1/health
Returns per-component health status.

**Response:**
```json
{
  "status": "HEALTHY",
  "version": "0.1.0",
  "uptime_seconds": 0,
  "components": {
    "bus": { "component": "event_bus", "status": "healthy", "message": "NATS cluster connected" },
    "ingest": { "component": "ingest", "status": "healthy", "message": "accepted=100 rejected=0 wal=true" },
    "index": { "status": "healthy", "indices": 1 },
    "detection": { "status": "healthy", "active_rules": 2, "total_alerts": 0 },
    "ontology": { "status": "healthy", "entities": 0 },
    "ai": { "status": "healthy", "models": 1 }
  }
}
```

#### GET /api/v1/metrics
Returns cluster metrics including ingestion statistics.

**Response:**
```json
{
  "status": "HEALTHY",
  "cluster": "cyberglass-standalone",
  "version": "0.1.0",
  "indexes": {
    "total_count": 1,
    "total_events": 1000,
    "total_bytes": 1048576
  },
  "detection": {
    "active_rules": 2,
    "total_alerts": 5
  },
  "ontology": {
    "entities_tracked": 50,
    "relationships_tracked": 75
  },
  "ingestion": {
    "accepted": 1000,
    "rejected": 0,
    "parse_errors": 0,
    "events_per_second": 0.0,
    "average_latency_us": 150,
    "backpressure_events": 0,
    "wal_records": 1000
  },
  "ai": {
    "models_available": 1
  },
  "uptime_seconds": 3600
}
```

### Indices

#### GET /api/v1/indices
Lists all search indices.

#### POST /api/v1/indices/clear
Clears documents from indexes without deleting their definitions. Requires
`index:manage` permission and explicit confirmation.

```json
{
  "scope": "all",
  "confirm": true
}
```

`scope` must be `external`, `internal`, or `all`. The response reports how
many indexes were cleared in each scope. Clearing internal indexes writes a
new cleanup audit event to `cg_audit` after the clear operation.

#### GET /api/v1/internal/logs?index=cg_internal
Returns up to 500 most recent records from a persistent internal index.
Supported names are `cg_internal`, `cg_audit`, and `cg_introspection`.
Internal queries support equality filters and an optional
`| head N` limit; aggregate pipelines are not supported for these indexes.

The server writes host resource and ingest pipeline snapshots to
`cg_introspection` every 15 seconds. Host fields include CPU usage/model/core
count, memory and swap use, mounted-disk totals, network byte counters, and OS
identity where the platform exposes them. Network byte values are cumulative
counters, not per-second rates. Blank or zero values can mean the host platform
does not expose that measurement. This describes the CyberGlass server host;
remote endpoint inventory must be collected by an endpoint agent. API request
counts and latency summaries are written when requests occurred during the
preceding collection interval. These are persisted records; they are not
synthetic values generated by the read API.
`GET /api/v1/internal/introspection` returns the same persisted introspection
stream.

#### GET /api/v1/events
Lists events with pagination.

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `page` | integer | 1 | Page number (1-based) |
| `page_size` | integer | 50 | Results per page (max 1000) |
| `index` | string | "main" | Index name to search |

**Response:**
```json
{
  "status": "SUCCESS",
  "index": "main",
  "page": 1,
  "page_size": 50,
  "total": 1000,
  "events": [
    {
      "_id": "uuid-v7-string",
      "_time": "2026-10-28T14:32:10Z",
      "source": "windows_security",
      "source_type": "WinEventLog:Security",
      "fields": {
        "EventID": "4624",
        "TargetUserName": "sec_admin"
      }
    }
  ]
}
```

### Ingestion

#### POST /api/v1/ingest
Ingests a single raw event.

#### POST /api/v1/ingest/batch
Ingests multiple events in a single request.

#### POST /services/collector
HEC (HTTP Event Collector) endpoint — event ingestion.
Accepts events in HEC format and ingests them through the pipeline.

**Headers:**
| Header | Value | Description |
|---|---|---|
| `Authorization` | `CyberGlass <token>` | HEC authentication token |

**Request:**
```json
{
  "event": { "raw": "EventID=4624 TargetUserName=admin" },
  "source": "windows_security",
  "sourcetype": "WinEventLog:Security",
  "index": "main",
  "host": "dc01.corp.local",
  "time": "2026-10-28T14:32:10Z"
}
```

**Response:**
```json
{
  "code": 200,
  "text": "success",
  "accepted": 1,
  "rejected": 0
}
```

#### POST /services/collector/event
Alias for `/services/collector` (HEC compatibility).

### Data Onboarding Methods

CyberGlass supports four data onboarding methods:

| Method | Endpoint / Port | Description |
|---|---|---|
| **REST API** | `POST /api/v1/ingest` | JSON-based event ingestion |
| **HEC** | `POST /services/collector` | HTTP Event Collector |
| **TCP Syslog** | `0.0.0.0:1514` | Syslog over TCP (newline-delimited) |
| **UDP Syslog** | `0.0.0.0:1514` | Syslog over UDP (packet-based) |
| **File Monitor** | Directory watcher | Watches `./data/import` for new `.log` files |
| **Scripted Agent** | `cg-agent` binary | Standalone agent for script/file onboarding |

### Search (CyberQL)

#### POST /api/v1/query
Executes a CyberQL query.

**Request:**
```json
{
  "query": "source=\"windows_security\" EventID=4625 | stats count by TargetUserName | sort -count"
}
```

**Response:**
```json
{
  "status": "SUCCESS",
  "stats": {
    "execution_time_ms": 12.5,
    "events_scanned": 1000,
    "results_returned": 15
  },
  "results": [
    { "TargetUserName": "Administrator", "count": 42 },
    { "TargetUserName": "guest", "count": 8 }
  ]
}
```

### Detection & Alerts

#### GET /api/v1/alerts
Lists security alerts.

#### POST /api/v1/alerts/status
Updates an alert's status.

**Request:**
```json
{
  "alert_id": "uuid-string",
  "status": "acknowledged"
}
```

#### GET /api/v1/rules
Lists detection rules.

#### POST /api/v1/rules
Creates a new detection rule.

**Request:**
```json
{
  "name": "Suspicious PowerShell",
  "query": "process=*powershell* -enc * | stats count by User",
  "severity": "High",
  "description": "Detects encoded PowerShell execution",
  "mitre": ["T1059.001"]
}
```

### Ontology & Knowledge Graph

#### GET /api/v1/entities
Searches discovered security entities.

#### GET /api/v1/graph
Returns knowledge graph nodes and edges for visualization.

**Response:**
```json
{
  "status": "SUCCESS",
  "nodes": [
    {
      "id": "entity-uuid",
      "display_name": "sec_admin",
      "entity_type": "user",
      "risk_score": 45.5,
      "confidence": 0.95
    }
  ],
  "edges": [
    {
      "source_entity_id": "uuid-1",
      "target_entity_id": "uuid-2",
      "relation_type": "AuthenticatedTo",
      "weight": 1.0,
      "confidence": 0.9
    }
  ],
  "node_count": 50,
  "edge_count": 75
}
```

### AI Threat Hunter (CGAP)

#### POST /api/v1/ai/chat
Sends a message to the cyberglass AI threat hunter.

**Request:**
```json
{
  "message": "How do I detect brute force attacks in CyberQL?",
  "prefer_local": true
}
```

**Response:**
```json
{
  "status": "SUCCESS",
  "response": "To detect brute force attacks, use this CyberQL query:\n\n```cyberql\nsource=\"windows_security\" EventID=4625 | stats count by TargetUserName | where count > 5\n```",
  "usage": { "prompt_tokens": 50, "completion_tokens": 100, "total_tokens": 150 }
}
```

### WebSocket

#### GET /api/v1/ws
WebSocket endpoint for real-time event streaming.

**Client → Server messages:**
```json
{ "action": "ping" }
```

**Server → Client messages (events from the bus):**
```json
{
  "event": {
    "id": "uuid-v7-string",
    "source": "firewall",
    "source_type": "pan:traffic",
    "index": "main",
    "severity": 4,
    "fields": { "src_ip": "10.0.0.1", "action": "blocked" }
  }
}
```

---

## gRPC API (Port 9400)

### Services

| Service | RPCs |
|---|---|
| `IngestService` | `IngestBatch`, `IngestStream`, `Health` |
| `QueryService` | `ExecuteQuery`, `Health` |
| `DetectionService` | `EvaluateEvent`, `ListRules`, `CreateRule`, `UpdateAlertStatus`, `Health` |
| `OntologyService` | `AddEntity`, `SearchEntities`, `GetGraph`, `Health` |
| `AiService` | `Chat`, `ListModels`, `Health` |
| `AdminService` | `GetConfig`, `ReloadConfig`, `Health` |

### Event Envelope (Protobuf)

```protobuf
message Event {
  string id = 1;                               // UUID v7
  google.protobuf.Timestamp timestamp = 2;     // Event time
  google.protobuf.Timestamp ingest_time = 3;   // Ingestion time
  string source = 4;                           // Source identifier
  string source_type = 5;                      // Source type
  string index = 6;                            // Target index
  bytes raw = 7;                               // Raw event bytes
  map<string, string> fields = 8;              // Extracted key-value fields
  map<string, string> metadata = 9;            // System metadata
  Severity severity = 10;
  string tenant_id = 11;                       // Multi-tenancy
  string collector_id = 12;                    // Collector ID
}
```

---

## Error Responses

All API endpoints return standard error formats:

```json
{
  "status": "ERROR",
  "error": "Human-readable error message"
}
```

Common status values: `SUCCESS`, `ACCEPTED`, `REJECTED`, `ERROR`, `PARSE_ERROR`, `HEALTHY`, `DEGRADED`.

---

## Web UI

The interactive CyberGlass Web UI is served at `http://localhost:9401/` and `http://localhost:9401/ui`. It includes:

- **CyberQL Search** — Query builder with presets, timeline histogram, results table, export
- **Ontology Graph** — Interactive knowledge graph with drag, zoom, and physics simulation
- **Alerts & Sigma** — Alert management with status workflow and MITRE ATT&CK tagging
- **Log Ingestion Lab** — Raw log ingestion with sample data and batch testing
- **AI Threat Hunter** — CyberGlass AI assistant with markdown rendering and one-click query execution
- **Cluster & Metrics** — System telemetry and storage tier information

**Keyboard Shortcuts:**
- `Ctrl/Cmd + K` — Focus search
- `/` — Focus search
- `Escape` — Close modals
