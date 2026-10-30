# 📚 CyberGlass Documentation Portal

Welcome to the technical documentation for **CyberGlass** — the next-generation cyberglass native SIEM and Data Fusion Platform combining the intelligence of CyberGlass Ontology with high-performance search.

---

## 🧭 Navigation Guide

| Topic | Document | Description |
|---|---|---|
| **System Architecture** | [Architecture Guide](architecture.md) | Zero-GC Rust engine, tiered storage, Arrow columnstore, and NATS JetStream bus |
| **CyberQL Query Language** | [CyberQL Reference](cyberql-reference.md) | Pipe-based query language, aggregations, transforms, and optimization |
| **Detection & Correlation** | [Detection Engine](detection-engine.md) | Real-time rules, sliding-window correlation, Sigma YAML import, MITRE ATT&CK matrix |
| **Ontology & Knowledge Graph** | [Ontology Fusion](ontology-fusion.md) | Entity extraction, relationship graph, BFS traversal, and risk scoring decay |
| **API & gRPC Protocol** | [API & gRPC Reference](api-and-grpc.md) | gRPC services, REST endpoints, JSON payloads, and grpcurl examples |
| **REST API Reference** | [REST API](API.md) | Complete REST API reference with request/response examples, WebSocket streaming, and gRPC service definitions |
| **AI Engine & CGAP** | [AI & Agent Protocol](ai-and-cgap.md) | Local GGUF models, remote OpenRouter fallback, CGAP tool protocol, automated triage |
| **CyberGlass Deployment** | [Deployment Guide](deployment-and-cyberglass.md) | Linux systemd, macOS launchd, Windows, and OCI containers |
| **Windows Installation** | [Windows Installation Guide](windows-installation-guide.md) | Step-by-step Windows Server & 10/11 installation, PowerShell installer, service setup, firewall rules |

---

## ⚡ Key Architectural Tenets

1. **CyberGlass First (Zero Phone-Home)**
   - Operates in totally disconnected / dark environments with zero external dependencies.
   - Open-source, self-hosted deployment with no phone-home requirement.
   - Self-hosted local AI inference (GGUF) and offline MITRE ATT&CK intelligence.

2. **Bounded Rust-Native Processing**
   - Ingestion uses a bounded admission channel, a single bounded batch worker, and a configurable per-event size limit.
   - Throughput and latency are deployment-dependent; no EPS or sub-millisecond claim is considered verified until measured on a named reference system.

3. **Dual Protocol Plane**
   - High-throughput binary streaming over gRPC (HTTP/2 with Protobuf).
   - Ergonomic, JSON-friendly REST gateway with OpenAPI compatibility.

4. **Data Fusion & Knowledge Graph**
   - Combines unstructured raw log search (Tantivy) with structured columnar analytics (Apache Arrow) and graph relationship discovery (Ontology).

## Production Ingest-to-Alert Slice

The current vertical path is raw event admission → parsing and normalization → index write and detection → Tantivy commit → event acknowledgement. The server sink commits the index before a successful ingest response, so acknowledged indexed events survive an index-manager restart.

Default resource limits:

| Limit | Default | Behavior |
|---|---:|---|
| Admission queue | 1,024 requests | Full queue rejects immediately with a backpressure error; it does not accumulate unbounded waiters. |
| Worker batch | 256 events | Hard-capped at 1,024 even if configuration asks for more. |
| Maximum raw event | 256 KiB | Oversized requests are rejected before queueing. |
| Outstanding events | 1,280 | Admission capacity plus one worker batch. |
| Batch wait | 10 ms | Flushes partial batches; committed ingest latency includes queueing and index commit. |
| Open indexes | 1,024 | Additional opens fail explicitly; index names are restricted to safe single path components. |
| WAL disk usage | 1 GiB | `ingest.wal_max_size` is a hard cap; admission fails explicitly when the WAL cannot accept another record. |
| WAL record | 2 MiB | Versioned records include the normalized event and source/type/index metadata, protected by CRC. |
| Durable alerts | 100,000 alerts / 1 GiB | The alert journal is bounded; capacity errors are returned instead of silently dropping alerts. |

`/api/v1/metrics` exposes queue depth/capacity, accepted and rejected counts, parse errors, backpressure events, average end-to-end accepted-event latency, lifetime-average EPS, and whether WAL recovery is required. EPS is not a rolling rate. CyberQL query responses include the Tantivy candidate count, candidates actually scanned, and `results_truncated`; the UI warns when a cap is reached.

Current automated acceptance checks verify bounded-queue rejection, event-size rejection, no successful acknowledgement after a failed index flush, a complete small-result query, torn-WAL recovery, replay of an unacknowledged event through the bounded queue, index idempotency, and alert/status recovery after restart. The local durable-ingest p95 target is **<250 ms** for the test workload; this is a regression guard, not a throughput certification. Before deployment, run a representative sustained-load benchmark with the intended event sizes, storage, and hardware.

**Recovery behavior:** startup replays CRC-validated, versioned WAL records through the bounded ingest queue before the server starts accepting traffic. Acknowledged records are cleared after sink commit; records left by a crash are replayed and then cleared only after all replayed events are committed. The stable event ID makes index replay an upsert, and alert persistence deduplicates the same rule/event trigger. A recovery error fails startup and leaves the WAL in place for investigation/retry.

Alerts and status changes are stored under `<node.data_dir>/alerts/alerts.journal`; journal updates are synced before success is returned and compacted within the configured hard limit. WAL format v2 requires source/type/index metadata. Existing v1 WAL files lack the information required for safe replay, so the server refuses them rather than guessing; preserve/export those files before upgrading.
