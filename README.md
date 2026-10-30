# 🛡️ CyberGlass

**Next-Generation SIEM & Data Fusion Platform**

> CyberGlass Ontology Intelligence × Search Ingestion Power — built on Rust, gRPC, and cyberglass-first principles.

[![Language: Rust](https://img.shields.io/badge/Language-Rust%20Zero--GC-orange.svg)](https://www.rust-lang.org/)
[![Target: CyberGlass](https://img.shields.io/badge/Air--Gap-100%25%20Offline-green.svg)]()
[![Protocol: gRPC + REST + WebSocket](https://img.shields.io/badge/Protocol-gRPC%20%2B%20REST%20%2B%20WS-blue.svg)]()
[![OS: Linux / macOS / Windows](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-purple.svg)]()

---

## 📖 Comprehensive Documentation

| Document | Topic |
|---|---|
| 📚 **[Documentation Portal](docs/README.md)** | Overview, index-to-alert slice, measured limits, and recovery boundary |
| 🏛️ **[System Architecture](docs/architecture.md)** | Zero-GC memory model, tiered storage, and Arrow columnstore |
| 🔍 **[CyberQL Reference](docs/cyberql-reference.md)** | Pipe-based query syntax, aggregations, and pipeline transforms |
| 🚨 **[Detection & Correlation](docs/detection-engine.md)** | Sliding-window threshold correlation, Sigma YAML converter, MITRE ATT&CK |
| 🕸️ **[Ontology & Knowledge Graph](docs/ontology-fusion.md)** | Ontology entity fusion, relationship discovery, and risk decay |
| 🔌 **[API & gRPC Reference](docs/api-and-grpc.md)** | gRPC services (Port 9400), REST Gateway (Port 9401), WebSocket (Port 9401) |
| 🤖 **[AI & Agent Protocol (CGAP)](docs/ai-and-cgap.md)** | Local GGUF models, OpenRouter fallback, and automated triage |
| 🚀 **[Deployment Guide](docs/deployment-and-cyberglass.md)** | Linux systemd, macOS launchd, Windows, OCI containers, offline installation |
| 🪟 **[Windows Installation Guide](docs/windows-installation-guide.md)** | Windows Server & 10/11 installation, service setup, and firewall |

---

## Architecture Highlights

- **Rust-native** — No JVM runtime; ingestion is bounded by an admission queue, worker batch, and per-event size limit.
- **gRPC & REST Gateway** — Binary streaming over gRPC (HTTP/2 with Protobuf) paired with JSON REST endpoints and WebSocket for real-time event streaming.
- **Open and self-hosted** — Apache-2.0 licensed, with embedded MITRE ATT&CK intelligence and local GGUF AI inference.
- **Dynamic Knowledge Graph** — Extracts hosts, users, IPs, domains, hashes, and processes into a real-time graph with risk decay.
- **CyberQL Analytics Engine** — CyberQL-compatible pipeline with `stats`, `eval`, `where`, `sort`, `dedup`, and `table`.
- **Built-in Network Listeners** — Ingests Syslog directly over UDP and TCP (Port 514 / 1514) without requiring third-party forwarders.
- **Write-Ahead Log (WAL)** — Bounded, versioned crash recovery for unacknowledged events; durable acknowledgements follow sink commit.
- **Backpressure & Circuit Breakers** — Per-source rate limiting and circuit breaker patterns protect against traffic spikes.

---

## Quick Start & Cross-Platform Installation

CyberGlass runs in **100% self-hosted, cyberglass dark environments** on **Linux**, **macOS**, and **Windows**.

### Linux & macOS (Offline POSIX Installer)
```bash
# Extract the offline archive:
tar -xzf cyberglass-v0.2.0-linux-x86_64.tar.gz  # or darwin-arm64
cd cyberglass-v0.2.0-*

# Install with system service (root):
sudo ./install.sh

# Or install in user mode (no sudo required):
./install.sh --user
```

RPM-based Linux systems can use `sudo rpm -Uvh cyberglass-v0.2.0-linux-x86_64.rpm`
and then `sudo systemctl enable --now cyberglass`.

### Windows (Offline Batch / PowerShell Installer)
```cmd
:: 1. Quick install via batch script (avoids PowerShell ExecutionPolicy restrictions):
.\install.bat

:: 2. Launch CyberGlass and automatically open the Web UI:
.\start.bat
```
The interactive CyberGlass Web UI will open in your default browser at `http://localhost:9401/`.
Sign in as `admin` on a fresh install (unless `CYBERGLASS_ADMIN_USERNAME` is set).
The password is `CYBERGLASS_ADMIN_PASSWORD` when configured; otherwise read it
from `<node.data_dir>\initial-admin-password`. See the
[Windows first-login guide](docs/windows-installation-guide.md#first-login) for
the Windows default path and troubleshooting.

See the complete [Windows Installation Guide](docs/windows-installation-guide.md) for installation, service management, and firewall rules.

### Docker / OCI Containers (CyberGlass)
```bash
docker load -i cyberglass-cyberglass-v0.1.0.tar
docker compose up -d
```

---

## 🌐 Web UI Features

The CyberGlass Web UI is a single-page application served at `http://localhost:9401/`:

| Tab | Description |
|---|---|
| **🔍 CyberQL Search** | Query the Tantivy inverted index with pipe-based CyberQL. Live event histogram, export to CSV/JSON. |
| **🕸️ Ontology Graph** | Interactive knowledge graph with physics-based layout, drag-to-rearrange, zoom, and entity risk visualization. |
| **🚨 Alerts & Sigma** | Real-time sliding-window correlation alerts with MITRE ATT&CK tagging, status workflow, and rule management. |
| **📥 Log Ingestion Lab** | Ingest raw logs via JSON, KV, Syslog, or CEF parsers. Built-in sample data and batch burst testing. |
| **🤖 AI Threat Hunter** | CyberGlass AI assistant for constructing CyberQL pipelines, analyzing IOCs, and explaining MITRE ATT&CK techniques. |
| **📊 Cluster & Metrics** | System telemetry, indexed event counts, tiered storage architecture, and health monitoring. |

**Animations**: Fade-in transitions, slide-in panels, pulse indicators, shimmer skeletons, interactive graph physics, and toast notifications.

**Keyboard Shortcuts**:
- `Ctrl/Cmd + K` — Focus search box
- `/` — Focus search box
- `Escape` — Close modals

---

## 🔌 API Reference

### REST Endpoints (Port 9401)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/info` | Platform information |
| GET | `/api/v1/health` | Enhanced per-component health status |
| GET | `/api/v1/metrics` | Cluster metrics including ingestion stats |
| GET | `/api/v1/indices` | List all indices with details |
| GET | `/api/v1/events?page=1&page_size=50&index=main` | Paginated event listing |
| POST | `/api/v1/ingest` | Ingest a single event |
| POST | `/api/v1/ingest/batch` | Ingest a batch of events |
| POST | `/api/v1/query` | Execute a CyberQL query |
| GET | `/api/v1/alerts` | List security alerts |
| POST | `/api/v1/alerts/status` | Update alert status |
| GET | `/api/v1/rules` | List detection rules |
| POST | `/api/v1/rules` | Create a detection rule |
| GET | `/api/v1/entities` | Search ontology entities |
| GET | `/api/v1/graph` | Get knowledge graph data |
| POST | `/api/v1/ai/chat` | AI threat hunting chat |
| GET | `/api/v1/ws` | WebSocket for real-time event streaming |

### gRPC Services (Port 9400)

| Service | Description |
|---|---|
| `IngestService` | Batch and stream ingestion |
| `QueryService` | CyberQL query execution |
| `DetectionService` | Rule and alert management |
| `OntologyService` | Knowledge graph operations |
| `AiService` | AI chat and CGAP protocol |
| `AdminService` | Administrative operations |

---

## Workspace Crates

```
crates/
├── cg-core        # Core types, configuration discovery, traits, health checks
├── cg-proto       # Protobuf definitions and generated gRPC service definitions
├── cg-crypto      # Cryptographic primitives (Ed25519, SHA-256, hash chaining, TLS)
├── cg-bus         # High-speed event bus (NATS JetStream & in-memory) with pub/sub
├── cg-collector   # Edge collector forwarder agents
├── cg-ingest      # Ingestion pipeline: WAL, rate limiting, circuit breakers, async batch processing
├── cg-index       # Tantivy full-text search & Arrow columnar store
├── cg-query       # CyberQL parser, optimizer, and execution engine
├── cg-ontology    # Knowledge graph, entity extractor, relationship discovery, risk scoring
├── cg-detect      # Real-time detection engine, sliding-window correlation, Sigma YAML converter, MITRE ATT&CK
├── cg-ai          # CyberGlass AI engine (local GGUF, OpenRouter, CGAP protocol)
├── cg-soar        # Playbook orchestration engine (Phase 5)
├── cg-gateway     # API Gateway: gRPC (9400) + REST (9401) + WebSocket (9401)
├── cg-storage     # Tiered storage lifecycle (Hot/Warm/Cold/Frozen) with Zstd/LZ4 Parquet
├── cg-plugin-sdk  # Sandboxed WASM plugin manifest SDK (Phase 6)
└── cg-server      # Main server daemon binary with multi-OS config auto-discovery
```

---

## Validation

Run the current workspace tests with `cargo test --workspace`. The ingest-to-alert slice, default resource limits, query completeness signal, latency regression target, and recovery behavior are documented in the [documentation portal](docs/README.md).

---

## License

CyberGlass is licensed under the [Apache License, Version 2.0](LICENSE).