//! # cg-proto
//!
//! Generated protobuf and gRPC service definitions for the CyberGlass platform.

#![allow(clippy::all)]
#![allow(clippy::result_large_err)]
#![allow(unknown_lints)]
//!
//! This crate compiles all `.proto` files from the `proto/` directory at the workspace
//! root and re-exports them as typed Rust modules. Each module corresponds to a
//! protobuf `package` namespace (e.g. `cyberglass.common` → [`common`]).
//!
//! ## Modules
//!
//! | Module        | Proto package             | Contents                            |
//! |---------------|---------------------------|-------------------------------------|
//! | [`common`]    | `cyberglass.common`       | Event, Severity, Health, Pagination |
//! | [`ingest`]    | `cyberglass.ingest`       | IngestService, batching             |
//! | [`query`]     | `cyberglass.query`        | QueryService, CyberQL dialects      |
//! | [`detection`] | `cyberglass.detection`    | DetectionService, rules, alerts     |
//! | [`ontology`]  | `cyberglass.ontology`     | OntologyService, knowledge graph    |
//! | [`ai`]        | `cyberglass.ai`           | AIService, CGAPService, tools       |
//! | [`admin`]     | `cyberglass.admin`        | AdminService and cluster management |

/// Common types shared across all CyberGlass services.
///
/// Contains the universal [`Event`](common::Event) envelope,
/// [`Severity`](common::Severity) levels, health-check types,
/// pagination helpers, and time-range definitions.
pub mod common {
    tonic::include_proto!("cyberglass.common");
}

/// High-throughput event ingestion service.
///
/// Provides both unary batch ingestion and bidirectional streaming
/// for continuous event intake from collectors.
pub mod ingest {
    tonic::include_proto!("cyberglass.ingest");
}

/// Unified search and analytics query service.
///
/// Supports query requests, streaming results, query plans, and
/// natural-language-to-query translation.
pub mod query {
    tonic::include_proto!("cyberglass.query");
}

/// Detection engine — rule management and alert generation.
///
/// Manages detection rules (simple, threshold, correlation, anomaly, chain),
/// Sigma rule import, backtesting, and real-time alert streaming.
pub mod detection {
    tonic::include_proto!("cyberglass.detection");
}

/// Knowledge-graph / entity management (ontology) service.
///
/// Tracks entities (hosts, users, IPs, domains, …), relationships,
/// graph traversal, entity timelines, and risk scoring.
pub mod ontology {
    tonic::include_proto!("cyberglass.ontology");
}

/// AI engine and CyberGlass Agent Protocol (CGAP) services.
///
/// Local & federated model inference for chat, query generation,
/// alert triage, incident summarisation, and threat-hunt suggestions.
/// CGAP provides tool registration, execution, and agent-to-agent
/// communication channels.
pub mod ai {
    tonic::include_proto!("cyberglass.ai");
}

/// Administration service — cluster, licensing, configuration, and metrics.
///
/// Manages cluster status, node enumeration,
/// runtime configuration updates, index lifecycle, and metric collection.
pub mod admin {
    tonic::include_proto!("cyberglass.admin");
}

/// Compiled file-descriptor set for gRPC server reflection.
///
/// Feed this into `tonic_reflection::server::Builder` so clients like
/// `grpcurl` can discover available services at runtime.
pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("cyberglass_descriptor");
