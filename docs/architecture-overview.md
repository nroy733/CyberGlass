# CyberGlass Architecture Overview

## Current data path

CyberGlass processes security events through a single service:

1. **Ingest:** HTTP, HEC, syslog, and file-monitor receivers submit events to the bounded ingest pipeline.
2. **Normalize:** Events are parsed into the shared event model before indexing and detection.
3. **Index:** External events are stored in named Tantivy indexes. Runtime, audit, and introspection records use the separate `cg_internal`, `cg_audit`, and `cg_introspection` indexes.
4. **Query:** CyberQL queries external indexes. Internal-index queries currently support equality filters and an optional `| head N` stage, capped at 1,000 results.
5. **Detect and alert:** Detection rules process ingested events and persist generated alerts.

## Internal telemetry

The server periodically records host resources, ingest-pipeline counters, and index storage inventory. API request and query activity is recorded when requests occurred during the sampling interval. Samples are persisted so dashboards can read them after a process restart.

Built-in dashboard values are derived from these persisted samples. A missing sample is shown as unavailable rather than replaced with a demonstration value. The dashboard query text selects the same internal index and source used by its data endpoint.

Custom dashboard definitions are persisted by the backend to
`<data_dir>/custom_dashboards.json`. Creating, editing, or deleting a custom
dashboard updates this file; startup loads it alongside the built-in dashboards.
The file contains custom dashboards only, so built-in definitions remain
managed by the application.

## Operational boundaries

- Internal query execution currently reads at most the newest 1,000 records before applying filters. Query responses report the number scanned and whether that scan may be incomplete.
- Daily byte-volume licensing metrics are not currently collected and are not represented as measured values.
- A dashboard widget's configured custom query is not executed by the widget endpoint; custom-query widgets must not be interpreted as live query results.
- Internal telemetry retention and historical query indexing should be implemented before treating this storage as unbounded.

## Engineering priorities

1. Add explicit retention and size limits for persisted internal telemetry.
2. Index internal fields needed for selective queries and report exact scan completeness.
3. Add end-to-end recovery tests for telemetry, dashboards, and alert state.
4. Keep dashboard metrics tied to measured sources, with explicit no-data and error states.
