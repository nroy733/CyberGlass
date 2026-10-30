# 📖 CyberQL Command Reference & Syntax Guide

**CyberQL** is the query and analytics language powering the **CyberGlass SIEM**. Built in Rust with Tantivy indexing and sub-millisecond pipeline execution, CyberQL combines familiar pipe (`|`) semantics with zero-GC memory safety and native vector/ontology acceleration.

---

## 📑 Table of Contents
1. [Pipeline Anatomy & Execution](#1-pipeline-anatomy--execution)
2. [Root Search Directives](#2-root-search-directives)
3. [Pipeline Commands Reference](#3-pipeline-commands-reference)
   - [`stats`](#stats)
   - [`where`](#where)
   - [`sort`](#sort)
   - [`dedup`](#dedup)
   - [`rename`](#rename)
   - [`eval`](#eval)
   - [`head`](#head)
   - [`tail`](#tail)
   - [`table`](#table)
   - [`fields`](#fields)
   - [`top`](#top)
   - [`rare`](#rare)
   - [`timechart`](#timechart)
   - [`chart`](#chart)
   - [`rex`](#rex)
   - [`lookup`](#lookup)
   - [`fillnull`](#fillnull)
   - [`replace`](#replace)
4. [Internal Indexes](#4-internal-indexes)
5. [SOC Threat Hunting Cookbook](#5-soc-threat-hunting-cookbook)

---

## 1. Pipeline Anatomy & Execution

A CyberQL query flows from left to right through pipeline stages separated by the vertical pipe character (`|`).

```text
[Root Search & Directives] | [Stage 1] | [Stage 2] | ... | [Output Projection]
```

### Example
```text
index=main source="firewall" action=blocked
| where severity >= 3
| stats count, sum(bytes) as total_bytes by src_ip, dest_ip
| sort -count
| head 25
| table src_ip, dest_ip, count, total_bytes
```

1. **Initial Search Clause**: Evaluated directly against the Tantivy inverted index using boolean queries and fast columnar postings.
2. **Pipeline Transforms**: Processed in-memory using streaming vector batches with SIMD optimizations.

---

## 2. Root Search Directives

Directives are specified before the first pipe (`|`) to select indexes, sources, and initial filter boundaries.

| Directive | Description | Example |
|---|---|---|
| `index=<name>` | Selects the target storage index | `index=main`, `index=cg_internal` |
| `source="<path/type>"` | Filters events by origin or stream | `source="syslog"`, `source="/var/log/secure"` |
| `sourcetype="<type>"` | Filters by event format specification | `sourcetype="access_combined"`, `sourcetype="json"` |
| `host="<fqdn/ip>"` | Matches host or machine identifier | `host="dc01.corp.internal"`, `host="192.168.*"` |
| `<field>=<value>` | Direct equality on indexed fields | `action=blocked`, `status=500` |
| `<field>!="<value>"` | Direct inequality filter | `status!=200` |
| `"<phrase>"` | Exact phrase search | `"authentication failed"` |
| `*` (Wildcards) | Prefix or suffix pattern matching | `src_ip="10.200.*"` |
| `AND`, `OR`, `NOT` | Boolean search composition | `(action=failed OR action=blocked) NOT user=test` |

---

## 3. Pipeline Commands Reference

### `stats`
Calculates summary statistics and aggregations across events, optionally partitioned by grouping fields.

**Syntax**:
```text
| stats <agg_function>(<field>) [as <alias>], ... [by <group_field1>, <group_field2>, ...]
```

**Supported Aggregation Functions**:
| Function | Description | Example |
|---|---|---|
| `count` | Total count of events in each group | `stats count by src_ip` |
| `sum(<field>)` | Arithmetic sum of numeric values | `stats sum(bytes) as total_bandwidth` |
| `avg(<field>)` | Arithmetic mean of numeric values | `stats avg(response_ms) as latency` |
| `min(<field>)` | Minimum observed numeric value | `stats min(severity)` |
| `max(<field>)` | Maximum observed numeric value | `stats max(bytes_out) as peak_egress` |
| `dc(<field>)` | Distinct count (cardinality) of unique values | `stats dc(src_ip) as unique_attackers` |
| `values(<field>)` | Deduplicated list of distinct values | `stats values(action) by host` |
| `earliest(<field>)` | Earliest chronological value in group | `stats earliest(_time) as first_seen` |
| `latest(<field>)` | Latest chronological value in group | `stats latest(status) as last_state` |

**Example**:
```text
source="auth" action="failure"
| stats count as attempts, dc(user) as targeted_users by src_ip
| where attempts > 10
| sort -attempts
```

---

### `where`
Filters the event stream using relational expressions, arithmetic comparisons, and boolean logic.

**Syntax**:
```text
| where <expression>
```

**Operators**:
- Equality: `=`, `==`
- Inequality: `!=`
- Comparison: `>`, `>=`, `<`, `<=`
- Logical: `AND`, `OR`, `NOT`

**Example**:
```text
source="firewall"
| where bytes_out > 1000000 AND action = "blocked"
```

---

### `sort`
Orders results by one or more fields. Prepend `-` for descending (highest to lowest) or `+` / no prefix for ascending.

**Syntax**:
```text
| sort [-]<field1>, [+/-]<field2>, ...
```

**Example**:
```text
index=cg_internal
| stats count by sourcetype
| sort -count
```

---

### `dedup`
Removes duplicate consecutive or subsequent events that share matching values for the specified fields.

**Syntax**:
```text
| dedup <field1>, <field2>, ...
```

**Example**:
```text
source="ids_alerts"
| dedup src_ip, signature_id
```

---

### `rename`
Renames one or more columns in the output stream for clearer visualization and reporting.

**Syntax**:
```text
| rename <old_field> as <new_field>, ...
```

**Example**:
```text
source="windows_security"
| rename TargetUserName as username, IpAddress as client_ip
```

---

### `eval`
Computes new fields or transforms existing fields using runtime expressions and functions.

**Syntax**:
```text
| eval <target_field> = <expression>
```

**Common Functions**:
- `upper(<field>)` - Converts string to uppercase.
- `lower(<field>)` - Converts string to lowercase.
- `len(<field>)` - Returns string character length.
- Arithmetic: `+`, `-`, `*`, `/`.

**Example**:
```text
source="network"
| eval total_mb = (bytes_in + bytes_out) / 1048576
| eval host_canonical = upper(hostname)
```

---

### `head`
Restricts output to the first $N$ events from the stream.

**Syntax**:
```text
| head <N>
```

**Example**:
```text
index=main | head 50
```

---

### `tail`
Restricts output to the last $N$ events from the stream.

**Syntax**:
```text
| tail <N>
```

**Example**:
```text
source="kernel" | tail 20
```

---

### `table`
Projects only the specified fields as tabular columns, discarding all other fields.

**Syntax**:
```text
| table <field1>, <field2>, ...
```

**Example**:
```text
source="windows_event"
| table _time, host, EventCode, TargetUserName, IpAddress
```

---

### `fields`
Selectively retains (`+`) or strips out (`-`) specified fields from the record stream.

**Syntax**:
```text
| fields [+|-] <field1>, <field2>, ...
```

**Example**:
```text
source="raw_json"
| fields - _raw, temp_cache
```

---

### `top`
Displays the most frequent values for the specified fields along with count and percentage distribution.

**Syntax**:
```text
| top [limit=<N>] <field1> [by <field2>]
```

**Example**:
```text
source="firewall" action=blocked
| top limit=10 src_ip
```

---

### `rare`
Displays the least frequent (anomalous) values for the specified fields.

**Syntax**:
```text
| rare [limit=<N>] <field1> [by <field2>]
```

**Example**:
```text
source="auth" action=success
| rare limit=5 user by host
```

---

### `timechart`
Creates a time-series aggregation bucketed by a specified time interval (e.g. `1m`, `5m`, `1h`, `1d`).

**Syntax**:
```text
| timechart [span=<interval>] <agg_function>(<field>) [by <split_field>]
```

**Example**:
```text
source="web"
| timechart span=5m count by status
```

---

### `chart`
Creates a two-dimensional matrix or pivot table over one field grouped by another.

**Syntax**:
```text
| chart <agg_function>(<field>) over <row_field> by <col_field>
```

**Example**:
```text
source="firewall"
| chart count over src_ip by action
```

---

### `rex`
Extracts custom fields from raw text (`_raw`) using regular expressions with named capture groups.

**Syntax**:
```text
| rex [field=<field>] "(?<capture_name><regex_pattern>)"
```

**Example**:
```text
source="syslog"
| rex field=_raw "user=(?<extracted_user>[^ ]+) from (?<client_ip>\d+\.\d+\.\d+\.\d+)"
```

---

### `lookup`
Enriches streaming events with static or threat intelligence lookup tables (e.g. GeoIP, threat intel, asset lists).

**Syntax**:
```text
| lookup <lookup_table> <input_field> [as <alias>] OUTPUT <output_fields>
```

**Example**:
```text
source="firewall"
| lookup threat_intel_ip ip as src_ip OUTPUT reputation, malicious_score
```

---

### `fillnull`
Substitutes missing or null values in specified fields with a default string or numeric fallback.

**Syntax**:
```text
| fillnull [value="<default>"] <field1>, ...
```

**Example**:
```text
source="main"
| fillnull value="N/A" user, dest_port
```

---

### `replace`
Performs literal string replacement within specified target fields.

**Syntax**:
```text
| replace "<search>" with "<replacement>" in <field>
```

**Example**:
```text
source="web"
| replace "404" with "Not Found", "500" with "Server Error" in status
```

---

## 4. Internal Indexes

CyberGlass provides built-in internal telemetry and audit indexes.
Internal-index queries support equality filters and an optional `| head N`
limit. Aggregation pipelines are not currently evaluated against these indexes.

| Internal Index | Purpose | Typical Query |
|---|---|---|
| `cg_internal` | Server startup, shutdown, and runtime logs | `index=cg_internal source=cyberglass.server \| head 50` |
| `cg_audit` | RBAC user actions, logins, rule changes, query audits | `index=cg_audit event_type=login \| head 50` |
| `cg_introspection` | Host resources, ingestion, API activity, index storage | `index=cg_introspection source=introspection.resources \| head 50` |

---

## 5. SOC Threat Hunting Cookbook

### 🛡️ Brute Force Authentication Detection
```text
source="auth" action="failure"
| stats count as failure_count, dc(user) as unique_users by src_ip
| where failure_count >= 10
| sort -failure_count
```

### 🚫 Blocked Port Scanning
```text
source="firewall" action="blocked"
| stats dc(dest_port) as scanned_ports, count as hit_count by src_ip
| where scanned_ports > 20
| sort -scanned_ports
```

### 📊 Top Bandwidth Consumers (Data Egress)
```text
source="network"
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| eval egress_mb = total_bytes / 1048576
| where egress_mb > 500
| sort -egress_mb
```

### ⚙️ CyberGlass Internal Health Audit
```text
index=cg_internal severity=ERROR | head 100
```
