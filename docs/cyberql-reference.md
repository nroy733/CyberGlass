# 🔍 CyberQL Query Language Reference

**CyberQL** is CyberGlass's query and analytics language. It is designed to be immediately familiar to security analysts and SOC operators, providing pipeline (`|`) syntax, familiar commands, and sub-millisecond execution.

---

## 1. Syntax Overview

A CyberQL query consists of:
1. **Initial Search Clause** (before the first pipe): Specifies the index, source, sourcetype, and keyword / field filters.
2. **Pipeline Transforms** (separated by `|`): Modifies, filters, aggregates, or re-shapes the result stream.

```text
source="firewall" action=blocked src_ip="10.*"
| where severity >= 3
| stats count, sum(bytes) as total_bytes by src_ip, dest_ip
| sort -count
| head 50
```

---

## 2. Command Reference

### `stats`
Performs aggregations, optionally grouped by one or more fields.

**Syntax**:
```text
| stats <agg_function>(<field>) [as <alias>], ... [by <group_field1>, <group_field2>, ...]
```

**Supported Aggregation Functions**:
| Function | Description | Example |
|---|---|---|
| `count` | Counts events in group | `stats count by src_ip` |
| `sum(<field>)` | Calculates numeric sum | `stats sum(bytes) as total_bytes` |
| `avg(<field>)` | Calculates arithmetic mean | `stats avg(latency) as avg_lat` |
| `min(<field>)` | Returns minimum value | `stats min(response_time)` |
| `max(<field>)` | Returns maximum value | `stats max(severity)` |
| `dc(<field>)` | Distinct count of values | `stats dc(user) as unique_users` |
| `values(<field>)` | Collects list of distinct values | `stats values(action) by host` |
| `latest(<field>)` | Chronologically latest value | `stats latest(status) by host` |
| `earliest(<field>)`| Chronologically earliest value | `stats earliest(timestamp) by host` |

---

### `where`
Filters rows using boolean expressions and numeric/string comparisons.

**Syntax**:
```text
| where <field> <op> <value>
```

**Supported Operators**:
- `=` or `==` : Equality
- `!=` : Inequality
- `>` : Greater than
- `>=` : Greater than or equal to
- `<` : Less than
- `<=` : Less than or equal to

**Examples**:
```text
| where severity >= 4
| where action != "allow"
| where count > 100
```

---

### `sort`
Sorts rows by one or more fields. Use `-` prefix for descending order, or `+` / no prefix for ascending order.

**Syntax**:
```text
| sort [-]<field1>, [+/-]<field2>, ...
```

**Examples**:
```text
| sort -count
| sort -severity, +host
```

---

### `dedup`
Removes subsequent duplicate rows sharing the same value across specified fields.

**Syntax**:
```text
| dedup <field1>, <field2>, ...
```

**Example**:
```text
| dedup src_ip, dest_ip
```

---

### `rename`
Renames columns in the output stream.

**Syntax**:
```text
| rename <old_field> as <new_field>, ...
```

**Example**:
```text
| rename src_ip as client_ip, dest_ip as target_ip
```

---

### `eval`
Computes new field values or applies transformations.

**Syntax**:
```text
| eval <target_field> = <expression>
```

**Supported Functions**:
- `upper(field)` : Converts string to uppercase
- `lower(field)` : Converts string to lowercase
- Literal assignment : `eval category = "external"`

**Example**:
```text
| eval host_upper = upper(hostname)
```

---

### `head` & `tail`
Limits the result set to the first or last $N$ rows.

**Syntax**:
```text
| head 100
| tail 20
```

---

### `table` & `fields`
Selects and retains only the specified fields, projecting out unwanted columns.

**Syntax**:
```text
| table _time, host, user, action, src_ip
| fields - _raw
```

## Internal Telemetry Queries

The internal indexes are `cg_internal`, `cg_audit`, and `cg_introspection`.
Internal queries currently support field equality filters and an
optional `| head N` stage (maximum 1,000 results); they do not support pipeline
aggregations or projections.

```text
index=cg_introspection source=introspection.resources | head 50
```

Internal query responses include the number of records scanned and a
`complete` flag. A scan that reaches the 1,000-record cap may be incomplete.
