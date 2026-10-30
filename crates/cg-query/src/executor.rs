use crate::ast::*;
use crate::error::{QueryError, Result};
use cg_index::IndexManager;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResults {
    pub rows: Vec<HashMap<String, JsonValue>>,
    pub stats: QueryStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryStats {
    pub execution_time_ms: u64,
    pub events_scanned: u64,
    pub candidate_count: usize,
    pub results_returned: usize,
    pub results_truncated: bool,
}

pub struct QueryExecutor {
    index_manager: Arc<IndexManager>,
}

impl QueryExecutor {
    pub fn new(index_manager: Arc<IndexManager>) -> Self {
        Self { index_manager }
    }

    pub async fn execute(&self, query: &Query) -> Result<QueryResults> {
        let start = Instant::now();
        let index_name = query
            .source
            .as_ref()
            .map(|s| s.index_name.as_str())
            .unwrap_or("main");

        let handle = self
            .index_manager
            .get_or_create_index(index_name)
            .map_err(|e| QueryError::IndexNotFound(e.to_string()))?;

        // 1. Build the Tantivy pre-filter. String equality and the time range
        // are pushed down; numeric comparisons are evaluated in memory because
        // event fields are stored as strings.
        let mut query_terms = Vec::new();
        for filter in &query.filters {
            if let Filter::Comparison {
                field,
                op: ComparisonOp::Eq,
                value: Value::String(s),
            } = filter
            {
                let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
                query_terms.push(format!("{}:\"{}\"", tantivy_field(field), escaped));
            }
        }

        if let Some(range) = &query.time_range {
            query_terms.push(format!(
                "_time:[{} TO {}]",
                range.start.to_rfc3339(),
                range.end.to_rfc3339()
            ));
        }

        let tantivy_query = if query_terms.is_empty() {
            "*".to_string()
        } else {
            query_terms.join(" AND ")
        };

        tracing::info!(
            "CyberQL executing pre-filter '{}' on index '{}'",
            tantivy_query,
            index_name
        );

        let max_results = query.limit.unwrap_or(1000).max(1);
        // Filters are re-applied in memory for exact semantics; scan a larger
        // window so selective predicates do not return an empty first page.
        let scan_limit = if query.filters.is_empty() {
            max_results
        } else {
            (max_results.saturating_mul(20)).clamp(1_000, 100_000)
        };

        let (search_results, candidate_count) = handle
            .reader
            .search_with_total(&tantivy_query, scan_limit)
            .map_err(|e| QueryError::ExecutionError(e.to_string()))?;

        tracing::info!(
            "Tantivy pre-filter matched {} documents (scan limit {})",
            search_results.len(),
            scan_limit
        );

        let events_scanned = search_results.len() as u64;
        let mut results_truncated = candidate_count > search_results.len();

        // 2. Convert search results to dynamic row maps
        let mut rows: Vec<HashMap<String, JsonValue>> = search_results
            .into_iter()
            .map(|sr| {
                let mut map = HashMap::new();
                map.insert("_id".to_string(), JsonValue::String(sr.id));
                map.insert("_raw".to_string(), JsonValue::String(sr.raw));
                map.insert("source".to_string(), JsonValue::String(sr.source));
                map.insert("source_type".to_string(), JsonValue::String(sr.source_type));
                map.insert("index".to_string(), JsonValue::String(sr.index_name));
                map.insert(
                    "severity".to_string(),
                    JsonValue::Number(sr.severity.into()),
                );
                map.insert(
                    "_time".to_string(),
                    JsonValue::String(sr.timestamp.to_rfc3339()),
                );

                for (k, v) in sr.fields {
                    map.insert(k, JsonValue::String(v));
                }

                map
            })
            .collect();

        // 3. Exact filtering (numeric ranges, LIKE, regex, time bounds, ...)
        rows.retain(|row| {
            if let Some(range) = &query.time_range {
                let within = row
                    .get("_time")
                    .and_then(|value| value.as_str())
                    .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                    .map(|timestamp| {
                        let timestamp = timestamp.with_timezone(&chrono::Utc);
                        timestamp >= range.start && timestamp < range.end
                    })
                    .unwrap_or(false);
                if !within {
                    return false;
                }
            }
            query
                .filters
                .iter()
                .all(|filter| evaluate_filter(row, filter))
        });

        // 4. Apply in-memory pipeline transforms
        let mut explicit_sort = false;
        for transform in &query.transforms {
            match transform {
                Transform::Head(n) => {
                    rows.truncate(*n);
                }
                Transform::Tail(n) => {
                    if rows.len() > *n {
                        rows = rows.split_off(rows.len() - *n);
                    }
                }
                Transform::Fields(fields) => {
                    for row in &mut rows {
                        row.retain(|k, _| fields.contains(k));
                    }
                }
                Transform::Table(fields) => {
                    for row in &mut rows {
                        row.retain(|k, _| fields.contains(k));
                    }
                }
                Transform::Dedup(fields) => {
                    rows = execute_dedup(rows, fields);
                }
                Transform::Rename(pairs) => {
                    execute_rename(&mut rows, pairs);
                }
                Transform::Eval { field, expression } => {
                    execute_eval(&mut rows, field, expression);
                }
                Transform::Where(filter) => {
                    rows.retain(|row| evaluate_filter(row, filter));
                }
                Transform::Stats(stats) => {
                    rows = execute_stats(rows, stats);
                }
                Transform::Sort(sort) => {
                    explicit_sort = true;
                    rows.sort_by(|a, b| {
                        for sf in &sort.fields {
                            let val_a = a.get(&sf.name);
                            let val_b = b.get(&sf.name);
                            let cmp = compare_json_values(val_a, val_b);
                            if cmp != std::cmp::Ordering::Equal {
                                return if sf.ascending { cmp } else { cmp.reverse() };
                            }
                        }
                        std::cmp::Ordering::Equal
                    });
                }
            }
        }

        // Newest first unless the query requested an explicit ordering.
        if !explicit_sort && !matches!(query.transforms.last(), Some(Transform::Stats(_))) {
            rows.sort_by(|a, b| {
                let time_a = a.get("_time").and_then(|v| v.as_str()).unwrap_or("");
                let time_b = b.get("_time").and_then(|v| v.as_str()).unwrap_or("");
                time_b.cmp(time_a)
            });
        }

        results_truncated |= rows.len() > max_results;
        rows.truncate(max_results);

        let results_returned = rows.len();
        let execution_time_ms = start.elapsed().as_millis() as u64;

        Ok(QueryResults {
            rows,
            stats: QueryStats {
                execution_time_ms,
                events_scanned,
                candidate_count,
                results_returned,
                results_truncated,
            },
        })
    }
}

/// Map a CyberQL field name onto its Tantivy field.
fn tantivy_field(field: &str) -> String {
    match field {
        "_id" | "_time" | "_raw" | "source" | "source_type" | "severity" => field.to_string(),
        "index" => "index_name".to_string(),
        other => format!("fields.{}", other),
    }
}

// ---------------------------------------------------------------------------
// Pipeline Helper Functions
// ---------------------------------------------------------------------------

fn compare_json_values(a: Option<&JsonValue>, b: Option<&JsonValue>) -> std::cmp::Ordering {
    match (a, b) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(va), Some(vb)) => {
            // Try numeric comparison
            if let (Some(na), Some(nb)) = (va.as_f64(), vb.as_f64()) {
                na.partial_cmp(&nb).unwrap_or(std::cmp::Ordering::Equal)
            } else if let (Some(sa), Some(sb)) = (va.as_str(), vb.as_str()) {
                sa.cmp(sb)
            } else {
                va.to_string().cmp(&vb.to_string())
            }
        }
    }
}

fn json_to_str(val: &JsonValue) -> String {
    match val {
        JsonValue::String(s) => s.clone(),
        _ => val.to_string(),
    }
}

fn json_to_f64(val: &JsonValue) -> Option<f64> {
    match val {
        JsonValue::Number(n) => n.as_f64(),
        JsonValue::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn execute_dedup(
    rows: Vec<HashMap<String, JsonValue>>,
    fields: &[String],
) -> Vec<HashMap<String, JsonValue>> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();

    for row in rows {
        let key: Vec<String> = fields
            .iter()
            .map(|f| row.get(f).map(json_to_str).unwrap_or_default())
            .collect();

        if seen.insert(key) {
            result.push(row);
        }
    }

    result
}

fn execute_rename(rows: &mut [HashMap<String, JsonValue>], pairs: &[(String, String)]) {
    for row in rows.iter_mut() {
        for (old_key, new_key) in pairs {
            if let Some(val) = row.remove(old_key) {
                row.insert(new_key.clone(), val);
            }
        }
    }
}

fn execute_eval(rows: &mut [HashMap<String, JsonValue>], target_field: &str, expr: &str) {
    let expr_clean = expr.trim();
    for row in rows.iter_mut() {
        let val = if let Some(stripped) = expr_clean.strip_prefix("upper(") {
            let src_field = stripped.trim_end_matches(')').trim();
            let src_val = row.get(src_field).map(json_to_str).unwrap_or_default();
            JsonValue::String(src_val.to_uppercase())
        } else if let Some(stripped) = expr_clean.strip_prefix("lower(") {
            let src_field = stripped.trim_end_matches(')').trim();
            let src_val = row.get(src_field).map(json_to_str).unwrap_or_default();
            JsonValue::String(src_val.to_lowercase())
        } else if let Some(src_val) = row.get(expr_clean) {
            src_val.clone()
        } else if let Ok(i) = expr_clean.parse::<i64>() {
            JsonValue::Number(i.into())
        } else if let Ok(f) = expr_clean.parse::<f64>() {
            serde_json::Number::from_f64(f)
                .map(JsonValue::Number)
                .unwrap_or(JsonValue::String(expr_clean.to_string()))
        } else if let Ok(b) = expr_clean.parse::<bool>() {
            JsonValue::Bool(b)
        } else {
            JsonValue::String(expr_clean.trim_matches('"').trim_matches('\'').to_string())
        };

        row.insert(target_field.to_string(), val);
    }
}

fn evaluate_filter(row: &HashMap<String, JsonValue>, filter: &Filter) -> bool {
    match filter {
        Filter::Comparison { field, op, value } => {
            let field_val = match row.get(field) {
                Some(v) => v,
                None => return false,
            };

            match value {
                Value::Integer(expected_i) => {
                    let actual_f = match json_to_f64(field_val) {
                        Some(f) => f,
                        None => return false,
                    };
                    let exp = *expected_i as f64;
                    match op {
                        ComparisonOp::Eq => (actual_f - exp).abs() < f64::EPSILON,
                        ComparisonOp::Neq => (actual_f - exp).abs() >= f64::EPSILON,
                        ComparisonOp::Gt => actual_f > exp,
                        ComparisonOp::Gte => actual_f >= exp,
                        ComparisonOp::Lt => actual_f < exp,
                        ComparisonOp::Lte => actual_f <= exp,
                    }
                }
                Value::Float(expected_f) => {
                    let actual_f = match json_to_f64(field_val) {
                        Some(f) => f,
                        None => return false,
                    };
                    match op {
                        ComparisonOp::Eq => (actual_f - expected_f).abs() < f64::EPSILON,
                        ComparisonOp::Neq => (actual_f - expected_f).abs() >= f64::EPSILON,
                        ComparisonOp::Gt => actual_f > *expected_f,
                        ComparisonOp::Gte => actual_f >= *expected_f,
                        ComparisonOp::Lt => actual_f < *expected_f,
                        ComparisonOp::Lte => actual_f <= *expected_f,
                    }
                }
                Value::String(expected_s) => {
                    let actual_s = json_to_str(field_val);
                    match op {
                        ComparisonOp::Eq => actual_s.eq_ignore_ascii_case(expected_s),
                        ComparisonOp::Neq => !actual_s.eq_ignore_ascii_case(expected_s),
                        ComparisonOp::Gt => actual_s > *expected_s,
                        ComparisonOp::Gte => actual_s >= *expected_s,
                        ComparisonOp::Lt => actual_s < *expected_s,
                        ComparisonOp::Lte => actual_s <= *expected_s,
                    }
                }
                Value::Boolean(expected_b) => {
                    let actual_b = field_val.as_bool().unwrap_or(false);
                    match op {
                        ComparisonOp::Eq => actual_b == *expected_b,
                        ComparisonOp::Neq => actual_b != *expected_b,
                        _ => false,
                    }
                }
                _ => true,
            }
        }
        Filter::And(left, right) => evaluate_filter(row, left) && evaluate_filter(row, right),
        Filter::Or(left, right) => evaluate_filter(row, left) || evaluate_filter(row, right),
        Filter::Not(sub) => !evaluate_filter(row, sub),
        Filter::Exists(field) => row.contains_key(field),
        Filter::In { field, values } => {
            if let Some(actual) = row.get(field) {
                let actual_s = json_to_str(actual);
                values.iter().any(|v| match v {
                    Value::String(s) => actual_s.eq_ignore_ascii_case(s),
                    Value::Integer(i) => json_to_f64(actual)
                        .map(|f| (f - *i as f64).abs() < f64::EPSILON)
                        .unwrap_or(false),
                    Value::Float(f) => json_to_f64(actual)
                        .map(|a| (a - *f).abs() < f64::EPSILON)
                        .unwrap_or(false),
                    Value::Boolean(b) => actual.as_bool().map(|ab| ab == *b).unwrap_or(false),
                    _ => false,
                })
            } else {
                false
            }
        }
        Filter::Like { field, pattern } => {
            if let Some(actual) = row.get(field) {
                let s = json_to_str(actual);
                let regex_pat = format!(
                    "(?i)^{}$",
                    regex::escape(pattern).replace("%", ".*").replace("_", ".")
                );
                if let Ok(re) = regex::Regex::new(&regex_pat) {
                    re.is_match(&s)
                } else {
                    false
                }
            } else {
                false
            }
        }
        Filter::Regex { field, pattern } => {
            if let Some(actual) = row.get(field) {
                let s = json_to_str(actual);
                if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(&s)
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => true,
    }
}

fn execute_stats(
    rows: Vec<HashMap<String, JsonValue>>,
    stats: &StatsTransform,
) -> Vec<HashMap<String, JsonValue>> {
    // 1. Group rows by group_by keys
    let mut group_order: Vec<Vec<String>> = Vec::new();
    let mut groups: HashMap<Vec<String>, Vec<&HashMap<String, JsonValue>>> = HashMap::new();

    for row in &rows {
        let group_key: Vec<String> = stats
            .group_by
            .iter()
            .map(|f| row.get(f).map(json_to_str).unwrap_or_default())
            .collect();

        if !groups.contains_key(&group_key) {
            group_order.push(group_key.clone());
        }
        groups.entry(group_key).or_default().push(row);
    }

    // If rows was empty and no group_by, return single empty row or empty
    if rows.is_empty() && stats.group_by.is_empty() {
        group_order.push(Vec::new());
        groups.insert(Vec::new(), Vec::new());
    }

    // 2. Aggregate each group
    let mut aggregated_rows = Vec::new();

    for key in group_order {
        let group_rows = groups.get(&key).cloned().unwrap_or_default();
        let mut out_row: HashMap<String, JsonValue> = HashMap::new();

        // Populate group_by fields
        for (i, field) in stats.group_by.iter().enumerate() {
            if let Some(val) = key.get(i) {
                out_row.insert(field.clone(), JsonValue::String(val.clone()));
            }
        }

        // Compute each aggregation
        for agg in &stats.aggregations {
            let col_name = agg.alias.clone().unwrap_or_else(|| match agg.function {
                AggFunction::Count => {
                    if agg.field.is_empty() {
                        "count".to_string()
                    } else {
                        format!("count_{}", agg.field)
                    }
                }
                AggFunction::Sum => format!("sum_{}", agg.field),
                AggFunction::Avg => format!("avg_{}", agg.field),
                AggFunction::Min => format!("min_{}", agg.field),
                AggFunction::Max => format!("max_{}", agg.field),
                AggFunction::Dc => format!("dc_{}", agg.field),
                AggFunction::Values => format!("values_{}", agg.field),
                AggFunction::Latest => format!("latest_{}", agg.field),
                AggFunction::Earliest => format!("earliest_{}", agg.field),
                AggFunction::Percentile(_) => format!("p_{}", agg.field),
            });

            let val: JsonValue = match agg.function {
                AggFunction::Count => JsonValue::Number(group_rows.len().into()),
                AggFunction::Sum => {
                    let sum: f64 = group_rows
                        .iter()
                        .filter_map(|r| r.get(&agg.field).and_then(json_to_f64))
                        .sum();
                    if sum.fract() == 0.0 {
                        JsonValue::Number((sum as i64).into())
                    } else {
                        serde_json::Number::from_f64(sum)
                            .map(JsonValue::Number)
                            .unwrap_or(JsonValue::Null)
                    }
                }
                AggFunction::Avg => {
                    let numbers: Vec<f64> = group_rows
                        .iter()
                        .filter_map(|r| r.get(&agg.field).and_then(json_to_f64))
                        .collect();
                    if numbers.is_empty() {
                        JsonValue::Null
                    } else {
                        let avg = numbers.iter().sum::<f64>() / numbers.len() as f64;
                        serde_json::Number::from_f64(avg)
                            .map(JsonValue::Number)
                            .unwrap_or(JsonValue::Null)
                    }
                }
                AggFunction::Min => {
                    let mut min_num: Option<f64> = None;
                    for r in &group_rows {
                        if let Some(n) = r.get(&agg.field).and_then(json_to_f64) {
                            min_num = Some(min_num.map(|m| m.min(n)).unwrap_or(n));
                        }
                    }
                    min_num
                        .and_then(serde_json::Number::from_f64)
                        .map(JsonValue::Number)
                        .unwrap_or(JsonValue::Null)
                }
                AggFunction::Max => {
                    let mut max_num: Option<f64> = None;
                    for r in &group_rows {
                        if let Some(n) = r.get(&agg.field).and_then(json_to_f64) {
                            max_num = Some(max_num.map(|m| m.max(n)).unwrap_or(n));
                        }
                    }
                    max_num
                        .and_then(serde_json::Number::from_f64)
                        .map(JsonValue::Number)
                        .unwrap_or(JsonValue::Null)
                }
                AggFunction::Dc => {
                    let mut distinct = HashSet::new();
                    for r in &group_rows {
                        if let Some(v) = r.get(&agg.field) {
                            distinct.insert(json_to_str(v));
                        }
                    }
                    JsonValue::Number(distinct.len().into())
                }
                AggFunction::Values => {
                    let mut distinct = Vec::new();
                    let mut seen = HashSet::new();
                    for r in &group_rows {
                        if let Some(v) = r.get(&agg.field) {
                            let s = json_to_str(v);
                            if seen.insert(s) {
                                distinct.push(v.clone());
                            }
                        }
                    }
                    JsonValue::Array(distinct)
                }
                AggFunction::Latest => group_rows
                    .iter()
                    .max_by_key(|r| r.get("_time").map(json_to_str).unwrap_or_default())
                    .and_then(|r| r.get(&agg.field))
                    .cloned()
                    .unwrap_or(JsonValue::Null),
                AggFunction::Earliest => group_rows
                    .iter()
                    .min_by_key(|r| r.get("_time").map(json_to_str).unwrap_or_default())
                    .and_then(|r| r.get(&agg.field))
                    .cloned()
                    .unwrap_or(JsonValue::Null),
                AggFunction::Percentile(_) => JsonValue::Null,
            };

            out_row.insert(col_name, val);
        }

        aggregated_rows.push(out_row);
    }

    aggregated_rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_core::config::IndexConfig;
    use cg_core::types::ParsedEvent;

    fn make_test_row(
        src_ip: &str,
        bytes: i64,
        severity: i64,
        action: &str,
    ) -> HashMap<String, JsonValue> {
        let mut m = HashMap::new();
        m.insert("src_ip".to_string(), JsonValue::String(src_ip.to_string()));
        m.insert("bytes".to_string(), JsonValue::Number(bytes.into()));
        m.insert("severity".to_string(), JsonValue::Number(severity.into()));
        m.insert("action".to_string(), JsonValue::String(action.to_string()));
        m
    }

    #[test]
    fn test_execute_stats_group_by_and_aggregations() {
        let rows = vec![
            make_test_row("192.168.1.10", 100, 3, "blocked"),
            make_test_row("192.168.1.10", 200, 5, "blocked"),
            make_test_row("10.0.0.5", 50, 2, "allowed"),
        ];

        let stats = StatsTransform {
            aggregations: vec![
                Aggregation {
                    function: AggFunction::Count,
                    field: String::new(),
                    alias: Some("event_count".to_string()),
                },
                Aggregation {
                    function: AggFunction::Sum,
                    field: "bytes".to_string(),
                    alias: Some("total_bytes".to_string()),
                },
            ],
            group_by: vec!["src_ip".to_string()],
        };

        let result = execute_stats(rows, &stats);
        assert_eq!(result.len(), 2);

        let row1 = result
            .iter()
            .find(|r| r.get("src_ip").and_then(|v| v.as_str()) == Some("192.168.1.10"))
            .unwrap();
        assert_eq!(row1.get("event_count").and_then(|v| v.as_i64()), Some(2));
        assert_eq!(row1.get("total_bytes").and_then(|v| v.as_i64()), Some(300));

        let row2 = result
            .iter()
            .find(|r| r.get("src_ip").and_then(|v| v.as_str()) == Some("10.0.0.5"))
            .unwrap();
        assert_eq!(row2.get("event_count").and_then(|v| v.as_i64()), Some(1));
        assert_eq!(row2.get("total_bytes").and_then(|v| v.as_i64()), Some(50));
    }

    #[test]
    fn test_execute_where_filter() {
        let row_high = make_test_row("1.1.1.1", 500, 5, "alert");
        let row_low = make_test_row("2.2.2.2", 10, 1, "info");

        let filter = Filter::Comparison {
            field: "severity".to_string(),
            op: ComparisonOp::Gte,
            value: Value::Integer(4),
        };

        assert!(evaluate_filter(&row_high, &filter));
        assert!(!evaluate_filter(&row_low, &filter));
    }

    #[test]
    fn test_execute_dedup_and_rename() {
        let rows = vec![
            make_test_row("10.0.0.1", 100, 1, "allow"),
            make_test_row("10.0.0.1", 200, 1, "allow"),
            make_test_row("10.0.0.2", 300, 1, "allow"),
        ];

        let mut deduped = execute_dedup(rows, &["src_ip".to_string()]);
        assert_eq!(deduped.len(), 2);

        execute_rename(
            &mut deduped,
            &[("src_ip".to_string(), "client_ip".to_string())],
        );
        assert!(deduped[0].contains_key("client_ip"));
        assert!(!deduped[0].contains_key("src_ip"));
    }

    #[tokio::test]
    async fn test_query_reports_truncation_and_complete_candidate_count() {
        let index_dir = std::env::temp_dir().join(format!(
            "cyberglass_query_completeness_{}",
            uuid::Uuid::new_v4()
        ));
        let config = IndexConfig {
            index_dir: index_dir.to_string_lossy().into_owned(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: false,
        };
        let manager = Arc::new(IndexManager::new(&config).unwrap());
        let handle = manager.get_or_create_index("completeness").unwrap();
        for id in 0..7 {
            let mut event = ParsedEvent::new("test", "json", b"event".to_vec());
            event.id = format!("query-event-{id}");
            handle.writer.add_event(&event).unwrap();
        }
        handle.writer.commit().unwrap();

        let executor = QueryExecutor::new(manager.clone());
        let make_query = |limit| Query {
            source: Some(Source {
                index_name: "completeness".into(),
                source_type: None,
            }),
            filters: Vec::new(),
            transforms: Vec::new(),
            limit: Some(limit),
            time_range: None,
        };

        let capped = executor.execute(&make_query(3)).await.unwrap();
        assert_eq!(capped.rows.len(), 3);
        assert_eq!(capped.stats.candidate_count, 7);
        assert_eq!(capped.stats.events_scanned, 3);
        assert!(capped.stats.results_truncated);

        let complete = executor.execute(&make_query(10)).await.unwrap();
        assert_eq!(complete.rows.len(), 7);
        assert_eq!(complete.stats.candidate_count, 7);
        assert!(!complete.stats.results_truncated);

        drop(manager);
        std::fs::remove_dir_all(index_dir).unwrap();
    }
}
