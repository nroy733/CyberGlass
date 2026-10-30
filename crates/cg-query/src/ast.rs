//! Abstract Syntax Tree for the CyberQL query language.
//!
//! CyberQL uses a pipeline syntax where the query starts with
//! optional source and filter clauses, followed by pipe-separated transform commands.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Top-level query
// ---------------------------------------------------------------------------

/// The root AST node representing a complete CyberQL query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    /// The source index to search. Extracted from `source="<name>"`.
    pub source: Option<Source>,
    /// Zero or more base filters parsed before the first pipe.
    pub filters: Vec<Filter>,
    /// Ordered list of pipeline transforms (everything after each `|`).
    pub transforms: Vec<Transform>,
    /// An optional result-count limit inferred from `| head N`.
    pub limit: Option<usize>,
    /// An optional time-range constraint for efficient Tantivy queries.
    pub time_range: Option<TimeRange>,
}

/// Identifies the index (data source) to search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    /// The index name, e.g. `"firewall"`.
    pub index_name: String,
    /// Optional source type qualifier (e.g. `"syslog"`).
    pub source_type: Option<String>,
}

/// A half-open time range `[start, end)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    /// Inclusive start of the range.
    pub start: DateTime<Utc>,
    /// Exclusive end of the range.
    pub end: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// A boolean filter expression that can be arbitrarily nested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Filter {
    /// `field op value`
    Comparison {
        /// Field name on the left-hand side.
        field: String,
        /// Comparison operator.
        op: ComparisonOp,
        /// Literal value on the right-hand side.
        value: Value,
    },
    /// Logical AND of two sub-filters.
    And(Box<Filter>, Box<Filter>),
    /// Logical OR of two sub-filters.
    Or(Box<Filter>, Box<Filter>),
    /// Logical NOT of a sub-filter.
    Not(Box<Filter>),
    /// `field IN (v1, v2, …)`
    In {
        /// Field name.
        field: String,
        /// Set of acceptable values.
        values: Vec<Value>,
    },
    /// `field LIKE "pattern"` (SQL-style wildcards).
    Like {
        /// Field name.
        field: String,
        /// Wildcard pattern (`%` and `_`).
        pattern: String,
    },
    /// `field REGEX "pattern"`
    Regex {
        /// Field name.
        field: String,
        /// Regular expression pattern.
        pattern: String,
    },
    /// `field EXISTS` — the field is present and non-null.
    Exists(String),
    /// `field BETWEEN low AND high`
    Between {
        /// Field name.
        field: String,
        /// Lower bound (inclusive).
        low: Box<Value>,
        /// Upper bound (inclusive).
        high: Box<Value>,
    },
}

/// Comparison operators supported in filter expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOp {
    /// `=` or `==`
    Eq,
    /// `!=`
    Neq,
    /// `>`
    Gt,
    /// `>=`
    Gte,
    /// `<`
    Lt,
    /// `<=`
    Lte,
}

/// A literal value in a CyberQL expression.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Value {
    /// A string literal (possibly containing wildcards).
    String(String),
    /// A 64-bit signed integer.
    Integer(i64),
    /// A 64-bit floating-point number.
    Float(f64),
    /// A boolean literal.
    Boolean(bool),
    /// The null literal.
    Null,
    /// An RFC-3339 timestamp.
    Timestamp(DateTime<Utc>),
}

// ---------------------------------------------------------------------------
// Transforms (pipeline commands)
// ---------------------------------------------------------------------------

/// A single pipeline transform command appearing after a `|`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Transform {
    /// `| stats <aggregations> [by <fields>]`
    Stats(StatsTransform),
    /// `| where <condition>`
    Where(Filter),
    /// `| sort [-]field …`
    Sort(SortTransform),
    /// `| head N`
    Head(usize),
    /// `| tail N`
    Tail(usize),
    /// `| fields field1, field2, …`
    Fields(Vec<String>),
    /// `| rename old AS new, …`
    Rename(Vec<(String, String)>),
    /// `| eval field=expression`
    Eval {
        /// Target field name.
        field: String,
        /// Expression string (evaluated at runtime).
        expression: String,
    },
    /// `| dedup field1, field2, …`
    Dedup(Vec<String>),
    /// `| table field1, field2, …`
    Table(Vec<String>),
}

/// The `stats` transform: zero or more aggregations, optional group-by.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsTransform {
    /// Aggregation functions to apply.
    pub aggregations: Vec<Aggregation>,
    /// Fields to group by; empty means a single global group.
    pub group_by: Vec<String>,
}

/// A single aggregation call inside `stats`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aggregation {
    /// The aggregation function.
    pub function: AggFunction,
    /// The field the function operates on (empty string for `count`).
    pub field: String,
    /// Optional alias via `as <name>`.
    pub alias: Option<String>,
}

/// Built-in aggregation functions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AggFunction {
    /// Count of events.
    Count,
    /// Numeric sum.
    Sum,
    /// Arithmetic mean.
    Avg,
    /// Minimum value.
    Min,
    /// Maximum value.
    Max,
    /// Distinct count.
    Dc,
    /// Collect all values into a list.
    Values,
    /// The chronologically latest value.
    Latest,
    /// The chronologically earliest value.
    Earliest,
    /// p-th percentile (0.0–100.0).
    Percentile(OrderedF64),
}

/// A wrapper around `f64` that implements `Eq`/`Hash` for use in enum variants.
/// We only use this for percentile values which are always finite.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OrderedF64(pub f64);

impl PartialEq for OrderedF64 {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for OrderedF64 {}

impl std::hash::Hash for OrderedF64 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

/// The `sort` transform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortTransform {
    /// Fields to sort by, in priority order.
    pub fields: Vec<SortField>,
}

/// A single field inside a `sort` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortField {
    /// Field name.
    pub name: String,
    /// `true` for ascending, `false` for descending.
    pub ascending: bool,
}
