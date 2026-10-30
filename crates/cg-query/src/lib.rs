//! # CyberQL Query Engine
//!
//! `cg-query` implements the CyberQL query language — a pipeline
//! syntax for searching, filtering, transforming, and aggregating security events
//! stored in CyberGlass indexes.
//!
//! ## Architecture
//!
//! The query pipeline follows a classic compiler architecture:
//!
//! 1. **Parser** — Hand-written recursive descent parser converts CyberQL text into an AST
//! 2. **Optimizer** — Applies predicate pushdown, filter merging, and limit propagation
//! 3. **Executor** — Walks the AST, converts filters to Tantivy queries, applies transforms
//!
//! ## CyberQL Syntax
//!
//! ```text
//! source="firewall" action=blocked src_ip="10.*"
//! | where severity > 3
//! | stats count, sum(bytes) by src_ip, dest_ip
//! | sort -count
//! | head 100
//! ```

pub mod ast;
pub mod error;
pub mod executor;
pub mod optimizer;
pub mod parser;

pub use ast::*;
pub use error::QueryError;
pub use executor::{QueryExecutor, QueryResults, QueryStats};
pub use optimizer::QueryOptimizer;
pub use parser::parse_query;
