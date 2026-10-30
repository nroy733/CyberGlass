//! Error types for the CyberQL query engine.

use thiserror::Error;

/// All errors that can occur during query parsing, optimization, or execution.
#[derive(Debug, Error)]
pub enum QueryError {
    /// A syntax error encountered during parsing.
    #[error("parse error at line {line}, column {column}: {message}")]
    ParseError {
        /// Human-readable description of the syntax error.
        message: String,
        /// 1-based line number where the error was found.
        line: usize,
        /// 1-based column number where the error was found.
        column: usize,
    },

    /// A type mismatch in a comparison or aggregation (e.g. comparing a string to an integer).
    #[error("type error: {0}")]
    TypeError(String),

    /// Reference to a field that does not exist in the schema.
    #[error("undefined field: {0}")]
    UndefinedField(String),

    /// A runtime error during query execution.
    #[error("execution error: {0}")]
    ExecutionError(String),

    /// The query exceeded the configured timeout.
    #[error("query timed out after {0} ms")]
    Timeout(u64),

    /// The specified index was not found.
    #[error("index not found: {0}")]
    IndexNotFound(String),
}

/// Convenience type alias for query results.
pub type Result<T> = std::result::Result<T, QueryError>;
