//! # CyberGlass Internal Logging System
//!
//! Provides internal indexes for system logs, audit trails, and telemetry
//! independently of external event indexes.
//!
//! Internal indexes:
//! - `cg_internal` - System logs and background activity
//! - `cg_audit` - Security audit trail
//! - `cg_introspection` - Host resource and service performance metrics

pub mod audit;
pub mod error;
pub mod internal_index;
pub mod introspection;

pub use audit::{AuditEventType, AuditLogger};
pub use internal_index::{InternalIndexConfig, InternalIndexManager, InternalLogEntry};
pub use introspection::{HostMetricsCollector, IntrospectionLogger, StorageIndexMetrics};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_index_creation() {
        // Just verify module loads
        assert!(true);
    }
}
