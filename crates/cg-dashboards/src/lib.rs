//! # CyberGlass Dashboards
//!
//! Pre-built dashboards for internal performance visualization,
//! search concurrency, resource consumption, data onboarding, data health,
//! REST API health, throughput, and storage metrics.

pub mod manager;
pub mod models;

pub use manager::DashboardManager;
pub use models::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_creation() {
        let dashboard = Dashboard::new(
            "System Overview".to_string(),
            "System health and performance metrics".to_string(),
        );
        assert_eq!(dashboard.title, "System Overview");
        assert_eq!(dashboard.widgets.len(), 0);
    }

    #[test]
    fn test_default_dashboards() {
        let dashboards = default_dashboards();
        assert!(!dashboards.is_empty());
        assert!(dashboards.iter().any(|d| d.title == "System Overview"));
        assert!(dashboards.iter().any(|d| d.title == "Data Onboarding"));
    }
}
