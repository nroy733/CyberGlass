//! # Dashboard Manager

use crate::models::*;
use anyhow::{Context, Result};
use dashmap::DashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use tracing::info;

/// Manages dashboards and widget data.
pub struct DashboardManager {
    dashboards: DashMap<String, Dashboard>,
    widget_data: DashMap<String, WidgetData>,
    persistence_path: Option<PathBuf>,
    mutation_lock: Mutex<()>,
}

impl DashboardManager {
    pub fn new() -> Self {
        Self::with_persistence(None)
    }

    /// Load custom dashboards from a backend-owned JSON config file.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let manager = Self::with_persistence(Some(path.clone()));
        match std::fs::read(&path) {
            Ok(contents) => {
                let dashboards: Vec<Dashboard> =
                    serde_json::from_slice(&contents).with_context(|| {
                        format!("Failed to parse dashboards config {}", path.display())
                    })?;
                for dashboard in dashboards {
                    if dashboard.is_builtin {
                        anyhow::bail!(
                            "Dashboards config {} contains a built-in dashboard",
                            path.display()
                        );
                    }
                    if manager.dashboards.contains_key(&dashboard.id) {
                        anyhow::bail!(
                            "Dashboards config {} contains duplicate or reserved ID {:?}",
                            path.display(),
                            dashboard.id
                        );
                    }
                    manager.dashboards.insert(dashboard.id.clone(), dashboard);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Failed to read dashboards config {}", path.display())
                });
            }
        }
        info!(
            custom_dashboards = manager
                .dashboards
                .iter()
                .filter(|dashboard| !dashboard.value().is_builtin)
                .count(),
            path = %path.display(),
            "Loaded persistent custom dashboards"
        );
        Ok(manager)
    }

    fn with_persistence(persistence_path: Option<PathBuf>) -> Self {
        let manager = Self {
            dashboards: DashMap::new(),
            widget_data: DashMap::new(),
            persistence_path,
            mutation_lock: Mutex::new(()),
        };

        // Register default dashboards
        for dashboard in default_dashboards() {
            manager.dashboards.insert(dashboard.id.clone(), dashboard);
        }

        info!(
            "Dashboard manager initialized with {} default dashboards",
            manager.dashboards.len()
        );
        manager
    }

    fn lock_mutations(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.mutation_lock
            .lock()
            .map_err(|error| format!("Dashboard mutation lock is poisoned: {error}"))
    }

    fn persist_custom_dashboards(&self) -> Result<(), String> {
        let Some(path) = self.persistence_path.as_deref() else {
            return Ok(());
        };
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if let Some(parent) = parent {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("Failed to create dashboard config directory: {error}"))?;
        }

        let mut dashboards: Vec<Dashboard> = self
            .dashboards
            .iter()
            .filter(|dashboard| !dashboard.value().is_builtin)
            .map(|dashboard| dashboard.value().clone())
            .collect();
        dashboards.sort_by(|left, right| left.id.cmp(&right.id));
        let contents = serde_json::to_vec_pretty(&dashboards)
            .map_err(|error| format!("Failed to serialize custom dashboards: {error}"))?;

        let directory = parent.unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(directory)
            .map_err(|error| format!("Failed to create temporary dashboard config: {error}"))?;
        temporary
            .write_all(&contents)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| format!("Failed to write custom dashboard config: {error}"))?;
        temporary
            .persist(path)
            .map_err(|error| format!("Failed to save custom dashboard config: {}", error.error))?;
        Ok(())
    }

    /// Get all dashboards.
    pub fn list_dashboards(&self) -> Vec<Dashboard> {
        self.dashboards.iter().map(|d| d.value().clone()).collect()
    }

    /// Get a specific dashboard by ID.
    pub fn get_dashboard(&self, id: &str) -> Option<Dashboard> {
        self.dashboards.get(id).map(|d| d.value().clone())
    }

    /// Create a new dashboard.
    pub fn create_dashboard(&self, dashboard: Dashboard) -> Result<(), String> {
        let _guard = self.lock_mutations()?;
        if dashboard.is_builtin {
            return Err("Custom dashboards cannot be marked as built-in".to_string());
        }
        if self.dashboards.contains_key(&dashboard.id) {
            return Err(format!("Dashboard {} already exists", dashboard.id));
        }
        let id = dashboard.id.clone();
        self.dashboards.insert(id.clone(), dashboard);
        if let Err(error) = self.persist_custom_dashboards() {
            self.dashboards.remove(&id);
            return Err(error);
        }
        Ok(())
    }

    /// Update a dashboard.
    pub fn update_dashboard(&self, id: &str, dashboard: Dashboard) -> Result<(), String> {
        let _guard = self.lock_mutations()?;
        if dashboard.id != id {
            return Err("Dashboard ID cannot be changed".to_string());
        }
        let Some(previous) = self
            .dashboards
            .get(id)
            .map(|dashboard| dashboard.value().clone())
        else {
            return Err(format!("Dashboard {} not found", id));
        };
        if previous.is_builtin {
            return Err("Built-in dashboards cannot be modified".to_string());
        }
        if dashboard.is_builtin {
            return Err("Custom dashboards cannot be marked as built-in".to_string());
        }
        self.dashboards.insert(id.to_string(), dashboard);
        if let Err(error) = self.persist_custom_dashboards() {
            self.dashboards.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(())
    }

    /// Delete a dashboard.
    pub fn delete_dashboard(&self, id: &str) -> Result<(), String> {
        let _guard = self.lock_mutations()?;
        let Some(dashboard) = self
            .dashboards
            .get(id)
            .map(|dashboard| dashboard.value().clone())
        else {
            return Err(format!("Dashboard {} not found", id));
        };
        if dashboard.is_builtin {
            return Err("Built-in dashboards cannot be deleted".to_string());
        }
        self.dashboards.remove(id);
        if let Err(error) = self.persist_custom_dashboards() {
            self.dashboards.insert(id.to_string(), dashboard);
            return Err(error);
        }
        Ok(())
    }

    /// Store widget data.
    pub fn set_widget_data(&self, widget_id: &str, data: serde_json::Value) {
        self.widget_data.insert(
            widget_id.to_string(),
            WidgetData {
                widget_id: widget_id.to_string(),
                data,
                updated_at: chrono::Utc::now(),
            },
        );
    }

    /// Get widget data.
    pub fn get_widget_data(&self, widget_id: &str) -> Option<WidgetData> {
        self.widget_data.get(widget_id).map(|d| d.value().clone())
    }

    /// Get dashboard stats.
    pub fn stats(&self) -> DashboardStats {
        DashboardStats {
            total_dashboards: self.dashboards.len(),
            builtin_dashboards: self
                .dashboards
                .iter()
                .filter(|d| d.value().is_builtin)
                .count(),
            custom_dashboards: self
                .dashboards
                .iter()
                .filter(|d| !d.value().is_builtin)
                .count(),
            total_widgets: self
                .dashboards
                .iter()
                .map(|d| d.value().widgets.len())
                .sum(),
        }
    }
}

/// Dashboard statistics.
#[derive(Debug, Clone)]
pub struct DashboardStats {
    pub total_dashboards: usize,
    pub builtin_dashboards: usize,
    pub custom_dashboards: usize,
    pub total_widgets: usize,
}

impl Default for DashboardManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_dashboard_manager() {
        let manager = DashboardManager::new();
        let dashboards = manager.list_dashboards();
        assert!(!dashboards.is_empty());

        let stats = manager.stats();
        assert!(stats.total_dashboards > 0);
        assert!(stats.builtin_dashboards > 0);
    }

    #[test]
    fn test_get_dashboard() {
        let manager = DashboardManager::new();
        let dashboard = manager.get_dashboard("sys-overview");
        assert!(dashboard.is_some());
        assert_eq!(dashboard.unwrap().title, "System Overview");
    }

    #[test]
    fn custom_dashboards_are_persisted_and_restored() {
        let directory = std::env::temp_dir().join(format!("cg_dashboards_{}", Uuid::new_v4()));
        let config_path = directory.join("dashboards.json");
        let mut dashboard =
            Dashboard::new("Custom SOC".to_string(), "Security operations".to_string());
        dashboard.widgets = default_dashboards()[0].widgets.clone();
        let dashboard_id = dashboard.id.clone();

        {
            let manager = DashboardManager::open(&config_path).unwrap();
            manager.create_dashboard(dashboard.clone()).unwrap();
            let saved: Vec<Dashboard> =
                serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
            assert_eq!(saved.len(), 1);
            assert_eq!(saved[0].id, dashboard_id);
            assert_eq!(saved[0].widgets.len(), dashboard.widgets.len());
        }

        {
            let manager = DashboardManager::open(&config_path).unwrap();
            assert_eq!(
                manager.get_dashboard(&dashboard_id).unwrap().title,
                "Custom SOC"
            );
            assert!(manager.get_dashboard("sys-overview").unwrap().is_builtin);

            let mut updated = manager.get_dashboard(&dashboard_id).unwrap();
            updated.title = "Updated SOC".to_string();
            manager.update_dashboard(&dashboard_id, updated).unwrap();
        }

        {
            let manager = DashboardManager::open(&config_path).unwrap();
            assert_eq!(
                manager.get_dashboard(&dashboard_id).unwrap().title,
                "Updated SOC"
            );
            manager.delete_dashboard(&dashboard_id).unwrap();
        }

        let reopened = DashboardManager::open(&config_path).unwrap();
        assert!(reopened.get_dashboard(&dashboard_id).is_none());
        assert!(reopened.get_dashboard("sys-overview").is_some());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn invalid_persisted_dashboard_config_fails_startup() {
        let directory = std::env::temp_dir().join(format!("cg_dashboards_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let config_path = directory.join("dashboards.json");
        std::fs::write(&config_path, b"{ invalid json").unwrap();

        assert!(DashboardManager::open(&config_path).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
