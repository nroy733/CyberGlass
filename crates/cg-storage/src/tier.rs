use crate::error::Result;
use cg_core::config::StorageConfig;
use cg_core::types::StorageTier;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierUsage {
    pub tier: StorageTier,
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub percent_used: f64,
}

pub struct TierManager {
    config: StorageConfig,
}

impl TierManager {
    pub fn new(config: &StorageConfig) -> Result<Self> {
        let manager = Self {
            config: config.clone(),
        };
        manager.ensure_directories()?;
        Ok(manager)
    }

    fn ensure_directories(&self) -> Result<()> {
        let dirs = [
            &self.config.hot.path,
            &self.config.warm.path,
            &self.config.cold.path,
            &self.config.frozen.path,
        ];

        for path in dirs {
            if !path.is_empty() {
                let p = Path::new(path);
                if !p.exists() {
                    let _ = std::fs::create_dir_all(p);
                }
            }
        }
        Ok(())
    }

    pub fn get_tier_for_age(&self, age_days: u64) -> StorageTier {
        if age_days <= self.config.hot.retention_days {
            StorageTier::Hot
        } else if age_days <= self.config.warm.retention_days {
            StorageTier::Warm
        } else if age_days <= self.config.cold.retention_days {
            StorageTier::Cold
        } else {
            StorageTier::Frozen
        }
    }

    pub fn get_tier_path(&self, tier: StorageTier) -> PathBuf {
        let path_str = match tier {
            StorageTier::Hot => &self.config.hot.path,
            StorageTier::Warm => &self.config.warm.path,
            StorageTier::Cold => &self.config.cold.path,
            StorageTier::Frozen => &self.config.frozen.path,
        };
        PathBuf::from(path_str)
    }

    pub fn get_tier_usage(&self, tier: StorageTier) -> Result<TierUsage> {
        let path = self.get_tier_path(tier);
        let mut used = 0u64;

        if path.exists() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        used += meta.len();
                    }
                }
            }
        }

        let total = 100 * 1024 * 1024 * 1024; // 100GB default
        let percent = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        Ok(TierUsage {
            tier,
            used_bytes: used,
            total_bytes: total,
            percent_used: percent,
        })
    }
}
