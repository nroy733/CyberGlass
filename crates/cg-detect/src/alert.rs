use crate::error::{DetectionError, Result};
use crate::rule::RuleSeverity;
use chrono::{DateTime, Utc};
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

const JOURNAL_MAGIC: &[u8; 8] = b"CGALERT\0";
const JOURNAL_VERSION: u32 = 1;
const HEADER_SIZE: u64 = 12;
const RECORD_HEADER_SIZE: usize = 8;
const MAX_ALERT_RECORD_SIZE: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_ALERTS: usize = 100_000;
const DEFAULT_MAX_JOURNAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    FalsePositive,
    Escalated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: RuleSeverity,
    pub description: String,
    pub event_ids: Vec<String>,
    pub fields: HashMap<String, String>,
    pub triggered_at: DateTime<Utc>,
    pub status: AlertStatus,
    pub assignee: Option<String>,
    pub mitre_techniques: Vec<String>,
    pub risk_score: f64,
    pub entity_ids: Vec<String>,
    pub incident_id: Option<String>,
}

struct AlertStoreState {
    alerts: HashMap<Uuid, Alert>,
    path: Option<PathBuf>,
    file: Option<File>,
    journal_bytes: u64,
    max_alerts: usize,
    max_journal_bytes: u64,
}

pub struct AlertStore {
    state: Mutex<AlertStoreState>,
}

impl Default for AlertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(AlertStoreState {
                alerts: HashMap::new(),
                path: None,
                file: None,
                journal_bytes: 0,
                max_alerts: DEFAULT_MAX_ALERTS,
                max_journal_bytes: DEFAULT_MAX_JOURNAL_BYTES,
            }),
        }
    }

    pub fn open(
        path: impl Into<PathBuf>,
        max_alerts: usize,
        max_journal_bytes: u64,
    ) -> Result<Self> {
        let path = path.into();
        if max_alerts == 0 || max_journal_bytes < HEADER_SIZE + RECORD_HEADER_SIZE as u64 {
            return Err(DetectionError::EvaluationError(
                "alert store limits are too small".into(),
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            DetectionError::EvaluationError("alert journal path has no parent directory".into())
        })?;
        std::fs::create_dir_all(parent).map_err(storage_error)?;
        let backup = backup_path(&path);
        if !path.exists() && backup.exists() {
            std::fs::rename(&backup, &path).map_err(storage_error)?;
        }

        let mut alerts = HashMap::new();
        let mut journal_bytes = HEADER_SIZE;
        if path.exists() {
            (alerts, journal_bytes) = read_journal(&path, max_alerts, max_journal_bytes)?;
        } else {
            let mut file = File::create(&path).map_err(storage_error)?;
            write_header(&mut file)?;
            file.sync_all().map_err(storage_error)?;
        }
        if backup.exists() {
            std::fs::remove_file(backup).map_err(storage_error)?;
        }
        let file = OpenOptions::new()
            .append(true)
            .read(true)
            .open(&path)
            .map_err(storage_error)?;
        Ok(Self {
            state: Mutex::new(AlertStoreState {
                alerts,
                path: Some(path),
                file: Some(file),
                journal_bytes,
                max_alerts,
                max_journal_bytes,
            }),
        })
    }

    pub fn add(&self, alert: Alert) -> Result<Uuid> {
        let mut state = self.lock_state();
        if let Some(existing) = state.alerts.get(&alert.id) {
            return Ok(existing.id);
        }
        if let Some(existing) = state
            .alerts
            .values()
            .find(|existing| same_trigger(existing, &alert))
        {
            return Ok(existing.id);
        }
        if state.alerts.len() >= state.max_alerts {
            return Err(DetectionError::EvaluationError(format!(
                "alert store capacity of {} alerts reached",
                state.max_alerts
            )));
        }
        persist_alert(&mut state, &alert)?;
        let id = alert.id;
        state.alerts.insert(id, alert);
        Ok(id)
    }

    pub fn get(&self, id: &Uuid) -> Option<Alert> {
        self.lock_state().alerts.get(id).cloned()
    }

    pub fn update_status(&self, id: &Uuid, status: AlertStatus) -> Result<()> {
        let mut state = self.lock_state();
        let mut alert = state
            .alerts
            .get(id)
            .cloned()
            .ok_or_else(|| DetectionError::AlertNotFound(id.to_string()))?;
        alert.status = status;
        persist_alert(&mut state, &alert)?;
        state.alerts.insert(*id, alert);
        Ok(())
    }

    pub fn list(&self, limit: usize) -> Vec<Alert> {
        let mut list: Vec<Alert> = self.lock_state().alerts.values().cloned().collect();
        list.sort_by(|a, b| b.triggered_at.cmp(&a.triggered_at));
        list.truncate(limit);
        list
    }

    pub fn count(&self) -> usize {
        self.lock_state().alerts.len()
    }

    pub fn list_by_status(&self, status: AlertStatus, limit: usize) -> Vec<Alert> {
        let mut list: Vec<Alert> = self
            .lock_state()
            .alerts
            .values()
            .filter(|alert| alert.status == status)
            .cloned()
            .collect();
        list.sort_by(|a, b| b.triggered_at.cmp(&a.triggered_at));
        list.truncate(limit);
        list
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, AlertStoreState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

fn same_trigger(existing: &Alert, candidate: &Alert) -> bool {
    existing.rule_id == candidate.rule_id && existing.event_ids == candidate.event_ids
}

fn persist_alert(state: &mut AlertStoreState, alert: &Alert) -> Result<()> {
    let Some(path) = state.path.clone() else {
        return Ok(());
    };
    let encoded = serde_json::to_vec(alert)
        .map_err(|error| DetectionError::EvaluationError(error.to_string()))?;
    if encoded.len() > MAX_ALERT_RECORD_SIZE {
        return Err(DetectionError::EvaluationError(format!(
            "serialized alert exceeds {MAX_ALERT_RECORD_SIZE} bytes"
        )));
    }
    let frame_size = RECORD_HEADER_SIZE as u64 + encoded.len() as u64;
    if state.journal_bytes.saturating_add(frame_size) <= state.max_journal_bytes {
        append_frame(
            state.file.as_mut().expect("persistent store has open file"),
            &encoded,
        )?;
        state.journal_bytes += frame_size;
        return Ok(());
    }

    let mut snapshot = state.alerts.clone();
    snapshot.insert(alert.id, alert.clone());
    let snapshot_size = snapshot.values().try_fold(HEADER_SIZE, |size, item| {
        let bytes = serde_json::to_vec(item)
            .map_err(|error| DetectionError::EvaluationError(error.to_string()))?;
        if bytes.len() > MAX_ALERT_RECORD_SIZE {
            return Err(DetectionError::EvaluationError(format!(
                "serialized alert exceeds {MAX_ALERT_RECORD_SIZE} bytes"
            )));
        }
        Ok(size.saturating_add(RECORD_HEADER_SIZE as u64 + bytes.len() as u64))
    })?;
    if snapshot_size > state.max_journal_bytes {
        return Err(DetectionError::EvaluationError(format!(
            "alert journal capacity of {} bytes reached",
            state.max_journal_bytes
        )));
    }
    state.file.take();
    if let Err(error) = compact_journal(&path, &snapshot) {
        state.file = Some(
            OpenOptions::new()
                .append(true)
                .read(true)
                .open(&path)
                .map_err(storage_error)?,
        );
        return Err(error);
    }
    let file = OpenOptions::new()
        .append(true)
        .read(true)
        .open(&path)
        .map_err(storage_error)?;
    state.file = Some(file);
    state.journal_bytes = snapshot_size;
    Ok(())
}

fn append_frame(file: &mut File, encoded: &[u8]) -> Result<()> {
    let len = u32::try_from(encoded.len())
        .map_err(|_| DetectionError::EvaluationError("alert record is too large".into()))?;
    let mut hasher = Hasher::new();
    hasher.update(encoded);
    let previous_size = file.metadata().map_err(storage_error)?.len();
    let write_result = file
        .write_all(&len.to_le_bytes())
        .and_then(|()| file.write_all(&hasher.finalize().to_le_bytes()))
        .and_then(|()| file.write_all(encoded))
        .and_then(|()| file.sync_all());
    if let Err(error) = write_result {
        let rollback_result = file.set_len(previous_size).and_then(|()| file.sync_all());
        if let Err(rollback_error) = rollback_result {
            return Err(DetectionError::EvaluationError(format!(
                "alert journal append failed ({error}); rollback failed ({rollback_error})"
            )));
        }
        return Err(storage_error(error));
    }
    Ok(())
}

fn write_header(file: &mut File) -> Result<()> {
    file.write_all(JOURNAL_MAGIC).map_err(storage_error)?;
    file.write_all(&JOURNAL_VERSION.to_le_bytes())
        .map_err(storage_error)
}

fn read_journal(
    path: &Path,
    max_alerts: usize,
    max_journal_bytes: u64,
) -> Result<(HashMap<Uuid, Alert>, u64)> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(storage_error)?;
    let file_len = file.metadata().map_err(storage_error)?.len();
    if file_len > max_journal_bytes {
        return Err(DetectionError::EvaluationError(format!(
            "alert journal size {file_len} exceeds configured limit {max_journal_bytes}"
        )));
    }
    let mut header = [0u8; HEADER_SIZE as usize];
    file.read_exact(&mut header).map_err(storage_error)?;
    if &header[..JOURNAL_MAGIC.len()] != JOURNAL_MAGIC {
        return Err(DetectionError::EvaluationError(
            "invalid alert journal magic".into(),
        ));
    }
    let version = u32::from_le_bytes(header[JOURNAL_MAGIC.len()..].try_into().unwrap());
    if version != JOURNAL_VERSION {
        return Err(DetectionError::EvaluationError(format!(
            "unsupported alert journal version {version}"
        )));
    }

    let mut alerts = HashMap::new();
    let mut valid_len = HEADER_SIZE;
    loop {
        let mut record_header = [0u8; RECORD_HEADER_SIZE];
        match file.read_exact(&mut record_header) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                if valid_len != file_len {
                    file.set_len(valid_len).map_err(storage_error)?;
                    file.sync_all().map_err(storage_error)?;
                }
                break;
            }
            Err(error) => return Err(storage_error(error)),
        }
        let len = u32::from_le_bytes(record_header[..4].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(record_header[4..].try_into().unwrap());
        if len > MAX_ALERT_RECORD_SIZE {
            return Err(DetectionError::EvaluationError(
                "alert journal record exceeds the record size limit".into(),
            ));
        }
        let mut encoded = vec![0u8; len];
        if let Err(error) = file.read_exact(&mut encoded) {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                file.set_len(valid_len).map_err(storage_error)?;
                file.sync_all().map_err(storage_error)?;
                break;
            }
            return Err(storage_error(error));
        }
        let mut hasher = Hasher::new();
        hasher.update(&encoded);
        if hasher.finalize() != expected_crc {
            return Err(DetectionError::EvaluationError(format!(
                "alert journal CRC mismatch at byte {valid_len}"
            )));
        }
        let alert: Alert = serde_json::from_slice(&encoded)
            .map_err(|error| DetectionError::EvaluationError(error.to_string()))?;
        if alerts.contains_key(&alert.id)
            || !alerts
                .values()
                .any(|existing| same_trigger(existing, &alert))
        {
            alerts.insert(alert.id, alert);
        }
        if alerts.len() > max_alerts {
            return Err(DetectionError::EvaluationError(format!(
                "alert count exceeds configured limit of {max_alerts}"
            )));
        }
        valid_len = valid_len.saturating_add(RECORD_HEADER_SIZE as u64 + len as u64);
    }
    Ok((alerts, valid_len))
}

fn compact_journal(path: &Path, alerts: &HashMap<Uuid, Alert>) -> Result<()> {
    let temporary = path.with_extension("compact");
    let backup = backup_path(path);
    let mut file = File::create(&temporary).map_err(storage_error)?;
    write_header(&mut file)?;
    let mut ordered: Vec<_> = alerts.values().collect();
    ordered.sort_by(|a, b| a.triggered_at.cmp(&b.triggered_at));
    for alert in ordered {
        let encoded = serde_json::to_vec(alert)
            .map_err(|error| DetectionError::EvaluationError(error.to_string()))?;
        if encoded.len() > MAX_ALERT_RECORD_SIZE {
            return Err(DetectionError::EvaluationError(
                "serialized alert exceeds the record size limit".into(),
            ));
        }
        let len = u32::try_from(encoded.len())
            .map_err(|_| DetectionError::EvaluationError("alert record is too large".into()))?;
        let mut hasher = Hasher::new();
        hasher.update(&encoded);
        file.write_all(&len.to_le_bytes()).map_err(storage_error)?;
        file.write_all(&hasher.finalize().to_le_bytes())
            .map_err(storage_error)?;
        file.write_all(&encoded).map_err(storage_error)?;
    }
    file.sync_all().map_err(storage_error)?;
    drop(file);

    if backup.exists() {
        std::fs::remove_file(&backup).map_err(storage_error)?;
    }
    if path.exists() {
        std::fs::rename(path, &backup).map_err(storage_error)?;
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        if backup.exists() && !path.exists() {
            std::fs::rename(&backup, path).map_err(storage_error)?;
        }
        return Err(storage_error(error));
    }
    if backup.exists() {
        std::fs::remove_file(backup).map_err(storage_error)?;
    }
    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("backup")
}

fn storage_error(error: std::io::Error) -> DetectionError {
    DetectionError::EvaluationError(format!("alert store I/O error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::RuleSeverity;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("cyberglass_alert_store_{nonce}"))
            .join("alerts.journal")
    }

    fn alert() -> Alert {
        Alert {
            id: Uuid::now_v7(),
            rule_id: "rule-test".into(),
            rule_name: "Test".into(),
            severity: RuleSeverity::High,
            description: "Test alert".into(),
            event_ids: vec!["event-1".into()],
            fields: HashMap::new(),
            triggered_at: Utc::now(),
            status: AlertStatus::New,
            assignee: None,
            mitre_techniques: Vec::new(),
            risk_score: 50.0,
            entity_ids: Vec::new(),
            incident_id: None,
        }
    }

    #[test]
    fn alert_and_status_survive_restart() {
        let path = temp_path();
        let stored_alert = alert();
        let id = stored_alert.id;
        {
            let store = AlertStore::open(&path, 10, 64 * 1024).unwrap();
            store.add(stored_alert).unwrap();
            store.update_status(&id, AlertStatus::Acknowledged).unwrap();
        }
        let recovered = AlertStore::open(&path, 10, 64 * 1024).unwrap();
        assert_eq!(
            recovered.get(&id).unwrap().status,
            AlertStatus::Acknowledged
        );
        assert_eq!(recovered.count(), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn duplicate_trigger_is_not_persisted_twice() {
        let path = temp_path();
        let first = alert();
        let mut duplicate = first.clone();
        duplicate.id = Uuid::now_v7();
        let store = AlertStore::open(&path, 10, 64 * 1024).unwrap();
        store.add(first.clone()).unwrap();
        assert_eq!(store.add(duplicate).unwrap(), first.id);
        assert_eq!(store.count(), 1);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn status_updates_compact_within_the_journal_limit() {
        let path = temp_path();
        let stored_alert = alert();
        let id = stored_alert.id;
        {
            let store = AlertStore::open(&path, 10, 2048).unwrap();
            store.add(stored_alert).unwrap();
            for step in 0..20 {
                let status = if step % 2 == 0 {
                    AlertStatus::Acknowledged
                } else {
                    AlertStatus::InProgress
                };
                store.update_status(&id, status).unwrap();
            }
        }
        assert!(std::fs::metadata(&path).unwrap().len() <= 2048);
        let recovered = AlertStore::open(&path, 10, 2048).unwrap();
        assert_eq!(recovered.get(&id).unwrap().status, AlertStatus::InProgress);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
