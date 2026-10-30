//! Versioned, bounded write-ahead log for recoverable ingestion.

use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tracing::{debug, info};

const WAL_MAGIC: &[u8; 6] = b"CGWAL\0";
const WAL_VERSION: u32 = 2;
const SEGMENT_HEADER_SIZE: u64 = 10;
const RECORD_HEADER_SIZE: u64 = 16;
const MAX_SEGMENT_SIZE: u64 = 100 * 1024 * 1024;
const MAX_RECORD_SIZE: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    pub sequence: u64,
    pub source: String,
    pub source_type: String,
    pub index: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct WalConfig {
    pub dir: PathBuf,
    pub max_segment_size: u64,
    pub max_total_size: u64,
    pub max_record_size: usize,
    pub sync_on_write: bool,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/var/lib/cyberglass/wal"),
            max_segment_size: MAX_SEGMENT_SIZE,
            max_total_size: 1024 * 1024 * 1024,
            max_record_size: MAX_RECORD_SIZE,
            sync_on_write: true,
        }
    }
}

pub struct WriteAheadLog {
    config: WalConfig,
    sequence: AtomicU64,
    current_segment: Mutex<Option<WalSegmentMeta>>,
    total_size: Mutex<u64>,
}

#[derive(Debug, Clone)]
struct WalSegmentMeta {
    path: PathBuf,
    size: u64,
}

impl WriteAheadLog {
    pub fn open(mut config: WalConfig) -> Result<Self, WalError> {
        config.max_segment_size = config
            .max_segment_size
            .clamp(SEGMENT_HEADER_SIZE + RECORD_HEADER_SIZE, MAX_SEGMENT_SIZE);
        config.max_record_size = config.max_record_size.min(u32::MAX as usize);
        if config.max_total_size < SEGMENT_HEADER_SIZE + RECORD_HEADER_SIZE
            || config.max_record_size == 0
        {
            return Err(WalError::Limit("WAL limits are too small".into()));
        }

        std::fs::create_dir_all(&config.dir).map_err(io_error)?;
        let mut segments = Self::segment_paths(&config.dir)?;
        segments.sort();

        let mut max_sequence = None;
        let mut total_size = 0u64;
        for path in &segments {
            let (records, valid_size) = Self::read_segment(path, &config)?;
            total_size = total_size.saturating_add(valid_size);
            if let Some(record) = records.last() {
                max_sequence =
                    Some(max_sequence.map_or(record.sequence, |max: u64| max.max(record.sequence)));
            }
        }
        if total_size > config.max_total_size {
            return Err(WalError::Limit(format!(
                "existing WAL size {total_size} exceeds configured limit {}",
                config.max_total_size
            )));
        }

        let latest_path = segments.last().cloned();
        let current_segment = latest_path
            .map(|path| {
                let size = std::fs::metadata(&path).map_err(io_error)?.len();
                Ok(WalSegmentMeta { path, size })
            })
            .transpose()?;

        info!(
            "WAL opened at {:?}, recovered sequence through {:?}, bytes={}",
            config.dir, max_sequence, total_size
        );
        Ok(Self {
            config,
            sequence: AtomicU64::new(max_sequence.map_or(0, |seq| seq.saturating_add(1))),
            current_segment: Mutex::new(current_segment),
            total_size: Mutex::new(total_size),
        })
    }

    fn segment_paths(dir: &Path) -> Result<Vec<PathBuf>, WalError> {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("wal") {
                paths.push(path);
            }
        }
        Ok(paths)
    }

    fn read_segment(path: &Path, config: &WalConfig) -> Result<(Vec<WalRecord>, u64), WalError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(io_error)?;
        let file_len = file.metadata().map_err(io_error)?.len();
        let mut header = [0u8; SEGMENT_HEADER_SIZE as usize];
        file.read_exact(&mut header).map_err(|error| {
            if file_len < SEGMENT_HEADER_SIZE {
                WalError::Corruption(format!("truncated segment header: {}", path.display()))
            } else {
                io_error(error)
            }
        })?;
        if &header[..WAL_MAGIC.len()] != WAL_MAGIC {
            return Err(WalError::Corruption(format!(
                "invalid WAL magic: {}",
                path.display()
            )));
        }
        let version = u32::from_le_bytes(header[WAL_MAGIC.len()..].try_into().unwrap());
        if version != WAL_VERSION {
            return Err(WalError::UnsupportedVersion(version));
        }

        let mut records = Vec::new();
        let mut valid_len = SEGMENT_HEADER_SIZE;
        loop {
            let mut record_header = [0u8; RECORD_HEADER_SIZE as usize];
            match file.read_exact(&mut record_header) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    if valid_len != file_len {
                        file.set_len(valid_len).map_err(io_error)?;
                        file.sync_all().map_err(io_error)?;
                    }
                    break;
                }
                Err(error) => return Err(io_error(error)),
            }

            let expected_crc = u32::from_le_bytes(record_header[0..4].try_into().unwrap());
            let len = u32::from_le_bytes(record_header[4..8].try_into().unwrap()) as usize;
            let sequence = u64::from_le_bytes(record_header[8..16].try_into().unwrap());
            if len > config.max_record_size {
                return Err(WalError::Limit(format!(
                    "WAL record length {len} exceeds configured limit {}",
                    config.max_record_size
                )));
            }
            let mut encoded = vec![0u8; len];
            match file.read_exact(&mut encoded) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    file.set_len(valid_len).map_err(io_error)?;
                    file.sync_all().map_err(io_error)?;
                    break;
                }
                Err(error) => return Err(io_error(error)),
            }

            let mut hasher = Hasher::new();
            hasher.update(&record_header[4..]);
            hasher.update(&encoded);
            if hasher.finalize() != expected_crc {
                return Err(WalError::Corruption(format!(
                    "CRC mismatch in {} at byte {valid_len}",
                    path.display()
                )));
            }
            let record: WalRecord = serde_json::from_slice(&encoded)
                .map_err(|error| WalError::Corruption(error.to_string()))?;
            if record.sequence != sequence {
                return Err(WalError::Corruption(format!(
                    "sequence mismatch in {}",
                    path.display()
                )));
            }
            records.push(record);
            valid_len = valid_len
                .saturating_add(RECORD_HEADER_SIZE)
                .saturating_add(len as u64);
        }
        Ok((records, valid_len))
    }

    pub fn append(
        &self,
        source: &str,
        source_type: &str,
        index: &str,
        payload: &[u8],
    ) -> Result<u64, WalError> {
        let mut total_size = self
            .total_size
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut segment = self
            .current_segment
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let sequence = self.sequence.load(Ordering::SeqCst);
        let record = WalRecord {
            sequence,
            source: source.to_string(),
            source_type: source_type.to_string(),
            index: index.to_string(),
            payload: payload.to_vec(),
        };
        let encoded =
            serde_json::to_vec(&record).map_err(|error| WalError::Encoding(error.to_string()))?;
        if encoded.len() > self.config.max_record_size {
            return Err(WalError::Limit(format!(
                "encoded WAL record is {} bytes; limit is {}",
                encoded.len(),
                self.config.max_record_size
            )));
        }

        let record_size = RECORD_HEADER_SIZE.saturating_add(encoded.len() as u64);
        if record_size.saturating_add(SEGMENT_HEADER_SIZE) > self.config.max_segment_size {
            return Err(WalError::Limit(
                "WAL record cannot fit in a segment with the configured segment limit".into(),
            ));
        }
        let needs_new_segment = match segment.as_ref() {
            None => true,
            Some(current) => {
                current.size.saturating_add(record_size) > self.config.max_segment_size
            }
        };
        let required_size = record_size.saturating_add(if needs_new_segment {
            SEGMENT_HEADER_SIZE
        } else {
            0
        });
        if total_size.saturating_add(required_size) > self.config.max_total_size {
            return Err(WalError::Limit(format!(
                "WAL disk limit of {} bytes reached",
                self.config.max_total_size
            )));
        }
        if needs_new_segment {
            let new_segment = Self::roll_new_segment(&self.config, sequence)?;
            *total_size = total_size.saturating_add(SEGMENT_HEADER_SIZE);
            *segment = Some(new_segment);
        }

        let current = segment.as_mut().expect("segment created above");
        let mut header = [0u8; RECORD_HEADER_SIZE as usize];
        header[4..8].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
        header[8..16].copy_from_slice(&sequence.to_le_bytes());
        let mut hasher = Hasher::new();
        hasher.update(&header[4..]);
        hasher.update(&encoded);
        header[..4].copy_from_slice(&hasher.finalize().to_le_bytes());

        let previous_size = current.size;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&current.path)
            .map_err(io_error)?;
        let write_result = file
            .write_all(&header)
            .and_then(|()| file.write_all(&encoded))
            .and_then(|()| {
                if self.config.sync_on_write {
                    file.sync_all()
                } else {
                    Ok(())
                }
            });
        if let Err(error) = write_result {
            let rollback_result = file.set_len(previous_size).and_then(|()| file.sync_all());
            if let Err(rollback_error) = rollback_result {
                return Err(WalError::Io(format!(
                    "append failed ({error}); rollback failed ({rollback_error})"
                )));
            }
            return Err(io_error(error));
        }
        current.size = current.size.saturating_add(record_size);
        *total_size = total_size.saturating_add(record_size);
        self.sequence
            .store(sequence.saturating_add(1), Ordering::SeqCst);
        debug!("WAL appended sequence={} bytes={}", sequence, encoded.len());
        Ok(sequence)
    }

    fn roll_new_segment(
        config: &WalConfig,
        first_sequence: u64,
    ) -> Result<WalSegmentMeta, WalError> {
        let path = config.dir.join(format!("segment_{first_sequence:020}.wal"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(io_error)?;
        let write_result = file
            .write_all(WAL_MAGIC)
            .and_then(|()| file.write_all(&WAL_VERSION.to_le_bytes()))
            .and_then(|()| {
                if config.sync_on_write {
                    file.sync_all()
                } else {
                    Ok(())
                }
            });
        if let Err(error) = write_result {
            drop(file);
            let cleanup_result = std::fs::remove_file(&path);
            if let Err(cleanup_error) = cleanup_result {
                return Err(WalError::Io(format!(
                    "segment creation failed ({error}); cleanup failed ({cleanup_error})"
                )));
            }
            return Err(io_error(error));
        }
        info!("WAL created segment {:?}", path);
        Ok(WalSegmentMeta {
            path,
            size: SEGMENT_HEADER_SIZE,
        })
    }

    pub async fn replay_async<F, Fut>(&self, mut callback: F) -> Result<(), WalError>
    where
        F: FnMut(WalRecord) -> Fut,
        Fut: Future<Output = Result<(), WalError>>,
    {
        let mut paths = Self::segment_paths(&self.config.dir)?;
        paths.sort();
        for path in paths {
            let (records, _) = Self::read_segment(&path, &self.config)?;
            for record in records {
                callback(record).await?;
            }
        }
        Ok(())
    }

    pub fn replay<F>(&self, mut callback: F) -> Result<(), WalError>
    where
        F: FnMut(u64, &[u8]),
    {
        let mut paths = Self::segment_paths(&self.config.dir)?;
        paths.sort();
        for path in paths {
            let (records, _) = Self::read_segment(&path, &self.config)?;
            for record in records {
                callback(record.sequence, &record.payload);
            }
        }
        Ok(())
    }

    pub fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }

    pub fn truncate_all(&self) -> Result<(), WalError> {
        let mut total_size = self
            .total_size
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut segment = self
            .current_segment
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for path in Self::segment_paths(&self.config.dir)? {
            std::fs::remove_file(path).map_err(io_error)?;
        }
        *segment = None;
        *total_size = 0;
        Ok(())
    }
}

fn io_error(error: std::io::Error) -> WalError {
    WalError::Io(error.to_string())
}

#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("WAL corruption: {0}")]
    Corruption(String),
    #[error("unsupported WAL version {0}")]
    UnsupportedVersion(u32),
    #[error("WAL limit: {0}")]
    Limit(String),
    #[error("WAL record encoding failed: {0}")]
    Encoding(String),
    #[error("WAL replay failed: {0}")]
    Replay(String),
}

pub type WalResult<T> = Result<T, WalError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::io::{Seek, SeekFrom};
    use std::time::SystemTime;

    fn temp_dir() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("cyberglass_wal_test_{ts}"))
    }

    #[test]
    fn test_wal_append_and_replay() {
        let dir = temp_dir();
        let wal = WriteAheadLog::open(WalConfig {
            dir: dir.clone(),
            sync_on_write: false,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(wal.append("auth", "json", "main", b"event-1").unwrap(), 0);
        assert_eq!(wal.append("auth", "json", "main", b"event-2").unwrap(), 1);
        let mut replayed = Vec::new();
        wal.replay(|sequence, payload| replayed.push((sequence, payload.to_vec())))
            .unwrap();
        assert_eq!(
            replayed,
            vec![(0, b"event-1".to_vec()), (1, b"event-2".to_vec())]
        );
        drop(wal);
        let reopened = WriteAheadLog::open(WalConfig {
            dir: dir.clone(),
            sync_on_write: false,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(reopened.current_sequence(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_wal_enforces_total_size_limit() {
        let dir = temp_dir();
        let wal = WriteAheadLog::open(WalConfig {
            dir: dir.clone(),
            max_segment_size: 128,
            max_total_size: 128,
            max_record_size: 128,
            sync_on_write: false,
        })
        .unwrap();
        wal.append("a", "b", "c", b"first").unwrap();
        assert!(matches!(
            wal.append("a", "b", "c", b"second"),
            Err(WalError::Limit(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_wal_truncates_torn_final_record_and_replays_valid_prefix() {
        let dir = temp_dir();
        let wal = WriteAheadLog::open(WalConfig {
            dir: dir.clone(),
            sync_on_write: false,
            ..Default::default()
        })
        .unwrap();
        wal.append("auth", "json", "main", b"event-1").unwrap();
        drop(wal);
        let path = only_segment(&dir);
        let mut file = OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(&[1, 2, 3]).unwrap();
        drop(file);
        let reopened = WriteAheadLog::open(WalConfig {
            dir: dir.clone(),
            sync_on_write: false,
            ..Default::default()
        })
        .unwrap();
        let mut replayed = Vec::new();
        reopened
            .replay(|seq, payload| replayed.push((seq, payload.to_vec())))
            .unwrap();
        assert_eq!(replayed, vec![(0, b"event-1".to_vec())]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_wal_rejects_crc_corruption() {
        let dir = temp_dir();
        let wal = WriteAheadLog::open(WalConfig {
            dir: dir.clone(),
            sync_on_write: false,
            ..Default::default()
        })
        .unwrap();
        wal.append("auth", "json", "main", b"event-1").unwrap();
        drop(wal);

        let path = only_segment(&dir);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(SEGMENT_HEADER_SIZE + RECORD_HEADER_SIZE))
            .unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Current(-1)).unwrap();
        byte[0] ^= 0xff;
        file.write_all(&byte).unwrap();
        drop(file);

        assert!(matches!(
            WriteAheadLog::open(WalConfig {
                dir: dir.clone(),
                sync_on_write: false,
                ..Default::default()
            }),
            Err(WalError::Corruption(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn only_segment(dir: &Path) -> PathBuf {
        WriteAheadLog::segment_paths(dir).unwrap().pop().unwrap()
    }
}
