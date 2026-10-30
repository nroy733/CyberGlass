use crate::error::{Result, StorageError};
use arrow::record_batch::RecordBatch;
use cg_core::types::StorageTier;
use chrono::{DateTime, Utc};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub id: String,
    pub index_name: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub tier: StorageTier,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub event_count: u64,
    pub compressed: bool,
}

pub struct SegmentWriter {
    path: PathBuf,
    writer: ArrowWriter<File>,
    event_count: u64,
}

impl SegmentWriter {
    pub fn new<P: AsRef<Path>>(path: P, schema: arrow::datatypes::SchemaRef) -> Result<Self> {
        let file = File::create(path.as_ref()).map_err(StorageError::Io)?;
        let writer = ArrowWriter::try_new(file, schema, None)?;
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            writer,
            event_count: 0,
        })
    }

    pub fn write_batch(&mut self, batch: &RecordBatch) -> Result<()> {
        self.writer.write(batch)?;
        self.event_count += batch.num_rows() as u64;
        Ok(())
    }

    pub fn finish(self, index_name: &str, tier: StorageTier) -> Result<Segment> {
        let _metadata = self.writer.close()?;
        let size_bytes = std::fs::metadata(&self.path)?.len();
        let now = Utc::now();

        Ok(Segment {
            id: Uuid::now_v7().to_string(),
            index_name: index_name.to_string(),
            start_time: now,
            end_time: now,
            tier,
            path: self.path,
            size_bytes,
            event_count: self.event_count,
            compressed: true,
        })
    }
}

pub struct SegmentReader {
    path: PathBuf,
}

impl SegmentReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self {
            path: path.as_ref().to_path_buf(),
        })
    }

    pub fn read_all(&self) -> Result<Vec<RecordBatch>> {
        let file = File::open(&self.path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let reader = builder.build()?;
        let mut batches = Vec::new();

        for batch_res in reader {
            batches.push(batch_res?);
        }

        Ok(batches)
    }
}
