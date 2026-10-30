use crate::error::Result;
use crate::schema::EventSchema;
use cg_core::types::ParsedEvent;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tantivy::Index;

pub struct IndexWriter {
    writer: Mutex<tantivy::IndexWriter>,
    event_schema: EventSchema,
    events_indexed: AtomicU64,
    dirty: AtomicBool,
}

impl IndexWriter {
    pub fn new(index: &Index, event_schema: EventSchema, memory_budget: usize) -> Result<Self> {
        let writer = index.writer(memory_budget)?;
        Ok(Self {
            writer: Mutex::new(writer),
            event_schema,
            events_indexed: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
        })
    }

    pub fn add_event(&self, event: &ParsedEvent) -> Result<()> {
        let doc = self.event_schema.to_document(event)?;
        let writer = self.writer.lock();
        writer.delete_term(tantivy::Term::from_field_text(
            self.event_schema.id_field,
            &event.id,
        ));
        writer.add_document(doc)?;
        self.events_indexed.fetch_add(1, Ordering::Relaxed);
        self.dirty.store(true, Ordering::Release);
        Ok(())
    }

    pub fn add_batch(&self, events: &[ParsedEvent]) -> Result<u64> {
        let writer = self.writer.lock();
        let mut count = 0u64;
        for ev in events {
            if let Ok(doc) = self.event_schema.to_document(ev) {
                writer.add_document(doc)?;
                count += 1;
            }
        }
        self.events_indexed.fetch_add(count, Ordering::Relaxed);
        if count > 0 {
            self.dirty.store(true, Ordering::Release);
        }
        Ok(count)
    }

    /// Commit pending documents. No-op when nothing has been added since the
    /// last commit, which avoids empty segments and pointless disk I/O.
    pub fn commit(&self) -> Result<()> {
        if !self.dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut writer = self.writer.lock();
        writer.commit()?;
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        let mut writer = self.writer.lock();
        writer.delete_all_documents()?;
        writer.commit()?;
        self.events_indexed.store(0, Ordering::Relaxed);
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub fn total_indexed(&self) -> u64 {
        self.events_indexed.load(Ordering::Relaxed)
    }
}
