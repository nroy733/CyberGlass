pub mod error;
pub mod manager;
pub mod reader;
pub mod schema;
pub mod writer;

pub use error::{IndexError, Result};
pub use manager::{IndexHandle, IndexInfo, IndexManager};
pub use reader::{IndexReader, SearchResult};
pub use schema::EventSchema;
pub use writer::IndexWriter;

#[cfg(test)]
mod tests {
    use super::*;
    use cg_core::config::IndexConfig;
    use cg_core::types::ParsedEvent;

    fn make_event(source: &str, source_type: &str) -> ParsedEvent {
        let mut event = ParsedEvent::new(source, source_type, b"test".to_vec());
        event
            .fields
            .insert("src_ip".to_string(), "10.0.0.1".to_string());
        event
            .fields
            .insert("action".to_string(), "allow".to_string());
        event
    }

    #[test]
    fn test_index_manager_creation() {
        let config = IndexConfig {
            index_dir: "./target/test_index_basic".to_string(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: true,
        };
        let manager = IndexManager::new(&config).unwrap();
        let indices = manager.list_indices();
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0].name, "main");
    }

    #[test]
    fn test_index_write_and_search() {
        let config = IndexConfig {
            index_dir: "./target/test_index_write".to_string(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: true,
        };
        let manager = IndexManager::new(&config).unwrap();
        let handle = manager.get_or_create_index("test").unwrap();

        let event = make_event("test_source", "json");
        handle.writer.add_event(&event).unwrap();
        handle.writer.commit().unwrap();

        let results = handle.reader.search("", 10).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_list_indices() {
        let config = IndexConfig {
            index_dir: "./target/test_index_list".to_string(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: true,
        };
        let manager = IndexManager::new(&config).unwrap();
        manager.get_or_create_index("idx1").unwrap();
        manager.get_or_create_index("idx2").unwrap();

        let indices = manager.list_indices();
        assert_eq!(indices.len(), 3); // main, idx1, idx2
        let names: Vec<&str> = indices.iter().map(|i| i.name.as_str()).collect();
        assert!(names.contains(&"main"));
        assert!(names.contains(&"idx1"));
        assert!(names.contains(&"idx2"));
    }

    #[test]
    fn test_rejects_unsafe_index_names() {
        let config = IndexConfig {
            index_dir: "./target/test_index_names".to_string(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: false,
        };
        let manager = IndexManager::new(&config).unwrap();
        assert!(manager.get_or_create_index("../outside").is_err());
        assert!(manager.get_or_create_index("nested/index").is_err());
    }

    #[test]
    fn test_in_memory_index() {
        let _ = std::fs::remove_dir_all("./target/test_index");
        let manager = IndexManager::in_memory().unwrap();
        let handle = manager.get_or_create_index("mem_test").unwrap();

        let event = make_event("mem_source", "json");
        handle.writer.add_event(&event).unwrap();
        handle.writer.commit().unwrap();

        let results = handle.reader.search("", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_committed_events_survive_index_restart_and_report_total_matches() {
        let index_dir = std::env::temp_dir().join(format!(
            "cyberglass_index_recovery_{}",
            uuid::Uuid::new_v4()
        ));
        let config = IndexConfig {
            index_dir: index_dir.to_string_lossy().into_owned(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: false,
        };

        {
            let manager = IndexManager::new(&config).unwrap();
            let handle = manager.get_or_create_index("recovery_test").unwrap();
            assert!(matches!(
                &handle.index.settings().docstore_compression,
                tantivy::store::Compressor::Zstd(_)
            ));
            for id in 0..7 {
                let mut event = make_event("recovery-test", "json");
                event.id = format!("recovery-event-{id}");
                event.fields.insert("sequence".into(), id.to_string());
                handle.writer.add_event(&event).unwrap();
            }
            handle.writer.commit().unwrap();
        }

        {
            let manager = IndexManager::new(&config).unwrap();
            let handle = manager.get_or_create_index("recovery_test").unwrap();
            assert!(matches!(
                &handle.index.settings().docstore_compression,
                tantivy::store::Compressor::Zstd(_)
            ));
            let (page, total_matches) = handle.reader.search_with_total("*", 3).unwrap();
            assert_eq!(page.len(), 3);
            assert_eq!(total_matches, 7);
        }

        std::fs::remove_dir_all(index_dir).unwrap();
    }

    #[test]
    fn existing_lz4_segments_remain_searchable_when_manager_uses_zstd() {
        let index_dir = std::env::temp_dir().join(format!(
            "cyberglass_index_compression_{}",
            uuid::Uuid::new_v4()
        ));
        let legacy_index_dir = index_dir.join("legacy");
        std::fs::create_dir_all(&legacy_index_dir).unwrap();
        let schema = EventSchema::build();
        let mut legacy_index =
            tantivy::Index::create_in_dir(&legacy_index_dir, schema.schema.clone()).unwrap();
        legacy_index.settings_mut().docstore_compression = tantivy::store::Compressor::Lz4;
        {
            let mut writer = legacy_index.writer(50 * 1024 * 1024).unwrap();
            writer
                .add_document(schema.to_document(&make_event("legacy", "json")).unwrap())
                .unwrap();
            writer.commit().unwrap();
        }
        drop(legacy_index);

        let config = IndexConfig {
            index_dir: index_dir.to_string_lossy().into_owned(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: false,
        };
        let manager = IndexManager::new(&config).unwrap();
        let handle = manager.get_or_create_index("legacy").unwrap();

        assert!(matches!(
            &handle.index.settings().docstore_compression,
            tantivy::store::Compressor::Zstd(_)
        ));
        assert_eq!(handle.reader.search("*", 10).unwrap().len(), 1);

        drop(manager);
        std::fs::remove_dir_all(index_dir).unwrap();
    }

    #[test]
    fn clear_all_preserves_indexes_and_removes_committed_events() {
        let index_dir =
            std::env::temp_dir().join(format!("cyberglass_index_clear_{}", uuid::Uuid::new_v4()));
        let config = IndexConfig {
            index_dir: index_dir.to_string_lossy().into_owned(),
            memory_budget: 50 * 1024 * 1024,
            num_threads: 0,
            commit_interval_seconds: 5,
            columnar_enabled: false,
        };
        let manager = IndexManager::new(&config).unwrap();
        let handle = manager.get_or_create_index("clear_test").unwrap();
        handle
            .writer
            .add_event(&make_event("clear-test", "json"))
            .unwrap();
        handle.writer.commit().unwrap();

        assert_eq!(manager.clear_all().unwrap(), 2);
        assert!(handle.reader.search("", 10).unwrap().is_empty());
        assert_eq!(handle.writer.total_indexed(), 0);
        assert_eq!(manager.list_indices().len(), 2);

        drop(manager);
        std::fs::remove_dir_all(index_dir).unwrap();
    }
}
