use crate::error::{IndexError, Result};
use crate::schema::EventSchema;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tantivy::collector::{Count, TopDocs};
use tantivy::query::QueryParser;
use tantivy::schema::Value;
use tantivy::{Index, TantivyDocument};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub id: String,
    pub score: f32,
    pub raw: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub source_type: String,
    pub index_name: String,
    pub severity: u64,
    pub fields: HashMap<String, String>,
}

pub struct IndexReader {
    reader: tantivy::IndexReader,
    event_schema: EventSchema,
    query_parser: QueryParser,
}

impl IndexReader {
    pub fn new(index: &Index, event_schema: EventSchema) -> Result<Self> {
        let reader = index.reader()?;
        let query_parser = QueryParser::for_index(
            index,
            vec![
                event_schema.raw_field,
                event_schema.source_field,
                event_schema.source_type_field,
                event_schema.index_name_field,
            ],
        );

        Ok(Self {
            reader,
            event_schema,
            query_parser,
        })
    }

    pub fn search(&self, query_str: &str, max_results: usize) -> Result<Vec<SearchResult>> {
        self.search_with_total(query_str, max_results)
            .map(|(results, _)| results)
    }

    /// Search a bounded page and return the full number of matching documents.
    pub fn search_with_total(
        &self,
        query_str: &str,
        max_results: usize,
    ) -> Result<(Vec<SearchResult>, usize)> {
        let _ = self.reader.reload();
        let searcher = self.reader.searcher();
        let query: Box<dyn tantivy::query::Query> =
            if query_str == "*" || query_str.trim().is_empty() {
                Box::new(tantivy::query::AllQuery)
            } else {
                self.query_parser
                    .parse_query(query_str)
                    .map_err(|e| IndexError::QueryParse(e.to_string()))?
            };

        let total_matches = searcher.search(&query, &Count)?;
        let top_docs = searcher.search(&query, &TopDocs::with_limit(max_results))?;
        let mut results = Vec::with_capacity(top_docs.len());

        for (score, doc_address) in top_docs {
            let doc: TantivyDocument = searcher.doc(doc_address)?;

            let id = doc
                .get_first(self.event_schema.id_field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let raw = doc
                .get_first(self.event_schema.raw_field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let source = doc
                .get_first(self.event_schema.source_field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let source_type = doc
                .get_first(self.event_schema.source_type_field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let index_name = doc
                .get_first(self.event_schema.index_name_field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            let severity = doc
                .get_first(self.event_schema.severity_field)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let timestamp = doc
                .get_first(self.event_schema.time_field)
                .and_then(|v| v.as_datetime())
                .and_then(|dt| DateTime::from_timestamp_millis(dt.into_timestamp_millis()))
                .unwrap_or_else(Utc::now);

            let mut fields = HashMap::new();
            if let Some(obj_val) = doc.get_first(self.event_schema.fields_field) {
                if let Some(obj_iter) = obj_val.as_object() {
                    for (k, v) in obj_iter {
                        let val_str = match v {
                            tantivy::schema::OwnedValue::Str(s) => s.clone(),
                            tantivy::schema::OwnedValue::I64(i) => i.to_string(),
                            tantivy::schema::OwnedValue::U64(u) => u.to_string(),
                            tantivy::schema::OwnedValue::F64(f) => f.to_string(),
                            tantivy::schema::OwnedValue::Bool(b) => b.to_string(),
                            _ => format!("{:?}", v),
                        };
                        fields.insert(k.to_string(), val_str);
                    }
                }
            }

            results.push(SearchResult {
                id,
                score,
                raw,
                timestamp,
                source,
                source_type,
                index_name,
                severity,
                fields,
            });
        }

        Ok((results, total_matches))
    }

    pub fn count(&self, query_str: &str) -> Result<usize> {
        let searcher = self.reader.searcher();
        let query = self
            .query_parser
            .parse_query(query_str)
            .map_err(|e| IndexError::QueryParse(e.to_string()))?;

        let count = searcher.search(&query, &Count)?;
        Ok(count)
    }
}
