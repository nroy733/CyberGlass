use crate::error::Result;
use cg_core::types::ParsedEvent;
use std::collections::BTreeMap;
use tantivy::schema::*;
use tantivy::TantivyDocument;

#[derive(Clone, Debug)]
pub struct EventSchema {
    pub schema: Schema,
    pub id_field: Field,
    pub time_field: Field,
    pub raw_field: Field,
    pub source_field: Field,
    pub source_type_field: Field,
    pub index_name_field: Field,
    pub severity_field: Field,
    pub fields_field: Field,
}

impl EventSchema {
    pub fn build() -> Self {
        let mut builder = Schema::builder();

        let id_field = builder.add_text_field("_id", STRING | STORED);
        let time_field = builder.add_date_field("_time", INDEXED | STORED | FAST);
        let raw_field = builder.add_text_field("_raw", TEXT | STORED);
        let source_field = builder.add_text_field("source", STRING | STORED);
        let source_type_field = builder.add_text_field("source_type", STRING | STORED);
        let index_name_field = builder.add_text_field("index_name", STRING | STORED);
        let severity_field = builder.add_u64_field("severity", INDEXED | STORED | FAST);
        let fields_field = builder.add_json_field("fields", TEXT | STORED);

        let schema = builder.build();

        Self {
            schema,
            id_field,
            time_field,
            raw_field,
            source_field,
            source_type_field,
            index_name_field,
            severity_field,
            fields_field,
        }
    }

    pub fn to_document(&self, event: &ParsedEvent) -> Result<TantivyDocument> {
        let mut doc = TantivyDocument::default();

        doc.add_text(self.id_field, &event.id);

        let dt = tantivy::DateTime::from_timestamp_millis(event.timestamp.timestamp_millis());
        doc.add_date(self.time_field, dt);

        let raw_str = String::from_utf8_lossy(&event.raw);
        doc.add_text(self.raw_field, &raw_str);

        doc.add_text(self.source_field, &event.source);
        doc.add_text(self.source_type_field, &event.source_type);
        doc.add_text(self.index_name_field, &event.index);
        doc.add_u64(self.severity_field, event.severity as u64);

        let mut object_map = BTreeMap::new();
        for (k, v) in &event.fields {
            object_map.insert(k.clone(), OwnedValue::Str(v.clone()));
        }
        doc.add_object(self.fields_field, object_map);

        Ok(doc)
    }
}
