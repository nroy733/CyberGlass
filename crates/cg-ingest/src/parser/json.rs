use cg_core::error::{CyberGlassError, Result};
use cg_core::traits::Parser;
use cg_core::types::ParsedEvent;
use serde_json::Value;

pub struct JsonParser;

impl Parser for JsonParser {
    fn name(&self) -> &str {
        "json"
    }

    fn can_parse(&self, raw: &[u8]) -> bool {
        if let Ok(s) = std::str::from_utf8(raw) {
            let s = s.trim();
            s.starts_with('{') && s.ends_with('}')
        } else {
            false
        }
    }

    fn parse(&self, raw: &[u8]) -> Result<ParsedEvent> {
        let val: Value = serde_json::from_slice(raw)
            .map_err(|e| CyberGlassError::Serialization(e.to_string()))?;

        let mut event = ParsedEvent::new("json", "json", raw.to_vec());

        if let Value::Object(map) = val {
            flatten_json("", &Value::Object(map), &mut event.fields);
        }

        if let Some(src) = event.fields.get("source") {
            event.source = src.clone();
        }

        Ok(event)
    }
}

fn flatten_json(prefix: &str, value: &Value, out: &mut std::collections::HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let new_key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten_json(&new_key, v, out);
            }
        }
        Value::Array(arr) => {
            for (idx, v) in arr.iter().enumerate() {
                let new_key = format!("{}[{}]", prefix, idx);
                flatten_json(&new_key, v, out);
            }
        }
        Value::String(s) => {
            out.insert(prefix.to_string(), s.clone());
        }
        Value::Number(n) => {
            out.insert(prefix.to_string(), n.to_string());
        }
        Value::Bool(b) => {
            out.insert(prefix.to_string(), b.to_string());
        }
        Value::Null => {
            out.insert(prefix.to_string(), "null".to_string());
        }
    }
}
