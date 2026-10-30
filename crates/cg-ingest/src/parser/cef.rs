use cg_core::error::{CyberGlassError, Result};
use cg_core::traits::Parser;
use cg_core::types::ParsedEvent;

pub struct CefParser;

impl Parser for CefParser {
    fn name(&self) -> &str {
        "cef"
    }

    fn can_parse(&self, raw: &[u8]) -> bool {
        raw.starts_with(b"CEF:")
    }

    fn parse(&self, raw: &[u8]) -> Result<ParsedEvent> {
        let text =
            std::str::from_utf8(raw).map_err(|e| CyberGlassError::Serialization(e.to_string()))?;

        let mut event = ParsedEvent::new("cef", "cef", raw.to_vec());

        let parts: Vec<&str> = text.split('|').collect();
        if parts.len() >= 8 {
            event.fields.insert(
                "cef.version".to_string(),
                parts[0].trim_start_matches("CEF:").to_string(),
            );
            event
                .fields
                .insert("device.vendor".to_string(), parts[1].to_string());
            event
                .fields
                .insert("device.product".to_string(), parts[2].to_string());
            event
                .fields
                .insert("device.version".to_string(), parts[3].to_string());
            event
                .fields
                .insert("device.event_class_id".to_string(), parts[4].to_string());
            event
                .fields
                .insert("name".to_string(), parts[5].to_string());
            event
                .fields
                .insert("severity".to_string(), parts[6].to_string());

            let extension = parts[7..].join("|");
            for kv in extension.split_whitespace() {
                if let Some((k, v)) = kv.split_once('=') {
                    event.fields.insert(k.to_string(), v.to_string());
                }
            }
        }

        Ok(event)
    }
}
