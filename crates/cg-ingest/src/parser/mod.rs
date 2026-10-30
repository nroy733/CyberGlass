pub mod cef;
pub mod json;
pub mod kv;
pub mod syslog;

use crate::error::{IngestError, Result};
use cg_core::traits::Parser;
use cg_core::types::ParsedEvent;
use std::collections::HashMap;

pub struct ParserRegistry {
    parsers: HashMap<String, Box<dyn Parser>>,
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ParserRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            parsers: HashMap::new(),
        };

        registry.register("json", Box::new(json::JsonParser));
        registry.register("kv", Box::new(kv::KvParser));
        registry.register("syslog", Box::new(syslog::SyslogParser));
        registry.register("cef", Box::new(cef::CefParser));

        registry
    }

    pub fn register(&mut self, name: &str, parser: Box<dyn Parser>) {
        self.parsers.insert(name.to_lowercase(), parser);
    }

    pub fn parse(&self, source_type: &str, raw: &[u8]) -> Result<ParsedEvent> {
        let st = source_type.to_lowercase();
        if let Some(parser) = self.parsers.get(&st) {
            return parser.parse(raw).map_err(|e| IngestError::Parse {
                source_type: source_type.to_string(),
                message: e.to_string(),
            });
        }

        // Auto-detect format if not explicitly found
        if let Some(detected) = self.detect_format(raw) {
            if let Some(parser) = self.parsers.get(&detected) {
                return parser.parse(raw).map_err(|e| IngestError::Parse {
                    source_type: detected,
                    message: e.to_string(),
                });
            }
        }

        // Fallback: raw unparsed event
        Ok(ParsedEvent::new("unknown", source_type, raw.to_vec()))
    }

    pub fn detect_format(&self, raw: &[u8]) -> Option<String> {
        let s = std::str::from_utf8(raw).ok()?.trim();
        if (s.starts_with('{') && s.ends_with('}')) || (s.starts_with('[') && s.ends_with(']')) {
            return Some("json".into());
        }
        if s.starts_with("CEF:") {
            return Some("cef".into());
        }
        if s.starts_with('<') && s.contains('>') {
            return Some("syslog".into());
        }
        if s.contains('=') {
            return Some("kv".into());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_format() {
        let registry = ParserRegistry::new();
        let raw = br#"{"src_ip": "10.0.0.1", "action": "allow", "bytes": 1024}"#;
        let event = registry.parse("json", raw).expect("JSON parse failed");

        assert_eq!(event.fields.get("src_ip").unwrap(), "10.0.0.1");
        assert_eq!(event.fields.get("action").unwrap(), "allow");
    }

    #[test]
    fn test_parse_kv_format() {
        let registry = ParserRegistry::new();
        let raw = b"src=192.168.1.50 dst=8.8.8.8 proto=TCP action=DENY";
        let event = registry.parse("kv", raw).expect("KV parse failed");

        assert_eq!(event.fields.get("src").unwrap(), "192.168.1.50");
        assert_eq!(event.fields.get("action").unwrap(), "DENY");
    }

    #[test]
    fn test_parse_cef_format() {
        let registry = ParserRegistry::new();
        let raw = b"CEF:0|PaloAlto|PAN-OS|10.0|TRAFFIC|drop|7|src=1.2.3.4 dst=5.6.7.8";
        let event = registry.parse("cef", raw).expect("CEF parse failed");

        assert_eq!(event.fields.get("device.vendor").unwrap(), "PaloAlto");
        assert_eq!(event.fields.get("src").unwrap(), "1.2.3.4");
    }
}
