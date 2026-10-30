use cg_core::error::{CyberGlassError, Result};
use cg_core::traits::Parser;
use cg_core::types::ParsedEvent;
use regex::Regex;
use std::sync::OnceLock;

static KV_REGEX: OnceLock<Regex> = OnceLock::new();

pub struct KvParser;

impl Parser for KvParser {
    fn name(&self) -> &str {
        "kv"
    }

    fn can_parse(&self, raw: &[u8]) -> bool {
        raw.contains(&b'=')
    }

    fn parse(&self, raw: &[u8]) -> Result<ParsedEvent> {
        let text =
            std::str::from_utf8(raw).map_err(|e| CyberGlassError::Serialization(e.to_string()))?;

        let re = KV_REGEX.get_or_init(|| {
            Regex::new(r#"([a-zA-Z0-9_.-]+)=(?:"([^"]*)"|'([^']*)'|(\S+))"#).unwrap()
        });

        let mut event = ParsedEvent::new("kv", "kv", raw.to_vec());

        for cap in re.captures_iter(text) {
            let key = &cap[1];
            let val = cap
                .get(2)
                .or_else(|| cap.get(3))
                .or_else(|| cap.get(4))
                .map(|m| m.as_str())
                .unwrap_or_default();

            event.fields.insert(key.to_string(), val.to_string());
        }

        Ok(event)
    }
}
