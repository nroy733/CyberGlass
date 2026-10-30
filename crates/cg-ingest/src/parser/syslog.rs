use cg_core::error::{CyberGlassError, Result};
use cg_core::traits::Parser;
use cg_core::types::{ParsedEvent, Severity};

pub struct SyslogParser;

impl Parser for SyslogParser {
    fn name(&self) -> &str {
        "syslog"
    }

    fn can_parse(&self, raw: &[u8]) -> bool {
        raw.starts_with(b"<")
    }

    fn parse(&self, raw: &[u8]) -> Result<ParsedEvent> {
        let text =
            std::str::from_utf8(raw).map_err(|e| CyberGlassError::Serialization(e.to_string()))?;

        let mut event = ParsedEvent::new("syslog", "syslog", raw.to_vec());

        if let Some(end_bracket) = text.find('>') {
            if let Ok(pri) = text[1..end_bracket].parse::<u32>() {
                let facility = pri / 8;
                let severity = pri % 8;
                event
                    .fields
                    .insert("syslog.facility".to_string(), facility.to_string());
                event
                    .fields
                    .insert("syslog.severity".to_string(), severity.to_string());
                event.severity = match severity {
                    0 => Severity::Emergency,
                    1 => Severity::Alert,
                    2 => Severity::Critical,
                    3 => Severity::Error,
                    4 => Severity::Warning,
                    5 => Severity::Notice,
                    6 => Severity::Info,
                    _ => Severity::Debug,
                };

                let remainder = text[end_bracket + 1..].trim();
                let parts: Vec<&str> = remainder.splitn(4, ' ').collect();
                if parts.len() >= 3 {
                    event
                        .fields
                        .insert("host".to_string(), parts[1].to_string());
                    event.fields.insert(
                        "app".to_string(),
                        parts[2].trim_end_matches(':').to_string(),
                    );
                }
                if parts.len() >= 4 {
                    event
                        .fields
                        .insert("message".to_string(), parts[3].to_string());
                }
            }
        }

        Ok(event)
    }
}
