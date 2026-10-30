use crate::error::Result;
use cg_core::types::ParsedEvent;

pub struct Normalizer;

impl Default for Normalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Normalizer {
    pub fn new() -> Self {
        Self
    }

    pub fn normalize(&self, event: &mut ParsedEvent) -> Result<()> {
        let field_mappings = [
            ("src_ip", "src_endpoint.ip"),
            ("dst_ip", "dst_endpoint.ip"),
            ("dest_ip", "dst_endpoint.ip"),
            ("source_ip", "src_endpoint.ip"),
            ("destination_ip", "dst_endpoint.ip"),
            ("src_port", "src_endpoint.port"),
            ("dst_port", "dst_endpoint.port"),
            ("dest_port", "dst_endpoint.port"),
            ("username", "user.name"),
            ("user", "user.name"),
            ("account_name", "user.name"),
            ("hostname", "host.name"),
            ("computer_name", "host.name"),
        ];

        let mut additions = Vec::new();
        for (legacy, standard) in field_mappings {
            if let Some(val) = event.fields.get(legacy) {
                if !event.fields.contains_key(standard) {
                    additions.push((standard.to_string(), val.clone()));
                }
            }
        }

        for (k, v) in additions {
            event.fields.insert(k, v);
        }

        Ok(())
    }
}
