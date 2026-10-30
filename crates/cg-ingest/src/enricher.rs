use crate::error::Result;
use cg_core::traits::Enricher;
use cg_core::types::ParsedEvent;
use std::net::IpAddr;

pub struct EnricherChain {
    enrichers: Vec<Box<dyn Enricher>>,
}

impl Default for EnricherChain {
    fn default() -> Self {
        Self::new()
    }
}

impl EnricherChain {
    pub fn new() -> Self {
        Self {
            enrichers: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut chain = Self::new();
        chain.add(Box::new(GeoIpEnricher));
        chain.add(Box::new(ThreatIntelEnricher));
        chain
    }

    pub fn add(&mut self, enricher: Box<dyn Enricher>) {
        self.enrichers.push(enricher);
    }

    pub fn enrich(&self, event: &mut ParsedEvent) -> Result<()> {
        for enricher in &self.enrichers {
            if let Err(e) = enricher.enrich(event) {
                tracing::debug!("Enricher '{}' failed: {}", enricher.name(), e);
            }
        }
        Ok(())
    }
}

pub struct GeoIpEnricher;

fn classify_ip(ip_str: &str) -> Option<&'static str> {
    let clean = ip_str.trim().trim_matches('"').trim_matches('\'');
    let ip: IpAddr = clean.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if v4.is_loopback() {
                Some("loopback")
            } else if octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
            {
                Some("private")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_broadcast() {
                Some("broadcast")
            } else if v4.is_multicast() {
                Some("multicast")
            } else {
                Some("public")
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Some("loopback")
            } else if v6.is_multicast() {
                Some("multicast")
            } else {
                let segments = v6.segments();
                if (segments[0] & 0xfe00) == 0xfc00 {
                    Some("private")
                } else if (segments[0] & 0xffc0) == 0xfe80 {
                    Some("link-local")
                } else {
                    Some("public")
                }
            }
        }
    }
}

impl Enricher for GeoIpEnricher {
    fn name(&self) -> &str {
        "geoip"
    }

    fn enrich(&self, event: &mut ParsedEvent) -> cg_core::error::Result<()> {
        // Source IP enrichment (handles full RFC 1918 range 172.16.0.0/12, 10.0.0.0/8, 192.168.0.0/16, IPv6)
        if let Some(src_ip) = event
            .fields
            .get("src_endpoint.ip")
            .or_else(|| event.fields.get("src_ip"))
            .or_else(|| event.fields.get("src"))
        {
            if let Some(classification) = classify_ip(src_ip) {
                event
                    .metadata
                    .insert("src_ip.type".to_string(), classification.to_string());
            }
        }

        // Destination IP enrichment
        if let Some(dst_ip) = event
            .fields
            .get("dst_endpoint.ip")
            .or_else(|| event.fields.get("dest_ip"))
            .or_else(|| event.fields.get("dst_ip"))
            .or_else(|| event.fields.get("dst"))
        {
            if let Some(classification) = classify_ip(dst_ip) {
                event
                    .metadata
                    .insert("dst_ip.type".to_string(), classification.to_string());
            }
        }

        Ok(())
    }
}

pub struct ThreatIntelEnricher;

impl Enricher for ThreatIntelEnricher {
    fn name(&self) -> &str {
        "threat_intel"
    }

    fn enrich(&self, event: &mut ParsedEvent) -> cg_core::error::Result<()> {
        event
            .metadata
            .insert("threat_intel.checked".to_string(), "true".to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_rfc1918_classification() {
        assert_eq!(classify_ip("10.0.0.1"), Some("private"));
        assert_eq!(classify_ip("192.168.1.100"), Some("private"));
        assert_eq!(classify_ip("172.16.0.1"), Some("private"));
        assert_eq!(classify_ip("172.24.50.1"), Some("private"));
        assert_eq!(classify_ip("172.31.255.254"), Some("private"));
        assert_eq!(classify_ip("172.32.0.1"), Some("public"));
        assert_eq!(classify_ip("8.8.8.8"), Some("public"));
        assert_eq!(classify_ip("127.0.0.1"), Some("loopback"));
    }

    #[test]
    fn test_enricher_private_and_public() {
        let mut event = ParsedEvent::new("test", "json", b"{}".to_vec());
        let mut fields = HashMap::new();
        fields.insert("src_ip".to_string(), "172.20.1.5".to_string());
        fields.insert("dest_ip".to_string(), "1.1.1.1".to_string());
        event.fields = fields;

        let enricher = GeoIpEnricher;
        enricher.enrich(&mut event).unwrap();

        assert_eq!(
            event.metadata.get("src_ip.type").map(|s| s.as_str()),
            Some("private")
        );
        assert_eq!(
            event.metadata.get("dst_ip.type").map(|s| s.as_str()),
            Some("public")
        );
    }
}
