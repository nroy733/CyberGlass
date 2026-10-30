use crate::entity::{Entity, EntityType};
use cg_core::types::ParsedEvent;
use regex::Regex;
use std::sync::OnceLock;

static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
static HASH_MD5_REGEX: OnceLock<Regex> = OnceLock::new();
static HASH_SHA1_REGEX: OnceLock<Regex> = OnceLock::new();
static HASH_SHA256_REGEX: OnceLock<Regex> = OnceLock::new();
static DOMAIN_REGEX: OnceLock<Regex> = OnceLock::new();
static URL_REGEX: OnceLock<Regex> = OnceLock::new();
static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct ExtractedEntity {
    pub entity_type: EntityType,
    pub value: String,
    pub source_field: String,
    pub confidence: f64,
}

pub struct EntityExtractor;

impl Default for EntityExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl EntityExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn extract(&self, event: &ParsedEvent) -> Vec<ExtractedEntity> {
        let mut extracted = Vec::new();

        let ipv4_re = IPV4_REGEX.get_or_init(|| {
            Regex::new(r#"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#).unwrap()
        });

        let sha256_re =
            HASH_SHA256_REGEX.get_or_init(|| Regex::new(r#"\b[a-fA-F0-9]{64}\b"#).unwrap());

        let sha1_re = HASH_SHA1_REGEX.get_or_init(|| Regex::new(r#"\b[a-fA-F0-9]{40}\b"#).unwrap());

        let md5_re = HASH_MD5_REGEX.get_or_init(|| Regex::new(r#"\b[a-fA-F0-9]{32}\b"#).unwrap());

        let domain_re = DOMAIN_REGEX.get_or_init(|| {
            Regex::new(r#"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|io|ai|co|xyz|info|biz|ru|cn|uk|de|jp)\b"#).unwrap()
        });

        let url_re = URL_REGEX.get_or_init(|| Regex::new(r#"https?://[^\s"'<>]+"#).unwrap());

        let email_re = EMAIL_REGEX.get_or_init(|| {
            Regex::new(r#"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"#).unwrap()
        });

        // 1. Structured field inspection
        for (k, v) in &event.fields {
            let k_lower = k.to_lowercase();
            if (k_lower.contains("ip") || k_lower == "src" || k_lower == "dst")
                && ipv4_re.is_match(v)
            {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::IpAddress,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 0.95,
                });
            } else if k_lower.contains("user")
                || k_lower == "account"
                || k_lower == "username"
                || k_lower == "targetusername"
            {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::User,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 0.92,
                });
            } else if k_lower.contains("host")
                || k_lower == "computer_name"
                || k_lower == "workstationname"
                || k_lower == "hostname"
            {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::Host,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 0.90,
                });
            } else if (k_lower.contains("hash") || k_lower == "sha256") && sha256_re.is_match(v) {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::FileHash,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 1.0,
                });
            } else if (k_lower.contains("sha1")) && sha1_re.is_match(v) {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::FileHash,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 1.0,
                });
            } else if (k_lower.contains("md5")) && md5_re.is_match(v) {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::FileHash,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 0.98,
                });
            } else if (k_lower.contains("url") || k_lower == "uri") && url_re.is_match(v) {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::Url,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 0.95,
                });
            } else if (k_lower.contains("domain") || k_lower == "query") && domain_re.is_match(v) {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::Domain,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 0.90,
                });
            } else if (k_lower.contains("email") || k_lower == "sender" || k_lower == "recipient")
                && email_re.is_match(v)
            {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::Email,
                    value: v.clone(),
                    source_field: k.clone(),
                    confidence: 0.95,
                });
            }
        }

        // 2. Fallback: Raw text scanning
        if extracted.is_empty() {
            let raw_str = String::from_utf8_lossy(&event.raw);
            for mat in ipv4_re.find_iter(&raw_str) {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::IpAddress,
                    value: mat.as_str().to_string(),
                    source_field: "_raw".to_string(),
                    confidence: 0.75,
                });
            }
            for mat in domain_re.find_iter(&raw_str) {
                extracted.push(ExtractedEntity {
                    entity_type: EntityType::Domain,
                    value: mat.as_str().to_string(),
                    source_field: "_raw".to_string(),
                    confidence: 0.70,
                });
            }
        }

        extracted
    }

    pub fn to_entity(&self, extracted: &ExtractedEntity) -> Entity {
        let mut entity = Entity::new(extracted.entity_type.clone(), extracted.value.clone());
        entity.confidence = extracted.confidence;
        entity
    }
}
