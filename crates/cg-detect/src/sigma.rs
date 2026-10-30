//! # Sigma Rule Converter
//!
//! Converts Sigma YAML detection rules into native CyberGlass detection rules
//! and CyberQL search queries with automatic MITRE ATT&CK technique extraction.

use crate::error::Result;
use crate::mitre::lookup_technique;
use crate::rule::{DetectionRule, RuleSeverity};
use std::collections::HashMap;

pub struct SigmaConverter;

impl SigmaConverter {
    pub fn convert(yaml: &str) -> Result<DetectionRule> {
        let mut title = "Untitled Sigma Rule".to_string();
        let mut description = String::new();
        let mut severity = RuleSeverity::Medium;
        let mut mitre_techniques = Vec::new();
        let mut tags = Vec::new();
        let mut current_section = "";
        let mut detection_fields: HashMap<String, Vec<String>> = HashMap::new();
        let mut current_field = String::new();
        let mut logsource_product = String::new();

        for line in yaml.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Top-level sections
            if !line.starts_with(' ') && !line.starts_with('\t') {
                if let Some((k, v)) = line.split_once(':') {
                    let k = k.trim();
                    let v = v.trim().trim_matches('"').trim_matches('\'');
                    current_section = k;

                    match k {
                        "title" => title = v.to_string(),
                        "description" => description = v.to_string(),
                        "level" => {
                            severity = match v.to_lowercase().as_str() {
                                "critical" => RuleSeverity::Critical,
                                "high" => RuleSeverity::High,
                                "medium" => RuleSeverity::Medium,
                                "low" => RuleSeverity::Low,
                                _ => RuleSeverity::Informational,
                            };
                        }
                        _ => {}
                    }
                    continue;
                }
            }

            // Inside subsections
            match current_section {
                "tags" => {
                    if let Some(tag_val) = trimmed.strip_prefix('-') {
                        let tag = tag_val.trim().trim_matches('\'').trim_matches('"');
                        tags.push(tag.to_string());

                        // Extract MITRE ATT&CK technique IDs (e.g. attack.t1059 or attack.t1059.001)
                        if let Some(attack_part) = tag.strip_prefix("attack.") {
                            if attack_part.starts_with('t') || attack_part.starts_with('T') {
                                let tech_id = attack_part.to_uppercase();
                                if lookup_technique(&tech_id).is_some() || tech_id.starts_with('T')
                                {
                                    mitre_techniques.push(tech_id);
                                }
                            }
                        }
                    }
                }
                "logsource" => {
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim() == "product" {
                            logsource_product =
                                v.trim().trim_matches('"').trim_matches('\'').to_string();
                        }
                    }
                }
                "detection" => {
                    // Check for field: value or field: (beginning list)
                    if let Some((k, v)) = trimmed.split_once(':') {
                        let k = k.trim();
                        let v = v.trim().trim_matches('"').trim_matches('\'');
                        if k != "selection" && k != "condition" {
                            let field_clean = k.split('|').next().unwrap_or(k).trim().to_string();
                            current_field = field_clean.clone();
                            if !v.is_empty() {
                                detection_fields
                                    .entry(field_clean)
                                    .or_default()
                                    .push(v.to_string());
                            }
                        }
                    } else if let Some(val) = trimmed.strip_prefix('-') {
                        if !current_field.is_empty() {
                            let clean_val = val.trim().trim_matches('\'').trim_matches('"');
                            detection_fields
                                .entry(current_field.clone())
                                .or_default()
                                .push(clean_val.to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        // Build CyberQL query filter from extracted selection fields
        let mut query_parts = Vec::new();

        if !logsource_product.is_empty() {
            query_parts.push(format!("product=\"{}\"", logsource_product));
        }

        for (field, values) in &detection_fields {
            if values.len() == 1 {
                query_parts.push(format!("{}=\"{}\"", field, values[0]));
            } else if !values.is_empty() {
                let or_clauses: Vec<String> = values
                    .iter()
                    .map(|v| format!("{}=\"{}\"", field, v))
                    .collect();
                query_parts.push(format!("({})", or_clauses.join(" OR ")));
            }
        }

        let query = if query_parts.is_empty() {
            "*".to_string()
        } else {
            query_parts.join(" ")
        };

        let mut rule = DetectionRule::new(uuid::Uuid::now_v7().to_string(), title, query, severity);
        rule.description = description;
        rule.mitre_techniques = mitre_techniques;
        rule.tags = tags;
        rule.tags.push("sigma".to_string());

        Ok(rule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_sigma_yaml() {
        let yaml = r#"
title: Suspicious PowerShell Download
status: experimental
description: Detects suspicious PowerShell cradle executing WebClient
level: high
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: powershell.exe
        CommandLine:
            - Net.WebClient
            - DownloadFile
    condition: selection
"#;

        let rule = SigmaConverter::convert(yaml).expect("Failed to convert Sigma YAML");
        assert_eq!(rule.name, "Suspicious PowerShell Download");
        assert_eq!(rule.severity, RuleSeverity::High);
        assert!(rule.mitre_techniques.contains(&"T1059".to_string()));
        assert!(rule.query.contains("powershell.exe"));
        assert!(rule.query.contains("Net.WebClient"));
    }
}
