//! # MITRE ATT&CK Matrix Lookup Table
//!
//! Provides built-in mappings from MITRE ATT&CK technique IDs (e.g. `T1110`)
//! to tactic, human-readable technique name, and security description.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
}

const TECHNIQUES: &[(&str, &str, &str, &str)] = &[
    (
        "T1110",
        "Brute Force",
        "Credential Access",
        "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
    ),
    (
        "T1078",
        "Valid Accounts",
        "Defense Evasion",
        "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
    ),
    (
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "Adversaries may abuse command and script interpreters (PowerShell, Bash, Python) to execute commands, scripts, or binaries.",
    ),
    (
        "T1068",
        "Exploitation for Privilege Escalation",
        "Privilege Escalation",
        "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.",
    ),
    (
        "T1053",
        "Scheduled Task/Job",
        "Persistence",
        "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
    ),
    (
        "T1003",
        "OS Credential Dumping",
        "Credential Access",
        "Adversaries may attempt to dump credentials from memory, LSASS, or security databases.",
    ),
    (
        "T1021",
        "Remote Services",
        "Lateral Movement",
        "Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as RDP, SSH, or SMB.",
    ),
    (
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        "Adversaries may steal data by transferring it over an existing command and control channel.",
    ),
    (
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
        "Adversaries may communicate using application layer protocols (e.g. HTTP, HTTPS, DNS) to blend in with normal network traffic.",
    ),
    (
        "T1566",
        "Phishing",
        "Initial Access",
        "Adversaries may send phishing messages with malicious attachments or links to gain initial access.",
    ),
    (
        "T1486",
        "Data Encrypted for Impact",
        "Impact",
        "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
    ),
];

pub fn lookup_technique(id: &str) -> Option<MitreTechnique> {
    let clean_id = id.trim().to_uppercase();
    TECHNIQUES
        .iter()
        .find(|(tid, _, _, _)| clean_id == *tid || clean_id.starts_with(&format!("{}.", tid)))
        .map(|(tid, name, tactic, desc)| MitreTechnique {
            id: tid.to_string(),
            name: name.to_string(),
            tactic: tactic.to_string(),
            description: desc.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_technique() {
        let tech = lookup_technique("T1110").expect("Technique T1110 should be found");
        assert_eq!(tech.name, "Brute Force");
        assert_eq!(tech.tactic, "Credential Access");

        let sub_tech = lookup_technique("T1110.001").expect("Subtechnique should resolve parent");
        assert_eq!(sub_tech.name, "Brute Force");

        assert!(lookup_technique("T9999").is_none());
    }
}
